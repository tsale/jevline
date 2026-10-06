// Speed and accuracy against a known incident: Jev in the engine, a general LLM answering the same
// engine requests, and the same LLM reading the telemetry on its own. Every method is scored
// against a ground-truth file of the incident's processes.
//
//   set -a; . ../.env; set +a      # TYPESAFE_API_KEY and OPENROUTER_API_KEY
//   node bench/compare.ts <log files...> --seed name:2.8.exe --context "..." --truth truth.json \
//     --methods jev,jev,jev-replay,llm-judge,llm-alone --llm z-ai/glm-5.3-flash --out results
//
// A method written as <method>@<report.json> reuses the report.json of an earlier run of that method
// (its timing, requests and tokens are as recorded then), so a later failure does not mean paying again.
//
// Ground truth: {"seed": {...}, "until": ISO time the ground truth covers up to,
//   "processes": [{"name": "x.exe", "pid": 1, "start": ISO, "why": "..."}]}. Results after `until`
// are listed but not scored. Live calls spend credit and send the telemetry to the providers.
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {parseArgs} from 'node:util';
import {analyze, findSeed, iso, load, unfold, type Loaded, type ProcessRow} from '../src/analyze.ts';
import {JevClient, MODEL, TransportError, typesafe, type JevResponse, type Transport} from '../src/jev.ts';
import {injectionCapable, PERSISTENCE_KEY} from '../src/links.ts';
import {answerFile} from '../src/files.ts';
import type {ProcessNode} from '../src/model.ts';

const {values, positionals} = parseArgs({allowPositionals: true, options: {
  seed: {type: 'string'}, context: {type: 'string'}, truth: {type: 'string'}, out: {type: 'string', default: 'compare-results'},
  methods: {type: 'string', default: 'jev,jev-replay,llm-judge,llm-alone'}, llm: {type: 'string', default: 'z-ai/glm-5.3-flash'},
  'chunk-chars': {type: 'string', default: '2000000'}, concurrency: {type: 'string', default: '8'},
}});
if (!positionals.length || !values.seed || !values.context || !values.truth) throw new Error('usage: compare.ts <files...> --seed ... --context ... --truth truth.json');
const methods = values.methods!.split(',');
const concurrency = Number(values.concurrency);
const OPENROUTER = 'https://openrouter.ai/api/v1/chat/completions';
/** Jev's price: TypeSafe publishes $42 per billion input tokens (typesafe.ai, October 2026) and no
 * output price; an answer is about 21 output tokens. */
const JEV_PER_INPUT_TOKEN = 42 / 1e9;

interface Truth { seed: {name: string; pid: number}; until: string; processes: {name: string; pid: number; start: string; why: string}[] }
const truth = JSON.parse(readFileSync(values.truth, 'utf8')) as Truth;
const until = Date.parse(truth.until) * 1000;
mkdirSync(values.out!, {recursive: true, mode: 0o700});

// ---- Shared preparation ------------------------------------------------------------------------
const prepStarted = performance.now();
const loaded = await load(positionals.map(path => ({path, format: 'auto' as const})));
const {key: seedKey} = findSeed(loaded, values.seed);
const prepMs = performance.now() - prepStarted;
const seed = loaded.nodes.get(seedKey)!;
console.log(`Parsed and linked ${loaded.stats.records.toLocaleString('en-US')} records in ${(prepMs / 1000).toFixed(2)} s; seed ${seed.name} (${seed.pid}).`);

interface Found { name: string; pid?: number; start?: string | null; node?: ProcessNode }
interface Result {
  method: string; model: string; ms: number; prepMs: number; requests: number; inputTokens: number; outputTokens: number;
  cost: number | null; found: Found[]; note?: string;
}

// ---- OpenRouter ------------------------------------------------------------------------------
interface Chat { text: string; promptTokens: number; completionTokens: number; cost: number }
async function chat(messages: {role: string; content: string}[], timeoutMs: number): Promise<Chat> {
  const key = process.env.OPENROUTER_API_KEY;
  if (!key) throw new Error('OPENROUTER_API_KEY is not set');
  let response: Response, text: string;
  try {  // The timeout covers reading the reply too, which is where a slow model spends its time.
    response = await fetch(OPENROUTER, {method: 'POST', signal: AbortSignal.timeout(timeoutMs),
      headers: {'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json', 'X-Title': 'Jevline benchmark'},
      body: JSON.stringify({model: values.llm, messages, temperature: 0, response_format: {type: 'json_object'}, usage: {include: true}})});
    text = await response.text();
  } catch (error) {
    throw new TransportError(`OpenRouter unreachable or timed out after ${timeoutMs / 1000} s (${(error as Error).name})`, true);
  }
  if (!response.ok) throw new TransportError(`OpenRouter HTTP ${response.status}: ${text.slice(0, 300)}`, response.status === 429 || response.status >= 500);
  const data = JSON.parse(text) as {choices?: {message?: {content?: string}}[]; usage?: {prompt_tokens?: number; completion_tokens?: number; cost?: number}; error?: {message?: string}};
  const content = data.choices?.[0]?.message?.content;
  if (typeof content !== 'string') throw new TransportError(`OpenRouter returned no content${data.error?.message ? `: ${data.error.message}` : ''}`, true);
  return {text: content, promptTokens: data.usage?.prompt_tokens ?? 0, completionTokens: data.usage?.completion_tokens ?? 0, cost: data.usage?.cost ?? 0};
}

/** The first JSON object in a model's reply (tolerating code fences or text around it). */
function json(text: string): Record<string, unknown> {
  const start = text.indexOf('{'), end = text.lastIndexOf('}');
  if (start < 0 || end < start) throw new TransportError('the model returned no JSON object', true);
  try { return JSON.parse(text.slice(start, end + 1)) as Record<string, unknown>; } catch { throw new TransportError('the model returned malformed JSON', true); }
}

const JUDGE = 'You answer structured questions about security telemetry. The user message is a JSON object with a `state` and ' +
  '`questions`. Each question asks whether something is true about the state. For every question key, give the probability (0 to 1) ' +
  'that the answer is true. Reply with only a JSON object that maps each question key to its probability, for example {"C1": 0.12}.';

/** An LLM answering the engine's Jev requests: same state, same questions, probabilities back. */
function llmJudge(spend: {cost: number}): Transport {
  return async body => {
    const request = JSON.parse(body) as {state: unknown; questions: Record<string, unknown>};
    const reply = await chat([{role: 'system', content: JUDGE}, {role: 'user', content: JSON.stringify({state: request.state, questions: request.questions})}], 300_000);
    spend.cost += reply.cost;
    const data = json(reply.text), answers: JevResponse['answers'] = {};
    for (const label of Object.keys(request.questions)) {
      const raw = data[label], p = typeof raw === 'number' ? raw : typeof raw === 'object' && raw ? Number((raw as {probability?: unknown}).probability) : Number(raw);
      if (!Number.isFinite(p) || p < 0 || p > 1) throw new TransportError(`the model gave no probability for ${label}`, true);
      answers[label] = {type: 'noul', noul: p};
    }
    return {model: values.llm, answers, usage: {input_tokens: reply.promptTokens, output_tokens: reply.completionTokens}};
  };
}

// ---- Methods ---------------------------------------------------------------------------------
async function engineRun(method: string, transport: Transport, model: string, cacheFile?: string, spend?: {cost: number}): Promise<Result> {
  const client = new JevClient(transport, {concurrency, ...(cacheFile ? {answers: answerFile(cacheFile)} : {})});
  const started = performance.now();
  const {report} = await analyze(loaded, seedKey, client, {description: values.context!, model, threshold: 0.8, margin: 0.05, batchSize: 1,
    maxRounds: 20, maxCandidatesPerRound: 2000, transport: method});
  const ms = performance.now() - started;
  writeFileSync(join(values.out!, `${method}-${results.length + 1}-report.json`), JSON.stringify(report, null, 1), {mode: 0o600});
  const calls = client.calls.filter(c => !c.cached);
  const latencies = calls.map(c => c.ms).sort((a, b) => a - b), at = (q: number) => latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))] ?? 0;
  const retried = calls.filter(c => c.attempts > 1).length;
  const timing = calls.length ? `per request: median ${(at(0.5) / 1000).toFixed(2)} s, 95th percentile ${(at(0.95) / 1000).toFixed(2)} s, slowest ${(at(1) / 1000).toFixed(1)} s` +
    (retried ? `; ${retried} requests needed retries` : '') : '';
  return {method, model, ms, prepMs, requests: calls.length, inputTokens: calls.reduce((s, c) => s + (c.input_tokens ?? 0), 0),
    outputTokens: calls.reduce((s, c) => s + (c.output_tokens ?? 0), 0),
    cost: spend ? spend.cost : calls.reduce((s, c) => s + (c.input_tokens ?? 0), 0) * JEV_PER_INPUT_TOKEN,
    found: unfold(report.incident).filter(p => p.key !== seedKey).map(p => ({name: p.name ?? '?', pid: p.pid, start: p.start ?? null, node: loaded.nodes.get(p.key)})),
    note: [report.jev.answered_from_cache ? `${report.jev.answered_from_cache} answers from the cache` : '', timing].filter(Boolean).join('; ')};
}

/** An earlier engine run, from its report.json. */
function fromReport(method: string, path: string): Result {
  const report = JSON.parse(readFileSync(path, 'utf8')) as {timings_ms: {investigate: number}; jev: {model: string; requests: number;
    answered_from_cache: number; input_tokens: number; output_tokens: number}; incident: ProcessRow[]};
  return {method, model: report.jev.model, ms: report.timings_ms.investigate, prepMs, requests: report.jev.requests - report.jev.answered_from_cache,
    inputTokens: report.jev.input_tokens, outputTokens: report.jev.output_tokens, cost: report.jev.input_tokens * JEV_PER_INPUT_TOKEN,
    found: unfold(report.incident).filter(p => p.key !== seedKey).map(p => ({name: p.name ?? '?', pid: p.pid, start: p.start ?? null, node: loaded.nodes.get(p.key)})),
    note: `recorded in an earlier run (${path.split('/').at(-1)})${report.jev.answered_from_cache ? `; ${report.jev.answered_from_cache} answers from the cache` : ''}`};
}

/** The telemetry an analyst (or an LLM) would read: every process start after the seed on its host, and
 * the events that connect processes (remote threads, injection-capable handles, executables written,
 * autostart entries, services and tasks). Network and DNS are left out to keep it within reach. */
function telemetryLines(data: Loaded): string[] {
  const host = seed.host, from = seed.start ?? 0;
  const label = (key: string | undefined) => { const n = key ? data.nodes.get(key) : undefined; return n ? `${n.name ?? '?'}(${n.pid ?? '?'})` : '?'; };
  const clip = (s: string | undefined, n: number) => !s ? '' : s.length > n ? `${s.slice(0, n)}…` : s;
  const lines: [number, string][] = [];
  for (const n of data.nodes.values()) {
    if (n.host !== host || n.start === null || n.start < from) continue;
    lines.push([n.start, `${iso(n.start)} PROCESS_START pid=${n.pid ?? '?'} image=${n.path ?? n.name} parent=${label(n.parent)} user=${n.user ?? '?'} cmd=${clip(n.cmd, 300)}`]);
  }
  for (const e of data.events) {
    if (e.host !== host || e.t === null || e.t < from) continue;
    const by = label(data.actor[e.seq]);
    const target = e.target ? `${e.target.name ?? e.target.path ?? '?'}(${e.target.pid ?? '?'})` : '?';
    if (e.kind === 'inject') lines.push([e.t, `${iso(e.t)} REMOTE_THREAD by=${by} into=${target}`]);
    else if (e.kind === 'process_access' && e.access !== undefined && injectionCapable(e.access)) lines.push([e.t, `${iso(e.t)} OPEN_PROCESS by=${by} target=${target} access=0x${e.access.toString(16)}`]);
    else if (e.kind === 'file_create' && e.file_path && /\.(exe|dll|scr|ps1|bat|cmd|vbs|js|hta|tmp)$/i.test(e.file_path)) lines.push([e.t, `${iso(e.t)} FILE_WRITE by=${by} path=${e.file_path}`]);
    else if (e.kind === 'registry_set' && e.reg?.key && PERSISTENCE_KEY.test(e.reg.key)) lines.push([e.t, `${iso(e.t)} AUTOSTART_SET by=${by} key=${e.reg.key} value=${clip(e.reg.value, 200)}`]);
    else if (e.kind === 'service_install' || e.kind === 'task_create') lines.push([e.t, `${iso(e.t)} ${e.kind.toUpperCase()} by=${by} launches=${clip(e.launches, 200)}`]);
  }
  return lines.sort((a, b) => a[0] - b[0]).map(([, line]) => line);
}

async function llmAlone(): Promise<Result> {
  const started = performance.now();
  const lines = telemetryLines(loaded), limit = Number(values['chunk-chars']);
  const chunks: string[][] = [[]];
  let size = 0;
  for (const line of lines) {
    if (size + line.length > limit && chunks.at(-1)!.length) { chunks.push([]); size = 0; }
    chunks.at(-1)!.push(line);
    size += line.length + 1;
  }
  const brief = `Confirmed malicious execution: ${seed.name} (pid ${seed.pid}) started ${iso(seed.start)} on host ${seed.host}, ` +
    `image ${seed.path}, parent ${loaded.nodes.get(seed.parent ?? '')?.name ?? 'unknown'}.\nAnalyst context: ${values.context}`;
  const task = 'Task: using the telemetry below, identify every process that belongs to the same incident as this malicious execution: ' +
    'processes it (or any process already part of the incident) started, injected into, hollowed, dropped and ran, persisted, or ' +
    'otherwise carried the execution chain into. Leave out unrelated user and system activity.\n' +
    'Reply with only JSON: {"processes": [{"pid": 1234, "image": "name.exe", "start": "ISO time from the telemetry", "reason": "a few words"}]}';
  let cost = 0, promptTokens = 0, completionTokens = 0;
  const replies = await Promise.all(chunks.map(async (chunk, i) => {
    const content = `${brief}\n\n${task}\n\nThis is part ${i + 1} of ${chunks.length} of the telemetry (${chunk[0]!.slice(0, 24)} to ${chunk.at(-1)!.slice(0, 24)}), one event per line:\n${chunk.join('\n')}`;
    for (let attempt = 1; ; attempt++) {
      try {
        const reply = await chat([{role: 'system', content: 'You are an experienced DFIR analyst reviewing Windows Sysmon and Security telemetry. Reply with JSON only.'},
          {role: 'user', content}], 900_000);
        cost += reply.cost; promptTokens += reply.promptTokens; completionTokens += reply.completionTokens;
        return json(reply.text);
      } catch (error) {
        if (!(error instanceof TransportError) || !error.retryable || attempt >= 3) throw error;
        await new Promise(r => setTimeout(r, 2000 * attempt));
      }
    }
  }));
  const found: Found[] = [];
  for (const reply of replies) {
    for (const p of Array.isArray(reply.processes) ? reply.processes as {pid?: unknown; image?: unknown; start?: unknown}[] : []) {
      const pid = Number(p.pid), name = String(p.image ?? '').split(/[\\/]/).at(-1) ?? '';
      if (!Number.isInteger(pid) || pid === seed.pid && name.toLowerCase() === seed.name?.toLowerCase()) continue;
      const start = typeof p.start === 'string' ? p.start : null;
      // The process the model means: same host, name and PID, nearest to the time it gave (or the first after the seed).
      const want = start && Number.isFinite(Date.parse(start)) ? Date.parse(start) * 1000 : seed.start ?? 0;
      const node = [...loaded.nodes.values()].filter(n => n.host === seed.host && n.pid === pid && n.name?.toLowerCase() === name.toLowerCase())
        .sort((a, b) => Math.abs((a.start ?? a.firstSeen ?? 0) - want) - Math.abs((b.start ?? b.firstSeen ?? 0) - want))[0];
      found.push({name, pid, start, ...(node ? {node} : {})});
    }
  }
  return {method: 'llm-alone', model: values.llm!, ms: performance.now() - started, prepMs, requests: chunks.length, inputTokens: promptTokens,
    outputTokens: completionTokens, cost, found, note: `${lines.length.toLocaleString('en-US')} telemetry lines in ${chunks.length} request(s) sent in parallel`};
}

// ---- Run ------------------------------------------------------------------------------------
const results: Result[] = [];
let firstJevCache: string | undefined;
for (const spec of methods) {
  const [method, earlier] = spec.split('@') as [string, string | undefined];
  console.log(`Running ${spec}…`);
  let result: Result;
  if (earlier) {
    result = fromReport(method, earlier);
  } else if (method === 'jev') {
    const key = process.env.TYPESAFE_API_KEY;
    if (!key) throw new Error('TYPESAFE_API_KEY is not set');
    const cacheFile = join(values.out!, `jev-cache-${results.length + 1}.jsonl`);
    firstJevCache ??= cacheFile;
    result = await engineRun('jev', typesafe(key), MODEL, cacheFile);
  } else if (method === 'jev-replay') {
    if (!firstJevCache) throw new Error('jev-replay needs an earlier jev run');
    result = await engineRun('jev-replay', async () => { throw new TransportError('replay made a call', false); }, MODEL, firstJevCache);
  } else if (method === 'llm-judge') {
    const spend = {cost: 0};
    result = await engineRun('llm-judge', llmJudge(spend), values.llm!, undefined, spend);
  } else if (method === 'llm-alone') {
    result = await llmAlone();
  } else {
    throw new Error(`unknown method ${method}`);
  }
  results.push(result);
  writeFileSync(join(values.out!, 'partial.json'), JSON.stringify(results.map(({found, ...r}) => ({...r, found: found.length})), null, 1), {mode: 0o600});
  console.log(`  ${(result.ms / 1000).toFixed(1)} s, ${result.requests} requests, ${result.found.length} processes${result.note ? ` (${result.note})` : ''}`);
}

// ---- Score ----------------------------------------------------------------------------------
const truthKey = (name: string, pid: number | undefined) => `${name.toLowerCase()}|${pid}`;
const truthStarts = new Map(truth.processes.map(p => [truthKey(p.name, p.pid), Date.parse(p.start) * 1000]));
const matches = (f: Found): string | null => {
  const k = truthKey(f.name, f.pid), at = truthStarts.get(k);
  if (at === undefined) return null;
  const start = f.node?.start ?? f.node?.firstSeen ?? (f.start ? Date.parse(f.start) * 1000 : null);
  return start === null || Math.abs(start - at) <= 5e6 ? k : null;
};
const inWindow = (f: Found) => { const t = f.node ? f.node.start ?? f.node.firstSeen : f.start ? Date.parse(f.start) * 1000 : null; return t === null || t <= until + 1e6; };
const scored = results.map(r => {
  const scope = r.found.filter(inWindow), hits = new Set(scope.map(matches).filter((k): k is string => k !== null));
  return {...r, scope: scope.length, after: r.found.length - scope.length, hits, precision: scope.length ? hits.size / scope.length : 0,
    falsePositives: scope.filter(f => matches(f) === null)};
});

const sec = (ms: number) => ms < 10_000 ? `${(ms / 1000).toFixed(2)} s` : `${(ms / 1000).toFixed(1)} s`;
const pct = (x: number) => `${Math.round(x * 100)}%`;
const label = (m: string) => ({jev: 'Jevline + Jev', 'jev-replay': 'Jevline + Jev, replayed from cache', 'llm-judge': `Jevline + ${values.llm} as judge`,
  'llm-alone': `${values.llm} alone`})[m] ?? m;
const total = truth.processes.length;
const md: string[] = [
  `# Jev vs ${values.llm}: ${truth.processes.length}-process incident, ${loaded.stats.records.toLocaleString('en-US')} records`, '',
  `Seed ${seed.name} (${seed.pid}) on ${seed.host}. Ground truth: ${total} processes up to ${truth.until}. Parsing and linking took ${sec(prepMs)} and is included in every Jevline total.`, '',
  '| Method | Model | Time to result | Requests | Input tokens | Cost | Incident processes found | Precision | Wrongly included | After ground truth |',
  '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|',
  ...scored.map(r => `| ${label(r.method)} | ${r.model} | ${sec(r.ms + (r.method === 'llm-alone' ? 0 : r.prepMs))} | ${r.requests} | ` +
    `${r.inputTokens.toLocaleString('en-US')} | ${r.cost === null ? '—' : `$${r.cost.toFixed(r.cost < 0.01 ? 4 : 3)}`} | ${r.hits.size} of ${total} (${pct(r.hits.size / total)}) | ` +
    `${pct(r.precision)} | ${r.falsePositives.length} | ${r.after} |`),
  '', '| Ground-truth process | Why it belongs | ' + scored.map((r, i) => `${label(r.method)}${scored.filter(s => s.method === r.method).length > 1 ? ` #${scored.slice(0, i + 1).filter(s => s.method === r.method).length}` : ''}`).join(' | ') + ' |',
  '|---|---|' + scored.map(() => ':---:').join('|') + '|',
  ...truth.processes.map(p => `| ${p.name} (${p.pid}) | ${p.why} | ${scored.map(r => r.hits.has(truthKey(p.name, p.pid)) ? '✓' : '—').join(' | ')} |`),
  '', ...scored.filter(r => r.falsePositives.length).map(r => `**${label(r.method)}, wrongly included (${r.falsePositives.length}):** ` +
    r.falsePositives.slice(0, 40).map(f => `${f.name} (${f.pid ?? '?'})`).join(', ') + (r.falsePositives.length > 40 ? ', …' : '')),
  '', ...scored.filter(r => r.note).map(r => `- ${label(r.method)}: ${r.note}`),
];
writeFileSync(join(values.out!, 'results.md'), md.join('\n') + '\n', {mode: 0o600});
writeFileSync(join(values.out!, 'results.json'), JSON.stringify(scored.map(({hits, falsePositives, found, ...r}) => ({...r, hits: [...hits],
  falsePositives: falsePositives.map(f => `${f.name}:${f.pid}`), found: found.map(f => ({name: f.name, pid: f.pid, start: f.start}))})), null, 1), {mode: 0o600});
console.log('\n' + md.join('\n'));
