#!/usr/bin/env node
// jevline: rebuild an incident from one confirmed malicious process.
//
//   node engine/src/cli.ts analyze <log files...> --seed name:2.8.exe --context "Analyst-confirmed ..."
//   node engine/src/cli.ts inspect <log files...> [--find 2.8.exe]
import {mkdirSync, readFileSync, statSync, writeFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {FORMATS, type Format} from './read.ts';
import {analyze, defaultThreads, findSeed, iso, load, unfold, type Input, type Report} from './analyze.ts';
import {JevClient, MODEL, typesafe} from './jev.ts';
import {standIn} from './standin.ts';
import {fingerprint, learn, SchemaCache, type Mapping} from './schema.ts';
import {answerFile, mappingFile, requestLog} from './files.ts';
import {relative} from './investigate.ts';

const HELP = `Usage:
  jevline analyze <log files...> --seed <selector> --context <text> [options]
  jevline inspect <log files...> [--find <image name>] [--format ...]

Log files: JSON, NDJSON, CSV/TSV or plain text, one event per line; several files are combined. Logs from a
schema the engine doesn't know (any EDR or other source) are understood by asking Jev once per event type.
Seed: a process (an event ID such as line-12057, name:<image> for its earliest start, or guid:<process GUID>),
or another entity: ip:<address>, domain:<name>, user:<account> or host:<name>.

Options:
  --context <text>        Why the seed is confirmed malicious (sent to Jev with every request)
  --format <f>            ${FORMATS.join(' | ')} (default auto, detected per file)
  --threshold <p>         Jev probability that links a process (default 0.8)
  --entity-threshold <p>  ...an address, domain, account or host nothing outside the incident touched, or a process
                          running a file the incident wrote, started by persistence it registered (default 0.5)
  --also <selector>       Another analyst-confirmed starting point, investigated with the seed (repeatable)
  --context-lines         Also report the [input, line] of every record a later run needs instead of these logs
  --batch <n>             Candidates per Jev request (default 1: each decision rests on its own evidence)
  --margin <p>            Flag decisions this close to the threshold for review (default 0.05)
  --concurrency <n>       Jev requests in flight (default 8)
  --rounds <n>            Most expansion rounds (default 20)
  --max-candidates <n>    Stop if one round would ask about more processes (default 2000)
  --model <id>            Jev model (default ${MODEL})
  --out <dir>             Write report.json and requests.jsonl (every exact request) there
  --cache <file>          Reuse and record Jev answers by request hash (JSONL); replays are exact and free
  --schemas <file>        Where mappings of unknown log schemas are kept (default ~/.jevline/schemas.jsonl)
  --ungrouped             Ask about every candidate separately, even ones identical apart from PID and time
  --offline               Use the offline stand-in instead of Jev (link types only; not Jev's judgment)
  --threads <n>           Cores used to parse large files (default: up to 8)
  --json                  Print the report as JSON instead of a table
  --key-file <file>       Read TYPESAFE_API_KEY from this private file (default: ./.env, then the repository's .env)
TypeSafe key: TYPESAFE_API_KEY in the environment or in a private .env (chmod 600).`;

const ENGINE = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** TYPESAFE_API_KEY from the environment, else a private .env (--key-file, or here, or the repository root). */
function apiKey(envFile?: string): string | null {
  if (process.env.TYPESAFE_API_KEY) return process.env.TYPESAFE_API_KEY;
  for (const file of envFile ? [resolve(envFile)] : [resolve('.env'), join(ENGINE, '..', '.env')]) {
    let text: string;
    try { text = readFileSync(file, 'utf8'); } catch { continue; }
    if (process.platform !== 'win32' && (statSync(file).mode & 0o077)) throw new Error(`${file} must be private; run: chmod 600 ${file}`);
    for (const line of text.split(/\r?\n/)) {
      const m = /^\s*(?:export\s+)?TYPESAFE_API_KEY\s*=\s*(.*?)\s*$/.exec(line);
      if (m) {
        const raw = m[1]!;
        const value = raw.length >= 2 && raw[0] === raw.at(-1) && `"'`.includes(raw[0]!) ? raw.slice(1, -1) : raw.split(/\s+#/)[0]!;
        if (value) return value;
      }
    }
  }
  return null;
}

const number = (value: string | undefined, fallback: number, name: string, min = 0, max = Infinity): number => {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n < min || n > max) throw new Error(`--${name} must be a number from ${min} to ${max}`);
  return n;
};

const seconds = (ms: number) => `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;

/** A summary of the event types learned from unknown schemas, with anything that looked wrong. */
function schemaLines(schemas: Report['schemas']): string[] {
  if (!schemas.length) return [];
  const by = (learned: string) => schemas.filter(s => s.learned === learned).length;
  const used = schemas.filter(s => s.kind !== 'other' && s.kind !== 'unknown');
  const lines = [`Unknown schemas: ${schemas.length} event types (${by('jev')} learned from Jev now, ${by('cache')} from earlier runs` +
    `${by('stand-in') ? `, ${by('stand-in')} guessed by the offline stand-in` : ''}${by('not learned') ? `, ${by('not learned')} not learned yet` : ''})` +
    (used.length ? `; ${used.length} of them used: ${used.slice(0, 8).map(s => `${s.group} → ${s.kind}`).join(', ')}${used.length > 8 ? ', …' : ''}.` : '.')];
  if (by('not learned')) lines.push('  Run analyze to learn them: Jev is asked once per event type, and the mappings are kept for next time.');
  for (const s of schemas) for (const w of s.warnings ?? []) if (lines.length < 8) lines.push(`  ${s.group}: ${w}`);
  return lines;
}

function printReport(report: Report) {
  const out: string[] = [];
  const seed = report.seed;
  out.push(seed.type === 'process' ? `Seed: ${seed.name} (pid ${seed.pid}) on ${seed.host}, started ${seed.start ?? 'before the logs'}`
    : `Seed: ${seed.type} ${seed.name}, first seen ${seed.first_seen ?? 'at an unknown time'}`);
  if (report.note) out.push(`Note: ${report.note}`);
  out.push('', `${'Since seed'.padEnd(13)} ${'Process or entity'.padEnd(34)} ${'Joined via'.padEnd(48)} Jev`);
  const origin = Date.parse(seed.start ?? seed.first_seen ?? '') * 1000;
  for (const p of report.incident) {
    const at = p.type === 'process' ? p.start : p.joined_incident ?? p.first_seen;
    const since = relative(at ? Date.parse(at) * 1000 : null, Number.isNaN(origin) ? null : origin) ?? 'before logs';
    const what = p.type === 'process' ? `${p.name ?? '?'} (${p.pid ?? '?'})${p.repeats ? ` ×${p.repeats.count}` : ''}${p.host !== seed.host ? ` @${p.host}` : ''}`
      : `${p.name} (${p.type})`;
    const via = p.joined ? p.joined.via.slice(0, 2).map(v => `${v.link} from ${v.from}`).join('; ') + (p.joined.via.length > 2 ? ` +${p.joined.via.length - 2}` : '') : 'confirmed seed';
    const score = p.joined ? `${Math.round(p.joined.probability * 100)}%${p.joined.review ? ' review' : ''}` : '—';
    out.push(`${since.padEnd(13)} ${what.padEnd(34).slice(0, 34)} ${via.padEnd(48).slice(0, 48)} ${score}`);
  }
  const t = report.timings_ms, j = report.jev;
  const members = unfold(report.incident), processes = members.filter(p => p.type === 'process').length;
  const folded = report.incident.filter(p => p.repeats).length;
  out.push('',
    `${members.length} in the incident (${processes} processes, ${members.length - processes} accounts, hosts, addresses or domains)` +
      `${folded ? `, shown as ${report.incident.length} rows: ${folded} ${folded === 1 ? 'process repeats' : 'processes repeat'} identically` : ''}; ${unfold(report.rejected).length} candidates not linked.`,
    `Timeline: ${report.timeline.length.toLocaleString('en-US')} rows from ${report.counts.timeline_events.toLocaleString('en-US')} events (repeats of the same activity folded).`,
    `Input: ${report.counts.records.toLocaleString('en-US')} records → ${report.counts.events.toLocaleString('en-US')} events, ` +
      `${report.counts.processes.toLocaleString('en-US')} processes, ${report.counts.entities.toLocaleString('en-US')} accounts, hosts, addresses and domains, ` +
      `${report.counts.links.toLocaleString('en-US')} links.`,
    ...schemaLines(report.schemas),
    `Time: read ${seconds(t.read_normalize!)}, processes ${seconds(t.identify_processes!)}, links ${seconds(t.build_links!)}, ` +
      `Jev ${seconds(t.investigate!)} → total ${seconds(t.total!)}.`,
    `Jev (${j.transport}): ${j.requests} requests over ${j.rounds} rounds for ${j.candidates_asked} candidate decisions` +
      `${j.answered_from_cache ? `, ${j.answered_from_cache} answered from cache` : ''}${j.input_tokens ? `, ${j.input_tokens.toLocaleString('en-US')} input tokens` : ''}.`);
  if (j.near_threshold) out.push(`${j.near_threshold} answers${j.near_threshold_candidates > j.near_threshold ? ` (deciding ${j.near_threshold_candidates} candidates)` : ''} ` +
    `are within ±${j.margin} of the ${j.threshold} threshold (marked "review"): a fresh run without --cache could decide them the other way.`);
  if (j.stopped) out.push(`Stopped early: ${j.stopped}. Raise --max-candidates or --rounds to continue.`);
  if (j.transport !== 'typesafe') out.push('Offline stand-in: links scored by type only. These are not Jev decisions.');
  console.log(out.join('\n'));
}

async function main(argv: string[]) {
  const {values, positionals} = parseArgs({args: argv, allowPositionals: true, options: {
    seed: {type: 'string'}, also: {type: 'string', multiple: true}, context: {type: 'string'}, format: {type: 'string', default: 'auto'},
    threshold: {type: 'string'}, 'entity-threshold': {type: 'string'}, 'context-lines': {type: 'boolean', default: false}, margin: {type: 'string'}, batch: {type: 'string'}, concurrency: {type: 'string'}, rounds: {type: 'string'},
    'max-candidates': {type: 'string'}, model: {type: 'string', default: MODEL}, out: {type: 'string'}, cache: {type: 'string'}, schemas: {type: 'string'},
    offline: {type: 'boolean', default: false}, ungrouped: {type: 'boolean', default: false}, json: {type: 'boolean', default: false}, find: {type: 'string'}, 'key-file': {type: 'string'}, threads: {type: 'string'}, help: {type: 'boolean', short: 'h'},
  }});
  const [command, ...files] = positionals;
  if (values.help || !command || !['analyze', 'inspect'].includes(command)) { console.log(HELP); return command && !values.help ? 2 : 0; }
  if (!files.length) throw new Error('give at least one log file');
  if (!(FORMATS as readonly string[]).includes(values.format!)) throw new Error(`--format must be one of ${FORMATS.join(', ')}`);
  const inputs: Input[] = files.map(path => ({path, format: values.format as Format}));
  const threads = number(values.threads, defaultThreads(), 'threads', 1, 64);
  const concurrency = number(values.concurrency, 8, 'concurrency', 1, 64);
  const schemaFile = values.schemas ?? join(homedir(), '.jevline', 'schemas.jsonl');

  if (command === 'inspect') {
    // Inspect never calls Jev: unknown schemas use mappings learned before, if any.
    const cache = new SchemaCache(mappingFile(schemaFile));
    const loaded = await load(inputs, {threads, learn: async profiles => {
      const known = new Map<string, Mapping>();
      for (const group of Object.values(profiles)) { const m = cache.get(fingerprint(group)); if (m) known.set(group.key, {...m, group: group.key}); }
      return known;
    }});
    const sources = [...loaded.stats.bySource].sort((a, b) => b[1] - a[1]).slice(0, 15).map(([s, n]) => `${s} ${n.toLocaleString('en-US')}`);
    const kinds = new Map<string, number>();
    for (const e of loaded.events) kinds.set(e.kind, (kinds.get(e.kind) ?? 0) + 1);
    const processes = [...loaded.nodes.values()].filter(n => n.type === 'process').length;
    const byType: Record<string, number> = {};
    for (const link of loaded.graph.links) byType[link.type] = (byType[link.type] ?? 0) + 1;
    console.log([
      ...loaded.inputs.map(i => `${i.path}: ${i.records.toLocaleString('en-US')} records, ${i.kept.toLocaleString('en-US')} kept`),
      `Sources: ${sources.join(', ')}`,
      `Kept events: ${[...kinds].sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} ${n.toLocaleString('en-US')}`).join(', ')}`,
      `${processes.toLocaleString('en-US')} processes (${[...loaded.nodes.values()].filter(n => n.starts.length).length.toLocaleString('en-US')} with a start record), ` +
        `${(loaded.nodes.size - processes).toLocaleString('en-US')} accounts, hosts, addresses and domains; links: ${JSON.stringify(byType)}`,
      `Time: read ${seconds(loaded.timings.read_normalize!)}, processes ${seconds(loaded.timings.identify_processes!)}, links ${seconds(loaded.timings.build_links!)}`,
      ...schemaLines(loaded.schemas),
    ].join('\n'));
    if (values.find) {
      const name = values.find.toLowerCase();
      for (const n of [...loaded.nodes.values()].filter(n => n.name?.toLowerCase() === name && n.starts.length)
        .sort((a, b) => (a.start ?? 0) - (b.start ?? 0))) {
        const start = loaded.events[n.starts[0]!]!;
        console.log(`  ${iso(n.start)}  ${n.host}  pid ${n.pid ?? '?'}  seed: ${start.id}${n.guid ? `  guid:${n.guid}` : ''}`);
      }
    }
    return 0;
  }

  if (!values.seed) throw new Error('--seed is required (an event ID, name:<image>, guid:<GUID>, ip:, domain:, user: or host:)');
  if (!values.context) throw new Error('--context is required: why the seed is confirmed malicious');
  let transport, transportName;
  if (values.offline) { transport = standIn(); transportName = 'offline stand-in'; }
  else {
    const key = apiKey(values['key-file']);
    if (!key) throw new Error('no TypeSafe key: set TYPESAFE_API_KEY or add it to a private .env (or use --offline)');
    transport = typesafe(key); transportName = 'typesafe';
  }
  if (values.out) mkdirSync(values.out, {recursive: true, mode: 0o700});
  const clientOptions = {concurrency, ...(values.cache ? {answers: answerFile(values.cache)} : {}), ...(values.out ? {onRequest: requestLog(join(values.out, 'requests.jsonl'))} : {})};
  // Mappings the stand-in guesses are not kept, so a later run with Jev learns them properly.
  const schemaCache = new SchemaCache(values.offline ? undefined : mappingFile(schemaFile));
  const schemaClient = new JevClient(transport, clientOptions);
  const loaded = await load(inputs, {threads,
    learn: profiles => learn(profiles, schemaClient, schemaCache, values.model!, values.offline ? 'stand-in' : 'jev')});
  const {key, note} = findSeed(loaded, values.seed);
  const confirmed = (values.also ?? []).map(selector => findSeed(loaded, selector).key).filter(k => k !== key);
  const client = new JevClient(transport, clientOptions);
  const {report} = await analyze(loaded, key, client, {
    description: values.context, model: values.model!, threshold: number(values.threshold, 0.8, 'threshold', 0, 1),
    entityThreshold: number(values['entity-threshold'], 0.5, 'entity-threshold', 0, 1), context: values['context-lines'],
    margin: number(values.margin, 0.05, 'margin', 0, 1), batchSize: number(values.batch, 1, 'batch', 1, 200), maxRounds: number(values.rounds, 20, 'rounds', 1, 1000),
    maxCandidatesPerRound: number(values['max-candidates'], 2000, 'max-candidates', 1), transport: transportName,
    group: !values.ungrouped, confirmed,
  }, note);
  if (values.out) writeFileSync(join(values.out, 'report.json'), JSON.stringify(report, null, 1) + '\n', {mode: 0o600});
  if (values.json) console.log(JSON.stringify(report, null, 1));
  else printReport(report);
  return 0;
}

main(process.argv.slice(2)).then(code => { process.exitCode = code; }, error => {
  console.error(`jevline: ${(error as Error).message}`);
  process.exitCode = 1;
});
