// Live check that batching does not change Jev's answers: the same real candidates are asked alone,
// in batches of 10, in one batch of 20, in reverse order, and again. About 30 calls; spends TypeSafe
// credit and sends the candidates' telemetry to TypeSafe, so it only runs with --live.
//
//   node bench/jev-batching.ts <log files...> --seed name:2.8.exe --context "..." --live [--out DIR]
import {mkdirSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {parseArgs} from 'node:util';
import {findSeed, load} from '../src/analyze.ts';
import {investigate, type Group} from '../src/investigate.ts';
import {JevClient, MODEL, typesafe, type JevResponse} from '../src/jev.ts';
import {standIn} from '../src/standin.ts';

const {values, positionals} = parseArgs({allowPositionals: true, options: {
  seed: {type: 'string'}, context: {type: 'string'}, live: {type: 'boolean', default: false}, out: {type: 'string', default: 'jev-batching'},
  size: {type: 'string', default: '20'}, model: {type: 'string', default: MODEL}, round: {type: 'string'},
}});
if (!positionals.length || !values.seed || !values.context) throw new Error('usage: jev-batching.ts <files...> --seed <selector> --context <text> --live');
const size = Number(values.size);

// 1. The candidates: the first round with enough of them, found with the offline stand-in.
const loaded = await load(positionals.map(path => ({path, format: 'auto' as const})));
const {key} = findSeed(loaded, values.seed);
let chosen: {round: number; groups: Group[]; build: (batch: Group[]) => {body: string; labels: string[]}} | undefined;
await investigate(loaded.events, loaded.nodes, loaded.graph, key, new JevClient(standIn()), {description: values.context, model: values.model!,
  threshold: 0.8, batchSize: 25, maxRounds: 10, maxCandidatesPerRound: 100000,
  onRound: (round, groups, build) => {
    if (!chosen && groups.length >= size && (values.round === undefined || round === Number(values.round))) chosen = {round, groups, build};
  }});
if (!chosen) throw new Error(`no round${values.round ? ` ${values.round}` : ''} has ${size} candidates`);
const step = chosen.groups.length / size;
const sample = Array.from({length: size}, (_, i) => chosen!.groups[Math.floor(i * step)]!);
const name = (g: Group) => { const n = loaded.nodes.get(g.members[0]![0])!; return `${n.name} (${n.pid})${g.members.length > 1 ? ` ×${g.members.length}` : ''}`; };

// 2. The plan: which batches each condition sends.
const conditions: [string, Group[][]][] = [
  ['alone', sample.map(g => [g])],
  ['alone again (first 5)', sample.slice(0, 5).map(g => [g])],
  ['batches of 10', [sample.slice(0, 10), sample.slice(10, 20)]],
  [`one batch of ${size}`, [sample]],
  [`one batch of ${size}, again`, [sample]],
  [`one batch of ${size}, reversed`, [[...sample].reverse()]],
];
const calls = conditions.reduce((n, [, batches]) => n + batches.length, 0);
console.log(`Round ${chosen.round}: ${size} of ${chosen.groups.length} candidates; ${calls} Jev calls planned:`);
for (const g of sample) console.log(`  ${name(g)}`);
if (!values.live) { console.log('\nDry run. Add --live to send these requests to TypeSafe (spends credit; sends this telemetry).'); process.exit(0); }
const apiKey = process.env.TYPESAFE_API_KEY;
if (!apiKey) throw new Error('set TYPESAFE_API_KEY (for example: set -a; . ../.env; set +a)');

// 3. Ask. Each condition gets its own client, so repeats really go to Jev instead of the cache.
mkdirSync(values.out!, {recursive: true, mode: 0o700});
const results = new Map<string, Map<Group, number>>();
const timing: [string, number, number, number][] = [];  // condition, calls, mean ms per call, input tokens per candidate
const log: unknown[] = [];
for (const [condition, batches] of conditions) {
  const client = new JevClient(typesafe(apiKey), {concurrency: 1});
  const answers = new Map<Group, number>();
  for (const batch of batches) {
    const {body, labels} = chosen.build(batch);
    const response: JevResponse = await client.ask(body, batch.length);
    log.push({condition, labels, candidates: batch.map(name), body: JSON.parse(body), response});
    batch.forEach((g, i) => answers.set(g, response.answers[labels[i]!]!.noul!));
  }
  results.set(condition, answers);
  const answered = client.calls.filter(c => !c.cached);
  timing.push([condition, answered.length, answered.reduce((s, c) => s + c.ms, 0) / answered.length,
    answered.reduce((s, c) => s + (c.input_tokens ?? 0), 0) / batches.reduce((n, b) => n + b.length, 0)]);
}
writeFileSync(join(values.out!, 'requests-and-answers.json'), JSON.stringify(log, null, 1), {mode: 0o600});

// 4. Compare every condition with asking alone.
const alone = results.get('alone')!;
const pct = (p: number | undefined) => p === undefined ? '' : `${Math.round(p * 100)}%`;
const lines = [`| Candidate | ${conditions.map(([c]) => c).join(' | ')} |`, `|---|${conditions.map(() => '---:').join('|')}|`];
for (const g of sample) lines.push(`| ${name(g)} | ${conditions.map(([c]) => pct(results.get(c)!.get(g))).join(' | ')} |`);
const summary: string[] = [];
for (const [condition] of conditions.slice(1)) {
  const diffs = [...results.get(condition)!].map(([g, p]) => ({d: Math.abs(p - alone.get(g)!), flip: (p >= 0.8) !== (alone.get(g)! >= 0.8)}));
  summary.push(`| ${condition} | ${Math.max(...diffs.map(x => x.d)).toFixed(3)} | ${(diffs.reduce((s, x) => s + x.d, 0) / diffs.length).toFixed(3)} | ` +
    `${diffs.filter(x => x.flip).length} of ${diffs.length} |`);
}
const report = [
  `# Jev batching check (${new Date().toISOString()}, model ${values.model})`, '',
  `${size} candidates from round ${chosen.round}, each asked under every condition.`, '', ...lines, '',
  '| Compared with asking alone | Largest difference | Mean difference | Decisions that flip at 0.8 |', '|---|---:|---:|---:|', ...summary, '',
  '| Condition | Calls | Mean latency per call | Input tokens per candidate |', '|---|---:|---:|---:|',
  ...timing.map(([c, n, ms, tokens]) => `| ${c} | ${n} | ${Math.round(ms)} ms | ${Math.round(tokens).toLocaleString('en-US')} |`),
].join('\n');
writeFileSync(join(values.out!, 'report.md'), report + '\n', {mode: 0o600});
console.log(report);
