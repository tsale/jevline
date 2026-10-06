// Throughput benchmark. With no arguments it hides the test incident (test/incident.ts) in
// synthetic background activity at several sizes, writes it as NDJSON, CSV and text, and runs the
// CLI on each (offline stand-in, one process per run). With files, it runs them as given.
//
//   node bench/bench.ts [--sizes 100000,300000,1000000]
//   node bench/bench.ts <log files...> --seed <selector>
import {spawnSync} from 'node:child_process';
import {closeSync, mkdtempSync, openSync, rmSync, statSync, writeSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {parseArgs} from 'node:util';
import {unfold, type ProcessRow} from '../src/analyze.ts';
import {csvLines, ecs, EVENTS, explorer, textLines, type Ev, type Proc} from '../test/incident.ts';

const CLI = join(import.meta.dirname, '..', 'src', 'cli.ts');
const EXPECTED = ['cmd.exe:3100', 'invoice.exe:2000', 'sihost.exe:3000', 'stage2.exe:2100', 'upd.exe:4000', 'whoami.exe:3110'];

/** About `size` events of everyday activity over six days around the incident, deterministic. */
function background(size: number): Ev[] {
  let x = 42;
  const rand = () => (x = (x * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
  const pick = <T>(items: T[]) => items[Math.floor(rand() * items.length)]!;
  const images = ['svchost.exe', 'chrome.exe', 'msedge.exe', 'OneDrive.exe', 'conhost.exe', 'backgroundTaskHost.exe', 'git.exe', 'node.exe', 'python.exe', 'Teams.exe'];
  const running: Proc[] = [explorer];
  const events: Ev[] = [];
  let n = 100;
  while (events.length < size) {
    const t = -2 * 86400 + rand() * 6 * 86400;
    const image = pick(images), pid = 10000 + Math.floor(rand() * 50000);  // PIDs get reused
    const p: Proc = {guid: `5EED0000-0000-0000-${String(n++).padStart(4, '0')}-${String(Math.floor(rand() * 1e12)).padStart(12, '0')}`,
      pid, image: `C:\\Program Files\\Vendor\\${image}`, cmd: `${image} --type=worker --id=${n}`, parent: pick(running)};
    running.push(p);
    if (running.length > 500) running.splice(1, 1);
    events.push({code: 1, t, p});
    const activity = Math.floor(rand() * 12);
    for (let i = 0; i < activity; i++) {
      const at = t + rand() * 600;
      const r = rand();
      if (r < 0.35) events.push({code: 11, t: at, p, path: `C:\\Users\\alice\\AppData\\Local\\Vendor\\cache\\${Math.floor(rand() * 1e6)}.tmp`});
      else if (r < 0.6) events.push({code: 13, t: at, p, key: `HKU\\S-1-5-21-1\\Software\\Vendor\\${image}\\State${Math.floor(rand() * 50)}`, value: `DWORD (0x${Math.floor(rand() * 255).toString(16)})`});
      else if (r < 0.75) events.push({code: 3, t: at, p, ip: `198.51.100.${Math.floor(rand() * 255)}`, port: pick([443, 80, 8080])});
      else if (r < 0.85) events.push({code: 22, t: at, p, query: `${pick(['cdn', 'api', 'telemetry'])}.vendor-${Math.floor(rand() * 40)}.example`});
      else events.push({code: 10, t: at, p, target: pick(running), access: rand() < 0.02 ? '0x1fffff' : pick(['0x1410', '0x1000', '0x40'])});
    }
    events.push({code: 5, t: t + 600 + rand() * 3600, p});
  }
  return [...events, ...EVENTS].sort((a, b) => a.t - b.t);
}

interface Result { label: string; mb: number; records: number; processes: number; links: number; timings: Record<string, number>; memory: number; requests: number; incident: string[] }

function run(label: string, files: string[], seed: string): Result {
  const started = performance.now();
  const child = spawnSync(process.execPath, [CLI, 'analyze', ...files, '--seed', seed, '--context', 'Benchmark.', '--offline', '--json', '--max-candidates', '100000'],
    {encoding: 'utf8', maxBuffer: 1 << 30});
  if (child.status !== 0) throw new Error(`${label}: ${child.stderr}`);
  const report = JSON.parse(child.stdout) as {counts: {records: number; processes: number; links: number}; timings_ms: Record<string, number>;
    peak_memory_mb: number; jev: {requests: number}; incident: ProcessRow[]};
  return {label, mb: files.reduce((s, f) => s + statSync(f).size, 0) / 2 ** 20, records: report.counts.records, processes: report.counts.processes,
    links: report.counts.links, timings: {...report.timings_ms, wall: performance.now() - started}, memory: report.peak_memory_mb,
    requests: report.jev.requests, incident: unfold(report.incident).map(p => `${p.name}:${p.pid}`).sort()};
}

/** Write lines in batches: a large export does not fit in one JavaScript string. */
function writeLines(path: string, lines: string[], eol: string) {
  const fd = openSync(path, 'w');
  try { for (let i = 0; i < lines.length; i += 10_000) writeSync(fd, lines.slice(i, i + 10_000).join(eol) + eol); } finally { closeSync(fd); }
}

const s = (ms = 0) => (ms / 1000).toFixed(2);
function print(results: Result[]) {
  console.log(`| Input | Size | Records | Processes | Links | Read + normalize | Processes | Links | Jev rounds* | Total | Records/s | Peak memory |`);
  console.log(`|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|`);
  for (const r of results) {
    const t = r.timings;
    console.log(`| ${r.label} | ${r.mb.toFixed(0)} MB | ${r.records.toLocaleString('en-US')} | ${r.processes.toLocaleString('en-US')} | ${r.links.toLocaleString('en-US')} | ` +
      `${s(t.read_normalize)} s | ${s(t.identify_processes)} s | ${s(t.build_links)} s | ${s(t.investigate)} s (${r.requests} req.) | ${s(t.total)} s | ` +
      `${Math.round(r.records / (t.total! / 1000)).toLocaleString('en-US')} | ${r.memory} MB |`);
  }
  console.log('\n* Offline stand-in, so this is the engine\'s own time; real Jev adds network time per round.');
}

const {values, positionals} = parseArgs({allowPositionals: true, options: {seed: {type: 'string'}, sizes: {type: 'string', default: '100000,300000,1000000'}}});
if (positionals.length) {
  if (!values.seed) throw new Error('--seed is required with files');
  print([run(positionals.join(' + '), positionals, values.seed)]);
} else {
  const dir = mkdtempSync(join(tmpdir(), 'jevline-bench-'));
  try {
    const results: Result[] = [];
    for (const size of values.sizes!.split(',').map(Number)) {
      const events = background(size);
      const files: [string, () => string[], string][] = [['ndjson', () => ecs(events), '\n'], ['csv', () => csvLines(events), '\r\n'], ['log', () => textLines(events), '\n']];
      for (const [ext, lines, eol] of files) {
        const path = join(dir, `${size}.${ext}`);
        writeLines(path, lines(), eol);
        const result = run(`${size.toLocaleString('en-US')} events, ${ext === 'ndjson' ? 'NDJSON (+4688 twins)' : ext === 'csv' ? 'CSV' : 'text'}`, [path], 'name:invoice.exe');
        if (JSON.stringify(result.incident) !== JSON.stringify(EXPECTED)) throw new Error(`${result.label}: found ${result.incident.join(', ')}`);
        results.push(result);
        rmSync(path);
      }
    }
    print(results);
    console.log('Every run found exactly the planted incident:', EXPECTED.join(', '));
  } finally {
    rmSync(dir, {recursive: true, force: true});
  }
}
