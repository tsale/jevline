// Repeated activity is reported once: a beacon, a brute force or a relaunched command is one row with
// a count, while anything that changes, or activity that resumes after a long pause, is a row of its own.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {analyze, findSeed, load, unfold, type Report} from '../src/analyze.ts';
import {JevClient} from '../src/jev.ts';
import {standIn} from '../src/standin.ts';
import {learn, SchemaCache} from '../src/schema.ts';
import {identicalMembers, interval, QUIET, runs, sameDetail, variable} from '../src/repeats.ts';
import type {Link, ProcessNode} from '../src/model.ts';
import {ecs, EVENTS, T0, type Ev, type Proc} from './incident.ts';
import {ATTACKER, authJson, C2} from './network.ts';

const dir = mkdtempSync(join(tmpdir(), 'jevline-repeats-'));
test.after(() => rmSync(dir, {recursive: true, force: true}));
let n = 0;
const file = (content: string, name: string) => { const path = join(dir, `${n++}-${name}`); writeFileSync(path, content); return path; };

async function run(paths: string[], seed: string): Promise<Report> {
  const learner = async (profiles: Parameters<typeof learn>[0]) => learn(profiles, new JevClient(standIn()), new SchemaCache(), 'jev-1.13.0', 'stand-in');
  const loaded = await load(paths.map(path => ({path, format: 'auto' as const})), {learn: learner});
  const {report} = await analyze(loaded, findSeed(loaded, seed).key, new JevClient(standIn()), {description: 'Confirmed malicious.', model: 'm',
    threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test'});
  return report;
}

const S = 1e6, MIN = 60 * S, H = 3600 * S;

test('runs: one per stretch of the same activity, split by a long pause, never across different activity', () => {
  const series = (key: string, times: number[]) => times.map(t => ({key, t}));
  const beacon = series('beacon', [...Array.from({length: 120}, (_, i) => i * MIN), ...Array.from({length: 10}, (_, i) => 10 * H + i * MIN)]);
  const hourly = series('task', Array.from({length: 24}, (_, i) => i * H + (i % 3) * MIN));  // an hourly task with some jitter
  const twice = series('rare', [0, 3 * 24 * H]);
  const items = [...beacon, ...hourly, ...twice].sort((a, b) => a.t - b.t);
  const found = runs(items, x => x.key, x => x.t).map(r => [items[r[0]!]!.key, r.length]);
  assert.deepEqual(found, [['beacon', 120], ['task', 24], ['rare', 1], ['beacon', 10], ['rare', 1]]);
  assert.equal(interval(beacon.slice(0, 120).map(x => x.t)), 60);
  assert.equal(interval([0, 5 * S]), undefined, 'two occurrences say nothing about a cycle');
  assert.ok(QUIET === H);
});

test('numbers and generated tokens are not a change, except in the names of executables', () => {
  assert.equal(variable('C:\\Users\\HELENA~1.CAR\\AppData\\Local\\Temp\\is-OB9B3JUD4C.tmp\\spoolsv.tmp /SL5="$8D0572,3755066"'),
    'C:\\Users\\HELENA~#.CAR\\AppData\\Local\\Temp\\is-#.tmp\\spoolsv.tmp /SL5="$#,#"');
  assert.equal(variable('C:\\Program Files (x86)\\Microsoft\\Edge'), 'C:\\Program Files (x86)\\Microsoft\\Edge', 'words stay');
  const cache = (name: string) => sameDetail('file_create', `C:\\Temp\\Cache_Data\\${name}`);
  assert.equal(cache('f_00a1b2'), cache('f_00a1c9'));
  const drop = (name: string) => sameDetail('file_create', `C:\\Temp\\${name}`);
  assert.notEqual(drop('ejlunwg0.exe'), drop('2018r20m.exe'), 'two dropped executables are two things');
  assert.notEqual(sameDetail('network', '203.0.113.9:443'), sameDetail('network', '203.0.113.10:443'), 'addresses must match exactly');
});

// The Sysmon incident, plus a beacon from the seed to its C2 every minute for two hours, a pause of
// eight hours, then ten more; one beacon to another port; and stage2 running the same command ten times.
const seedProc = EVENTS.find(e => e.code === 1 && e.p.pid === 2000 && e.t === 0)!.p;
const stage2 = EVENTS.find(e => e.code === 1 && e.p.pid === 2100)!.p;
const sihost = EVENTS.find(e => e.code === 8)!.target;  // injected by the seed at +12 s
const ping = (i: number): Proc => ({guid: `26BBF027-0000-6AB1-${String(100 + i).padStart(4, '0')}-000000005C00`, pid: 7000 + i,
  image: 'C:\\Windows\\System32\\PING.EXE', cmd: `ping -n 1 ${C2}`, parent: stage2});
const extra: Ev[] = [
  ...Array.from({length: 120}, (_, i) => ({code: 3 as const, t: 63 + i * 60, p: seedProc, ip: C2, port: 443})),
  ...Array.from({length: 10}, (_, i) => ({code: 3 as const, t: 63 + 119 * 60 + 8 * 3600 + i * 60, p: seedProc, ip: C2, port: 443})),
  {code: 3, t: 90, p: seedProc, ip: C2, port: 8443},
  ...Array.from({length: 10}, (_, i) => ({code: 1 as const, t: 50 + i * 20, p: ping(i)})),
  // stage2 fills a cache (one activity) and drops two executables (two things).
  ...Array.from({length: 50}, (_, i) => ({code: 11 as const, t: 31 + i / 10, p: stage2, path: `C:\\Users\\alice\\Cache\\f_${(0xa100 + i).toString(16).padStart(6, '0')}`})),
  {code: 11, t: 36, p: stage2, path: 'C:\\Users\\alice\\AppData\\Local\\Temp\\a1b2c3d4.exe'},
  {code: 11, t: 37, p: stage2, path: 'C:\\Users\\alice\\AppData\\Local\\Temp\\e5f6a7b8.exe'},
  // Numbered registry keys with the same value are one activity; another value is another.
  ...Array.from({length: 5}, (_, i) => ({code: 13 as const, t: 32 + i, p: stage2, key: `HKU\\S-1-5-21-1\\Software\\RecentDocs\\${i}`, value: 'x'})),
  {code: 13, t: 38, p: stage2, key: 'HKU\\S-1-5-21-1\\Software\\RecentDocs\\9', value: 'y'},
  // sihost's own activity before the injection is not the incident's; after it, it is.
  {code: 11, t: 5, p: sihost, path: 'C:\\Users\\alice\\before-injection.txt'},
  {code: 11, t: 25, p: sihost, path: 'C:\\Users\\alice\\after-injection.txt'},
];
const events = [...EVENTS, ...extra].sort((a, b) => a.t - b.t);

test('a beacon is one row per stretch, a relaunched command one row, and the incident is unchanged', async () => {
  const plain = await run([file(ecs().join('\n'), 'plain.ndjson')], 'name:invoice.exe');
  const report = await run([file(ecs(events).join('\n'), 'beacon.ndjson')], 'name:invoice.exe');
  const name = (p: {type: string; name?: string; pid?: number}) => p.type === 'process' ? `${p.name}:${p.pid}` : `${p.type}:${p.name}`;
  // The same members as without the repeats, plus the ten pings, which are one row.
  const members = unfold(report.incident).map(name).sort();
  assert.deepEqual(members.filter(m => !m.startsWith('PING.EXE')), unfold(plain.incident).map(name).sort());
  assert.equal(members.filter(m => m.startsWith('PING.EXE')).length, 10);
  const pings = report.incident.filter(p => p.name === 'PING.EXE');
  assert.equal(pings.length, 1);
  assert.equal(pings[0]!.repeats!.count, 10);
  assert.deepEqual(pings[0]!.repeats!.others.map(o => o.pid), [7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009]);
  assert.equal(pings[0]!.repeats!.last_start, new Date(T0 + 230_000).toISOString().replace('Z', '000Z'));

  const rows = (kind: string, detail: string) => report.timeline.filter(r => r.process === 'invoice.exe' && r.kind === kind && r.detail === detail);
  // The first contact and two hours of beacons, then, after the pause, the ten that resumed.
  assert.deepEqual(rows('network', `${C2}:443`).map(r => [r.count, r.every_s]), [[121, 60], [10, 60]]);
  assert.equal(rows('network', `${C2}:443`)[0]!.until_since_seed, '+02:00:03');
  assert.deepEqual(rows('network', `${C2}:8443`).map(r => r.count), [undefined], 'another port is another row');
  // Ten starts of the same command by the same parent: one row, counted once per process (not per Sysmon and Security record).
  const starts = report.timeline.filter(r => r.kind === 'process_start' && r.process === 'PING.EXE');
  assert.deepEqual(starts.map(r => [r.count, r.every_s]), [[10, 20]]);
  assert.equal(report.counts.timeline_events - report.timeline.length > 150, true);
  const writes = report.timeline.filter(r => r.process === 'stage2.exe' && r.kind === 'file_create');
  const cache = writes.filter(r => r.detail?.includes('\\Cache\\'));
  assert.deepEqual(cache.map(r => [r.detail, r.count, r.variants]), [['C:\\Users\\alice\\Cache\\f_00a100', 50, 50]]);
  assert.deepEqual(writes.filter(r => r.detail?.endsWith('.exe') && r.detail.includes('Temp')).map(r => r.count), [undefined, undefined]);
  const recent = report.timeline.filter(r => r.kind === 'registry_set' && r.detail?.includes('RecentDocs'));
  assert.deepEqual(recent.map(r => [r.detail, r.count, r.variants]), [['HKU\\S-1-5-21-1\\Software\\RecentDocs\\0 = x', 5, 5], ['HKU\\S-1-5-21-1\\Software\\RecentDocs\\9 = y', undefined, undefined]]);
  const sihostRows = report.timeline.filter(r => r.process === 'sihost.exe').map(r => r.detail);
  assert.ok(sihostRows.includes('C:\\Users\\alice\\after-injection.txt') && !sihostRows.includes('C:\\Users\\alice\\before-injection.txt'));
});

test('a brute force is one row, and the logon that succeeded stays its own', async () => {
  const iso = (t: number) => new Date(T0 + t * 1000).toISOString();
  const burst = Array.from({length: 200}, (_, i) => JSON.stringify({ts: iso(61 + i), event: 'login_failure', user: 'svc_backup',
    src_ip: ATTACKER, dst_host: 'srv-01', dst_ip: '10.0.1.10', method: 'rdp'})).join('\n') + '\n';
  const plain = await run([file(authJson(), 'auth.jsonl')], `ip:${ATTACKER}`);
  const report = await run([file(authJson() + burst, 'auth-burst.jsonl')], `ip:${ATTACKER}`);
  assert.deepEqual(report.incident.map(p => p.key), plain.incident.map(p => p.key));
  const failed = report.timeline.filter(r => r.kind === 'logon_failed');
  assert.deepEqual(failed.map(r => [r.detail, r.count, r.every_s]), [[`svc_backup from ${ATTACKER} type rdp`, 201, 1]]);
  assert.equal(report.timeline.filter(r => r.kind === 'logon' && r.detail?.startsWith(`svc_backup from ${ATTACKER}`)).length, 1);
});

test('identical members fold even when one is linked from a process that started after it', () => {
  const node = (key: string, start: number, parent?: string): ProcessNode => ({key, type: 'process', host: 'ws-01', name: key.replace(/\d$/, '.exe'),
    path: `C:\\Temp\\${key.replace(/\d$/, '.exe')}`, cmd: key.replace(/\d$/, '.exe'), start, firstSeen: start, end: null, events: [], starts: [0],
    ...(parent ? {parent} : {})});
  const nodes = new Map([node('seed0', 0), node('writer1', 1, 'seed0'), node('loop1', 10, 'seed0'), node('writer2', 11, 'seed0'), node('loop2', 20, 'seed0')].map(n => [n.key, n]));
  const link = (type: Link['type'], from: string, to: string): Link => ({type, from, to, t: 0, act: 0, last: 0, count: 1, evidence: []});
  const links: Record<string, Link[]> = {
    writer1: [link('spawned', 'seed0', 'writer1')], writer2: [link('spawned', 'seed0', 'writer2')],
    // The second writer (identical to the first) started just after loop1, as can happen between sources' clocks.
    loop1: [link('spawned', 'seed0', 'loop1'), link('dropped_and_ran', 'writer2', 'loop1')],
    loop2: [link('spawned', 'seed0', 'loop2'), link('dropped_and_ran', 'writer1', 'loop2')],
  };
  const same = identicalMembers(['seed0', 'writer1', 'loop1', 'writer2', 'loop2'], nodes, k => links[k], new Set(['seed0']));
  assert.deepEqual([same.get('writer2'), same.get('loop2')], ['writer1', 'loop1']);
});

test('a file rewritten right after a process started from it: the earlier writer dropped it', async () => {
  const proc = (n: number, pid: number, image: string): Proc => ({guid: `26BBF027-0000-6AB1-${String(200 + n).padStart(4, '0')}-000000005C00`, pid,
    image, cmd: image, parent: seedProc});
  const [first, second, loop, other] = [proc(1, 8001, 'C:\\Temp\\dropper.exe'), proc(2, 8002, 'C:\\Temp\\dropper.exe'),
    proc(3, 8003, 'C:\\Temp\\loop.exe'), proc(4, 8004, 'C:\\Temp\\late.exe')];
  const added: Ev[] = [{code: 1, t: 50, p: first}, {code: 11, t: 51, p: first, path: loop.image},
    {code: 1, t: 60, p: loop}, {code: 1, t: 60.2, p: second}, {code: 11, t: 60.3, p: second, path: loop.image},
    // With no earlier write, one within the clock difference between sources still counts.
    {code: 1, t: 70, p: other}, {code: 11, t: 70.5, p: first, path: other.image}];
  const loopEvents = [...EVENTS, ...added].sort((a, b) => a.t - b.t);
  const loaded = await load([{path: file(ecs(loopEvents, {security: false}).join('\n'), 'loop.ndjson'), format: 'auto'}]);
  const pidOf = (k: string) => loaded.nodes.get(k)?.pid;
  const drops = loaded.graph.links.filter(l => l.type === 'dropped_and_ran').map(l => [pidOf(l.from), pidOf(l.to)]);
  assert.ok(drops.some(([from, to]) => from === 8001 && to === 8003), JSON.stringify(drops));
  assert.ok(!drops.some(([from, to]) => from === 8002 && to === 8003), 'the next writer did not drop it');
  assert.ok(drops.some(([from, to]) => from === 8001 && to === 8004));
});
