// Reproducibility: the same incident in different telemetry must give Jev the same requests and
// produce the same incident; running twice, in parallel or from the cache must change nothing.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {analyze, findSeed, load, unfold} from '../src/analyze.ts';
import {JevClient, type Transport} from '../src/jev.ts';
import {standIn} from '../src/standin.ts';
import {csv, defend, ecs, EVENTS, shuffle, text} from './incident.ts';

const dir = mkdtempSync(join(tmpdir(), 'jevline-repro-'));
test.after(() => rmSync(dir, {recursive: true, force: true}));

let files = 0;
const file = (content: string, ext: string) => { const path = join(dir, `${files++}.${ext}`); writeFileSync(path, content); return path; };

interface Run { bodies: string[]; incident: string[]; rejected: string[]; transportCalls: number; requests: number; cached: number; asked: string[] }

async function run(paths: string[], {batch = 1, concurrency = 8, cacheFile, group = true}: {batch?: number; concurrency?: number; cacheFile?: string; group?: boolean} = {}): Promise<Run> {
  const loaded = await load(paths.map(path => ({path, format: 'auto' as const})));
  const {key} = findSeed(loaded, 'name:invoice.exe');
  const bodies: string[] = [];
  const inner = standIn();
  const transport: Transport = body => { bodies.push(body); return inner(body); };
  const client = new JevClient(transport, {concurrency, ...(cacheFile ? {cacheFile} : {})});
  const {report} = await analyze(loaded, key, client, {description: 'Analyst-confirmed invoice.exe execution on WS-01.', model: 'jev-1.13.0',
    threshold: 0.8, batchSize: batch, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test', group});
  const name = (p: {type: string; name?: string; pid?: number}) => p.type === 'process' ? `${p.name}:${p.pid}` : `${p.type}:${p.name}`;
  const asked = bodies.flatMap(b => Object.values((JSON.parse(b) as {state: {candidates: Record<string, {name: string}>}}).state.candidates).map(c => c.name));
  return {bodies: bodies.sort(), incident: unfold(report.incident).map(name), rejected: unfold(report.rejected).map(name), transportCalls: bodies.length,
    requests: report.jev.requests, cached: report.jev.answered_from_cache, asked: asked.sort()};
}

// The processes, and the C2 address and domain only the incident's processes contacted.
const EXPECTED = ['invoice.exe:2000', 'stage2.exe:2100', 'sihost.exe:3000', 'cmd.exe:3100', 'whoami.exe:3110', 'upd.exe:4000',
  'ip:203.0.113.9', 'domain:evil.example'];

test('the incident: injection, drop and run, persistence, causality and noise', async () => {
  const result = await run([file(ecs().join('\n'), 'ndjson')]);
  assert.deepEqual(result.incident.toSorted(), EXPECTED.toSorted());
  // rundll32 only shares a pipe and explorer was only opened with full access: the stand-in scores both 0.5 or less.
  assert.deepEqual(result.rejected.toSorted(), ['explorer.exe:1000', 'rundll32.exe:5000']);
  // taskhostw.exe was started by sihost.exe 30 minutes before the injection, so it is never asked about,
  // and chrome.exe (started by explorer.exe, which never joined) is not a candidate either.
  assert.deepEqual(result.asked, ['203.0.113.9', 'cmd.exe', 'evil.example', 'explorer.exe', 'rundll32.exe', 'sihost.exe', 'stage2.exe', 'upd.exe', 'whoami.exe']);
  assert.equal(result.bodies.some(b => b.includes('taskhostw.exe')), false);
  // stage2.exe's credential read of lsass.exe is not a link, but Jev sees it as stage2's activity.
  assert.ok(result.bodies.some(b => b.includes('"accessed":["lsass.exe (0x1410)"]')));
});

test('equivalent telemetry sends Jev byte-identical requests', async () => {
  const reference = await run([file(ecs().join('\n'), 'ndjson')]);
  const variants: Record<string, string[]> = {
    'Splunk CSV (Sysmon names, FQDN hosts, DOMAIN\\user)': [file(csv(), 'csv')],
    'key=value text': [file(text(), 'log')],
    'shuffled lines': [file(shuffle(ecs()).join('\n'), 'ndjson')],
    'Sysmon and Security in separate files': [file(ecs(EVENTS, {security: false}).join('\n'), 'ndjson'), file(ecs(EVENTS, {sysmon: false}).join('\n'), 'ndjson')],
    'Security first, then Sysmon': [file(ecs(EVENTS, {sysmon: false}).join('\n'), 'ndjson'), file(ecs(EVENTS, {security: false}).join('\n'), 'ndjson')],
    'CSV and text together (duplicates of every event)': [file(csv(), 'csv'), file(text(), 'log')],
  };
  for (const [name, paths] of Object.entries(variants)) {
    const result = await run(paths);
    assert.deepEqual(result.incident, reference.incident, `${name}: same incident`);
    assert.deepEqual(result.bodies, reference.bodies, `${name}: same Jev requests`);
  }
});

test('Sysmon without process-creation events, with starts from Security 4688, finds the same incident', async () => {
  // A common Sysmon configuration: no event 1, so every process start comes from Security 4688
  // (no GUID, no hashes) and every other Sysmon event carries a GUID the start never had.
  const reference = await run([file(ecs().join('\n'), 'ndjson')]);
  const noSysmonStarts = ecs(EVENTS.filter(e => e.code !== 1), {security: false}).concat(ecs(EVENTS.filter(e => e.code === 1 || e.code === 5), {sysmon: false}));
  const result = await run([file(noSysmonStarts.join('\n'), 'ndjson')]);
  assert.deepEqual(result.incident, reference.incident);
  assert.deepEqual(result.rejected, reference.rejected);
});

test('Security 4688 alone finds the lineage it can see, and says nothing it cannot', async () => {
  const result = await run([file(ecs(EVENTS, {sysmon: false}).join('\n'), 'ndjson')]);
  assert.deepEqual(result.incident.toSorted(), ['invoice.exe:2000', 'stage2.exe:2100']);
  // The PID-reused notepad.exe (same PID as the seed, an hour earlier) stays a different process.
  assert.deepEqual(result.asked, ['stage2.exe']);
  assert.equal(result.bodies.some(b => b.includes('notepad.exe')), false);
});

test('batch size, concurrency and grouping do not change the decisions', async () => {
  const path = file(ecs().join('\n'), 'ndjson');
  const reference = await run(path ? [path] : []);
  for (const options of [{batch: 25, concurrency: 1}, {batch: 2, concurrency: 64}, {batch: 1, concurrency: 1, group: false}]) {
    const result = await run([path], options);
    assert.deepEqual(result.incident, reference.incident, JSON.stringify(options));
    assert.deepEqual(result.rejected, reference.rejected, JSON.stringify(options));
  }
});

test('a repeated run is answered from the cache: same result, no calls', async () => {
  const path = file(ecs().join('\n'), 'ndjson'), cacheFile = join(dir, 'cache.jsonl');
  const first = await run([path], {cacheFile});
  const second = await run([path], {cacheFile});
  assert.ok(first.transportCalls > 0);
  assert.equal(second.transportCalls, 0);
  assert.equal(second.cached, first.requests);
  assert.deepEqual(second.incident, first.incident);
});

test('Sysmon and Elastic Defend together: each process once, under either source\'s ID, and the same incident', async () => {
  const sysmon = file(ecs().join('\n'), 'ndjson'), edr = file(defend().join('\n'), 'ndjson');
  const processes = async (paths: string[]) => [...(await load(paths.map(path => ({path, format: 'auto' as const})))).nodes.values()]
    .filter(n => n.type === 'process').length;
  assert.equal(await processes([sysmon, edr]), await processes([sysmon]));
  const alone = await run([sysmon]), both = await run([sysmon, edr]), defendOnly = await run([edr]);
  assert.deepEqual(both.incident.toSorted(), alone.incident.toSorted());
  // Elastic Defend alone records no named pipes or handle access, but lineage, injection, drops and persistence carry the incident.
  assert.deepEqual(defendOnly.incident.toSorted(), EXPECTED.toSorted());
  // The seed by either source's ID: Sysmon's GUID in any case, or Elastic Defend's case-sensitive entity ID.
  const loaded = await load([{path: sysmon, format: 'auto'}, {path: edr, format: 'auto'}]);
  const seed = findSeed(loaded, 'name:invoice.exe').key;
  const entityId = defend().map(line => JSON.parse(line) as {event: {type: string[]}; process: {name: string; entity_id: string}})
    .find(d => d.process.name === 'invoice.exe' && d.event.type[0] === 'start')!.process.entity_id;
  assert.equal(findSeed(loaded, `guid:${entityId}`).key, seed);
  assert.equal(findSeed(loaded, `guid:{${EVENTS.find(e => e.code === 1 && e.p.pid === 2000 && e.t === 0)!.p.guid.toLowerCase()}}`).key, seed);
  assert.throws(() => findSeed(loaded, `guid:${entityId.toLowerCase()}`), /no process with GUID/);
});
