// Logs without processes: accounts, hosts, addresses and domains carry an intrusion too.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {analyze, findSeed, load, unfold} from '../src/analyze.ts';
import {JevClient} from '../src/jev.ts';
import {standIn} from '../src/standin.ts';
import {learn, SchemaCache} from '../src/schema.ts';
import {readText} from '../src/read.ts';
import {normalize} from '../src/normalize.ts';
import {ecs} from './incident.ts';
import {ATTACKER, authCsv, authJson, C2, firewallCsv, webJson} from './network.ts';

const dir = mkdtempSync(join(tmpdir(), 'jevline-entities-'));
test.after(() => rmSync(dir, {recursive: true, force: true}));
let n = 0;
const file = (content: string, name: string) => { const path = join(dir, `${n++}-${name}`); writeFileSync(path, content); return path; };

interface Run { incident: string[]; rejected: string[]; links: Record<string, number> }

async function run(paths: string[], seed: string): Promise<Run> {
  const learner = async (profiles: Parameters<typeof learn>[0]) => learn(profiles, new JevClient(standIn()), new SchemaCache(), 'jev-1.13.0', 'stand-in');
  const loaded = await load(paths.map(path => ({path, format: 'auto' as const})), {learn: learner});
  const {report} = await analyze(loaded, findSeed(loaded, seed).key, new JevClient(standIn()), {description: 'Confirmed malicious.', model: 'm',
    threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test'});
  const name = (p: {type: string; name?: string; pid?: number}) => p.type === 'process' ? `${p.name}:${p.pid}` : `${p.type}:${p.name}`;
  return {incident: unfold(report.incident).map(name).sort(), rejected: unfold(report.rejected).map(name).sort(), links: report.counts.links_by_type as Record<string, number>};
}

test('Windows logons become account, host and address links', () => {
  const doc = (code: string, ip: string) => JSON.stringify({'@timestamp': '2026-09-21T17:00:00Z', host: {name: 'SRV-01', ip: ['fe80::1', '10.0.1.10']},
    event: {code, dataset: 'system.security'}, winlog: {channel: 'Security', event_data: {TargetUserName: 'CORP\\svc_backup', IpAddress: ip, IpPort: '50123', LogonType: '10'}}});
  const events = [...readText(`${doc('4624', ATTACKER)}\n${doc('4625', '-')}`)].map((r, i) => normalize(r, 0, i)!);
  assert.deepEqual([events[0]!.kind, events[0]!.account, events[0]!.src, events[0]!.logon_type, events[0]!.host_ips],
    ['logon', 'svc_backup', {ip: ATTACKER, port: 50123}, '10', ['10.0.1.10']]);
  assert.deepEqual([events[1]!.kind, events[1]!.src], ['logon_failed', {port: 50123}], 'a "-" address is no address');
});

test('from an attacker address: the account it used, the hosts it reached, and nothing common', async () => {
  const result = await run([file(authJson(), 'auth.jsonl'), file(firewallCsv(), 'firewall.csv'), file(webJson(), 'web.jsonl')], `ip:${ATTACKER}`);
  assert.deepEqual(result.incident, ['host:db-01', 'host:srv-01', 'host:web-01', `ip:${ATTACKER}`, 'user:svc_backup']);
  // The servers' later lookups reach the shared resolver, which everyone uses: asked about, not linked.
  assert.ok(result.rejected.includes('ip:8.8.8.8'));
  // Other visitors of the compromised web server are asked about and rejected; unrelated accounts and
  // the brute force against another account are never even candidates.
  assert.ok(result.rejected.includes('host:ws-01') && result.rejected.includes('ip:203.0.113.77'));
  for (const quiet of ['user:alice', 'user:bob', 'user:dba', 'user:admin', 'ip:192.0.2.50', 'host:ws-02']) {
    assert.ok(!result.incident.includes(quiet) && !result.rejected.includes(quiet), `${quiet} is never a candidate`);
  }
  assert.ok(result.links.used_account! >= 1 && result.links.logon_from! >= 1 && result.links.requested! >= 1 && result.links.contacted! >= 1);
});

test('the same authentication log in another format finds the same incident', async () => {
  const json = await run([file(authJson(), 'a.jsonl'), file(firewallCsv(), 'f.csv'), file(webJson(), 'w.jsonl')], `ip:${ATTACKER}`);
  const csv = await run([file(authCsv(), 'a.csv'), file(firewallCsv(), 'f2.csv'), file(webJson(), 'w2.jsonl')], `ip:${ATTACKER}`);
  assert.deepEqual(csv.incident, json.incident);
});

test('from a malware process to its C2, and from the C2 to another host that reached it later', async () => {
  const result = await run([file(ecs().join('\n'), 'sysmon.ndjson'), file(firewallCsv(), 'fw.csv'), file(authJson(), 'auth2.jsonl')], 'name:invoice.exe');
  for (const expected of [`ip:${C2}`, 'domain:evil.example', 'host:ws-01', 'host:ws-02', 'invoice.exe:2000', 'stage2.exe:2100', 'upd.exe:4000']) {
    assert.ok(result.incident.includes(expected), `${expected} in ${result.incident.join(', ')}`);
  }
  assert.ok(!result.incident.includes('ip:8.8.8.8'));
});

test('a seed must exist, and an event that names no process cannot seed by itself', async () => {
  const loaded = await load([{path: file(authJson(), 'auth3.jsonl'), format: 'auto'}],
    {learn: profiles => learn(profiles, new JevClient(standIn()), new SchemaCache(), 'm', 'stand-in')});
  assert.throws(() => findSeed(loaded, 'ip:203.0.113.250'), /no ip 203.0.113.250/);
  assert.throws(() => findSeed(loaded, 'line-1'), /names no process; seed with ip:, user:, host: or domain:/);
  assert.equal(findSeed(loaded, 'user:CORP\\svc_backup').key, 'user:svc_backup');
  assert.equal(findSeed(loaded, 'host:SRV-01.corp.example').key, 'host:srv-01');
});

test('infrastructure only the incident touched links at the lower entity threshold; shared infrastructure does not', async () => {
  const {EVENTS, explorer} = await import('./incident.ts');
  // Explorer, not part of the incident, also looks up evil.example; only the incident contacts 203.0.113.9.
  const path = file(ecs([...EVENTS, {code: 22, t: 130, p: explorer, query: 'evil.example'}]).join('\n') + '\n', 'shared.ndjson');
  const base = standIn();
  const entitiesAt = (p: number) => async (body: string) => {
    const response = await base(body);
    const {state} = JSON.parse(body) as {state: {candidates?: Record<string, {type: string; seen_outside_incident?: unknown}>}};
    for (const [label, c] of Object.entries(state.candidates ?? {})) if (c.type !== 'process') response.answers[label] = {type: 'noul', noul: p};
    return response;
  };
  const loaded = await load([{path, format: 'auto' as const}]);
  const options = {description: 'Confirmed malicious.', model: 'm', threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test'};
  const {report} = await analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, new JevClient(entitiesAt(0.6)), options);
  const decided = (rows: typeof report.incident) => Object.fromEntries(unfold(rows).filter(r => r.type !== 'process').map(r => [r.name, r.joined?.threshold]));
  assert.deepEqual(decided(report.incident), {'203.0.113.9': 0.5}, 'exclusive C2 address joins at 0.6');
  assert.deepEqual(decided(report.rejected), {'evil.example': 0.8}, 'a domain Explorer also looked up needs 0.8');
  assert.equal(report.jev.entity_threshold, 0.5);
  const strict = await analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, new JevClient(entitiesAt(0.6)), {...options, entityThreshold: 0.8});
  assert.deepEqual(unfold(strict.report.incident).filter(r => r.type !== 'process'), [], 'entityThreshold 0.8 restores the single threshold');
});

test('a file the incident wrote, started by persistence the incident registered, links at the lower threshold', async () => {
  const {EVENTS} = await import('./incident.ts');
  const base = standIn();
  // Jev scores the relaunched updater 0.6: below the process threshold, as for CLA-WS-216's SmcGui.exe.
  const updaterAt = (p: number) => async (body: string) => {
    const response = await base(body);
    const {state} = JSON.parse(body) as {state: {candidates?: Record<string, unknown>}};
    for (const [label, c] of Object.entries(state.candidates ?? {})) if ((c as {name?: string}).name === 'upd.exe') response.answers[label] = {type: 'noul', noul: p};
    return response;
  };
  const options = {description: 'Confirmed malicious.', model: 'm', threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test'};
  const updater = async (events: typeof EVENTS) => {
    const loaded = await load([{path: file(ecs(events).join('\n') + '\n', 'relaunch.ndjson'), format: 'auto' as const}]);
    const {report} = await analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, new JevClient(updaterAt(0.6)), options);
    const find = (rows: typeof report.incident) => unfold(rows).find(r => r.name === 'upd.exe');
    return {joined: find(report.incident), rejected: find(report.rejected)};
  };
  const relaunch = await updater(EVENTS);
  assert.equal(relaunch.joined?.joined?.threshold, 0.5, 'dropped by stage2 and started by its Run key: joins at 0.6');
  const dropped = await updater(EVENTS.filter(e => e.code !== 13));  // no Run key: only dropped_and_ran
  assert.equal(dropped.joined, undefined);
  assert.equal(dropped.rejected?.joined?.threshold ?? 0.8, 0.8, 'a dropped file alone still needs the process threshold');
});

test('a DNS answer the resolver relayed does not make a domain shared', async () => {
  const {EVENTS, seed, T0} = await import('./incident.ts');
  const answer = JSON.stringify({'@timestamp': new Date(T0 + 2500).toISOString(), host: {name: 'WS-01'},
    event: {category: ['network'], type: ['protocol', 'info'], action: 'lookup_result', dataset: 'endpoint.events.network'},
    process: {name: 'svchost.exe', pid: 900, entity_id: 'dns-client-service', executable: 'C:\\Windows\\System32\\svchost.exe'},
    dns: {question: {name: 'only.example'}, resolved_ip: ['198.51.100.7']}});
  const events = [...EVENTS, {code: 22 as const, t: 2.4, p: seed, query: 'only.example'}];
  const path = file([...ecs(events), answer].join('\n') + '\n', 'relayed.ndjson');
  const base = standIn();
  const entities = async (body: string) => {
    const response = await base(body);
    for (const [label, c] of Object.entries((JSON.parse(body) as {state: {candidates?: Record<string, {type: string}>}}).state.candidates ?? {}))
      if (c.type !== 'process') response.answers[label] = {type: 'noul', noul: 0.6};
    return response;
  };
  const loaded = await load([{path, format: 'auto' as const}]);
  assert.ok(loaded.events.some(e => e.kind === 'dns' && e.dns_answer), 'the lookup_result is read as a relayed answer');
  const {report} = await analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, new JevClient(entities),
    {description: 'Confirmed malicious.', model: 'm', threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test'});
  const only = unfold(report.incident).find(r => r.name === 'only.example');
  assert.equal(only?.joined?.threshold, 0.5, 'only the incident asked for it');
});

test('the reported context alone rebuilds the incident, and shared infrastructure stays shared', async () => {
  const {EVENTS, explorer} = await import('./incident.ts');
  const lines = ecs([...EVENTS, {code: 22, t: 130, p: explorer, query: 'evil.example'}]);
  const path = file(lines.join('\n') + '\n', 'full.ndjson');
  const options = {description: 'Confirmed malicious.', model: 'm', threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test', context: true};
  const loaded = await load([{path, format: 'auto' as const}]);
  const full = (await analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, new JevClient(standIn()), options)).report;
  assert.ok(full.context && full.context.length < lines.length, 'the context is a subset of the input');
  const subset = file(full.context!.map(([, line]) => lines[line - 1]).join('\n') + '\n', 'context.ndjson');
  const again = await load([{path: subset, format: 'auto' as const}]);
  const rebuilt = (await analyze(again, findSeed(again, 'name:invoice.exe').key, new JevClient(standIn()), options)).report;
  const names = (rows: typeof full.incident) => unfold(rows).map(r => `${r.type}:${r.name}:${r.pid ?? ''}`).sort();
  assert.deepEqual(names(rebuilt.incident), names(full.incident));
  const shared = (r: typeof full) => unfold([...r.incident, ...r.rejected]).find(x => x.name === 'evil.example')?.joined?.threshold;
  assert.equal(shared(rebuilt), 0.8, 'Explorer\'s lookup of evil.example is kept, so it still needs 0.8');
});

test('analyst-confirmed starting points join the incident beside the seed in one investigation', async () => {
  const path = file(ecs().join('\n') + '\n', 'confirmed.ndjson');
  const loaded = await load([{path, format: 'auto' as const}]);
  const seed = findSeed(loaded, 'name:invoice.exe').key, rundll = findSeed(loaded, 'name:rundll32.exe').key;
  const options = {description: 'Confirmed malicious.', model: 'm', threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test'};
  const alone = (await analyze(loaded, seed, new JevClient(standIn()), options)).report;
  assert.ok(!unfold(alone.incident).some(r => r.name === 'rundll32.exe'), 'the stand-in does not link rundll32 from the seed');
  const {report} = await analyze(loaded, seed, new JevClient(standIn()), {...options, confirmed: [rundll]});
  const row = unfold(report.incident).find(r => r.name === 'rundll32.exe');
  assert.equal(row?.confirmed, true);
  assert.equal(row?.joined, undefined, 'no Jev decision for a confirmed member');
  assert.ok(report.timeline.some(t => t.process === 'rundll32.exe'), 'its activity is in the timeline');
});
