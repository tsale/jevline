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
