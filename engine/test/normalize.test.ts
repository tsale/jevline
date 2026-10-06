import {test} from 'node:test';
import assert from 'node:assert/strict';
import {canonicalHost, canonicalUser, normalize, parseTime} from '../src/normalize.ts';
import {readText} from '../src/read.ts';
import type {Event} from '../src/model.ts';
import {resolveProcesses} from '../src/identity.ts';
import {buildLinks, injectionCapable, launchedPaths, pathKey} from '../src/links.ts';

const events = (text: string): Event[] => {
  const out: Event[] = [];
  for (const r of readText(text)) { const e = normalize(r, 0, out.length); if (e) out.push(e); }
  return out;
};
const one = (doc: object) => { const [e] = events(JSON.stringify(doc)); assert.ok(e, 'kept'); return e; };

test('times: ISO 8601 with any offset or precision, epoch milliseconds; locale formats refused', () => {
  const t = Date.UTC(2026, 8, 21, 17, 18, 50) * 1000;
  assert.equal(parseTime('2026-09-21T17:18:50Z'), t);
  assert.equal(parseTime('2026-09-21 17:18:50.1234567'), t + 123456, 'Sysmon UtcTime: naive is UTC, 7 digits');
  assert.equal(parseTime('2026-09-21T19:18:50+02:00'), t);
  assert.equal(parseTime('2026-09-21T13:18:50-0400'), t);
  assert.equal(parseTime('2026-09-21 17:18:50,250'), t + 250000);
  assert.equal(parseTime(Date.UTC(2026, 8, 21, 17, 18, 50)), t);
  for (const bad of ['9/21/2026 5:18:50 PM', '2026-02-30T00:00:00Z', 'yesterday', '']) assert.equal(parseTime(bad), null, bad);
});

test('process IDs: Windows GUIDs ignore braces and case, other IDs keep their case', async () => {
  const {guid} = await import('../src/normalize.ts');
  assert.equal(guid('{26bbf027-6796-6ab1-6709-000000005c00}'), '26BBF027-6796-6AB1-6709-000000005C00');
  assert.equal(guid('Y2xhLXdzLTIxNC04Nzg4'), 'Y2xhLXdzLTIxNC04Nzg4');
  assert.notEqual(guid('aBc'), guid('AbC'));
  assert.equal(guid('{00000000-0000-0000-0000-000000000000}'), undefined);
});

test('hosts and users are compared in one canonical form', () => {
  assert.equal(canonicalHost('CLA-WS-214.corp.example'), 'cla-ws-214');
  assert.equal(canonicalHost('10.10.62.214'), '10.10.62.214');
  assert.equal(canonicalUser('TECHCORP\\Helena.Cardenas'), 'helena.cardenas');
  assert.equal(canonicalUser('helena.cardenas@techcorp.example'), 'helena.cardenas');
  assert.equal(canonicalUser('-'), undefined);
});

test('Elastic Agent Sysmon and Security records', () => {
  const start = one({'@timestamp': '2026-09-21T17:21:26.904Z', host: {name: 'CLA-WS-214'}, user: {name: 'helena.cardenas'},
    event: {code: '1', dataset: 'windows.sysmon_operational'}, winlog: {channel: 'Microsoft-Windows-Sysmon/Operational'},
    process: {name: '2.8.exe', pid: 8788, entity_id: '{26bbf027-6796-6ab1-6709-000000005c00}', executable: 'C:\\x\\2.8.exe', command_line: ' 2.8.exe ',
      hash: {sha256: 'AB'.repeat(32)}, parent: {name: 'explorer.exe', pid: 7412, entity_id: '{26BBF027-5E3E-6AB1-CF07-000000005C00}'}}});
  assert.deepEqual([start.kind, start.source, start.host], ['process_start', 'sysmon:1', 'cla-ws-214']);
  assert.deepEqual(start.proc, {guid: '26BBF027-6796-6AB1-6709-000000005C00', pid: 8788, path: 'C:\\x\\2.8.exe', name: '2.8.exe', cmd: '2.8.exe',
    sha256: 'ab'.repeat(32), user: 'helena.cardenas'});
  assert.deepEqual(start.parent, {guid: '26BBF027-5E3E-6AB1-CF07-000000005C00', pid: 7412, name: 'explorer.exe'});

  const security = one({'@timestamp': '2026-09-21T17:21:26.905Z', host: {name: 'CLA-WS-214'}, event: {code: '4688', dataset: 'system.security'},
    winlog: {channel: 'Security', event_data: {NewProcessId: '0x2254', ProcessId: '0x1cf4'}},
    process: {name: '2.8.exe', pid: 8788, executable: 'C:\\x\\2.8.exe', parent: {pid: 7412, executable: 'C:\\Windows\\explorer.exe'}}});
  assert.deepEqual([security.kind, security.proc.pid, security.parent?.pid, security.parent?.name], ['process_start', 8788, 7412, 'explorer.exe']);

  const inject = one({'@timestamp': '2026-09-21T17:21:30Z', host: {name: 'h'}, event: {code: '8', dataset: 'windows.sysmon_operational'},
    process: {entity_id: '{A}', pid: 1}, winlog: {event_data: {TargetProcessGUID: '{B}', TargetProcessId: '7328', TargetImage: 'C:\\Windows\\System32\\sihost.exe'}}});
  assert.deepEqual([inject.kind, inject.target], ['inject', {guid: 'B', pid: 7328, path: 'C:\\Windows\\System32\\sihost.exe', name: 'sihost.exe'}]);

  const access = one({'@timestamp': '2026-09-21T17:21:31Z', host: {name: 'h'}, event: {code: '10', dataset: 'windows.sysmon_operational'},
    process: {entity_id: '{A}'}, winlog: {event_data: {SourceProcessGUID: '{A}', TargetProcessGUID: '{C}', GrantedAccess: '0x1fffff'}}});
  assert.deepEqual([access.kind, access.access, access.target?.guid], ['process_access', 0x1fffff, 'C']);

  const pipe = one({'@timestamp': '2026-09-21T17:21:31Z', host: {name: 'h'}, event: {code: '17', dataset: 'windows.sysmon_operational'}, process: {pid: 4}, file: {name: '\\evil'}});
  assert.deepEqual([pipe.kind, pipe.pipe], ['pipe_create', '\\evil']);
  const reg = one({'@timestamp': '2026-09-21T17:21:31Z', host: {name: 'h'}, event: {code: '13', dataset: 'windows.sysmon_operational'}, process: {pid: 4},
    registry: {path: 'HKU\\S\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x', data: {strings: ['C:\\p.exe']}}});
  assert.deepEqual(reg.reg, {key: 'HKU\\S\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x', value: 'C:\\p.exe'});
});

test('flat records: a Security 4688 row names the new process NewProcessId and its creator ProcessId', () => {
  const [e] = events('TimeCreated,Computer,Channel,EventID,NewProcessId,ProcessId,NewProcessName,CommandLine,SubjectUserName\n' +
    '2026-09-21T17:21:26Z,WS-01,Security,4688,0x2254,0x1cf4,C:\\x\\a.exe,a.exe -v,alice\n');
  assert.deepEqual([e!.kind, e!.proc.pid, e!.parent?.pid, e!.proc.name, e!.proc.cmd, e!.proc.user], ['process_start', 8788, 7412, 'a.exe', 'a.exe -v', 'alice']);
});

test('EDR and generic ECS: categories, types and injection APIs', () => {
  const start = one({'@timestamp': '2026-09-21T17:21:26Z', host: {name: 'h'}, event: {category: ['process'], type: ['start'], dataset: 'endpoint.events.process'},
    process: {entity_id: 'abc', pid: 5, executable: '/usr/bin/curl', parent: {entity_id: 'def'}}});
  assert.deepEqual([start.kind, start.proc.name, start.proc.guid, start.parent?.guid], ['process_start', 'curl', 'abc', 'def'], 'EDR entity IDs keep their case');
  const api = one({'@timestamp': '2026-09-21T17:21:27Z', host: {name: 'h'}, event: {category: ['api'], dataset: 'endpoint.events.api'},
    process: {entity_id: 'abc', pid: 5, Ext: {api: {name: 'WriteProcessMemory'}}}, Target: {process: {entity_id: 'xyz', pid: 9, name: 'notepad.exe'}}});
  assert.deepEqual([api.kind, api.target], ['inject', {guid: 'xyz', pid: 9, name: 'notepad.exe'}]);
  assert.equal(events(JSON.stringify({'@timestamp': '2026-09-21T17:21:27Z', event: {category: ['api']}, process: {pid: 5, Ext: {api: {name: 'ReadFile'}}}})).length, 0);
  // A process "start" with nothing identifying the process (PowerShell engine lifecycle) is not kept.
  assert.equal(events(JSON.stringify({'@timestamp': '2026-09-21T17:21:27Z', event: {code: '400', category: ['process'], type: ['start'], dataset: 'windows.powershell'}})).length, 0);
});

test('processes: a 4688 twin joins its Sysmon start, PID reuse makes separate processes, PIDs resolve by time', () => {
  const lines = [
    {'@timestamp': '2026-09-21T10:00:00Z', host: {name: 'h'}, event: {code: '4688', dataset: 'system.security'}, process: {pid: 100, executable: 'C:\\a\\old.exe'}},
    {'@timestamp': '2026-09-21T10:05:00Z', host: {name: 'h'}, event: {code: '4689', dataset: 'system.security'}, process: {pid: 100}},
    {'@timestamp': '2026-09-21T11:00:00.001Z', host: {name: 'h'}, event: {code: '4688', dataset: 'system.security'}, process: {pid: 100, executable: 'C:\\a\\new.exe', command_line: 'new.exe /4688'}},
    {'@timestamp': '2026-09-21T11:00:00Z', host: {name: 'h'}, event: {code: '1', dataset: 'windows.sysmon_operational'}, process: {pid: 100, entity_id: 'G1', executable: 'C:\\a\\new.exe', command_line: 'new.exe'}},
    {'@timestamp': '2026-09-21T11:00:05Z', host: {name: 'h'}, event: {code: '4688', dataset: 'system.security'}, process: {pid: 200, executable: 'C:\\a\\child.exe', parent: {pid: 100}}},
    {'@timestamp': '2026-09-21T10:01:00Z', host: {name: 'h'}, event: {code: '4688', dataset: 'system.security'}, process: {pid: 300, executable: 'C:\\a\\early.exe', parent: {pid: 100}}},
  ];
  const evs = events(lines.map(l => JSON.stringify(l)).join('\n'));
  const {nodes} = resolveProcesses(evs);
  const byName = (name: string) => [...nodes.values()].filter(n => n.name === name);
  assert.equal(byName('new.exe').length, 1, 'Sysmon 1 and its 4688 twin are one process');
  assert.equal(byName('new.exe')[0]!.cmd, 'new.exe', 'attributes come from the GUID source');
  assert.equal(byName('old.exe').length, 1);
  assert.notEqual(byName('old.exe')[0]!.key, byName('new.exe')[0]!.key, 'PID 100 reused: two processes');
  assert.equal(byName('child.exe')[0]!.parent, byName('new.exe')[0]!.key, 'parent PID resolves to the process running then');
  assert.equal(byName('early.exe')[0]!.parent, byName('old.exe')[0]!.key);
});

test('processes: a GUID first seen after a GUID-less 4688 start joins that process', () => {
  const lines = [
    {'@timestamp': '2026-09-21T11:00:00Z', host: {name: 'h'}, event: {code: '4688', dataset: 'system.security'}, process: {pid: 500, executable: 'C:\\t\\synchost.exe'}},
    {'@timestamp': '2026-09-21T11:00:01Z', host: {name: 'h'}, event: {code: '7', dataset: 'windows.sysmon_operational'}, process: {pid: 500, entity_id: 'S1', executable: 'C:\\t\\synchost.exe'}, file: {path: 'C:\\t\\x.dll'}},
    {'@timestamp': '2026-09-21T11:00:02Z', host: {name: 'h'}, event: {code: '10', dataset: 'windows.sysmon_operational'}, process: {pid: 9, entity_id: 'A'},
      winlog: {event_data: {SourceProcessGUID: 'A', TargetProcessGUID: 'S1', TargetProcessId: '500', TargetImage: 'C:\\t\\synchost.exe', GrantedAccess: '0x1fffff'}}},
    // A different image under the same PID and GUID-less start is not merged.
    {'@timestamp': '2026-09-21T11:00:03Z', host: {name: 'h'}, event: {code: '3', dataset: 'windows.sysmon_operational'}, process: {pid: 500, entity_id: 'OTHER', executable: 'C:\\x\\other.exe'}, destination: {ip: '1.2.3.4', port: 80}},
  ];
  const {nodes, actor, target} = resolveProcesses(events(lines.map(l => JSON.stringify(l)).join('\n')));
  assert.equal(actor[1], actor[0], 'the Sysmon 7 event is the 4688 process');
  assert.equal(target.get(2), actor[0], 'and so is the Sysmon 10 target');
  assert.notEqual(actor[3], actor[0]);
  assert.equal(nodes.get(actor[0]!)!.guid, 'S1');
});

test('injection-capable access masks', () => {
  for (const mask of [0x1fffff, 0x1f0fff, 0x2, 0x28, 0x143a]) assert.equal(injectionCapable(mask), true, mask.toString(16));
  for (const mask of [0x1410, 0x1010, 0x40, 0x1000, 0x20, 0x8, 0x100000]) assert.equal(injectionCapable(mask), false, mask.toString(16));
});

test('persistence payloads leave out the launcher around them', () => {
  assert.deepEqual(launchedPaths('"C:\\Windows\\system32\\cmd.exe" /c start /b "" "C:\\Users\\a\\wlrmdr.exe"'), ['\\users\\a\\wlrmdr.exe']);
  assert.deepEqual(launchedPaths('C:\\Windows\\system32\\cmd.exe /c whoami'), ['\\windows\\system32\\cmd.exe']);
  assert.equal(pathKey('\\Device\\HarddiskVolume3\\Users\\A\\x.exe'), pathKey('C:\\users\\a\\X.EXE'), 'EDR device paths match drive paths');
  assert.deepEqual(launchedPaths('rundll32.exe shell32.dll'), []);
});

test('links: last writer before a start, persistence to the next start only, no self links', () => {
  const ecs = (t: string, code: string, process: object, extra: object = {}) =>
    JSON.stringify({'@timestamp': `2026-09-21T${t}Z`, host: {name: 'h'}, event: {code, dataset: 'windows.sysmon_operational'}, process, ...extra});
  const A = {entity_id: 'A', pid: 1, executable: 'C:\\a.exe'}, B = {entity_id: 'B', pid: 2, executable: 'C:\\b.exe'};
  const lines = [
    ecs('10:00:00', '1', A), ecs('10:00:01', '1', B),
    ecs('10:00:02', '11', B, {file: {path: 'C:\\t\\p.exe'}}),
    ecs('10:00:03', '11', A, {file: {path: 'C:\\T\\P.EXE'}}),  // A wrote it last
    ecs('10:00:04', '13', A, {registry: {path: 'HKU\\S\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\p', data: {strings: ['C:\\t\\p.exe']}}}),
    ecs('10:00:05', '1', {entity_id: 'P1', pid: 3, executable: 'C:\\t\\p.exe'}),
    ecs('10:00:06', '1', {entity_id: 'P2', pid: 4, executable: 'C:\\t\\p.exe'}),
    ecs('10:00:07', '10', A, {winlog: {event_data: {TargetProcessGUID: 'B', GrantedAccess: '0x1410'}}}),
    ecs('10:00:08', '10', A, {winlog: {event_data: {TargetProcessGUID: 'B', GrantedAccess: '0x1fffff'}}}),
    ecs('10:00:09', '10', A, {winlog: {event_data: {TargetProcessGUID: 'A', GrantedAccess: '0x1fffff'}}}),
  ];
  const evs = events(lines.join('\n'));
  const processes = resolveProcesses(evs);
  const {links} = buildLinks(evs, processes);
  const name = (key: string) => processes.nodes.get(key)!.guid;
  assert.deepEqual(links.map(l => `${l.type} ${name(l.from)}->${name(l.to)}`).sort(), [
    'dropped_and_ran A->P1', 'dropped_and_ran A->P2', 'opened_for_injection A->B', 'persisted_and_ran A->P1',
  ]);
  const drop = links.find(l => l.type === 'dropped_and_ran' && name(l.to) === 'P1')!;
  assert.equal(drop.act, parseTime('2026-09-21T10:00:03Z'), 'the time of the write, not of the start');
});

test('Sysmon 2, a file\'s creation time changed (timestomping), is kept as file_time', () => {
  const e = normalize([...readText(JSON.stringify({'@timestamp': '2026-09-21T17:21:27.008Z', host: {name: 'WS-01'}, event: {code: '2'},
    winlog: {channel: 'Microsoft-Windows-Sysmon/Operational', event_data: {ProcessGuid: '{26BBF027-0000-6AB1-0001-000000005C00}', ProcessId: '8788',
      Image: 'C:\\x\\2.8.exe', TargetFilename: 'C:\\x\\wlrmdr.exe'}}}))][0]!, 0, 0)!;
  assert.deepEqual([e.kind, e.file_path], ['file_time', 'C:\\x\\wlrmdr.exe']);
});
