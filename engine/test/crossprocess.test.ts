// Execution carried into a process outside the lineage: an injection into a process that was already running
// (CLA-WS-217, October 2026: a ghosted payload allocated and wrote memory in the user's Explorer, which then
// contacted new infrastructure), a child created under a spoofed parent, and an injection Jev does not link.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {analyze, findSeed, load, unfold} from '../src/analyze.ts';
import {JevClient} from '../src/jev.ts';
import {standIn} from '../src/standin.ts';
import {conclusiveInjection} from '../src/links.ts';
import {defend, EVENTS, explorer, stage2, T0, type Proc} from './incident.ts';

const dir = mkdtempSync(join(tmpdir(), 'jevline-crossprocess-'));
test.after(() => rmSync(dir, {recursive: true, force: true}));
let files = 0;

// Elastic Defend records, identified the way defend() identifies the incident's processes.
const entity = (p: Proc) => createHash('sha256').update(p.guid).digest('base64').slice(0, 22);
const at = (s: number) => new Date(T0 + s * 1000 + 4).toISOString();
const ref = (p: Proc) => ({entity_id: entity(p), pid: p.pid, executable: p.image, name: p.image.split('\\').pop()});
const record = (s: number, dataset: string, category: string, type: string, p: Proc, extra: object) => JSON.stringify({'@timestamp': at(s),
  host: {name: 'WS-01', os: {type: 'windows'}}, user: {name: 'alice'}, data_stream: {dataset: `endpoint.events.${dataset}`},
  event: {category: [category], type: [type], dataset: `endpoint.events.${dataset}`, module: 'endpoint'}, process: ref(p), ...extra});
const api = (s: number, from: Proc, name: string, to: Proc, {behaviors, suspended}: {behaviors?: string[]; suspended?: true} = {}) =>
  record(s, 'api', 'api', 'change', from, {process: {...ref(from), Ext: {api: {name, ...(behaviors ? {behaviors} : {})}}},
    Target: {process: {...ref(to), ...(suspended ? {Ext: {created_suspended: true}} : {})}}});
const started = (s: number, p: Proc, extra: object = {}) =>
  record(s, 'process', 'process', 'start', p, {process: {...ref(p), command_line: p.cmd, ...(p.parent ? {parent: {...ref(p.parent), ...extra}} : {})}});
const connected = (s: number, p: Proc, ip: string) => record(s, 'network', 'network', 'start', p, {destination: {ip, port: 443}});
// Sysmon 25: the image of a running process was replaced (hollowing) or locked (herpaderping and installers).
const tampered = (s: number, p: Proc, type: string) => JSON.stringify({'@timestamp': at(s), host: {name: 'WS-01', hostname: 'WS-01'}, user: {name: 'alice'},
  event: {code: '25', category: ['process'], type: ['change'], dataset: 'windows.sysmon_operational'},
  winlog: {channel: 'Microsoft-Windows-Sysmon/Operational', event_id: '25', computer_name: 'WS-01',
    event_data: {ProcessGuid: `{${p.guid}}`, ProcessId: String(p.pid), Image: p.image, Type: type}},
  process: {entity_id: entity(p), pid: p.pid, executable: p.image, name: p.image.split('\\').pop()}});
const child = (n: number, image: string, cmd: string, parent: Proc): Proc =>
  ({guid: `26BBF027-0000-6AB1-00${n}-000000005C00`, pid: 9800 + n, image, cmd, parent});
const via = (report: Awaited<ReturnType<typeof analyzeLines>>['report'], name: string) =>
  (unfold(report.incident).find(r => r.name === name) ?? unfold(report.rejected).find(r => r.name === name))?.joined;

async function analyzeLines(lines: string[], answer?: (name: string) => number | undefined) {
  const path = join(dir, `${files++}.ndjson`);
  writeFileSync(path, [...defend(EVENTS), ...lines].join('\n') + '\n');
  const base = standIn(), asked: string[] = [];
  const client = new JevClient(async body => {
    const response = await base(body);
    for (const [label, c] of Object.entries((JSON.parse(body) as {state: {candidates: Record<string, {name?: string}>}}).state.candidates)) {
      asked.push(c.name ?? '');
      const p = answer?.(c.name ?? '');
      if (p !== undefined) response.answers[label] = {type: 'noul', noul: p};
    }
    return response;
  });
  const loaded = await load([{path, format: 'auto' as const}]);
  const {report} = await analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, client,
    {description: 'Confirmed malicious.', model: 'm', threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test'});
  return {report, asked, loaded};
}

test('which injection steps prove code ran in the target', () => {
  assert.ok(conclusiveInjection('VirtualAllocEx + WriteProcessMemory'), 'memory allocated in the target, then written');
  assert.ok(conclusiveInjection('CreateRemoteThread'), 'a thread started in the target');
  assert.ok(conclusiveInjection('WriteProcessMemory + QueueUserAPC'), 'an APC queued in the target');
  assert.ok(conclusiveInjection('SetThreadContext'), 'a hijacked thread');
  assert.equal(conclusiveInjection('WriteProcessMemory'), false, 'a write alone: debuggers and security products do this');
  assert.equal(conclusiveInjection('VirtualAllocEx'), false);
  assert.equal(conclusiveInjection(undefined), false);
  assert.ok(conclusiveInjection('Wow64SetThreadContext'), 'a hijacked 32-bit thread');
  assert.ok(conclusiveInjection('WriteProcessMemory (process hollowing)'), 'a write into a process its writer created suspended');
  assert.ok(conclusiveInjection('WriteProcessMemory (shellcode)'), 'a write the sensor saw was shellcode');
  assert.ok(conclusiveInjection('image replaced (process hollowing)'));
});

test('a complete injection into a process that was already running joins it from the injection, without a question', async () => {
  // explorer.exe is the seed's parent and has run for an hour; at +50 s stage2 allocates and writes memory in it.
  const {report, asked} = await analyzeLines([
    connected(40, explorer, '198.51.100.10'),  // Explorer's own connection before the injection
    api(50, stage2, 'VirtualAllocEx', explorer), api(50.1, stage2, 'WriteProcessMemory', explorer),
    connected(52, explorer, '198.51.100.77'),  // what the injected code did
  ]);
  const row = unfold(report.incident).find(r => r.name === 'explorer.exe');
  assert.ok(row, 'Explorer joins the incident');
  assert.equal(row.joined?.basis, 'injection');
  assert.equal(row.joined?.via[0]?.detail, 'VirtualAllocEx + WriteProcessMemory');
  assert.equal(row.joined_incident, `${at(50).slice(0, 23)}000Z`, 'from the injection');
  assert.equal(asked.includes('explorer.exe'), false, 'no question was asked about it');
  const explorerRows = report.timeline.filter(r => r.process === 'explorer.exe');
  assert.ok(explorerRows.some(r => r.detail?.startsWith('198.51.100.77')), 'its activity after the injection is reviewed');
  assert.equal(explorerRows.some(r => r.detail?.startsWith('198.51.100.10')), false, 'its activity before the injection is not');
  assert.ok(report.timeline.some(r => r.process === 'stage2.exe' && r.kind === 'inject' && r.detail === 'explorer.exe VirtualAllocEx'));
});

test('a single memory write is asked about, and when Jev does not link the target, what it did next is shown', async () => {
  const notepad: Proc = {guid: '26BBF027-0000-6AB1-0099-000000005C00', pid: 9900, image: 'C:\\Windows\\System32\\notepad.exe', cmd: 'notepad.exe', parent: explorer};
  const shell: Proc = {guid: '26BBF027-0000-6AB1-0098-000000005C00', pid: 9910, image: 'C:\\Windows\\System32\\cmd.exe', cmd: 'cmd.exe /c whoami /all', parent: notepad};
  const {report, asked} = await analyzeLines([
    started(-600, notepad),
    api(60, stage2, 'WriteProcessMemory', notepad),
    connected(61, notepad, '203.0.113.50'), started(62, shell),
  ], name => name === 'notepad.exe' ? 0.2 : undefined);
  assert.ok(asked.includes('notepad.exe'), 'a write alone is a question for Jev');
  assert.equal(unfold(report.incident).some(r => r.name === 'notepad.exe'), false, 'Jev did not link it');
  const row = report.timeline.find(r => r.process === 'stage2.exe' && r.kind === 'inject' && r.detail?.startsWith('notepad.exe'));
  assert.equal(row?.target, 'notepad.exe (9900)');
  assert.deepEqual(row?.target_after, ['started cmd.exe: cmd.exe /c whoami /all', 'connected to 203.0.113.50:443'],
    'the review still sees what the target did after the injection');
});

test('a child created under a spoofed parent is a candidate through the process that really created it', async () => {
  // Elastic Defend records the real creator (process.parent.Ext.real.pid) of a process started as Explorer's child.
  const spoofed: Proc = {guid: '26BBF027-0000-6AB1-0097-000000005C00', pid: 9920, image: 'C:\\Users\\alice\\AppData\\Local\\Temp\\svc.exe',
    cmd: 'svc.exe -k', parent: explorer};
  const {report, asked} = await analyzeLines([started(70, spoofed, {Ext: {real: {pid: stage2.pid}}})]);
  assert.ok(asked.includes('svc.exe'), 'asked about, as stage2.exe\'s child');
  const via = (unfold(report.incident).find(r => r.name === 'svc.exe') ?? unfold(report.rejected).find(r => r.name === 'svc.exe'))?.joined?.via;
  assert.deepEqual(via?.map(v => [v.link, v.from, v.detail]), [['spawned', 'stage2.exe (2100)', 'created it posing as a child of explorer.exe']]);
});

test('a child started right after an incident process opened its parent with create-process rights is that process\'s child', async () => {
  const child: Proc = {guid: '26BBF027-0000-6AB1-0096-000000005C00', pid: 9930, image: 'C:\\Users\\alice\\AppData\\Local\\Temp\\run.exe',
    cmd: 'run.exe', parent: explorer};
  const handle = (s: number) => JSON.stringify({'@timestamp': at(s), host: {name: 'WS-01', hostname: 'WS-01'}, user: {name: 'alice'},
    event: {code: '10', category: ['process'], type: ['access'], dataset: 'windows.sysmon_operational'},
    winlog: {channel: 'Microsoft-Windows-Sysmon/Operational', event_id: '10', computer_name: 'WS-01',
      event_data: {SourceProcessGUID: `{${stage2.guid}}`, SourceProcessId: String(stage2.pid), SourceImage: stage2.image,
        TargetProcessGUID: `{${explorer.guid}}`, TargetProcessId: String(explorer.pid), TargetImage: explorer.image, GrantedAccess: '0x80'}},
    process: {entity_id: entity(stage2), pid: stage2.pid, executable: stage2.image, name: 'stage2.exe'},
    Target: {process: ref(explorer)}});
  const late = await analyzeLines([handle(80), started(81, child)]);
  const via = (rows: typeof late.report.incident) => unfold(rows).find(r => r.name === 'run.exe')?.joined?.via;
  const links = via(late.report.incident) ?? via(late.report.rejected);
  assert.ok(links?.some(v => v.link === 'spawned' && v.from === 'stage2.exe (2100)' && v.detail === 'created it through a handle to explorer.exe'));
  const unrelated = await analyzeLines([handle(80), started(120, child)]);  // forty seconds later: not through that handle
  assert.equal(unrelated.asked.includes('run.exe'), false);
});

test('a process its creator started suspended and wrote into is hollowed: it joins without a question', async () => {
  const hollowed = child(50, 'C:\\Windows\\System32\\svchost.exe', 'svchost.exe -k netsvcs', stage2);
  const other = child(51, 'C:\\Windows\\System32\\notepad.exe', 'notepad.exe', explorer);  // suspended, but not stage2's
  const {report, asked} = await analyzeLines([
    started(60, hollowed), api(60.2, stage2, 'WriteProcessMemory', hollowed, {suspended: true}), connected(62, hollowed, '203.0.113.9'),
    started(-600, other), api(64, stage2, 'WriteProcessMemory', other, {suspended: true}),
  ], name => name === 'notepad.exe' ? 0.2 : undefined);
  const joined = via(report, 'svchost.exe');
  assert.equal(joined?.basis, 'injection');
  assert.equal(joined?.via.find(v => v.link === 'injected')?.detail, 'WriteProcessMemory (process hollowing)');
  assert.equal(asked.includes('svchost.exe'), false);
  assert.ok(report.timeline.some(r => r.process === 'stage2.exe' && r.detail === 'svchost.exe WriteProcessMemory (created suspended)'));
  assert.ok(asked.includes('notepad.exe'), 'a write into a suspended process someone else created is still a question');
});

test('shellcode written into a running process, or its 32-bit thread hijacked, joins it', async () => {
  const notepad = child(52, 'C:\\Windows\\System32\\notepad.exe', 'notepad.exe', explorer);
  const calc = child(53, 'C:\\Windows\\SysWOW64\\calc.exe', 'calc.exe', explorer);
  const {report, asked} = await analyzeLines([
    started(-600, notepad), started(-500, calc),
    api(60, stage2, 'WriteProcessMemory', notepad, {behaviors: ['cross-process', 'shellcode']}),
    api(61, stage2, 'Wow64SetThreadContext', calc, {behaviors: ['cross-process', 'hardware_breakpoint_set']}),
  ]);
  assert.equal(via(report, 'notepad.exe')?.basis, 'injection');
  assert.equal(via(report, 'notepad.exe')?.via[0]?.detail, 'WriteProcessMemory (shellcode)');
  assert.equal(via(report, 'calc.exe')?.basis, 'injection');
  assert.equal(via(report, 'calc.exe')?.via[0]?.detail, 'Wow64SetThreadContext');
  assert.equal(asked.some(n => n === 'notepad.exe' || n === 'calc.exe'), false);
});

test('a process Sysmon saw with its image replaced was hollowed by its creator; a locked image is only a question', async () => {
  const help = child(54, 'C:\\Windows\\HelpPane.exe', 'HelpPane.exe', stage2);
  const installer = child(55, 'C:\\Windows\\System32\\msiexec.exe', 'msiexec.exe /i x.msi', stage2);
  const {report, asked} = await analyzeLines([
    started(70, help), tampered(70.4, help, 'Image is replaced'),
    started(72, installer), tampered(72.4, installer, 'Image is locked for access'),
  ]);
  assert.equal(via(report, 'HelpPane.exe')?.basis, 'injection');
  assert.equal(via(report, 'HelpPane.exe')?.via.find(v => v.link === 'injected')?.detail, 'image replaced (process hollowing)');
  assert.equal(asked.includes('HelpPane.exe'), false);
  assert.ok(asked.includes('msiexec.exe'));
});

test('a process started through WMI for an incident process is a candidate through that process', async () => {
  // Elastic Defend names the requester of a brokered start in process.Ext.effective_parent (CLA-WS-219, October 2026:
  // PowerShell running a temp script, recorded as WmiPrvSE.exe's child).
  const wmi: Proc = {guid: '26BBF027-0000-6AB1-0060-000000005C00', pid: 1500, image: 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe', cmd: 'wmiprvse.exe -Embedding'};
  const script = child(56, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    'powershell -ExecutionPolicy Bypass -nop -w h -f C:\\Users\\alice\\AppData\\Local\\Temp\\w_update.ps1', wmi);
  const start = record(90, 'process', 'process', 'start', script, {process: {...ref(script), command_line: script.cmd, parent: ref(wmi),
    Ext: {effective_parent: {entity_id: entity(stage2), pid: stage2.pid, name: 'stage2.exe', executable: stage2.image}}}});
  const {report, asked} = await analyzeLines([start]);
  assert.ok(asked.includes('powershell.exe'));
  assert.deepEqual(via(report, 'powershell.exe')?.via.map(v => [v.link, v.from, v.detail]), [['spawned', 'stage2.exe (2100)', 'had it started through WmiPrvSE.exe']]);
});
