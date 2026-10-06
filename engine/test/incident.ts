// One synthetic incident, written once and rendered as different telemetry: Elastic Agent NDJSON
// (Sysmon plus Security 4688 twins), Splunk-style Sysmon CSV, key=value text logs, and Security
// 4688 alone. The reproducibility tests check that equivalent telemetry gives Jev identical requests.
import {createHash} from 'node:crypto';

export const T0 = Date.UTC(2026, 8, 21, 17, 21, 26, 904);  // the seed's start, ms
const HOST = 'WS-01', USER = 'alice';

export interface Proc { guid: string; pid: number; image: string; cmd: string; parent?: Proc; sha256?: string; host?: string }

const proc = (n: number, pid: number, image: string, cmd: string, parent?: Proc, sha256?: string, host?: string): Proc =>
  ({guid: `26BBF027-0000-6AB1-${String(n).padStart(4, '0')}-000000005C00`, pid, image, cmd, ...(parent ? {parent} : {}), ...(sha256 ? {sha256} : {}), ...(host ? {host} : {})});

const services = proc(1, 800, 'C:\\Windows\\System32\\services.exe', 'C:\\Windows\\system32\\services.exe');
export const explorer = proc(2, 1000, 'C:\\Windows\\explorer.exe', 'C:\\Windows\\Explorer.EXE');
const sihost = proc(3, 3000, 'C:\\Windows\\System32\\sihost.exe', 'sihost.exe', services);
export const seed = proc(4, 2000, 'C:\\Users\\alice\\Downloads\\invoice.exe', '"C:\\Users\\alice\\Downloads\\invoice.exe"', explorer, 'a'.repeat(64));
export const stage2 = proc(5, 2100, 'C:\\Users\\alice\\AppData\\Local\\Temp\\stage2.exe', 'stage2.exe --run', seed, 'b'.repeat(64));
const before = proc(6, 2900, 'C:\\Windows\\System32\\taskhostw.exe', 'taskhostw.exe', sihost);  // sihost's child before the injection
export const shell = proc(7, 3100, 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c whoami', sihost);  // after the injection
const whoami = proc(8, 3110, 'C:\\Windows\\System32\\whoami.exe', 'whoami', shell);
export const client = proc(9, 5000, 'C:\\Windows\\System32\\rundll32.exe', 'rundll32.exe C:\\Users\\alice\\AppData\\Local\\Temp\\x.dll,Run', explorer);
export const updater = proc(10, 4000, 'C:\\Users\\alice\\AppData\\Roaming\\upd.exe', 'C:\\Users\\alice\\AppData\\Roaming\\upd.exe', explorer, 'c'.repeat(64));
const chrome = proc(11, 6000, 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'chrome.exe', explorer);
const lsass = proc(12, 700, 'C:\\Windows\\System32\\lsass.exe', 'lsass.exe');
const other = proc(13, 2000, 'C:\\Users\\bob\\Downloads\\invoice.exe', 'invoice.exe', undefined, 'a'.repeat(64), 'WS-02');
// The same PID as the seed on the same host, an hour before it: a different process (PID reuse).
const reused = proc(14, 2000, 'C:\\Windows\\System32\\notepad.exe', 'notepad.exe', explorer);

export type Ev =
  | {code: 1; t: number; p: Proc}
  | {code: 5; t: number; p: Proc}
  | {code: 3; t: number; p: Proc; ip: string; port: number}
  | {code: 8; t: number; p: Proc; target: Proc}
  | {code: 10; t: number; p: Proc; target: Proc; access: string}
  | {code: 11; t: number; p: Proc; path: string}
  | {code: 13; t: number; p: Proc; key: string; value: string}
  | {code: 17 | 18; t: number; p: Proc; pipe: string}
  | {code: 22; t: number; p: Proc; query: string};

/** The incident, in seconds from the seed's start. */
export const EVENTS: Ev[] = [
  {code: 1, t: -3600, p: explorer},
  {code: 1, t: -3590, p: reused}, {code: 5, t: -3500, p: reused},
  {code: 1, t: -1800, p: before},
  {code: 1, t: 0, p: seed},
  {code: 22, t: 2, p: seed, query: 'evil.example'},
  {code: 3, t: 3, p: seed, ip: '203.0.113.9', port: 443},
  {code: 11, t: 5, p: seed, path: 'C:\\Users\\alice\\AppData\\Local\\Temp\\stage2.exe'},
  {code: 1, t: 10, p: stage2},
  {code: 8, t: 12, p: seed, target: sihost},
  {code: 17, t: 15, p: stage2, pipe: '\\evilpipe'},
  {code: 1, t: 16, p: client},
  {code: 18, t: 17, p: client, pipe: '\\evilpipe'},
  {code: 1, t: 20, p: shell},
  {code: 1, t: 21, p: whoami},
  {code: 11, t: 28, p: stage2, path: 'C:\\Users\\alice\\AppData\\Roaming\\upd.exe'},
  {code: 13, t: 30, p: stage2, key: 'HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater', value: 'C:\\Users\\alice\\AppData\\Roaming\\upd.exe'},
  {code: 10, t: 40, p: stage2, target: lsass, access: '0x1410'},
  {code: 10, t: 41, p: stage2, target: explorer, access: '0x1fffff'},
  {code: 1, t: 120, p: chrome},
  {code: 1, t: 200, p: other},
  {code: 5, t: 300, p: stage2},
  {code: 1, t: 3600, p: updater},
  {code: 3, t: 3605, p: updater, ip: '203.0.113.9', port: 443},
];

const iso = (t: number) => new Date(T0 + t * 1000).toISOString();
const base = (path: string) => path.split('\\').at(-1)!;
const hex = (n: number) => `0x${n.toString(16)}`;
const host = (p: Proc) => p.host ?? HOST;

const SYSMON_TASK: Record<number, string> = {1: 'Process creation', 3: 'Network connection', 5: 'Process terminated', 8: 'CreateRemoteThread',
  10: 'ProcessAccess', 11: 'FileCreate', 13: 'RegistryEvent (Value Set)', 17: 'PipeEvent (Pipe Created)', 18: 'PipeEvent (Pipe Connected)', 22: 'DNSEvent (DNS query)'};

/** Elastic Agent documents (ECS with winlog), one per line. Process starts also get a Security 4688 twin. */
export function ecs(events = EVENTS, {security = true, sysmon = true} = {}): string[] {
  const lines: string[] = [];
  for (const e of events) {
    const p = e.p;
    const common = {'@timestamp': iso(e.t), host: {name: host(p), hostname: host(p)}, user: {name: USER}};
    const process = {name: base(p.image), pid: p.pid, entity_id: `{${p.guid}}`, executable: p.image};
    const event = (extra: object) => ({...common, event: {code: String(e.code), action: SYSMON_TASK[e.code], dataset: 'windows.sysmon_operational', provider: 'Microsoft-Windows-Sysmon'},
      winlog: {channel: 'Microsoft-Windows-Sysmon/Operational', event_id: String(e.code), computer_name: host(p)}, ...extra});
    if (sysmon) {
      switch (e.code) {
        case 1: lines.push(JSON.stringify(event({process: {...process, command_line: p.cmd, ...(p.sha256 ? {hash: {sha256: p.sha256}} : {}),
          ...(p.parent ? {parent: {name: base(p.parent.image), pid: p.parent.pid, entity_id: `{${p.parent.guid}}`, executable: p.parent.image, command_line: p.parent.cmd}} : {})},
          event: {code: '1', category: ['process'], type: ['start'], dataset: 'windows.sysmon_operational'}}))); break;
        case 5: lines.push(JSON.stringify(event({process}))); break;
        case 3: lines.push(JSON.stringify(event({process, destination: {ip: e.ip, port: e.port}}))); break;
        case 8: lines.push(JSON.stringify(event({process, winlog: {channel: 'Microsoft-Windows-Sysmon/Operational', event_id: '8',
          event_data: {TargetProcessGUID: `{${e.target.guid}}`, TargetProcessId: String(e.target.pid), TargetImage: e.target.image}}}))); break;
        case 10: lines.push(JSON.stringify(event({process, winlog: {channel: 'Microsoft-Windows-Sysmon/Operational', event_id: '10',
          event_data: {SourceProcessGUID: `{${p.guid}}`, TargetProcessGUID: `{${e.target.guid}}`, TargetProcessId: String(e.target.pid),
            TargetImage: e.target.image, GrantedAccess: e.access}}}))); break;
        case 11: lines.push(JSON.stringify(event({process, file: {path: e.path, name: base(e.path)}}))); break;
        case 13: lines.push(JSON.stringify(event({process, registry: {path: e.key, data: {strings: [e.value]}}}))); break;
        case 17: case 18: lines.push(JSON.stringify(event({process, file: {name: e.pipe}}))); break;
        case 22: lines.push(JSON.stringify(event({process, dns: {question: {name: e.query}}}))); break;
      }
    }
    if (security && e.code === 1) {
      lines.push(JSON.stringify({'@timestamp': iso(e.t + 0.001), host: {name: host(p)}, user: {name: USER},
        event: {code: '4688', action: 'created-process', category: ['process'], type: ['start'], dataset: 'system.security'},
        winlog: {channel: 'Security', event_id: '4688', event_data: {NewProcessId: hex(p.pid), ProcessId: p.parent ? hex(p.parent.pid) : '0x4'}},
        process: {name: base(p.image), pid: p.pid, executable: p.image, command_line: p.cmd,
          ...(p.parent ? {parent: {name: base(p.parent.image), pid: p.parent.pid, executable: p.parent.image}} : {})}}));
    }
    if (security && e.code === 5) {
      lines.push(JSON.stringify({'@timestamp': iso(e.t), host: {name: host(p)}, event: {code: '4689', category: ['process'], type: ['end'], dataset: 'system.security'},
        winlog: {channel: 'Security', event_id: '4689'}, process: {name: base(p.image), pid: p.pid, executable: p.image}}));
    }
  }
  return lines;
}

/** Elastic Defend (endpoint.events.*): its own base64 entity IDs for the processes, a few milliseconds off
 * Sysmon's clock, and no handle-access or named-pipe events. */
export function defend(events = EVENTS): string[] {
  const entity = (p: Proc) => createHash('sha256').update(p.guid).digest('base64').slice(0, 22);
  const lines: string[] = [];
  for (const e of events) {
    const p = e.p;
    const process = {entity_id: entity(p), pid: p.pid, executable: p.image, name: base(p.image)};
    const doc = (dataset: string, category: string, type: string, extra: object) => JSON.stringify({'@timestamp': iso(e.t + 0.004),
      host: {name: host(p), os: {type: 'windows'}}, user: {name: USER}, data_stream: {dataset: `endpoint.events.${dataset}`},
      event: {category: [category], type: [type], dataset: `endpoint.events.${dataset}`, module: 'endpoint'}, process, ...extra});
    switch (e.code) {
      case 1: lines.push(doc('process', 'process', 'start', {process: {...process, command_line: p.cmd, ...(p.sha256 ? {hash: {sha256: p.sha256}} : {}),
        ...(p.parent ? {parent: {entity_id: entity(p.parent), pid: p.parent.pid, executable: p.parent.image, name: base(p.parent.image)}} : {})}})); break;
      case 5: lines.push(doc('process', 'process', 'end', {})); break;
      case 3: lines.push(doc('network', 'network', 'start', {destination: {ip: e.ip, port: e.port}})); break;
      case 22: lines.push(doc('network', 'network', 'protocol', {dns: {question: {name: e.query}}})); break;
      case 8: lines.push(doc('api', 'api', 'info', {process: {...process, Ext: {api: {name: 'WriteProcessMemory'}}},
        Target: {process: {entity_id: entity(e.target), pid: e.target.pid, executable: e.target.image, name: base(e.target.image)}}})); break;
      case 11: lines.push(doc('file', 'file', 'creation', {file: {path: e.path, name: base(e.path)}})); break;
      case 13: lines.push(doc('registry', 'registry', 'change', {registry: {path: e.key, data: {strings: [e.value]}}})); break;
    }
  }
  return lines;
}

const COLUMNS = ['_time', 'host', 'source', 'EventCode', 'User', 'Image', 'CommandLine', 'ProcessId', 'ProcessGuid', 'Hashes', 'ParentImage',
  'ParentCommandLine', 'ParentProcessId', 'ParentProcessGuid', 'TargetImage', 'TargetProcessId', 'TargetProcessGuid', 'GrantedAccess',
  'TargetFilename', 'TargetObject', 'Details', 'PipeName', 'DestinationIp', 'DestinationPort', 'QueryName'];

function sysmonFields(e: Ev): Record<string, string> {
  const p = e.p;
  const f: Record<string, string> = {_time: iso(e.t), host: `${host(p)}.corp.example`, source: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
    EventCode: String(e.code), User: `CORP\\${USER}`, Image: p.image, ProcessId: String(p.pid), ProcessGuid: `{${p.guid}}`};
  switch (e.code) {
    case 1:
      Object.assign(f, {CommandLine: p.cmd, ...(p.sha256 ? {Hashes: `MD5=00,SHA256=${p.sha256.toUpperCase()}`} : {})});
      if (p.parent) Object.assign(f, {ParentImage: p.parent.image, ParentCommandLine: p.parent.cmd, ParentProcessId: String(p.parent.pid), ParentProcessGuid: `{${p.parent.guid}}`});
      break;
    case 8: case 10:
      Object.assign(f, {TargetImage: e.target.image, TargetProcessId: String(e.target.pid), TargetProcessGuid: `{${e.target.guid}}`, ...(e.code === 10 ? {GrantedAccess: e.access} : {})});
      break;
    case 11: f.TargetFilename = e.path; break;
    case 13: Object.assign(f, {TargetObject: e.key, Details: e.value}); break;
    case 17: case 18: f.PipeName = e.pipe; break;
    case 3: Object.assign(f, {DestinationIp: e.ip, DestinationPort: String(e.port)}); break;
    case 22: f.QueryName = e.query; break;
  }
  return f;
}

const csvValue = (v: string) => /[",\n]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v;

/** Sysmon as a Splunk CSV export: Sysmon field names, fully qualified host names, a DOMAIN\user. */
export const csvLines = (events = EVENTS): string[] =>
  [COLUMNS.join(','), ...events.map(e => { const f = sysmonFields(e); return COLUMNS.map(c => csvValue(f[c] ?? '')).join(','); })];
export const csv = (events = EVENTS): string => csvLines(events).join('\r\n') + '\r\n';

/** Sysmon as key=value text lines with a leading timestamp. */
export const textLines = (events = EVENTS): string[] => events.map(e => {
  const {_time, ...f} = sysmonFields(e);
  const pairs = Object.entries({...f, Channel: 'Microsoft-Windows-Sysmon/Operational'}).map(([k, v]) => `${k}="${v.replaceAll('"', '\\"')}"`);
  return `${_time} ${pairs.join(' ')}`;
});
export const text = (events = EVENTS): string => textLines(events).join('\n') + '\n';

/** A deterministic shuffle (the order of lines must not matter). */
export function shuffle<T>(items: T[], seed = 7): T[] {
  const out = [...items];
  let x = seed;
  for (let i = out.length - 1; i > 0; i--) {
    x = (x * 1103515245 + 12345) % 2 ** 31;
    const j = x % (i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

// ---- The same incident in EDR schemas the engine has no built-in rules for ----------------------

/** When each process started (seconds from the seed); processes that started before the logs get a time anyway, as EDRs report it. */
const started = new Map<Proc, number>(EVENTS.filter(e => e.code === 1).map(e => [e.p, e.t]));
const startOf = (p: Proc) => started.get(p) ?? -7200;

const MDE_COLUMNS = {
  DeviceProcessEvents: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA256', 'ProcessId', 'ProcessCommandLine',
    'ProcessCreationTime', 'AccountDomain', 'AccountName', 'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId',
    'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime', 'InitiatingProcessAccountName', 'ReportId'],
  DeviceEvents: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'ProcessId', 'ProcessCreationTime', 'AccountName',
    'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId', 'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
    'AdditionalFields', 'ReportId'],
  DeviceFileEvents: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA256', 'InitiatingProcessFileName',
    'InitiatingProcessFolderPath', 'InitiatingProcessId', 'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime', 'ReportId'],
  DeviceRegistryEvents: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'RegistryKey', 'RegistryValueName', 'RegistryValueData',
    'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId', 'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime', 'ReportId'],
  DeviceNetworkEvents: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'RemoteIP', 'RemotePort', 'LocalIP', 'LocalPort', 'Protocol',
    'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessId', 'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime', 'ReportId'],
} as const;
export type MdeTable = keyof typeof MDE_COLUMNS;

/** Microsoft Defender for Endpoint Advanced Hunting exports, one CSV per table. */
export function mde(events = EVENTS): Record<MdeTable, string> {
  const rows: Record<MdeTable, string[]> = {DeviceProcessEvents: [], DeviceEvents: [], DeviceFileEvents: [], DeviceRegistryEvents: [], DeviceNetworkEvents: []};
  let report = 1000;
  const initiating = (p: Proc) => ({InitiatingProcessFileName: base(p.image), InitiatingProcessFolderPath: p.image, InitiatingProcessId: String(p.pid),
    InitiatingProcessCommandLine: p.cmd, InitiatingProcessCreationTime: iso(startOf(p))});
  const common = (e: Ev) => ({Timestamp: iso(e.t), DeviceId: 'd41d8cd98f00b204e9800998ecf8427e', DeviceName: `${host(e.p).toLowerCase()}.corp.example`, ReportId: String(report++)});
  for (const e of events) {
    const p = e.p;
    let table: MdeTable | null = null, f: Record<string, string> = {};
    switch (e.code) {
      case 1: table = 'DeviceProcessEvents'; f = {ActionType: 'ProcessCreated', FileName: base(p.image), FolderPath: p.image, SHA256: p.sha256 ?? '',
        ProcessId: String(p.pid), ProcessCommandLine: p.cmd, ProcessCreationTime: iso(e.t), AccountDomain: 'corp', AccountName: USER,
        ...(p.parent ? {...initiating(p.parent), InitiatingProcessAccountName: USER} : {})}; break;
      case 8: table = 'DeviceEvents'; f = {ActionType: 'CreateRemoteThreadApiCall', FileName: base(e.target.image), FolderPath: e.target.image,
        ProcessId: String(e.target.pid), ProcessCreationTime: iso(startOf(e.target)), AccountName: USER, ...initiating(p)}; break;
      case 10: table = 'DeviceEvents'; f = {ActionType: 'OpenProcessApiCall', FileName: base(e.target.image), FolderPath: e.target.image,
        ProcessId: String(e.target.pid), ProcessCreationTime: iso(startOf(e.target)), AccountName: USER, ...initiating(p),
        AdditionalFields: JSON.stringify({DesiredAccess: parseInt(e.access, 16)})}; break;
      case 11: table = 'DeviceFileEvents'; f = {ActionType: 'FileCreated', FileName: base(e.path), FolderPath: e.path, ...initiating(p)}; break;
      case 13: {
        const at = e.key.lastIndexOf('\\');
        table = 'DeviceRegistryEvents';
        f = {ActionType: 'RegistryValueSet', RegistryKey: e.key.slice(0, at).replace(/^HKU\\S-1-5-21-1/, 'HKEY_CURRENT_USER'),
          RegistryValueName: e.key.slice(at + 1), RegistryValueData: e.value, ...initiating(p)};
        break;
      }
      case 3: table = 'DeviceNetworkEvents'; f = {ActionType: 'ConnectionSuccess', RemoteIP: e.ip, RemotePort: String(e.port), LocalIP: '10.0.0.5',
        LocalPort: '50123', Protocol: 'Tcp', ...initiating(p)}; break;
    }
    if (table) rows[table].push(MDE_COLUMNS[table].map(c => csvValue(({...common(e), ...f} as Record<string, string>)[c] ?? '')).join(','));
  }
  return Object.fromEntries(Object.entries(rows).map(([t, r]) => [t, [MDE_COLUMNS[t as MdeTable].join(','), ...r].join('\n') + '\n'])) as Record<MdeTable, string>;
}

const falcon = (p: Proc) => String(4398046511104 + Number(p.guid.split('-')[3]) * 1000);
const device = (path: string) => path.replace(/^[A-Za-z]:/, '\\Device\\HarddiskVolume3');

/** CrowdStrike Falcon Data Replicator events (NDJSON): Falcon process IDs, epoch-millisecond times, device paths. */
export function falconFdr(events = EVENTS): string[] {
  const lines: string[] = [];
  for (const e of events) {
    const p = e.p;
    const common = {timestamp: String(T0 + e.t * 1000), aid: 'f00dfacef00dfacef00dfacef00dface', ComputerName: host(p), ContextTimeStamp: ((T0 + e.t * 1000) / 1000).toFixed(3)};
    switch (e.code) {
      case 1: lines.push(JSON.stringify({event_simpleName: 'ProcessRollup2', ...common, UserName: USER, TargetProcessId: falcon(p), RawProcessId: String(p.pid),
        ImageFileName: device(p.image), CommandLine: p.cmd, ...(p.sha256 ? {SHA256HashData: p.sha256} : {}),
        ...(p.parent ? {ParentProcessId: falcon(p.parent), ParentBaseFileName: base(p.parent.image)} : {})})); break;
      case 5: lines.push(JSON.stringify({event_simpleName: 'EndOfProcess', ...common, TargetProcessId: falcon(p)})); break;
      case 8: lines.push(JSON.stringify({event_simpleName: 'InjectedThread', ...common, ContextProcessId: falcon(p), TargetProcessId: falcon(e.target)})); break;
      case 11: lines.push(JSON.stringify({event_simpleName: 'NewExecutableWritten', ...common, ContextProcessId: falcon(p), TargetFileName: device(e.path)})); break;
      case 13: {
        const at = e.key.lastIndexOf('\\');
        lines.push(JSON.stringify({event_simpleName: 'AsepValueUpdate', ...common, ContextProcessId: falcon(p),
          RegObjectName: e.key.slice(0, at).replace(/^HKU\\/, '\\REGISTRY\\USER\\'), RegValueName: e.key.slice(at + 1), RegStringValue: e.value}));
        break;
      }
      case 3: lines.push(JSON.stringify({event_simpleName: 'NetworkConnectIP4', ...common, ContextProcessId: falcon(p), RemoteAddressIP4: e.ip, RemotePort: String(e.port)})); break;
      case 22: lines.push(JSON.stringify({event_simpleName: 'DnsRequest', ...common, ContextProcessId: falcon(p), DomainName: e.query})); break;
    }
  }
  return lines;
}
