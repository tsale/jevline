// Raw records from the sources the engine knows (ECS / Elastic Agent winlog, Sysmon, Security
// auditing, Elastic Defend and other ECS EDR data, and CSV/text exports that use their field names)
// into canonical Events. Records from any other schema are handed to schema learning (schema.ts).
import type {Event, Kind, ProcRef} from './model.ts';
import {isObj, normKey, type RawRecord} from './read.ts';

interface Path { dotted: string; parts: string[]; norm: string }
const paths = (...names: string[]): Path[] => names.map(dotted => ({dotted, parts: dotted.split('.'), norm: normKey(dotted)}));

// Where each canonical field lives, in order of preference: ECS paths, Windows event_data names
// (as Elastic Agent nests them and as CSV/Splunk exports name their columns).
const F = {
  time: paths('@timestamp', 'timestamp', 'time', '_time', 'UtcTime', 'TimeCreated', 'SystemTime', 'event.created'),
  host: paths('host.name', 'host.hostname', 'winlog.computer_name', 'Computer', 'ComputerName', 'hostname', 'host', 'DeviceName'),
  code: paths('event.code', 'winlog.event_id', 'EventID', 'EventCode'),
  origin: paths('winlog.channel', 'Channel', 'LogName', 'event.dataset', 'data_stream.dataset', 'event.module', 'event.provider',
    'winlog.provider_name', 'ProviderName', 'Provider', 'SourceName', 'source', 'sourcetype'),
  kind: paths('kind'),
  windowsLog: paths('winlog.channel', 'winlog.provider_name', 'Channel', 'LogName', 'ProviderName'),
  category: paths('event.category', 'category'),
  type: paths('event.type', 'type'),
  action: paths('event.action', 'action'),
  guid: paths('process.entity_id', 'winlog.event_data.ProcessGuid', 'ProcessGuid', 'winlog.event_data.SourceProcessGUID', 'SourceProcessGUID', 'SourceProcessGuid'),
  pid: paths('process.pid', 'winlog.event_data.ProcessId', 'ProcessId', 'SourceProcessId', 'pid'),
  newPid: paths('winlog.event_data.NewProcessId', 'NewProcessId'),
  path: paths('process.executable', 'winlog.event_data.Image', 'Image', 'NewProcessName', 'SourceImage', 'process.path'),
  name: paths('process.name'),
  cmd: paths('process.command_line', 'winlog.event_data.CommandLine', 'CommandLine', 'ProcessCommandLine'),
  user: paths('user.name', 'winlog.event_data.User', 'User', 'UserName', 'SubjectUserName', 'AccountName'),
  sha256: paths('process.hash.sha256', 'sha256'),
  hashes: paths('winlog.event_data.Hashes', 'Hashes', 'winlog.event_data.Hash', 'Hash'),
  parentGuid: paths('process.parent.entity_id', 'winlog.event_data.ParentProcessGuid', 'ParentProcessGuid'),
  parentPid: paths('process.parent.pid', 'winlog.event_data.ParentProcessId', 'ParentProcessId', 'CreatorProcessId', 'ppid'),
  parentPath: paths('process.parent.executable', 'winlog.event_data.ParentImage', 'ParentImage', 'ParentProcessName'),
  parentName: paths('process.parent.name'),
  parentCmd: paths('process.parent.command_line', 'winlog.event_data.ParentCommandLine', 'ParentCommandLine'),
  targetGuid: paths('winlog.event_data.TargetProcessGUID', 'TargetProcessGUID', 'TargetProcessGuid', 'Target.process.entity_id'),
  targetPid: paths('winlog.event_data.TargetProcessId', 'TargetProcessId', 'Target.process.pid'),
  targetPath: paths('winlog.event_data.TargetImage', 'TargetImage', 'Target.process.executable'),
  targetName: paths('Target.process.name'),
  access: paths('winlog.event_data.GrantedAccess', 'GrantedAccess'),
  apiName: paths('process.Ext.api.name'),
  filePath: paths('file.path', 'winlog.event_data.TargetFilename', 'TargetFilename', 'dll.path', 'winlog.event_data.ImageLoaded', 'ImageLoaded', 'file'),
  fileSha256: paths('file.hash.sha256', 'dll.hash.sha256'),
  pipe: paths('winlog.event_data.PipeName', 'PipeName', 'file.name'),
  ip: paths('destination.ip', 'winlog.event_data.DestinationIp', 'DestinationIp'),
  port: paths('destination.port', 'winlog.event_data.DestinationPort', 'DestinationPort'),
  domain: paths('destination.domain', 'winlog.event_data.DestinationHostname', 'DestinationHostname'),
  query: paths('dns.question.name', 'winlog.event_data.QueryName', 'QueryName'),
  regKey: paths('registry.path', 'winlog.event_data.TargetObject', 'TargetObject'),
  regValue: paths('registry.data.strings', 'winlog.event_data.Details', 'Details'),
  service: paths('winlog.event_data.ServiceFileName', 'ServiceFileName', 'winlog.event_data.ImagePath', 'ImagePath', 'service.executable'),
  taskContent: paths('winlog.event_data.TaskContent', 'TaskContent'),
  // Logons and web requests: who, from where, how.
  account: paths('winlog.event_data.TargetUserName', 'TargetUserName', 'user.target.name', 'user.name', 'UserName', 'User', 'AccountName'),
  srcIp: paths('source.ip', 'winlog.event_data.IpAddress', 'IpAddress', 'winlog.event_data.SourceIp', 'SourceIp', 'client.ip'),
  srcPort: paths('source.port', 'winlog.event_data.IpPort', 'IpPort', 'winlog.event_data.SourcePort', 'SourcePort', 'client.port'),
  srcHost: paths('source.domain', 'winlog.event_data.WorkstationName', 'WorkstationName'),
  logonType: paths('winlog.logon.type', 'winlog.event_data.LogonType', 'LogonType'),
  outcome: paths('event.outcome'),
  url: paths('url.full', 'url.original', 'url.path'),
  method: paths('http.request.method'),
  status: paths('http.response.status_code'),
} as const;

type Get = (field: readonly Path[]) => unknown;

function getter(record: RawRecord): Get {
  const flat = record.flat;
  if (flat) return field => { for (const p of field) { const v = flat.get(p.norm); if (v !== undefined && v !== null && v !== '') return v; } return undefined; };
  const root = record.nested!;
  return field => {
    for (const p of field) {
      let v: unknown = root[p.dotted];  // Some exports use literal dotted keys.
      if (v === undefined) {
        v = root;
        for (const part of p.parts) { if (!isObj(v)) { v = undefined; break; } v = v[part]; }
      }
      if (Array.isArray(v)) v = v.length ? v[0] : undefined;
      if (v !== undefined && v !== null && v !== '') return v;
    }
    return undefined;
  };
}

const str = (v: unknown): string | undefined => typeof v === 'string' ? v : typeof v === 'number' ? String(v) : undefined;
const list = (v: unknown): string[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]).map(x => String(x).toLowerCase());

export function int(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isInteger(v)) return v;
  const s = str(v)?.trim();
  if (!s) return undefined;
  if (/^[0-9]{1,15}$/.test(s)) return Number(s);
  if (/^0x[0-9a-f]{1,12}$/i.test(s)) return parseInt(s.slice(2), 16);
  return undefined;
}

/** A process's unique ID. Windows GUIDs ({26bbf027-...}) are compared without braces or case; other
 * IDs, such as Elastic Defend's base64 entity IDs, are case-sensitive and kept as they are. */
export const guid = (v: unknown): string | undefined => {
  let s = str(v)?.trim().replace(/^\{|\}$/g, '');
  if (!s) return undefined;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) s = s.toUpperCase();
  return /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(s) ? undefined : s;
};

export const basename = (path: string): string => path.split(/[\\/]/).filter(Boolean).at(-1) ?? path;

/** Lower-case short host name; IP addresses as they are. */
export function canonicalHost(v: unknown): string {
  const s = str(v)?.trim().toLowerCase() ?? '';
  return /^[0-9.]+$/.test(s) || s.includes(':') ? s : s.split('.')[0]!;
}

/** "TECHCORP\helena.cardenas" and "helena.cardenas@techcorp" both become "helena.cardenas". */
export function canonicalUser(v: unknown): string | undefined {
  const s = str(v)?.trim();
  if (!s || s === '-') return undefined;
  return s.split('\\').at(-1)!.split('@')[0]!.toLowerCase();
}

const sha256From = (hashes: unknown): string | undefined => {
  const match = /(?:^|,)\s*SHA256=([0-9A-Fa-f]{64})/.exec(str(hashes) ?? '');
  return match ? match[1]!.toLowerCase() : undefined;
};

const ISO = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}(?::?\d{2})?)?$/i;

/**
 * Microseconds since the epoch. ISO 8601 (a missing offset means UTC, as Sysmon UtcTime is) or
 * epoch milliseconds. Locale formats are refused rather than read in this machine's time zone,
 * which would make results depend on where the analysis runs.
 */
export function parseTime(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? Math.round(v * 1000) : null;
  const s = str(v)?.trim();
  const m = s ? ISO.exec(s) : null;
  if (!m) return null;
  const [y, mo, d, h, mi, sec] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const ms = Date.UTC(y, mo - 1, d, h, mi, sec);
  const check = new Date(ms);
  if (check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d || h > 23 || mi > 59 || sec > 60) return null;
  let offset = 0;
  if (m[8] && m[8].toUpperCase() !== 'Z') {
    const sign = m[8][0] === '-' ? -1 : 1, digits = m[8].slice(1).replace(':', '');
    offset = sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2) || 0));
  }
  return (ms - offset * 60_000) * 1000 + Number((m[7] ?? '').slice(0, 6).padEnd(6, '0'));
}

const SYSMON: Record<string, Kind> = {
  '1': 'process_start', '5': 'process_end', '3': 'network', '7': 'image_load', '8': 'inject', '10': 'process_access',
  '11': 'file_create', '15': 'file_create', '29': 'file_create', '23': 'file_delete', '26': 'file_delete',
  '13': 'registry_set', '17': 'pipe_create', '18': 'pipe_connect', '22': 'dns',
};
const SECURITY: Record<string, Kind> = {'4688': 'process_start', '4689': 'process_end', '4697': 'service_install', '4698': 'task_create',
  '4624': 'logon', '4625': 'logon_failed'};
const SYSTEM: Record<string, Kind> = {'7045': 'service_install'};
const INJECTION_APIS = /^(WriteProcessMemory|CreateRemoteThread\w*|NtCreateThreadEx|QueueUserAPC\w*|NtQueueApcThread\w*|SetThreadContext|NtMapViewOfSection|MapViewOfFile\w*|VirtualAllocEx|NtWriteVirtualMemory)$/i;

function family(origin: string): string {
  if (origin.includes('sysmon')) return 'sysmon';
  if (origin.includes('security')) return 'security';
  if (/(^|[ .:])system( |$)|service control manager|system\.system/.test(origin)) return 'system';
  if (origin.includes('endpoint')) return 'edr';
  return '';
}

/** The kind from ECS categories/types/actions (EDR and generic ECS data, flat records with a kind). */
function ecsKind(get: Get): Kind {
  const explicit = str(get(F.kind))?.toLowerCase();
  if (explicit === 'execution') return 'process_start';
  const categories = list(get(F.category)), types = list(get(F.type)), action = (str(get(F.action)) ?? '').toLowerCase();
  const has = (xs: string[], x: string) => xs.some(v => v === x || v.split(/[ ,]+/).includes(x));
  if (has(categories, 'api') && INJECTION_APIS.test(str(get(F.apiName)) ?? '') || /inject/.test(action)) return 'inject';
  if (has(categories, 'process')) {
    if (has(types, 'start') || /^(start|exec|fork|create|process_started|created-process|process creation)$/.test(action)) return 'process_start';
    if (has(types, 'end') || /^(end|exit|exited-process|process_stopped)$/.test(action)) return 'process_end';
  }
  if (has(categories, 'library') || has(categories, 'driver')) return 'image_load';
  if (has(categories, 'file')) {
    if (has(types, 'creation') || has(types, 'change')) return 'file_create';
    if (has(types, 'deletion')) return 'file_delete';
  }
  if (has(categories, 'authentication')) {
    const outcome = (str(get(F.outcome)) ?? '').toLowerCase();
    if (outcome === 'failure') return 'logon_failed';
    if (outcome === 'success' || has(types, 'start')) return 'logon';
  }
  if (has(categories, 'web')) return 'http_request';
  if (has(categories, 'network')) return get(F.query) !== undefined ? 'dns' : 'network';
  if (has(categories, 'registry') && (has(types, 'change') || has(types, 'creation'))) return 'registry_set';
  return 'other';
}

function proc(get: Get, which: 'actor' | 'parent' | 'target', kind: Kind, source: string): ProcRef {
  const ref: ProcRef = {};
  const set = <K extends keyof ProcRef>(key: K, value: ProcRef[K] | undefined) => { if (value !== undefined && value !== '') ref[key] = value; };
  if (which === 'actor') {
    set('guid', guid(get(F.guid)));
    // A flat Security 4688 row names the new process NewProcessId and its creator ProcessId.
    set('pid', source === 'security:4688' ? int(get(F.newPid)) ?? int(get(F.pid)) : int(get(F.pid)) ?? int(get(F.newPid)));
    set('path', str(get(F.path))?.trim());
    set('name', str(get(F.name))?.trim() || (ref.path ? basename(ref.path) : undefined));
    if (kind === 'process_start') {
      set('cmd', str(get(F.cmd))?.trim());
      set('sha256', str(get(F.sha256))?.toLowerCase() ?? sha256From(get(F.hashes)));
    }
    set('user', canonicalUser(get(F.user)));
  } else if (which === 'parent') {
    set('guid', guid(get(F.parentGuid)));
    const flatCreator = source === 'security:4688' && get(F.newPid) !== undefined ? int(get(F.pid)) : undefined;
    set('pid', int(get(F.parentPid)) ?? flatCreator);
    set('path', str(get(F.parentPath))?.trim());
    set('name', str(get(F.parentName))?.trim() || (ref.path ? basename(ref.path) : undefined));
    set('cmd', str(get(F.parentCmd))?.trim());
  } else {
    set('guid', guid(get(F.targetGuid)));
    set('pid', int(get(F.targetPid)));
    set('path', str(get(F.targetPath))?.trim());
    set('name', str(get(F.targetName))?.trim() || (ref.path ? basename(ref.path) : undefined));
  }
  return ref;
}

/** The command a scheduled task runs, from its XML definition. */
function taskCommand(xml: unknown): string | undefined {
  const s = str(xml);
  if (!s) return undefined;
  const command = /<Command>([^<]*)<\/Command>/i.exec(s)?.[1]?.trim();
  const args = /<Arguments>([^<]*)<\/Arguments>/i.exec(s)?.[1]?.trim();
  return command ? (args ? `${command} ${args}` : command) : undefined;
}

export interface NormalizeStats { records: number; kept: number; other: number; untimed: number; unknown: number; bySource: Map<string, number> }
export const newStats = (): NormalizeStats => ({records: 0, kept: 0, other: 0, untimed: 0, unknown: 0, bySource: new Map()});

/**
 * The canonical event for one record, or null when it says nothing the engine uses ("other"
 * kinds such as logons and privilege use are counted, not kept). A record from a schema these
 * rules don't know (no recognised channel or provider, no ECS event category) goes to `unknown`.
 */
export function normalize(record: RawRecord, file: number, seq: number, stats?: NormalizeStats,
  unknown?: (record: RawRecord) => void): Event | null {
  const get = getter(record);
  const origin = [...F.origin].map(p => str(get([p]))).filter(Boolean).join(' ').toLowerCase();
  const fam = family(origin);
  const code = str(get(F.code))?.trim();
  // Windows event-log records (any channel) are a known source: event IDs these rules don't use are irrelevant, not unknown.
  if (!fam && code !== '4688' && get(F.category) === undefined && get(F.kind) === undefined && get(F.windowsLog) === undefined) {
    if (stats) { stats.records++; stats.unknown++; }
    unknown?.(record);
    return null;
  }
  let kind: Kind = 'other';
  if (fam === 'sysmon' && code) kind = SYSMON[code] ?? 'other';
  else if (fam === 'security' && code) kind = SECURITY[code] ?? 'other';
  else if (fam === 'system' && code) kind = SYSTEM[code] ?? 'other';
  else if (!fam && code === '4688') kind = 'process_start';
  if (kind === 'other' && fam !== 'sysmon' && fam !== 'security') kind = ecsKind(get);
  const source = code && fam ? `${fam}:${code}` : fam || (record.flat ? 'flat' : 'ecs');
  if (stats) { stats.records++; stats.bySource.set(source, (stats.bySource.get(source) ?? 0) + 1); }
  if (kind === 'other') { if (stats) stats.other++; return null; }

  const t = parseTime(get(F.time));
  if (stats) { stats.kept++; if (t === null) stats.untimed++; }
  const event: Event = {seq, id: record.id, ...(record.lineId ? {lineId: true as const} : {}), file, line: record.line, t,
    host: canonicalHost(get(F.host)), kind, source, proc: proc(get, 'actor', kind, source)};
  if (kind === 'process_start' && !Object.keys(event.proc).some(k => k !== 'user')) {  // e.g. PowerShell engine starts
    if (stats) {
      stats.kept--;
      stats.other++;
      if (t === null) stats.untimed--;
    }
    return null;
  }
  switch (kind) {
    case 'process_start': {
      const parent = proc(get, 'parent', kind, source);
      if (Object.keys(parent).length) event.parent = parent;
      break;
    }
    case 'inject': case 'process_access': {
      event.target = proc(get, 'target', kind, source);
      const access = int(get(F.access));
      if (access !== undefined) event.access = access;
      break;
    }
    case 'file_create': case 'file_delete': case 'image_load': {
      const path = str(get(F.filePath))?.trim();
      if (path) event.file_path = path;
      const sha = str(get(F.fileSha256))?.toLowerCase() ?? sha256From(get(F.hashes));
      if (sha) event.file_sha256 = sha;
      break;
    }
    case 'network': case 'dns': {
      const net = {ip: str(get(F.ip)), port: int(get(F.port)), domain: str(get(kind === 'dns' ? F.query : F.domain))};
      event.net = Object.fromEntries(Object.entries(net).filter(([, v]) => v !== undefined));
      break;
    }
    case 'registry_set': event.reg = {key: str(get(F.regKey)), value: str(get(F.regValue))}; break;
    case 'pipe_create': case 'pipe_connect': { const pipe = str(get(F.pipe)); if (pipe) event.pipe = pipe; break; }
    case 'service_install': { const image = str(get(F.service))?.trim(); if (image) event.launches = image; break; }
    case 'task_create': { const command = taskCommand(get(F.taskContent)); if (command) event.launches = command; break; }
  }
  if (kind === 'logon' || kind === 'logon_failed' || kind === 'http_request' || kind === 'network') {
    const account = kind === 'network' ? undefined : canonicalUser(get(F.account));
    if (account) event.account = account;
    const src = Object.fromEntries(Object.entries({ip: address(get(F.srcIp)), port: int(get(F.srcPort)), host: str(get(F.srcHost))?.trim() || undefined})
      .filter(([, v]) => v !== undefined));
    if (Object.keys(src).length) event.src = src;
    const ips = hostIps(record);
    if (ips.length) event.host_ips = ips;
  }
  if (kind === 'logon' || kind === 'logon_failed') { const type = str(get(F.logonType)); if (type) event.logon_type = type; }
  if (kind === 'http_request') {
    const http = Object.fromEntries(Object.entries({method: str(get(F.method)), url: str(get(F.url)), status: int(get(F.status))}).filter(([, v]) => v !== undefined));
    if (Object.keys(http).length) event.http = http;
  }
  return event;
}

/** An IP address as written, or undefined for placeholders ("-", "::", empty). */
export function address(v: unknown): string | undefined {
  const s = str(v)?.trim().replace(/^::ffff:/i, '');
  return s && /^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]+)$/i.test(s) && s !== '::' ? s : undefined;
}

/** The host's own addresses from ECS `host.ip` (all of them), leaving out loopback and link-local ones. */
function hostIps(record: RawRecord): string[] {
  const host = record.nested?.host, raw = isObj(host) ? host.ip : record.flat?.get('hostip');
  return (Array.isArray(raw) ? raw : raw === undefined ? [] : [raw]).map(address)
    .filter((ip): ip is string => ip !== undefined && !/^(127\.|::1$|fe80:)/i.test(ip));
}
