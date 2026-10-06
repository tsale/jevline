// Schema learning: logs from sources the built-in rules don't know (any EDR, SIEM export or other
// structured log) are understood by asking Jev, once per event type, what kind of event it is and
// then what each field holds, from a list written for that kind of event. The answer is a mapping
// that plain code applies to every record of that type, so the cost depends on how many event types
// there are, not on how many records. Mappings are cached by a fingerprint of the event type and its fields.
import {createHash} from 'node:crypto';
import {appendFileSync, existsSync, mkdirSync, readFileSync} from 'node:fs';
import {dirname} from 'node:path';
import type {Event, Kind, ProcRef} from './model.ts';
import {isObj, normKey, type RawRecord} from './read.ts';
import {address, basename, canonicalHost, canonicalUser, guid, int, parseTime} from './normalize.ts';
import type {JevClient, JevResponse} from './jev.ts';

// ---- What an event can be, and what its fields can hold ---------------------------------------

export const KINDS = {
  process_start: 'A process was started',
  process_end: 'A process ended',
  inject: 'Code was injected into another process (remote thread, APC, memory write, process hollowing)',
  process_access: 'A handle to another process was opened or its memory read',
  file_create: 'A file was created, written or renamed',
  file_delete: 'A file was deleted',
  image_load: 'A DLL, module or driver was loaded',
  network: 'A network connection or flow (made by a process, or seen by a firewall or proxy)',
  dns: 'A DNS query was made',
  registry_set: 'A registry value was set or a key created',
  pipe_create: 'A named pipe was created',
  pipe_connect: 'A named pipe was connected to',
  service_install: 'A service was installed',
  task_create: 'A scheduled task was created',
  logon: 'An account logged on or authenticated successfully (Windows logon, SSH, VPN, cloud or web sign-in)',
  logon_failed: 'A logon or authentication attempt failed',
  http_request: 'A web request was made to a server (web server, proxy or load balancer access log)',
  other: 'Something else (logons, alerts, inventory, status), or not about a single action',
} as const;
export type LearnedKind = keyof typeof KINDS;

const ID = 'a unique process identifier (a GUID or a long EDR process ID, not the small operating-system PID)';
const PID = 'the operating-system process ID (PID), a small number';
/** The roles a process can be described by, for one process (prefix) in one sense (who). */
const processRoles = (prefix: string, who: string, withCommandLine = true, withHash = false): Record<string, string> => ({
  [`${prefix}_id`]: `${who}: ${ID}`,
  [`${prefix}_pid`]: `${who}: ${PID}`,
  [`${prefix}_image`]: `${who}: executable path or file name`,
  [`${prefix}_start_time`]: `${who}: when it was created`,
  ...(withCommandLine ? {[`${prefix}_command_line`]: `${who}: command line`} : {}),
  ...(withHash ? {[`${prefix}_hash`]: `${who}: hash (SHA-256 or other) of its executable`} : {}),
});
const COMMON = {
  time: 'When the event happened',
  host: 'The computer or device the event happened on',
  user: 'The user account the event ran as',
  event_type: 'Names the type of event (an event ID, action or event name)',
  other: 'None of these, or not needed to follow an intrusion',
};
const ACTOR = processRoles('actor', 'The process that performed this action');
const {user: _user, ...BASE} = COMMON;
const source = (what: string) => ({
  source_ip: `IP address the ${what} came from`, source_port: `Port the ${what} came from`, source_host: `Name of the computer the ${what} came from`,
});
const logon = (verb: string) => ({...BASE, host: `The computer, server or service ${verb}`, account: `The account that ${verb.replace(/ to$/, '')}`,
  ...source('logon'), host_ip: `An IP address of the computer ${verb}`, logon_type: 'How it logged on (interactive, remote desktop, network, SSH key, password…)', ...ACTOR});

/** For each kind of event, the roles its fields can have. Asking with the menu for the kind makes
 * "which process is which" unambiguous: the actor is always the process that did it. */
export const ROLE_MENUS: Record<Exclude<LearnedKind, 'other'>, Record<string, string>> = {
  process_start: {...COMMON, ...processRoles('new_process', 'The process that was started', true, true),
    ...processRoles('creator', 'The process that started it (parent or initiating process)')},
  process_end: {...COMMON, ...processRoles('process', 'The process that ended', false)},
  inject: {...COMMON, ...ACTOR, ...processRoles('target', 'The process injected into', false),
    api_name: 'Name of the API call made (WriteProcessMemory, QueueUserAPC, CreateRemoteThread...)'},
  process_access: {...COMMON, ...ACTOR, ...processRoles('target', 'The process whose handle was opened or memory read', false),
    access_mask: 'Access rights requested on the target process (for example 0x1fffff)', api_name: 'Name of the API call made'},
  file_create: {...COMMON, ...ACTOR, file_path: 'Full path of the file (or its folder, when the name is a separate field)', file_name: 'File name only', file_hash: 'Hash of the file'},
  file_delete: {...COMMON, ...ACTOR, file_path: 'Full path of the file (or its folder)', file_name: 'File name only', file_hash: 'Hash of the file'},
  image_load: {...COMMON, ...ACTOR, file_path: 'Full path of the DLL, module or driver loaded', file_name: 'Its file name only', file_hash: 'Its hash'},
  network: {...COMMON, ...ACTOR, source_ip: 'Source or local IP address', source_port: 'Source or local port',
    destination_ip: 'Destination or remote IP address', destination_port: 'Destination or remote port', domain: 'Remote host or domain name', url: 'URL requested'},
  dns: {...COMMON, ...ACTOR, domain: 'The name looked up', destination_ip: 'An address it resolved to'},
  registry_set: {...COMMON, ...ACTOR, registry_key: 'The registry key path', registry_value_name: 'The value name, when the key path is in another field',
    registry_value: 'The data written'},
  pipe_create: {...COMMON, ...ACTOR, file_path: 'The pipe name'},
  pipe_connect: {...COMMON, ...ACTOR, file_path: 'The pipe name'},
  service_install: {...COMMON, ...ACTOR, launches: 'The program or command line the service runs'},
  task_create: {...COMMON, ...ACTOR, launches: 'The program or command line the task runs'},
  logon: logon('logged on to'),
  logon_failed: logon('tried to log on to'),
  http_request: {...BASE, host: 'The web server (or virtual host) that received the request', host_ip: "The server's own IP address",
    ...source('request'), url: 'The URL or path requested', domain: 'The host name requested', http_method: 'The HTTP method (GET, POST…)',
    http_status: 'The response status code', account: 'The authenticated user, if any'},
};
export type Role = string;

// ---- Reading any record as a flat list of named fields ----------------------------------------

const MAX_FIELDS = 200, MAX_DEPTH = 6;

/** Every scalar field of a record by its name as written ("process.parent.pid", "InitiatingProcessId").
 * Arrays give their first element; a string holding a JSON object is opened up ("AdditionalFields.DesiredAccess"). */
export function flatten(record: RawRecord): Map<string, unknown> {
  const out = new Map<string, unknown>();
  const add = (name: string, value: unknown, depth: number) => {
    if (out.size >= MAX_FIELDS || value === null || value === undefined || value === '') return;
    if (Array.isArray(value)) { if (value.length) add(name, value[0], depth); return; }
    if (typeof value === 'string' && value.startsWith('{') && value.endsWith('}') && depth < MAX_DEPTH) {
      try { const inner = JSON.parse(value) as unknown; if (isObj(inner)) { for (const [k, v] of Object.entries(inner)) add(`${name}.${k}`, v, depth + 1); return; } } catch { /* plain text */ }
    }
    if (isObj(value)) { if (depth < MAX_DEPTH) for (const [k, v] of Object.entries(value)) add(name ? `${name}.${k}` : k, v, depth + 1); return; }
    out.set(name, value);
  };
  if (record.flat) for (const [key, value] of record.flat) add(record.names?.get(key) ?? key, value, 0);
  else add('', record.nested, 0);
  return out;
}

// Names that usually say which type of event a record is, compared without case or separators.
const DISCRIMINATORS = ['eventsimplename', 'actiontype', 'eventtype', 'eventname', 'eventid', 'eventcode', 'winlogeventid', 'eventaction',
  'activityname', 'classname', 'classuid', 'activityid', 'action', 'operation', 'category', 'type', 'msgtype', 'logtype', 'recordtype', 'kind',
  'event', 'evt', 'activity'];

/** The field and value that say which type of event a record is, or null. */
export function eventType(fields: Map<string, unknown>): [string, string] | null {
  const byKey = new Map([...fields].map(([name, value]) => [normKey(name), [name, value] as const]));
  for (const key of DISCRIMINATORS) {
    const hit = byKey.get(key);
    if (hit && (typeof hit[1] === 'string' || typeof hit[1] === 'number') && String(hit[1]).length <= 80) return [hit[0], String(hit[1])];
  }
  return null;
}

/** The group a record belongs to: its event type, or failing that its set of fields. */
export function groupKey(fields: Map<string, unknown>): string {
  const type = eventType(fields);
  return type ? `${type[0]}=${type[1]}` : `fields:${createHash('sha256').update([...fields.keys()].sort().join('\n')).digest('hex').slice(0, 16)}`;
}

// ---- What values look like ---------------------------------------------------------------------

const SHAPES: [string, RegExp][] = [
  ['iso_time', /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/],
  ['guid', /^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$/i],
  ['ipv4', /^\d{1,3}(\.\d{1,3}){3}$/],
  ['ipv6', /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i],
  ['sha256', /^[0-9a-f]{64}$/i], ['sha1', /^[0-9a-f]{40}$/i], ['md5', /^[0-9a-f]{32}$/i],
  ['hash_list', /(^|,)\s*(SHA256|SHA1|MD5|IMPHASH)=/i],
  ['hex_number', /^0x[0-9a-f]+$/i],
  ['registry_path', /^(HKLM|HKCU|HKU|HKCR|HKEY_|\\REGISTRY\\)/i],
  ['windows_path', /^([a-z]:\\|\\\\|\\Device\\)/i],
  ['unix_path', /^\/[^\s]*$/],
  ['url', /^[a-z][a-z0-9+.-]*:\/\//i],
  ['domain_user', /^[^\s\\@]+\\[^\s\\]+$|^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i],
  ['domain', /^(?=.*[a-z])[a-z0-9-]+(\.[a-z0-9-]+)+$/i],
  ['executable', /\.(exe|dll|sys|scr|com|ps1|bat|cmd|vbs|js|hta|msi|so|sh|py|bin)$/i],
  ['command_line', /\s-{1,2}\w|\s\/\w|\.(exe|ps1|sh|py)["']?\s/i],
];

/** What a value looks like: shapes a model (or a person) can recognise a field by. */
export function shapes(value: unknown): string[] {
  if (typeof value === 'boolean') return ['boolean'];
  const number = (n: number): string[] => !Number.isInteger(n) ? (timeOf(n) !== null ? ['number', 'epoch_time'] : ['number'])
    : n > 1e8 && timeOf(n) !== null ? ['large_integer', 'epoch_time'] : n >= 1e8 ? ['large_integer'] : ['small_integer'];
  if (typeof value === 'number') return number(value);
  const s = String(value).trim();
  const found = SHAPES.filter(([, re]) => re.test(s)).map(([name]) => name);
  if (/^-?\d+(\.\d+)?$/.test(s)) found.push(...number(Number(s)));
  if (!found.length) found.push(s.length > 80 ? 'long_text' : 'text');
  return found;
}

/**
 * Microseconds since the epoch from ISO 8601 text or a number in seconds, milliseconds,
 * microseconds, nanoseconds or Windows FILETIME units (whichever gives a year from 1990 to 2100).
 */
export function timeOf(value: unknown): number | null {
  if (typeof value === 'string' && /^-?\d+(\.\d+)?$/.test(value.trim())) value = Number(value.trim());
  if (typeof value !== 'number') return parseTime(value);
  if (!Number.isFinite(value) || value <= 0) return null;
  const lo = Date.UTC(1990, 0, 1) * 1000, hi = Date.UTC(2100, 0, 1) * 1000;
  for (const us of [value * 1e6, value * 1e3, value, value / 1e3]) if (us >= lo && us < hi) return Math.round(us);
  const filetime = value / 10 - 11_644_473_600_000_000;  // 100 ns ticks since 1601
  return filetime >= lo && filetime < hi ? Math.round(filetime) : null;
}

// ---- Profiling: a bounded summary of each group, mergeable across files and threads ------------

/** Records of unknown schemas kept in memory per worker (four times this when reading on one thread);
 * a file with more is read a second time instead, once their mappings are learned. */
export const KEEP_UNKNOWN = 20_000;

export interface FieldProfile { count: number; samples: string[]; shapes: string[] }
export interface GroupProfile { key: string; type: [string, string] | null; count: number; sources: string[]; fields: Record<string, FieldProfile>; example: Record<string, string> }
export type Profiles = Record<string, GroupProfile>;

const clip = (s: string, n: number) => s.length > n ? `${s.slice(0, n)}…` : s;

/** Add one record to the profiles (at most `samples` example values per field). */
export function observe(profiles: Profiles, record: RawRecord, source: string, samples = 3): void {
  const fields = flatten(record), key = groupKey(fields);
  let group = profiles[key];
  if (!group) {
    group = profiles[key] = {key, type: eventType(fields), count: 0, sources: [], fields: {}, example: {}};
    for (const [name, value] of fields) group.example[name] = clip(String(value), 160);
  }
  group.count++;
  if (!group.sources.includes(source) && group.sources.length < 3) group.sources.push(source);
  for (const [name, value] of fields) {
    const f = group.fields[name] ??= {count: 0, samples: [], shapes: []};
    f.count++;
    const text = clip(String(value), 100);
    if (f.samples.length < samples && !f.samples.includes(text)) {
      f.samples.push(text);
      for (const shape of shapes(value)) if (!f.shapes.includes(shape)) f.shapes.push(shape);
    }
  }
}

export function mergeProfiles(into: Profiles, from: Profiles): void {
  for (const [key, g] of Object.entries(from)) {
    const target = into[key];
    if (!target) { into[key] = g; continue; }
    target.count += g.count;
    for (const s of g.sources) if (!target.sources.includes(s) && target.sources.length < 3) target.sources.push(s);
    for (const [name, f] of Object.entries(g.fields)) {
      const t = target.fields[name] ??= {count: 0, samples: [], shapes: []};
      t.count += f.count;
      for (const s of f.samples) if (t.samples.length < 3 && !t.samples.includes(s)) t.samples.push(s);
      for (const s of f.shapes) if (!t.shapes.includes(s)) t.shapes.push(s);
    }
  }
}

// ---- Mappings ----------------------------------------------------------------------------------

export interface Mapping {
  fingerprint: string;
  group: string;
  kind: Kind;
  /** Field name -> what it holds (fields that hold nothing the engine uses are left out). */
  roles: Record<string, Role>;
  /** How the mapping was made: asked of Jev now, read from the cache, or the offline stand-in. */
  learned: 'jev' | 'cache' | 'stand-in';
  /** Jev's probability for each choice, and anything that looked wrong. */
  confidence?: Record<string, number>;
  warnings?: string[];
}

/** A fingerprint of a group's event type and the fields it has: the same schema gets the same one. */
export function fingerprint(group: GroupProfile): string {
  const fields = Object.entries(group.fields).filter(([, f]) => f.count >= group.count * 0.2).map(([name]) => name).sort();
  return createHash('sha256').update(JSON.stringify([group.type, fields])).digest('hex').slice(0, 24);
}

/** Mappings learned before, by fingerprint (a JSONL file of {fingerprint, group, kind, roles}). */
export class SchemaCache {
  private readonly known = new Map<string, Omit<Mapping, 'learned'>>();
  private readonly file: string | undefined;
  constructor(file?: string) {
    this.file = file;
    if (file && existsSync(file)) {
      for (const line of readFileSync(file, 'utf8').split('\n')) {
        try { const m = JSON.parse(line) as Omit<Mapping, 'learned'>; if (m.fingerprint && m.roles) this.known.set(m.fingerprint, m); } catch { /* skip */ }
      }
    }
  }
  get(fingerprint: string): Mapping | undefined { const m = this.known.get(fingerprint); return m ? {...m, learned: 'cache'} : undefined; }
  set(mapping: Mapping): void {
    const {learned: _learned, confidence: _confidence, ...stored} = mapping;
    this.known.set(mapping.fingerprint, stored);
    if (this.file) {
      mkdirSync(dirname(this.file), {recursive: true, mode: 0o700});
      appendFileSync(this.file, JSON.stringify(stored) + '\n', {mode: 0o600});
    }
  }
}

const TASK = 'Map the fields of one type of security log event to what they hold, so these events can be followed in an intrusion investigation.';

/** What Jev sees about a group: its event type, an example event and every field with its shapes and examples. */
function describe(group: GroupProfile): {state: Record<string, unknown>; labels: Map<string, string>} {
  const used = Object.entries(group.fields).filter(([, f]) => f.count >= group.count * 0.2).sort(([a], [b]) => a.localeCompare(b));
  const labels = new Map<string, string>(), fields: Record<string, unknown> = {};
  used.forEach(([name, f], i) => {
    labels.set(`F${i + 1}`, name);
    fields[`F${i + 1}`] = {name, looks_like: f.shapes, examples: f.samples};
  });
  return {labels, state: {task: TASK, source: group.sources, event_type: group.type ? `${group.type[0]} = ${group.type[1]}` : null,
    events_of_this_type: group.count, example_event: group.example, fields}};
}

/** The first question about a group: what kind of event it is. */
export function kindRequest(group: GroupProfile, model: string): string {
  const {state} = describe(group);
  return JSON.stringify({model, state, questions: {kind: {type: 'choice', instructions: 'What kind of event is this type of event?', criteria: KINDS}}});
}

/** The second question: what each field holds, from the menu for the group's kind. */
export function rolesRequest(group: GroupProfile, kind: Exclude<LearnedKind, 'other'>, model: string): {body: string; labels: Map<string, string>} {
  const {state, labels} = describe(group);
  const questions: Record<string, unknown> = {};
  for (const label of labels.keys()) {
    questions[label] = {type: 'choice', instructions: `In this ${KINDS[kind].toLowerCase().replace(/^a /, '').replace(/ \(.*$/, '')} event, what does field ${label} hold?`, criteria: ROLE_MENUS[kind]};
  }
  return {body: JSON.stringify({model, state: {...state, kind_of_event: KINDS[kind]}, questions}), labels};
}

const choice = (response: JevResponse, label: string): [string, number] | null => {
  const answer = response.answers[label];
  if (!answer || typeof answer.choice !== 'string') return null;
  return [answer.choice, answer.probabilities?.[answer.choice] ?? answer.confidence ?? 1];
};

/** The kind Jev chose, or 'other' when the answer is unusable. */
export function readKind(response: JevResponse): [LearnedKind, number] {
  const answer = choice(response, 'kind');
  return answer && answer[0] in KINDS ? [answer[0] as LearnedKind, answer[1]] : ['other', 0];
}

/** Turn Jev's role answers into a mapping: each role at most once (the most probable field wins),
 * unsure answers left out, and a "PID" that only ever holds long numbers treated as a unique ID. */
export function readMapping(group: GroupProfile, kind: LearnedKind, kindConfidence: number, response: JevResponse | null,
  labels: Map<string, string>, learned: Mapping['learned']): Mapping {
  const warnings: string[] = [], confidence: Record<string, number> = {kind: kindConfidence}, best = new Map<Role, [string, number]>();
  const menu = kind === 'other' ? {} : ROLE_MENUS[kind];
  for (const [label, name] of response ? labels : []) {
    const answer = choice(response!, label);
    if (!answer || !(answer[0] in menu)) { warnings.push(`no usable answer for ${name}`); continue; }
    let [role, p] = answer;
    confidence[name] = p;
    if (role === 'other') continue;
    if (p < 0.5) { warnings.push(`${name} → ${role} only at ${Math.round(p * 100)}%, not used`); continue; }
    const samples = group.fields[name]?.samples ?? [];
    if (role.endsWith('_pid') && samples.length && samples.every(v => /^\d{9,}$/.test(v))) {
      const id = role.replace(/_pid$/, '_id');
      warnings.push(`${name} holds long numbers, so it is used as ${id}, not ${role}`);
      role = id;
    }
    const held = best.get(role);
    if (held && held[1] >= p) { warnings.push(`${name} also looked like ${role}; ${held[0]} kept`); continue; }
    if (held) warnings.push(`${held[0]} also looked like ${role}; ${name} kept`);
    best.set(role, [name, p]);
  }
  const roles: Record<string, Role> = {};
  for (const [role, [name]] of best) roles[name] = role;
  const timed = Object.values(roles).includes('time') || (kind === 'process_start' && Object.values(roles).includes('new_process_start_time'));
  if (kind !== 'other' && !timed) warnings.push('no time field: these events have no time');
  return {fingerprint: fingerprint(group), group: group.key, kind, roles, learned, confidence, ...(warnings.length ? {warnings} : {})};
}

/** Mappings for every group: from the cache, or asked of Jev (the kind, then the fields for that
 * kind; groups in parallel). Groups of kind "other" need only the first question. */
export async function learn(profiles: Profiles, client: JevClient, cache: SchemaCache, model: string, learned: Mapping['learned'] = 'jev'): Promise<Map<string, Mapping>> {
  const out = new Map<string, Mapping>();
  await Promise.all(Object.values(profiles).map(async group => {
    const cached = cache.get(fingerprint(group));
    if (cached) { out.set(group.key, {...cached, group: group.key}); return; }
    const [kind, kindConfidence] = readKind(await client.ask(kindRequest(group, model), 1));
    let mapping: Mapping;
    if (kind === 'other') {
      mapping = readMapping(group, kind, kindConfidence, null, new Map(), learned);
    } else {
      const {body, labels} = rolesRequest(group, kind, model);
      mapping = readMapping(group, kind, kindConfidence, await client.ask(body, labels.size), labels, learned);
    }
    cache.set(mapping);
    out.set(group.key, mapping);
  }));
  return out;
}

// ---- Applying a mapping ------------------------------------------------------------------------

const text = (v: unknown): string | undefined => typeof v === 'string' ? v.trim() || undefined : typeof v === 'number' ? String(v) : undefined;
const hash256 = (v: unknown): string | undefined => {
  const s = text(v);
  if (!s) return undefined;
  const listed = /(?:^|,)\s*SHA256=([0-9A-Fa-f]{64})/.exec(s);
  return listed ? listed[1]!.toLowerCase() : /^[0-9a-f]{64}$/i.test(s) ? s.toLowerCase() : undefined;
};

/** One process from the fields mapped to `<prefix>_...` (new_process, creator, actor, target or process). */
function processRef(get: (role: Role) => unknown, prefix: string): ProcRef {
  const ref: ProcRef = {};
  const id = guid(get(`${prefix}_id`)), pid = int(get(`${prefix}_pid`)), started = timeOf(get(`${prefix}_start_time`));
  // Without a unique ID, the PID and creation time together identify a process across event types.
  if (id) ref.guid = id; else if (pid !== undefined && started !== null) ref.guid = `PID-${pid}@${started}`;
  if (pid !== undefined) ref.pid = pid;
  const image = text(get(`${prefix}_image`));
  if (image) { if (/[\\/]/.test(image)) { ref.path = image; ref.name = basename(image); } else ref.name = image; }
  const cmd = text(get(`${prefix}_command_line`));
  if (cmd) ref.cmd = cmd;
  const sha = hash256(get(`${prefix}_hash`));
  if (sha) ref.sha256 = sha;
  return ref;
}

/** The canonical event for a record of a learned schema, or null when its kind isn't used. */
export function applyMapping(record: RawRecord, mapping: Mapping, file: number, seq: number, fields = flatten(record)): Event | null {
  if (mapping.kind === 'other') return null;
  const byRole = new Map<Role, unknown>();
  for (const [name, role] of Object.entries(mapping.roles)) { const v = fields.get(name); if (v !== undefined) byRole.set(role, v); }
  const get = (role: Role) => byRole.get(role);
  const kind = mapping.kind;
  // In a process start the event is about the new process, its creator is the parent; otherwise it is about the actor.
  const proc = processRef(get, kind === 'process_start' ? 'new_process' : kind === 'process_end' ? 'process' : 'actor');
  const user = canonicalUser(get('user'));
  if (user) proc.user = user;
  // Who and where, for logons, web requests and flows (which often name no process at all).
  const account = canonicalUser(get('account'));
  const src = Object.fromEntries(Object.entries({ip: address(get('source_ip')), port: int(get('source_port')), host: text(get('source_host'))})
    .filter(([, v]) => v !== undefined));
  const hostIp = address(get('host_ip'));
  if (kind === 'process_start' && !proc.guid && proc.pid === undefined && !proc.path && !proc.name) return null;
  // A process start happens when the new process is created, so its creation time serves as the event time.
  const t = timeOf(get('time')) ?? (kind === 'process_start' ? timeOf(get('new_process_start_time')) : null);
  const event: Event = {seq, id: record.id, ...(record.lineId ? {lineId: true as const} : {}), file, line: record.line, t,
    host: canonicalHost(get('host')), kind, source: `learned:${mapping.group}`, proc};
  if (kind === 'process_start') { const parent = processRef(get, 'creator'); if (Object.keys(parent).length) event.parent = parent; }
  if (kind === 'inject' || kind === 'process_access') {
    event.target = processRef(get, 'target');
    const access = int(get('access_mask'));
    if (access !== undefined) event.access = access;
  }
  if (kind === 'file_create' || kind === 'file_delete' || kind === 'image_load') {
    const path = text(get('file_path')), name = text(get('file_name'));
    const full = path && name && !path.toLowerCase().endsWith(name.toLowerCase()) ? `${path.replace(/[\\/]+$/, '')}\\${name}` : path ?? name;
    if (full) event.file_path = full;
    const sha = hash256(get('file_hash'));
    if (sha) event.file_sha256 = sha;
  }
  if (kind === 'network' || kind === 'dns') {
    const net = {ip: text(get('destination_ip')), port: int(get('destination_port')), domain: text(get('domain')) ?? text(get('url'))};
    event.net = Object.fromEntries(Object.entries(net).filter(([, v]) => v !== undefined));
  }
  if (kind === 'registry_set') {
    const key = text(get('registry_key')), name = text(get('registry_value_name'));
    event.reg = {key: key && name ? `${key.replace(/\\+$/, '')}\\${name}` : key, value: text(get('registry_value'))};
  }
  if (kind === 'pipe_create' || kind === 'pipe_connect') { const pipe = text(get('file_path')); if (pipe) event.pipe = pipe; }
  if (kind === 'service_install' || kind === 'task_create') { const launches = text(get('launches')); if (launches) event.launches = launches; }
  if (kind === 'logon' || kind === 'logon_failed' || kind === 'http_request' || kind === 'network') {
    if (account && kind !== 'network') event.account = account;
    if (Object.keys(src).length) event.src = src;
    if (hostIp) event.host_ips = [hostIp];
  }
  if (kind === 'logon' || kind === 'logon_failed') { const type = text(get('logon_type')); if (type) event.logon_type = type; }
  if (kind === 'http_request') {
    const http = Object.fromEntries(Object.entries({method: text(get('http_method')), url: text(get('url')), status: int(get('http_status'))})
      .filter(([, v]) => v !== undefined));
    if (Object.keys(http).length) event.http = http;
    if (!event.host) event.host = canonicalHost(get('domain'));
  }
  return event;
}
