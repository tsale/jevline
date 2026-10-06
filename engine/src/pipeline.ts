// The pipeline after reading, the same in Node and in a browser: combine every input's events,
// identify processes, link them, pick the seed, ask Jev round by round and report. Reading files
// is analyze.ts (Node, on several cores) or browser.ts.
import type {EntityType, Event, LinkType, ProcessNode} from './model.ts';
import type {Format} from './read.ts';
import {canonicalHost, canonicalUser, guid, type NormalizeStats} from './normalize.ts';
import {resolveProcesses, timeOrder} from './identity.ts';
import {buildLinks, type Graph} from './links.ts';
import {investigate, relative, SKEW, type Decision, type InvestigateOptions, type Investigation} from './investigate.ts';
import type {JevClient} from './jev.ts';
import type {Mapping, Profiles} from './schema.ts';
import {identicalMembers, interval, runs, sameDetail} from './repeats.ts';

export interface Loaded {
  /** Each input file (its path, or its name in a browser) with how many records it had and kept. */
  inputs: {path: string; format: Format; records: number; kept: number}[];
  events: Event[];
  nodes: Map<string, ProcessNode>;
  /** Node key of each event's process (index = event seq). */
  actor: string[];
  graph: Graph;
  stats: NormalizeStats;
  /** Events dropped because an earlier input file already had them. */
  duplicates: number;
  /** Event types from schemas the built-in rules don't know, and how each was understood. */
  schemas: SchemaSummary[];
  timings: Record<string, number>;
}

export interface SchemaSummary {
  group: string; records: number; events: number; kind: string; learned: Mapping['learned'] | 'not learned';
  roles?: Record<string, string>; warnings?: string[];
}

/** Mappings for the groups of records from unknown schemas (see schema.ts learn()). */
export type Learner = (profiles: Profiles) => Promise<Map<string, Mapping>>;

/** What makes two records the same event, whichever export they came from. */
const identity = (e: Event): string => JSON.stringify([e.t, e.host, e.kind, e.proc.guid ?? e.proc.pid ?? e.proc.path?.toLowerCase(),
  e.target?.guid ?? e.target?.pid, e.parent?.guid ?? e.parent?.pid, e.file_path?.toLowerCase(), e.access, e.net?.ip, e.net?.port,
  e.net?.domain, e.reg?.key, e.reg?.value, e.pipe, e.launches, e.account, e.src?.ip, e.src?.port, e.http?.url, e.logon_type]);

const ms = (since: number) => Math.round((performance.now() - since) * 10) / 10;

/** One summary per event type from an unknown schema: how many records, how many events its mapping
 * made, and the mapping itself. */
export function schemaSummaries(profiles: Profiles, mappings: Map<string, Mapping>, produced: Map<string, number>): SchemaSummary[] {
  return Object.values(profiles).sort((a, b) => b.count - a.count).map(group => {
    const m = mappings.get(group.key);
    return {group: group.key, records: group.count, events: produced.get(`learned:${group.key}`) ?? 0, kind: m?.kind ?? 'unknown',
      learned: m?.learned ?? 'not learned', ...(m ? {roles: m.roles} : {}), ...(m?.warnings ? {warnings: m.warnings} : {})};
  });
}

/** Everything after reading: drop records an earlier input already had, resolve processes, check learned
 * schemas against the data and build the links. `all` is every input's events in input order. */
export function assemble(all: Event[], stats: NormalizeStats, inputs: Loaded['inputs'], schemas: SchemaSummary[],
  timings: Record<string, number>): Loaded {
  let t: number;
  t = performance.now();
  // Overlapping exports (the same events from two pipelines or two queries) would otherwise count
  // twice. Within one file every record is its own event (Sysmon logs repeated identical accesses
  // in the same millisecond); a later file's record is a duplicate only as many times as an earlier
  // file already had it.
  const earlier = new Map<string, number>(), events: Event[] = [];
  let current = new Map<string, number>(), file = 0;
  const finishFile = () => { for (const [id, n] of current) earlier.set(id, Math.max(earlier.get(id) ?? 0, n)); current = new Map(); };
  for (const e of all) {
    if (e.file !== file) { finishFile(); file = e.file; }
    const id = identity(e), n = (current.get(id) ?? 0) + 1;
    current.set(id, n);
    if (n <= (earlier.get(id) ?? 0)) continue;
    e.seq = events.length;
    events.push(e);
  }
  const duplicates = all.length - events.length;
  timings.deduplicate = ms(t);
  t = performance.now();
  const processes = resolveProcesses(events);
  timings.identify_processes = ms(t);
  checkSchemas(schemas, events, processes.nodes);
  t = performance.now();
  const graph = buildLinks(events, processes);
  timings.build_links = ms(t);
  return {inputs, events, nodes: processes.nodes, actor: processes.actor, graph, stats, duplicates, schemas, timings};
}

/** Check learned process-start mappings against the data: if almost no started process has a parent
 * that is in the input, the parent fields were probably mapped wrong. */
function checkSchemas(schemas: SchemaSummary[], events: Event[], nodes: Map<string, ProcessNode>) {
  for (const schema of schemas) {
    if (schema.kind !== 'process_start' || schema.events < 50) continue;
    const source = `learned:${schema.group}`;
    let starts = 0, withParent = 0;
    for (const n of nodes.values()) {
      if (!n.starts.some(i => events[i]!.source === source)) continue;
      starts++;
      if (n.parent && nodes.get(n.parent)?.starts.length) withParent++;
    }
    if (starts >= 50 && withParent / starts < 0.05) {
      (schema.warnings ??= []).push(`only ${withParent} of ${starts} started processes have a parent in the input: check the parent fields`);
    }
  }
}

/**
 * The seed: a process from an event ID (its process), "name:<image>" (the earliest start of that
 * image) or "guid:<process GUID>"; or another entity from "ip:<address>", "domain:<name>",
 * "user:<account>" or "host:<name>". Throws with the reason when nothing matches.
 */
export function findSeed(loaded: Loaded, selector: string): {key: string; note?: string} {
  const {events, nodes} = loaded;
  const entity = /^(ip|domain|user|host):(.+)$/i.exec(selector);
  if (entity) {
    const type = entity[1]!.toLowerCase();
    const value = type === 'user' ? canonicalUser(entity[2]) ?? '' : type === 'host' ? canonicalHost(entity[2]) : entity[2]!.trim().toLowerCase();
    const key = `${type}:${value}`;
    if (!nodes.has(key)) throw new Error(`no ${type === 'user' ? 'account' : type} ${value} in the input`);
    return {key};
  }
  const started = (n: ProcessNode) => n.starts.length > 0;
  const byStart = (a: ProcessNode, b: ProcessNode) => (a.start ?? Infinity) - (b.start ?? Infinity) || a.key.localeCompare(b.key);
  if (selector.startsWith('name:')) {
    const name = selector.slice(5).toLowerCase();
    const matches = [...nodes.values()].filter(n => started(n) && n.name?.toLowerCase() === name).sort(byStart);
    if (!matches.length) throw new Error(`no process start named ${selector.slice(5)} in the input`);
    return {key: matches[0]!.key, ...(matches.length > 1 ? {note: `${matches.length} starts of ${matches[0]!.name}; using the earliest`} : {})};
  }
  if (selector.startsWith('guid:')) {
    // Any source's ID for the process: a Sysmon GUID in any case and with or without braces, or an EDR's
    // own (case-sensitive) entity ID.
    const id = guid(selector.slice(5));
    const match = events.find(e => e.proc.guid === id && loaded.actor[e.seq]);
    if (!match) throw new Error(`no process with GUID ${selector.slice(5)} in the input`);
    return {key: loaded.actor[match.seq]!};
  }
  const matches = events.filter(e => e.id === selector);
  if (!matches.length) throw new Error(`no event with ID ${selector}; use an event ID, name:<image> or guid:<GUID>`);
  const event = matches.find(e => e.kind === 'process_start') ?? matches[0]!;
  if (!loaded.actor[event.seq]) throw new Error(`event ${selector} names no process; seed with ip:, user:, host: or domain: instead`);
  return {key: loaded.actor[event.seq]!};
}

export interface Report {
  seed: ProcessRow;
  note?: string;
  inputs: Loaded['inputs'];
  counts: {records: number; events: number; duplicates: number; processes: number; entities: number; links: number; links_by_type: Partial<Record<LinkType, number>>;
    /** Events of the incident, before repeats of the same activity were folded into timeline rows. */
    timeline_events: number};
  /** Event types from schemas the built-in rules don't know, and the mapping used for each. */
  schemas: SchemaSummary[];
  timings_ms: Record<string, number>;
  /** Peak memory of the process (Node only; a browser does not report it). */
  peak_memory_mb?: number;
  jev: {model: string; transport: string; threshold: number; margin: number; rounds: number; requests: number; answered_from_cache: number; failed: number;
    candidates_asked: number; questions: number;
    /** Answers within the margin of the threshold, and the candidates they decided (one answer decides a group of identical ones). */
    near_threshold: number; near_threshold_candidates: number; input_tokens: number; output_tokens: number; slowest_call_ms: number; stopped?: string};
  /** One row per distinct member: identical repeats of a process are folded into its row's `repeats`. */
  incident: ProcessRow[];
  rejected: ProcessRow[];
  /** One row per run of the same activity (see repeats.ts). */
  timeline: TimelineRow[];
}

export interface ProcessRow {
  type: EntityType; name?: string; pid?: number; host: string; path?: string; command_line?: string; user?: string; sha256?: string;
  start?: string; first_seen?: string; end?: string; key: string;
  /** When it became part of the incident (the seed: when it starts or is first seen). */
  joined_incident?: string;
  joined?: {round: number; probability: number; review?: true; group_size?: number;
    /** Each link that brought it in: its type, the member it came from (a label, and that member's key), when, and what it says. */
    via: {link: LinkType; from?: string; from_key: string; at?: string; detail?: string}[]};
  /** The same process again (same executable, user and parent, linked the same way; see repeats.ts): how
   * many there are in all, counting this one, when the last started, and each of the others, with its own
   * path and command line where they differ from this one's. */
  repeats?: {count: number; last_start?: string;
    others: {key: string; pid?: number; start?: string; probability?: number; path?: string; command_line?: string}[]};
}

/** Every member a list of rows stands for, with identical repeats unfolded. */
export const unfold = (rows: ProcessRow[]): ProcessRow[] =>
  rows.flatMap(({repeats, ...row}) => [row, ...(repeats?.others ?? []).map(({key, pid, start, path, command_line}) => {
    const other: ProcessRow = {...row, key, ...(path ? {path} : {}), ...(command_line ? {command_line} : {})};
    if (pid === undefined) delete other.pid; else other.pid = pid;
    if (start === undefined) delete other.start; else other.start = start;
    return other;
  })]);

export interface TimelineRow {
  time?: string; since_seed?: string; host: string; process?: string; pid?: number;
  /** For events of an account, host, address or domain in the incident, which one. */
  entity?: string;
  /** The incident member the row belongs to: its process, or the account, host, address or domain. */
  member?: string;
  kind: string; detail?: string; event_id: string; input: number; line: number; source: string;
  /** When the same activity repeated: how many times (processes, for process starts and ends), until when, the
   * usual interval in seconds, the last repeat's event, and how many different details (file names or
   * command lines that differed only in their changing parts) the row stands for. */
  count?: number; until?: string; until_since_seed?: string; every_s?: number; last_event_id?: string; variants?: number;
}

/** ISO 8601 with microseconds. */
export const iso = (t: number | null | undefined): string | undefined => {
  if (t === null || t === undefined) return undefined;
  const text = new Date(Math.floor(t / 1000)).toISOString();
  return `${text.slice(0, 23)}${String(((t % 1000) + 1000) % 1000).padStart(3, '0')}Z`;
};

function row(nodes: Map<string, ProcessNode>, key: string, decision?: Decision, joined?: number | null): ProcessRow {
  const n = nodes.get(key)!;
  const label = (k: string) => { const o = nodes.get(k); return !o ? k : o.type === 'process' ? `${o.name ?? '?'} (${o.pid ?? '?'})` : `${o.name} (${o.type})`; };
  return Object.fromEntries(Object.entries({
    type: n.type, name: n.name, pid: n.pid, host: n.host || undefined, path: n.path, command_line: n.cmd, user: n.user, sha256: n.sha256,
    start: iso(n.start), first_seen: n.type === 'process' ? undefined : iso(n.firstSeen), end: iso(n.end), key, joined_incident: iso(joined),
    joined: decision && {round: decision.round, probability: decision.probability, ...(decision.review ? {review: true as const} : {}),
      ...(decision.group_size > 1 ? {group_size: decision.group_size} : {}),
      via: decision.links.map(l => ({link: l.type, from: label(l.from === key ? l.to : l.from), from_key: l.from === key ? l.to : l.from, at: iso(l.t), detail: l.detail}))},
  }).filter(([, v]) => v !== undefined)) as unknown as ProcessRow;
}

function detail(e: Event): string | undefined {
  switch (e.kind) {
    case 'process_start': return e.proc.cmd ?? e.proc.path;
    case 'inject': case 'process_access': return [e.target?.name ?? e.target?.path, e.access !== undefined ? `0x${e.access.toString(16)}` : undefined].filter(Boolean).join(' ');
    case 'file_create': case 'file_delete': case 'file_time': case 'image_load': return e.file_path;
    case 'network': return `${e.src?.ip && !e.proc.pid && !e.proc.guid ? `${e.src.ip} → ` : ''}${[e.net?.domain ?? e.net?.ip, e.net?.port].filter(x => x !== undefined).join(':')}`;
    case 'dns': return e.net?.domain;
    case 'registry_set': return e.reg?.key && `${e.reg.key} = ${e.reg.value ?? ''}`;
    case 'pipe_create': case 'pipe_connect': return e.pipe;
    case 'service_install': case 'task_create': return e.launches;
    case 'logon': case 'logon_failed':
      return [e.account, e.src?.ip ?? e.src?.host ? `from ${e.src?.ip ?? e.src?.host}` : undefined, e.logon_type ? `type ${e.logon_type}` : undefined].filter(Boolean).join(' ');
    case 'http_request': return [e.src?.ip, e.http?.method, e.http?.url, e.http?.status].filter(x => x !== undefined).join(' ');
    default: return undefined;
  }
}

export interface AnalyzeOptions extends InvestigateOptions { transport: string }

export async function analyze(loaded: Loaded, seedKey: string, client: JevClient, options: AnalyzeOptions,
  note?: string): Promise<{report: Report; investigation: Investigation}> {
  const started = performance.now();
  const investigation = await investigate(loaded.events, loaded.nodes, loaded.graph, seedKey, client, options);
  const timings = {...loaded.timings, investigate: ms(started)};
  const {nodes, events} = loaded;
  const members = new Set(investigation.incident);
  // Processes in the order they started; other entities when they joined the incident.
  const at = (k: string) => { const n = nodes.get(k)!; return n.type === 'process' ? n.start ?? n.firstSeen : investigation.since.get(k) ?? n.firstSeen; };
  const byStart = (a: string, b: string) => (at(a) ?? Infinity) - (at(b) ?? Infinity) || a.localeCompare(b);
  const seed = nodes.get(seedKey)!, origin = seed.start ?? seed.firstSeen;
  // Which incident account, host, address or domain each of their events belongs to.
  const entityOf = new Map<number, string>(), entityKey = new Map<number, string>();
  for (const key of investigation.incident) {
    const n = nodes.get(key)!;
    if (n.type !== 'process') for (const i of n.events) if (!entityOf.has(i)) { entityOf.set(i, `${n.name} (${n.type})`); entityKey.set(i, key); }
  }
  // Identical repeats of a member (the same command relaunched by the same parent) are one row.
  const linksOf = (k: string) => investigation.decisions.get(k)?.links;
  const incidentOrder = [...members].sort(byStart);
  const same = identicalMembers(incidentOrder, nodes, linksOf, new Set([seedKey]));
  const rejectedOrder = [...investigation.decisions.values()].filter(d => !d.related).map(d => d.key).sort(byStart);
  const fold = (order: string[], representative: Map<string, string>, rowOf: (k: string) => ProcessRow) => {
    const rows = new Map<string, ProcessRow>();
    for (const k of order) {
      const head = rows.get(representative.get(k) ?? k);
      if (!head) { rows.set(k, rowOf(k)); continue; }
      const n = nodes.get(k)!, repeats = head.repeats ??= {count: 1, others: []};
      repeats.count++;
      if (n.start !== null) repeats.last_start = iso(n.start);
      repeats.others.push(Object.fromEntries(Object.entries({key: k, pid: n.pid, start: iso(n.start),
        probability: investigation.decisions.get(k)?.probability, path: n.path !== head.path ? n.path : undefined,
        command_line: n.cmd !== head.command_line ? n.cmd : undefined}).filter(([, v]) => v !== undefined)) as {key: string});
    }
    return [...rows.values()];
  };
  // Every event of the incident's processes from when each joined (an injected explorer.exe's earlier
  // activity is not the attacker's), and of its accounts, hosts, addresses and domains, in time order,
  // with repeats of the same activity by the same (or an identical) process folded into one row.
  const joinedAt = (key: string, t: number | null) => {
    const since = key === seedKey ? null : investigation.since.get(key) ?? null;
    return since === null || t === null || t >= since - SKEW;
  };
  const shown = timeOrder(events).filter(i => members.has(loaded.actor[i]!) ? joinedAt(loaded.actor[i]!, events[i]!.t) : entityOf.has(i));
  const by = (i: number) => { const key = loaded.actor[i]!; return members.has(key) ? same.get(key) ?? key : `${entityOf.get(i)}|${key}`; };
  const timeline: TimelineRow[] = [];
  const details = shown.map(i => detail(events[i]!));
  const activity = (j: number) => { const e = events[shown[j]!]!; return JSON.stringify([e.host, by(shown[j]!), e.kind, sameDetail(e.kind, details[j])]); };
  for (const run of runs(shown.map((_, j) => j), activity, j => events[shown[j]!]!.t)) {
    const i = shown[run[0]!]!, e = events[i]!, key = loaded.actor[i]!;
    const process = members.has(key) ? nodes.get(key)! : undefined;
    // A process starts and ends once, however many sources recorded it.
    const once = e.kind === 'process_start' || e.kind === 'process_end';
    const processes = new Set<string>(), occurrences = run.map(j => shown[j]!)
      .filter(j => !once || (!processes.has(loaded.actor[j]!) && processes.add(loaded.actor[j]!)));
    const last = events[occurrences.at(-1)!]!;
    const variants = new Set(run.map(j => details[j])).size;
    const repeated = occurrences.length > 1 ? {count: occurrences.length, until: iso(last.t), until_since_seed: relative(last.t, origin) ?? undefined,
      every_s: interval(occurrences.map(j => events[j]!.t).filter((t): t is number => t !== null)), last_event_id: last.id,
      variants: variants > 1 ? variants : undefined} : {};
    timeline.push(Object.fromEntries(Object.entries({time: iso(e.t), since_seed: relative(e.t, origin) ?? undefined, host: e.host,
      process: process?.name, pid: process?.pid, entity: process ? undefined : entityOf.get(i), member: process ? key : entityKey.get(i),
      kind: e.kind, detail: details[run[0]!], event_id: e.id,
      input: e.file, line: e.line, source: e.source, ...repeated}).filter(([, v]) => v !== undefined)) as unknown as TimelineRow);
  }
  const calls = client.calls;
  const linksByType: Partial<Record<LinkType, number>> = {};
  for (const link of loaded.graph.links) linksByType[link.type] = (linksByType[link.type] ?? 0) + 1;
  const report: Report = {
    seed: row(nodes, seedKey, undefined, investigation.since.get(seedKey)), ...(note ? {note} : {}),
    inputs: loaded.inputs,
    schemas: loaded.schemas,
    counts: {records: loaded.stats.records, events: events.length, duplicates: loaded.duplicates,
      processes: [...nodes.values()].filter(n => n.type === 'process').length, entities: [...nodes.values()].filter(n => n.type !== 'process').length, links: loaded.graph.links.length, links_by_type: linksByType,
      timeline_events: shown.length},
    timings_ms: {...timings, total: Math.round(Object.values(timings).reduce((a, b) => a + b, 0) * 10) / 10},
    ...(typeof globalThis.process?.resourceUsage === 'function' ? {peak_memory_mb: Math.round(globalThis.process.resourceUsage().maxRSS / 1024)} : {}),
    jev: {model: options.model, transport: options.transport, threshold: options.threshold, margin: options.margin ?? 0.05, rounds: investigation.rounds, requests: calls.length,
      answered_from_cache: calls.filter(c => c.cached).length, failed: calls.filter(c => c.error).length,
      candidates_asked: investigation.history.length, questions: calls.reduce((s, c) => s + c.questions, 0),
      near_threshold: new Set([...investigation.decisions.values()].filter(d => d.review).map(d => `${d.request}|${d.probability}`)).size,
      near_threshold_candidates: [...investigation.decisions.values()].filter(d => d.review).length,
      input_tokens: calls.reduce((s, c) => s + (c.input_tokens ?? 0), 0), output_tokens: calls.reduce((s, c) => s + (c.output_tokens ?? 0), 0),
      slowest_call_ms: Math.round(Math.max(0, ...calls.map(c => c.ms))),
      ...(investigation.stopped ? {stopped: investigation.stopped} : {})},
    incident: fold(incidentOrder, same, k => row(nodes, k, investigation.decisions.get(k), investigation.since.get(k))),
    rejected: fold(rejectedOrder, identicalMembers(rejectedOrder, nodes, linksOf, new Set()), k => row(nodes, k, investigation.decisions.get(k))),
    timeline,
  };
  return {report, investigation};
}
