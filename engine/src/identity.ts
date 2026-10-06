// Which process each event is about. Processes are identified by host + GUID when the source has
// one (Sysmon, EDR), otherwise by host + PID + start time, with PID reuse handled by tracking each
// PID's incarnations over time. A Security 4688 and a Sysmon 1 record of the same start become one
// process, and so do the different GUIDs two sources (Sysmon and an EDR) give the same process, so
// telemetry with and without GUIDs, alone or combined, describes the incident the same way.
import type {Event, ProcRef, ProcessNode} from './model.ts';

/** Two records of one start (4688 and Sysmon 1, different clocks) are at most this far apart. */
const TWIN_MICROS = 2_000_000;

/** One lifetime of a PID. `known` when its start record is in the input; otherwise `start` is only
 * when it was first seen, and it may have been running before that. */
interface Incarnation { start: number; end: number | null; key: string; known: boolean }

export interface Processes {
  nodes: Map<string, ProcessNode>;
  /** Node key of each event's acting process (index = event seq), or '' when it names no process. */
  actor: string[];
  /** For inject/process_access events: the target's node key. */
  target: Map<number, string>;
}

const lower = (s: string | undefined) => s?.toLowerCase();

/** Whether a reference identifies a process at all (a user name alone does not). */
export const isProcess = (ref: ProcRef): boolean => ref.guid !== undefined || ref.pid !== undefined || !!ref.path || !!ref.name;

/** The source a GUID comes from: different sources (Sysmon, an EDR) name one process with different
 * GUIDs, while within one source a different GUID is always a different process. */
const space = (e: Event) => `${e.file}|${e.source.split(':')[0]}`;

export function resolveProcesses(events: Event[]): Processes {
  const nodes = new Map<string, ProcessNode>();
  const incarnations = new Map<string, Incarnation[]>();  // "host|pid" -> by start time
  const order = timeOrder(events);
  const spaceOf = new Map<string, string>();  // GUID node -> the source of its GUID
  // A GUID that names a process already known under another key (its GUID from another source, or
  // its PID in a GUID-less source) -> that key.
  const sameProcess = new Map<string, string>();

  const node = (key: string, host: string, t: number | null): ProcessNode => {
    let n = nodes.get(key);
    if (!n) {
      n = {key, type: 'process', host, start: null, firstSeen: t, end: null, events: [], starts: []};
      nodes.set(key, n);
    } else if (t !== null && (n.firstSeen === null || t < n.firstSeen)) {
      n.firstSeen = t;
    }
    return n;
  };
  const register = (host: string, pid: number | undefined, start: number | null, key: string, known = false) => {
    if (pid === undefined || start === null) return;
    const list = incarnations.get(`${host}|${pid}`) ?? [];
    if (list.some(i => i.key === key)) return;
    const at = list.findIndex(i => i.start > start);
    list.splice(at < 0 ? list.length : at, 0, {start, end: null, key, known});
    incarnations.set(`${host}|${pid}`, list);
  };
  /** The incarnation of host+pid running at time t, allowing for clock skew between sources. */
  const running = (host: string, pid: number, t: number | null): Incarnation | undefined => {
    const list = incarnations.get(`${host}|${pid}`);
    if (!list) return undefined;
    if (t === null) return list.at(-1);
    let found: Incarnation | undefined, next: Incarnation | undefined;
    for (const i of list) if (i.start <= t + TWIN_MICROS) found = i; else { next = i; break; }
    if (found && (found.end === null || found.end >= t - TWIN_MICROS)) return found;
    // The next lifetime was only seen later: with no start record it may already have been running.
    return next && !next.known ? next : undefined;
  };

  // 1. Process starts. Starts with a GUID first, so a GUID-less twin can join its node. The start of
  // a process another source already started, under its own GUID, joins that process.
  const starts = order.filter(i => events[i]!.kind === 'process_start');
  const startKey = new Map<number, string>();
  for (const i of starts) {
    const e = events[i]!;
    if (!e.proc.guid) continue;
    let key = `g:${e.host}:${e.proc.guid}`;
    if (!nodes.has(key)) {
      const twin = sameProcess.get(key) ?? (e.proc.pid === undefined || e.t === null ? undefined : incarnations.get(`${e.host}|${e.proc.pid}`)?.find(c =>
        c.known && spaceOf.has(c.key) && spaceOf.get(c.key) !== space(e) && Math.abs(c.start - e.t!) <= TWIN_MICROS && sameImage(nodes.get(c.key)!, events, e.proc))?.key);
      if (twin) { sameProcess.set(key, twin); key = twin; } else spaceOf.set(key, space(e));
    }
    node(key, e.host, e.t).starts.push(i);
    register(e.host, e.proc.pid, e.t, key, true);
    startKey.set(i, key);
  }
  for (const i of starts) {
    const e = events[i]!;
    if (e.proc.guid) continue;
    const twin = e.proc.pid === undefined || e.t === null ? undefined : incarnations.get(`${e.host}|${e.proc.pid}`)?.find(c => {
      const n = nodes.get(c.key)!;
      return c.key.startsWith('g:') && Math.abs(c.start - e.t!) <= TWIN_MICROS && sameImage(n, events, e.proc);
    });
    const key = twin?.key ?? `p:${e.host}:${e.proc.pid ?? '?'}:${e.t ?? e.seq}`;
    node(key, e.host, e.t).starts.push(i);
    register(e.host, e.proc.pid, e.t, key, true);
    startKey.set(i, key);
  }
  for (const n of nodes.values()) n.start = preferredStart(n, events)?.t ?? null;

  // 2. Every other event, in time order: who did it (and, for inject/access, to whom).
  // A GUID first seen after its process appeared under another key belongs to that process, not to a
  // new one: after a GUID-less source (a 4688 start, then Sysmon image loads or handle events with a
  // ProcessGuid; or an injection target first named only by PID), or under another source's GUID
  // (a process that started before the logs, seen by both Sysmon and an EDR).
  const resolve = (host: string, ref: ProcRef, t: number | null, seq: number): string => {
    if (ref.guid) {
      const key = `g:${host}:${ref.guid}`;
      const known = sameProcess.get(key);
      if (known) { node(known, host, t); return known; }
      if (!nodes.has(key) && ref.pid !== undefined) {
        const live = running(host, ref.pid, t);
        const n = live ? nodes.get(live.key) : undefined;
        const other = n && (live!.key.startsWith('g:') ? spaceOf.get(live!.key) !== space(events[seq]!) : true);
        if (n && other && (!n.starts.length || sameImage(n, events, ref)) && sameName(n, events, ref)) {
          sameProcess.set(key, n.key);
          node(n.key, host, t);
          return n.key;
        }
      }
      if (!nodes.has(key)) { register(host, ref.pid, t, key); spaceOf.set(key, space(events[seq]!)); }  // Started before the input begins.
      node(key, host, t);
      return key;
    }
    if (ref.pid !== undefined) {
      const live = running(host, ref.pid, t);
      if (live) { node(live.key, host, t); return live.key; }
      const key = `p:${host}:${ref.pid}:${t ?? `?${seq}`}`;
      node(key, host, t);
      register(host, ref.pid, t, key);
      return key;
    }
    const key = `u:${host}:${lower(ref.path ?? ref.name) ?? '?'}`;  // Only a name: one node per host and image.
    node(key, host, t);
    return key;
  };
  const actor: string[] = new Array(events.length).fill('');
  const target = new Map<number, string>();
  for (const i of order) {
    const e = events[i]!;
    // Logons, firewall flows and web requests often name no process at all: they get no actor.
    if (!startKey.has(i) && !isProcess(e.proc)) continue;
    const key = startKey.get(i) ?? resolve(e.host, e.proc, e.t, e.seq);
    actor[i] = key;
    const n = nodes.get(key)!;
    n.events.push(i);
    if (e.kind === 'process_end') {
      if (e.t !== null && (n.end === null || e.t > n.end)) n.end = e.t;
      const live = e.proc.pid === undefined ? undefined : incarnations.get(`${e.host}|${e.proc.pid}`)?.find(c => c.key === key);
      if (live) live.end = e.t;
    }
    if ((e.kind === 'inject' || e.kind === 'process_access') && e.target && isProcess(e.target)) {
      target.set(i, resolve(e.host, e.target, e.t, e.seq));
    }
  }

  // 3. Parents and attributes, from the preferred start record (GUID source first, then earliest).
  const seenAs = new Map<string, ProcRef[]>();  // How other records describe a process (as parent or target).
  const describe = (key: string, ref: ProcRef) => { const list = seenAs.get(key); if (list) list.push(ref); else seenAs.set(key, [ref]); };
  for (const n of [...nodes.values()]) {
    const start = preferredStart(n, events);
    if (start?.parent && (start.parent.guid || start.parent.pid !== undefined)) {
      n.parent = resolve(n.host, start.parent, start.t, start.seq);
      if (n.parent === n.key) delete n.parent;
      else describe(n.parent, start.parent);
    }
  }
  for (const [i, key] of target) describe(key, events[i]!.target!);
  for (const n of nodes.values()) fillAttributes(n, events, seenAs.get(n.key) ?? []);
  return {nodes, actor, target};
}

/** Event indexes by time (untimed last), then input order. */
export function timeOrder(events: Event[]): number[] {
  return events.map((_, i) => i).sort((a, b) => {
    const ta = events[a]!.t, tb = events[b]!.t;
    if (ta !== tb) return ta === null ? 1 : tb === null ? -1 : ta - tb;
    return a - b;
  });
}

/** For a process without a start record: whether the image its own records name (if any) is the reference's. */
function sameName(n: ProcessNode, events: Event[], ref: ProcRef): boolean {
  if (n.starts.length) return true;
  const named = n.events.map(i => events[i]!.proc).find(r => r.path || r.name);
  const a = lower(named?.path ?? named?.name), b = lower(ref.path ?? ref.name);
  const base = (s: string) => s.split(/[\\/]/).at(-1);
  return !a || !b || base(a) === base(b);
}

function sameImage(n: ProcessNode, events: Event[], ref: ProcRef): boolean {
  const start = n.starts.map(i => events[i]!).find(e => e.proc.path || e.proc.name);
  if (!start) return true;
  const a = lower(start.proc.path ?? start.proc.name)!, b = lower(ref.path ?? ref.name);
  if (!b) return true;
  const base = (s: string) => s.split(/[\\/]/).at(-1);
  return a === b || base(a) === base(b);
}

function preferredStart(n: ProcessNode, events: Event[]): Event | undefined {
  return n.starts.map(i => events[i]!).sort((a, b) =>
    Number(!a.proc.guid) - Number(!b.proc.guid) || (a.t ?? Infinity) - (b.t ?? Infinity) || a.seq - b.seq)[0];
}

/** Name, path, command line, user and hash: the preferred start record first, then the process's own
 * records in time order, then how others describe it (as their parent, as an injection target). */
function fillAttributes(n: ProcessNode, events: Event[], seenAs: ProcRef[]) {
  const refs: ProcRef[] = [];
  const start = preferredStart(n, events);
  if (start) refs.push(start.proc, ...n.starts.map(i => events[i]!.proc).filter(r => r !== start.proc));
  for (const i of n.events) refs.push(events[i]!.proc);
  refs.push(...seenAs);
  for (const r of refs) {
    n.guid ??= r.guid; n.pid ??= r.pid; n.path ??= r.path; n.name ??= r.name; n.cmd ??= r.cmd; n.user ??= r.user; n.sha256 ??= r.sha256;
  }
  if (!n.name && n.path) n.name = n.path.split(/[\\/]/).filter(Boolean).at(-1);
}
