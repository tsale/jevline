// Typed links between processes: every observed way one process can carry an execution chain
// into another. Links are candidates only; Jev decides which belong to the incident.
import type {Event, Link, LinkType, ProcessNode} from './model.ts';
import type {Processes} from './identity.ts';
import {timeOrder} from './identity.ts';
import {addEntities} from './entities.ts';

const PROCESS_CREATE_THREAD = 0x2, PROCESS_VM_OPERATION = 0x8, PROCESS_VM_WRITE = 0x20;
const ALL_ACCESS = [0x1fffff, 0x1f0fff];
const SKEW = 2_000_000;  // µs of clock difference tolerated between sources
const EVIDENCE = 3;

/** Access rights that allow writing code into another process or starting a thread in it. */
export const injectionCapable = (mask: number): boolean =>
  ALL_ACCESS.some(all => (mask & all) === all) || (mask & PROCESS_CREATE_THREAD) !== 0 ||
  (mask & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) === (PROCESS_VM_WRITE | PROCESS_VM_OPERATION);

/** Paths compared case-insensitively, ignoring slash direction and how the volume is written: "C:\\x",
 * "\\\\?\\C:\\x" and an EDR's "\\Device\\HarddiskVolume3\\x" are the same file. */
export const pathKey = (path: string): string => path.trim().replace(/^\\\\\?\\/, '').replace(/\//g, '\\').toLowerCase()
  .replace(/^\\device\\harddiskvolume\d+(?=\\)/, '').replace(/^[a-z]:(?=\\)/, '');

// Launchers that persistence often wraps around the real payload ("cmd.exe /c start payload.exe").
const LAUNCHERS = /\\(cmd|powershell|pwsh|rundll32|regsvr32|wscript|cscript|mshta|conhost|explorer)\.exe$/i;

/** The payload paths a registry value, service image path or task command launches: the
 * executables it names, leaving out launchers like cmd.exe when it names something else too. */
export function launchedPaths(text: string | undefined): string[] {
  if (!text) return [];
  const found = new Set<string>();
  for (const m of text.matchAll(/([a-z]:\\[^"<>|*?\r\n]*?\.(?:exe|dll|com|scr|bat|cmd|ps1|vbs|js|hta))(?=$|[\s",])/gi)) found.add(pathKey(m[1]!));
  const payloads = [...found].filter(p => !LAUNCHERS.test(p));
  return payloads.length ? payloads : [...found];
}

/** Files that can run: programs, libraries and scripts. */
export const EXECUTABLE = /\.(exe|dll|sys|scr|com|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|lnk|msi|jar)$/i;

/** Registry locations that make Windows start a program at boot, logon or another trigger. */
export const PERSISTENCE_KEY = new RegExp('\\\\(' + [
  'Run', 'RunOnce', 'RunOnceEx', 'RunServices', 'RunServicesOnce', 'Policies\\\\Explorer\\\\Run',
  'Winlogon\\\\(Userinit|Shell|Notify)', 'Environment\\\\UserInitMprLogonScript', 'Image File Execution Options\\\\[^\\\\]+\\\\Debugger',
  'SilentProcessExit', 'AppInit_DLLs', 'Services\\\\[^\\\\]+\\\\(ImagePath|Parameters\\\\ServiceDll)',
  'Shell Folders\\\\Startup', 'Command Processor\\\\AutoRun', 'Schedule\\\\TaskCache',
].join('|') + ')(\\\\|$)', 'i');

/** Link types followed in both directions (either end may already be in the incident): a C2 address
 * reached from an incident process leads to every later process or host that contacts it, an attacker
 * address to the accounts it used and the hosts it reached, and so on. */
export const UNDIRECTED: ReadonlySet<LinkType> = new Set(['pipe', 'contacted', 'logged_on', 'logon_from', 'used_account', 'failed_logon', 'requested']);

export interface Graph {
  links: Link[];
  /** Links by the node they leave from (and, for undirected types, also by the node they reach). */
  touching: Map<string, Link[]>;
}

interface Write { t: number | null; key: string; seq: number }

export function buildLinks(events: Event[], processes: Processes): Graph {
  const {nodes, actor, target} = processes;
  const byId = new Map<string, Link>();
  const add = (type: LinkType, from: string, to: string, t: number | null, seq: number | null, detail?: string, act: number | null = t) => {
    if (from === to) return;
    const id = `${type}|${from}|${to}`;
    let link = byId.get(id);
    if (!link) {
      link = {type, from, to, t, act, last: t, count: 0, evidence: []};
      if (detail) link.detail = detail;
      byId.set(id, link);
    } else if (t !== null && (link.t === null || t < link.t)) {
      link.t = t;
      link.act = act;
      if (detail) link.detail = detail;
    }
    link.count++;
    if (t !== null && (link.last === null || t > link.last)) link.last = t;
    if (seq !== null && link.evidence.length < EVIDENCE && !link.evidence.includes(seq)) link.evidence.push(seq);
  };

  for (const n of nodes.values()) {
    if (n.parent && nodes.has(n.parent)) add('spawned', n.parent, n.key, n.start, n.starts[0] ?? null);
  }

  const writes = new Map<string, Write[]>();    // path -> writes in time order
  const hashes = new Map<string, Write[]>();    // sha256 of written file -> writes
  const pipes = new Map<string, Write[]>();     // pipe name -> creations
  const persisted = new Map<string, Write[]>(); // launched path -> registrations
  const push = (map: Map<string, Write[]>, k: string, w: Write) => { const list = map.get(k); if (list) list.push(w); else map.set(k, [w]); };
  // The last write before time t. One a little after t (within the clock difference between sources)
  // counts only when nothing was written before: a malware loop that rewrites a file right after
  // starting it must not credit the next writer with this start.
  const lastBefore = (list: Write[] | undefined, t: number | null, exclude: string): Write | undefined => {
    let before: Write | undefined, after: Write | undefined;
    for (const w of list ?? []) {
      if (t !== null && w.t !== null && w.t > t + SKEW) break;
      if (w.key === exclude) continue;
      if (t === null || w.t === null || w.t <= t) before = w; else after ??= w;
    }
    return before ?? after;
  };

  const order = timeOrder(events);
  for (const i of order) {
    const e = events[i]!, from = actor[i]!;
    if (!from) continue;  // No process: only entity links (below) come from this event.
    switch (e.kind) {
      case 'inject': {
        const to = target.get(i);
        if (to) add('injected', from, to, e.t, i, e.source === 'sysmon:8' ? 'CreateRemoteThread' : e.source);
        break;
      }
      case 'process_access': {
        const to = target.get(i);
        if (to && e.access !== undefined && injectionCapable(e.access)) add('opened_for_injection', from, to, e.t, i, `0x${e.access.toString(16)}`);
        break;
      }
      case 'file_create':
        if (e.file_path) push(writes, pathKey(e.file_path), {t: e.t, key: from, seq: i});
        if (e.file_sha256) push(hashes, e.file_sha256, {t: e.t, key: from, seq: i});
        break;
      case 'image_load': {
        const w = e.file_path ? lastBefore(writes.get(pathKey(e.file_path)), e.t, from) : undefined;
        if (w) add('dropped_and_loaded', w.key, from, e.t, w.seq, e.file_path, w.t);
        break;
      }
      case 'pipe_create':
        if (e.pipe) push(pipes, e.pipe.toLowerCase(), {t: e.t, key: from, seq: i});
        break;
      case 'pipe_connect': {
        const w = e.pipe ? lastBefore(pipes.get(e.pipe.toLowerCase()), e.t, from) : undefined;
        if (w) add('pipe', w.key, from, e.t, i, e.pipe);
        break;
      }
      case 'registry_set':
        if (e.reg?.key && PERSISTENCE_KEY.test(e.reg.key)) {
          for (const p of launchedPaths(e.reg.value)) push(persisted, p, {t: e.t, key: from, seq: i});
        }
        break;
      case 'service_install': case 'task_create':
        for (const p of launchedPaths(e.launches)) push(persisted, p, {t: e.t, key: from, seq: i});
        break;
    }
  }

  // Started from a file another process wrote (by path, or by hash when the file was renamed or copied).
  const startsByPath = new Map<string, ProcessNode[]>();
  for (const n of nodes.values()) {
    if (!n.starts.length) continue;
    const start = n.start;
    const byPath = n.path ? lastBefore(writes.get(pathKey(n.path)), start, n.key) : undefined;
    if (byPath) add('dropped_and_ran', byPath.key, n.key, start, byPath.seq, n.path, byPath.t);
    const byHash = n.sha256 ? lastBefore(hashes.get(n.sha256), start, n.key) : undefined;
    if (byHash && byHash.key !== byPath?.key) add('dropped_and_ran', byHash.key, n.key, start, byHash.seq, `same SHA-256 as ${events[byHash.seq]!.file_path ?? 'a written file'}`, byHash.t);
    if (n.path && n.start !== null) {
      const list = startsByPath.get(pathKey(n.path));
      if (list) list.push(n); else startsByPath.set(pathKey(n.path), [n]);
    }
  }
  // A Run key, service or task fires at the next logon or service start: each registration is linked
  // to the next start of what it launches, not to every later start of that program.
  for (const [path, registrations] of persisted) {
    const starts = (startsByPath.get(path) ?? []).sort((a, b) => a.start! - b.start! || a.key.localeCompare(b.key));
    for (const r of registrations) {
      const next = starts.find(n => n.key !== r.key && (r.t === null || n.start! >= r.t - SKEW));
      const event = events[r.seq]!;
      if (next) add('persisted_and_ran', r.key, next.key, next.start, r.seq, event.reg?.key ?? event.launches, r.t);
    }
  }

  addEntities(events, nodes, actor, order, add);

  const links = [...byId.values()].sort(compareLinks(nodes));
  const touching = new Map<string, Link[]>();
  const index = (key: string, link: Link) => { const list = touching.get(key); if (list) list.push(link); else touching.set(key, [link]); };
  for (const link of links) {
    index(link.from, link);
    if (UNDIRECTED.has(link.type)) index(link.to, link);
  }
  return {links, touching};
}

/** Time, then type, then names: an order that does not depend on how the source identified processes. */
export const compareLinks = (nodes: Map<string, ProcessNode>) => (a: Link, b: Link): number =>
  (a.t ?? Infinity) - (b.t ?? Infinity) || a.type.localeCompare(b.type) ||
  describe(nodes.get(a.from)).localeCompare(describe(nodes.get(b.from))) ||
  describe(nodes.get(a.to)).localeCompare(describe(nodes.get(b.to))) ||
  a.from.localeCompare(b.from) || a.to.localeCompare(b.to);

export const describe = (n: ProcessNode | undefined): string =>
  n ? `${(n.name ?? '').toLowerCase()}|${n.pid ?? ''}|${n.start ?? n.firstSeen ?? ''}` : '';
