// From the seed outwards: each round gathers everything a link connects to the incident (processes,
// and the accounts, hosts, addresses and domains of logs without processes), asks Jev about each one
// (one candidate per request by default, in parallel), and adds the ones Jev links. Requests contain
// only canonical fields with request-local labels, so the same incident in different telemetry, or
// the same input run twice, produces the same requests.
import type {EntityType, Event, Link, LinkType, ProcessNode} from './model.ts';
import {isInternal} from './entities.ts';
import type {Graph} from './links.ts';
import {compareLinks, describe, EXECUTABLE, injectionCapable, PERSISTENCE_KEY, UNDIRECTED} from './links.ts';
import type {JevClient, JevResponse} from './jev.ts';
import {sha256} from './jev.ts';

export interface InvestigateOptions {
  description: string;
  model: string;
  threshold: number;
  /** The threshold for an account, host, address or domain that nothing outside the incident ever touched
   * (default 0.5, or `threshold` if that is lower). Jev scores such exclusive attacker infrastructure well
   * below processes (0.55-0.77 for CLA-WS-219's C2) yet far above common infrastructure (0.05-0.20).
   * It also applies to a relaunch: a process running a file the incident wrote, started by persistence
   * the incident registered (0.76 for CLA-WS-216's SmcGui.exe relaunched by its Run key). */
  entityThreshold?: number;
  /** Other members the analyst already confirmed (node keys): they start in the incident beside the seed,
   * from their own start, so one investigation covers them all. */
  confirmed?: string[];
  /** Decisions this close to the threshold are flagged for review: Jev's answer to the identical
   * request varies by a few hundredths, so a fresh run could put them on the other side. */
  margin?: number;
  /** Candidates per request. 1 (the default) makes each decision depend only on that candidate's
   * own evidence; larger batches cost fewer tokens but other candidates in the request sway Jev. */
  batchSize: number;
  maxRounds: number;
  /** Stop asking (and report it) when one round would ask about more processes than this. */
  maxCandidatesPerRound: number;
  /** Ask once for candidates Jev would see as identical apart from PID and start time (default true). */
  group?: boolean;
  /** Called before each round's requests with its candidate groups and a builder for the exact
   * request any batch of them would send (used by bench/jev-batching.ts). */
  onRound?: (round: number, groups: Group[], build: (batch: Group[]) => {body: string; labels: string[]}) => void;
}

/** Clock difference tolerated between sources when ordering an action after a process joined. */
export const SKEW = 2_000_000;

export interface Decision {
  key: string;
  round: number;
  /** How many identical candidates this one answer decided (1 unless grouped). */
  group_size: number;
  probability: number;
  related: boolean;
  /** The threshold this decision used: `entityThreshold` for exclusive infrastructure, else `threshold`. */
  threshold: number;
  /** Within `margin` of the threshold. */
  review: boolean;
  links: Link[];
  request: string;  // SHA-256 of the request body that decided it
}

export interface Investigation {
  incident: string[];        // node keys in the order they joined (seed first)
  /** When each incident process became part of the incident (µs; null when unknown). */
  since: Map<string, number | null>;
  decisions: Map<string, Decision>;  // the latest decision per candidate
  history: Decision[];       // every decision, including re-asks
  rounds: number;
  stopped?: string;          // why the expansion stopped early, if it did
}

interface Context { events: Event[]; nodes: Map<string, ProcessNode>; graph: Graph; activity: Map<string, Activity>; seed: ProcessNode; since: Map<string, number | null>;
  /** The links each member joined through (the seed has none). */
  joined: Map<string, Link[]>;
  /** Members the analyst confirmed alongside the seed. */
  confirmed: Set<string> }

/** Ask Jev outward from the seed until no new process is linked. */
export async function investigate(events: Event[], nodes: Map<string, ProcessNode>, graph: Graph, seedKey: string,
  client: JevClient, options: InvestigateOptions): Promise<Investigation> {
  const seed = nodes.get(seedKey)!;
  const confirmed = [...new Set(options.confirmed ?? [])].filter(k => k !== seedKey && nodes.has(k));
  const incident = [seedKey, ...confirmed], members = new Set(incident);
  const since = new Map<string, number | null>([[seedKey, seed.start ?? seed.firstSeen],
    ...confirmed.map(k => [k, nodes.get(k)!.start ?? nodes.get(k)!.firstSeen] as [string, number | null])]);
  const ctx: Context = {events, nodes, graph, seed, since, activity: new Map(), joined: new Map(), confirmed: new Set(confirmed)};
  // Only what happened after a member joined the incident can carry the incident further. A link seen
  // many times (a host's lookups, a beacon) counts if any of it came after.
  const afterJoining = (member: string, link: Link) => {
    const joined = since.get(member) ?? null;
    const act = UNDIRECTED.has(link.type) ? link.last : link.from === member ? link.act : link.t;
    return joined === null || act === null || act >= joined - SKEW;
  };
  const decisions = new Map<string, Decision>(), history: Decision[] = [];
  const asked = new Map<string, string>();  // candidate -> signature of the links it was last asked with
  let round = 0, stopped: string | undefined;
  for (; round < options.maxRounds;) {
    const candidates = new Map<string, Link[]>();
    for (const member of incident) {
      for (const link of graph.touching.get(member) ?? []) {
        const other = link.from === member ? link.to : link.from;
        if (members.has(other) || (link.to !== other && !UNDIRECTED.has(link.type)) || !afterJoining(member, link)) continue;
        const list = candidates.get(other);
        if (list) list.push(link); else candidates.set(other, [link]);
      }
    }
    const pending = [...candidates].filter(([key, links]) => asked.get(key) !== signature(links));
    if (!pending.length) break;
    for (const [, links] of pending) links.sort(compareLinks(nodes));
    pending.sort(([a, la], [b, lb]) => compareLinks(nodes)(la[0]!, lb[0]!) || describe(nodes.get(a)).localeCompare(describe(nodes.get(b))) || a.localeCompare(b));
    const groups = group(ctx, pending, options.group ?? true);
    if (groups.length > options.maxCandidatesPerRound) {
      stopped = `round ${round + 1} would ask ${groups.length} questions about ${pending.length} candidates (limit ${options.maxCandidatesPerRound})`;
      break;
    }
    round++;
    options.onRound?.(round, groups, batch => request(ctx, batch, incident, options));
    const batches: Group[][] = [];
    for (let i = 0; i < groups.length; i += options.batchSize) batches.push(groups.slice(i, i + options.batchSize));
    const answered = await Promise.all(batches.map(async batch => {
      const {body, labels} = request(ctx, batch, incident, options);
      const response = await client.ask(body, batch.length);
      return {batch, labels, response, digest: sha256(body)};
    }));
    const joined: string[] = [];
    for (const {batch, labels, response, digest} of answered) {
      batch.forEach((g, i) => {
        const probability = readAnswer(response, labels[i]!);
        for (const [key, links] of g.members) {
          const threshold = thresholdFor(ctx, key, options, links);
          const decision: Decision = {key, round, group_size: g.members.length, probability, related: probability >= threshold, threshold,
            review: Math.abs(probability - threshold) < (options.margin ?? 0.05), links, request: digest};
          decisions.set(key, decision);
          history.push(decision);
          asked.set(key, signature(links));
          if (decision.related) joined.push(key);
        }
      });
    }
    for (const key of joined) {
      members.add(key);
      incident.push(key);
      // It joined when the link first reached it after the other side was already in the incident.
      const times = decisions.get(key)!.links.map(l => {
        const other = since.get(l.from === key ? l.to : l.from) ?? null;
        return l.t === null || other === null ? l.t : Math.max(l.t, other);
      }).filter((t): t is number => t !== null);
      since.set(key, times.length ? Math.min(...times) : null);
      ctx.joined.set(key, decisions.get(key)!.links);
    }
    if (!joined.length) break;  // Nothing new joined, so no new links can appear.
  }
  if (!stopped && round >= options.maxRounds) stopped = `stopped after ${options.maxRounds} rounds`;
  return {incident, since, decisions, history, rounds: round, ...(stopped ? {stopped} : {})};
}

export interface Group { members: [string, Link[]][] }

/** Nothing outside the incident ever touched this account, host, address or domain. */
function exclusive(ctx: Context, key: string): boolean {
  const n = ctx.nodes.get(key)!;
  return n.type !== 'process' && (ctx.graph.touching.get(key) ?? []).every(l => ctx.since.has(l.from === key ? l.to : l.from));
}

/** The incident's own program started again by its own persistence: a member wrote the file this process
 * runs and a member registered what started it. With no parent in the incident, Jev scores it below its first run. */
function relaunched(ctx: Context, key: string, links: Link[]): boolean {
  if (ctx.nodes.get(key)!.type !== 'process') return false;
  const by = (type: Link['type']) => links.some(l => l.type === type && l.to === key && ctx.since.has(l.from));
  return by('dropped_and_ran') && by('persisted_and_ran');
}

function thresholdFor(ctx: Context, key: string, options: InvestigateOptions, links: Link[] = []): number {
  return exclusive(ctx, key) || relaunched(ctx, key, links) ? Math.min(options.threshold, options.entityThreshold ?? 0.5) : options.threshold;
}

/** Candidates that Jev would see identically apart from PID and start time share one question. */
function group(ctx: Context, pending: [string, Link[]][], enabled: boolean): Group[] {
  if (!enabled) return pending.map(member => ({members: [member]}));
  const groups = new Map<string, Group>();
  for (const [key, links] of pending) {
    const {pid: _pid, started: _started, ended: _ended, first_seen: _first, last_seen: _last, ...what} = summary(ctx, key) as Record<string, unknown>;
    const {since: _since, ...did} = activity(ctx, key, firstLink(links));
    const id = JSON.stringify([what, links.map(l => [l.type, l.from === key ? l.to : l.from, l.detail]), did]);
    const g = groups.get(id);
    if (g) g.members.push([key, links]); else groups.set(id, {members: [[key, links]]});
  }
  return [...groups.values()];
}

/** When the earliest link reached a candidate: what it did from then on is what matters. */
const firstLink = (links: Link[]): number | null => {
  const times = links.map(l => l.t).filter((t): t is number => t !== null);
  return times.length ? Math.min(...times) : null;
};

const signature = (links: Link[]) => links.map(l => `${l.type}|${l.from}|${l.to}`).sort().join(',');

function readAnswer(response: JevResponse, label: string): number {
  const p = response.answers[label]?.noul;
  if (typeof p !== 'number' || !Number.isFinite(p) || p < 0 || p > 1) {
    throw new Error(`Jev returned an unusable answer for ${label}; no decision was assumed`);
  }
  return p;
}

// ---- What Jev sees ---------------------------------------------------------------------------

/** "+1d 02:03:04" from the seed's start, whole seconds, so sub-second clock differences between sources vanish. */
export function relative(t: number | null, origin: number | null): string | null {
  if (t === null || origin === null) return null;
  const total = Math.trunc((t - origin) / 1e6), sign = total < 0 ? '-' : '+', s = Math.abs(total);
  const days = Math.floor(s / 86400), hms = [Math.floor(s / 3600) % 24, Math.floor(s / 60) % 60, s % 60].map(x => String(x).padStart(2, '0')).join(':');
  return `${sign}${days ? `${days}d ` : ''}${hms}`;
}

const clip = (s: string | undefined, n: number) => s === undefined ? undefined : s.length > n ? `${s.slice(0, n)}…` : s;
const compact = <T extends object>(o: T): T => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null &&
  !(Array.isArray(v) && !v.length))) as T;

interface Activity {
  since?: string | null;
  children: string[]; child_count: number;
  wrote: string[]; write_count: number;
  network: string[]; dns: string[];
  registry: string[]; injected_into: string[]; opened: string[]; accessed: string[]; pipes: string[];
}
const SAMPLES = 5;
const importantFirst = (items: [boolean, string][]) => [...items.filter(([x]) => x), ...items.filter(([x]) => !x)].map(([, v]) => v);

/**
 * What a process did from `from` on (everything when null), as bounded samples: the items that
 * matter most first (executables and scripts written, persistence keys set), then by time. The
 * same input always gives the same summary.
 */
function activity(ctx: Context, key: string, from: number | null): Activity | EntityActivity {
  const id = `${key}@${from}`;
  const cached = ctx.activity.get(id);
  if (cached) return cached;
  const n = ctx.nodes.get(key)!;
  if (n.type !== 'process') return entityActivity(ctx, n, from, id);
  const after = (t: number | null) => from === null || t === null || t >= from - SKEW;
  const wrote: [boolean, string][] = [], registry: [boolean, string][] = [];
  const a: Activity = {children: [], child_count: 0, wrote: [], write_count: 0, network: [], dns: [], registry: [], injected_into: [], opened: [], accessed: [], pipes: []};
  const add = (list: string[], value: string | undefined, max = SAMPLES) => { if (value && list.length < max && !list.includes(value)) list.push(value); };
  for (const i of n.events) {
    const e = ctx.events[i]!;
    if (!after(e.t)) continue;
    switch (e.kind) {
      case 'file_create': a.write_count++; if (e.file_path) wrote.push([EXECUTABLE.test(e.file_path), e.file_path]); break;
      case 'network': add(a.network, [e.net?.domain ?? e.net?.ip, e.net?.port].filter(x => x !== undefined).join(':')); break;
      case 'dns': add(a.dns, e.net?.domain); break;
      case 'registry_set': if (e.reg?.key) registry.push([PERSISTENCE_KEY.test(e.reg.key), `${e.reg.key} = ${clip(e.reg.value, 160) ?? ''}`]); break;
      case 'pipe_create': case 'pipe_connect': add(a.pipes, e.pipe, 3); break;
      case 'process_access':  // Handles that cannot inject but can read, such as credential access to lsass.exe.
        if (e.access !== undefined && !injectionCapable(e.access)) add(a.accessed, `${e.target?.name ?? e.target?.path ?? 'a process'} (0x${e.access.toString(16)})`);
        break;
    }
  }
  for (const value of importantFirst(wrote)) add(a.wrote, value);
  for (const value of importantFirst(registry)) add(a.registry, value, 3);
  for (const link of ctx.graph.touching.get(key) ?? []) {
    if (link.from !== key || !after(link.act)) continue;
    const other = ctx.nodes.get(link.to)?.name;
    if (link.type === 'spawned') { a.child_count++; add(a.children, other); }
    if (link.type === 'injected') add(a.injected_into, other);
    if (link.type === 'opened_for_injection') add(a.opened, other && `${other} (${link.detail})`);
  }
  if (from !== null) a.since = relative(from, ctx.seed.start ?? ctx.seed.firstSeen);
  ctx.activity.set(id, a);
  return a;
}

// ---- Entities other than processes -------------------------------------------------------------

const TYPE_NAME: Record<EntityType, string> = {process: 'process', host: 'host', user: 'account', ip: 'IP address', domain: 'domain'};
const PLURAL: Record<EntityType, string> = {process: 'processes', host: 'hosts', user: 'accounts', ip: 'addresses', domain: 'domains'};

/** How a link reads from one of its ends ("contacted by", "logged on to"...). */
const RELATION: Partial<Record<LinkType, [string, string]>> = {  // [as the link's source, as its target]
  contacted: ['contacted', 'contacted by'],
  logged_on: ['logged on to', 'logons by accounts'],
  logon_from: ['logged on to', 'logons from'],
  used_account: ['logged on as', 'logons from'],
  failed_logon: ['failed to log on as', 'failed logons from'],
  requested: ['sent web requests to', 'web requests from'],
  pipe: ['shares a named pipe with', 'shares a named pipe with'],
};

interface EntityActivity { since?: string | null; [relation: string]: unknown }

const nodeLabel = (n: ProcessNode | undefined): string =>
  !n ? '?' : n.type === 'process' ? `${n.name ?? '?'} (${n.pid ?? '?'})` : n.name ?? n.key;

/** Who an account, host, address or domain dealt with from `from` on: each relation with a count and examples. */
function entityActivity(ctx: Context, n: ProcessNode, from: number | null, id: string): EntityActivity {
  const by = new Map<string, Set<string>>();
  for (const link of ctx.graph.touching.get(n.key) ?? []) {
    if (from !== null && link.t !== null && link.t < from - SKEW) continue;
    const relation = RELATION[link.type]?.[link.from === n.key ? 0 : 1];
    if (!relation) continue;
    const other = ctx.nodes.get(link.from === n.key ? link.to : link.from);
    const set = by.get(relation) ?? new Set<string>();
    set.add(`${TYPE_NAME[other?.type ?? 'process']} ${nodeLabel(other)}`);
    by.set(relation, set);
  }
  const a: EntityActivity = {};
  for (const [relation, others] of [...by].sort(([x], [y]) => x.localeCompare(y))) a[relation] = {count: others.size, examples: [...others].slice(0, SAMPLES)};
  if (from !== null) a.since = relative(from, ctx.seed.start ?? ctx.seed.firstSeen);
  ctx.activity.set(id, a as never);
  return a;
}

/** An account, host, address or domain as Jev sees it, with its prevalence across the whole input: an
 * address that hundreds of processes and hosts contact is common infrastructure, one only the incident
 * touches is not. */
function entitySummary(ctx: Context, n: ProcessNode) {
  const origin = ctx.seed.start ?? ctx.seed.firstSeen;
  const seen = new Map<EntityType, Set<string>>();
  for (const link of ctx.graph.touching.get(n.key) ?? []) {
    const other = ctx.nodes.get(link.from === n.key ? link.to : link.from);
    if (!other) continue;
    const set = seen.get(other.type) ?? new Set<string>();
    set.add(other.key);
    seen.set(other.type, set);
  }
  let last: number | null = null;
  for (const i of n.events) { const t = ctx.events[i]!.t; if (t !== null && (last === null || t > last)) last = t; }
  // The same counts without the incident's own members: "none" means only the incident ever touched it.
  const outside = [...seen].map(([type, keys]) => [type, [...keys].filter(k => !ctx.since.has(k)).length] as const).filter(([, n]) => n > 0);
  return compact({
    type: TYPE_NAME[n.type], name: n.name,
    scope: n.type === 'ip' ? (isInternal(n.name ?? '') ? 'internal' : 'external') : undefined,
    first_seen: relative(n.firstSeen, origin), last_seen: relative(last, origin), events: n.events.length,
    seen_with: Object.fromEntries([...seen].sort(([a], [b]) => a.localeCompare(b)).map(([type, keys]) => [PLURAL[type], keys.size])),
    seen_outside_incident: outside.length ? Object.fromEntries(outside.sort(([a], [b]) => a.localeCompare(b)).map(([type, n]) => [PLURAL[type], n])) : 'none',
  });
}

/** Any candidate as Jev sees it. */
function summary(ctx: Context, key: string) {
  const n = ctx.nodes.get(key)!;
  return n.type === 'process' ? {type: 'process', ...processSummary(ctx, key)} : entitySummary(ctx, n);
}

function processSummary(ctx: Context, key: string) {
  const n = ctx.nodes.get(key)!, origin = ctx.seed.start ?? ctx.seed.firstSeen;
  const parent = n.parent ? ctx.nodes.get(n.parent) : undefined;
  return compact({
    name: n.name, path: n.path, command_line: clip(n.cmd, 600), pid: n.pid, user: n.user, sha256: n.sha256,
    host: n.host !== ctx.seed.host ? n.host : undefined,
    started: n.start !== null ? relative(n.start, origin) : `before the logs (first seen ${relative(n.firstSeen, origin) ?? 'unknown'})`,
    ended: relative(n.end, origin), parent: parent?.name,
  });
}

/** What a link says about a candidate, from the candidate's side. Links between processes always
 * point at the candidate; links between other entities can point either way. */
function linkText(type: LinkType, candidateIsTarget: boolean): string {
  switch (type) {
    case 'spawned': return 'started this process';
    case 'injected': return 'injected code into this process';
    case 'opened_for_injection': return 'opened this process with injection-capable access';
    case 'dropped_and_ran': return 'wrote the file this process was started from';
    case 'dropped_and_loaded': return 'wrote a DLL this process loaded';
    case 'pipe': return 'shares a named pipe with this candidate';
    case 'persisted_and_ran': return 'registered persistence that later started this process';
    case 'contacted': return candidateIsTarget ? 'contacted this candidate' : 'was contacted by this candidate';
    case 'logged_on': return candidateIsTarget ? 'logged on to this candidate' : 'is a host this account logged on to';
    case 'logon_from': return candidateIsTarget ? 'logged on to this candidate' : 'received a logon from this candidate';
    case 'used_account': return candidateIsTarget ? 'logged on using this account' : 'is an account this candidate logged on as';
    case 'failed_logon': return candidateIsTarget ? 'tried and failed to log on as this account' : 'is an account this candidate failed to log on as';
    case 'requested': return candidateIsTarget ? 'sent web requests to this candidate' : 'received web requests from this candidate';
  }
}

// Only relatedness is asked. How a process is linked is already recorded exactly by its links, and a
// Choice between overlapping bases (a dropped file run as a child is both lineage and artifact)
// changed between identical requests in the live batching check.
const question = (label: string) => ({
  [label]: {type: 'noul', instructions: `Is candidate ${label} part of the same incident as the seed, with the attacker's activity continuing through it?`,
    criteria: {true: 'Same incident: the links and activity show the attacker\'s activity continuing through this candidate (a process, account, host, address or domain)',
      false: 'Independent, benign or common activity (such as widely used infrastructure), or not enough evidence to link it'}},
});

/** How an incident member joined: the links that brought it in, from the members they came from (at most three). */
function joinedVia(ctx: Context, key: string): {what: string; from: string}[] | undefined {
  if (ctx.confirmed.has(key)) return [{what: 'confirmed by the analyst as part of this incident', from: 'analyst'}];
  const links = ctx.joined.get(key);
  return links?.length ? links.slice(0, 3).map(l => ({what: linkText(l.type, l.to === key), from: nodeLabel(ctx.nodes.get(l.from === key ? l.to : l.from))})) : undefined;
}

/** The exact request body for one batch, and the label of each candidate in it. */
function request(ctx: Context, batch: Group[], incident: string[], options: InvestigateOptions): {body: string; labels: string[]} {
  const origin = ctx.seed.start ?? ctx.seed.firstSeen;
  // Incident processes this batch's links come from, labelled in the order they joined (seed first).
  const sources = new Set(batch.flatMap(g => g.members.flatMap(([key, links]) => links.map(l => l.from === key ? l.to : l.from))));
  const label = new Map<string, string>([[ctx.seed.key, 'seed']]);
  const involved = incident.filter(k => k !== ctx.seed.key && sources.has(k));
  involved.forEach((k, i) => label.set(k, `I${i + 1}`));
  const labels = batch.map((_, i) => `C${i + 1}`);
  const candidates: Record<string, unknown> = {};
  batch.forEach((g, i) => {
    const [key, links] = g.members[0]!;
    const repeats = g.members.length > 1 ? compact({occurrences: g.members.length,
      first_started: relative(ctx.nodes.get(key)!.start, origin), last_started: relative(ctx.nodes.get(g.members.at(-1)![0])!.start, origin)}) : {};
    candidates[labels[i]!] = {
      ...summary(ctx, key), ...repeats,
      links: links.map(l => compact({from: label.get(l.from === key ? l.to : l.from), what: linkText(l.type, l.to === key),
        at: relative(l.t, origin), ...(l.count > 1 ? {times: l.count, last: relative(l.last, origin)} : {}), detail: clip(l.detail, 200)})),
      activity: compact(activity(ctx, key, firstLink(links))),
    };
  });
  const state = {
    analyst_context: options.description,
    seed: {...summary(ctx, ctx.seed.key), activity: compact(activity(ctx, ctx.seed.key, null))},
    incident: Object.fromEntries(involved.map(k => [label.get(k)!,
      compact({...summary(ctx, k), joined_incident: relative(ctx.since.get(k) ?? null, origin), joined_via: joinedVia(ctx, k)})])),
    candidates,
  };
  const questions = Object.assign({}, ...labels.map(question));
  return {body: JSON.stringify({model: options.model, state, questions}), labels};
}
