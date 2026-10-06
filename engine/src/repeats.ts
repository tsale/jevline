// Repeated activity, folded. The same thing done again without any meaningful change (a beacon to
// the same address and port, one failed logon after another, a scheduled relaunch of the same command)
// is reported once, with how many times it happened, its first and last time and how often it
// repeated. Anything that differs (a destination, a domain, an account, a registry value, an
// executable's name, the process that acted or the parent that started it) is a separate row, and so
// is activity that resumes after a long pause. Only numbers and random-looking tokens in a process's
// folder and arguments, in registry key paths and in the names of other files are not a change:
// installers rerun from is-OB9B3JUD4C.tmp, browser cache entries f_00a1b2, RecentDocs\12.
import type {Link, ProcessNode} from './model.ts';
import {EXECUTABLE} from './links.ts';

/** Repeats further apart than this (and than 3× their usual interval) start a new row: the activity
 * stopped and later resumed, which is worth seeing. */
export const QUIET = 3600 * 1e6;

/** Text with its changing parts as '#': numbers, and tokens with digits in them that look generated
 * (OB9B3JUD4C, f_00a1b2, $8D0572). Words stay as they are. */
export const variable = (text: string): string =>
  text.replace(/[A-Za-z0-9]+/g, t => /\d/.test(t) && (t.length >= 4 || /^\d+$/.test(t)) ? '#' : t);

/** What two events' details must share to be the same activity: a command line, a registry key path or
 * the name of a file that is not an executable, apart from their changing parts; registry values and
 * anything else exactly. */
export function sameDetail(kind: string, detail: string | undefined): string | undefined {
  if (detail === undefined) return undefined;
  if (kind === 'process_start') return variable(detail);
  if ((kind === 'file_create' || kind === 'file_delete' || kind === 'file_time') && !EXECUTABLE.test(detail)) return variable(detail);
  if (kind === 'registry_set') { const at = detail.indexOf(' = '); return at < 0 ? variable(detail) : variable(detail.slice(0, at)) + detail.slice(at); }
  return detail;
}

/**
 * Incident members that are the same process again: on the same host, the same executable (its folder
 * and command line apart from their changing parts) with the same user and hash, started by the same
 * (or an identical) parent and linked to the incident the same way. `order` is the members by start
 * time; each gets its representative, the earliest of its identical set. Members in `keep` (the seed)
 * and accounts, hosts, addresses and domains, which are unique by definition, represent themselves.
 */
export function identicalMembers(order: string[], nodes: Map<string, ProcessNode>, linksOf: (key: string) => Link[] | undefined,
  keep: Set<string>): Map<string, string> {
  let representative = new Map<string, string>();
  // A member can be linked from one that started after it (clocks differ between sources), so repeat
  // until every member's links are compared through their final representatives.
  for (let pass = 0; pass < 5; pass++) {
    const previous = representative, next = new Map<string, string>(), first = new Map<string, string>();
    const as = (key: string | undefined) => key === undefined ? '' : next.get(key) ?? previous.get(key) ?? key;
    for (const key of order) {
      const n = nodes.get(key)!;
      if (n.type !== 'process' || keep.has(key)) { next.set(key, key); continue; }
      const via = [...new Set((linksOf(key) ?? []).map(l => `${l.type}>${as(l.from === key ? l.to : l.from)}`))].sort();
      const path = (n.path ?? n.name ?? '').toLowerCase(), cut = path.search(/[^\\/]*$/);
      const id = JSON.stringify([n.host, variable(path.slice(0, cut)), path.slice(cut), n.cmd && variable(n.cmd), n.user, n.sha256, as(n.parent), via]);
      const earlier = first.get(id);
      if (earlier === undefined) first.set(id, key);
      next.set(key, earlier ?? key);
    }
    representative = next;
    if ([...next].every(([k, r]) => previous.get(k) === r)) break;
  }
  return representative;
}

/**
 * Time-ordered items split into runs of the same activity (items with the same key). A run continues
 * while each repeat comes within QUIET of the one before, or within 3× the activity's usual interval
 * when it repeats on a longer cycle (an hourly task stays one run). Runs are ordered by their first item.
 */
export function runs<T>(items: T[], keyOf: (item: T) => string, timeOf: (item: T) => number | null): number[][] {
  const keys = items.map(keyOf), times = new Map<string, number[]>();
  keys.forEach((k, i) => {
    const t = timeOf(items[i]!);
    if (t === null) return;
    const list = times.get(k);
    if (list) list.push(t); else times.set(k, [t]);
  });
  const limit = new Map<string, number>();
  for (const [k, list] of times) {
    const gaps = gapsOf(list);
    limit.set(k, gaps.length >= 4 ? Math.max(QUIET, 3 * median(gaps)) : QUIET);
  }
  const open = new Map<string, {run: number[]; last: number | null}>(), result: number[][] = [];
  keys.forEach((k, i) => {
    const t = timeOf(items[i]!), current = open.get(k);
    if (current && (t === null || current.last === null || t - current.last <= limit.get(k)!)) {
      current.run.push(i);
      if (t !== null) current.last = t;
      return;
    }
    const run = [i];
    result.push(run);
    open.set(k, {run, last: t});
  });
  return result;
}

const gapsOf = (times: number[]) => times.slice(1).map((t, i) => t - times[i]!);
const median = (xs: number[]) => xs.toSorted((a, b) => a - b)[xs.length >> 1]!;

/** The usual interval between repeats in seconds (one decimal), when there are enough of them to tell. */
export function interval(times: number[]): number | undefined {
  const gaps = gapsOf(times);
  return gaps.length >= 2 ? Math.round(median(gaps) / 1e5) / 10 : undefined;
}
