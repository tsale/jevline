// Entities other than processes: the accounts, hosts, addresses and domains an intrusion moves
// through, and the links events make between them (and to processes). This is what lets logs without
// processes (authentication, firewall, proxy, web server, DNS) take part in an incident.
import type {EntityType, Event, LinkType, ProcessNode} from './model.ts';
import {canonicalHost} from './normalize.ts';

/** Built-in and machine identities: they log on all the time and say nothing about an intrusion. */
const SERVICE_ACCOUNT = /^(system|local service|network service|localservice|networkservice|anonymous logon|dwm-\d+|umfd-\d+|-|n\/a|unknown)$/i;
export const isServiceAccount = (name: string): boolean => name.endsWith('$') || SERVICE_ACCOUNT.test(name);
const NOWHERE = /^(127\.|0\.0\.0\.0$|::1?$|169\.254\.|fe80:)/i;

/** Private (RFC 1918 / unique local) addresses: internal to the organisation. */
export const isInternal = (ip: string): boolean => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd][0-9a-f]{2}:)/i.test(ip);

type Add = (type: LinkType, from: string, to: string, t: number | null, seq: number | null, detail?: string) => void;

/**
 * Add account, host, address and domain nodes to `nodes` and link them through `add`:
 * - a process (or, for flows with no process, the source host or address) `contacted` the
 *   destination address and domain of a connection or lookup;
 * - an account `logged_on` to a host; the logon came from an address or host (`logon_from`), which
 *   `used_account` (or `failed_logon` as) that account;
 * - an address `requested` pages from a web server.
 * An internal address is the host it belongs to whenever an event says which host has it.
 */
export function addEntities(events: Event[], nodes: Map<string, ProcessNode>, actor: string[], order: number[], add: Add): void {
  const hostByIp = new Map<string, string>();
  for (const e of events) for (const ip of e.host_ips ?? []) if (e.host && !hostByIp.has(ip)) hostByIp.set(ip, e.host);

  const entity = (type: EntityType, value: string, t: number | null, seq: number): string => {
    const key = `${type}:${value}`;
    let n = nodes.get(key);
    if (!n) {
      n = {key, type, host: type === 'host' ? value : '', name: value, start: null, firstSeen: t, end: null, events: [], starts: []};
      nodes.set(key, n);
    } else if (t !== null && (n.firstSeen === null || t < n.firstSeen)) {
      n.firstSeen = t;
    }
    if (n.events.at(-1) !== seq) n.events.push(seq);
    return key;
  };
  /** The node an address stands for: the host it belongs to, the address itself, or nothing for loopback. */
  const place = (ip: string | undefined, t: number | null, seq: number): string | null => {
    if (!ip || NOWHERE.test(ip)) return null;
    const host = hostByIp.get(ip);
    return host ? entity('host', host, t, seq) : entity('ip', ip.toLowerCase(), t, seq);
  };
  const domain = (name: string | undefined, t: number | null, seq: number): string | null => {
    const d = name?.trim().toLowerCase().replace(/\.$/, '');
    if (!d || /^[0-9.]+$/.test(d) || !d.includes('.')) return d && /^[0-9.]+$/.test(d) ? place(d, t, seq) : null;
    return entity('domain', d, t, seq);
  };
  const urlHost = (url: string | undefined) => /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i.exec(url ?? '')?.[1];

  for (const i of order) {
    const e = events[i]!, t = e.t;
    switch (e.kind) {
      case 'network': case 'dns': {
        // A relayed DNS answer is not a contact by the resolver: the asking process's lookup links instead.
        if (e.dns_answer) break;
        // Who connected: the process when the event names one, otherwise the source (a firewall flow).
        const from = actor[i] || place(e.src?.ip, t, i);
        if (!from) break;
        const port = e.net?.port !== undefined ? `port ${e.net.port}` : undefined;
        const to = [place(e.net?.ip, t, i), domain(e.net?.domain, t, i)].filter((k): k is string => k !== null && k !== from);
        for (const k of to) add('contacted', from, k, t, i, port);
        break;
      }
      case 'logon': case 'logon_failed': {
        if (!e.host) break;
        const host = entity('host', e.host, t, i);
        const user = e.account && !isServiceAccount(e.account) ? entity('user', e.account, t, i) : null;
        const sourceHost = e.src?.host ? canonicalHost(e.src.host) : undefined;
        let from = place(e.src?.ip, t, i);
        if (!from && sourceHost && sourceHost !== e.host && !/^(-|localhost)$/.test(sourceHost)) from = entity('host', sourceHost, t, i);
        if (from === host) from = null;
        const how = e.logon_type ? `logon type ${e.logon_type}` : undefined;
        if (e.kind === 'logon') {
          if (user) add('logged_on', user, host, t, i, how);
          if (from) add('logon_from', from, host, t, i, how);
          if (from && user) add('used_account', from, user, t, i, how);
        } else if (from && user) {
          add('failed_logon', from, user, t, i, how);
        }
        break;
      }
      case 'http_request': {
        const from = place(e.src?.ip, t, i);
        const server = e.host ? entity('host', e.host, t, i) : domain(urlHost(e.http?.url), t, i);
        const detail = [e.http?.method, e.http?.url, e.http?.status].filter(x => x !== undefined).join(' ') || undefined;
        if (from && server && from !== server) add('requested', from, server, t, i, detail);
        break;
      }
    }
  }
}
