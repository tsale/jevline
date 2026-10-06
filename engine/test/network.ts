// An intrusion seen through logs without processes, in custom formats the engine has no rules for:
// an authentication log, firewall flows and a web access log. Times are seconds from T0 (the seed's
// start in incident.ts), so these logs line up with the Sysmon incident there.
import {T0} from './incident.ts';

const iso = (t: number) => new Date(T0 + t * 1000).toISOString();
export const ATTACKER = '198.51.100.66', C2 = '203.0.113.9';
const HOSTS = {'ws-01': '10.0.0.5', 'ws-02': '10.0.0.7', 'srv-01': '10.0.1.10', 'db-01': '10.0.1.20', 'web-01': '10.0.2.30'} as const;
type Host = keyof typeof HOSTS;

interface Auth { t: number; ok: boolean; user: string; from: string; to: Host; method: string }
const AUTH: Auth[] = [
  // Everyday logons (they also tell which address each host has).
  {t: -3000, ok: true, user: 'bob', from: HOSTS['ws-02'], to: 'ws-02', method: 'interactive'},
  {t: -2900, ok: true, user: 'alice', from: HOSTS['ws-01'], to: 'ws-01', method: 'interactive'},
  {t: -2800, ok: true, user: 'svc_backup', from: HOSTS['srv-01'], to: 'srv-01', method: 'service'},
  {t: -2700, ok: true, user: 'dba', from: HOSTS['db-01'], to: 'db-01', method: 'interactive'},
  {t: -2600, ok: true, user: 'www', from: HOSTS['web-01'], to: 'web-01', method: 'service'},
  // Unrelated brute force against another account.
  {t: -100, ok: false, user: 'admin', from: '192.0.2.50', to: 'web-01', method: 'ssh'},
  {t: -99, ok: false, user: 'admin', from: '192.0.2.50', to: 'web-01', method: 'ssh'},
  // The intrusion: a failed then successful remote logon as svc_backup, then on to the database server.
  {t: 60, ok: false, user: 'svc_backup', from: ATTACKER, to: 'srv-01', method: 'rdp'},
  {t: 65, ok: true, user: 'svc_backup', from: ATTACKER, to: 'srv-01', method: 'rdp'},
  {t: 400, ok: true, user: 'svc_backup', from: HOSTS['srv-01'], to: 'db-01', method: 'rdp'},
];

/** Authentication as JSON lines. */
export const authJson = (): string => AUTH.map(a => JSON.stringify({ts: iso(a.t), event: a.ok ? 'login_success' : 'login_failure', user: a.user,
  src_ip: a.from, dst_host: a.to, dst_ip: HOSTS[a.to], method: a.method})).join('\n') + '\n';

/** The same authentication log as CSV with other column names and values. */
export const authCsv = (): string => ['Timestamp,EventName,UserName,ClientIP,TargetHost,TargetIP,AuthMethod',
  ...AUTH.map(a => [iso(a.t), a.ok ? 'LoginSucceeded' : 'LoginFailed', a.user, a.from, a.to.toUpperCase(), HOSTS[a.to], a.method].join(','))].join('\n') + '\n';

interface Flow { t: number; src: string; dst: string; port: number }
const FLOWS: Flow[] = [
  ...(Object.values(HOSTS).map((ip, i) => ({t: -1000 + i, src: ip, dst: '8.8.8.8', port: 53}))),  // everyone uses the same resolver
  ...(Object.values(HOSTS).map((ip, i) => ({t: 1000 + i, src: ip, dst: '8.8.8.8', port: 53}))),
  {t: 3, src: HOSTS['ws-01'], dst: C2, port: 443},       // the malware on ws-01 calls its C2
  {t: 120, src: ATTACKER, dst: HOSTS['srv-01'], port: 3389},  // the attacker's remote desktop session
  {t: 700, src: HOSTS['ws-02'], dst: C2, port: 443},     // another host reaches the same C2 later
];

/** Firewall flows as CSV. */
export const firewallCsv = (): string => ['time,src_ip,src_port,dst_ip,dst_port,proto,action,bytes',
  ...FLOWS.map((f, i) => [iso(f.t), f.src, 50000 + i, f.dst, f.port, 'tcp', 'allow', 1200 + i].join(','))].join('\n') + '\n';

/** Web server access log as JSON lines. */
export const webJson = (): string => [
  {t: -200, client_ip: ATTACKER, method: 'GET', url: '/admin/login.php', status: 200},
  {t: -150, client_ip: HOSTS['ws-01'], method: 'GET', url: '/', status: 200},
  {t: 30, client_ip: ATTACKER, method: 'POST', url: '/admin/upload.php', status: 200},
  {t: 50, client_ip: '203.0.113.77', method: 'GET', url: '/index.html', status: 200},
].map(r => JSON.stringify({time: iso(r.t), client_ip: r.client_ip, method: r.method, url: r.url, status: r.status, vhost: 'web-01',
  bytes: 5120, user_agent: 'Mozilla/5.0'})).join('\n') + '\n';
