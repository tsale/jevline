// An offline stand-in for Jev, for benchmarks, tests and dry runs. It reads the same request bodies
// Jev would get. Incident questions are answered from the link types alone; schema questions from
// field-name words and value shapes. It is not Jev, and results produced with it are labelled as such.
import type {JevResponse, Transport} from './jev.ts';
import {KINDS, ROLE_MENUS, type LearnedKind, type Role} from './schema.ts';

const SCORES: [RegExp, number][] = [
  [/injected code/, 0.95],
  [/wrote the file this process was started from/, 0.9],
  [/registered persistence/, 0.9],
  [/started this process/, 0.9],
  [/wrote a DLL/, 0.85],
  [/logged on to this candidate|logged on using this account|received a logon from|an account this candidate logged on as|a host this account logged on to/, 0.85],
  [/sent web requests to this candidate/, 0.8],    // an incident address attacking a server
  [/received web requests from this candidate/, 0.3],  // another visitor of a server in the incident
  [/failed to log on/, 0.6],
  [/injection-capable access/, 0.5],
  [/named pipe/, 0.4],
];
/** Contact with an address or domain counts only when few hosts (and processes) in the whole input
 * touched it: common infrastructure is contacted from everywhere. */
const rare = (seen: Record<string, number> | undefined) => (seen?.hosts ?? 0) <= 3 && (seen?.processes ?? 0) <= 5;

const KIND_WORDS: [RegExp, keyof typeof KINDS][] = [
  [/(logon|login|signin|auth).*fail|fail.*(logon|login|signin|auth)|invalidpassword|badpassword|^4625$/, 'logon_failed'],
  [/logon|login|signin|authenticat|sessionopen|accepted|^4624$/, 'logon'],
  [/inject|remotethread|queueuserapc|writeprocessmemory|setthreadcontext|^8$/, 'inject'],
  [/openprocess|processaccess|handle|^10$/, 'process_access'],
  // File writes first: names like NewExecutableWritten would otherwise read as process starts.
  [/filedelet|^23$|^26$/, 'file_delete'],
  [/filecreat|filewrit|written|newexecutable|filemodif|filerenam|^11$|^29$/, 'file_create'],
  [/processcreat|processrollup|process_?start|processlaunch|^exec|^1$|^4688$/, 'process_start'],
  [/endofprocess|processterminat|process_?end|processexit|^5$|^4689$/, 'process_end'],
  [/imageload|moduleload|^7$/, 'image_load'],
  [/dns/, 'dns'],
  [/network|connect|^3$/, 'network'],
  [/registry|regvalue|asep|^13$/, 'registry_set'],
  [/pipe.*connect|^18$/, 'pipe_connect'],
  [/pipe|^17$/, 'pipe_create'],
  [/service.*install|^7045$|^4697$/, 'service_install'],
  [/scheduledtask|taskcreat|^4698$/, 'task_create'],
];

const words = (name: string) => name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

function guessKind(eventType: string | null, fields: FieldInfo[]): keyof typeof KINDS {
  const value = (eventType?.split(' = ').at(-1) ?? '').toLowerCase().replace(/[\s_-]/g, '');
  const known = KIND_WORDS.find(([re]) => re.test(value))?.[1];
  if (known) return known;
  // No telling event type: go by the fields (a web access log has a URL, a flow has two addresses).
  const names = fields.map(f => words(f.name)), any = (...xs: string[]) => names.some(w => xs.some(x => w.includes(x)));
  if (any('url', 'uri')) return 'http_request';
  if (any('login', 'logon', 'auth') && any('user', 'account')) return /fail|denied|invalid/.test(value) ? 'logon_failed' : 'logon';
  const ips = fields.filter(f => f.looks_like.includes('ipv4') || f.looks_like.includes('ipv6')).length;
  return ips >= 2 ? 'network' : 'other';
}

interface FieldInfo { name: string; looks_like: string[]; examples: string[] }

/** The role a field most likely has, from its name and values, in an event of the given kind, and
 * how sure the guess is (a full path beats a bare file name for the same role). */
function guessRole(f: FieldInfo, kind: string, typeField: string | undefined): [Role, number] {
  const w = words(f.name), has = (...xs: string[]) => xs.some(x => w.includes(x));
  const timeLike = f.looks_like.includes('iso_time') || f.looks_like.includes('epoch_time');
  if (typeField && f.name === typeField) return ['event_type', 0.9];
  const parentish = has('parent', 'initiating', 'creator'), context = has('context', 'actor') || (has('source', 'src') && has('process'));
  const targetish = has('target');
  const created = has('creation', 'created', 'start', 'started');
  const start = kind === 'process_start', end = kind === 'process_end', actedOn = kind === 'inject' || kind === 'process_access';
  const fileKind = ['file_create', 'file_delete', 'image_load', 'pipe_create', 'pipe_connect'].includes(kind);
  // Logons and web requests: the account, where it came from, and the host it reached.
  if (kind === 'logon' || kind === 'logon_failed' || kind === 'http_request') {
    const fromSide = has('src', 'source', 'client', 'remote', 'origin', 'workstation');
    if (has('ip', 'addr', 'address')) return fromSide ? ['source_ip', 0.9] : ['host_ip', 0.9];
    if (has('port')) return [fromSide ? 'source_port' : 'other', 0.9];
    if (has('agent', 'referer', 'referrer', 'bytes', 'size')) return ['other', 0.9];
    if (has('url', 'uri', 'path', 'request')) return kind === 'http_request' ? ['url', 0.9] : ['other', 0.9];
    if (has('method') && kind === 'http_request') return ['http_method', 0.9];
    if (has('status', 'code', 'response')) return kind === 'http_request' ? ['http_status', 0.9] : ['other', 0.9];
    if (has('user', 'account', 'login', 'username')) return ['account', 0.9];
    if (has('type', 'method', 'mechanism', 'protocol') && kind !== 'http_request') return ['logon_type', 0.9];
    if (has('host', 'hostname', 'computer', 'server', 'device', 'workstation', 'vhost')) return fromSide ? ['source_host', 0.9] : ['host', 0.9];
  }
  // process start, the process that ended, or otherwise the actor and the process it acted on.
  const self = start ? 'new_process' : end ? 'process' : 'actor';
  let who: string | null = null;
  if (parentish) who = start ? 'creator' : 'actor';
  else if (context) who = start ? 'creator' : 'actor';
  else if (targetish && !fileKind) who = start ? 'new_process' : end ? 'process' : 'target';
  else if (!fileKind && has('process', 'image', 'command', 'cmd', 'pid', 'file', 'folder', 'path', 'sha256')) who = actedOn ? 'target' : self;
  if (timeLike && !who) return created ? ['other', 0.9] : ['time', 0.9];
  if (has('device', 'computer', 'host', 'machine', 'hostname') && !has('id', 'remote', 'destination')) return ['host', 0.9];
  if (has('user', 'account', 'sid')) return !parentish && !context && has('name', 'user') && !has('sid', 'domain', 'id') ? ['user', 0.9] : ['other', 0.9];
  if (has('remote', 'destination', 'dst')) return [has('port') ? 'destination_port' : has('url') ? 'url' : has('ip', 'address') ? 'destination_ip' : 'other', 0.9];
  if (has('local', 'src', 'source', 'client') && !has('process', 'image', 'file')) return [has('port') ? 'source_port' : has('ip', 'address', 'addr') ? 'source_ip' : 'other', 0.9];
  if (has('domain', 'query')) return ['domain', 0.9];
  if (has('registry', 'reg')) return [has('value') && has('name') ? 'registry_value_name' : has('value', 'data', 'string') ? 'registry_value' : 'registry_key', 0.9];
  if (has('access', 'desired', 'granted')) return ['access_mask', 0.9];
  if (has('api', 'function')) return ['api_name', 0.9];
  if (fileKind && !parentish && !context) {
    if (has('sha256', 'hash')) return ['file_hash', 0.9];
    if (has('folder', 'path', 'target', 'pipe')) return ['file_path', 0.92];
    if (has('file', 'name')) return ['file_name', 0.88];
  }
  if (!who) return ['other', 0.9];
  if (timeLike && created) return [`${who}_start_time`, 0.9];
  if (has('command', 'cmd', 'cmdline')) return [`${who}_command_line`, 0.9];
  if (has('sha256')) return [`${who}_hash`, 0.9];
  if (has('raw', 'pid') || (has('process') && has('id') && f.examples.every(x => /^\d{1,7}$/.test(x)))) return [`${who}_pid`, 0.9];
  if (has('guid', 'entity', 'unique') || (has('id') && has('process'))) return [`${who}_id`, 0.9];
  if (has('folder', 'path')) return [`${who}_image`, 0.92];
  if (has('image', 'file', 'exe', 'name')) return [`${who}_image`, 0.88];
  return ['other', 0.9];
}

export const standIn = (latencyMs = 0): Transport => async body => {
  const request = JSON.parse(body) as {state: {task?: string; event_type?: string | null; kind_of_event?: string; fields?: Record<string, FieldInfo>;
    candidates?: Record<string, {links?: {what?: string}[]; seen_with?: Record<string, number>}>}};
  const answers: JevResponse['answers'] = {};
  if (request.state.task?.startsWith('Map the fields')) {
    // First question: the kind of event. Second: the fields, from the menu for that kind.
    const described = Object.entries(KINDS).find(([, text]) => text === request.state.kind_of_event)?.[0] as LearnedKind | undefined;
    const kind = described ?? guessKind(request.state.event_type ?? null, Object.values(request.state.fields ?? {}));
    if (!described) answers.kind = {type: 'choice', choice: kind, probabilities: {[kind]: 0.9}};
    else {
      const typeField = request.state.event_type?.split(' = ')[0];
      const menu = kind === 'other' ? {} : ROLE_MENUS[kind];
      for (const [label, field] of Object.entries(request.state.fields ?? {})) {
        const [role, p] = guessRole(field, kind, typeField);
        answers[label] = {type: 'choice', choice: role in menu ? role : 'other', probabilities: {[role in menu ? role : 'other']: p}};
      }
    }
  } else {
    for (const [label, candidate] of Object.entries(request.state.candidates ?? {})) {
      let best = 0.1;
      for (const link of candidate.links ?? []) {
        const contact = /contacted/.test(link.what ?? '') ? (rare(candidate.seen_with) ? 0.85 : 0.2) : 0;
        const match = SCORES.find(([pattern]) => pattern.test(link.what ?? ''));
        best = Math.max(best, contact, match?.[1] ?? 0);
      }
      answers[label] = {type: 'noul', noul: best};
    }
  }
  if (latencyMs) await new Promise(resolve => setTimeout(resolve, latencyMs));
  return {model: 'offline-stand-in', answers, usage: {input_tokens: 0, output_tokens: 0}};
};
