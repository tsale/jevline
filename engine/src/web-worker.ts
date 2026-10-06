// The website's engine thread: a Web Worker that reads the visitor's log files, learns unknown schemas,
// links the incident and asks Jev round by round, so the page stays responsive on large files. The page
// (ui/app.js) sends {type: 'load' | 'analyze'} messages and receives progress, the loaded summary and the
// report. Nothing here stores anything: files, answers and keys live only as long as the page.
import {analyze, findSeed, iso, loadFiles, relay, type Loaded} from './browser.ts';
import {JevClient, MODEL, type JevResponse} from './jev.ts';
import {fingerprint, learn, SchemaCache, type Mapping, type StoredMapping} from './schema.ts';

interface Access { endpoint: string; key?: string }
type Message =
  | {type: 'load'; files: File[]; access: Access; mappings: StoredMapping[]}
  | {type: 'analyze'; seed: string; context: string; access: Access};

const scope = globalThis as unknown as {onmessage: ((event: {data: Message}) => void) | null; postMessage(message: unknown): void};
const post = (message: unknown) => scope.postMessage(message);
let loaded: Loaded | null = null;
let received = 0;  // Jev answers received in this session, for the page to say whether a retry reuses any.
// Jev answers from this page's earlier runs, by request hash: a run after a failure, or with another
// threshold, reuses every answer already received instead of paying for it again.
const answers = new Map<string, JevResponse>();
const memory = {load: () => answers.entries(), save: (sha: string, response: JevResponse) => { answers.set(sha, response); }};

/** Process starts a visitor can pick as the seed, in time order. */
function seeds(data: Loaded) {
  return [...data.nodes.values()].filter(n => n.type === 'process' && n.starts.length)
    .sort((a, b) => (a.start ?? Infinity) - (b.start ?? Infinity) || a.key.localeCompare(b.key))
    .map(n => ({key: n.key, name: n.name ?? '?', pid: n.pid, host: n.host, start: iso(n.start), user: n.user,
      command_line: n.cmd && n.cmd.length > 300 ? `${n.cmd.slice(0, 300)}…` : n.cmd, event_id: data.events[n.starts[0]!]!.id}));
}

function summary(data: Loaded) {
  const processes = [...data.nodes.values()].filter(n => n.type === 'process').length;
  const entities: Record<string, number> = {};
  for (const n of data.nodes.values()) if (n.type !== 'process') entities[n.type] = (entities[n.type] ?? 0) + 1;
  return {inputs: data.inputs, records: data.stats.records, events: data.events.length, duplicates: data.duplicates, processes, entities,
    links: data.graph.links.length, schemas: data.schemas, timings: data.timings,
    sources: [...data.stats.bySource].sort((a, b) => b[1] - a[1]).slice(0, 8)};
}

async function handle(message: Message) {
  if (message.type === 'load') {
    loaded = null;
    const {access} = message;
    const cache = new SchemaCache({load: () => message.mappings, save: mapping => post({type: 'mapping', mapping})});
    // Unknown schemas are learned with Jev only with the visitor's key: the demo key answers questions
    // about the bundled example, which needs none.
    const learner = async (profiles: Parameters<typeof learn>[0]) => {
      if (!access.key) {
        const known = new Map<string, Mapping>();
        for (const group of Object.values(profiles)) {
          const m = cache.get(fingerprint(group));
          if (m) known.set(group.key, {...m, group: group.key});
        }
        return known;
      }
      post({type: 'progress', stage: 'learn', message: `Learning ${Object.keys(profiles).length} event types from an unknown schema with Jev…`});
      return learn(profiles, new JevClient(relay(access.endpoint, access.key), {answers: memory}), cache, MODEL, 'jev');
    };
    loaded = await loadFiles(message.files, {learn: learner,
      onProgress: p => post({type: 'progress', stage: 'read', file: p.file, index: p.index, bytes: p.bytes, size: p.size, pass: p.pass})});
    post({type: 'loaded', summary: summary(loaded), seeds: seeds(loaded)});
    return;
  }
  if (!loaded) throw new Error('Load log files first.');
  const data = loaded;
  let key: string;
  if (message.seed.startsWith('key:')) {
    key = message.seed.slice(4);
    if (!data.nodes.has(key)) throw new Error('That process is not in the loaded files.');
  } else {
    key = findSeed(data, message.seed).key;
  }
  const requests: {sha256: string; body: unknown}[] = [];
  let answered = 0, round = 0;
  const transport = relay(message.access.endpoint, message.access.key);
  const client = new JevClient(async (body, signal) => {
    const response = await transport(body, signal);
    received++;
    post({type: 'progress', stage: 'ask', round, answered: ++answered});
    return response;
  }, {concurrency: 6, answers: memory, onRequest: (sha256, body) => requests.push({sha256, body: JSON.parse(body) as unknown})});
  const {report} = await analyze(data, key, client, {description: message.context, model: MODEL, threshold: 0.8, margin: 0.05, batchSize: 1,
    maxRounds: 20, maxCandidatesPerRound: 2000, transport: message.access.key ? 'TypeSafe, your key, through this site\'s relay' : 'TypeSafe, demo key, through this site\'s relay',
    onRound: (n, groups) => { round = n; post({type: 'progress', stage: 'round', round: n, questions: groups.length}); }});
  post({type: 'report', report, requests});
}

scope.onmessage = event => {
  handle(event.data).catch((error: Error) => post({type: 'error', during: event.data.type, message: error.message || String(error), answers: received}));
};
