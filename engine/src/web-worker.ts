// The website's engine thread, used with the visitor's own TypeSafe key: a Web Worker that reads the
// visitor's log files, learns unknown schemas, links the incident and asks Jev round by round, so the page
// stays responsive on large files. (With the site's free key, api/analyze.js does the same on the server.) The page
// (ui/app.js) sends {type: 'load' | 'analyze'} messages and receives progress, the loaded summary and the
// report. Nothing here stores anything: files, answers and keys live only as long as the page.
import {analyze, findSeed, loadFiles, relay, seeds, summary, type Loaded} from './browser.ts';
import {JevClient, MODEL, type JevResponse} from './jev.ts';
import {learn, SchemaCache, type StoredMapping} from './schema.ts';

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

async function handle(message: Message) {
  if (message.type === 'load') {
    loaded = null;
    const {access} = message;
    const cache = new SchemaCache({load: () => message.mappings, save: mapping => post({type: 'mapping', mapping})});
    // Unknown schemas are learned with Jev (the visitor's key, or the site's), once per event type; this
    // browser remembers the mappings, so the same log source asks nothing next time.
    const learner = async (profiles: Parameters<typeof learn>[0]) => {
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
    maxRounds: 20, maxCandidatesPerRound: 2000, transport: message.access.key ? 'TypeSafe, your key, through this site\'s relay' : 'TypeSafe, this site\'s key, through its relay',
    onRound: (n, groups) => { round = n; post({type: 'progress', stage: 'round', round: n, questions: groups.length}); }});
  post({type: 'report', report, requests});
}

scope.onmessage = event => {
  handle(event.data).catch((error: Error) => post({type: 'error', during: event.data.type, message: error.message || String(error), answers: received}));
};
