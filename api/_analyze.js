// Analysis on the server, with the site's free TypeSafe key: the page uploads at most 2 MB of logs, and
// this function runs the engine on them (the same code as the browser and the command line) and returns
// the result. The site's key only ever answers questions this function builds from uploaded logs, so it
// cannot be used for anything else. Nothing is stored or logged: files, answers and results live in this
// request's memory and are gone when it ends.
//
// POST {files: [{name, text}], mappings?: [...]}                      -> {summary, seeds, mappings}
// POST {files: [{name, text}], seed, context, mappings?: [...]}       -> {report, requests, mappings}
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {readJson} = require('./_relay.js');

const MAX_LOG_BYTES = 2 * 1024 * 1024;     // what the page lets the free key analyze
const MAX_BODY = 3 * 1024 * 1024;          // the logs as JSON text, plus the choices
const MAX_FILES = 20;
const MAX_CONTEXT = 500;
const MAX_JEV_REQUESTS = 2000;             // per analysis; 2 MB of logs needs a few hundred at most
const MAX_REQUEST_LOG = 1.5 * 1024 * 1024; // exact requests returned for download, when they fit
const WINDOW_MS = 60 * 60 * 1000;
// Per visitor address per hour, and for all visitors together, per running instance.
const LIMITS = {load: 60, analyze: 12, analyzeTotal: 200};

const isObj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const bytes = text => Buffer.byteLength(text);

let engine = null;
// The engine's modules as JavaScript (types erased, as the website build publishes them), imported once per instance.
async function loadEngine() {
  if (engine) return engine;
  const {engineModules} = require('../scripts/build_site.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'jevline-engine-'));
  for (const [file, js] of engineModules()) fs.writeFileSync(path.join(dir, file.replace(/\.ts$/, '.js')), js);
  fs.writeFileSync(path.join(dir, 'package.json'), '{"type": "module"}');
  const load = name => import(pathToFileURL(path.join(dir, name)).href);
  const [browser, jev, schema] = await Promise.all([load('browser.js'), load('jev.js'), load('schema.js')]);
  return (engine = {browser, jev, schema});
}

// Why the body cannot be analyzed, or null.
function bodyProblem(body) {
  if (!isObj(body) || !Array.isArray(body.files) || !body.files.length || body.files.length > MAX_FILES) return 'Send 1 to 20 log files.';
  if (!body.files.every(f => isObj(f) && typeof f.name === 'string' && f.name.length <= 200 && typeof f.text === 'string')) return 'Each file needs a name and its text.';
  const total = body.files.reduce((sum, f) => sum + bytes(f.text), 0);
  if (total > MAX_LOG_BYTES) return `Our free key analyzes up to 2 MB of logs; these are ${(total / 1048576).toFixed(1)} MB. Use your own TypeSafe key for larger files.`;
  if (body.seed !== undefined && (typeof body.seed !== 'string' || !body.seed || body.seed.length > 1000)) return 'Choose the starting point.';
  if (body.seed !== undefined && (typeof body.context !== 'string' || !body.context.trim() || body.context.length > MAX_CONTEXT)) return 'Add analyst context of at most 500 characters.';
  if (body.mappings !== undefined && (!Array.isArray(body.mappings) || body.mappings.length > 300)) return 'Unusable schema mappings.';
  return null;
}

function createHandler({transport = null, env = process.env, now = Date.now} = {}) {
  const hits = new Map();
  const limited = (bucket, limit) => {
    const t = now(), recent = (hits.get(bucket) || []).filter(time => t - time < WINDOW_MS);
    if (recent.length >= limit) { hits.set(bucket, recent); return true; }
    recent.push(t);
    hits.set(bucket, recent);
    if (hits.size > 10000) for (const [key, times] of hits) if (!times.some(time => t - time < WINDOW_MS)) hits.delete(key);
    return false;
  };

  return async function handler(req, res) {
    const send = (status, value) => {
      res.statusCode = status;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.end(JSON.stringify(value));
    };
    const refuse = (status, error) => send(status, {error});
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return refuse(405, 'Use POST.'); }
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    if (!host || ![`https://${host}`, `http://${host}`].includes(req.headers.origin)) return refuse(403, 'Requests must come from this site.');
    if (String(req.headers['content-type'] || '').split(';')[0].trim() !== 'application/json') return refuse(415, 'JSON required.');
    const {body, problem} = await readJson(req, MAX_BODY);
    if (problem) return refuse(problem[0], problem[0] === 413 ? 'Our free key analyzes up to 2 MB of logs. Use your own TypeSafe key for larger files.' : problem[1]);
    const reason = bodyProblem(body);
    if (reason) return refuse(400, reason);
    const analyzing = body.seed !== undefined;
    const address = String(req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket?.remoteAddress || 'unknown').trim();
    if (analyzing && limited('analyze:*', LIMITS.analyzeTotal)) return refuse(429, 'The free key is busy right now; try again in a few minutes, or use your own TypeSafe key.');
    if (limited(`${analyzing ? 'analyze' : 'load'}:${address}`, analyzing ? LIMITS.analyze : LIMITS.load)) {
      return refuse(429, `You have reached the free key's limit of ${analyzing ? LIMITS.analyze : LIMITS.load} ${analyzing ? 'analyses' : 'loads'} per hour; try later, or use your own TypeSafe key.`);
    }
    const key = env.TYPESAFE_API_KEY;
    const NOT_CONFIGURED = 'The free key is not configured on this site yet. Choose "My own TypeSafe key" to analyze now.';

    try {
      const {browser, jev, schema} = await loadEngine();
      let asked = 0;
      // Without a key, logs the built-in rules read still load; only asking Jev fails.
      const base = transport || (key ? jev.typesafe(key) : async () => { throw new jev.TransportError(NOT_CONFIGURED, false); });
      const capped = async (requestBody, signal) => {
        if (++asked > MAX_JEV_REQUESTS) throw new jev.TransportError(`This analysis needs more than ${MAX_JEV_REQUESTS} Jev questions, more than the free key allows. Use your own TypeSafe key.`, false);
        return base(requestBody, signal);
      };
      const learned = [];
      const cache = new schema.SchemaCache({load: () => (body.mappings || []).filter(m => isObj(m) && typeof m.fingerprint === 'string' && isObj(m.roles)),
        save: mapping => learned.push(mapping)});
      const files = body.files.map(f => new File([f.text], f.name));
      const loaded = await browser.loadFiles(files, {learn: profiles => schema.learn(profiles, new jev.JevClient(capped), cache, jev.MODEL, 'jev')});
      if (!analyzing) return send(200, {summary: browser.summary(loaded), seeds: browser.seeds(loaded), mappings: learned});
      let seedKey;
      if (body.seed.startsWith('key:')) {
        seedKey = body.seed.slice(4);
        if (!loaded.nodes.has(seedKey)) return refuse(400, 'That process is not in the uploaded files.');
      } else {
        try { seedKey = browser.findSeed(loaded, body.seed).key; } catch (error) { return refuse(400, error.message); }
      }
      const requests = [];
      const client = new jev.JevClient(capped, {concurrency: 8, onRequest: (sha256, text) => requests.push({sha256, body: JSON.parse(text)})});
      const {report} = await browser.analyze(loaded, seedKey, client, {description: body.context.trim(), model: jev.MODEL, threshold: 0.8, margin: 0.05,
        batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 2000, transport: 'TypeSafe, this site\'s free key, on the server'});
      const requestLog = JSON.stringify(requests);
      return send(200, {report, requests: bytes(requestLog) <= MAX_REQUEST_LOG ? requests : null, mappings: learned});
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return refuse(/more than the free key allows/.test(message) ? 413 : message === NOT_CONFIGURED ? 503 : 502, message.slice(0, 300));
    }
  };
}

module.exports = {createHandler, bodyProblem, LIMITS, MAX_LOG_BYTES};
