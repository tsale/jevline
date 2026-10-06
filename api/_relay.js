// Jev relay for the website: browsers cannot call TypeSafe directly (no CORS), so the page sends each
// Jev request here and this function forwards it unchanged. It stores and logs nothing.
//
// - With an Authorization header, the visitor's own TypeSafe key is forwarded for that one request.
// - Without one, the site's demo key (TYPESAFE_API_KEY) is used, but only for requests about the
//   bundled lab example: every word in the request must come from that example or from the engine's
//   own wording (link descriptions, questions, field names), so no other data can be analyzed with it.
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const example = require('../examples/malicious_events.json');

const API = 'https://api.typesafe.ai/v1/systemone';
const MODEL = 'jev-1.13.0';  // engine/src/jev.ts MODEL (tests/test_relay.js checks they match)
const MAX_BODY = 256 * 1024;
const WINDOW_MS = 10 * 60 * 1000;
const LIMITS = {demo: 300, own: 3000};  // Requests per visitor address per window, per running instance.
const CACHE_SIZE = 1000;
const TIMEOUT_MS = 60000;
const MAX_CANDIDATES = 20;
const MAX_CONTEXT = 500;
// The engine files whose wording appears in requests (included in this function on Vercel; see vercel.json).
const ENGINE_FILES = ['investigate.ts', 'links.ts', 'entities.ts', 'normalize.ts'];

const isObj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const tokens = text => String(text).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
let known = null;
// Every word of the bundled example and of the engine's wording, built once per running instance.
function vocabulary() {
  if (known) return known;
  known = new Set(tokens(JSON.stringify(example)));
  for (const file of ENGINE_FILES) for (const t of tokens(fs.readFileSync(path.join(__dirname, '..', 'engine', 'src', file), 'utf8'))) known.add(t);
  return known;
}

// Each string in a request (keys and values), with where it is.
function* strings(value, where = '') {
  if (typeof value === 'string') yield [where, value];
  else if (Array.isArray(value)) for (const [i, v] of value.entries()) yield* strings(v, `${where}[${i}]`);
  else if (isObj(value)) for (const [k, v] of Object.entries(value)) { yield [`${where}.${k}`, k]; yield* strings(v, `${where}.${k}`); }
}

// Why a request may not use the demo key, or null when every word in it comes from the bundled example
// or the engine. Numbers (PIDs, ports, counts, times such as +1d 02:03:04) and the request's own labels
// for candidates and incident members (C1, I2) are allowed; a value the engine shortened ("…") may end in
// part of a word.
function demoProblem(body) {
  const notExample = 'The demo key only analyzes the bundled lab example. Choose "My own TypeSafe key" to analyze other data.';
  if (!isObj(body) || Object.keys(body).sort().join() !== 'model,questions,state' || body.model !== MODEL || !isObj(body.state) || !isObj(body.questions)) {
    return 'Not a Jev request from this site.';
  }
  const {analyst_context: context, ...state} = body.state;
  const labels = Object.keys(body.questions);
  if (typeof context !== 'string' || context.length > MAX_CONTEXT || !labels.length || labels.length > MAX_CANDIDATES ||
      !labels.every(label => /^C\d{1,2}$/.test(label) && isObj(body.questions[label]) && body.questions[label].type === 'noul')) {
    return 'Not a Jev request from this site.';
  }
  const words = vocabulary();
  for (const [, text] of strings({state, questions: body.questions})) {
    const list = tokens(text);
    if (text.endsWith('…')) list.pop();
    if (!list.every(t => words.has(t) || /^(\d+d?|[ci]\d{1,4})$/.test(t))) return notExample;
  }
  return null;
}

async function readJson(req) {
  let body;
  try { body = req.body; } catch { return {problem: [400, 'Invalid JSON.']}; }  // Vercel parses lazily and throws on bad JSON.
  let text;
  if (body !== undefined && body !== null && typeof body.pipe !== 'function') {
    if (isObj(body) || Array.isArray(body)) {
      text = JSON.stringify(body);
      return Buffer.byteLength(text) > MAX_BODY ? {problem: [413, 'Request too large.']} : {body};
    }
    text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body);
  } else {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BODY) return {problem: [413, 'Request too large.']};
      chunks.push(chunk);
    }
    text = Buffer.concat(chunks).toString('utf8');
  }
  if (Buffer.byteLength(text) > MAX_BODY) return {problem: [413, 'Request too large.']};
  try { return {body: JSON.parse(text)}; } catch { return {problem: [400, 'Invalid JSON.']}; }
}

function createHandler({fetchImpl = (...args) => fetch(...args), env = process.env, now = Date.now} = {}) {
  const hits = new Map();   // "mode:address" -> request times within the window
  const cache = new Map();  // SHA-256 of a demo request -> TypeSafe's answer (identical inputs, identical answer)

  const limited = (bucket, limit) => {
    const t = now();
    const recent = (hits.get(bucket) || []).filter(time => t - time < WINDOW_MS);
    if (recent.length >= limit) { hits.set(bucket, recent); return true; }
    recent.push(t);
    hits.set(bucket, recent);
    if (hits.size > 10000) for (const [key, times] of hits) if (!times.some(time => t - time < WINDOW_MS)) hits.delete(key);
    return false;
  };

  return async function handler(req, res) {
    const send = (status, text) => {
      res.statusCode = status;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.end(text);
    };
    const refuse = (status, error) => send(status, JSON.stringify({error, source: 'relay'}));

    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return refuse(405, 'Use POST.'); }
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    if (!host || ![`https://${host}`, `http://${host}`].includes(req.headers.origin)) return refuse(403, 'Requests must come from this site.');
    if (String(req.headers['content-type'] || '').split(';')[0].trim() !== 'application/json') return refuse(415, 'JSON required.');
    const auth = req.headers.authorization;
    const own = typeof auth === 'string' && auth !== '';
    if (own && !/^Bearer [\x21-\x7e]{1,512}$/.test(auth)) return refuse(400, 'Malformed TypeSafe key.');
    const {body, problem} = await readJson(req);
    if (problem) return refuse(...problem);
    if (own) {
      if (!isObj(body) || typeof body.model !== 'string' || !isObj(body.state) || !isObj(body.questions)) return refuse(400, 'Not a Jev request from this site.');
    } else {
      const reason = demoProblem(body);
      if (reason) return refuse(403, reason);
    }
    const address = String(req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket?.remoteAddress || 'unknown').trim();
    if (limited(`${own ? 'own' : 'demo'}:${address}`, own ? LIMITS.own : LIMITS.demo)) {
      return refuse(429, own ? 'Too many Jev requests from your connection; wait a few minutes and retry.'
        : 'The demo key is busy for your connection; wait a few minutes or use your own TypeSafe key.');
    }
    const payload = JSON.stringify(body);
    const cacheKey = own ? null : crypto.createHash('sha256').update(payload).digest('hex');
    if (cacheKey && cache.has(cacheKey)) return send(200, cache.get(cacheKey));
    const key = own ? auth.slice('Bearer '.length) : env.TYPESAFE_API_KEY;
    if (!key) return refuse(503, 'The demo key is not configured on this site yet. Choose "My own TypeSafe key" to analyze now.');

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let status, text;
    try {
      const upstream = await fetchImpl(API, {method: 'POST', body: payload, signal: controller.signal,
        headers: {'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}});
      status = upstream.status;
      text = await upstream.text();
    } catch (error) {
      // Not labelled as a relay refusal, so the page retries it like any temporary TypeSafe failure.
      return send(controller.signal.aborted ? 504 : 502, JSON.stringify({error: 'TypeSafe could not be reached from the relay.'}));
    } finally {
      clearTimeout(timer);
    }
    if (!own && (status === 401 || status === 403)) return refuse(503, 'TypeSafe rejected the demo key; the site owner needs to renew it. Use your own TypeSafe key meanwhile.');
    if (!own && status === 429) return refuse(429, 'The demo key has reached TypeSafe\'s rate limit; try later or use your own TypeSafe key.');
    if (cacheKey && status === 200) {
      cache.set(cacheKey, text);
      if (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value);
    }
    return send(status, text);
  };
}

module.exports = {createHandler, demoProblem, LIMITS, MODEL};
