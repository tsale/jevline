// Jev relay for the website: browsers cannot call TypeSafe directly (no CORS), so the page sends each
// Jev request here and this function forwards it unchanged. It stores and logs nothing.
//
// - With an Authorization header, the visitor's own TypeSafe key is forwarded for that one request.
// - Without one, the site's key (TYPESAFE_API_KEY) is used, for any logs, within a per-visitor limit.
// Either way the body must be a Jev request in the engine's shape.
'use strict';
const crypto = require('node:crypto');

const API = 'https://api.typesafe.ai/v1/systemone';
const MODEL = 'jev-1.13.0';  // engine/src/jev.ts MODEL (tests/test_relay.js checks they match)
const MAX_BODY = 256 * 1024;
// The site's free key pays for every request, so it takes only what the website sends: one candidate per
// request (the engine's requests are under 9 KB), from at most 2 MB of uploaded logs (ui/app.js).
const FREE_MAX_BODY = 16 * 1024;
const WINDOW_MS = 10 * 60 * 1000;
// Requests per window, per running instance: per visitor address (2 MB of logs takes a few hundred), and
// for the free key across all visitors, which caps what it can cost however many addresses send.
const LIMITS = {demo: 600, own: 5000, demoTotal: 3000};
const CACHE_SIZE = 2000;
const TIMEOUT_MS = 60000;
const MAX_QUESTIONS = 60;
const MAX_CONTEXT = 500;

const isObj = x => x !== null && typeof x === 'object' && !Array.isArray(x);

// Why a body is not a Jev request as the engine builds one, or null: the engine's model, an object state
// (with an analyst context of at most 500 characters when it has one), and 1-60 Noul or Choice questions,
// each with instructions. Incident questions are Nouls; questions that learn a log schema are Choices.
function requestProblem(body) {
  const bad = 'Not a Jev request from this site.';
  if (!isObj(body) || Object.keys(body).sort().join() !== 'model,questions,state' || body.model !== MODEL || !isObj(body.state) || !isObj(body.questions)) return bad;
  const context = body.state.analyst_context;
  if (context !== undefined && (typeof context !== 'string' || context.length > MAX_CONTEXT)) return bad;
  const questions = Object.values(body.questions);
  if (!questions.length || questions.length > MAX_QUESTIONS) return bad;
  if (!questions.every(q => isObj(q) && (q.type === 'noul' || q.type === 'choice') && typeof q.instructions === 'string')) return bad;
  return null;
}

async function readJson(req, max = MAX_BODY) {
  let body;
  try { body = req.body; } catch { return {problem: [400, 'Invalid JSON.']}; }  // Vercel parses lazily and throws on bad JSON.
  let text;
  if (body !== undefined && body !== null && typeof body.pipe !== 'function') {
    if (isObj(body) || Array.isArray(body)) {
      text = JSON.stringify(body);
      return Buffer.byteLength(text) > max ? {problem: [413, 'Request too large.']} : {body};
    }
    text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body);
  } else {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > max) return {problem: [413, 'Request too large.']};
      chunks.push(chunk);
    }
    text = Buffer.concat(chunks).toString('utf8');
  }
  if (Buffer.byteLength(text) > max) return {problem: [413, 'Request too large.']};
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
    const {body, problem} = await readJson(req, own ? MAX_BODY : FREE_MAX_BODY);
    if (problem) return refuse(...problem);
    const reason = requestProblem(body);
    if (reason) return refuse(400, reason);
    const address = String(req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket?.remoteAddress || 'unknown').trim();
    if (!own && limited('demo:*', LIMITS.demoTotal)) {
      return refuse(429, 'The free key is busy right now; wait a few minutes or use your own TypeSafe key.');
    }
    if (limited(`${own ? 'own' : 'demo'}:${address}`, own ? LIMITS.own : LIMITS.demo)) {
      return refuse(429, own ? 'Too many Jev requests from your connection; wait a few minutes and retry.'
        : 'You have reached this site\'s fair-use limit for the free key; wait a few minutes or use your own TypeSafe key.');
    }
    const payload = JSON.stringify(body);
    const cacheKey = own ? null : crypto.createHash('sha256').update(payload).digest('hex');
    if (cacheKey && cache.has(cacheKey)) return send(200, cache.get(cacheKey));
    const key = own ? auth.slice('Bearer '.length) : env.TYPESAFE_API_KEY;
    if (!key) return refuse(503, 'The free key is not configured on this site yet. Choose "My own TypeSafe key" to analyze now.');

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
    if (!own && (status === 401 || status === 403)) return refuse(503, 'TypeSafe rejected the site\'s key; the site owner needs to renew it. Use your own TypeSafe key meanwhile.');
    if (!own && status === 429) return refuse(429, 'The site\'s key has reached TypeSafe\'s rate limit; try later or use your own TypeSafe key.');
    if (cacheKey && status === 200) {
      cache.set(cacheKey, text);
      if (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value);
    }
    return send(status, text);
  };
}

module.exports = {createHandler, requestProblem, LIMITS, MODEL};
