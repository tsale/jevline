// Jev relay for the website, for visitors who use their own TypeSafe key: browsers cannot call TypeSafe
// directly (no CORS), so the page sends each Jev request here with the visitor's key, and this function
// forwards it unchanged for that one request. It stores and logs nothing. The site's own free key is never
// used here; it only answers questions the server builds from uploaded logs (api/analyze.js).
'use strict';

const API = 'https://api.typesafe.ai/v1/systemone';
const MODEL = 'jev-1.13.0';  // engine/src/jev.ts MODEL (tests/test_relay.js checks they match)
const MAX_BODY = 256 * 1024;
const WINDOW_MS = 10 * 60 * 1000;
// Requests per visitor address per window, per running instance.
const LIMITS = {own: 5000};
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

function createHandler({fetchImpl = (...args) => fetch(...args), now = Date.now} = {}) {
  const hits = new Map();   // address -> request times within the window

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
    if (typeof auth !== 'string' || auth === '') return refuse(401, 'This relay forwards your own TypeSafe key. With the free key, the site analyzes uploaded logs on its server instead.');
    if (!/^Bearer [\x21-\x7e]{1,512}$/.test(auth)) return refuse(400, 'Malformed TypeSafe key.');
    const {body, problem} = await readJson(req, MAX_BODY);
    if (problem) return refuse(...problem);
    const reason = requestProblem(body);
    if (reason) return refuse(400, reason);
    const address = String(req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket?.remoteAddress || 'unknown').trim();
    if (limited(address, LIMITS.own)) return refuse(429, 'Too many Jev requests from your connection; wait a few minutes and retry.');
    const payload = JSON.stringify(body);
    const key = auth.slice('Bearer '.length);

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
    return send(status, text);
  };
}

module.exports = {createHandler, requestProblem, readJson, LIMITS, MODEL};
