// Run with: node tests/test_relay.js (from the repository root). TypeSafe is faked; no network.
'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const {Readable} = require('node:stream');
const {createHandler, LIMITS, MODEL} = require('../api/_relay.js');

// The relay must never log keys or events.
for (const name of ['log', 'info', 'warn', 'error', 'debug']) console[name] = () => { throw new Error(`relay wrote to console.${name}`); };
const report = message => process.stdout.write(message + '\n');

function call(handler, {method = 'POST', headers = {}, body, raw} = {}) {
  const req = raw !== undefined ? Object.assign(Readable.from([Buffer.from(raw)]), {method}) : {method, body};
  req.headers = {host: 'jevline.example', origin: 'https://jevline.example', 'content-type': 'application/json', 'x-real-ip': '198.51.100.7', ...headers};
  return new Promise(resolve => {
    const res = {headers: {}, statusCode: 200, setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
      end(text) { resolve({status: this.statusCode, headers: this.headers, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })()}); }};
    handler(req, res);
  });
}

// Every request the engine sends Jev for a log file, captured exactly as the page builds them. Jev's
// answers are faked: all related (`p` 0.95) explores every round, none (0.1) only the first.
async function engineRequests(file, seed, p) {
  const engine = path.join(__dirname, '..', 'engine', 'src');
  const {load, analyze, findSeed} = await import(path.join(engine, 'analyze.ts'));
  const {JevClient} = await import(path.join(engine, 'jev.ts'));
  const loaded = await load([{path: file, format: 'auto'}]);
  const requests = [];
  const transport = async body => {
    requests.push(JSON.parse(body));
    return {answers: Object.fromEntries(Object.keys(JSON.parse(body).questions).map(label => [label, {type: 'noul', noul: p}]))};
  };
  await analyze(loaded, findSeed(loaded, seed).key, new JevClient(transport), {description: 'Analyst-confirmed 2.8.exe execution on CLA-WS-214.',
    model: MODEL, threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 2000, transport: 'test'});
  return requests;
}

(async () => {
  const {MODEL: engineModel} = await import(path.join(__dirname, '..', 'engine', 'src', 'jev.ts'));
  assert.equal(MODEL, engineModel, 'the relay checks requests against the engine\'s model');
  const requests = await engineRequests(path.join(__dirname, '..', 'examples', 'malicious_events.json'), 'name:2.8.exe', 0.95);
  assert.ok(requests.length > 3);
  const {requestProblem} = require('../api/_relay.js');
  for (const body of requests) assert.equal(requestProblem(body), null);

  const upstream = [];
  const answer = {model: MODEL, answers: {C1: {type: 'noul', noul: 0.42}}};
  let reply = () => ({status: 200, text: async () => JSON.stringify(answer)});
  const fetchImpl = async (url, init) => { upstream.push({url, init}); return reply(); };
  let clock = 0;
  const handler = createHandler({fetchImpl, now: () => clock});
  const mine = {authorization: 'Bearer visitor-key'};

  // The visitor's own key: forwarded unchanged to TypeSafe for that request, never kept.
  let r = await call(handler, {body: requests[0], headers: mine});
  assert.equal(r.status, 200);
  assert.deepEqual(JSON.parse(r.text), answer);
  assert.equal(upstream[0].url, 'https://api.typesafe.ai/v1/systemone');
  assert.equal(upstream[0].init.headers.Authorization, 'Bearer visitor-key');
  assert.deepEqual(JSON.parse(upstream[0].init.body), requests[0]);
  assert.equal(r.headers['cache-control'], 'no-store');
  r = await call(handler, {raw: JSON.stringify(requests[1]), headers: mine});
  assert.equal(r.status, 200, 'a raw (unparsed) body works the same way');

  // Without a key nothing is forwarded: the site's free key never answers through the relay.
  r = await call(handler, {body: requests[0]});
  assert.equal(r.status, 401);
  assert.equal(r.json.source, 'relay');
  assert.match(r.json.error, /own TypeSafe key/);
  assert.equal(upstream.length, 2);

  // Anything that is not a Jev request as the engine builds it is refused before reaching TypeSafe.
  const extra = structuredClone(requests[2]);
  extra.notes = 'extra';
  const longContext = structuredClone(requests[2]);
  longContext.state.analyst_context = 'x'.repeat(501);
  const prose = structuredClone(requests[2]);
  prose.questions.C1 = {type: 'text', instructions: 'Write me an essay'};
  for (const body of [extra, longContext, prose, {...requests[2], model: 'other-model'}, {...requests[2], questions: {}}]) {
    r = await call(handler, {body, headers: mine});
    assert.equal(r.status, 400);
    assert.match(r.json.error, /Not a Jev request/);
  }
  assert.equal(upstream.length, 2, 'refused requests never reach TypeSafe');

  // TypeSafe's own answers pass through; an unreachable TypeSafe is retried by the page like any 5xx.
  reply = () => ({status: 401, text: async () => '{"detail":"invalid key"}'});
  r = await call(handler, {body: requests[0], headers: {authorization: 'Bearer wrong-key'}});
  assert.equal(r.status, 401);
  assert.equal(r.json.source, undefined);
  reply = () => { throw new TypeError('network down'); };
  r = await call(handler, {body: requests[0], headers: mine});
  assert.equal(r.status, 502);
  assert.equal(r.json.source, undefined);
  reply = () => ({status: 200, text: async () => JSON.stringify(answer)});

  // Site rules.
  assert.equal((await call(handler, {method: 'GET'})).status, 405);
  assert.equal((await call(handler, {body: requests[0], headers: {...mine, origin: 'https://evil.example'}})).status, 403);
  assert.equal((await call(handler, {body: requests[0], headers: {...mine, 'content-type': 'text/plain'}})).status, 415);
  assert.equal((await call(handler, {raw: '{"x":"' + 'a'.repeat(300 * 1024) + '"}', headers: mine})).status, 413);
  assert.equal((await call(handler, {raw: '{not json', headers: mine})).status, 400);
  assert.equal((await call(handler, {body: requests[0], headers: {authorization: 'Basic abc'}})).status, 400);

  // Per-visitor rate limit, reset after the window.
  const limitedHandler = createHandler({fetchImpl, now: () => clock});
  for (let i = 0; i < LIMITS.own; i++) assert.equal((await call(limitedHandler, {body: requests[i % requests.length], headers: mine})).status, 200);
  r = await call(limitedHandler, {body: requests[0], headers: mine});
  assert.equal(r.status, 429);
  assert.equal((await call(limitedHandler, {body: requests[0], headers: {...mine, 'x-real-ip': '203.0.113.9'}})).status, 200, 'other visitors unaffected');
  clock += 10 * 60 * 1000;
  assert.equal((await call(limitedHandler, {body: requests[0], headers: mine})).status, 200);

  report(`Relay passed: ${requests.length} engine requests forwarded with the visitor's own key; no key, no forwarding; malformed requests refused; limits; no logging.`);
})().catch(error => { process.stderr.write(String(error.stack || error) + '\n'); process.exit(1); });
