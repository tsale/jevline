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
  const example = path.join(__dirname, '..', 'examples', 'malicious_events.json');
  const requests = [...await engineRequests(example, 'name:2.8.exe', 0.1), ...await engineRequests(example, 'name:2.8.exe', 0.95)];
  assert.ok(requests.length > 3);

  const upstream = [];
  const answer = {model: MODEL, answers: {C1: {type: 'noul', noul: 0.42}}};
  let reply = () => ({status: 200, text: async () => JSON.stringify(answer)});
  const fetchImpl = async (url, init) => { upstream.push({url, init}); return reply(); };
  let clock = 0;
  const handler = createHandler({fetchImpl, env: {TYPESAFE_API_KEY: 'site-demo-key'}, now: () => clock});

  // The site's key: forwarded unchanged to TypeSafe.
  let r = await call(handler, {body: requests[0]});
  assert.equal(r.status, 200);
  assert.deepEqual(JSON.parse(r.text), answer);
  assert.equal(upstream.length, 1);
  assert.equal(upstream[0].url, 'https://api.typesafe.ai/v1/systemone');
  assert.equal(upstream[0].init.headers.Authorization, 'Bearer site-demo-key');
  assert.deepEqual(JSON.parse(upstream[0].init.body), requests[0]);
  assert.equal(r.headers['cache-control'], 'no-store');
  assert.ok(!r.text.includes('site-demo-key'));
  // Identical demo requests are answered from the cache without paying again.
  r = await call(handler, {body: requests[0]});
  assert.equal(r.status, 200);
  assert.equal(upstream.length, 1);
  // A raw (unparsed) body works the same way.
  r = await call(handler, {raw: JSON.stringify(requests[1])});
  assert.equal(r.status, 200);
  assert.equal(upstream.length, 2);

  // The site's key analyzes any logs: every request the engine builds is allowed, for the example,
  // for another incident, and the questions that learn an unknown log schema.
  const {requestProblem} = require('../api/_relay.js');
  const fs = require('node:fs'), os = require('node:os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'jevline-relay-'));
  const {ecs, falconFdr} = await import(path.join(__dirname, '..', 'engine', 'test', 'incident.ts'));
  fs.writeFileSync(path.join(dir, 'other.ndjson'), ecs().join('\n'));
  const others = await engineRequests(path.join(dir, 'other.ndjson'), 'name:invoice.exe', 0.95);
  const {learn, SchemaCache} = await import(path.join(__dirname, '..', 'engine', 'src', 'schema.ts'));
  const {JevClient} = await import(path.join(__dirname, '..', 'engine', 'src', 'jev.ts'));
  const {standIn} = await import(path.join(__dirname, '..', 'engine', 'src', 'standin.ts'));
  const {load} = await import(path.join(__dirname, '..', 'engine', 'src', 'analyze.ts'));
  const schemaRequests = [], inner = standIn();
  fs.writeFileSync(path.join(dir, 'fdr.ndjson'), falconFdr().join('\n'));
  await load([{path: path.join(dir, 'fdr.ndjson'), format: 'auto'}], {learn: profiles => learn(profiles,
    new JevClient(body => { schemaRequests.push(JSON.parse(body)); return inner(body); }), new SchemaCache(), MODEL, 'jev')});
  fs.rmSync(dir, {recursive: true, force: true});
  assert.ok(others.length > 3 && schemaRequests.length > 3);
  for (const body of [...requests, ...others, ...schemaRequests]) assert.equal(requestProblem(body), null, JSON.stringify(body).slice(0, 200));
  r = await call(handler, {body: others[0]});
  assert.equal(r.status, 200, 'another incident uses the site\'s key');
  assert.equal(upstream.at(-1).init.headers.Authorization, 'Bearer site-demo-key');

  // Anything that is not a Jev request as the engine builds it is refused before reaching TypeSafe:
  // an extra key, a long context, another model, another kind of question, or no questions.
  const foreign = others[0];
  const extra = structuredClone(requests[2]);
  extra.notes = 'extra';
  const longContext = structuredClone(requests[2]);
  longContext.state.analyst_context = 'x'.repeat(501);
  const prose = structuredClone(requests[2]);
  prose.questions.C1 = {type: 'text', instructions: 'Write me an essay'};
  const empty = structuredClone(requests[2]);
  empty.questions = {};
  for (const [body, pattern] of [[extra, /Not a Jev request/], [longContext, /Not a Jev request/], [{...requests[2], model: 'other-model'}, /Not a Jev request/],
    [prose, /Not a Jev request/], [empty, /Not a Jev request/]]) {
    r = await call(handler, {body});
    assert.equal(r.status, 400);
    assert.equal(r.json.source, 'relay');
    assert.match(r.json.error, pattern);
  }
  assert.equal(upstream.length, 3, 'refused requests never reach TypeSafe');

  // Own key: forwarded for that request only, any data allowed, never replaced by the site key.
  r = await call(handler, {body: foreign, headers: {authorization: 'Bearer visitor-key'}});
  assert.equal(r.status, 200);
  assert.equal(upstream.at(-1).init.headers.Authorization, 'Bearer visitor-key');
  reply = () => ({status: 401, text: async () => '{"detail":"invalid key"}'});
  r = await call(handler, {body: foreign, headers: {authorization: 'Bearer wrong-key'}});
  assert.equal(r.status, 401, "TypeSafe's own answer is passed through for the visitor's key");
  assert.equal(r.json.source, undefined);
  // A rejected site key is explained, not blamed on the visitor.
  r = await call(handler, {body: requests[3]});
  assert.equal(r.status, 503);
  assert.match(r.json.error, /rejected the site's key/);
  reply = () => { throw new TypeError('network down'); };
  r = await call(handler, {body: requests[3]});
  assert.equal(r.status, 502);
  assert.equal(r.json.source, undefined, 'unreachable TypeSafe is retried by the page like any 5xx');
  reply = () => ({status: 200, text: async () => JSON.stringify(answer)});

  // Site rules.
  assert.equal((await call(handler, {method: 'GET'})).status, 405);
  assert.equal((await call(handler, {body: requests[0], headers: {origin: 'https://evil.example'}})).status, 403);
  assert.equal((await call(handler, {body: requests[0], headers: {'content-type': 'text/plain'}})).status, 415);
  assert.equal((await call(handler, {raw: '{"x":"' + 'a'.repeat(300 * 1024) + '"}'})).status, 413);
  assert.equal((await call(handler, {raw: '{not json'})).status, 400);
  assert.equal((await call(handler, {body: foreign, headers: {authorization: 'Basic abc'}})).status, 400);
  const unconfigured = createHandler({fetchImpl, env: {}});
  r = await call(unconfigured, {body: requests[4]});
  assert.equal(r.status, 503);
  assert.match(r.json.error, /free key is not configured/);

  // Per-visitor rate limit for the site's key, reset after the window.
  const limitedHandler = createHandler({fetchImpl, env: {TYPESAFE_API_KEY: 'k'}, now: () => clock});
  for (let i = 0; i < LIMITS.demo; i++) assert.equal((await call(limitedHandler, {body: requests[i % requests.length]})).status, 200);
  r = await call(limitedHandler, {body: requests[0]});
  assert.equal(r.status, 429);
  assert.match(r.json.error, /fair-use limit/);
  assert.equal((await call(limitedHandler, {body: requests[0], headers: {'x-real-ip': '203.0.113.9'}})).status, 200, 'other visitors unaffected');
  clock += 10 * 60 * 1000;
  assert.equal((await call(limitedHandler, {body: requests[0]})).status, 200);

  // The free key takes only the website's small requests, and caps all visitors together.
  const big = structuredClone(requests[0]);
  big.state.analyst_context = 'x'.repeat(400);
  Object.values(big.state.candidates)[0].padding = 'y'.repeat(20 * 1024);
  assert.equal((await call(createHandler({fetchImpl, env: {TYPESAFE_API_KEY: 'k'}}), {body: big})).status, 413, 'free key: 16 KiB per request');
  assert.equal((await call(createHandler({fetchImpl, env: {TYPESAFE_API_KEY: 'k'}}), {body: big, headers: {authorization: 'Bearer mine'}})).status, 200, 'own key: larger requests');
  const shared = createHandler({fetchImpl, env: {TYPESAFE_API_KEY: 'k'}, now: () => clock});
  for (let i = 0; i < LIMITS.demoTotal; i++) await call(shared, {body: requests[i % requests.length], headers: {'x-real-ip': `203.0.${Math.floor(i / 250)}.${i % 250}`}});
  r = await call(shared, {body: requests[0], headers: {'x-real-ip': '192.0.2.200'}});
  assert.equal(r.status, 429);
  assert.match(r.json.error, /free key is busy/);
  assert.equal((await call(shared, {body: requests[0], headers: {'x-real-ip': '192.0.2.200', authorization: 'Bearer mine'}})).status, 200, 'own keys are not capped by it');

  report(`Relay passed: ${requests.length + others.length + schemaRequests.length} engine requests (the example, another incident, schema learning) allowed on the site's key; malformed requests refused; own keys forwarded unchanged, caching, limits, no logging.`);
})().catch(error => { process.stderr.write(String(error.stack || error) + '\n'); process.exit(1); });
