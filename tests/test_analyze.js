// Run with: node tests/test_analyze.js (from the repository root). TypeSafe is faked; no network.
// Analysis on the server with the site's free key (api/_analyze.js).
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createHandler, LIMITS, MAX_LOG_BYTES} = require('../api/_analyze.js');

// The function must never log keys, logs or results.
for (const name of ['log', 'info', 'warn', 'error', 'debug']) console[name] = () => { throw new Error(`analyze wrote to console.${name}`); };

function call(handler, body, headers = {}) {
  const req = {method: 'POST', body, headers: {host: 'jevline.example', origin: 'https://jevline.example', 'content-type': 'application/json',
    'x-real-ip': '198.51.100.7', ...headers}};
  return new Promise(resolve => {
    const res = {headers: {}, statusCode: 200, setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
      end(text) { resolve({status: this.statusCode, json: JSON.parse(text)}); }};
    handler(req, res);
  });
}

(async () => {
  const example = fs.readFileSync(path.join(__dirname, '..', 'examples', 'malicious_events.json'), 'utf8');
  const files = [{name: 'malicious_events.json', text: example}];
  // Jev, faked: whatever an injection reaches is related. Every question is recorded.
  const asked = [];
  const transport = async body => {
    const request = JSON.parse(body);
    asked.push(request);
    return {model: 'jev-1.13.0', usage: {input_tokens: 100, output_tokens: 1}, answers: Object.fromEntries(Object.entries(request.questions).map(([label]) =>
      [label, {type: 'noul', noul: request.state.candidates?.[label]?.links.some(l => /injected/.test(l.what)) ? 0.9 : 0.2}]))};
  };
  const handler = createHandler({transport});

  // Loading: the seed list and a summary, without any Jev question (the example needs no schema learning).
  let r = await call(handler, {files});
  assert.equal(r.status, 200);
  assert.equal(r.json.summary.records, 100);
  const seed = r.json.seeds.find(s => s.name === '2.8.exe');
  assert.ok(seed && seed.pid === 8788);
  assert.equal(asked.length, 0);

  // Analyzing: the incident, with every question the server built, from the uploaded logs only.
  r = await call(handler, {files, seed: `key:${seed.key}`, context: 'Analyst-confirmed 2.8.exe execution.'});
  assert.equal(r.status, 200);
  const names = r.json.report.incident.map(row => row.name);
  assert.ok(names.includes('sihost.exe') && names.includes('RuntimeBroker.exe'), names.join(', '));
  assert.equal(r.json.report.jev.transport, 'TypeSafe, this site\'s free key, on the server');
  assert.ok(asked.length > 3 && r.json.requests.length === asked.length);
  assert.ok(asked.every(request => request.state.analyst_context === 'Analyst-confirmed 2.8.exe execution.'));
  r = await call(handler, {files, seed: 'name:2.8.exe', context: 'Again, by name.'});
  assert.equal(r.status, 200, 'any seed selector works');

  // Unknown log schemas are learned with the free key too, and the mappings come back for the browser to keep.
  const {falconFdr} = await import(path.join(__dirname, '..', 'engine', 'test', 'incident.ts'));
  const {standIn} = await import(path.join(__dirname, '..', 'engine', 'src', 'standin.ts'));
  const learner = createHandler({transport: standIn()});
  r = await call(learner, {files: [{name: 'fdr.ndjson', text: falconFdr().join('\n')}]});
  assert.equal(r.status, 200);
  assert.ok(r.json.mappings.length >= 7 && r.json.seeds.some(s => s.name === 'invoice.exe'));
  r = await call(learner, {files: [{name: 'fdr.ndjson', text: falconFdr().join('\n')}], mappings: r.json.mappings});
  assert.equal(r.json.mappings.length, 0, 'mappings sent back are reused, not learned again');

  // The free key's bounds: 2 MB of logs, the seed and context, and the site's own origin.
  r = await call(handler, {files: [{name: 'big.log', text: 'x'.repeat(MAX_LOG_BYTES + 1)}]});
  assert.equal(r.status, 400);
  assert.match(r.json.error, /up to 2 MB/);
  assert.equal((await call(handler, {files, seed: 'name:2.8.exe', context: ''})).status, 400);
  assert.equal((await call(handler, {files, seed: 'name:2.8.exe', context: 'x'.repeat(501)})).status, 400);
  assert.equal((await call(handler, {files: []})).status, 400);
  assert.equal((await call(handler, {files}, {origin: 'https://evil.example'})).status, 403);
  r = await call(handler, {files, seed: 'name:nothing.exe', context: 'x'});
  assert.equal(r.status, 400);
  assert.match(r.json.error, /no process start named/);
  const unconfigured = createHandler({env: {}});
  assert.equal((await call(unconfigured, {files})).status, 200, 'no key: logs still load');
  r = await call(unconfigured, {files, seed: 'name:2.8.exe', context: 'x'});
  assert.equal(r.status, 503, 'no key: analysis says so');
  assert.match(r.json.error, /not configured/);

  // Limits per visitor and for everyone, reset after an hour.
  let clock = 0;
  const limits = createHandler({transport, now: () => clock});
  for (let i = 0; i < LIMITS.analyze; i++) assert.equal((await call(limits, {files, seed: 'name:2.8.exe', context: 'x'})).status, 200);
  r = await call(limits, {files, seed: 'name:2.8.exe', context: 'x'});
  assert.equal(r.status, 429);
  assert.match(r.json.error, /analyses per hour/);
  assert.equal((await call(limits, {files, seed: 'name:2.8.exe', context: 'x'}, {'x-real-ip': '203.0.113.9'})).status, 200, 'other visitors unaffected');
  clock += 60 * 60 * 1000;
  assert.equal((await call(limits, {files, seed: 'name:2.8.exe', context: 'x'})).status, 200);

  process.stdout.write(`Server analysis passed: load, analyze (${asked.length} questions built from the upload), schema learning, 2 MB cap, limits, no logging.\n`);
})().catch(error => { process.stderr.write(String(error.stack || error) + '\n'); process.exit(1); });
