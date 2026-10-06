// Run with: node ui/test_engine.js (from the repository root). No network: fetch is faked.
// The JavaScript port must reproduce jev_incident.py exactly (tests/fixtures/engine_golden.json is
// written and checked by test_jev_incident.py).
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const engine = require('./engine.js');

const root = path.join(__dirname, '..');
const golden = JSON.parse(fs.readFileSync(path.join(root, 'tests', 'fixtures', 'engine_golden.json'), 'utf8'));
const fixtures = {synthetic: 'tests/fixtures/synthetic.json', edge_cases: 'tests/fixtures/edge_cases.json',
  malicious_events: 'examples/malicious_events.json'};
const load = name => { const data = JSON.parse(fs.readFileSync(path.join(root, fixtures[name]), 'utf8')); return Array.isArray(data) ? data : data.events; };
const digest = text => crypto.createHash('sha256').update(text).digest('hex');

function goldenJudge(state) {  // Same rule as test_jev_incident.golden_judge.
  const entity = e => { const p = e.process; return p && typeof p === 'object' && !Array.isArray(p) && p.entity_id !== undefined ? p.entity_id : null; };
  const parent = (state.candidate.process || {}).parent || {};
  const known = new Set([state.seed, ...state.known_related].map(entity).filter(x => x !== null));
  if (parent && typeof parent === 'object' && known.has(parent.entity_id ?? null)) return [0.9, 'lineage'];
  return [0.1 + 0.05 * state.surrounding.length, 'no_link'];
}

const response = (status, body) => ({ok: status >= 200 && status < 300, status, text: async () => typeof body === 'string' ? body : JSON.stringify(body)});
const jevAnswer = (noul, choice = 'lineage') => response(200, {model: 'jev-1.13.0', usage: {input_tokens: 10, output_tokens: 1},
  answers: {related: {type: 'noul', noul}, evidence: {type: 'choice', choice}}});

(async () => {
  // 1. Parity with the Python reference implementation.
  for (const [name, expected] of Object.entries(golden)) {
    const events = load(name);
    const keep = name === 'malicious_events' ? digest : text => text;
    const compacted = events.map(engine.compact);
    assert.deepEqual(compacted.map(e => keep(JSON.stringify(e))), expected.compact, `${name}: compact()`);
    assert.deepEqual(compacted.map(e => engine.timestamp(e.time ?? null)), expected.times, `${name}: timestamp()`);
    assert.deepEqual(compacted.filter(engine.isExecution).map(e => e.id), expected.executions, `${name}: isExecution()`);
    const contexts = Object.fromEntries(compacted.filter(engine.isExecution).map(e => [e.id, engine.context(compacted, e).map(c => c.id)]));
    assert.deepEqual(contexts, expected.contexts, `${name}: context()`);
    const requests = [];
    const results = await engine.run(events, expected.seed, 'Analyst-confirmed seed.', async state => goldenJudge(state),
      {observer: (pass, state) => { requests.push(keep(JSON.stringify([pass, state]))); }});
    assert.deepEqual(requests, expected.requests, `${name}: request sequence`);
    assert.deepEqual(results, expected.results, `${name}: decisions`);
  }

  const events = load('synthetic');
  const state = {seed_description: 'x', seed: engine.compact(events[0]), known_related: [], candidate: engine.compact(events[2]), surrounding: []};

  // 2. Retries: temporary 5xx twice, then an answer.
  {
    const calls = [], sleeps = [];
    const replies = [response(520, 'origin error'), response(503, 'busy'), jevAnswer(0.91)];
    const answer = await engine.jev(state, 'user-key', {fetchImpl: async (url, init) => { calls.push({url, init}); return replies.shift(); },
      sleep: async ms => { sleeps.push(ms); }});
    assert.deepEqual(answer, [0.91, 'lineage']);
    assert.deepEqual(sleeps, [1000, 2000]);
    assert.equal(calls.length, 3);
    assert.equal(calls[0].url, 'https://api.typesafe.ai/v1/systemone');
    assert.equal(calls[0].init.headers.Authorization, 'Bearer user-key');
    assert.equal(calls[0].init.credentials, 'omit');
    assert.ok(!calls[0].init.body.includes('user-key'), 'the key travels only in the Authorization header');
  }
  // Exhausted retries, rejected key and an unreachable/CORS-blocked API are named, not guessed.
  await assert.rejects(engine.jev(state, 'k', {fetchImpl: async () => response(520, 'x'), sleep: async () => {}}),
    {message: 'TypeSafe returned HTTP 520 after 3 attempts; retry later.'});
  let count = 0;
  await assert.rejects(engine.jev(state, 'k', {fetchImpl: async () => { count++; return response(401, 'no'); }, sleep: async () => {}}),
    {message: 'TypeSafe rejected the API key (HTTP 401); check your TypeSafe key.'});
  assert.equal(count, 1, '4xx is never retried');
  await assert.rejects(engine.jev(state, 'k', {fetchImpl: async () => { throw new TypeError('Failed to fetch'); }}), /CORS/);
  await assert.rejects(engine.jev(state, 'k', {fetchImpl: async () => response(200, {answers: {related: {noul: 1.5}, evidence: {choice: 'lineage'}}})}),
    {message: 'TypeSafe returned an unusable Jev answer; no decision was assumed.'});

  // 3. analyze(): a failed run keeps its answers, and resume asks Jev only for the rest.
  {
    const cache = new Map();
    let calls = 0;
    const failing = async () => ++calls <= 2 ? jevAnswer(0.9) : response(401, 'expired');
    const error = await engine.analyze(events, 'seed', 'Confirmed', 'k', {cache, fetchImpl: failing, sleep: async () => {}}).then(() => null, e => e);
    assert.equal(error.resumeAvailable, true);
    assert.equal(error.reusable, 2);
    calls = 0;
    const result = await engine.analyze(events, 'seed', 'Confirmed', 'k', {cache, resume: true, fetchImpl: async () => { calls++; return jevAnswer(0.2, 'no_link'); }, sleep: async () => {}});
    assert.equal(result.summary.reused_answers, 2);
    assert.equal(result.summary.api_calls, calls);
    assert.equal(result.summary.resumed, true);
    assert.equal(result.decisions.filter(d => d.reused).length, 2);
    assert.ok(result.decisions.filter(d => d.reused).every(d => typeof d.reused.answered_utc === 'string'));
    assert.match(result.analysis_id, /^browser-/);
    // A wrong seed is an input problem, not a resumable provider failure.
    const bad = await engine.analyze(events, 'file-1', 'x', 'k', {fetchImpl: failing}).then(() => null, e => e);
    assert.equal(bad.message, 'seed id must identify an execution event');
    assert.equal(bad.resumeAvailable, undefined);
  }

  // 4. Narrative: only seed, Jev-linked starts and exact entity context; drafts are validated.
  {
    const decisions = [{id: 'seed', related: true}, {id: 'child', related: true}, {id: 'later', related: false}];
    assert.deepEqual(engine.timelineInput(events, decisions).map(e => e.id), ['seed', 'file-1', 'child']);
    const draft = rows => response(200, {model: 'deepseek/deepseek-v4.1-flash', choices: [{finish_reason: 'stop', message: {content: JSON.stringify({timeline: rows})}}]});
    const sent = [];
    const replies = [response(200, {choices: [{finish_reason: 'length', message: {content: null}}]}),
      draft([{event_id: 'child', title: 'Child', summary: 'Observed start', evidence_ids: ['seed', 'child']}])];
    const result = await engine.narrate(events, decisions, 'or-key', {fetchImpl: async (url, init) => { sent.push({url, init}); return replies.shift(); }});
    assert.equal(sent.length, 2, 'one retry with a larger budget');
    assert.equal(sent[0].url, 'https://openrouter.ai/api/v1/chat/completions');
    assert.equal(sent[0].init.headers.Authorization, 'Bearer or-key');
    assert.deepEqual(JSON.parse(sent[1].init.body).max_tokens, 16384);
    assert.equal(JSON.parse(sent[0].init.body).model, 'deepseek/deepseek-v4.1-flash');
    assert.deepEqual(JSON.parse(JSON.parse(sent[0].init.body).messages[1].content).linked_events.map(e => e.id), ['seed', 'file-1', 'child']);
    assert.equal(result.timeline[0].event_id, 'child');
    const invented = draft([{event_id: 'made-up', title: 'x', summary: 'x', evidence_ids: ['seed']}]);
    await assert.rejects(engine.narrate(events, decisions, 'k', {fetchImpl: async () => invented}),
      {message: 'OpenRouter returned invalid or truncated JSON after retry'});
    await assert.rejects(engine.narrate(events, decisions, 'k', {fetchImpl: async () => response(401, 'no')}),
      {message: 'OpenRouter rejected the API key (HTTP 401); check your OpenRouter key.'});
    // Chosen model, ATT&CK mapping and the Markdown execution chain (same rules as web_app.py).
    const chosen = [];
    const drafted = await engine.narrate(events, decisions, 'k', {model: 'anthropic/claude-sonnet-5.5', fetchImpl: async (url, init) => { chosen.push(JSON.parse(init.body)); return response(200, {
      model: 'anthropic/claude-sonnet-5.5', choices: [{finish_reason: 'stop', message: {content: JSON.stringify({timeline: [
        {event_id: 'child', title: 'Child', summary: 'Started', evidence_ids: ['child'], tactic: 'execution', techniques: ['t1059.003', 'bogus']}],
        execution_chain: '- **stage.exe** [evt:child] then [evt:invented]'})}}]}); }});
    assert.equal(chosen[0].model, 'anthropic/claude-sonnet-5.5');
    assert.deepEqual([drafted.timeline[0].tactic, drafted.timeline[0].tactic_id, drafted.timeline[0].techniques], ['Execution', 'TA0002', ['T1059.003']]);
    assert.equal(drafted.execution_chain, '- **stage.exe** [evt:child] then [unknown event]');
    await assert.rejects(engine.narrate(events, decisions, 'k', {model: 'https://evil/x', fetchImpl: async () => { throw new Error('sent'); }}), /OpenRouter model ID/);
    // Each event tells the model how it is linked.
    const links = Object.fromEntries(engine.timelineInput(events, [{id: 'seed', related: true, probability: 1, reason: 'Confirmed starting execution (user-provided)'},
      {id: 'child', related: true, probability: 0.94, reason: 'lineage (Jev-selected category; not generated prose)'}]).map(e => [e.id, e.link]));
    assert.deepEqual(links, {seed: {type: 'confirmed_seed'}, 'file-1': {type: 'same_process_as', event_id: 'seed'}, child: {type: 'jev_linked', probability: 0.94, basis: 'lineage'}});
    // The narrative prompt and tactic list are the same as the local portal's (web_app.py).
    const python = fs.readFileSync(path.join(root, 'web_app.py'), 'utf8');
    const literals = block => [...block.matchAll(/'((?:[^'\\\n]|\\.)*)'/g)].map(m => m[1]).join('');
    const between = (textBlock, open, close) => { const start = textBlock.indexOf(open); return textBlock.slice(start, textBlock.indexOf(close, start)); };
    assert.equal(literals(between(python, '# <narrative-prompt>', '# </narrative-prompt>')), engine.SYSTEM_PROMPT);
    const pyTactics = Object.fromEntries([...between(python, 'TACTICS = {', '}').matchAll(/'(TA\d{4})': '([^']+)'/g)].map(m => [m[1], m[2]]));
    assert.deepEqual(pyTactics, engine.TACTICS);
  }
  console.log('Engine passed: byte-identical Jev requests to jev_incident.py on 3 fixtures, retries, resume, narrative validation.');
})().catch(error => { console.error(error); process.exit(1); });
