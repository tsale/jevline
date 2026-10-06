// Run with: node ui/test_site.js (from the repository root). Offline: Jev and OpenRouter are faked.
// The website page (site/index.html) and what it shows from a report (ui/view.js).
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const View = require('./view.js');

const ROOT = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'site', 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');

// The privacy claim is enforced by the page's own connection policy, not just promised.
const policy = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
const directive = name => policy.split(';').map(d => d.trim()).find(d => d.startsWith(name + ' '));
assert.equal(directive('connect-src'), "connect-src 'self' https://openrouter.ai", 'only this site (its Jev relay) and OpenRouter can be contacted');
assert.equal(directive('default-src'), "default-src 'none'");
assert.equal(directive('script-src'), "script-src 'self'", 'the engine thread is a script from this site too');
assert.equal(directive('form-action'), "form-action 'none'");
assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)[^>]*>/, 'no inline scripts');
assert.doesNotMatch(html, /<script[^>]+src="https?:/, 'no third-party scripts');
assert.match(html, /<script src="view\.js" defer><\/script>\s*<script src="app\.js" defer><\/script>/);
assert.match(app, /new Worker\('engine\/web-worker\.js', \{type: 'module'\}\)/);
// Every element the page's script uses exists in the page.
const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map(m => m[1]));
const used = new Set([...app.matchAll(/\$\('([a-z-]+)'\)/g)].map(m => m[1]));
for (const name of ['setup', 'incident', 'events', 'chain', 'table']) used.add(`page-${name}`).add(`nav-${name}`);
for (const id of used) assert.ok(ids.has(id), `#${id} is in the page`);

(async () => {
  // A real report: the engine on the bundled example, with Jev faked to link what an injection reaches.
  const engine = path.join(ROOT, 'engine', 'src');
  const {load, analyze, findSeed} = await import(path.join(engine, 'analyze.ts'));
  const {JevClient} = await import(path.join(engine, 'jev.ts'));
  const loaded = await load([{path: path.join(ROOT, 'examples', 'malicious_events.json'), format: 'auto'}]);
  const jev = async body => {
    const request = JSON.parse(body);
    const answers = {};
    for (const [label, candidate] of Object.entries(request.state.candidates)) {
      answers[label] = {type: 'noul', noul: candidate.links.some(l => /injected/.test(l.what)) ? 0.9 : 0.2};
    }
    return {answers};
  };
  const {report} = await analyze(loaded, findSeed(loaded, 'name:2.8.exe').key, new JevClient(jev), {description: 'Analyst-confirmed 2.8.exe execution.',
    model: 'jev-1.13.0', threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 2000, transport: 'test'});

  // Members: every process a folded row stands for is still there, with its own probability.
  const members = View.members(report);
  assert.equal(members.size, report.incident.reduce((n, row) => n + (row.repeats?.count ?? 1), 0));
  const brokers = report.incident.find(row => row.name === 'RuntimeBroker.exe');
  assert.equal(brokers.repeats.count, 5);
  for (const other of brokers.repeats.others) assert.equal(members.get(other.key).row, brokers);

  // Timeline rows: the seed's activity, and the injection row, which is folded.
  const origins = report.timeline.map(row => View.originOf(row, report, members).kind);
  assert.ok(origins.includes('seed'));
  const injection = report.timeline.find(row => row.kind === 'inject' && row.detail.startsWith('RuntimeBroker'));
  assert.equal(injection.count, 5);
  assert.match(View.repeatText(injection), /^×5 until .*, every <1 s$/);
  assert.deepEqual(View.indicatorFor({kind: 'network', detail: '10.0.0.5 → 203.0.113.9:443'}), ['203.0.113.9', 'ip-address', 'IP Addresses']);
  assert.deepEqual(View.indicatorFor({kind: 'registry_set', detail: 'HKU\\x\\Run\\a = b.exe'}), ['HKU\\x\\Run\\a', 'registry-key', 'Host Artifacts']);

  // The Jev-only chain: the seed first, each member under the one it joined from, every member counted.
  const chain = View.chainMarkdown(report);
  assert.match(chain, /^## Incident chain from Jev results/);
  assert.match(chain, /\n- \*\*2\.8\.exe\*\* \(PID 8788\) · confirmed seed · started /);
  assert.match(chain, /\n {2}- injected into → \*\*sihost\.exe\*\* \(PID 7328\) · Jev 90% · running before the logs/);
  assert.match(chain, /\*\*RuntimeBroker\.exe\*\* \(PID 9972\) · Jev 90% · running before the logs · ×5 identical/);
  assert.match(chain, new RegExp(`${[...members.values()].filter(m => m.row.type === 'process').length} processes and `));
  // Under each process, what it did: the seed's drop, timestomp, persistence and network, with citations.
  for (const line of [/\n {2}- File write `C:\\Users\\USER_1\\AppData\\Roaming\\Microsoft\\Windows\\Services\\wlrmdr\.exe` ×2 \[evt:/,
    /\n {2}- File time changed `[^`]*wlrmdr\.exe` \[evt:/, /\n {2}- Registry `[^`]*UserInitMprLogonScript/, /\n {2}- Network `173\.223\.234\.200:80`/]) assert.match(chain, line);

  // The narrative input: the seed and every member's joining event first, each with how it is linked.
  const input = View.narrativeInput(report);
  assert.ok(input.length <= 60 && input.length > 3);
  assert.equal(input.filter(e => e.link.type === 'confirmed_seed' && e.kind === 'process_start').length, 1);
  assert.ok(input.some(e => e.link.type === 'activity_of_linked_member' || e.link.type === 'confirmed_seed'));
  const allowed = new Set(input.map(e => e.event_id));
  const id = input[0].event_id;

  // A draft is kept only if every event ID it cites was supplied; ATT&CK values are checked, not trusted.
  const row = {event_id: id, title: 'Loader starts', summary: 'The confirmed loader starts.', evidence_ids: [id], tactic: 'execution', techniques: ['t1059.001', 'T9', 'T1055']};
  assert.deepEqual(View.validateTimeline({timeline: [row]}, allowed)[0], {...row, tactic: 'Execution', tactic_id: 'TA0002', techniques: ['T1059.001', 'T1055']});
  assert.throws(() => View.validateTimeline({timeline: [{...row, event_id: 'invented'}]}, allowed), /invented/);
  assert.throws(() => View.validateTimeline({timeline: [{...row, evidence_ids: ['invented']}]}, allowed), /unknown event/);
  assert.equal(View.cleanChain(`- **x** [evt:${id}] [evt:nope]`, allowed), `- **x** [evt:${id}] [unknown event]`);

  // narrate(): one OpenRouter request with the selected events; the model's JSON is validated.
  const sent = [];
  const reply = {model: 'test/model', choices: [{finish_reason: 'stop', message: {content: JSON.stringify({timeline: [row], execution_chain: `- seed [evt:${id}]`})}}]};
  const fetchImpl = async (url, init) => { sent.push({url, init}); return new Response(JSON.stringify(reply), {status: 200}); };
  const draft = await View.narrate(report, 'or-key', {fetchImpl, model: 'test/model'});
  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, 'https://openrouter.ai/api/v1/chat/completions');
  assert.equal(sent[0].init.headers.Authorization, 'Bearer or-key');
  const body = JSON.parse(sent[0].init.body);
  assert.equal(body.messages[0].content, View.SYSTEM_PROMPT);
  assert.deepEqual(JSON.parse(body.messages[1].content).incident_events, input);
  assert.equal(draft.timeline[0].tactic, 'Execution');
  assert.equal(draft.execution_chain, `- seed [evt:${id}]`);
  await assert.rejects(View.narrate(report, 'k', {fetchImpl: async () => new Response('{}', {status: 401})}), /rejected the API key/);
  await assert.rejects(View.narrate(report, 'k', {model: 'not a model id'}), /OpenRouter model ID/);

  process.stdout.write(`Website tests passed: page policy and elements; ${report.incident.length} incident rows (${members.size} members), ${report.timeline.length} timeline rows, chain, narrative.\n`);
})().catch(error => { process.stderr.write(String(error.stack || error) + '\n'); process.exit(1); });
