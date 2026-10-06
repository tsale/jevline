// Run with: node ui/test_browser.js (from the repository root).
// The static website (site/index.html): keys typed in the page, requests only to the two providers.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'site', 'index.html'), 'utf8');
// The privacy claim is enforced by the page's own connection policy, not just promised.
const policy = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
const directive = name => policy.split(';').map(d => d.trim()).find(d => d.startsWith(name + ' '));
assert.equal(directive('connect-src'), "connect-src 'self' https://openrouter.ai", 'only this site (its Jev relay) and OpenRouter can be contacted');
assert.equal(directive('default-src'), "default-src 'none'");
assert.equal(directive('script-src'), "script-src 'self'");
assert.equal(directive('form-action'), "form-action 'none'");
assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)[^>]*>/, 'no inline scripts');
assert.doesNotMatch(html, /<script[^>]+src="https?:/, 'no third-party scripts');
assert.match(html, /<body data-mode="browser" data-jev-endpoint="api\/jev">/);
const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map(m => m[1]);

class Node {
  constructor(tag = 'div') {
    this.tagName = tag; this.children = []; this.listeners = {}; this._text = '';
    this.value = ''; this.disabled = false; this.hidden = false; this.checked = false; this.className = ''; this.style = {};
    this.classList = {add() {}, remove() {}, toggle() {}};
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  get options() { return this.children; }
  append(...items) {
    this.children.push(...items);
    if (this.tagName === 'select' && items.length && this.children.length === items.length) this.value = this.children[0].value;
    // <script src="examples/malicious_events.js"> appended to <head>: run the built example file.
    for (const item of items) if (item.tagName === 'script') setImmediate(() => { context.CASEBENCH_EXAMPLE = example; item.onload(); });
  }
  replaceChildren(...items) { this.children = []; this._text = ''; this.append(...items); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  setAttribute(name, value) { this[name] = value; }
  fire(name, data = {}) { return this.listeners[name](data); }
  click() { return this.fire('click'); }
}
const example = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'examples', 'malicious_events.json'), 'utf8'));
const nodes = Object.fromEntries(ids.map(id => [id, new Node(id === 'seed' ? 'select' : 'div')]));
nodes.download.hidden = nodes.resume.hidden = true;
const storage = new Map();
const requests = [];
let respond = () => { throw new Error('unexpected request'); };
const context = {
  document: {getElementById: id => nodes[id], createElement: tag => new Node(tag), body: {dataset: {mode: 'browser', jevEndpoint: 'api/jev'}}, head: new Node('head')},
  location: {hostname: 'jev-incident-timeline.vercel.app', protocol: 'https:', origin: 'https://jev-incident-timeline.vercel.app', hash: ''},
  localStorage: {getItem: k => storage.has(k) ? storage.get(k) : null, setItem: (k, v) => storage.set(k, String(v)), removeItem: k => storage.delete(k)},
  fetch: async (url, init) => { requests.push({url, init}); return respond(url, init); },
  URL, Date, Set, Map, JSON, Error, TypeError, AbortController, TextEncoder, crypto, performance, setTimeout, clearTimeout, setImmediate, Promise,
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, 'engine.js'), 'utf8'), context);
vm.runInContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), context);

const flush = () => new Promise(resolve => setImmediate(resolve));
async function settle() { for (let i = 0; i < 200; i++) await flush(); }
const reply = (status, body) => ({ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body)});
const jev = noul => reply(200, {model: 'jev-1.13.0', usage: {input_tokens: 5, output_tokens: 1},
  answers: {related: {type: 'noul', noul}, evidence: {type: 'choice', choice: noul >= 0.8 ? 'lineage' : 'no_link'}}});
const scores = {child: 0.94, later: 0.88, unrelated: 0.05};
const typeSafe = (url, init) => jev(scores[JSON.parse(init.body).state.candidate.id] ?? 0.1);
const choose = mode => { nodes['mode-demo'].checked = mode === 'demo'; nodes['mode-own'].checked = mode === 'own'; nodes[`mode-${mode}`].fire('change'); };
const type = (id, value) => { nodes[id].value = value; nodes[id].fire('input'); };

(async () => {
  assert.equal(requests.length, 0, 'opening the page contacts no one');
  // The privacy notice can be dismissed, stays dismissed in this browser, and comes back from the top bar.
  assert.equal(nodes['privacy-note'].hidden, false);
  assert.equal(nodes['privacy-show'].hidden, true);
  nodes['privacy-dismiss'].click();
  assert.equal(nodes['privacy-note'].hidden, true);
  assert.equal(nodes['privacy-show'].hidden, false);
  assert.equal(storage.get('jevline.privacyDismissed'), '1');
  nodes['privacy-show'].click();
  assert.equal(nodes['privacy-note'].hidden, false);
  assert.equal(storage.has('jevline.privacyDismissed'), false);
  // The demo key is the default: no key field, and Analyze works on the bundled example only.
  assert.equal(nodes['mode-demo'].checked, true);
  assert.equal(nodes['jev-key-field'].hidden, true);
  assert.match(nodes['key-status'].textContent, /Demo key \(bundled example only\)/);

  // Bundled example loads from the site's own static files; nothing is sent.
  await nodes.preview.click(); await settle();
  assert.match(nodes.source.textContent, /Bundled malicious-events example · 100 events/);
  assert.equal(nodes.description.value, 'Analyst-confirmed 2.8.exe execution on CLA-WS-214.', 'the example fills in its analyst context');
  assert.equal(nodes.seed.value, 'VvT8xKABOYkemEz9sgQR');
  assert.equal(requests.length, 0);

  // Demo analysis goes to this site's relay without any key.
  nodes.description.value = 'Confirmed';
  respond = typeSafe;
  await nodes.analyze.click(); await settle();
  assert.ok(requests.length >= 3);
  assert.ok(requests.every(r => r.url === 'api/jev' && r.init.headers.Authorization === undefined), 'demo requests carry no key');
  assert.match(nodes.status.textContent, /Jev relatedness received/);

  // A relay refusal is shown as written.
  nodes.description.value = 'Confirmed again'; nodes.description.fire('input');
  respond = () => reply(429, {error: 'The demo key is busy for your connection; wait a few minutes or use your own TypeSafe key.', source: 'relay'});
  await nodes.analyze.click(); await settle();
  assert.match(nodes.status.textContent, /Analysis failed: The demo key is busy for your connection/);

  // The demo key is refused locally for the visitor's own file.
  const fixture = fs.readFileSync(path.join(__dirname, '..', 'tests', 'fixtures', 'synthetic.json'), 'utf8');
  await nodes.file.fire('change', {target: {files: [{size: fixture.length, name: 'synthetic.json', text: async () => fixture}]}});
  await settle();
  nodes.seed.value = 'seed'; nodes.seed.fire('change');
  nodes.description.value = 'Analyst context';
  requests.length = 0;
  await nodes.analyze.click(); await settle();
  assert.match(nodes.status.textContent, /demo key only analyzes the bundled lab example/);
  assert.equal(requests.length, 0);

  // Own key: the field appears; without a key nothing is sent.
  choose('own');
  assert.equal(nodes['jev-key-field'].hidden, false);
  assert.match(nodes['key-status'].textContent, /TypeSafe key needed/);
  await nodes.analyze.click(); await settle();
  assert.match(nodes.status.textContent, /Enter your TypeSafe API key/);
  assert.equal(requests.length, 0);

  // Keys stay in memory unless "Remember on this device" is checked; Forget clears both.
  type('jev-key', ' ts-key ');
  assert.equal(storage.size, 0, 'not stored by default');
  nodes['remember-keys'].checked = true; nodes['remember-keys'].fire('change');
  assert.deepEqual(JSON.parse(storage.get('jevline.keys')), {jev: 'ts-key', openrouter: ''});
  nodes['forget-keys'].click();
  assert.equal(storage.size, 0);
  assert.equal(nodes['jev-key'].value, '');
  type('jev-key', 'ts-key');

  // A full analysis of the visitor's file goes through the relay with their key, only in the header.
  respond = typeSafe;
  await nodes.analyze.click(); await settle();
  assert.ok(requests.length >= 3);
  assert.ok(requests.every(r => r.url === 'api/jev'));
  assert.ok(requests.every(r => r.init.headers.Authorization === 'Bearer ts-key' && !r.init.body.includes('ts-key')));
  assert.equal(nodes['page-events'].hidden, false, 'results open the timeline');
  assert.match(nodes.timeline.textContent, /Jev 94%/);
  assert.match(nodes.count.textContent, /^4 linked of 5 source events$/);
  assert.match(nodes['timeline-banner'].textContent, /Jev results only · no AI enrichment/);
  assert.match(nodes.chain.textContent, /Process chain from Jev results/);
  assert.equal(nodes['narrative-model'].value, 'deepseek/deepseek-v4.1-flash', 'the narrative model is shown before a draft is requested');
  assert.match(nodes.findings.textContent, /Jev decision\(s\) matched/);
  assert.equal(nodes.download.hidden, false, 'run can be downloaded');
  assert.equal(nodes.narrate.disabled, true, 'narrative needs an OpenRouter key');

  // Optional narrative goes only to OpenRouter.
  type('openrouter-key', 'or-key');
  assert.equal(nodes.narrate.disabled, false);
  requests.length = 0;
  type('narrative-model', 'anthropic/claude-sonnet-5.5');
  assert.equal(storage.get('jevline.model'), 'anthropic/claude-sonnet-5.5', 'a chosen model is remembered');
  respond = () => reply(200, {model: 'anthropic/claude-sonnet-5.5', choices: [{finish_reason: 'stop', message: {content: JSON.stringify({timeline: [
    {event_id: 'child', title: 'Stage execution', summary: 'stage.exe started from the seed', evidence_ids: ['seed', 'child'], tactic: 'Execution', techniques: ['T1059.001']}],
    execution_chain: '- **powershell.exe** [evt:seed]\n  - **stage.exe** [evt:child]'})}}]});
  await nodes.narrate.click(); await settle();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, 'https://openrouter.ai/api/v1/chat/completions');
  assert.equal(requests[0].init.headers.Authorization, 'Bearer or-key');
  assert.equal(JSON.parse(requests[0].init.body).model, 'anthropic/claude-sonnet-5.5', 'the chosen model is used');
  assert.match(nodes['table-banner'].textContent, /AI-enriched draft.*anthropic\/claude-sonnet-5.5/);
  assert.equal(nodes['page-chain'].hidden, false, 'the drafted chain opens in its own tab');
  assert.match(nodes['table-body'].textContent, /Execution · TA0002/);
  assert.match(nodes['table-body'].textContent, /T1059.001/);
  type('narrative-model', 'not a model');
  await nodes.narrate.click(); await settle();
  assert.match(nodes.status.textContent, /must be an OpenRouter model ID/);
  assert.equal(requests.length, 1, 'an invalid model is refused before sending');
  type('narrative-model', 'deepseek/deepseek-v4.1-flash');
  assert.equal(storage.has('jevline.model'), false, 'the default model is not stored');
  assert.match(nodes['table-body'].textContent, /Stage execution/);

  // An outage after one answer offers Resume, which asks Jev only for the remaining candidates.
  nodes.description.value = 'Analyst context, again'; nodes.description.fire('input');
  requests.length = 0;
  let calls = 0;
  respond = (url, init) => ++calls === 1 ? typeSafe(url, init) : reply(401, {error: 'expired'});
  await nodes.analyze.click(); await settle();
  assert.match(nodes.status.textContent, /Analysis failed: TypeSafe rejected the API key \(HTTP 401\)/);
  assert.equal(nodes.resume.hidden, false);
  assert.match(nodes.resume.textContent, /1 answered call reused/);
  requests.length = 0;
  respond = typeSafe;
  await nodes.resume.click(); await settle();
  assert.match(nodes.status.textContent, /after resume \(1 answer reused\)/);
  assert.ok(requests.length >= 2);

  // An unreachable relay explains itself and offers nothing to resume.
  nodes.description.value = 'Third run'; nodes.description.fire('input');
  respond = () => { throw new TypeError('Failed to fetch'); };
  await nodes.analyze.click(); await settle();
  assert.match(nodes.status.textContent, /relay on this site could not be reached/);
  assert.equal(nodes.resume.hidden, true);
  console.log('Browser site passed: self+OpenRouter connection policy, demo key on the example only, own key via relay, direct OpenRouter, resume.');
})().catch(error => { console.error(error); process.exit(1); });
