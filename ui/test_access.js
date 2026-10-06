// Preview-mode access gate: no provider request leaves the page until the access code is accepted.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
class Node {
  constructor(tag = 'div') {
    this.tagName = tag; this.children = []; this.listeners = {}; this._text = '';
    this.value = ''; this.disabled = false; this.className = ''; this.style = {};
    this.classList = {add() {}, remove() {}, toggle() {}};
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  get options() { return this.children; }
  append(...items) { this.children.push(...items); if (this.tagName === 'select' && items.length && this.children.length === items.length) this.value = this.children[0].value; }
  replaceChildren(...items) { this.children = []; this._text = ''; this.append(...items); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  setAttribute(name, value) { this[name] = value; }
  fire(name, data = {}) { return this.listeners[name](data); }
  click() { return this.fire('click'); }
}
const ids = ['drop','file','choose','preview','source','seed','description','backend','analyze','resume','narrate','status','count','timeline','findings','narrative','nav-setup','nav-events','nav-chain','nav-table','page-setup','page-events','page-chain','page-table','chain','chain-banner','timeline-banner','table-banner','chain-source','chain-toggle','copy-chain','narrative-model','table-body','table-count','table-summary','table-guidance','provider-status','provider-help','model-name','refresh-provider','access-box','access-code','access-state','unlock'];
const nodes = Object.fromEntries(ids.map(id => [id, new Node(id === 'seed' ? 'select' : 'div')]));
const origin = 'https://example.replit.dev';
const requests = [];
let answers = [];
const context = {
  document: {getElementById: id => nodes[id], createElement: tag => new Node(tag)},
  location: {hostname:'example.replit.dev', protocol:'https:', origin, hash:''},
  URL, Date, Set, Map, JSON, Error, AbortController,
  fetch: async (url, options) => {
    if (url.endsWith('/api/status')) return {ok:true, json:async () => ({jev_configured:true, openrouter_configured:true, narrative_model:'deepseek/deepseek-v4.1-flash', example_available:false, access_required:true})};
    requests.push({url, headers:options.headers, body:JSON.parse(options.body)});
    const answer = answers.shift();
    return answer.httpStatus ? {ok:false, status:answer.httpStatus, json:async () => ({error:answer.error})} : {ok:true, json:async () => answer};
  }
};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), context);
const flush = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  await flush();
  assert.equal(nodes['access-box'].hidden, false, 'preview shows the access-code field');
  assert.match(nodes['access-state'].textContent, /calls locked/);
  const fixture = fs.readFileSync(path.join(__dirname, '..', 'tests', 'fixtures', 'synthetic.json'), 'utf8');
  await nodes.file.fire('change', {target:{files:[{size:fixture.length, name:'synthetic.json', text:async () => fixture}]}});
  await flush();
  nodes.seed.value = 'seed'; nodes.seed.fire('change');
  nodes.description.value = 'Analyst context';
  await nodes.analyze.click(); await flush();
  assert.equal(requests.length, 0, 'locked preview sends nothing');
  assert.match(nodes.status.textContent, /access code/);

  answers = [{httpStatus:403, error:'Preview access code rejected; copy the current code from the workflow console (it changes on every restart).'}];
  nodes['access-code'].value = 'wrong';
  await nodes.unlock.click(); await flush();
  assert.equal(requests[0].url, `${origin}/api/access`);
  assert.equal(requests[0].headers['X-Preview-Access-Code'], 'wrong');
  assert.match(nodes.status.textContent, /Unlock failed: Preview access code rejected/);
  await nodes.analyze.click(); await flush();
  assert.equal(requests.length, 1, 'rejected code keeps provider calls locked');

  answers = [{authorized:true}, {analysis_id:'analysis-1', decisions:[{id:'child', related:true, probability:.9}], summary:{}}];
  nodes['access-code'].value = 'right-code';
  await nodes.unlock.click(); await flush();
  assert.equal(nodes['access-code'].value, '', 'code field is cleared after unlock');
  assert.match(nodes['access-state'].textContent, /unlocked/);
  await nodes.analyze.click(); await flush();
  assert.equal(requests[2].url, `${origin}/api/analyze`);
  assert.equal(requests[2].headers['X-Preview-Access-Code'], 'right-code');
  assert.match(nodes.status.textContent, /Jev relatedness received/);

  // A server restart rotates the code: a 401/403 relocks the page.
  answers = [{httpStatus:403, error:'Preview access code rejected; copy the current code from the workflow console (it changes on every restart).'}];
  await nodes.narrate.click(); await flush();
  assert.match(nodes.status.textContent, /Narrative failed: Preview access code rejected/);
  assert.match(nodes['access-state'].textContent, /calls locked/);
  await nodes.narrate.click(); await flush();
  assert.equal(requests.length, 4, 'relocked page sends nothing more');
  console.log('Preview access gate passed: locked until the server accepts the code, relocks on rejection.');
})().catch(e => {console.error(e); process.exitCode = 1;});
