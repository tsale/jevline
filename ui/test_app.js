// Run with: node ui/test_app.js (from the repository root).
// Minimal DOM harness exercises the browser event handlers without a server or external traffic.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
assert.match(html, /<th>Timestamp<\/th><th>Host<\/th><th>Phase<\/th><th>Title<\/th><th>Description<\/th><th>Tools<\/th><th>TTPs<\/th><th>Command Line<\/th><th>Indicator<\/th><th>Type<\/th><th>Pyramid<\/th>/, 'table matches detauto CSV columns in order');
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
const requests = [];
let answers = [];
const context = {
  document: {getElementById: id => nodes[id], createElement: tag => new Node(tag)},
  location: {hostname:'127.0.0.1', protocol:'http:', origin:'http://127.0.0.1:8765', hash:''},
  URL, Date, Set, Map, JSON, Error, AbortController,
  fetch: async (url, options) => {
    if (url.endsWith('/api/status')) return {ok:true, json:async () => ({jev_configured:true, openrouter_configured:!process.env.POC_NO_OPENROUTER, narrative_model:'deepseek/deepseek-v4.1-flash', example_available:true})};
    if (url === '/examples/malicious_events.json') return {ok:true, text:async () => fs.readFileSync(path.join(__dirname, '..', 'examples', 'malicious_events.json'), 'utf8')};
    requests.push({url, body:JSON.parse(options.body), options});
    const answer = answers.shift();
    if (answer?.networkError) throw new TypeError('offline');
    return answer?.httpStatus ? {ok:false, status:answer.httpStatus, json:async () => answer.body ?? ({error:answer.error})}
      : {ok:true, json:async () => answer};
  }
};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), context);
const flush = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  assert.equal(requests.length, 0);
  await nodes.preview.click();
  // Import keeps the analyst on Source & analysis, where the seed and context are confirmed next.
  assert.equal(nodes['page-setup'].hidden, false);
  assert.equal(nodes['page-events'].hidden, true);
  assert.equal(nodes['page-table'].hidden, true);
  nodes['nav-table'].click();
  assert.equal(nodes['page-table'].hidden, false);
  assert.equal(nodes['table-body'].children.length, 0, 'incident timeline does not show unassessed events');
  assert.match(nodes['table-guidance'].textContent, /Analyze with Jev/);
  nodes['nav-events'].click();
  assert.equal(nodes['page-events'].hidden, false);
  assert.match(nodes.source.textContent, /Bundled malicious-events example · 100 events/);
  assert.equal(nodes.description.value, 'Analyst-confirmed 2.8.exe execution on CLA-WS-214.', 'the example fills in its analyst context');
  assert.equal(nodes.seed.value, 'VvT8xKABOYkemEz9sgQR');
  assert.match(nodes.count.textContent, /^0 linked of 100 source events$/);
  assert.equal(nodes.narrate.disabled, true);
  assert.equal(nodes.timeline.children.length, 1, 'event timeline does not show unassessed events');
  assert.equal(nodes.timeline.children[0].className, 'empty', 'empty timeline explains the next step');
  assert.equal(requests.length, 0, 'bundled example import never contacts providers');
  const fixture = fs.readFileSync(path.join(__dirname, '..', 'tests', 'fixtures', 'synthetic.json'), 'utf8');
  await nodes.file.fire('change', {target:{files:[{size:fixture.length, name:'synthetic.json', text:async () => fixture}]}});
  await flush();
  nodes.seed.value = 'later'; nodes.seed.fire('change');
  assert.equal(nodes['table-body'].children.length, 0);
  nodes.seed.value = 'seed'; nodes.seed.fire('change');
  nodes.description.value = 'Analyst context';
  answers = [{analysis_id:'analysis-1', decisions:[{id:'child', related:true, probability:.88, reason:'lineage'}], summary:{
      model:'jev-1.13.0', threshold:.8, api_calls:2, evaluated_candidates:4, related_candidates:1,
      reused_answers:0, retried_requests:0, elapsed_seconds:1.5, api_elapsed_seconds:1.2,
      input_tokens:300, output_tokens:40, resumed:false, evidence_dir:'/srv/.local-runs/private/evidence',
      telemetry_file:'/srv/private-input.json', resumed_from:'/srv/.local-runs/previous'}},
    {timeline:[{event_id:'child', title:'Child execution', summary:'Observed process start', evidence_ids:['seed','child'], tactic:'Execution', tactic_id:'TA0002', techniques:['T1059']}],
      execution_chain:'## Chain\n- **powershell.exe** [evt:seed]\n  - **stage.exe** [evt:child]\n\n### ATT&CK summary\n| Tactic | Technique | Evidence |\n|---|---|---|\n| Execution | T1059 | [evt:child] |',
      model:'local-model', usage:{}}];
  nodes.analyze.click(); await flush();
  assert.equal(requests[0].url, 'http://127.0.0.1:8765/api/analyze');
  assert.equal(requests[0].body.seed_id, 'seed');
  assert.equal(requests[0].body.events.length, 5);
  assert.equal(requests[0].body.description, 'Analyst context');
  assert.equal(requests[0].options.credentials, 'omit');
  assert.equal(nodes['page-events'].hidden, false, 'a completed analysis opens the event timeline');
  assert.equal(nodes['provider-help'].textContent, '', 'no key hint once Jev is configured');
  assert.match(nodes.timeline.textContent, /Jev 88%/);
  assert.match(nodes.timeline.textContent, /Seed · 100%/);
  assert.match(nodes.timeline.textContent, /Same process/);
  assert.match(nodes.count.textContent, /^3 linked of 5 source events$/);
  // Without a narrative every results tab says plainly that it shows Jev results only.
  for (const id of ['timeline-banner', 'chain-banner', 'table-banner']) {
    assert.equal(nodes[id].hidden, false);
    assert.match(nodes[id].textContent, /Jev results only · no AI enrichment/);
  }
  // The execution chain is built from Jev results alone until a narrative is drafted.
  assert.match(nodes.chain.textContent, /Process chain from Jev results/);
  assert.match(nodes.chain.textContent, /stage.exe/);
  assert.match(nodes['chain-source'].textContent, /no AI/);
  assert.equal(nodes['chain-toggle'].hidden, true);
  assert.match(nodes.findings.textContent, /Model jev-1.13.0/);
  assert.match(nodes.findings.textContent, /4 candidates evaluated/);
  assert.match(nodes.findings.textContent, /300 input \/ 40 output tokens/);
  assert.match(nodes.findings.textContent, /Fresh run/);
  assert.doesNotMatch(nodes.findings.textContent, /\/srv\/|\.local-runs|telemetry_file|resumed_from/);
  assert.equal(nodes['table-body'].children.length, 3, 'seed, related candidate and same-entity file evidence only');
  assert.doesNotMatch(nodes['table-body'].textContent, /unrelated|notepad.exe|rundll32.exe/);
  assert.match(nodes['table-body'].textContent, /88%/);
  assert.match(nodes['table-body'].textContent, /Seed · 100%/);
  assert.match(nodes['table-body'].textContent, /Same process/);
  assert.match(nodes['table-summary'].textContent, /1 related/);
  assert.doesNotMatch(nodes['table-body'].textContent, /Unassessed/);
  assert.match(nodes['table-body'].textContent, /Same process as seed/);
  assert.match(nodes['table-guidance'].textContent, /Jev assessed/);
  assert.doesNotMatch(nodes.timeline.textContent + nodes['table-body'].textContent, /Reused from earlier run/, 'new answers carry no reuse marker');
  if (process.env.POC_NO_OPENROUTER) {
    assert.equal(nodes.narrate.disabled, true);
    assert.match(nodes['provider-status'].textContent, /OpenRouter key missing/);
    assert.match(nodes['table-body'].textContent, /Jev basis: lineage/);
    console.log('Missing-key gate passed: Jev assessments visible, DeepSeek draft unavailable.');
    return;
  }
  assert.equal(nodes.narrate.disabled, false);
  assert.match(nodes['table-body'].textContent, /Jev basis: lineage/);
  assert.match(nodes['model-name'].textContent, /deepseek\/deepseek-v4.1-flash/);
  assert.match(nodes['provider-status'].textContent, /OpenRouter ready/);
  nodes.narrate.click(); await flush();
  assert.equal(requests[1].url, 'http://127.0.0.1:8765/api/narrate');
  assert.deepEqual(Object.keys(requests[1].body), ['analysis_id', 'model']);
  assert.equal(requests[1].body.model, 'deepseek/deepseek-v4.1-flash', 'the default narrative model is shown and sent');
  assert.equal(requests[1].body.analysis_id, 'analysis-1');
  assert.match(nodes.narrative.textContent, /Evidence IDs: seed, child/);
  assert.match(nodes['table-body'].textContent, /Child execution/);
  assert.match(nodes['table-body'].textContent, /Observed process start/);
  assert.match(nodes['table-body'].textContent, /88%/, 'OpenRouter draft does not replace Jev probability');
  assert.match(nodes['table-body'].textContent, /Execution · TA0002/);
  assert.match(nodes['table-body'].textContent, /T1059/);
  for (const id of ['timeline-banner', 'chain-banner', 'table-banner']) assert.match(nodes[id].textContent, /AI-enriched draft.*local-model/);
  assert.match(nodes.timeline.textContent, /AIChild execution: Observed process start/);
  // The drafted Markdown chain opens in its own tab, rendered (list and table), with the Jev-only version one click away.
  assert.equal(nodes['page-chain'].hidden, false);
  assert.match(nodes['chain-source'].textContent, /AI draft · local-model/);
  assert.match(nodes.chain.textContent, /ATT&CK summary/);
  assert.ok(nodes.chain.children.some(child => child.className === 'md-table'));
  assert.ok(nodes.chain.children.some(child => child.tagName === 'ul'));
  nodes['chain-toggle'].click();
  assert.match(nodes.chain.textContent, /Process chain from Jev results/);
  nodes['chain-toggle'].click();
  assert.match(nodes.chain.textContent, /ATT&CK summary/);
  assert.equal(nodes.narrative.children[1].children[3].children[1].href, '#event-2');
  assert.equal(nodes.narrative.children[1].children[3].children[3].href, '#event-0');
  answers = [{httpStatus:502, error:'OpenRouter returned invalid or truncated JSON after retry'}];
  nodes.narrate.click(); await flush();
  assert.match(nodes.status.textContent, /OpenRouter returned invalid or truncated JSON after retry/);
  nodes.description.value = 'Changed context'; nodes.description.fire('input');
  assert.equal(nodes.narrate.disabled, true);
  assert.equal(nodes.timeline.children.filter(child => child.className === 'event').length, 0, 'changing analyst context clears linked timeline');
  nodes.backend.value = 'http://127.0.0.1:8766';
  nodes.analyze.click(); await flush();
  assert.match(nodes.status.textContent, /same origin/);
  assert.equal(requests.length, 3);
  nodes.backend.value = 'http://127.0.0.1:8765';
  answers = [{analysis_id:'analysis-2', decisions:[{id:'missing', related:true}], summary:{}}];
  nodes.analyze.click(); await flush();
  assert.match(nodes.status.textContent, /unknown event decision/);
  assert.equal(nodes.narrate.disabled, true);
  // Resume after a provider failure: only offered when the server reports a saved resume point.
  const before = requests.length;
  answers = [{httpStatus:502, body:{error:'TypeSafe returned HTTP 520 after 3 attempts; retry later.', resume_available:true, reusable_answers:2}}];
  nodes.analyze.click(); await flush();
  assert.match(nodes.status.textContent, /HTTP 520 after 3 attempts/);
  assert.equal(nodes.resume.hidden, false);
  assert.match(nodes.resume.textContent, /2 answered calls reused/);
  assert.equal('resume' in requests[before].body, false, 'a fresh Analyze never asks to resume');
  assert.equal('fresh' in requests[before].body, false, 'no fresh flag without a Resume offer');
  answers = [{networkError:true}];
  nodes.resume.click(); await flush();
  assert.match(nodes.status.textContent, /Analysis failed: offline/);
  assert.equal(nodes.resume.hidden, false, 'a lost resume response keeps the resume offer (the server saved its successor)');
  assert.equal(requests[before + 1].body.resume, true);
  answers = [{httpStatus:502}];
  nodes.resume.click(); await flush();
  assert.equal(nodes.resume.hidden, false, 'a proxy error without a server reply keeps the resume offer');
  answers = [{analysis_id:'analysis-3', decisions:[{id:'seed', related:true, probability:1}, {id:'child', related:true, probability:.88, reason:'lineage', reused:{answered_utc:'2026-09-25T10:15:00Z'}}], summary:{reused_answers:2, resumed:true}}];
  nodes.resume.click(); await flush();
  assert.equal(requests[before + 3].url, 'http://127.0.0.1:8765/api/analyze');
  assert.equal(requests[before + 3].body.resume, true);
  assert.equal(requests[before + 3].body.seed_id, 'seed');
  assert.equal(requests[before + 3].body.events.length, 5);
  assert.equal(nodes.resume.hidden, true);
  assert.match(nodes.status.textContent, /after resume \(2 answers reused\)/);
  assert.match(nodes.findings.textContent, /2 answers reused · Resumed run/);
  assert.match(nodes.timeline.textContent, /Jev 88%/);
  // Decisions whose Jev answer came from the earlier run carry a quiet marker with the original answer time.
  const eventFor = anchor => nodes.timeline.children.find(article => article.id === anchor);
  const childEvent = eventFor('event-2');
  assert.ok(childEvent.children[1].children[0].children.some(tag => tag.className === 'pill reused' && tag.textContent === 'Reused from earlier run · answered 2026-09-25T10:15:00Z'));
  assert.doesNotMatch(eventFor('event-0').textContent, /Reused from earlier run/, 'the analyst-confirmed seed is never marked reused');
  const tableRow = id => nodes['table-body'].children.find(tr => tr.sourceEventId === id);
  assert.ok(tableRow('child').children[3].children.some(span => span.className === 'row-origin reused' && span.textContent === 'Reused from earlier run · answered 2026-09-25T10:15:00Z'));
  assert.doesNotMatch(tableRow('seed').textContent, /Reused from earlier run/);
  assert.equal(nodes['table-body'].children.filter(tr => /Reused from earlier run/.test(tr.textContent)).length, 1, 'entity-linked context rows are not marked reused');
  answers = [{httpStatus:502, body:{error:'TypeSafe could not be reached or timed out; retry later.', resume_available:true, reusable_answers:1}}];
  nodes.analyze.click(); await flush();
  assert.equal(nodes.resume.hidden, false);
  nodes.description.value = 'Different context'; nodes.description.fire('input');
  assert.equal(nodes.resume.hidden, true, 'changing inputs withdraws the resume offer');
  nodes.resume.click(); await flush();
  assert.equal(requests.length, before + 5, 'no request without a resume offer');
  answers = [{httpStatus:400, body:{error:'Input or evidence error.'}}];
  nodes.analyze.click(); await flush();
  assert.equal(nodes.resume.hidden, true, 'no resume offer without a server resume point');
  // After a restart (or reload), Analyze finds the saved interrupted run and offers it without calling Jev.
  answers = [{httpStatus:409, body:{error:'An earlier interrupted run for these exact inputs saved 3 answered Jev calls. Resume to reuse them, or Analyze again to start fresh.', resume_available:true, reusable_answers:3}}];
  nodes.analyze.click(); await flush();
  assert.equal(nodes.resume.hidden, false);
  assert.match(nodes.resume.textContent, /3 answered calls reused/);
  assert.match(nodes.status.textContent, /^An earlier interrupted run/, 'saved progress is not reported as a failure');
  answers = [{httpStatus:409, body:{error:'No saved resume point for these exact inputs; run a fresh Jev analysis.'}}];
  nodes.resume.click(); await flush();
  assert.equal(requests[before + 7].body.resume, true);
  assert.equal(nodes.resume.hidden, true, 'a 409 without a saved resume point withdraws the offer');
  answers = [{httpStatus:409, body:{error:'Saved progress', resume_available:true, reusable_answers:3}}];
  nodes.analyze.click(); await flush();
  answers = [{analysis_id:'analysis-4', decisions:[{id:'child', related:true, probability:.9, reason:'lineage'}], summary:{}}];
  nodes.analyze.click(); await flush();
  assert.doesNotMatch(nodes.timeline.textContent + nodes['table-body'].textContent, /Reused from earlier run/, 'a fresh run clears reuse markers');
  assert.equal(requests[before + 9].body.fresh, true, 'Analyze while Resume is offered deliberately starts fresh');
  assert.equal('resume' in requests[before + 9].body, false);
  assert.equal(nodes.resume.hidden, true);
  answers = [{analysis_id:'analysis-5', decisions:[{id:'child', related:true, probability:.9, reused:'/private/run'}], summary:{}}];
  nodes.analyze.click(); await flush();
  assert.match(nodes.status.textContent, /invalid, duplicate, or unknown event decision/, 'a malformed reuse marker is rejected');
  const ecs = {events:[{_id:'ecs-1', _source:{'@timestamp':'2026-09-21T18:00:00Z', event:{category:['process'], action:'start'}, process:{name:'<img src=x onerror=alert(1)>', entity_id:'entity-1', parent:{entity_id:'parent-1'}}}}]};
  await nodes.file.fire('change', {target:{files:[{size:JSON.stringify(ecs).length, name:'ecs.json', text:async () => JSON.stringify(ecs)}]}});
  await flush();
  assert.equal(nodes.seed.value, 'ecs-1');
  assert.match(nodes.seed.options[0].textContent, /<img src=x onerror=alert\(1\)>/);
  assert.equal(nodes.timeline.children.filter(child => child.className === 'event').length, 0, 'unscored ECS import is not an incident timeline');
  assert.equal(requests.length, before + 11, 'import is offline');
  const fieldsOnly = [{_id:'fields-1', fields:{'@timestamp':['2026-09-21T18:00:01Z'], 'event.category':['process'], 'event.type':['start'], 'event.action':['created-process'], 'process.name':['child.exe'], 'process.entity_id':['entity-2'], 'process.parent.entity_id':['entity-1'], 'host.name':['WS-01']}}];
  await nodes.file.fire('change', {target:{files:[{size:JSON.stringify(fieldsOnly).length, name:'fields.json', text:async () => JSON.stringify(fieldsOnly)}]}});
  await flush();
  assert.equal(nodes.seed.value, 'fields-1');
  assert.match(nodes.seed.options[0].textContent, /child.exe/);
  assert.match(nodes.seed.options[0].textContent, /2026-09-21T18:00:01Z/);
  await nodes.file.fire('change', {target:{files:[{size:3 * 1024 * 1024, name:'large.json'}]}});
  assert.match(nodes.status.textContent, /2 MiB limit/);
  if (process.env.POC_SAMPLE_JSON) {
    const data = fs.readFileSync(process.env.POC_SAMPLE_JSON);
    const file = {size:data.length, name:'local-export.json', text:async () => data.toString('utf8')};
    await nodes.file.fire('change', {target:{files:[file]}});
    await flush();
    const count = JSON.parse(data).length;
    assert.equal(nodes.source.textContent.includes(`${count} events`), true);
    assert.match(nodes.count.textContent, /^0 linked of \d+ source events$/);
    assert.equal(nodes.seed.disabled, false, 'fields-only export contains process starts');
    if (process.env.POC_RUN_DIR) assert.equal(nodes.seed.value, 'VvT8xKABOYkemEz9sgQR', 'prefer entity-identified duplicate 2.8.exe start over same-time record without entity ID');
    assert.doesNotMatch(nodes.source.textContent, /Time unavailable/);
    await nodes.drop.fire('drop', {preventDefault() {}, dataTransfer:{files:[file]}});
    await flush();
    assert.equal(nodes.source.textContent.includes(`${count} events`), true, 'drag-and-drop import matches file picker');
    console.log(`Local export UI check passed: ${count} events, timestamps and execution seed recognized.`);
    if (process.env.POC_RUN_DIR) {
      const run = process.env.POC_RUN_DIR;
      const decisions = JSON.parse(fs.readFileSync(path.join(run, 'decisions.json'), 'utf8'));
      const summary = JSON.parse(fs.readFileSync(path.join(run, 'summary.json'), 'utf8'));
      assert.deepEqual(nodes.seed.options.map(option => option.value).sort(), decisions.map(d => d.id).sort(), 'HTML and Python select the same execution event IDs');
      nodes.seed.value = summary.seed_id; nodes.seed.fire('change');
      nodes.description.value = 'Analyst-confirmed 2.8.exe execution';
      answers = [{analysis_id:'cli-replay', decisions, summary}];
      nodes.analyze.click(); await flush();
      assert.match(nodes['table-summary'].textContent, /10 Jev decisions/);
      assert.match(nodes['table-summary'].textContent, /1 related/);
      const byId = new Map(nodes['table-body'].children.map(tr => [tr.sourceEventId, tr]));
      for (const decision of decisions.slice(1)) {
        const shown = byId.get(decision.id);
        if (decision.related) {
          assert.ok(shown, `missing linked CLI decision ${decision.id}`);
          assert.match(shown.textContent, new RegExp(`${(decision.probability * 100).toFixed(0)}%`));
        } else assert.equal(shown, undefined, `below-threshold candidate ${decision.id} must not appear`);
      }
      const contextRows = nodes['table-body'].children.filter(tr => tr.textContent.includes('Same process'));
      assert.equal(contextRows.length, 19, 'same-host, same-entity non-execution evidence must be linked as context');
      assert.equal(nodes['table-body'].children.length, 21, 'only 2 process starts and 19 linked context events in incident timeline');
      assert.match(nodes['table-body'].textContent, /UserInitMprLogonScript/, 'registry evidence survives Elasticsearch fields projection');
      assert.match(nodes['table-body'].textContent, /sihost.exe/, 'remote-thread target survives Elasticsearch fields projection');
      assert.doesNotMatch(nodes.timeline.textContent, /\[object Object\]/, 'events whose user has no name show no placeholder');
      assert.ok(nodes['table-body'].children.every(tr => tr.children.length === 11));
      assert.match(nodes['table-summary'].textContent, /19 entity-linked context/);
      console.log('CLI replay comparison passed: all candidate probabilities and 19 same-entity context events mapped without invented scores.');
    }
  }
  console.log('UI flow passed: offline preview/import, ECS fields, size limit, explicit requests, analysis-ID-only narration, evidence and origin checks.');
})().catch(e => {console.error(e); process.exitCode = 1;});
