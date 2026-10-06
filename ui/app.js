// The Jevline website: load any log files, choose the confirmed starting point, and let Jev link the
// incident. The engine runs in a Web Worker in this browser (engine/web-worker.js, built from engine/src);
// each Jev request goes through this site's relay (api/jev.js). An OpenRouter narrative is optional.
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const View = globalThis.JevView;
  const PAGES = ['setup', 'incident', 'events', 'chain', 'table'];
  const JEV_ENDPOINT = document.body?.dataset?.jevEndpoint || 'api/jev';
  const KEY_STORE = 'jevline.keys', MODEL_STORE = 'jevline.model', NOTE_STORE = 'jevline.privacyDismissed', SCHEMA_STORE = 'jevline.schemas';
  const EXAMPLE_CONTEXT = 'Analyst-confirmed 2.8.exe execution on CLA-WS-214.';
  const MAX_ROWS = 3000;  // Rows drawn per tab; the downloaded report always has every row.
  const state = {worker: null, generation: 0, busy: false, summary: null, seeds: [], report: null, requests: null, exampleLoaded: false,
    keys: {jev: '', openrouter: ''}, jevMode: 'demo', drafts: new Map(), chain: '', draftModel: '', chainJevView: false, chainMarkdown: ''};

  const text = x => x === undefined || x === null || x === '' ? '—' : String(x);
  const plural = (n, one, many = `${one}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;
  function element(tag, cls, value) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (value !== undefined) node.textContent = text(value);
    return node;
  }
  function setStatus(message, error = false) {
    $('status').textContent = message;
    $('status').classList.toggle('error', error);
  }
  function page(name) {
    for (const id of PAGES) {
      $(`page-${id}`).hidden = id !== name;
      $(`nav-${id}`).setAttribute('aria-selected', String(id === name));
    }
    if (location.hash.slice(1) !== name) history.replaceState(null, '', `#${name}`);
  }

  // ---- Keys and the privacy notice (kept in this browser only) -----------------------------------
  function renderKeys() {
    const demo = state.jevMode === 'demo';
    $('jev-key-field').hidden = demo;
    const jev = demo ? 'This site\'s free key' : state.keys.jev ? 'TypeSafe key entered' : 'TypeSafe key needed to analyze';
    $('key-status').textContent = `${jev} · ${state.keys.openrouter ? 'OpenRouter key entered' : 'OpenRouter key optional'}`;
    renderButtons();
  }
  function saveKeys() {
    try {
      if ($('remember-keys').checked && (state.keys.jev || state.keys.openrouter)) localStorage.setItem(KEY_STORE, JSON.stringify(state.keys));
      else localStorage.removeItem(KEY_STORE);
    } catch { /* Storage unavailable: keys stay in this tab's memory only. */ }
  }
  function setupKeys() {
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(KEY_STORE) || 'null'); } catch { saved = null; }
    if (saved && typeof saved === 'object') {
      state.keys = {jev: typeof saved.jev === 'string' ? saved.jev : '', openrouter: typeof saved.openrouter === 'string' ? saved.openrouter : ''};
      $('remember-keys').checked = true;
    }
    state.jevMode = state.keys.jev ? 'own' : 'demo';
    $('mode-demo').checked = state.jevMode === 'demo';
    $('mode-own').checked = state.jevMode === 'own';
    for (const id of ['mode-demo', 'mode-own']) $(id).addEventListener('change', () => { state.jevMode = $('mode-own').checked ? 'own' : 'demo'; renderKeys(); });
    $('jev-key').value = state.keys.jev;
    $('openrouter-key').value = state.keys.openrouter;
    for (const [id, name] of [['jev-key', 'jev'], ['openrouter-key', 'openrouter']]) {
      $(id).addEventListener('input', () => { state.keys[name] = $(id).value.trim(); saveKeys(); renderKeys(); });
    }
    $('remember-keys').addEventListener('change', saveKeys);
    $('forget-keys').addEventListener('click', () => {
      state.keys = {jev: '', openrouter: ''};
      $('jev-key').value = ''; $('openrouter-key').value = ''; $('remember-keys').checked = false;
      saveKeys(); renderKeys();
      setStatus('Keys removed from this page and this browser.');
    });
    let model = '';
    try { model = localStorage.getItem(MODEL_STORE) || ''; } catch { model = ''; }
    $('narrative-model').value = View.MODEL_ID.test(model) ? model : View.NARRATIVE_MODEL;
    $('narrative-model').addEventListener('input', () => {
      try { narrativeModel() === View.NARRATIVE_MODEL ? localStorage.removeItem(MODEL_STORE) : localStorage.setItem(MODEL_STORE, narrativeModel()); } catch { /* Not remembered. */ }
    });
    renderKeys();
  }
  const narrativeModel = () => $('narrative-model').value.trim() || View.NARRATIVE_MODEL;
  function setupPrivacyNote() {
    const show = visible => {
      $('privacy-note').hidden = !visible;
      $('privacy-show').hidden = visible;
      try { visible ? localStorage.removeItem(NOTE_STORE) : localStorage.setItem(NOTE_STORE, '1'); } catch { /* Not remembered. */ }
    };
    let dismissed = false;
    try { dismissed = localStorage.getItem(NOTE_STORE) === '1'; } catch { dismissed = false; }
    show(!dismissed);
    $('privacy-dismiss').addEventListener('click', () => show(false));
    $('privacy-show').addEventListener('click', () => { show(true); page('setup'); });
  }
  // Schema mappings Jev learned for log formats this browser has seen: field names and roles, no data.
  function savedMappings() {
    try { const list = JSON.parse(localStorage.getItem(SCHEMA_STORE) || '[]'); return Array.isArray(list) ? list : []; } catch { return []; }
  }
  function saveMapping(mapping) {
    try { localStorage.setItem(SCHEMA_STORE, JSON.stringify([...savedMappings().filter(m => m.fingerprint !== mapping.fingerprint), mapping].slice(-300))); }
    catch { /* Not remembered: it is learned again next time. */ }
  }

  // ---- The engine thread ---------------------------------------------------------------------------
  const access = () => ({endpoint: new URL(JEV_ENDPOINT, location.href).href, ...(state.jevMode === 'own' && state.keys.jev ? {key: state.keys.jev} : {})});
  function engine() {
    if (state.worker) return state.worker;
    const worker = new Worker('engine/web-worker.js', {type: 'module'});
    const generation = state.generation;
    worker.onmessage = event => { if (generation === state.generation) receive(event.data); };
    worker.onerror = event => { if (generation === state.generation) fail(`The engine stopped: ${event.message || 'it could not start in this browser'}`); };
    state.worker = worker;
    return worker;
  }
  const mb = bytes => `${(bytes / 1048576).toLocaleString('en-US', {maximumFractionDigits: bytes < 10485760 ? 1 : 0})} MB`;
  function receive(message) {
    switch (message.type) {
      case 'progress':
        if (message.stage === 'read') setStatus(`${message.pass === 2 ? 'Applying learned schemas to' : 'Reading'} ${message.file}: ${mb(message.bytes)} of ${mb(message.size)}…`);
        else if (message.stage === 'learn') setStatus(message.message);
        else if (message.stage === 'round') setStatus(`Round ${message.round}: asking Jev about ${plural(message.questions, 'candidate')}…`);
        else if (message.stage === 'ask') setStatus(`Round ${message.round}: ${plural(message.answered, 'Jev answer')} so far…`);
        break;
      case 'mapping': saveMapping(message.mapping); break;
      case 'loaded': loaded(message.summary, message.seeds); break;
      case 'report': finished(message.report, message.requests); break;
      case 'error': fail(message.during === 'load' ? `Reading failed: ${message.message}` : `Analysis failed: ${message.message}`, message.during, message.answers); break;
    }
  }
  function fail(message, during, answers = 0) {
    state.busy = false;
    setStatus(during === 'analyze' && answers ? `${message} Analyze again to continue: the ${plural(answers, 'answer')} already received are reused.` : message, true);
    renderButtons();
  }

  // ---- Loading -----------------------------------------------------------------------------------
  function resetResults() {
    state.report = null; state.requests = null; state.drafts = new Map(); state.chain = ''; state.draftModel = ''; state.chainJevView = false;
    $('findings').replaceChildren(element('div', 'empty', 'No Jev decisions yet.'));
    $('narrative').textContent = 'Narrative is optional and must be requested separately.';
    renderAll();
  }
  function load(files, label, example = false) {
    if (!files.length) return;
    state.generation++;
    state.worker?.terminate();
    state.worker = null;
    state.summary = null; state.seeds = []; state.exampleLoaded = example; state.busy = true;
    resetResults();
    $('seed').replaceChildren(element('option', '', 'Reading…'));
    $('seed').disabled = $('seed-filter').disabled = $('seed-other').disabled = true;
    $('loaded-summary').hidden = true;
    $('source').textContent = label;
    const context = $('description').value.trim();
    if (example && (!context || context === EXAMPLE_CONTEXT)) $('description').value = EXAMPLE_CONTEXT;
    setStatus(`Reading ${plural(files.length, 'file')} in this browser…`);
    engine().postMessage({type: 'load', files, access: access(), mappings: savedMappings()});
    renderButtons();
  }
  function loaded(summary, seeds) {
    state.busy = false;
    state.summary = summary;
    state.seeds = seeds;
    const entities = Object.entries(summary.entities).map(([type, n]) => plural(n, {user: 'account', ip: 'address', domain: 'domain', host: 'host'}[type] || type,
      {user: 'accounts', ip: 'addresses', domain: 'domains', host: 'hosts'}[type])).join(', ');
    const box = $('loaded-summary');
    box.replaceChildren();
    box.append(element('strong', '', `${plural(summary.records, 'record')} → ${plural(summary.events, 'event')}`),
      element('span', '', ` · ${plural(summary.processes, 'process', 'processes')}${entities ? `, ${entities}` : ''} · ${plural(summary.links, 'link')} · read and linked in ${((summary.timings.read_normalize + summary.timings.identify_processes + summary.timings.build_links + (summary.timings.deduplicate || 0)) / 1000).toFixed(2)} s`));
    const learned = summary.schemas.filter(s => s.learned !== 'not learned' && s.kind !== 'other' && s.kind !== 'unknown');
    if (summary.schemas.length) {
      const missing = summary.schemas.filter(s => s.learned === 'not learned').length;
      box.append(element('span', missing ? 'warn' : 'small', missing
        ? `${plural(missing, 'event type')} from a log schema that couldn't be learned. Check the Jev access below and load the files again: Jev learns each event type once, with no mapping from you.`
        : ` Learned ${plural(learned.length, 'event type')} from an unknown schema with Jev${summary.schemas.some(s => s.learned === 'cache') ? ' (some remembered from earlier)' : ''}.`));
    }
    box.hidden = false;
    $('seed-filter').disabled = $('seed-other').disabled = false;
    $('seed-filter').value = '';
    renderSeeds();
    if (state.exampleLoaded) {
      const first = state.seeds.find(s => s.name.toLowerCase() === '2.8.exe');
      if (first) $('seed').value = `key:${first.key}`;
    }
    setStatus(state.seeds.length ? `Loaded; nothing was sent. Choose the starting point${state.exampleLoaded ? ' (2.8.exe is selected)' : ''} and analyze.`
      : 'Loaded; no process starts found. Use "Or another starting point" (ip:, domain:, user: or host:).');
    renderButtons();
  }
  function renderSeeds() {
    const query = $('seed-filter').value.trim().toLowerCase(), select = $('seed'), current = select.value;
    const matches = state.seeds.filter(s => !query || [s.name, s.pid, s.host, s.user, s.command_line, s.event_id].some(v => v !== undefined && String(v).toLowerCase().includes(query)));
    select.replaceChildren();
    for (const s of matches.slice(0, 500)) {
      const option = element('option', '', `${s.name} · PID ${text(s.pid)} · ${s.host} · ${text(s.start)}${s.user ? ` · ${s.user}` : ''}`);
      option.value = `key:${s.key}`;
      option.title = s.command_line || s.name;
      select.append(option);
    }
    if (!matches.length) select.append(element('option', '', state.seeds.length ? 'No process start matches' : 'No process starts found'));
    if (matches.length > 500) select.append(Object.assign(element('option', '', `… ${plural(matches.length - 500, 'more match', 'more matches')}: refine the search`), {disabled: true}));
    if ([...select.options].some(o => o.value === current)) select.value = current;
    select.disabled = !matches.length;
  }
  const chosenSeed = () => $('seed-other').value.trim() || ($('seed').value.startsWith('key:') ? $('seed').value : '');
  function renderButtons() {
    const ready = !!state.summary && !state.busy;
    $('analyze').disabled = !ready || !chosenSeed();
    $('narrate').disabled = state.busy || !state.report || !state.keys.openrouter;
    $('download').hidden = $('download-requests').hidden = !state.report;
  }

  // ---- Analyzing -----------------------------------------------------------------------------------
  function analyze() {
    const seed = chosenSeed(), context = $('description').value.trim();
    if (!state.summary || !seed) { setStatus('Load logs and choose the starting point first.', true); return; }
    if (!context) { setStatus('Add a sentence of analyst context: why the starting point is confirmed malicious.', true); return; }
    if (state.jevMode === 'own' && !state.keys.jev) { setStatus('Enter your TypeSafe API key first; nothing was sent.', true); return; }
    resetResults();
    state.busy = true;
    renderButtons();
    setStatus('Asking Jev from this browser, through this site\'s relay…');
    engine().postMessage({type: 'analyze', seed, context, access: access()});
  }
  function finished(report, requests) {
    state.busy = false;
    state.report = report;
    state.requests = requests;
    renderAll();
    renderFindings();
    const members = View.members(report).size;
    setStatus(`Done: ${plural(members, 'member')} in the incident. Jev scores are relatedness, not maliciousness; review every row.`);
    renderButtons();
    page('incident');
  }
  function renderFindings() {
    const r = state.report, j = r.jev, target = $('findings');
    target.replaceChildren();
    const all = View.members(r);
    let processes = 0;
    for (const {row} of all.values()) if (row.type === 'process') processes++;
    const t = r.timings_ms, local = (t.read_normalize + t.identify_processes + t.build_links + (t.deduplicate || 0)) / 1000;
    target.append(element('p', 'summary', `${plural(all.size, 'member')}: ${plural(processes, 'process', 'processes')} and ${plural(all.size - processes, 'account, host, address or domain', 'accounts, hosts, addresses or domains')}` +
      ` · ${plural(j.requests, 'Jev request')} over ${plural(j.rounds, 'round')}${j.answered_from_cache ? ` (${j.answered_from_cache} reused)` : ''} · ` +
      `${plural(j.input_tokens, 'input token')} · read and linked in ${local.toFixed(2)} s, Jev ${(t.investigate / 1000).toFixed(1)} s`));
    target.append(element('p', 'note', `Starting point confirmed by you; every other member was linked by Jev at ${j.threshold} or above. ${j.near_threshold ? `${plural(j.near_threshold, 'answer')} within ±${j.margin} of the threshold are marked review.` : ''}`));
    if (j.stopped) target.append(element('p', 'note', `Stopped early: ${j.stopped}.`));
    target.append(element('p', 'note', `${plural(r.timeline.length, 'timeline row')} from ${plural(r.counts.timeline_events, 'event')}: repeats of the same activity are folded.`));
  }

  // ---- Results ----------------------------------------------------------------------------------
  function renderAll() { renderIncident(); renderTimeline(); renderTable(); renderChain(); renderEnrichment(); }
  const memberLabel = row => row.type === 'process' ? `${row.name || '?'} (${text(row.pid)})` : `${row.name} (${row.type === 'user' ? 'account' : row.type})`;
  function sinceSeed(row) {
    const origin = Date.parse(state.report.seed.start || state.report.seed.first_seen || '');
    const at = Date.parse(row.type === 'process' ? row.start : row.joined_incident || row.first_seen);
    if (!Number.isFinite(origin) || !Number.isFinite(at)) return 'before logs';
    const total = Math.trunc((at - origin) / 1000), s = Math.abs(total), days = Math.floor(s / 86400);
    return `${total < 0 ? '-' : '+'}${days ? `${days}d ` : ''}${[Math.floor(s / 3600) % 24, Math.floor(s / 60) % 60, s % 60].map(x => String(x).padStart(2, '0')).join(':')}`;
  }
  function renderIncident() {
    const body = $('incident-body');
    body.replaceChildren();
    const r = state.report;
    $('incident-empty').hidden = !!r;
    if (!r) { $('incident-count').textContent = 'Nothing linked yet'; return; }
    const total = View.members(r).size;
    $('incident-count').textContent = `${plural(total, 'member')}${r.incident.length < total ? `, ${plural(r.incident.length, 'row')} (identical repeats folded)` : ''}`;
    for (const row of r.incident) {
      const seed = row.key === r.seed.key;
      const tr = element('tr', `origin-${seed ? 'seed' : 'related'}`);
      const what = element('td');
      what.append(element('span', 'member-name', memberLabel(row)));
      if (row.repeats) what.append(element('span', 'repeat', `×${row.repeats.count}`));
      const meta = row.type === 'process' ? [row.host !== r.seed.host ? row.host : '', row.user, row.command_line].filter(Boolean).join(' · ') : '';
      if (meta) what.append(element('span', 'member-meta', meta.length > 220 ? `${meta.slice(0, 220)}…` : meta));
      const via = element('td', '', seed ? 'Confirmed starting point' : (row.joined?.via || []).slice(0, 3).map(v => `${v.link.replaceAll('_', ' ')} from ${v.from}`).join('; ') +
        ((row.joined?.via || []).length > 3 ? ` +${row.joined.via.length - 3}` : ''));
      const score = element('td');
      if (seed) score.append(element('span', 'pill seed', 'Seed'));
      else {
        score.append(element('span', 'pill related', `Jev ${Math.round(row.joined.probability * 100)}%`));
        if (row.joined.review) score.append(element('span', 'pill review', 'review'));
      }
      tr.append(element('td', '', sinceSeed(row)), what, via, score);
      body.append(tr);
    }
  }
  function renderTimeline() {
    const target = $('timeline');
    target.replaceChildren();
    const r = state.report;
    if (!r) {
      $('count').textContent = '0 rows';
      target.append(element('div', 'empty', 'No linked events yet. Load logs, choose the starting point and analyze with Jev to build this sequence.'));
      return;
    }
    $('count').textContent = `${plural(r.timeline.length, 'row')} from ${plural(r.counts.timeline_events, 'event')}`;
    const memberMap = View.members(r);
    r.timeline.slice(0, MAX_ROWS).forEach((row, index) => {
      const origin = View.originOf(row, r, memberMap), draft = state.drafts.get(row.event_id);
      const article = element('article', `event ${origin.kind}`);
      article.id = `event-${index}`;
      const line = element('div', 'event-line');
      line.append(element('span', `dot ${origin.kind}`), element('strong', 'event-name', row.process || row.entity || '?'), element('span', `pill ${origin.kind}`, origin.score),
        element('span', 'event-action', View.kindLabel(row.kind)));
      if (origin.review) line.append(element('span', 'pill review', 'review'));
      const body = element('div', 'event-body');
      body.append(line);
      if (draft) {
        const ai = element('p', 'ai-line');
        ai.append(element('span', 'ai-badge', 'AI'), element('span', '', `${draft.title}: ${draft.summary}`));
        body.append(ai);
        if (draft.tactic || draft.techniques.length) body.append(attackChips(draft));
      }
      if (row.detail) body.append(element('code', 'event-detail', row.detail));
      if (row.count) body.append(element('span', 'repeat-line', View.repeatText(row)));
      body.append(element('p', 'event-meta', [row.host, row.pid !== undefined ? `PID ${row.pid}` : '', `${row.source} · event ${row.event_id}`, row.since_seed].filter(Boolean).join(' · ')));
      article.append(element('time', 'event-time', row.time || 'Time unavailable'), body);
      target.append(article);
    });
    if (r.timeline.length > MAX_ROWS) target.append(element('div', 'empty', `${plural(r.timeline.length - MAX_ROWS, 'more row')} in the downloaded report.`));
  }
  function attackChips(draft, withTactic = true) {
    const wrap = element('span', 'attack');
    if (withTactic && draft.tactic) wrap.append(element('span', 'chip tactic', draft.tactic_id ? `${draft.tactic} · ${draft.tactic_id}` : draft.tactic));
    for (const id of draft.techniques) {
      const link = element('a', 'chip technique', id);
      link.href = `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
      link.target = '_blank'; link.rel = 'noopener noreferrer';
      wrap.append(link);
    }
    return wrap;
  }
  function renderTable() {
    const target = $('table-body');
    target.replaceChildren();
    const r = state.report, summary = $('table-summary');
    summary.replaceChildren();
    if (!r) {
      $('table-count').textContent = '0 rows';
      $('table-guidance').textContent = state.summary ? 'Choose the starting point on Source & analysis, then analyze with Jev.' : 'Load logs to begin.';
      return;
    }
    const memberMap = View.members(r);
    $('table-count').textContent = plural(r.timeline.length, 'row');
    for (const label of [`${plural(r.counts.records, 'record')}`, `${plural(r.counts.events, 'event')}`, `${plural(r.jev.candidates_asked, 'Jev decision')}`,
      `${plural(memberMap.size, 'member')}`, `${plural(r.timeline.length, 'incident row')}`]) summary.append(element('span', 'metric', label));
    $('table-guidance').textContent = state.drafts.size ? `AI draft from ${state.draftModel}; verify every claim against the evidence.`
      : 'Rows come from Jev\'s decisions and exact matches. Request a narrative on Source & analysis for AI-drafted titles and ATT&CK mapping.';
    for (const row of r.timeline.slice(0, MAX_ROWS)) {
      const origin = View.originOf(row, r, memberMap), draft = state.drafts.get(row.event_id);
      const [indicator, type, pyramid] = View.indicatorFor(row);
      const tr = element('tr', `origin-${origin.kind}`);
      const phase = element('td');
      phase.append(draft?.tactic ? element('span', 'chip tactic', draft.tactic_id ? `${draft.tactic} · ${draft.tactic_id}` : draft.tactic) : element('span', 'chip phase', View.kindLabel(row.kind)));
      const title = element('td');
      title.append(element('span', 'row-title', draft ? draft.title : `${row.process || row.entity || '?'} · ${View.kindLabel(row.kind)}`), element('span', `pill ${origin.kind}`, origin.score));
      const description = element('td');
      description.append(element('span', '', draft ? draft.summary : `${row.detail || View.kindLabel(row.kind)}. ${origin.label}${origin.member && !origin.member.seed && origin.member.row.joined ? ` (joined through ${origin.member.row.joined.via.map(v => v.link.replaceAll('_', ' ')).join(', ')})` : ''}.`));
      if (draft) description.append(element('span', 'ai-badge inline', 'AI draft'));
      if (row.count) description.append(element('span', 'repeat-line', View.repeatText(row)));
      const ttp = element('td');
      if (draft?.techniques.length) ttp.append(attackChips(draft, false)); else ttp.append(element('span', 'muted', '—'));
      tr.append(element('td', 'mono', row.time || ''), element('td', '', row.host || ''), phase, title, description, element('td', '', row.process || ''), ttp,
        element('td', 'mono', row.kind === 'process_start' ? row.detail || '' : ''), element('td', 'mono', indicator), element('td', '', type), element('td', '', pyramid));
      target.append(tr);
    }
  }
  function renderEnrichment() {
    const ai = state.drafts.size > 0;
    for (const id of ['timeline-banner', 'chain-banner', 'table-banner']) {
      const banner = $(id);
      banner.hidden = !state.report;
      banner.className = `enrichment ${ai ? 'ai' : 'jev'}`;
      banner.replaceChildren(element('strong', '', ai ? 'AI-enriched draft' : 'Jev results only · no AI enrichment'),
        element('span', '', ai ? `Titles, summaries, ATT&CK tactics and techniques${state.chain ? ' and the execution chain' : ''} were drafted by ${state.draftModel} from these Jev results. Verify every claim against the evidence.`
          : 'Rows, scores and links come straight from Jev and exact matches. Request a narrative to add AI-drafted titles, ATT&CK mapping and an execution chain.'));
    }
  }
  function renderChain() {
    const jevOnly = state.report ? View.chainMarkdown(state.report) : '';
    const showAi = !!state.chain && !state.chainJevView;
    const markdown = showAi ? state.chain : jevOnly;
    state.chainMarkdown = markdown;
    $('chain-source').textContent = !markdown ? '' : showAi ? `AI draft · ${state.draftModel}` : 'From Jev results · no AI';
    $('chain-toggle').hidden = !state.chain;
    $('chain-toggle').textContent = showAi ? 'Show Jev-only chain' : 'Show AI draft';
    $('copy-chain').hidden = !markdown;
    if (!markdown) {
      $('chain').replaceChildren(element('div', 'empty', 'No execution chain yet. Analyze with Jev to build it; a narrative adds an AI-drafted version with ATT&CK mapping.'));
      return;
    }
    renderMarkdown($('chain'), markdown);
  }

  // Minimal, safe Markdown: headings, nested lists, tables, code, bold, rules and [evt:ID] citations.
  // Builds DOM nodes with textContent only, so drafted text can never become markup or script.
  function renderInline(parent, value) {
    const pattern = /(`[^`]+`|\*\*[^*]+\*\*|\[evt:[^\]\s]+\])/g;
    let last = 0, match;
    while ((match = pattern.exec(value))) {
      if (match.index > last) parent.append(element('span', '', value.slice(last, match.index)));
      const token = match[0];
      if (token[0] === '`') parent.append(element('code', '', token.slice(1, -1)));
      else if (token.startsWith('**')) parent.append(element('strong', '', token.slice(2, -2)));
      else {
        const id = token.slice(5, -1), index = state.report ? state.report.timeline.findIndex(row => row.event_id === id) : -1;
        const link = element('a', 'evt-ref', id);
        link.href = `#event-${index}`;
        link.addEventListener('click', event => { event.preventDefault(); page('events'); document.getElementById(`event-${index}`)?.scrollIntoView({block: 'center'}); });
        parent.append(link);
      }
      last = pattern.lastIndex;
    }
    if (last < value.length) parent.append(element('span', '', value.slice(last)));
  }
  function renderMarkdown(target, markdown) {
    target.replaceChildren();
    const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
    const cells = line => line.trim().replace(/^\||\|$/g, '').split('|').map(cell => cell.trim());
    let stack = [], paragraph = null;
    const closeBlocks = () => { stack = []; paragraph = null; };
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) { closeBlocks(); continue; }
      if (line.trim().startsWith('```')) {
        closeBlocks();
        const code = [];
        while (++i < lines.length && !lines[i].trim().startsWith('```')) code.push(lines[i]);
        const pre = element('pre');
        pre.append(element('code', '', code.join('\n') || ' '));
        target.append(pre);
        continue;
      }
      const heading = /^(#{1,6})\s+(.*)$/.exec(line);
      if (heading) {
        closeBlocks();
        const node = element(heading[1].length === 1 ? 'h3' : heading[1].length === 2 ? 'h4' : 'h5');
        renderInline(node, heading[2]);
        target.append(node);
        continue;
      }
      if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { closeBlocks(); target.append(element('hr')); continue; }
      if (line.trim().startsWith('|') && i + 1 < lines.length && /^\s*\|?\s*:?-{3,}/.test(lines[i + 1])) {
        closeBlocks();
        const table = element('table'), head = element('thead'), body = element('tbody'), headRow = element('tr');
        for (const cell of cells(line)) { const th = element('th'); renderInline(th, cell); headRow.append(th); }
        head.append(headRow);
        i++;
        while (i + 1 < lines.length && lines[i + 1].trim().startsWith('|')) {
          const tr = element('tr');
          for (const cell of cells(lines[++i])) { const td = element('td'); renderInline(td, cell); tr.append(td); }
          body.append(tr);
        }
        table.append(head, body);
        const wrap = element('div', 'md-table');
        wrap.append(table);
        target.append(wrap);
        continue;
      }
      const item = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/.exec(line);
      if (item) {
        paragraph = null;
        const indent = item[1].replace(/\t/g, '    ').length;
        while (stack.length && indent < stack[stack.length - 1].indent) stack.pop();
        if (!stack.length || indent > stack[stack.length - 1].indent) {
          const list = element(/\d/.test(item[2]) ? 'ol' : 'ul');
          (stack.length && stack[stack.length - 1].last ? stack[stack.length - 1].last : target).append(list);
          stack.push({indent, list, last: null});
        }
        const li = element('li');
        renderInline(li, item[3]);
        stack[stack.length - 1].list.append(li);
        stack[stack.length - 1].last = li;
        continue;
      }
      if (stack.length && /^\s+/.test(line)) { renderInline(stack[stack.length - 1].last, ` ${line.trim()}`); continue; }
      stack = [];
      if (!paragraph) { paragraph = element('p'); target.append(paragraph); } else paragraph.append(element('span', '', ' '));
      renderInline(paragraph, line.trim());
    }
  }

  // ---- The optional narrative and downloads --------------------------------------------------------
  async function narrate() {
    if (!state.report || !state.keys.openrouter || state.busy) return;
    if (!View.MODEL_ID.test(narrativeModel())) { setStatus('Narrative model must be an OpenRouter model ID, for example deepseek/deepseek-v4.1-flash.', true); return; }
    const generation = state.generation, report = state.report;
    state.busy = true;
    renderButtons();
    setStatus(`Requesting a narrative from ${narrativeModel()}…`);
    try {
      const result = await View.narrate(report, state.keys.openrouter, {model: narrativeModel()});
      if (generation !== state.generation || report !== state.report) return;
      state.drafts = new Map(result.timeline.map(row => [row.event_id, row]));
      state.chain = result.execution_chain;
      state.draftModel = result.model;
      state.chainJevView = false;
      const target = $('narrative');
      target.replaceChildren(element('p', 'note', `Optional narrative · ${result.model} · analyst review required. Generated text is not an evidence source.`));
      for (const row of result.timeline) {
        const article = element('article', 'event');
        article.append(element('h3', '', row.title), element('p', '', row.summary));
        target.append(article);
      }
      renderAll();
      page(state.chain ? 'chain' : 'table');
      setStatus(`Narrative drafted by ${result.model}; verify every claim against the evidence.`);
    } catch (error) {
      if (generation === state.generation) setStatus(`Narrative failed: ${error.message}`, true);
    } finally {
      if (generation === state.generation) { state.busy = false; renderButtons(); }
    }
  }
  function save(name, content, type) {
    const url = URL.createObjectURL(new Blob([content], {type}));
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const stamp = () => new Date().toISOString().replace(/[:.]/g, '-');

  // ---- Wiring ----------------------------------------------------------------------------------------
  for (const id of PAGES) $(`nav-${id}`).addEventListener('click', () => page(id));
  addEventListener('hashchange', () => { const name = location.hash.slice(1); if (PAGES.includes(name)) page(name); });
  page(PAGES.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'setup');
  setupKeys();
  setupPrivacyNote();
  $('choose').addEventListener('click', () => $('file').click());
  $('file').addEventListener('change', event => { const files = [...event.target.files]; event.target.value = ''; load(files, files.map(f => f.name).join(', ')); });
  const drop = $('drop');
  drop.addEventListener('dragover', event => { event.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', event => {
    event.preventDefault();
    drop.classList.remove('over');
    const files = [...event.dataTransfer.files];
    load(files, files.map(f => f.name).join(', '));
  });
  $('preview').addEventListener('click', async () => {
    try {
      // Same-site cookies only: a Vercel preview behind its login needs them; the site sets none of its own.
      const response = await fetch('examples/malicious_events.json', {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) throw new Error('the bundled example is not available on this site');
      load([new File([await response.blob()], 'malicious_events.json', {type: 'application/json'})], 'Bundled lab example: 100 Sysmon and Security records from CLA-WS-214', true);
    } catch (error) { setStatus(`Example load failed: ${error.message}`, true); }
  });
  $('seed-filter').addEventListener('input', () => { renderSeeds(); renderButtons(); });
  for (const id of ['seed', 'seed-other', 'description']) $(id).addEventListener('input', renderButtons);
  $('analyze').addEventListener('click', analyze);
  $('narrate').addEventListener('click', narrate);
  $('download').addEventListener('click', () => state.report && save(`jevline-report-${stamp()}.json`, JSON.stringify(state.report, null, 1) + '\n', 'application/json'));
  $('download-requests').addEventListener('click', () => state.requests && save(`jevline-requests-${stamp()}.jsonl`,
    state.requests.map(r => JSON.stringify(r)).join('\n') + '\n', 'application/x-ndjson'));
  $('chain-toggle').addEventListener('click', () => { state.chainJevView = !state.chainJevView; renderChain(); });
  $('copy-chain').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(state.chainMarkdown); setStatus('Execution chain copied as Markdown.'); }
    catch { setStatus('Copy failed; select the text to copy it manually.', true); }
  });
  renderAll();
  renderButtons();
})();
