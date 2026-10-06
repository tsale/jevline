// Log file formats for the portal: JSON, NDJSON, CSV/TSV and plain text, one event per line.
// Port of parse_lines() in jev_incident.py, so a file gives the same events (and the same assigned
// IDs) in the browser and on the command line; tests/fixtures/formats_golden.json checks both.
(function (root) {
  'use strict';
  const FORMATS = ['auto', 'json', 'ndjson', 'csv', 'text'];
  const CSV_DELIMITERS = [',', '\t', ';', '|'];
  const CSV_HEADER = /^[A-Za-z_@][A-Za-z0-9_.@ -]{0,99}$/;
  const TEXT_TIME = /^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?/;
  const TEXT_PAIR = /(?:^|[ \t\f\v,;])([A-Za-z_@][A-Za-z0-9_.@-]*)=(?:"((?:[^"\\]|\\.)*)"|([^ \t\f\v,;]*))/g;
  const INTEGER_FIELDS = ['process.pid', 'process.parent.pid', 'destination.port', 'source.port'];
  // Column and key names of common Windows, Sysmon, Splunk and EDR exports (jev_incident.ALIASES).
  const ALIASES = new Map();
  const alias = (path, ...names) => { for (const name of names) ALIASES.set(name, path); };
  alias('@timestamp', '@timestamp', 'timestamp', 'time', 'utctime', 'timecreated', 'systemtime', 'eventtime',
    'datetime', 'dateandtime', 'date', 'timegenerated');
  alias('host.name', 'host', 'hostname', 'computer', 'computername', 'device', 'devicename', 'workstation');
  alias('user.name', 'user', 'username', 'accountname', 'subjectusername');
  alias('process.executable', 'image', 'newprocessname', 'processname', 'processpath', 'exe', 'executable');
  alias('process.command_line', 'commandline', 'cmdline', 'processcommandline', 'command');
  alias('process.pid', 'processid', 'pid', 'newprocessid');
  alias('process.entity_id', 'processguid', 'processentityid');
  alias('process.hash.sha256', 'sha256', 'processsha256');
  alias('process.parent.executable', 'parentimage', 'parentprocessname', 'parentprocesspath');
  alias('process.parent.command_line', 'parentcommandline', 'parentprocesscommandline');
  alias('process.parent.pid', 'parentprocessid', 'ppid', 'creatorprocessid');
  alias('process.parent.entity_id', 'parentprocessguid');
  alias('file.path', 'targetfilename', 'filepath', 'file');
  alias('destination.ip', 'destinationip', 'dstip', 'destip', 'destinationaddress');
  alias('destination.port', 'destinationport', 'dstport', 'destport');
  alias('destination.domain', 'destinationhostname', 'destinationhost', 'dsthost');
  alias('source.ip', 'sourceip', 'srcip');
  alias('source.port', 'sourceport', 'srcport');
  alias('dns.question.name', 'queryname', 'dnsquery');
  alias('registry.path', 'targetobject', 'registrypath', 'registrykey');
  alias('target.image', 'targetimage');
  alias('target.entity_id', 'targetprocessguid');
  alias('event.code', 'eventid', 'eventcode');
  alias('event.action', 'action', 'eventaction');
  alias('event.category', 'category', 'eventcategory');
  alias('event.type', 'eventtype');
  alias('winlog.channel', 'channel', 'logname', 'source');
  alias('event.provider', 'provider', 'providername', 'sourcename');
  alias('event.dataset', 'sourcetype', 'dataset');
  alias('message', 'message', 'msg');

  const isObj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
  const has = (obj, key) => isObj(obj) && Object.prototype.hasOwnProperty.call(obj, key);
  const get = (obj, key) => has(obj, key) ? obj[key] : null;
  const truthy = x => !(x === null || x === undefined || x === false || x === 0 || x === '' ||
    (Array.isArray(x) && !x.length) || (isObj(x) && !Object.keys(x).length));
  const pyStr = x => x === null || x === undefined ? 'None' : x === true ? 'True' : x === false ? 'False' : String(x);
  const blank = line => /^[ \t\r\f\v]*$/.test(line);
  // Own properties only, so a column named __proto__ is data like any other.
  const setOwn = (obj, key, value) => Object.defineProperty(obj, key, {value, writable: true, enumerable: true, configurable: true});

  // The event's own ID as compact() in jev_incident.py / ui/engine.js reads it ('' when it has none).
  function eventId(raw) {
    let src = raw;
    if (truthy(get(raw, '_source'))) src = raw._source;
    else if (isObj(get(raw, 'fields'))) {
      const value = raw.fields['event.id'];
      src = {event: {id: Array.isArray(value) ? (value.length ? value[0] : null) : value ?? null}};
    }
    const event = truthy(get(src, 'event')) ? src.event : {};
    for (const value of [get(raw, 'id'), get(raw, '_id'), get(src, 'id'), get(event, 'id')]) if (truthy(value)) return pyStr(value);
    return '';
  }

  // Set a dotted path; the first value for a field wins and never overwrites a parent.
  function put(record, path, value) {
    const keys = path.split('.');
    for (const key of keys.slice(0, -1)) {
      if (!has(record, key)) setOwn(record, key, {});
      else if (!isObj(record[key])) return;
      record = record[key];
    }
    const last = keys[keys.length - 1];
    if (!has(record, last)) setOwn(record, last, value);
  }

  const basename = path => { const parts = path.split(/[\\/]/).filter(Boolean); return parts.length ? parts[parts.length - 1] : path; };

  // One event from [name, text value] pairs of a CSV row or a key=value log line.
  function flatEvent(pairs) {
    const record = {};
    let hashes = null;
    for (let [name, value] of pairs) {
      if (value === '') continue;
      const key = name.toLowerCase().replace(/[ _-]/g, '');
      if (key === 'hashes' && hashes === null) hashes = value;
      const path = name.includes('.') || name === '@timestamp' ? name : ALIASES.has(key) ? ALIASES.get(key) : name;
      if (INTEGER_FIELDS.includes(path)) {
        if (/^[0-9]{1,15}$/.test(value)) value = Number(value);
        else if (/^0[xX][0-9a-fA-F]{1,12}$/.test(value)) value = parseInt(value.slice(2), 16);
      }
      put(record, path, value);
    }
    const process = get(record, 'process');
    if (isObj(process)) {
      if (typeof get(process, 'executable') === 'string') put(record, 'process.name', basename(process.executable));
      const parent = get(process, 'parent');
      if (isObj(parent) && typeof get(parent, 'executable') === 'string') put(record, 'process.parent.name', basename(parent.executable));
    }
    if (hashes !== null) {
      const match = /(?:^|,)[ \t]*SHA256=([0-9A-Fa-f]{64})/.exec(hashes);
      if (match) put(record, 'process.hash.sha256', match[1].toLowerCase());
    }
    // A Windows process creation (Security 4688, Sysmon 1) is a process start unless the row says otherwise.
    const event = get(record, 'event');
    if (isObj(event) && !has(event, 'category') && get(event, 'code') !== null) {
      const winlog = isObj(get(record, 'winlog')) ? record.winlog : {};
      const origin = [get(winlog, 'channel'), get(event, 'provider'), get(event, 'dataset')]
        .filter(x => typeof x === 'string').join(' ').toLowerCase();
      const code = pyStr(event.code);
      if (code === '4688' || (code === '1' && origin.includes('sysmon'))) {
        put(record, 'event.category', ['process']);
        put(record, 'event.type', ['start']);
      }
    }
    return record;
  }

  // Fields of one physical line; state carries an open quoted field into the next line.
  function csvSplit(text, delimiter, state = null) {
    let [fields, field, quoted, start] = state || [[], '', false, true];
    let i = 0;
    while (i < text.length) {
      if (quoted) {  // Up to the next quote: "" is a literal quote, a single one closes the field.
        const j = text.indexOf('"', i);
        if (j < 0) { field += text.slice(i); break; }
        field += text.slice(i, j);
        if (text[j + 1] === '"') { field += '"'; i = j + 2; } else { quoted = false; i = j + 1; }
      } else if (start && text[i] === '"') {  // Only a quote that opens a field starts quoting.
        quoted = true; start = false; i++;
      } else {  // Up to the next delimiter; any quote in between is literal.
        const j = text.indexOf(delimiter, i);
        field += text.slice(i, j < 0 ? text.length : j);
        if (j < 0) { start = false; break; }
        fields.push(field); field = ''; start = true; i = j + 1;
      }
    }
    return [fields, field, quoted, start];
  }

  // [delimiter, column names] when a first line reads as a CSV/TSV header, else null.
  function csvHeader(line) {
    const counts = CSV_DELIMITERS.map(d => [csvSplit(line, d)[0].length, d]);
    const best = Math.max(...counts.map(([n]) => n));
    if (best === 0) return null;
    const delimiter = counts.find(([n]) => n === best)[1];
    const [fields, last, quoted] = csvSplit(line, delimiter);
    const names = [...fields, last].map(name => name.replace(/^[ \t]+|[ \t]+$/g, ''));
    if (quoted || new Set(names).size !== names.length || !names.every(name => CSV_HEADER.test(name))) return null;
    // Names with spaces ("Event ID") need three columns, so a sentence with a comma stays plain text.
    if (names.length < 3 && names.some(name => name.includes(' '))) return null;
    return [delimiter, names];
  }

  function detectFormat(firstLine) {
    const line = firstLine.replace(/^[ \t\r\f\v]+/, '');
    // An events array opens with "[{", "[]" or a bare "["; "[2026-09-21 ...] ..." is a text log.
    if (line.startsWith('[') && ['', '{', ']'].includes(line.slice(1).replace(/^[ \t\r\f\v]+/, '').slice(0, 1))) return 'json';
    if (line.startsWith('{')) {
      try { return isObj(JSON.parse(line)) ? 'ndjson' : 'json'; } catch { return 'json'; }  // A JSON document spread over several lines.
    }
    return csvHeader(line) ? 'csv' : 'text';
  }

  // The events inside {"events": [...]} or an Elasticsearch search response, else null.
  function wrapped(data) {
    if (Array.isArray(get(data, 'events'))) return data.events;
    const hits = get(data, 'hits');
    return isObj(hits) && Array.isArray(get(hits, 'hits')) ? hits.hits : null;
  }

  function unwrap(data) {
    if (isObj(data)) return wrapped(data) ?? [data];
    if (Array.isArray(data)) return data;
    throw new Error('JSON input must be an array of events or an object with an events array');
  }

  // Give events without an id, _id or event.id a stable one from their place in the input.
  function numbered(events, label) {
    return events.map(([number, raw]) => {
      if (!isObj(raw)) throw new Error(`${label} ${number} is not a JSON object`);
      if (!eventId(raw)) setOwn(raw, 'id', `${label}-${number}`);
      return raw;
    });
  }

  // Events from the text of a log file, in input order. format is one of FORMATS; see
  // parse_lines in jev_incident.py for how "auto" decides and how missing IDs are assigned.
  function parse(text, format = 'auto') {
    if (!FORMATS.includes(format)) throw new Error(`format must be one of ${FORMATS.join(', ')}`);
    const lines = text.split('\n').map(line => line.replace(/\r+$/, ''));
    if (lines.length) lines[0] = lines[0].replace(/^﻿+/, '');
    const first = lines.findIndex(line => !blank(line));
    if (first < 0) throw new Error('input contains no events');
    if (format === 'auto') format = detectFormat(lines[first]);
    if (format === 'json') {
      let data;
      try { data = JSON.parse(lines.join('\n')); } catch (error) { throw new Error(`not valid JSON: ${error.message}`); }
      return numbered(unwrap(data).map((raw, i) => [i + 1, raw]), 'event');
    }
    if (format === 'ndjson') {
      const events = [];
      lines.forEach((line, i) => {
        if (blank(line)) return;
        try { events.push([i + 1, JSON.parse(line)]); } catch (error) { throw new Error(`line ${i + 1} is not valid JSON: ${error.message}`); }
      });
      const inner = events.length === 1 && isObj(events[0][1]) ? wrapped(events[0][1]) : null;
      if (inner !== null) return numbered(inner.map((raw, i) => [i + 1, raw]), 'event');  // A one-line {"events": [...]} document.
      return numbered(events, 'line');
    }
    if (format === 'csv') {
      const header = csvHeader(lines[first]);
      if (header === null) throw new Error('first line is not a CSV header of field names');
      const [delimiter, names] = header;
      const events = [];
      let state = null, start = null;
      for (let i = first + 1; i < lines.length; i++) {
        if (state === null && blank(lines[i])) continue;
        if (state === null) start = i + 1;
        const [fields, field, quoted, atStart] = csvSplit(lines[i], delimiter, state);
        if (quoted) { state = [fields, field + '\n', quoted, atStart]; continue; }
        state = null;
        const values = [...fields, field];
        events.push([start, flatEvent(names.slice(0, values.length).map((name, j) => [name, values[j]]))]);
      }
      if (state !== null) throw new Error(`line ${start} opens a quoted CSV field that never closes`);
      return numbered(events, 'line');
    }
    const events = [];
    lines.forEach((line, i) => {
      if (blank(line)) return;
      const pairs = [...line.matchAll(TEXT_PAIR)].map(([, name, quoted, bare]) => [name, quoted ? quoted.replaceAll('\\"', '"') : bare ?? '']);
      const stamp = TEXT_TIME.exec(line);
      if (stamp) pairs.push(['@timestamp', stamp[1]]);
      events.push([i + 1, flatEvent([['message', line], ...pairs])]);
    });
    return numbered(events, 'line');
  }

  const api = {FORMATS, parse, detectFormat, csvHeader, flatEvent, eventId};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.JevFormats = api;
})(typeof window !== 'undefined' ? window : globalThis);
