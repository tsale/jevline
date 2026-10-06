// Reading logs: JSON documents, NDJSON, CSV/TSV and plain text, from any source of numbered lines, so
// files can be streamed in chunks (files.ts in Node, browser.ts in a browser) and their size is limited
// by disk, not by memory or by V8's maximum string length (except a single JSON document, which has to
// be parsed whole).

export const FORMATS = ['auto', 'json', 'ndjson', 'csv', 'text'] as const;
export type Format = typeof FORMATS[number];

/** One record as read: nested (JSON) or flat (CSV row, text line, Elasticsearch `fields`). */
export interface RawRecord {
  line: number;           // first line of the record in its file (1-based); for JSON documents, the position
  id: string;             // own id, or line-N / event-N
  /** The id is line-N, made from the line number (so it moves if the line number is offset). */
  lineId?: true;
  nested?: Record<string, unknown>;
  flat?: Map<string, unknown>;
  /** For flat records: each normalized key's name as written in the source ("InitiatingProcessId"). */
  names?: Map<string, string>;
}

const BLANK = /^[ \t\r\f\v]*$/;
const CSV_DELIMITERS = [',', '\t', ';', '|'];
const CSV_HEADER = /^[A-Za-z_@][A-Za-z0-9_.@ -]{0,99}$/;
const TEXT_TIME = /^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?/;
const TEXT_PAIR = /(?:^|[ \t\f\v,;])([A-Za-z_@][A-Za-z0-9_.@-]*)=(?:"((?:[^"\\]|\\.)*)"|([^ \t\f\v,;]*))/g;

export const isObj = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);

/** Lower-case and drop separators, so "Process Guid", "process_guid" and "process.guid" match. */
export const normKey = (name: string): string => name.toLowerCase().replace(/[ _.@-]/g, '');

/** The lines of a string, numbered from 1, the same way files.ts reads a file. */
export function* textLines(text: string): Generator<[number, string]> {
  let number = 0;
  for (const line of text.replace(/^﻿+/, '').split('\n')) yield [++number, line.replace(/\r+$/, '')];
}

type CsvState = [string[], string, boolean, boolean];

/** Fields of one physical line; the state carries an open quoted field into the next line. */
export function csvSplit(text: string, delimiter: string, state: CsvState | null = null): CsvState {
  let [fields, field, quoted, start] = state ?? [[], '', false, true];
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

/** [delimiter, column names] when a line reads as a CSV/TSV header, else null. */
export function csvHeader(line: string): [string, string[]] | null {
  const counts = CSV_DELIMITERS.map(d => [csvSplit(line, d)[0].length, d] as const);
  const best = Math.max(...counts.map(([n]) => n));
  if (best === 0) return null;
  const delimiter = counts.find(([n]) => n === best)![1];
  const [fields, last, quoted] = csvSplit(line, delimiter);
  const names = [...fields, last].map(name => name.trim());
  if (quoted || new Set(names).size !== names.length || !names.every(name => CSV_HEADER.test(name))) return null;
  // Names with spaces ("Event ID") need three columns, so a sentence with a comma stays plain text.
  if (names.length < 3 && names.some(name => name.includes(' '))) return null;
  return [delimiter, names];
}

export function detectFormat(firstLine: string): Exclude<Format, 'auto'> {
  const line = firstLine.replace(/^[ \t\r\f\v]+/, '');
  // An events array opens with "[{", "[]" or a bare "["; "[2026-09-21 ...] ..." is a text log.
  if (line.startsWith('[') && ['', '{', ']'].includes(line.slice(1).trimStart().slice(0, 1))) return 'json';
  if (line.startsWith('{')) {
    try { return isObj(JSON.parse(line)) ? 'ndjson' : 'json'; } catch { return 'json'; }
  }
  return csvHeader(line) ? 'csv' : 'text';
}

/** The record's own ID: id, _id, then id or event.id in its source. */
function ownId(value: Record<string, unknown>): string {
  const source = isObj(value._source) ? value._source : value;
  const event = isObj(source.event) ? source.event : {};
  for (const id of [value.id, value._id, source.id, event.id]) {
    if (typeof id === 'string' && id) return id;
    if (typeof id === 'number') return String(id);
  }
  return '';
}

function record(value: unknown, line: number, label: string): RawRecord {
  if (!isObj(value)) throw new Error(`${label} ${line} is not a JSON object`);
  const own = ownId(value), id = own || `${label}-${line}`;
  const lineId = !own && label === 'line' ? {lineId: true as const} : {};
  if (isObj(value.fields) && !isObj(value._source)) {  // Elasticsearch hit with dotted, multi-value fields only.
    const flat = new Map<string, unknown>(), names = new Map<string, string>();
    for (const [key, v] of Object.entries(value.fields)) { flat.set(normKey(key), Array.isArray(v) ? v[0] : v); names.set(normKey(key), key); }
    return {line, id, ...lineId, flat, names};
  }
  return {line, id, ...lineId, nested: isObj(value._source) ? value._source : value};
}

function unwrap(data: unknown): unknown[] | null {
  if (Array.isArray(data)) return data;
  if (!isObj(data)) return null;
  if (Array.isArray(data.events)) return data.events;
  const hits = data.hits;
  if (isObj(hits) && Array.isArray(hits.hits)) return hits.hits;  // An Elasticsearch search response.
  return null;
}

function flatRecord(pairs: Iterable<[string, string]>, line: number, ownLabel = 'line'): RawRecord {
  const flat = new Map<string, unknown>(), names = new Map<string, string>();
  for (const [name, value] of pairs) {
    const key = normKey(name);
    if (value !== '' && !flat.has(key)) { flat.set(key, value); names.set(key, name); }
  }
  const id = flat.get('id');
  return typeof id === 'string' && id ? {line, id, flat, names} : {line, id: `${ownLabel}-${line}`, lineId: true, flat, names};
}

/** A CSV part ended inside a quoted field, so the next part did not start at a record. */
export class OpenQuoteError extends Error {}

export interface ReadOptions {
  /** This is a part of a file that starts at a line boundary after its first line: no format
   * detection or header, never a one-line {"events": [...]} document. */
  part?: boolean;
  /** For a CSV part: the delimiter and column names from the file's header. */
  header?: [string, string[]];
}

/**
 * Records from numbered lines. "auto" reads the first non-blank line: "[{"/"[" or a multi-line "{"
 * starts a JSON document, a one-line JSON object starts NDJSON, a header of field names starts
 * CSV/TSV, and anything else is plain text, one record per line.
 */
export function* readLines(lines: Iterable<[number, string]>, format: Format = 'auto', options: ReadOptions = {}): Generator<RawRecord> {
  if (!FORMATS.includes(format)) throw new Error(`format must be one of ${FORMATS.join(', ')}`);
  if (options.part && format === 'auto') throw new Error('a part of a file needs its format');
  const iterator = lines[Symbol.iterator]();
  const head: [number, string][] = [];
  for (let next = iterator.next(); !next.done; next = iterator.next()) {
    head.push(next.value);
    if (!BLANK.test(next.value[1])) break;
  }
  const first = head.at(-1);
  if (!first || BLANK.test(first[1])) {
    if (options.part) return;
    throw new Error('input contains no events');
  }
  const rest = function* (): Generator<[number, string]> {
    yield* head;
    for (let next = iterator.next(); !next.done; next = iterator.next()) yield next.value;
  };
  const kind = format === 'auto' ? detectFormat(first[1]) : format;
  if (kind === 'json') {
    let data: unknown;
    const parts: string[] = [];
    for (const [, line] of rest()) parts.push(line);
    try { data = JSON.parse(parts.join('\n')); } catch (error) { throw new Error(`not valid JSON: ${(error as Error).message}`); }
    const events = unwrap(data) ?? [data];
    for (let i = 0; i < events.length; i++) yield record(events[i], i + 1, 'event');
    return;
  }
  if (kind === 'ndjson') {
    let count = 0, only: RawRecord | null = null, onlyValue: unknown = null;
    for (const [number, line] of rest()) {
      if (BLANK.test(line)) continue;
      let value: unknown;
      try { value = JSON.parse(line); } catch (error) { throw new Error(`line ${number} is not valid JSON: ${(error as Error).message}`); }
      count++;
      if (count === 1 && !options.part) { only = record(value, number, 'line'); onlyValue = value; continue; }  // Held back: it may be a one-line document.
      if (count === 2 && !options.part) yield only!;
      yield record(value, number, 'line');
    }
    if (count === 1 && !options.part) {
      const inner = isObj(onlyValue) ? unwrap(onlyValue) : null;
      if (inner) for (let i = 0; i < inner.length; i++) yield record(inner[i], i + 1, 'event');
      else yield only!;
    }
    return;
  }
  if (kind === 'csv') {
    const header = options.header ?? csvHeader(first[1]);
    if (!header) throw new Error('first line is not a CSV header of field names');
    const [delimiter, names] = header;
    let state: CsvState | null = null, start = 0;
    for (const [number, line] of rest()) {
      if (!options.header && number <= first[0]) continue;
      if (state === null && BLANK.test(line)) continue;
      if (state === null) start = number;
      const [fields, field, quoted, atStart] = csvSplit(line, delimiter, state);
      if (quoted) { state = [fields, field + '\n', quoted, atStart]; continue; }
      state = null;
      const values = [...fields, field];
      yield flatRecord(names.slice(0, values.length).map((name, j) => [name, values[j]!] as [string, string]), start);
    }
    if (state !== null) throw new OpenQuoteError(`line ${start} opens a quoted CSV field that never closes`);
    return;
  }
  for (const [number, line] of rest()) {
    if (BLANK.test(line)) continue;
    const pairs: [string, string][] = [['message', line]];
    for (const [, name, quoted, bare] of line.matchAll(TEXT_PAIR)) pairs.push([name!, quoted ? quoted.replaceAll('\\"', '"') : bare ?? '']);
    const stamp = TEXT_TIME.exec(line);
    if (stamp) pairs.push(['@timestamp', stamp[1]!]);
    yield flatRecord(pairs, number);
  }
}

export const readText = (text: string, format: Format = 'auto') => readLines(textLines(text), format);
