// The engine in a browser: log files (File or Blob objects) are read in chunks at line boundaries, so
// a file never has to fit in one string, then go through the same pipeline as in Node (pipeline.ts).
// Jev is reached through the website's relay, because browsers cannot call TypeSafe directly.
import type {Event} from './model.ts';
import {csvHeader, detectFormat, OpenQuoteError, readLines, textLines, type Format, type RawRecord} from './read.ts';
import {newStats, normalize, type NormalizeStats} from './normalize.ts';
import {applyMapping, flatten, groupKey, KEEP_UNKNOWN, mergeProfiles, observe, type Mapping, type Profiles} from './schema.ts';
import {TransportError, type JevResponse, type Transport} from './jev.ts';
import {assemble, schemaSummaries, type Learner, type Loaded, type SchemaSummary} from './pipeline.ts';

export * from './pipeline.ts';

/** What the loader needs of a File. */
export interface LogFile { name: string; size: number; slice(start?: number, end?: number): Blob }

export interface BrowserLoadOptions {
  learn?: Learner;
  /** Bytes read so far of the file being read. */
  onProgress?: (progress: {file: string; index: number; bytes: number; size: number; pass: 1 | 2}) => void;
  /** Bytes read at a time (tests make it small). */
  chunk?: number;
  keepUnknown?: number;
}

const CHUNK = 8 * 1024 * 1024;
const BLANK = /^[ \t\r\f\v]*$/;
const ms = (since: number) => Math.round((performance.now() - since) * 10) / 10;

/** A file's lines in batches, numbered from 1 across the whole file, without line endings or a leading BOM. */
async function* lineBatches(file: LogFile, chunk: number, onBytes: (bytes: number) => void): AsyncGenerator<[number, string][]> {
  const decoder = new TextDecoder();
  let carry = new Uint8Array(0), position = 0, number = 0, first = true;
  const lines = (bytes: Uint8Array): [number, string][] => {
    let text = decoder.decode(bytes);
    if (first) { text = text.replace(/^﻿+/, ''); first = false; }
    return text.split('\n').map(line => [++number, line.endsWith('\r') ? line.replace(/\r+$/, '') : line]);
  };
  while (position < file.size) {
    const bytes = new Uint8Array(await file.slice(position, position + chunk).arrayBuffer());
    position += bytes.length;
    onBytes(position);
    const data = carry.length ? new Uint8Array(carry.length + bytes.length) : bytes;
    if (carry.length) { data.set(carry); data.set(bytes, carry.length); }
    const last = data.lastIndexOf(10);
    if (last < 0) { carry = data; continue; }
    yield lines(data.subarray(0, last));
    carry = data.slice(last + 1);
  }
  if (carry.length) yield lines(carry);
}

/** The format of a file from its first non-blank line. */
async function formatOf(file: LogFile, chunk: number): Promise<{format: Exclude<Format, 'auto'>; header?: [string, string[]]; headerLine?: number}> {
  for await (const batch of lineBatches(file, chunk, () => {})) {
    const first = batch.find(([, line]) => !BLANK.test(line));
    if (!first) continue;
    const format = detectFormat(first[1]);
    if (format !== 'csv') return {format};
    const header = csvHeader(first[1]);
    if (!header) throw new Error(`${file.name}: the first line is not a CSV header of field names`);
    return {format, header, headerLine: first[0]};
  }
  throw new Error(`${file.name} contains no events`);
}

/**
 * Every record of a file, read in chunks. A JSON document is read whole; a CSV field quoted across two
 * chunks makes the whole file be read again in one piece (`whole`), as the Node reader does.
 */
async function* fileRecords(file: LogFile, chunk: number, onBytes: (bytes: number) => void, whole = false): AsyncGenerator<RawRecord[]> {
  const {format, header, headerLine} = await formatOf(file, chunk);
  if (format === 'json' || whole) {
    const text = new TextDecoder().decode(await file.slice(0).arrayBuffer());
    onBytes(file.size);
    yield [...readLines(textLines(text), format)];
    return;
  }
  // A file of one NDJSON line may be a whole {"events": [...]} document: read it as a non-part.
  if (file.size <= chunk) {
    const text = new TextDecoder().decode(await file.slice(0).arrayBuffer());
    onBytes(file.size);
    yield [...readLines(textLines(text), format)];
    return;
  }
  for await (const batch of lineBatches(file, chunk, onBytes)) {
    const lines = headerLine === undefined ? batch : batch.filter(([number]) => number > headerLine);
    yield [...readLines(lines, format, {part: true, ...(header ? {header} : {})})];
  }
}

/**
 * Read, normalize and link log files in a browser: the counterpart of analyze.ts load(). Records of
 * unknown schemas are profiled, learned through `learn`, then turned into events (kept in memory when
 * few, otherwise read again).
 */
export async function loadFiles(files: LogFile[], {learn, onProgress, chunk = CHUNK, keepUnknown = KEEP_UNKNOWN}: BrowserLoadOptions = {}): Promise<Loaded> {
  const timings: Record<string, number> = {};
  let t = performance.now();
  const all: Event[] = [], stats = newStats(), inputs: Loaded['inputs'] = [], profiles: Profiles = {};
  const unknownFiles = new Map<number, RawRecord[] | null>();
  for (const [index, file] of files.entries()) {
    const progress = (pass: 1 | 2) => (bytes: number) => onProgress?.({file: file.name, index, bytes, size: file.size, pass});
    let events: Event[] = [], fileStats = newStats(), fileProfiles: Profiles = {}, kept: RawRecord[] | null = [];
    const read = async (whole: boolean) => {
      for await (const records of fileRecords(file, chunk, progress(1), whole)) {
        for (const record of records) {
          const event = normalize(record, index, all.length + events.length, fileStats, unknown => {
            observe(fileProfiles, unknown, file.name);
            if (kept && kept.length < keepUnknown * 4) kept.push(unknown); else kept = null;
          });
          if (event) events.push(event);
        }
      }
    };
    try {
      await read(false);
    } catch (error) {
      if (!(error instanceof OpenQuoteError)) throw error;
      events = []; fileStats = newStats(); fileProfiles = {}; kept = [];
      await read(true);
    }
    for (const e of events) all.push(e);
    merge(stats, fileStats);
    mergeProfiles(profiles, fileProfiles);
    if (fileStats.unknown) unknownFiles.set(index, kept);
    inputs.push({path: file.name, format: 'auto', records: fileStats.records, kept: fileStats.kept});
  }
  timings.read_normalize = ms(t);

  const schemas: SchemaSummary[] = [];
  if (unknownFiles.size) {
    t = performance.now();
    const mappings = learn ? await learn(profiles) : new Map<string, Mapping>();
    timings.learn_schemas = ms(t);
    t = performance.now();
    const byKey = Object.fromEntries(mappings), produced = new Map<string, number>();
    for (const [index, records] of unknownFiles) {
      const learned: Event[] = [];
      const toEvent = (record: RawRecord) => {
        const fields = flatten(record), mapping = byKey[groupKey(fields)];
        const event = mapping ? applyMapping(record, mapping, index, learned.length, fields) : null;
        if (event) learned.push(event);
      };
      if (records) {
        for (const record of records) toEvent(record);
      } else if (Object.keys(byKey).length) {
        const file = files[index]!;
        const reread = async (whole: boolean) => {
          learned.length = 0;
          for await (const batch of fileRecords(file, chunk, bytes => onProgress?.({file: file.name, index, bytes, size: file.size, pass: 2}), whole)) {
            for (const record of batch) normalize(record, index, 0, undefined, toEvent);
          }
        };
        try { await reread(false); } catch (error) { if (!(error instanceof OpenQuoteError)) throw error; await reread(true); }
      }
      for (const e of learned) {
        all.push(e);
        produced.set(e.source, (produced.get(e.source) ?? 0) + 1);
        stats.kept++;
        if (e.t === null) stats.untimed++;
      }
      inputs[index]!.kept += learned.length;
    }
    all.sort((a, b) => a.file - b.file || a.line - b.line);
    schemas.push(...schemaSummaries(profiles, mappings, produced));
    timings.apply_schemas = ms(t);
  }
  return assemble(all, stats, inputs, schemas, timings);
}

function merge(into: NormalizeStats, from: NormalizeStats) {
  into.records += from.records; into.kept += from.kept; into.other += from.other; into.untimed += from.untimed; into.unknown += from.unknown;
  for (const [source, n] of from.bySource) into.bySource.set(source, (into.bySource.get(source) ?? 0) + n);
}

/**
 * Jev through the website's relay (api/jev.js). With a key the relay forwards it to TypeSafe for this one
 * request; without one it uses the site's demo key, which only answers requests about the bundled example.
 * The relay's own refusals are final and say why; TypeSafe's temporary failures are retried.
 */
export function relay(endpoint: string, key?: string, {timeoutMs = 90_000} = {}): Transport {
  return async (body, signal) => {
    let response: Response;
    try {
      // Same-site cookies only (the relay is this site): a Vercel preview behind its login needs them.
      response = await fetch(endpoint, {method: 'POST', body, credentials: 'same-origin', referrerPolicy: 'no-referrer', redirect: 'error',
        headers: {'Content-Type': 'application/json', ...(key ? {'Authorization': `Bearer ${key}`} : {})},
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs)});
    } catch (error) {
      if (signal?.aborted) throw error;
      throw new TransportError('The Jev relay on this site could not be reached; check your connection.', true);
    }
    const text = await response.text();
    let data: unknown;
    try { data = JSON.parse(text); } catch { data = null; }
    const refusal = data && typeof data === 'object' && (data as {source?: unknown}).source === 'relay' ? String((data as {error?: unknown}).error ?? '') : null;
    if (!response.ok) {
      const status = response.status;
      if (refusal) throw new TransportError(refusal.slice(0, 300), status === 429);
      if (status === 401 || status === 403) throw new TransportError(`TypeSafe rejected the API key (HTTP ${status}); check your TypeSafe key.`, false);
      throw new TransportError(`TypeSafe returned HTTP ${status}`, status === 429 || status >= 500);
    }
    if (!data || typeof (data as JevResponse).answers !== 'object') throw new TransportError('TypeSafe returned a response that is not a Jev answer', false);
    return data as JevResponse;
  };
}
