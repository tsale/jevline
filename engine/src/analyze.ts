// Reading log files in Node: large files are parsed in byte ranges on several cores (worker.ts), and
// files with records from unknown schemas are read again once those are learned. The rest of the
// pipeline is pipeline.ts, which also runs in a browser (browser.ts).
import type {Event} from './model.ts';
import {closeSync, openSync, readSync, statSync} from 'node:fs';
import {availableParallelism} from 'node:os';
import {basename} from 'node:path';
import {Worker} from 'node:worker_threads';
import {csvHeader, detectFormat, type Format, type RawRecord} from './read.ts';
import {readFile} from './files.ts';
import type {Part, PartResult} from './worker.ts';
import {newStats, normalize, type NormalizeStats} from './normalize.ts';
import {applyMapping, flatten, groupKey, KEEP_UNKNOWN, mergeProfiles, observe, type Mapping, type Profiles} from './schema.ts';
import {assemble, schemaSummaries, type Learner, type Loaded, type SchemaSummary} from './pipeline.ts';

export * from './pipeline.ts';

export interface Input { path: string; format: Format }

const ms = (since: number) => Math.round((performance.now() - since) * 10) / 10;

/** Files at least this large are parsed on several cores. */
const PARALLEL_BYTES = 64 * 1024 * 1024;

/** Bytes [start, end) of a file. */
function bytesAt(fd: number, start: number, length: number): Buffer {
  const buffer = Buffer.allocUnsafe(length);
  return buffer.subarray(0, readSync(fd, buffer, 0, length, start));
}

/** The byte just after the next line break at or after `position` (the file size if there is none). */
function nextLineStart(fd: number, position: number, size: number): number {
  for (let at = position; at < size; at += 1 << 20) {
    const i = bytesAt(fd, at, 1 << 20).indexOf(10);
    if (i >= 0) return at + i + 1;
  }
  return size;
}

/**
 * Events from one large NDJSON, CSV or text file, parsed in byte ranges on worker threads and put
 * back together exactly as the sequential reader would produce them. Returns null when the file
 * should be read sequentially instead: a JSON document, a CSV quoted field that spans two ranges,
 * or any error (the sequential reader then reports it with the right line number).
 */
async function readParallel(input: Input, file: number, threads: number, minBytes: number, stats: NormalizeStats,
  profiles: Profiles, mappings?: Record<string, Mapping>, unknown?: {records: RawRecord[] | null}, keepUnknown = KEEP_UNKNOWN): Promise<Event[] | null> {
  const size = statSync(input.path).size;
  if (threads < 2 || size < minBytes || size === 0) return null;
  const fd = openSync(input.path, 'r');
  const parts: Part[] = [];
  let format: Format, header: [string, string[]] | undefined, start = 0, headerLines = 0;
  try {
    // The first non-blank line decides the format; for CSV it is the header and the ranges start after it.
    let line = '';
    do {
      const end = nextLineStart(fd, start, size);
      if (end - start > 1 << 20) return null;
      line = bytesAt(fd, start, end - start).toString('utf8').replace(/^\ufeff+/, '').replace(/\r?\n$/, '');
      headerLines++;
      start = end;
    } while (/^[ \t\r\f\v]*$/.test(line) && start < size);
    format = input.format === 'auto' ? detectFormat(line) : input.format;
    if (format === 'json') return null;
    if (format === 'csv') {
      header = csvHeader(line) ?? undefined;
      if (!header) return null;
    } else {
      start = 0;
      headerLines = 0;
    }
    for (let i = 0; i < threads; i++) {
      const end = i === threads - 1 ? size : nextLineStart(fd, start + Math.floor((size - start) / (threads - i)), size);
      if (end > start) parts.push({path: input.path, start, end, format, ...(header ? {header} : {}), file, keepUnknown, ...(mappings ? {mappings} : {})});
      start = end;
    }
  } finally {
    closeSync(fd);
  }
  const results = await Promise.all(parts.map(part => new Promise<PartResult>((resolve, reject) => {
    const worker = new Worker(new URL('./worker.ts', import.meta.url), {workerData: part});
    worker.once('message', resolve);
    worker.once('error', reject);
  })));
  if (results.some((r, i) => r.error || (r.openQuote && i < results.length - 1))) return null;
  const events: Event[] = [];
  let offset = headerLines;
  for (const r of results) {
    for (const e of r.events) {
      e.line += offset;
      if (e.lineId) e.id = `line-${e.line}`;
      events.push(e);
    }
    if (unknown) {
      if (!r.unknown || !unknown.records) unknown.records = null;
      else for (const record of r.unknown) {
        record.line += offset;
        if (record.lineId) record.id = `line-${record.line}`;
        unknown.records.push(record);
      }
    }
    offset += r.lines;
    stats.records += r.stats.records; stats.kept += r.stats.kept; stats.other += r.stats.other; stats.untimed += r.stats.untimed;
    stats.unknown += r.stats.unknown;
    for (const [source, n] of r.stats.bySource) stats.bySource.set(source, (stats.bySource.get(source) ?? 0) + n);
    mergeProfiles(profiles, r.profiles);
  }
  return events;
}

export const defaultThreads = () => Math.min(availableParallelism(), 8);

export interface LoadOptions {
  threads?: number;
  parallelBytes?: number;
  /** Understands records from schemas the built-in rules don't know. Without it they are only counted. */
  learn?: Learner;
  /** Unknown-schema records kept in memory per thread; with more, the file is read again (tests lower it). */
  keepUnknown?: number;
}

/**
 * Everything before the investigation: parse every input, normalize it, learn any unknown schemas,
 * resolve processes and build the links. Files with records of unknown schemas are read twice: once
 * to profile them, and once more, after their mappings are learned, to turn them into events.
 */
export async function load(inputs: Input[], {threads = defaultThreads(), parallelBytes = PARALLEL_BYTES, learn, keepUnknown = KEEP_UNKNOWN}: LoadOptions = {}): Promise<Loaded> {
  const timings: Record<string, number> = {};
  let t = performance.now();
  const all: Event[] = [], stats = newStats(), counted: Loaded['inputs'] = [], profiles: Profiles = {};
  // Records of unknown schemas, per file: kept from the first pass when there are few, or null when
  // the file has too many to keep and is read a second time once their mappings are learned.
  const unknownFiles = new Map<number, RawRecord[] | null>();
  for (const [file, input] of inputs.entries()) {
    const before = {records: stats.records, kept: stats.kept, unknown: stats.unknown};
    const kept: {records: RawRecord[] | null} = {records: []};
    const parallel = await readParallel(input, file, threads, parallelBytes, stats, profiles, undefined, kept, keepUnknown);
    if (parallel) {
      for (const e of parallel) all.push(e);
    } else {
      const source = basename(input.path);
      for (const record of readFile(input.path, input.format)) {
        const event = normalize(record, file, all.length, stats, unknown => {
          observe(profiles, unknown, source);
          if (kept.records && kept.records.length < keepUnknown * 4) kept.records.push(unknown); else kept.records = null;
        });
        if (event) all.push(event);
      }
    }
    if (stats.unknown > before.unknown) unknownFiles.set(file, kept.records);
    counted.push({...input, records: stats.records - before.records, kept: stats.kept - before.kept});
  }
  timings.read_normalize = ms(t);

  // Unknown schemas: learn a mapping per event type, then read those files again to apply them.
  const schemas: SchemaSummary[] = [];
  if (unknownFiles.size) {
    t = performance.now();
    const mappings = learn ? await learn(profiles) : new Map<string, Mapping>();
    timings.learn_schemas = ms(t);
    t = performance.now();
    const byKey = Object.fromEntries(mappings);
    const produced = new Map<string, number>();
    const toEvent = (record: RawRecord, file: number, into: Event[]) => {
      const fields = flatten(record), mapping = byKey[groupKey(fields)];
      const event = mapping ? applyMapping(record, mapping, file, into.length, fields) : null;
      if (event) into.push(event);
    };
    for (const [file, records] of unknownFiles) {
      const input = inputs[file]!;
      let learned: Event[] | null = [];
      if (records) {
        for (const record of records) toEvent(record, file, learned);
      } else {
        learned = await readParallel(input, file, threads, parallelBytes, newStats(), {}, byKey);
        if (!learned) {
          learned = [];
          for (const record of readFile(input.path, input.format)) normalize(record, file, 0, undefined, unknown => toEvent(unknown, file, learned!));
        }
      }
      for (const e of learned) {
        all.push(e);
        produced.set(e.source, (produced.get(e.source) ?? 0) + 1);
        stats.kept++;
        if (e.t === null) stats.untimed++;
      }
      counted[file]!.kept += learned.length;
    }
    all.sort((a, b) => a.file - b.file || a.line - b.line);  // Back in input order (the second pass came last).
    schemas.push(...schemaSummaries(profiles, mappings, produced));
    timings.apply_schemas = ms(t);
  }
  return assemble(all, stats, counted, schemas, timings);
}

