// Parses one byte range of a log file in a worker thread (see readParallel in analyze.ts).
// First pass: records of known sources become events and the rest are profiled for schema
// learning. Second pass (with `mappings`): only the records of learned schemas, as events.
import {basename} from 'node:path';
import {parentPort, workerData} from 'node:worker_threads';
import type {Event} from './model.ts';
import {fileLines, OpenQuoteError, readLines, type Format, type RawRecord} from './read.ts';
import {newStats, normalize} from './normalize.ts';
import {applyMapping, flatten, groupKey, KEEP_UNKNOWN, observe, type Mapping, type Profiles} from './schema.ts';

export interface Part {
  path: string; start: number; end: number; format: Exclude<Format, 'auto'>; header?: [string, string[]]; file: number;
  mappings?: Record<string, Mapping>;
  keepUnknown?: number;
}
export interface PartResult {
  events: Event[]; stats: ReturnType<typeof newStats>; profiles: Profiles; lines: number; openQuote: boolean; error?: string;
  /** Records of unknown schemas, kept so they need not be read again (null when there were too many to keep). */
  unknown: RawRecord[] | null;
}

const part = workerData as Part;
const stats = newStats(), events: Event[] = [], profiles: Profiles = {};
let unknown: RawRecord[] | null = [];
const source = basename(part.path);
let lines = 0, openQuote = false, error: string | undefined;
const counted = function* () { for (const entry of fileLines(part.path, undefined, part.start, part.end)) { lines = entry[0]; yield entry; } };
try {
  for (const record of readLines(counted(), part.format, {part: true, ...(part.header ? {header: part.header} : {})})) {
    if (part.mappings) {
      normalize(record, part.file, 0, undefined, unknown => {
        const fields = flatten(unknown), mapping = part.mappings![groupKey(fields)];
        const event = mapping ? applyMapping(unknown, mapping, part.file, events.length, fields) : null;
        if (event) events.push(event);
      });
    } else {
      const event = normalize(record, part.file, events.length, stats, other => {
        observe(profiles, other, source);
        if (unknown && unknown.length < (part.keepUnknown ?? KEEP_UNKNOWN)) unknown.push(other); else unknown = null;
      });
      if (event) events.push(event);
    }
  }
} catch (e) {
  if (e instanceof OpenQuoteError) openQuote = true;
  else error = (e as Error).message;
}
parentPort!.postMessage({events, stats, profiles, lines, openQuote, unknown: part.mappings ? [] : unknown, ...(error ? {error} : {})} satisfies PartResult);
