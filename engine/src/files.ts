// The engine's file system side, for Node only: reading log files in chunks, and the JSONL files that
// keep Jev answers, the exact requests and learned schema mappings between runs. Everything else in
// src/ also runs in a browser (see browser.ts).
import {appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync} from 'node:fs';
import {dirname} from 'node:path';
import {readLines, type Format} from './read.ts';
import type {AnswerStore, JevResponse} from './jev.ts';
import type {MappingStore, StoredMapping} from './schema.ts';

const CHUNK = 16 * 1024 * 1024;

/** The lines of a file (or of bytes [start, end) of it, which must begin at a line start) without line
 * endings, numbered from 1, read `chunk` bytes at a time. A line break byte never occurs inside a
 * UTF-8 character, so decoding up to the last one is always safe. */
export function* fileLines(path: string, chunk = CHUNK, start = 0, end = Infinity): Generator<[number, string]> {
  const fd = openSync(path, 'r');
  try {
    const buffer = Buffer.allocUnsafe(chunk);
    let carry = Buffer.alloc(0), number = 0, first = start === 0, position = start;
    const decode = (bytes: Buffer) => {
      let text = bytes.toString('utf8');
      if (first) { text = text.replace(/^﻿+/, ''); first = false; }
      return text.split('\n').map(line => line.endsWith('\r') ? line.replace(/\r+$/, '') : line);
    };
    for (;;) {
      const read = readSync(fd, buffer, 0, Math.min(chunk, end - position), position);
      if (read <= 0) break;
      position += read;
      const data = carry.length ? Buffer.concat([carry, buffer.subarray(0, read)]) : buffer.subarray(0, read);
      const last = data.lastIndexOf(10);
      if (last < 0) { carry = Buffer.from(data); continue; }
      for (const line of decode(data.subarray(0, last))) yield [++number, line];
      carry = Buffer.from(data.subarray(last + 1));
    }
    if (carry.length) for (const line of decode(carry)) yield [++number, line];
  } finally {
    closeSync(fd);
  }
}

export const readFile = (path: string, format: Format = 'auto') => readLines(fileLines(path), format);

/** Each JSON line of a file that parses (a truncated last line from an interrupted run is skipped). */
function* jsonLines(path: string): Generator<unknown> {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    try { if (line.trim()) yield JSON.parse(line); } catch { /* skip */ }
  }
}

const append = (path: string, value: unknown) => {
  mkdirSync(dirname(path), {recursive: true, mode: 0o700});
  appendFileSync(path, JSON.stringify(value) + '\n', {mode: 0o600});
};

/** Jev answers kept in a private JSONL file of {sha256, response}: earlier answers are reused, new ones appended. */
export const answerFile = (path: string): AnswerStore => ({
  *load() {
    for (const entry of jsonLines(path) as Iterable<{sha256?: unknown; response?: JevResponse}>) {
      if (typeof entry?.sha256 === 'string' && entry.response?.answers) yield [entry.sha256, entry.response];
    }
  },
  save: (sha256, response) => append(path, {sha256, response}),
});

/** Records every distinct request body in a private JSONL file of {sha256, body}. */
export const requestLog = (path: string) => (sha256: string, body: string) => append(path, {sha256, body: JSON.parse(body) as unknown});

/** Learned schema mappings kept in a private JSONL file of {fingerprint, group, kind, roles}. */
export const mappingFile = (path: string): MappingStore => ({
  *load() {
    for (const m of jsonLines(path) as Iterable<StoredMapping>) if (m?.fingerprint && m.roles) yield m;
  },
  save: mapping => append(path, mapping),
});
