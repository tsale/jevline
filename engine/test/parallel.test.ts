// Parsing a file on several threads must give exactly what the sequential reader gives.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {load} from '../src/analyze.ts';
import {csv, ecs, text} from './incident.ts';

const dir = mkdtempSync(join(tmpdir(), 'jevline-parallel-'));
test.after(() => rmSync(dir, {recursive: true, force: true}));

async function same(name: string, content: string) {
  const path = join(dir, name);
  writeFileSync(path, content);
  const sequential = await load([{path, format: 'auto'}], {threads: 1});
  for (const threads of [2, 3, 7]) {
    const parallel = await load([{path, format: 'auto'}], {threads, parallelBytes: 0});
    assert.deepEqual(parallel.events, sequential.events, `${name} on ${threads} threads`);
    assert.deepEqual(parallel.stats, sequential.stats, `${name} stats on ${threads} threads`);
  }
}

test('NDJSON with a BOM, CRLF and blank lines', () => same('a.ndjson', '﻿' + ecs().join('\r\n\r\n') + '\r\n'));
test('CSV, with the header kept out of the ranges', () => same('a.csv', '\r\n' + csv()));
test('text', () => same('a.log', text()));

test('a CSV quoted field across two ranges falls back to the sequential reader', async () => {
  const rows = csv().split('\r\n');
  const long = `${rows[1]!.replace(/^([^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,)[^,]*/, `$1"${'x'.repeat(200)}\nsecond line of the same field"`)}`;
  await same('quoted.csv', [rows[0], ...rows.slice(1, 10), long, ...rows.slice(10)].join('\r\n'));
});

test('an invalid line is reported with its line number in the file', async () => {
  const path = join(dir, 'bad.ndjson');
  const lines = ecs();
  lines.splice(20, 0, '{not json');
  writeFileSync(path, lines.join('\n'));
  await assert.rejects(load([{path, format: 'auto'}], {threads: 4, parallelBytes: 0}), /line 21 is not valid JSON/);
});
