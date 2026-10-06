import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {JevClient, sha256, TransportError, type JevResponse, type Transport} from '../src/jev.ts';
import {answerFile, requestLog as requestLogFile} from '../src/files.ts';
import {ecs} from './incident.ts';

const answer: JevResponse = {model: 'jev-1.13.0', answers: {C1: {type: 'noul', noul: 0.9}}, usage: {input_tokens: 10, output_tokens: 2}};
const dir = mkdtempSync(join(tmpdir(), 'jevline-jev-'));
test.after(() => rmSync(dir, {recursive: true, force: true}));

test('temporary failures are retried with backoff, honouring Retry-After', async () => {
  const failures = [new TransportError('HTTP 429', true, 5000), new TransportError('HTTP 529', true), new TransportError('timeout', true)];
  const sleeps: number[] = [];
  const client = new JevClient(async () => { const f = failures.shift(); if (f) throw f; return answer; }, {sleep: async ms => { sleeps.push(ms); }});
  assert.deepEqual(await client.ask('{}', 2), answer);
  assert.deepEqual(sleeps, [5000, 2000, 4000]);
  assert.equal(client.calls[0]!.attempts, 4);
});

test('client errors are not retried, and retries are bounded', async () => {
  let calls = 0;
  const unauthorized = new JevClient(async () => { calls++; throw new TransportError('HTTP 401', false); }, {sleep: async () => {}});
  await assert.rejects(unauthorized.ask('{}', 2), /HTTP 401/);
  assert.equal(calls, 1);
  calls = 0;
  const down = new JevClient(async () => { calls++; throw new TransportError('HTTP 503', true); }, {retries: 2, sleep: async () => {}});
  await assert.rejects(down.ask('{}', 2), /HTTP 503/);
  assert.equal(calls, 3);
  assert.equal(down.calls[0]!.error, 'HTTP 503');
});

test('no more than `concurrency` requests are in flight', async () => {
  let active = 0, peak = 0;
  const transport: Transport = async () => { active++; peak = Math.max(peak, active); await new Promise(r => setTimeout(r, 5)); active--; return answer; };
  const client = new JevClient(transport, {concurrency: 3});
  await Promise.all(Array.from({length: 12}, (_, i) => client.ask(`{"i":${i}}`, 2)));
  assert.equal(peak, 3);
});

test('answers are cached by the SHA-256 of the exact request, on disk and in memory', async () => {
  const cacheFile = join(dir, 'cache.jsonl'), requestLog = join(dir, 'requests.jsonl');
  let calls = 0;
  const transport: Transport = async () => { calls++; return answer; };
  const first = new JevClient(transport, {answers: answerFile(cacheFile), onRequest: requestLogFile(requestLog)});
  await first.ask('{"a":1}', 2);
  await first.ask('{"a":1}', 2);
  assert.equal(calls, 1);
  writeFileSync(cacheFile, readFileSync(cacheFile, 'utf8') + '{"sha256": "trunc');  // an interrupted write
  const second = new JevClient(transport, {answers: answerFile(cacheFile)});
  assert.deepEqual(await second.ask('{"a":1}', 2), answer);
  assert.equal(calls, 1);
  await second.ask('{"a":2}', 2);
  assert.equal(calls, 2);
  assert.equal(statSync(cacheFile).mode & 0o777, 0o600);
  assert.deepEqual(readFileSync(requestLog, 'utf8').trim().split('\n').map(l => (JSON.parse(l) as {sha256: string}).sha256), [sha256('{"a":1}')]);
});

test('an answer without a usable probability fails the analysis instead of guessing', async () => {
  const path = join(dir, 'incident.ndjson');
  writeFileSync(path, ecs().join('\n'));
  const {load, findSeed, analyze} = await import('../src/analyze.ts');
  const loaded = await load([{path, format: 'auto'}]);
  const client = new JevClient(async () => ({answers: {C1: {type: 'noul', noul: 1.7}}}));
  await assert.rejects(analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, client, {description: 'x', model: 'm', threshold: 0.8,
    batchSize: 25, maxRounds: 5, maxCandidatesPerRound: 100, transport: 'test'}), /unusable answer for C1/);
});

const cli = (...args: string[]) => spawnSync(process.execPath, [join(import.meta.dirname, '..', 'src', 'cli.ts'), ...args],
  {encoding: 'utf8', env: {...process.env, TYPESAFE_API_KEY: ''}, cwd: dir});

test('CLI: inspect, analyze offline with a report and request log, clear errors', () => {
  const path = join(dir, 'cli.ndjson'), out = join(dir, 'run');
  writeFileSync(path, ecs().join('\n'));
  const inspect = cli('inspect', path, '--find', 'invoice.exe');
  assert.equal(inspect.status, 0, inspect.stderr);
  assert.match(inspect.stdout, /processes .*links/);
  assert.match(inspect.stdout, /pid 2000 {2}seed: line-\d+ {2}guid:/);

  const run = cli('analyze', path, '--seed', 'name:invoice.exe', '--context', 'Confirmed.', '--offline', '--out', out);
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /8 in the incident \(6 processes, 2 accounts, hosts, addresses or domains\)/);
  assert.match(run.stdout, /These are not Jev decisions/);
  const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8')) as {incident: unknown[]; jev: {requests: number}};
  assert.equal(report.incident.length, 8);
  assert.equal(readFileSync(join(out, 'requests.jsonl'), 'utf8').trim().split('\n').length, report.jev.requests);
  assert.equal(statSync(out).mode & 0o777, 0o700);

  const noKey = cli('analyze', path, '--seed', 'name:invoice.exe', '--context', 'x', '--key-file', join(dir, 'no.env'));
  assert.equal(noKey.status, 1);
  assert.match(noKey.stderr, /no TypeSafe key/);
  assert.match(cli('analyze', path, '--seed', 'name:nothing.exe', '--context', 'x', '--offline').stderr, /no process start named nothing.exe/);
  assert.match(cli('analyze', path, '--seed', 'line-1', '--offline').stderr, /--context is required/);
  assert.match(cli('inspect', join(dir, 'missing.log')).stderr, /ENOENT/);
});
