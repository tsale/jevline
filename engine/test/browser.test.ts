// The engine in a browser (browser.ts) reads File objects in chunks and must produce exactly the events
// the Node reader produces from the same files, whatever the chunk size.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {load} from '../src/analyze.ts';
import {analyze, findSeed, loadFiles, relay} from '../src/browser.ts';
import {JevClient} from '../src/jev.ts';
import {standIn} from '../src/standin.ts';
import {learn, SchemaCache} from '../src/schema.ts';
import {csv, ecs, falconFdr, mde, text} from './incident.ts';
import {authCsv, firewallCsv} from './network.ts';

const dir = mkdtempSync(join(tmpdir(), 'jevline-browser-'));
test.after(() => rmSync(dir, {recursive: true, force: true}));
const learner = async (profiles: Parameters<typeof learn>[0]) => learn(profiles, new JevClient(standIn()), new SchemaCache(), 'm', 'stand-in');

async function same(name: string, contents: Record<string, string>, chunk: number) {
  const paths = Object.entries(contents).map(([file, content]) => { const path = join(dir, `${name}-${file}`); writeFileSync(path, content); return path; });
  const node = await load(paths.map(path => ({path, format: 'auto' as const})), {learn: learner, threads: 1});
  const files = paths.map(path => new File([readFileSync(path)], path.split('/').at(-1)!));
  const browser = await loadFiles(files, {learn: learner, chunk});
  assert.deepEqual(browser.events, node.events, `${name}, ${chunk}-byte chunks`);
  assert.deepEqual(browser.schemas, node.schemas);
  assert.deepEqual(browser.inputs.map(i => [i.records, i.kept]), node.inputs.map(i => [i.records, i.kept]));
}

test('File objects read in chunks give the Node reader\'s events, in every format', async () => {
  const bom = '\ufeff';
  const inputs: Record<string, Record<string, string>> = {
    ndjson: {'a.ndjson': bom + ecs().join('\r\n') + '\r\n'},
    csv: {'a.csv': csv()},
    text: {'a.log': text()},
    json: {'a.json': JSON.stringify({events: ecs().map(line => JSON.parse(line) as unknown)}, null, 1)},
    mde: Object.fromEntries(Object.entries(mde()).map(([table, content]) => [`${table}.csv`, content])),
    falcon: {'fdr.ndjson': falconFdr().join('\n')},
    network: {'auth.csv': authCsv(), 'fw.csv': firewallCsv()},
  };
  for (const [name, contents] of Object.entries(inputs)) for (const chunk of [7, 100, 1 << 20]) await same(name, contents, chunk);
});

test('a CSV field quoted across two chunks is read whole, without counting anything twice', async () => {
  const content = 'time,host,EventID,Image,CommandLine,ProcessId\n' + Array.from({length: 40}, (_, i) =>
    `2026-09-21T17:2${i % 10}:00Z,WS-01,1,C:\\\\x${i}.exe,"run\nacross lines ${i}",${100 + i}`).join('\n') + '\n';
  await same('quoted', {'q.csv': content}, 64);
});

test('the relay transport: answers, the relay\'s own refusals, and TypeSafe failures', async () => {
  const original = globalThis.fetch;
  const replies: [number, unknown][] = [];
  const sent: {url?: string; auth?: string | null} = {};
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    Object.assign(sent, {url, auth: new Headers(init.headers).get('authorization')});
    const [status, body] = replies.shift()!;
    return new Response(JSON.stringify(body), {status});
  }) as typeof fetch;
  try {
    replies.push([200, {answers: {C1: {type: 'noul', noul: 0.9}}}]);
    assert.equal((await relay('api/jev', 'k')('{}')).answers.C1!.noul, 0.9);
    assert.deepEqual(sent, {url: 'api/jev', auth: 'Bearer k'});
    replies.push([403, {source: 'relay', error: 'The demo key only analyzes the bundled lab example.'}]);
    await assert.rejects(relay('api/jev')('{}'), (e: Error & {retryable: boolean}) => /bundled lab example/.test(e.message) && !e.retryable);
    assert.equal(sent.auth, null, 'no key: the demo key on the relay');
    replies.push([502, {error: 'TypeSafe could not be reached from the relay.'}]);
    await assert.rejects(relay('api/jev', 'k')('{}'), (e: Error & {retryable: boolean}) => e.retryable);
  } finally {
    globalThis.fetch = original;
  }
});

test('a whole analysis runs without Node\'s globals, as in a browser', async () => {
  const file = new File([ecs().join('\n')], 'sysmon.ndjson');
  const hidden = {process: globalThis.process, Buffer: globalThis.Buffer};
  Object.defineProperty(globalThis, 'process', {value: undefined, configurable: true, writable: true});
  Object.defineProperty(globalThis, 'Buffer', {value: undefined, configurable: true, writable: true});
  let report;
  try {
    const loaded = await loadFiles([file], {learn: learner});
    ({report} = await analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, new JevClient(standIn()), {description: 'x', model: 'm',
      threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test'}));
  } finally {
    Object.defineProperty(globalThis, 'process', {value: hidden.process, configurable: true, writable: true});
    Object.defineProperty(globalThis, 'Buffer', {value: hidden.Buffer, configurable: true, writable: true});
  }
  assert.ok(report.incident.some(row => row.name === 'stage2.exe'));
  assert.equal(report.peak_memory_mb, undefined);
});

test('the browser build of the engine imports nothing from Node', () => {
  const src = join(import.meta.dirname, '..', 'src');
  const graph = new Set<string>(), queue = ['browser.ts'];
  while (queue.length) {
    const file = queue.pop()!;
    if (graph.has(file)) continue;
    graph.add(file);
    for (const [, spec] of readFileSync(join(src, file), 'utf8').matchAll(/^(?:import|export)[^'"]*from '([^']+)'/gm)) {
      assert.ok(!spec!.startsWith('node:'), `${file} imports ${spec}`);
      if (spec!.startsWith('./')) queue.push(spec!.slice(2));
    }
  }
  assert.ok(graph.has('pipeline.ts') && graph.has('investigate.ts') && !graph.has('files.ts') && !graph.has('analyze.ts'));
  assert.ok(readdirSync(src).includes('browser.ts'));
});
