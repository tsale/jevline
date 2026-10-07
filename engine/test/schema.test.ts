// Schema learning: logs from schemas with no built-in rules are understood once per event type.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {analyze, findSeed, load, unfold} from '../src/analyze.ts';
import {JevClient, type JevResponse, type Transport} from '../src/jev.ts';
import {standIn} from '../src/standin.ts';
import {mappingFile} from '../src/files.ts';
import {readText} from '../src/read.ts';
import {fingerprint, flatten, groupKey, kindRequest, learn, MAX_QUESTIONS, MAX_REQUEST_BYTES, observe, readMapping, rolesRequest, SchemaCache, shapes, timeOf, type Profiles} from '../src/schema.ts';
import {ecs, falconFdr, mde} from './incident.ts';

const dir = mkdtempSync(join(tmpdir(), 'jevline-schema-'));
test.after(() => rmSync(dir, {recursive: true, force: true}));
let n = 0;
const file = (content: string, name: string) => { const path = join(dir, `${n++}-${name}`); writeFileSync(path, content); return path; };
const one = (text: string) => [...readText(text)][0]!;

test('times in any common unit', () => {
  const us = Date.UTC(2026, 8, 21, 17, 21, 26, 904) * 1000;
  assert.equal(timeOf('2026-09-21T17:21:26.904Z'), us);
  assert.equal(timeOf(us / 1e6), us, 'seconds');
  assert.equal(timeOf('1790011286.904'), us, 'seconds as text');
  assert.equal(timeOf(us / 1000), us, 'milliseconds');
  assert.equal(timeOf(us), us, 'microseconds');
  assert.equal(timeOf(us * 1000), us, 'nanoseconds');
  assert.equal(timeOf((us + 11_644_473_600_000_000) * 10), us, 'Windows FILETIME');
  assert.equal(timeOf(8788), null, 'a PID is not a time');
});

test('fields are read from any shape, including JSON held in a string', () => {
  const fields = flatten(one(JSON.stringify({a: {b: [{c: 1}]}, AdditionalFields: JSON.stringify({DesiredAccess: 2097151}), empty: ''})));
  assert.deepEqual(Object.fromEntries(fields), {'a.b.c': 1, 'AdditionalFields.DesiredAccess': 2097151});
  const csv = flatten(one('InitiatingProcessId,ActionType\n7412,ProcessCreated\n'));
  assert.deepEqual([...csv.keys()], ['InitiatingProcessId', 'ActionType'], 'CSV columns keep their names');
  assert.equal(groupKey(csv), 'ActionType=ProcessCreated');
  assert.match(groupKey(flatten(one('{"x": 1, "y": 2}'))), /^fields:/, 'no event-type field: grouped by the fields it has');
});

test('a mapping keeps each role once (the more probable field) and drops unsure answers', () => {
  const profiles: Profiles = {};
  observe(profiles, one(JSON.stringify({ActionType: 'ProcessCreated', A: 1, B: 2, C: 3})), 'x.json');
  const group = Object.values(profiles)[0]!;
  const {labels} = rolesRequest(group, 'process_start', 'm');
  const label = (name: string) => [...labels].find(([, f]) => f === name)![0];
  const answers: JevResponse['answers'] = {};
  answers[label('A')] = {type: 'choice', choice: 'new_process_pid', probabilities: {new_process_pid: 0.7}};
  answers[label('B')] = {type: 'choice', choice: 'new_process_pid', probabilities: {new_process_pid: 0.9}};
  answers[label('C')] = {type: 'choice', choice: 'creator_pid', probabilities: {creator_pid: 0.4}};
  answers[label('ActionType')] = {type: 'choice', choice: 'event_type', probabilities: {event_type: 0.99}};
  const mapping = readMapping(group, 'process_start', 0.95, {answers}, labels, 'jev');
  assert.deepEqual(mapping.roles, {B: 'new_process_pid', ActionType: 'event_type'});
  assert.equal(mapping.kind, 'process_start');
  assert.ok(mapping.warnings!.some(w => w.includes('A also looked like new_process_pid')));
  assert.ok(mapping.warnings!.some(w => w.includes('C → creator_pid only at 40%')));
  assert.ok(mapping.warnings!.some(w => w.includes('no time field')));
});

test('a "PID" that only holds long numbers is used as a unique process ID', () => {
  const profiles: Profiles = {};
  observe(profiles, one(JSON.stringify({event_simpleName: 'ProcessRollup2', ParentProcessId: '4398046513104', ts: '2026-09-21T17:21:26Z'})), 'f.json');
  const group = Object.values(profiles)[0]!;
  const {labels} = rolesRequest(group, 'process_start', 'm');
  const label = (name: string) => [...labels].find(([, f]) => f === name)![0];
  const mapping = readMapping(group, 'process_start', 0.9, {answers: {
    [label('ParentProcessId')]: {type: 'choice', choice: 'creator_pid', probabilities: {creator_pid: 0.8}},
    [label('ts')]: {type: 'choice', choice: 'time', probabilities: {time: 0.9}}}}, labels, 'jev');
  assert.equal(mapping.roles.ParentProcessId, 'creator_id');
  assert.deepEqual(shapes('4398046513104'), ['large_integer']);
  assert.deepEqual(shapes(8788), ['small_integer']);
});

test('a schema with many long fields is learned in requests the website relay accepts', async () => {
  const profiles: Profiles = {};
  for (let r = 0; r < 3; r++) {
    const record: Record<string, unknown> = {ActionType: 'ProcessCreated', ProcessId: 4000 + r};
    for (let i = 0; i < 190; i++) record[`Field_${i}`] = `C:\\Windows\\System32\\${r}\\${'x'.repeat(150)}`;
    observe(profiles, one(JSON.stringify(record)), 'wide.json');
  }
  const group = Object.values(profiles)[0]!;
  const size = (body: string) => new TextEncoder().encode(body).length;
  assert.ok(size(kindRequest(group, 'm')) <= MAX_REQUEST_BYTES);
  const {requests, labels} = rolesRequest(group, 'process_start', 'm');
  assert.ok(requests.length > 1);
  for (const {body, questions} of requests) {
    assert.ok(size(body) <= MAX_REQUEST_BYTES, `${size(body)} bytes`);
    assert.equal(Object.keys(JSON.parse(body).questions).length, questions);
    assert.ok(questions <= MAX_QUESTIONS);
  }
  assert.equal(requests.reduce((sum, r) => sum + r.questions, 0), labels.size, 'every field is asked about once');
  const sent: number[] = [];
  const transport: Transport = async body => {
    const {questions} = JSON.parse(body) as {questions: Record<string, unknown>};
    sent.push(size(body));
    return {answers: Object.fromEntries(Object.keys(questions).map(label => [label, label === 'kind'
      ? {type: 'choice', choice: 'process_start', confidence: 0.9}
      : {type: 'choice', choice: labels.get(label) === 'ProcessId' ? 'new_process_pid' : 'other', confidence: 0.9}]))};
  };
  const mapping = (await learn(profiles, new JevClient(transport), new SchemaCache(), 'm')).get(group.key)!;
  assert.ok(sent.every(bytes => bytes <= MAX_REQUEST_BYTES));
  assert.equal(mapping.roles.ProcessId, 'new_process_pid', 'answers from every request are used');
});

test('the same schema has the same fingerprint whatever its values', () => {
  const profile = (pid: number) => { const p: Profiles = {}; observe(p, one(JSON.stringify({event_simpleName: 'ProcessRollup2', RawProcessId: pid})), 'a'); return Object.values(p)[0]!; };
  assert.equal(fingerprint(profile(1)), fingerprint(profile(2)));
});

interface Run { incident: string[]; schemaRequests: number; mappings: Map<string, Record<string, string>> }

async function run(paths: string[], schemaFile?: string, transport: Transport = standIn()): Promise<Run> {
  const schemaClient = new JevClient(transport);
  const cache = new SchemaCache(schemaFile ? mappingFile(schemaFile) : undefined);
  const mappings = new Map<string, Record<string, string>>();
  const loaded = await load(paths.map(path => ({path, format: 'auto' as const})), {
    learn: async profiles => { const m = await learn(profiles, schemaClient, cache, 'jev-1.13.0', 'stand-in'); for (const [k, v] of m) mappings.set(k, v.roles); return m; }});
  const {report} = await analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, new JevClient(standIn()), {description: 'x', model: 'm',
    threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 1000, transport: 'test'});
  return {incident: unfold(report.incident).filter(p => p.type === 'process').map(p => p.name ?? '?').sort(), schemaRequests: schemaClient.calls.filter(c => !c.cached).length, mappings};
}

const EXPECTED = ['cmd.exe', 'invoice.exe', 'sihost.exe', 'stage2.exe', 'upd.exe', 'whoami.exe'];

test('Microsoft Defender for Endpoint exports find the same incident as Sysmon', async () => {
  const sysmon = await run([file(ecs().join('\n'), 'sysmon.ndjson')]);
  assert.deepEqual(sysmon.incident, EXPECTED);
  assert.equal(sysmon.schemaRequests, 0, 'built-in sources need no schema questions');
  const tables = mde();
  const result = await run(Object.entries(tables).map(([table, csv]) => file(csv, `${table}.csv`)));
  assert.deepEqual(result.incident, EXPECTED);
  // In a process start, InitiatingProcess* is the creator; in an injection it's the process that injected.
  assert.equal(result.mappings.get('ActionType=ProcessCreated')!.InitiatingProcessId, 'creator_pid');
  assert.equal(result.mappings.get('ActionType=CreateRemoteThreadApiCall')!.InitiatingProcessId, 'actor_pid');
  assert.equal(result.mappings.get('ActionType=CreateRemoteThreadApiCall')!.ProcessId, 'target_pid');
  assert.equal(result.mappings.get('ActionType=OpenProcessApiCall')!['AdditionalFields.DesiredAccess'], 'access_mask');
  assert.equal(result.schemaRequests, 12, 'two small requests per event type (its kind, then its fields)');
});

test('CrowdStrike Falcon events find the same incident, and a second run asks nothing', async () => {
  const path = file(falconFdr().join('\n'), 'fdr.ndjson'), schemas = join(dir, 'schemas.jsonl');
  const first = await run([path], schemas);
  assert.deepEqual(first.incident, EXPECTED);
  assert.equal(first.mappings.get('event_simpleName=ProcessRollup2')!.TargetProcessId, 'new_process_id', 'in a process start the "target" is the new process');
  assert.equal(first.mappings.get('event_simpleName=InjectedThread')!.TargetProcessId, 'target_id');
  assert.equal(first.schemaRequests, 14);
  let asked = 0;
  const second = await run([path], schemas, async body => { asked++; return standIn()(body); });
  assert.deepEqual(second.incident, EXPECTED);
  assert.equal(second.schemaRequests, 0, 'every schema came from the cache');
  assert.equal(asked, 0);
});

test('without a learner, unknown schemas are counted and reported, never guessed', async () => {
  const loaded = await load([{path: file(falconFdr().join('\n'), 'fdr2.ndjson'), format: 'auto'}]);
  assert.equal(loaded.events.length, 0);
  assert.ok(loaded.schemas.length >= 7);
  assert.ok(loaded.schemas.every(s => s.learned === 'not learned'));
});

test('reading a file again for its unknown records gives the same events as keeping them', async () => {
  const path = file(falconFdr().join('\n'), 'fdr3.ndjson');
  const learner = async (profiles: Profiles) => learn(profiles, new JevClient(standIn()), new SchemaCache(), 'm', 'stand-in');
  const kept = await load([{path, format: 'auto'}], {learn: learner, threads: 1});
  for (const options of [{threads: 1, keepUnknown: 0}, {threads: 3, parallelBytes: 0, keepUnknown: 0}, {threads: 3, parallelBytes: 0}]) {
    const other = await load([{path, format: 'auto'}], {learn: learner, ...options});
    assert.deepEqual(other.events, kept.events, JSON.stringify(options));
  }
});
