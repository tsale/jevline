import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {detectFormat, fileLines, readFile, readText, type RawRecord} from '../src/read.ts';

const all = (text: string, format?: Parameters<typeof readText>[1]) => [...readText(text, format)];
const flat = (r: RawRecord) => Object.fromEntries(r.flat!);

test('formats are detected from the first non-blank line', () => {
  assert.equal(detectFormat('[{"a":1}]'), 'json');
  assert.equal(detectFormat('['), 'json');
  assert.equal(detectFormat('{'), 'json');
  assert.equal(detectFormat('{"a": 1}'), 'ndjson');
  assert.equal(detectFormat('_time,host,EventCode'), 'csv');
  assert.equal(detectFormat('Image\tCommandLine'), 'csv');
  assert.equal(detectFormat('Event ID,Date and Time,Level'), 'csv');
  assert.equal(detectFormat('a sentence, with a comma'), 'text');
  assert.equal(detectFormat('[2026-09-21 17:18:50] service started'), 'text');
});

test('JSON documents: arrays, {"events": [...]}, search responses, fields-only hits', () => {
  assert.deepEqual(all('[{"_id": "a", "_source": {"x": 1}}, {"y": 2}]').map(r => [r.id, r.nested]), [['a', {x: 1}], ['event-2', {y: 2}]]);
  assert.deepEqual(all('{\n "events": [{"id": 7}]\n}').map(r => r.id), ['7']);
  assert.deepEqual(all('{"hits": {"hits": [{"_id": "h"}]}}').map(r => r.id), ['h']);
  const [hit] = all('[{"_id": "f", "fields": {"process.name": ["a.exe"], "event.code": ["1"]}}]');
  assert.deepEqual(flat(hit!), {processname: 'a.exe', eventcode: '1'});
  assert.throws(() => all('[1]', 'json'), /event 1 is not a JSON object/);
});

test('NDJSON: line numbers as IDs, blank lines, a one-line wrapper, errors name the line', () => {
  assert.deepEqual(all('\ufeff{"a": 1}\r\n\r\n{"_id": "x"}\r\n').map(r => r.id), ['line-1', 'x']);
  assert.deepEqual(all('{"events": [{"a": 1}, {"b": 2}]}').map(r => r.id), ['event-1', 'event-2']);
  assert.deepEqual(all('{"a": 1}').map(r => r.id), ['line-1']);
  assert.throws(() => all('{"a": 1}\n\n{bad\n'), /line 3 is not valid JSON/);
  assert.throws(() => all('{"a": 1}\n[1]\n'), /line 2 is not a JSON object/);
  assert.throws(() => all(' \n'), /no events/);
});

test('CSV: quoting, delimiters, line breaks inside quotes, ragged rows', () => {
  const rows = all('a;b;c\n"x;y";"he said ""hi""";z\n\n"multi\nline",2,3\n');
  assert.deepEqual(flat(rows[0]!), {a: 'x;y', b: 'he said "hi"', c: 'z'});
  assert.deepEqual(rows.map(r => r.line), [2, 4]);
  assert.deepEqual(flat(rows[1]!), {a: 'multi\nline,2,3'}, 'the header chose ";": commas are data');
  assert.deepEqual(flat(all('a|b\n1|2|3\n4\n')[1]!), {a: '4'});
  assert.deepEqual(flat(all('a,b\nx"y",z\n')[0]!), {a: 'x"y"', b: 'z'}, 'a quote inside an unquoted field is data');
  assert.equal(all('id,b\nown,1\n')[0]!.id, 'own');
  assert.throws(() => all('a,b\n1,2\n"open,\n'), /line 3 opens a quoted CSV field/);
});

test('text: the line, key=value pairs (quoted or bare) and a leading timestamp', () => {
  const [r] = all('2026-09-21T17:18:50Z host=WS-01 Image="C:\\Program Files\\a.exe" CommandLine="a.exe \\"x\\"" pid=0x190 empty=""\n');
  assert.deepEqual(flat(r!), {message: '2026-09-21T17:18:50Z host=WS-01 Image="C:\\Program Files\\a.exe" CommandLine="a.exe \\"x\\"" pid=0x190 empty=""',
    host: 'WS-01', image: 'C:\\Program Files\\a.exe', commandline: 'a.exe "x"', pid: '0x190', timestamp: '2026-09-21T17:18:50Z'});
});

test('files are streamed in chunks without splitting lines or UTF-8 characters', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jevline-read-'));
  try {
    const path = join(dir, 'events.ndjson');
    const lines = Array.from({length: 50}, (_, i) => JSON.stringify({id: `e${i}`, name: `prozeß-${'é'.repeat(i % 7)}`}));
    writeFileSync(path, '\ufeff' + lines.join('\r\n'));  // no final newline
    for (const chunk of [1, 2, 3, 7, 64, 1 << 20]) {
      assert.deepEqual([...fileLines(path, chunk)].map(([, line]) => line), lines, `chunk size ${chunk}`);
    }
    assert.deepEqual([...readFile(path)].map(r => (r.nested as {name: string}).name), lines.map(l => (JSON.parse(l) as {name: string}).name));
  } finally {
    rmSync(dir, {recursive: true, force: true});
  }
});
