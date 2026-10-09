// A loop started again and again (a batch file relaunched every few seconds for hours) is one question per
// step of the loop, not one per run: on a busy host each run's processes would otherwise outnumber what one
// round may ask, and the investigation would stop.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {analyze, findSeed, load, unfold} from '../src/analyze.ts';
import {JevClient} from '../src/jev.ts';
import {standIn} from '../src/standin.ts';
import {ecs, EVENTS, seed, type Ev, type Proc} from './incident.ts';

const dir = mkdtempSync(join(tmpdir(), 'jevline-loops-'));
test.after(() => rmSync(dir, {recursive: true, force: true}));

const RUNS = 30;
const step = (run: number, n: number, image: string, cmd: string, parent: Proc): Proc =>
  ({guid: `26BBF027-0000-6AB1-${String(100 + run * 4 + n).padStart(4, '0')}-000000005C00`, pid: 7000 + run * 4 + n, image, cmd, parent});

function loop(): Ev[] {
  const events: Ev[] = [];
  for (let run = 0; run < RUNS; run++) {
    const t = 200 + run * 13;  // every 13 seconds
    const shell = step(run, 0, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      'powershell -NoProfile -Command "Start-Process -FilePath \'C:\\Temp\\zl\\12.bat\' -Verb RunAs"', seed);
    const batch = step(run, 1, 'C:\\Windows\\System32\\cmd.exe', '"C:\\Windows\\System32\\cmd.exe" /C "C:\\Temp\\zl\\12.bat"', shell);
    const launcher = step(run, 2, 'C:\\Windows\\py.exe', '"C:\\Windows\\py.exe" "C:\\Program Files\\Python311\\Scripts\\net.py" session', batch);
    const python = step(run, 3, 'C:\\Program Files\\Python311\\python.exe',
      '"C:\\Program Files\\Python311\\python.exe" "C:\\Program Files\\Python311\\Scripts\\net.py" session', launcher);
    events.push({code: 1, t, p: shell}, {code: 1, t: t + 1, p: batch}, {code: 1, t: t + 2, p: launcher}, {code: 1, t: t + 3, p: python});
  }
  return events;
}

test('each step of a repeated loop is asked once, with only the first run as context', async () => {
  const path = join(dir, 'loop.ndjson');
  writeFileSync(path, ecs([...EVENTS, ...loop()]).join('\n') + '\n');
  const base = standIn();
  const asked: {candidates: string[]; occurrences: number[]; incident: number}[] = [];
  const counting = async (body: string) => {
    const {state} = JSON.parse(body) as {state: {candidates: Record<string, {name?: string; occurrences?: number}>; incident: Record<string, unknown>}};
    asked.push({candidates: Object.values(state.candidates).map(c => c.name ?? ''),
      occurrences: Object.values(state.candidates).map(c => c.occurrences ?? 1), incident: Object.keys(state.incident).length});
    return base(body);
  };
  const loaded = await load([{path, format: 'auto' as const}]);
  const {report} = await analyze(loaded, findSeed(loaded, 'name:invoice.exe').key, new JevClient(counting),
    {description: 'Confirmed malicious.', model: 'm', threshold: 0.8, batchSize: 1, maxRounds: 20, maxCandidatesPerRound: 10, transport: 'test'});
  assert.equal(report.jev.stopped, undefined, 'ten questions a round are enough for 120 loop processes');
  const loopQuestions = asked.filter(a => a.candidates.some(n => ['powershell.exe', 'py.exe', 'python.exe'].includes(n) ||
    a.occurrences.some(o => o === RUNS)));
  for (const name of ['powershell.exe', 'py.exe', 'python.exe']) {
    const questions = asked.filter(a => a.candidates.includes(name));
    assert.equal(questions.length, 1, `${name}: one question for all ${RUNS} runs`);
    assert.equal(questions[0]!.occurrences[questions[0]!.candidates.indexOf(name)], RUNS);
  }
  assert.ok(loopQuestions.every(a => a.incident <= 2), 'a shared question names one run\'s parents, not every run\'s');
  const joined = unfold(report.incident).filter(r => r.name === 'python.exe');
  assert.equal(joined.length, RUNS, 'the answer applies to every run');
});
