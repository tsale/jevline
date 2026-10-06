from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch
from urllib.error import HTTPError, URLError
from email.message import Message

import jev_incident as poc

SAMPLE = Path(__file__).parent / "tests" / "fixtures" / "synthetic.json"
GOLDEN = Path(__file__).parent / "tests" / "fixtures" / "engine_golden.json"
GOLDEN_FIXTURES = {"synthetic": (SAMPLE, "seed"), "edge_cases": (SAMPLE.parent / "edge_cases.json", "seed"),
                   "malicious_events": (Path(__file__).parent / "examples" / "malicious_events.json", "VvT8xKABOYkemEz9sgQR")}
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def golden_judge(state):
    """Deterministic stand-in for Jev, reproduced exactly by ui/test_engine.js."""
    def entity(event):
        process = event.get("process") or {}
        return process.get("entity_id") if isinstance(process, dict) else None
    parent = (state["candidate"].get("process") or {}).get("parent") or {}
    known = {entity(e) for e in [state["seed"]] + state["known_related"]} - {None}
    if isinstance(parent, dict) and parent.get("entity_id") in known:
        return 0.9, "lineage"
    return 0.1 + 0.05 * len(state["surrounding"]), "no_link"


def engine_golden():
    """Reference outputs the browser port (ui/engine.js) must reproduce byte for byte.

    Regenerate after an intentional change to jev_incident.py:
        python3 -c "import test_jev_incident as t; t.write_golden()"
    """
    def dumps(value):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    def digest(text):
        return hashlib.sha256(text.encode()).hexdigest()

    golden = {}
    for name, (path, seed) in GOLDEN_FIXTURES.items():
        data = json.loads(path.read_text(encoding="utf-8"))
        events = data["events"] if isinstance(data, dict) else data
        compacted = [poc.compact(e) for e in events]
        requests = []
        results = poc.run(events, seed, "Analyst-confirmed seed.", golden_judge,
                          observer=lambda number, state, decision: requests.append(dumps([number, state])))
        times = [poc.timestamp(e.get("time")) for e in compacted]
        keep = (lambda text: text) if name != "malicious_events" else digest  # The large export is stored as hashes.
        golden[name] = {
            "seed": seed,
            "compact": [keep(dumps(e)) for e in compacted],
            "times": [None if t is None else (t - EPOCH) // timedelta(microseconds=1) for t in times],
            "executions": [e["id"] for e in compacted if poc.is_execution(e)],
            "contexts": {e["id"]: [c["id"] for c in poc.context(compacted, e)] for e in compacted if poc.is_execution(e)},
            "requests": [keep(r) for r in requests],
            "results": results,
        }
    return golden


def write_golden():
    GOLDEN.write_text(json.dumps(engine_golden(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.events = json.loads(SAMPLE.read_text())["events"]

    def test_progressive_context_and_unrelated_host(self):
        calls = []
        def judge(state):
            calls.append(state)
            if state["candidate"]["id"] == "unrelated":
                return 0.14, "no_link"
            return 0.93, "lineage"
        rows = poc.run(self.events, "seed", "Confirmed malicious PowerShell", judge)
        self.assertEqual([r["related"] for r in rows], [True, True, True, False])
        self.assertEqual(calls[1]["candidate"]["id"], "later")
        self.assertIn("child", [e["id"] for e in calls[1]["known_related"]])
        self.assertIn("file-1", [e["id"] for e in calls[0]["surrounding"]])
        self.assertEqual(calls[2]["surrounding"], [])
        self.assertEqual(len(calls), 4)  # second pass revisits the negative

    def test_reconsider_negative_after_new_link(self):
        calls = []
        def judge(state):
            candidate = state["candidate"]["id"]
            known = [e["id"] for e in state["known_related"]]
            calls.append((candidate, known))
            return (0.9, "lineage") if candidate == "child" or candidate == "later" and "child" in known else (0.1, "no_link")
        rows = poc.run(self.events, "seed", "Confirmed malicious", judge)
        self.assertTrue(rows[2]["related"])
        self.assertNotIn("unrelated", calls[1][1])

    def test_ecs_and_pid_reuse(self):
        event = poc.compact({"_id":"ecs", "_source":{"@timestamp":"2026-09-21T17:18:50Z", "event":{"category":["process"], "action":["start"]}, "host":{"name":"WS-01"}, "process":{"name":"cmd.exe", "pid":400,"entity_id":"different"}}})
        self.assertTrue(poc.is_execution(event))
        seed = poc.compact(self.events[0])
        self.assertFalse(poc.related_evidence(seed, dict(event, time="2026-09-22T17:18:50Z")))
        with self.assertRaisesRegex(ValueError, "unique"):
            poc.run(self.events + [self.events[0]], "seed", "seed", lambda _: (0.5, "no_link"))

    def test_actual_export_shape_and_projected_roundtrip(self):
        event = {"@timestamp":"2026-09-21T17:21:26.9045099Z",
                 "event":{"id":"native-event-id", "category":["process"], "action":["start"]},
                 "host":{"name":"CLA-WS-214"},
                 "process":{"name":"2.8.exe", "entity_id":"seed-entity",
                            "parent":{"name":"explorer.exe", "entity_id":"shell-entity", "Ext":{"ignored":True}},
                            "Ext":{"ancestry":["shell-entity"]}, "hash":{"sha256":"abc"}}}
        projected = poc.compact(event)
        self.assertEqual(projected["id"], "native-event-id")
        self.assertEqual(projected["process"]["parent"]["entity_id"], "shell-entity")
        self.assertEqual(projected["process"]["sha256"], "abc")
        self.assertNotIn("Ext", projected["process"]["parent"])
        self.assertEqual(poc.compact(projected), projected)
        self.assertTrue(poc.is_execution(projected))

    def test_elasticsearch_fields_only_process_start(self):
        hit = {'_id': 'es-start', 'fields': {
            '@timestamp': ['2026-09-21T17:21:26Z'],
            'event.category': ['process'], 'event.type': ['start'], 'event.action': ['created-process'],
            'host.name': ['WS-01'], 'user.name': ['analyst'],
            'process.name': ['sample.exe'], 'process.pid': [334],
            'process.entity_id': ['entity-334'], 'process.parent.entity_id': ['parent-10'],
            'process.command_line': ['sample.exe /q']}}
        event = poc.compact(hit)
        self.assertEqual(event['id'], 'es-start')
        self.assertEqual(event['time'], '2026-09-21T17:21:26Z')
        self.assertEqual(event['process']['entity_id'], 'entity-334')
        self.assertEqual(event['process']['parent']['entity_id'], 'parent-10')
        self.assertTrue(poc.is_execution(event))

    def test_api_shape_and_probability_not_choice_confidence(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self): return b'{"answers":{"related":{"type":"noul","noul":0.81},"evidence":{"type":"choice","choice":"artifact","confidence":0.2}}}'
        with patch.object(poc, "urlopen", return_value=Response()) as mocked:
            probability, reason = poc.jev({"seed": {}, "candidate": {}}, "test-key", "jev-1.13.0")
        self.assertEqual((probability, reason), (0.81, "artifact"))
        req = mocked.call_args.args[0]
        body = json.loads(req.data)
        self.assertEqual(body["questions"]["related"]["type"], "noul")
        self.assertEqual(body["questions"]["evidence"]["type"], "choice")
        self.assertNotIn("test-key", str(body))

    def test_timestamps_with_any_fraction_length_parse_on_every_python(self):
        # Python < 3.11 rejects fractions other than 3 or 6 digits; EDR exports often carry 7.
        self.assertEqual(poc.timestamp("2026-09-21T17:21:26.9045099Z"), poc.timestamp("2026-09-21T17:21:26.904509Z"))
        self.assertEqual(poc.timestamp("2026-09-21T17:21:26.5Z").microsecond, 500000)
        self.assertEqual(poc.timestamp("2026-09-21 17:21:26.123456789+00:00").microsecond, 123456)
        self.assertIsNotNone(poc.timestamp("2026-09-21T17:21:26Z"))
        self.assertIsNone(poc.timestamp("not a time"))

    def test_env_file_keys_and_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text('# comment\nexport OPENROUTER_API_KEY=\'or-value\'\nTYPESAFE_API_KEY=ts-value  # inline note\nEMPTY=\n')
            env.chmod(0o600)
            self.assertEqual(poc.read_key(env, "TYPESAFE_API_KEY"), "ts-value")
            self.assertEqual(poc.read_key(env, "OPENROUTER_API_KEY"), "or-value")
            self.assertIsNone(poc.read_key(env, "EMPTY"))
            self.assertIsNone(poc.read_key(env, "MISSING"))
            legacy = Path(directory) / "key"
            legacy.write_text("TYPESAFE_API_KEY=legacy-value\n")
            legacy.chmod(0o600)
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(poc.find_key("TYPESAFE_API_KEY", env_file=env), "ts-value")
                self.assertIsNone(poc.find_key("TYPESAFE_API_KEY", env_file=None))
            with patch.dict(os.environ, {"TYPESAFE_API_KEY": "from-environment"}):
                # The environment overrides .env; an explicit key file overrides both.
                self.assertEqual(poc.find_key("TYPESAFE_API_KEY", env_file=env), "from-environment")
                self.assertEqual(poc.find_key("TYPESAFE_API_KEY", legacy, env), "legacy-value")
            if os.name != "nt":
                env.chmod(0o644)
                with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, "chmod 600 .env"):
                    poc.find_key("TYPESAFE_API_KEY", env_file=env)

    def test_private_key_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key"
            path.write_text('TYPESAFE_API_KEY="test-value"\n')
            path.chmod(0o600)
            self.assertEqual(poc.load_key_file(path), "test-value")
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private"):
                poc.load_key_file(path)

    def test_recorded_run_keeps_timing_and_related_evidence(self):
        def fake_jev(state, key, model, metadata, on_failure=None):
            metadata.update({"model": model, "usage": {"input_tokens": 17, "output_tokens": 2},
                             "request_bytes": 200, "answers": {"related": {"noul": 0.91}}})
            return (0.91, "lineage") if state["candidate"]["id"] == "child" else (0.12, "no_link")
        with tempfile.TemporaryDirectory() as directory, patch.object(poc, "jev", side_effect=fake_jev):
            path = Path(directory) / "run"
            rows, summary = poc.recorded_run(self.events, "seed", "confirmed", "test-key",
                                             "jev-1.13.0", 0.8, path, SAMPLE)
            attempts = [json.loads(line) for line in (path / "attempts.jsonl").read_text().splitlines()]
            self.assertEqual(summary["api_calls"], len(attempts))
            self.assertEqual(summary["evaluated_candidates"], 3)
            self.assertEqual(summary["related_candidates"], 1)
            self.assertEqual(summary["input_tokens"], 17 * len(attempts))
            self.assertGreaterEqual(summary["elapsed_seconds"], summary["api_elapsed_seconds"])
            self.assertEqual(len(list((path / "evidence").glob("*.json"))), 2)
            self.assertEqual(json.loads((path / "evidence" / "001.json").read_text())["candidate"]["id"], "child")
            self.assertEqual(json.loads((path / "decisions.json").read_text()), rows)
            disk_summary = json.loads((path / "summary.json").read_text())
            self.assertEqual(disk_summary, summary)
            self.assertEqual(disk_summary["evidence_dir"], str(path / "evidence"))
            self.assertEqual(disk_summary["telemetry_file"], str(SAMPLE))
            with self.assertRaises(FileExistsError):
                poc.recorded_run(self.events, "seed", "confirmed", "test-key", "jev-1.13.0", 0.8, path, SAMPLE)



VALID_ANSWER = b'{"answers":{"related":{"type":"noul","noul":0.91},"evidence":{"type":"choice","choice":"lineage"}}}'


class Response:
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def read(self): return VALID_ANSWER


def http_error(code):
    return HTTPError(poc.API, code, "error", Message(), io.BytesIO())


class RetryTests(unittest.TestCase):
    STATE = {"seed": {}, "candidate": {"id": "c"}}

    def setUp(self):
        self.events = json.loads(SAMPLE.read_text())["events"]

    def ask(self, *outcomes, on_failure=None):
        with patch.object(poc, "urlopen", side_effect=list(outcomes)) as send, patch.object(poc, "sleep") as sleep:
            try:
                return poc.jev(self.STATE, "test-key", "jev-1.13.0", on_failure=on_failure), send, sleep
            except Exception as exc:
                return exc, send, sleep

    def test_temporary_5xx_and_timeouts_are_retried_then_answered(self):
        for failure in (http_error(520), http_error(503), TimeoutError("read timed out"), URLError(TimeoutError("timed out"))):
            with self.subTest(failure=failure):
                answer, send, sleep = self.ask(failure, Response())
                self.assertEqual(answer, (0.91, "lineage"))
                self.assertEqual(send.call_count, 2)
                sleep.assert_called_once_with(poc.RETRY_BACKOFF_SECONDS[0])

    def test_retries_are_bounded_and_last_error_is_raised(self):
        failures = []
        error, send, sleep = self.ask(http_error(520), http_error(502), http_error(520), Response(),
                                      on_failure=lambda *args: failures.append(args))
        self.assertIsInstance(error, HTTPError)
        self.assertEqual((error.code, error.attempts), (520, 3))
        self.assertEqual(send.call_count, 3)  # one try plus at most 2 retries
        self.assertEqual(sleep.call_args_list, [call(1.0), call(2.0)])
        self.assertEqual([(f[0], f[2], f[3]) for f in failures], [(1, True, 1.0), (2, True, 2.0), (3, False, None)])

    def test_client_errors_and_unreachable_host_are_not_retried(self):
        for failure in (http_error(401), http_error(403), http_error(429), URLError(ConnectionRefusedError())):
            with self.subTest(failure=failure):
                error, send, sleep = self.ask(failure, Response())
                self.assertIs(error, failure)
                self.assertEqual(error.attempts, 1)
                self.assertEqual(send.call_count, 1)
                sleep.assert_not_called()

    def test_unusable_answer_is_not_retried(self):
        class Bad(Response):
            def read(self): return b'{"answers":{}}'
        error, send, sleep = self.ask(Bad(), Response())
        self.assertIsInstance(error, KeyError)
        self.assertEqual(send.call_count, 1)
        sleep.assert_not_called()

    def run_recorded(self, outcomes, directory):
        path = Path(directory) / "run"
        with patch.object(poc, "urlopen", side_effect=outcomes), patch.object(poc, "sleep"):
            try:
                result = poc.recorded_run(self.events, "seed", "confirmed", "test-key", "jev-1.13.0", 0.8, path, SAMPLE)
            except Exception as exc:
                result = exc
        records = [json.loads(line) for line in (path / "attempts.jsonl").read_text().splitlines()]
        return result, records

    def test_recorded_run_logs_retried_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            outcomes = [http_error(520), Response()] + [Response() for _ in range(10)]
            (rows, summary), records = self.run_recorded(outcomes, directory)
            failed = [r for r in records if r.get("type") == "failed_request"]
            decisions = [r for r in records if "decision" in r]
            self.assertEqual(len(failed), 1)
            self.assertEqual({k: failed[0][k] for k in ("candidate_id", "request_attempt", "error", "retrying", "backoff_seconds")},
                             {"candidate_id": decisions[0]["candidate_id"], "request_attempt": 1, "error": "HTTP 520",
                              "retrying": True, "backoff_seconds": 1.0})
            self.assertEqual(summary["retried_requests"], 1)
            self.assertEqual(summary["api_calls"], len(decisions))
            self.assertTrue(all(r["related"] for r in rows))

    def test_recorded_run_fails_when_retries_run_out(self):
        with tempfile.TemporaryDirectory() as directory:
            error, records = self.run_recorded([TimeoutError(), http_error(520), http_error(520)], directory)
            self.assertIsInstance(error, HTTPError)
            self.assertEqual(error.attempts, 3)
            self.assertEqual([(r["error"], r["retrying"]) for r in records],
                             [("timeout", True), ("HTTP 520", True), ("HTTP 520", False)])
            self.assertFalse((Path(directory) / "run" / "decisions.json").exists())

    def resume(self, previous, outcomes, directory, name, description="confirmed"):
        path = Path(directory) / name
        with patch.object(poc, "urlopen", side_effect=list(outcomes)) as send, patch.object(poc, "sleep"):
            try:
                result = poc.recorded_run(self.events, "seed", description, "test-key", "jev-1.13.0", 0.8, path, SAMPLE,
                                          resume_from=Path(directory) / previous)
            except Exception as exc:
                result = exc
        records = [json.loads(line) for line in (path / "attempts.jsonl").read_text().splitlines()]
        return result, records, send

    def test_resume_reuses_answered_calls_and_asks_jev_for_the_rest(self):
        with tempfile.TemporaryDirectory() as directory:
            # First call answered, second call exhausts its retries.
            error, first = self.run_recorded([Response(), http_error(520), http_error(520), http_error(520)], directory)
            self.assertIsInstance(error, HTTPError)
            answered = [r for r in first if "decision" in r]
            self.assertEqual(len(answered), 1)
            (rows, summary), records, send = self.resume("run", [Response(), Response()], directory, "resumed")
            self.assertEqual(send.call_count, 2)  # only the unanswered candidates are sent
            self.assertEqual((summary["api_calls"], summary["reused_answers"]), (2, 1))
            self.assertEqual(summary["resumed_from"], str(Path(directory) / "run"))
            decisions = [r for r in records if "decision" in r]
            self.assertEqual(decisions[0]["reused_from"]["run_dir"], str(Path(directory) / "run"))
            self.assertEqual({k: decisions[0][k] for k in ("candidate_id", "pass", "known_related_ids", "surrounding_ids", "answers", "request_sha256")},
                             {k: answered[0][k] for k in ("candidate_id", "pass", "known_related_ids", "surrounding_ids", "answers", "request_sha256")})
            self.assertTrue(all("reused_from" not in r for r in decisions[1:]))
            # The candidate whose request failed is asked again, never assumed.
            failed_id = next(r["candidate_id"] for r in first if r.get("type") == "failed_request")
            self.assertIn(failed_id, [r["candidate_id"] for r in decisions[1:]])
            with patch.object(poc, "urlopen", side_effect=[Response() for _ in range(3)]), patch.object(poc, "sleep"):
                clean, _ = poc.recorded_run(self.events, "seed", "confirmed", "test-key", "jev-1.13.0", 0.8, Path(directory) / "clean", SAMPLE)
            # The reused decision is marked with the original answer time only; no private path.
            reused = [r for r in rows if "reused" in r]
            self.assertEqual([r["id"] for r in reused], [answered[0]["candidate_id"]])
            self.assertEqual(reused[0]["reused"], {"answered_utc": answered[0]["completed_utc"]})
            self.assertNotIn(directory, json.dumps(rows))
            decisions_file = json.loads((Path(directory) / "resumed" / "decisions.json").read_text())
            self.assertEqual(decisions_file, rows)
            self.assertEqual([{k: v for k, v in r.items() if k != "reused"} for r in rows], clean)
            self.assertTrue(all("reused" not in r for r in clean))

    def test_resume_can_be_chained_after_another_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_recorded([Response(), http_error(502), http_error(502), http_error(502)], directory)
            error, second, send = self.resume("run", [Response(), TimeoutError(), TimeoutError(), TimeoutError()], directory, "second")
            self.assertIsInstance(error, TimeoutError)
            self.assertEqual(send.call_count, 4)
            self.assertEqual(len([r for r in second if "decision" in r]), 2)  # one reused, one new answer
            (rows, summary), _, send = self.resume("second", [Response()], directory, "third")
            self.assertEqual((send.call_count, summary["api_calls"], summary["reused_answers"]), (1, 1, 2))
            self.assertTrue(all(r["related"] for r in rows))
            # A twice-reused answer still reports when Jev originally answered it, not when it was reused.
            first = [json.loads(line) for line in (Path(directory) / "run" / "attempts.jsonl").read_text().splitlines()]
            new_in_second = next(r for r in second if "decision" in r and "reused_from" not in r)
            self.assertEqual({r["id"]: r["reused"]["answered_utc"] for r in rows if "reused" in r},
                             {next(r for r in first if "decision" in r)["candidate_id"]: next(r for r in first if "decision" in r)["completed_utc"],
                              new_in_second["candidate_id"]: new_in_second["completed_utc"]})

    def test_resume_never_reuses_mismatched_or_unanswered_records(self):
        with tempfile.TemporaryDirectory() as directory:
            (rows, _), records = self.run_recorded([Response() for _ in range(3)], directory)
            good = [r for r in records if "decision" in r]
            self.assertEqual(len(good), 3)
            # Changed analyst context changes every request: nothing is reused.
            (_, summary), _, send = self.resume("run", [Response() for _ in range(3)], directory, "other-context", "different")
            self.assertEqual((send.call_count, summary["reused_answers"]), (3, 0))
            base = good[0]
            variants = [
                dict(base, surrounding_ids=base["surrounding_ids"] + ["extra"]),
                dict(base, known_related_ids=["child"]),
                dict(base, **{"pass": 2}),
                dict(base, candidate_id="unrelated"),
                dict(base, request_sha256="0" * 64),
                {k: v for k, v in base.items() if k != "request_sha256"},  # written before request hashing
                dict(base, answers={"related": {"noul": 1.5}, "evidence": {"choice": "lineage"}}),
                dict(base, answers={"related": {"noul": True}, "evidence": {"choice": "lineage"}}),
                dict(base, answers={"related": {"noul": 0.9}, "evidence": {"choice": "made_up"}}),
                dict(base, answers=None),
                {"type": "failed_request", "candidate_id": base["candidate_id"], "request_attempt": 3, "error": "HTTP 520",
                 "retrying": False, "decision": base["decision"], "pass": 1, "known_related_ids": [], "surrounding_ids": [],
                 "request_sha256": base["request_sha256"], "answers": base["answers"]},
            ]
            tampered = Path(directory) / "tampered"
            tampered.mkdir()
            lines = [json.dumps(v) for v in variants] + [json.dumps(base)[:-20]]  # plus a truncated final line
            (tampered / "attempts.jsonl").write_text("\n".join(lines) + "\n")
            # Unanswered, invalid, legacy and truncated lines are dropped; the rest load but match no request.
            self.assertEqual(len(poc.load_resume(tampered)), 5)
            (_, summary), _, send = self.resume("tampered", [Response() for _ in range(3)], directory, "from-tampered")
            self.assertEqual((send.call_count, summary["reused_answers"]), (3, 0))

    def test_resume_requires_existing_log_and_new_run_dir(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "new"
            with self.assertRaises(FileNotFoundError):
                poc.recorded_run(self.events, "seed", "confirmed", "test-key", "jev-1.13.0", 0.8, target, SAMPLE,
                                 resume_from=Path(directory) / "missing")
            self.assertFalse(target.exists())
            argv = ["jev_incident.py", str(SAMPLE), "--seed-id", "seed", "--description", "x", "--resume-run", directory]
            with patch.object(poc.sys, "argv", argv), patch("sys.stderr"), self.assertRaises(SystemExit) as exit_:
                poc.main()
            self.assertEqual(exit_.exception.code, 2)


class EngineGoldenTests(unittest.TestCase):
    def test_browser_engine_reference_matches_python(self):
        # ui/test_engine.js checks the JavaScript port against the same file.
        self.assertEqual(json.loads(GOLDEN.read_text(encoding="utf-8")), engine_golden(),
                         'jev_incident.py changed; if intended run: python3 -c "import test_jev_incident as t; t.write_golden()"')

    def test_reference_exercises_both_passes(self):
        passes = {json.loads(r)[0] for r in engine_golden()["edge_cases"]["requests"]}
        self.assertEqual(passes, {1, 2})


if __name__ == "__main__":
    unittest.main()
