#!/usr/bin/env python3
"""Small Jev incident-linking experiment. No third-party dependencies."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from time import perf_counter, sleep
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API = "https://api.typesafe.ai/v1/systemone"
# Private KEY=VALUE file next to this script; real environment variables take precedence.
ENV_FILE = Path(__file__).resolve().parent / ".env"
QUESTION = "Is `candidate` related to the same incident as `seed` and `known_related`?"
# Temporary TypeSafe failures (5xx, timeouts) get at most this many extra tries.
RETRY_BACKOFF_SECONDS = (1.0, 2.0)
FIELDS = ("name", "executable", "command_line", "pid", "entity_id", "parent", "ancestry")


def fields_source(fields):
    """Project Elasticsearch fields-only hits into a small nested ECS shape."""
    def one(key):
        value = fields.get(key)
        return value[0] if isinstance(value, list) and value else value if not isinstance(value, list) else None
    process = {k: one("process." + k) for k in ("name", "executable", "command_line", "pid", "entity_id", "sha256")}
    parent = {k: one("process.parent." + k) for k in ("name", "pid", "entity_id", "command_line")}
    process = {k: v for k, v in process.items() if v is not None}
    if any(v is not None for v in parent.values()):
        process["parent"] = {k: v for k, v in parent.items() if v is not None}
    return {"@timestamp": one("@timestamp"),
            "event": {"category": fields.get("event.category", []), "type": fields.get("event.type", []),
                      "action": one("event.action"), "id": one("event.id")},
            "host": {"name": one("host.name")}, "user": {"name": one("user.name")},
            "process": process,
            "file": {"path": one("file.path"), "name": one("file.name")},
            "destination": {"ip": one("destination.ip"), "domain": one("destination.domain"), "port": one("destination.port")},
            "dns": {"question": {"name": one("dns.question.name")}},
            "registry": {"path": one("registry.path"), "value": one("registry.value")},
            "target": {"image": one("winlog.event_data.TargetImage"),
                       "entity_id": one("winlog.event_data.TargetProcessGUID")}}


def timestamp(value):
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    try:
        text = str(value).replace("Z", "+00:00")
        # Python < 3.11 parses only 3 or 6 fractional digits; EDR exports often carry 7 (e.g. .9045099).
        text = re.sub(r"([T ]\d{2}:\d{2}:\d{2})\.(\d+)", lambda m: f"{m.group(1)}.{m.group(2)[:6]:0<6}", text, count=1)
        parsed = datetime.fromisoformat(text)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except (ValueError, TypeError):
        return None


def compact(raw):
    src = raw.get("_source") or (fields_source(raw["fields"]) if isinstance(raw.get("fields"), dict) else raw)
    proc = src.get("process") or {}
    event = src.get("event") or {}
    host = src.get("host") or {}
    user = src.get("user") or {}
    dest = src.get("destination") or {}
    file = src.get("file") or {}
    action = event.get("action", src.get("action", src.get("kind", "")))
    if isinstance(action, list):
        action = ",".join(action)
    category = event.get("category", "")
    if isinstance(category, list):
        category = ",".join(category)
    selected_process = {k: proc[k] for k in FIELDS if k in proc and k != "parent"}
    if isinstance(proc.get("parent"), dict):
        selected_process["parent"] = {k: proc["parent"][k] for k in ("name", "pid", "entity_id", "command_line") if k in proc["parent"]}
    if "ancestry" not in selected_process and isinstance(proc.get("Ext"), dict):
        if "ancestry" in proc["Ext"]:
            selected_process["ancestry"] = proc["Ext"]["ancestry"]
    if isinstance(proc.get("hash"), dict) and proc["hash"].get("sha256"):
        selected_process["sha256"] = proc["hash"]["sha256"]
    elif proc.get("sha256"):
        selected_process["sha256"] = proc["sha256"]
    out = {
        "id": str(raw.get("id") or raw.get("_id") or src.get("id") or event.get("id") or ""),
        "time": src.get("@timestamp") or src.get("timestamp") or src.get("time"),
        "kind": src.get("kind") or category or event.get("dataset", ""),
        "action": action,
        "event_type": event.get("type", []),
        "host": host.get("name") if isinstance(host, dict) else host,
        "user": user.get("name") if isinstance(user, dict) else user,
        "process": selected_process,
        "file": {k: file[k] for k in ("path", "name", "hash") if k in file},
        "destination": {k: dest[k] for k in ("ip", "domain", "port") if k in dest},
        "source": src.get("source", {}),
        "target": src.get("target", {}),
        "dns": src.get("dns", {}),
        "registry": src.get("registry", {}),
    }
    if not out["process"] and src.get("name"):
        out["process"] = {k: src[k] for k in FIELDS if k in src}
    return {k: v for k, v in out.items() if v not in (None, "", {}, [])}


def is_execution(event):
    kind = str(event.get("kind", "")).lower()
    action = str(event.get("action", "")).lower()
    event_types = event.get("event_type", [])
    return bool(event.get("process")) and (
        kind == "execution" or
        ("process" in kind and ("start" in event_types or any(x in action.split(",") for x in ("start", "exec", "fork", "create", "process_started", "created-process", "process creation")))) or
        ("sysmon" in kind and action in ("1", "process create"))
    )


def related_evidence(candidate, other):
    """Select context, not verdicts. Avoid PID-only joins when entity IDs exist."""
    a, b = candidate.get("process", {}), other.get("process", {})
    if candidate.get("host") != other.get("host") or not candidate.get("host"):
        return False
    ids = {str(x) for x in (a.get("entity_id"), a.get("parent", {}).get("entity_id") if isinstance(a.get("parent"), dict) else None) if x}
    other_ids = {str(x) for x in (b.get("entity_id"), b.get("parent", {}).get("entity_id") if isinstance(b.get("parent"), dict) else None) if x}
    if ids & other_ids:
        return True
    ta, tb = timestamp(candidate.get("time")), timestamp(other.get("time"))
    if ta and tb and abs((ta - tb).total_seconds()) <= 600:
        # Same-host nearby events are context only; Jev decides whether relevant.
        return True
    return False


def context(events, candidate, limit=8):
    matches = [e for e in events if e["id"] != candidate["id"] and related_evidence(candidate, e)]
    def rank(e):
        a = timestamp(e.get("time")); b = timestamp(candidate.get("time"))
        return abs((a - b).total_seconds()) if a and b else float("inf")
    return sorted(matches, key=rank)[:limit]


def retryable(exc):
    """Only temporary server errors and timeouts are retried; 4xx such as 401 never are."""
    if isinstance(exc, HTTPError):
        return 500 <= exc.code <= 599
    if isinstance(exc, URLError):
        return isinstance(exc.reason, TimeoutError)
    return isinstance(exc, TimeoutError)


def failure_label(exc):
    return f"HTTP {exc.code}" if isinstance(exc, HTTPError) else "timeout" if retryable(exc) else type(exc).__name__


QUESTIONS = {
    "related": {"type": "noul", "instructions": QUESTION,
                "criteria": {"true": "Same incident, supported by telemetry links or shared artifacts",
                             "false": "Independent activity or insufficient evidence to link"}},
    "evidence": {"type": "choice", "instructions": "What is the strongest observed basis for the incident-link decision about `candidate`?",
                 "criteria": {"lineage": "Parent/child lineage or process identifier link",
                              "interaction": "Injection or direct process interaction",
                              "artifact": "Shared file, command, or network artifact",
                              "user_host_time": "User, host, and time context without a stronger link",
                              "no_link": "No convincing link in the supplied telemetry"}},
}


def request_body(state, model):
    """Exact bytes sent to Jev for one candidate (the API key travels only in a header)."""
    return json.dumps({"model": model, "state": state, "questions": QUESTIONS}).encode()


def parse_answers(answers):
    """Validate Jev answers; raise instead of guessing when they are unusable."""
    probability = answers["related"]["noul"]
    evidence = answers["evidence"]["choice"]
    if (isinstance(probability, bool) or not isinstance(probability, (int, float)) or not 0 <= probability <= 1
            or evidence not in QUESTIONS["evidence"]["criteria"]):
        raise ValueError("Invalid Jev answer")
    return probability, evidence


def jev(state, key, model, metadata=None, on_failure=None):
    """Ask Jev about one candidate.

    Temporary 5xx errors and timeouts are retried up to len(RETRY_BACKOFF_SECONDS)
    times. on_failure(attempt_number, exc, retrying, backoff_seconds) is called for
    each failed request. If retries run out, the last error is re-raised with an
    ``attempts`` attribute; no answer is assumed.
    """
    body = request_body(state, model)
    request = Request(API, data=body, headers={"Authorization": "Bearer " + key,
                                                 "Content-Type": "application/json"})
    for attempt_number in range(1, len(RETRY_BACKOFF_SECONDS) + 2):
        try:
            with urlopen(request, timeout=30) as response:
                result = json.load(response)
            break
        except (HTTPError, URLError, TimeoutError) as exc:
            retrying = retryable(exc) and attempt_number <= len(RETRY_BACKOFF_SECONDS)
            backoff = RETRY_BACKOFF_SECONDS[attempt_number - 1] if retrying else None
            if on_failure is not None:
                on_failure(attempt_number, exc, retrying, backoff)
            if not retrying:
                exc.attempts = attempt_number
                raise
            if isinstance(exc, HTTPError):
                exc.close()
            sleep(backoff)
    answers = result["answers"]
    probability, evidence = parse_answers(answers)
    if metadata is not None:
        metadata.update({"model": result.get("model"), "usage": result.get("usage", {}),
                         "request_bytes": len(body), "answers": answers})
    return probability, evidence


def run(events, seed_id, description, judge, threshold=0.8, observer=None, lookup=None):
    """lookup(pass_number, state) may return a previously answered (probability, evidence)
    for this exact request, or None to ask judge(state)."""
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be between 0 and 1")
    events = [compact(e) for e in events]
    ids = [e.get("id") for e in events]
    if not all(ids) or len(ids) != len(set(ids)):
        raise ValueError("Every event needs a unique id or _id")
    by_id = {e["id"]: e for e in events}
    if seed_id not in by_id or not is_execution(by_id[seed_id]):
        raise ValueError("seed id must identify an execution event")
    seed = by_id[seed_id]
    candidates = [e for e in events if e["id"] != seed_id and is_execution(e)]
    candidates.sort(key=lambda e: (timestamp(e.get("time")) or datetime.min.replace(tzinfo=timezone.utc), e["id"]))
    known = [seed]
    results = {seed_id: {"id": seed_id, "execution": seed.get("process", {}).get("name", seed_id), "related": True, "probability": 1.0, "reason": "Confirmed starting execution (user-provided)"}}
    # Reconsider negatives once after new high-confidence links are discovered.
    for pass_number in range(2):
        newly_related = False
        for e in candidates:
            if e["id"] in results and results[e["id"]]["related"]:
                continue
            if pass_number and not newly_related and len(known) == 1:
                break
            state = {"seed_description": description, "seed": seed,
                     "known_related": known[1:][-6:], "candidate": e,
                     "surrounding": context(events, e)}
            answer = lookup(pass_number + 1, state) if lookup is not None else None
            probability, evidence = answer if answer is not None else judge(state)
            related = probability >= threshold
            results[e["id"]] = {"id": e["id"], "execution": e.get("process", {}).get("name", e["id"]),
                                "related": related, "probability": probability,
                                "reason": evidence.replace("_", " ") + " (Jev-selected category; not generated prose)"}
            if observer is not None:
                observer(pass_number + 1, state, results[e["id"]])
            if related:
                known.append(e)
                newly_related = True
        if not newly_related:
            break
    return [results[seed_id]] + [results[e["id"]] for e in candidates]


def read_key(path, name):
    """NAME's value in a private KEY=VALUE file (a .env file or a one-line key file), or None.

    The file must not be readable by other users (chmod 600). Windows has no such mode bits.
    """
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError(f"{path.name} must be private; run: chmod 600 {path.name}")
    value = None
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        match = re.fullmatch(r"\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*?)\s*", line)
        if match and match.group(1) == name:
            raw = match.group(2)
            quoted = len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'"
            value = raw[1:-1] if quoted else re.split(r"\s+#", raw)[0]
    return value or None


def load_key_file(path, name="TYPESAFE_API_KEY"):
    key = read_key(path, name)
    if not key:
        raise ValueError(f"{path.name} must contain a {name}=... line")
    return key


def find_key(name, key_file=None, env_file=ENV_FILE):
    """API key NAME from an explicit key file, else the environment, else the .env file; None if unset."""
    if key_file is not None:
        return load_key_file(key_file, name)
    if os.environ.get(name):
        return os.environ[name]
    if env_file is not None and env_file.is_file():
        return read_key(env_file, name)
    return None


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def private_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def _ids(value):
    return tuple(value) if isinstance(value, list) and all(isinstance(i, str) for i in value) else None


def load_resume(run_dir):
    """Answered Jev calls from an earlier (usually failed) run's attempts.jsonl.

    Returns {(candidate_id, pass, known_related_ids, surrounding_ids, request_sha256):
    ((probability, evidence), record)}. Only complete decision records with valid
    answers and an exact request hash are kept; failed_request lines, truncated
    lines and records written before request hashing are ignored, so a call that
    was never answered can never be treated as answered.
    """
    answered = {}
    with open(Path(run_dir) / "attempts.jsonl", encoding="utf-8") as stream:
        for line in stream:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or "type" in record or not isinstance(record.get("decision"), dict):
                continue
            candidate_id, pass_number, digest = record.get("candidate_id"), record.get("pass"), record.get("request_sha256")
            known, surrounding = _ids(record.get("known_related_ids")), _ids(record.get("surrounding_ids"))
            if not isinstance(candidate_id, str) or type(pass_number) is not int or not isinstance(digest, str) \
                    or known is None or surrounding is None:
                continue
            try:
                answer = parse_answers(record.get("answers"))
            except (KeyError, TypeError, ValueError):
                continue
            answered.setdefault((candidate_id, pass_number, known, surrounding, digest), (answer, record))
    return answered


def answered_utc(record):
    """When Jev originally answered a logged decision, following chained resumes back to the
    first answer. Returns None when the log does not say."""
    earlier = record.get("reused_from")
    if isinstance(earlier, dict):
        for key in ("answered_utc", "completed_utc"):
            if isinstance(earlier.get(key), str):
                return earlier[key]
        return None
    value = record.get("completed_utc")
    return value if isinstance(value, str) else None


def recorded_run(events, seed_id, description, key, model, threshold, run_dir, telemetry_file, resume_from=None,
                 run_info=None):
    """Keep every API attempt and each final related event in a private run directory.

    With resume_from, answers logged by that earlier run are reused only when the
    candidate, pass, submitted context IDs and the exact request bytes match; every
    other candidate is sent to Jev. The new run_dir logs reused answers too (marked
    ``reused_from``), so it can itself be resumed. Each returned row decided by a reused
    answer carries ``reused: {"answered_utc": ...}`` (original answer time, no path).

    run_info (a JSON object) is written to run_dir/run.json before any Jev call, so a
    caller can find this run again after a crash, restart or lost response.
    """
    previous = load_resume(resume_from) if resume_from is not None else {}
    run_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    if run_info is not None:
        private_json(run_dir / "run.json", {**run_info, "resumed_from": str(resume_from) if resume_from is not None else None})
    attempts = []
    latest = {}
    metadata = {}
    timing = {}
    started_utc = utc_now()
    started = perf_counter()

    retries = []

    with os.fdopen(os.open(run_dir / "attempts.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        def write(record):
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

        def judge(state):
            metadata.clear()
            call_start = perf_counter()

            def on_failure(attempt_number, exc, retrying, backoff):
                # Failed requests are logged separately from decisions; they carry no answer.
                record = {"type": "failed_request", "candidate_id": state["candidate"]["id"],
                          "request_attempt": attempt_number, "error": failure_label(exc),
                          "retrying": retrying, "backoff_seconds": backoff,
                          "completed_utc": utc_now(), "elapsed_seconds": perf_counter() - call_start}
                if retrying:
                    retries.append(record)
                write(record)

            answer = jev(state, key, model, metadata, on_failure)
            timing["elapsed_seconds"] = perf_counter() - call_start
            timing["completed_utc"] = utc_now()
            return answer

        def lookup(pass_number, state):
            digest = hashlib.sha256(request_body(state, model)).hexdigest()
            timing.clear()
            timing["request_sha256"] = digest
            hit = previous.get((state["candidate"]["id"], pass_number,
                                tuple(e["id"] for e in state["known_related"]),
                                tuple(e["id"] for e in state["surrounding"]), digest))
            if hit is None:
                return None
            timing["reused"] = hit[1]
            return hit[0]

        def observe(pass_number, state, decision):
            reused = timing.get("reused")
            source = reused if reused is not None else metadata
            attempt = {"candidate_id": decision["id"], "pass": pass_number,
                       "completed_utc": utc_now() if reused is not None else timing["completed_utc"],
                       "elapsed_seconds": 0.0 if reused is not None else timing["elapsed_seconds"],
                       "decision": dict(decision), "model": source.get("model"),
                       "usage": source.get("usage"), "request_bytes": source.get("request_bytes"),
                       "answers": source.get("answers"),
                       "known_related_ids": [e["id"] for e in state["known_related"]],
                       "surrounding_ids": [e["id"] for e in state["surrounding"]],
                       "request_sha256": timing["request_sha256"]}
            if reused is not None:
                # Not a new Jev call: the answer was logged by the earlier run.
                attempt["reused_from"] = {"run_dir": str(resume_from), "completed_utc": reused.get("completed_utc"),
                                          "answered_utc": answered_utc(reused)}
            attempts.append(attempt)
            latest[decision["id"]] = (attempt, state)
            write(attempt)

        rows = run(events, seed_id, description, judge, threshold, observe, lookup)
    # Mark each final decision whose Jev answer came from an earlier run. Only the time of the
    # original answer is exposed here; the earlier run's private directory stays in attempts.jsonl.
    rows = [dict(row, reused={"answered_utc": latest[row["id"]][0]["reused_from"]["answered_utc"]})
            if row["id"] in latest and "reused_from" in latest[row["id"]][0] else row for row in rows]
    fresh = [a for a in attempts if "reused_from" not in a]

    elapsed = perf_counter() - started
    evidence_dir = run_dir / "evidence"
    evidence_dir.mkdir(mode=0o700)
    source_events = {compact(e)["id"]: e for e in events}
    private_json(evidence_dir / "seed.json", {"confirmed_by_user": True,
                 "event": compact(source_events[seed_id]), "source_event": source_events[seed_id]})
    for index, row in enumerate(rows[1:], 1):
        if row["related"]:
            attempt, state = latest[row["id"]]
            private_json(evidence_dir / f"{index:03d}.json", {
                "decision": row, "attempt": attempt, "candidate": state["candidate"],
                "source_event": source_events[row["id"]],
                "seed": state["seed"], "known_related": state["known_related"],
                "surrounding": state["surrounding"]})
    private_json(run_dir / "decisions.json", rows)
    summary = {"started_utc": started_utc, "finished_utc": utc_now(),
               "elapsed_seconds": elapsed, "api_elapsed_seconds": sum(a["elapsed_seconds"] for a in fresh),
               "api_calls": len(fresh), "reused_answers": len(attempts) - len(fresh),
               "resumed_from": str(resume_from) if resume_from is not None else None,
               "retried_requests": len(retries), "evaluated_candidates": len(rows) - 1,
               "related_candidates": sum(r["related"] for r in rows[1:]),
               "input_tokens": sum((a["usage"] or {}).get("input_tokens", 0) for a in fresh),
               "output_tokens": sum((a["usage"] or {}).get("output_tokens", 0) for a in fresh),
               "request_bytes": sum(a["request_bytes"] or 0 for a in fresh),
               "seed_id": seed_id, "model_requested": model, "threshold": threshold,
               "evidence_dir": str(evidence_dir), "telemetry_file": str(telemetry_file),
               "telemetry_sha256": hashlib.sha256(Path(telemetry_file).read_bytes()).hexdigest()}
    private_json(run_dir / "summary.json", summary)
    return rows, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("telemetry", type=Path, help="JSON array or object with events array")
    parser.add_argument("--seed-id", required=True, help="exact event id of confirmed execution")
    parser.add_argument("--description", required=True, help="short confirmed-malicious starting context")
    parser.add_argument("--threshold", type=float, default=0.8)
    parser.add_argument("--model", default="jev-1.13.0")
    parser.add_argument("--key-file", type=Path, help="private file containing TYPESAFE_API_KEY=... (mode 600); "
                        "default: the TYPESAFE_API_KEY environment variable, then .env")
    parser.add_argument("--output", type=Path, help="optional JSON decisions file")
    parser.add_argument("--run-dir", type=Path, help="new private directory for timing and related-event evidence")
    parser.add_argument("--resume-run", type=Path, help="earlier --run-dir whose answered Jev calls are reused when the exact "
                        "request matches; the rest are sent to Jev (requires a new --run-dir)")
    args = parser.parse_args()
    if args.resume_run and not args.run_dir:
        parser.error("--resume-run requires a new --run-dir for the resumed run")
    try:
        data = json.loads(args.telemetry.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        parser.error(f"cannot read telemetry JSON from {args.telemetry}: {exc}")
    if isinstance(data, dict):
        data = data.get("events")
    if not isinstance(data, list):
        parser.error("telemetry must be a JSON array of events or an object with an events array")
    try:
        key = find_key("TYPESAFE_API_KEY", args.key_file)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if not key:
        parser.error("no TypeSafe API key found; add TYPESAFE_API_KEY to .env (or run: python3 web_app.py --setup-keys) "
                     "or set it in the environment")
    summary = None
    try:
        if args.run_dir:
            rows, summary = recorded_run(data, args.seed_id, args.description, key, args.model,
                                         args.threshold, args.run_dir, args.telemetry, args.resume_run)
        else:
            rows = run(data, args.seed_id, args.description, lambda state: jev(state, key, args.model), args.threshold)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        hint = ""
        if args.run_dir and (args.run_dir / "attempts.jsonl").is_file() and not (args.run_dir / "summary.json").exists():
            hint = f"; answered Jev calls are kept, resume with --resume-run {args.run_dir} --run-dir <new dir>"
        parser.error(str(exc) + hint)
    print(f'{"Execution (event id)":48} Related  Probability  Reason')
    for row in rows:
        print(f'{(row["execution"] + " (" + row["id"] + ")")[:48]:48} {"YES" if row["related"] else "NO ":7} {row["probability"]:9.0%}  {row["reason"]}')
    if args.output:
        args.output.write_text(json.dumps(rows, indent=2) + "\n")
    if summary is not None:
        reused = f', {summary["reused_answers"]} reused from {summary["resumed_from"]}' if summary["resumed_from"] else ''
        print(f'Timed run: {summary["elapsed_seconds"]:.3f}s total, {summary["api_calls"]} API calls{reused}; evidence: {summary["evidence_dir"]}')


if __name__ == "__main__":
    main()
