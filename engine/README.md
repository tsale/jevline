# Jevline engine

Give it log files and something you've confirmed as malicious: a process, an IP address, a domain, an account or a host. It returns the incident and a timeline of everything in it:
- every process that continued the malicious execution chain;
- every account, host, address and domain the attacker's activity went through;
- how each one is connected.

It reads hundreds of thousands of events per second. Jev makes every judgment call, but it's only asked about processes that telemetry actually connects to the incident, so the number of Jev calls grows with the size of the incident, not with the size of the logs.

> [!NOTE]
> This is the new engine (TypeScript, no runtime dependencies). It runs alongside the original Python engine and portal in the repository root, which will switch over to it in the next milestone.

## Quick start

You need Node.js 22.18 or newer. There's nothing to build or install.

```bash
node engine/src/cli.ts inspect export.ndjson --find 2.8.exe
node engine/src/cli.ts analyze export.ndjson --seed name:2.8.exe \
  --context "Analyst-confirmed 2.8.exe execution on CLA-WS-214." --out runs/2.8
```

- `inspect` parses the input and reports what it found (sources, event kinds, processes, links, timings) without calling Jev. With `--find <image>` it lists every start of that image with an ID you can use as the seed.
- `analyze` runs the investigation and prints the incident in time order with how each process joined and Jev's probability. `--out` writes `report.json` and `requests.jsonl`, which holds every exact request sent to Jev.
- `--offline` swaps Jev for a stand-in that scores links by type only. Use it to try the engine or measure speed; its results are labelled and are not Jev decisions.

The seed can be a process (an event ID such as `line-12057` or the export's own `_id`, `name:<image>` for its earliest start, or `guid:<ID>` with any source's process ID, such as a Sysmon GUID or an Elastic Defend `entity_id`) or another entity: `ip:198.51.100.66`, `domain:evil.example`, `user:svc_backup` or `host:srv-01`. The TypeSafe key comes from `TYPESAFE_API_KEY`, or from a private `.env` file (`chmod 600`) given with `--key-file`, in the current directory, or in the repository root.

| Option | Default | |
|---|---|---|
| `--threshold` | `0.8` | Jev probability that links a process |
| `--batch` | `1` | Candidates per Jev request. Larger batches use fewer tokens, but other candidates in the request sway Jev (see [Batching](#batching)) |
| `--margin` | `0.05` | Mark decisions this close to the threshold "review" |
| `--concurrency` | `8` | Jev requests in flight |
| `--rounds` | `20` | Most expansion rounds |
| `--max-candidates` | `2000` | Stop, and say so, if one round would ask more questions than this |
| `--cache <file>` | | Reuse and record Jev answers by request hash; a repeated run is exact and free |
| `--ungrouped` | | Ask about every process separately, even ones identical apart from PID and time |
| `--format` | `auto` | `json`, `ndjson`, `csv` or `text` instead of detecting it |
| `--threads` | up to 8 | Cores used to parse large files |

## Input

Pass one file or several. They're combined, and a record that appears in two files counts once, so overlapping exports and Sysmon and Security exported separately are both fine.

**Formats.** These are detected from the first line:

- JSON: an array of events, `{"events": [...]}`, or an Elasticsearch search response.
- NDJSON.
- CSV or TSV with a header row.
- Plain text, one event per line: `key=value` pairs become fields, and a leading ISO 8601 time becomes the event time.

Records without an ID get `line-N`, their line in the file.

**Any log schema.** The engine doesn't need to know a log source in advance.

- **Built-in sources, no questions asked.** Windows event logs (Sysmon, Security, System and any other channel) and ECS data such as Elastic Defend are read with built-in rules. In Windows channels, event IDs the engine doesn't use are irrelevant, not unknown.
- **Everything else is learned from Jev, once per event type.** That covers other EDRs (Defender for Endpoint, CrowdStrike…), SIEM exports, cloud audit logs and anything structured.
  - Records are grouped by the field that names their event type (`ActionType`, `event_simpleName`, `EventID`…), or by their set of fields.
  - Jev gets a few example values per field, tagged by shape: time, IP, GUID, hash, path, small or large integer, and so on.
  - It answers two small questions: what kind of event this is (process start, injection, file write, network, registry…), then what each field holds, from a menu written for that kind of event.

  For a process start the menu offers the new process and the process that created it. For an injection it offers the process that injected and the process injected into. That matches how EDRs name things: `InitiatingProcess*` in Defender, `ContextProcessId` / `TargetProcessId` in CrowdStrike.
- **The mapping is applied to every record by plain code.** Cost grows with the number of event types, not records. Mappings are kept in `~/.jevline/schemas.jsonl` (`--schemas` to change it) by a fingerprint of the event type and its fields, so the same source costs nothing the next time.
- **What to expect.** The schemas live-tested below took 12–14 small requests, about 0.3 s.
- **Every mapping is in the report.** A process field that only ever holds long numbers (9 digits or more) is treated as a unique ID, not a PID. Anything that looked uncertain is listed: a field Jev was less than 50% sure of, two fields claiming one role, no time field, or started processes whose parents never appear. `inspect` shows the mappings already learned and never calls Jev.

Without a unique process ID, a process is identified by its PID and creation time, as Defender reports them. Paths match however the volume is written (`C:\…` or `\Device\HarddiskVolume3\…`). Times can be ISO 8601 (no offset means UTC, as Sysmon's `UtcTime` is) or epoch seconds, milliseconds, microseconds, nanoseconds or Windows FILETIME, whichever gives a plausible date. Locale formats such as `9/21/2026 5:18:50 PM` are refused rather than read in this machine's time zone.

**Tested schemas.** The shared test incident is rendered as Sysmon, as Defender for Endpoint Advanced Hunting CSVs (five tables) and as CrowdStrike Falcon FDR events. Offline, all three must find the same incident. Live with Jev (October 2026), all three found the same incident:
- Jev mapped every Defender and CrowdStrike field the investigation needs correctly;
- the same three processes were linked from each source;
- `cmd.exe` scored 0.76–0.79 in each, just under the threshold.

## How it works

```
files ─▶ read ─▶ normalize ─▶ processes ─▶ links ─▶ rounds of Jev questions ─▶ incident + timeline
         (parallel) (one model)   (identity)   (typed)    (parallel, cached)
```

1. **Read and normalize.** Large files are parsed on several cores in byte ranges and reassembled exactly as a single reader would produce them. Every record becomes one canonical event: kind, time, host, acting process, target process, file, registry value, pipe or network destination.
2. **Processes.** A process is identified by host and GUID when the source has one, otherwise by host, PID and start time.
   - **PID reuse:** each PID's lifetimes are tracked, so a reused PID never joins two processes.
   - **Twin records:** a Security 4688 and the Sysmon 1 of the same start are merged into one process, so a source with GUIDs and one without describe it the same way.
   - **GUIDs seen late:** when Sysmon doesn't log process creation, a process starts in Security 4688 (no GUID) and its later Sysmon events carry a GUID. That GUID joins the process running with that PID and image at the time.
   - **Two sources, two GUIDs:** Sysmon and an EDR such as Elastic Defend name the same process with different IDs. The ID from the second source joins the process the first already named, if it has the same host, PID and image at the same time (two live processes never share a PID). Within one source, a different GUID is always a different process. Combining the Elastic Defend and Windows exports of CLA-WS-214 gives 25,705 processes, against 25,673 for the Windows logs alone, rather than about 51,000.
   - **Processes that started before the logs** may be mentioned by PID earlier than by GUID, and are still recognised as one process.
3. **Links.** These are every observed way the attack can move. Between processes:

   | Link | From |
   |---|---|
   | `spawned` | parent and child |
   | `injected` | Sysmon 8, EDR injection APIs |
   | `opened_for_injection` | a handle with VM write and operation, create thread, or full access (credential reads such as `0x1410` are activity, not links) |
   | `dropped_and_ran` | the last process to write the file (or one with the same SHA-256) a process started from |
   | `dropped_and_loaded` | the last process to write a DLL another process loaded |
   | `pipe` | the creator and a client of a named pipe |
   | `persisted_and_ran` | a Run key, Winlogon or logon-script value, service, scheduled task or IFEO entry, linked to the next start of the payload it launches |

   Between processes and the accounts, hosts, addresses and domains in logs without processes (authentication, firewall, proxy, DNS, web server). These are followed both ways, so a C2 address reached from an incident process leads to every later process or host that contacts it:

   | Link | From |
   |---|---|
   | `contacted` | a process connected to or looked up an address or domain; or, in a firewall flow with no process, a host or address connected to one |
   | `logged_on` | an account logged on to a host |
   | `logon_from` | a logon to a host came from an address or another host |
   | `used_account` / `failed_logon` | an address logged on (or failed to) as an account |
   | `requested` | an address sent web requests to a server |

   An internal address is the host it belongs to whenever any event says so (a record's `host.ip`, a logon's target address). Loopback addresses and built-in identities (`SYSTEM`, machine accounts ending in `$`) are left out.

4. **Rounds.** Starting from the seed, each round collects every process that a link connects to the incident, asks Jev about all of them, and adds the ones Jev links. It stops when a round adds nothing.
   - **Causality:** a process can only pass the incident on through what it did after it joined. A child that explorer.exe started before 2.8.exe injected into it is never even a candidate.
   - **Re-asking:** a process Jev rejected is asked again only if new links reach it.
5. **Questions.** Each candidate gets its own request with one Noul: "part of the same incident, continuing its malicious execution chain?". Jev isn't asked for a basis: the links already record exactly how a process is connected, and in the live check a Choice between overlapping bases changed between identical requests. It sees:
   - the seed;
   - the incident processes the candidate's links come from, and when each joined;
   - the links themselves;
   - samples of what the candidate did after it was linked, with executables, scripts and persistence keys first.

   Candidates that would look identical to Jev apart from PID and start time (for example 1,350 relaunches of one beacon) share one question that says how many there are.
   An account, host, address or domain is shown with its **prevalence**: how many processes, hosts, accounts and addresses touched it across the whole input. That lets Jev tell common infrastructure (a public resolver, a search engine) from addresses only the incident touched. A link seen many times shows how often and until when (a beacon's hundreds of connections), and it counts for causality if any of it came after the incident side joined.
6. **Review flags.** Jev's answer to an identical request varies by up to about 0.05. Decisions within `--margin` of the threshold are marked `review`, because a fresh run without the cache could decide them the other way.
7. **Repeats folded.** The same activity repeated without any meaningful change is reported once: a beacon, a brute force, a scheduled relaunch.
   - **Timeline:** a process's events count from when it joined, so an injected explorer.exe's earlier activity isn't listed. Each run of the same activity is one row, with `count`, `until`, `every_s` (the usual interval) and `last_event_id`. "The same" means the same host, kind, process and detail. A different destination, domain, account, registry value or process makes a new row, and so does activity that resumes after a quiet hour (or three times its usual interval, for slower cycles).
   - **Incident and rejected lists:** identical processes are one row with `repeats`: the count, the last start, and every other member's key, PID and start. They must have the same executable, user and hash, the same (or an identical) parent, and the same links into the incident. `unfold()` gives every member back.
   - **Changing parts:** numbers and generated tokens don't count as a change in a process's folder and arguments, in registry key paths, or in the names of files that aren't executables. Examples are installers rerun from `is-OB9B3JUD4C.tmp`, cache entries `f_00a1b2`, handles such as `$8D0572`, and `RecentDocs\12`. Such rows say how many `variants` they stand for. Executable names and registry values are always compared exactly, so two dropped payloads stay two rows.

   On the CLA-WS-214 exports (Elastic Defend and Windows logs, live), 1,495 incident members become 99 rows and 21,795 events become 2,512 timeline rows. What's left is mostly distinct work, such as three PyInstaller payloads each unpacking 96 different modules.

## Reproducibility

The same incident should give the same result whatever telemetry it arrives in, and the same input should give the same result every time.

- **No source-specific values in requests.** Processes are labelled `seed`, `I1…` and `C1…` within each request. Times are relative to the seed in whole seconds, and hosts and users are in one canonical form. GUIDs, record IDs and file positions are never sent.
- **Deterministic order.** Candidates, links, batches and samples are ordered by time, then names, never by input order or completion order. Concurrency can't change the results, because each round's requests depend only on the decisions of the rounds before it.
- **One candidate per request.** Each decision rests only on that candidate's own evidence, never on which other processes happened to be in the logs alongside it.
- **Cache.** Jev isn't deterministic: the identical request can come back a few hundredths different. Exact replays therefore come from the cache (`--cache`), which stores every answer under the SHA-256 of its exact request. A replay of the full CLA-WS-214 investigation made 0 calls and reproduced the report exactly, and `requests.jsonl` lets anyone check what Jev was asked.

[`test/repro.test.ts`](test/repro.test.ts) enforces this. One incident (injection, drop and run, persistence, a named pipe, credential access, PID reuse and unrelated noise) is rendered as:

- Elastic Agent NDJSON with Security 4688 twins;
- a Splunk-style Sysmon CSV with fully qualified hosts and `DOMAIN\user`;
- `key=value` text;
- shuffled lines;
- Sysmon and Security as separate files, in either order;
- Sysmon without process-creation events, with starts from Security 4688 (same incident and rejections; the requests differ only where 4688 has less to say, such as hashes);
- CSV and text together, so every event is duplicated.

All of them must send Jev **byte-identical requests** and produce the same incident. Batch size, concurrency, grouping and cache replays must not change any decision. Security 4688 alone must find exactly the lineage it can see.

## Performance

On an Apple M2 Max, with Jev replaced by the offline stand-in. This measures the engine's own time; with Jev, each round adds one round of requests, which run in parallel.

| Input | Records | Total | Records/s | Peak memory |
|---|---:|---:|---:|---:|
| CLA-WS-214 Elastic export, NDJSON, 955 MB (Sysmon + Security, 6 days) | 310,942 | 2.6 s | 121,000 | 2.0 GB |
| CLA-WS-214 Elastic Defend export, NDJSON, 1,242 MB (`endpoint.events.*`, 6 days) | 705,017 | 6.6 s | 107,000 | 2.4 GB |
| Both exports together | 1,015,959 | 9.6 s | 106,000 | 3.3 GB |
| Synthetic, 300,000 events, NDJSON with 4688 twins / CSV / text | 300,000–382,000 | 2.0–2.4 s | 146,000–162,000 | 0.9–1.1 GB |
| Synthetic, 1,000,000 events, NDJSON with 4688 twins / CSV / text | 1.0–1.3 million | 6.7–9.3 s | 137,000–148,000 | 1.7–2.4 GB |

**Live, with Jev (jev-1.13.0), on the CLA-WS-214 export:**
- **Full investigation outward from 2.8.exe:** 364 requests over 6 rounds, about 700,000 input tokens, 7.6 s end to end (2.3 s local, the rest Jev at 8 requests in flight). The previous engine needed one request per process start and pass on the same file: 28,813 to 57,581.
- **Rerun after an engine change:** reused 219 cached answers and sent 102 new requests, 3.8 s.
- **Replay from the cache:** 0 calls, 2.3 s, an identical report.

```bash
node engine/bench/bench.ts                       # synthetic 100k / 300k / 1M events in three formats
node engine/bench/bench.ts export.ndjson --seed name:2.8.exe
node engine/bench/jev-batching.ts export.ndjson --seed name:2.8.exe --context "..." --round 2 --live
```

**Live, with entities (October 2026).** On the same export, with accounts, hosts, addresses and domains linkable, the investigation took 341 requests and 7.5 s.
- **Linked from the processes into the attacker's infrastructure:** the C2 `193.178.158.107` and two other addresses 2.8.exe contacted, the hollowed Notepad's `sxdment.click`, and twelve algorithmically generated domains the fake `spoolsv.tmp` copies looked up.
- **Rejected:** `www.google.com` and the Google and Bing addresses 2.8.exe touched (0.29–0.73).
- **Just under 0.8, flagged for review:** three ground-truth items: the DGA domain `dym1vps…com` (0.79), the Telegram C2 `149.154.166.110` (0.79) and `193.178.158.65` (0.59).

**Live, on the Elastic Defend export (October 2026),** scored against the analyst's attack chain for CLA-WS-214 (41 processes after the seed, up to 2026-09-24 16:41):

| Input | Jev requests | Total time | Ground-truth processes found | Other processes in the window |
|---|---:|---:|---:|---:|
| Elastic Defend alone | 376 | 10.7 s | 33 / 41 | 1 |
| Elastic Defend + Windows logs | 412 | 14.6 s | 40 / 41 | 1 |

- **Elastic Defend alone** misses four `RuntimeBroker.exe` injections it didn't record (only one appears in its API events). It also scored the relaunched `a2p9xg7d.exe` at 0.77 and `FnHotkeyUtility.exe` (9644) at 0.75, which cost the installer's two descendants as well.
- **With the Windows logs** the injections and the installer chain are linked. The only miss is `FnHotkeyUtility.exe` (9644) at 0.76. The one extra process is the `msedge.exe` that the hollowed Notepad started and injected, which the chain lists for Chrome but not Edge.
- **Linked infrastructure:** the C2 `193.178.158.107`, the Telegram C2 `149.154.166.110` (0.81) and the DGA domain `dym1vps…com` (0.82), all three previously just under the threshold, plus `sxdment.click` and the DGA domains the fake `spoolsv.tmp` copies looked up.
- **Folding:** the combined incident's 1,495 members are shown as 99 rows, and its 21,795 events as 2,512 timeline rows. 2.8.exe's 1,591 connections to its C2, every ~290 s for five days, are one row.

[`test/entities.test.ts`](test/entities.test.ts) covers an intrusion seen only through logs without processes, in three formats the engine has no rules for: a JSON authentication log, CSV firewall flows and a JSON web access log.
- From the attacker's address it finds the account used, the two servers reached through it and the attacked web server. It rejects other visitors of that web server and the shared resolver, and never considers unrelated accounts or a separate brute force.
- The authentication log in another format (CSV with different column names) finds the same incident.
- From the malware process it reaches its C2 and then a second host that contacted the same C2 later.

### Batching

`jev-batching.ts` is a live check (about 30 calls, so it spends credit and sends that telemetry to TypeSafe). It asks the same 20 real candidates alone, in batches of 10, in one batch of 20, in reverse order and again, then reports any differences, threshold flips and latency per call. Its first run (October 2026, jev-1.13.0, round 2 of the CLA-WS-214 investigation):

| Compared with asking alone | Largest difference | Mean difference | Decisions that flip at 0.8 |
|---|---:|---:|---:|
| The identical request again | 0.03 | 0.01 | 0 of 5 |
| Batches of 10 | 0.18 | 0.04 | 1 of 20 |
| One batch of 20 | 0.20 | 0.05 | 1 of 20 |
| One batch of 20, reversed | 0.25 | 0.04 | 2 of 20 |

- **Clear-cut candidates are stable.** They scored 0.89–0.95 however they were asked.
- **Borderline ones move with the company they keep.** A `cmd.exe` scored 0.50 alone and 0.25–0.32 in batches; a dropped `.tmp` scored 0.78 alone and 0.92 in every batch.
- **Batching saves tokens, not time.** About 960 input tokens per candidate in a batch of 20 against about 2,160 alone. Calls took about 100 ms alone and about 190 ms for 20, so single-candidate requests in parallel are as fast.

That's why the default is one candidate per request.

## Limitations

- **Validated on one incident.** The scores above come from one host and one analyst's attack chain, which stops on 2026-09-24. Decisions after that, and on other incidents, haven't been adjudicated. Many decisions sit near the threshold (155 answers in the combined run), so a fresh run without the cache can move a few of them.
- **Rate limits are unknown.** TypeSafe doesn't publish them; 429 and 529 answers are retried with backoff. Lower `--concurrency` if you see many retries.
- **Unstructured text is only lightly understood.** Plain-text lines are read as `key=value` pairs plus the message; free-form messages (classic syslog) aren't yet reduced to templates, so they rarely carry a process chain.
- **No link from an account to the processes it ran.** An account joins through logons, but the processes it then started on a host don't join through it (that would pull in a user's whole working day). Seed one of those processes to follow it.
- **No remote-execution links yet.** Hosts connect through logons and shared addresses, but a process started remotely (PsExec, WMI, WinRM) isn't linked to the process that started it.
- **Only what the telemetry records.** Without Sysmon 8/10 or EDR API events there are no injection links; with Security 4688 alone only lineage is visible. The reproducibility tests show exactly this degradation.
- **One JSON document is read whole**, which V8 limits to about 512 MB. Use NDJSON for larger exports.
- **"Other" events aren't kept.** Privilege use, logoffs and handle auditing are counted in `inspect` but not used.

## Development

```bash
cd engine
npm ci              # TypeScript and Node types, for type checking only
npm run typecheck
npm test
```

| Path | Contents |
|---|---|
| `src/read.ts` | Streaming and ranged reading, format detection, CSV and text parsing |
| `src/normalize.ts` | The built-in sources (Windows event logs, ECS), into the canonical model (`src/model.ts`) |
| `src/schema.ts` | Learning any other schema: grouping, value shapes, the questions Jev answers, mappings and their cache |
| `src/identity.ts` | Process identity: GUIDs, PID lifetimes, 4688/Sysmon twins, GUIDs seen late, parents |
| `src/links.ts`, `src/entities.ts` | Typed links between processes, and the accounts, hosts, addresses and domains of logs without processes |
| `src/investigate.ts` | Rounds, causality, grouping, and exactly what Jev is asked |
| `src/jev.ts`, `src/standin.ts` | TypeSafe client (retries, concurrency, cache, request log) and the offline stand-in |
| `src/analyze.ts`, `src/worker.ts`, `src/cli.ts` | Pipeline and report, parallel parsing, command line |
| `test/` | Unit tests and the reproducibility harness (`incident.ts` renders the shared incident) |
| `bench/` | Throughput benchmark and the live batching check |
