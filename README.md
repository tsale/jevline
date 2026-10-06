# Jevline

*Jev incident timelines: one confirmed process in, the whole incident out.*

**Start from one process you know is malicious. Get back the incident.**

**[Try it in your browser →](https://jev-incident-timeline.vercel.app/)** · [Run it locally](#quick-start)

<p align="center">
  <img src="docs/how-it-works.svg" alt="Three steps: a telemetry export with one confirmed-malicious process; Jev asks of every other process whether it belongs to the same incident; the result is a timeline of only the linked activity." width="100%">
</p>

Once an analyst confirms one malicious process, the next question is always *what else is part of this?* This proof of concept puts that question to [Jev](https://docs.typesafe.ai/), TypeSafe's structured-decision model, one process at a time, and turns the answers into an incident timeline you can review.

It comes as a web portal you can use as a website or run locally, and a command-line script. Nothing to install: the website runs in your browser, and the local version uses only the Python standard library.

> [!NOTE]
> This is an experimental proof of concept, not a validated detector. A Jev score measures **relatedness to the incident**, not whether a process is malicious. Every result needs analyst review.

## Two ways to use it

| | **Website** | **Local portal** |
|---|---|---|
| Start | Open **[jev-incident-timeline.vercel.app](https://jev-incident-timeline.vercel.app/)** | `python3 web_app.py` (see [Quick start](#quick-start)) |
| Jev (TypeSafe) | Our **demo key** on the bundled example, or **your own key** for your files | Your key, saved in `.env` on your machine |
| OpenRouter (optional) | Your key, typed into the page | Your key, in `.env` |
| Where data goes | Jev requests go through the site's relay to TypeSafe; narratives go straight from your browser to OpenRouter | From your machine straight to both providers |
| Evidence | **Download run (JSON)** | Private bundle in `.local-runs/` |

**How the website handles keys and data.** Browsers can't call TypeSafe's API directly (it doesn't allow cross-site requests), so the website runs the analysis in your browser and sends each Jev request through a small relay on the same site, [`api/jev.js`](api/jev.js), which forwards it to TypeSafe unchanged.

- **Demo key:** our TypeSafe key, stored as a server secret, works only on the bundled lab example. The relay rejects any request containing other data.
- **Your own key:** it travels with each request through the relay to TypeSafe and is never stored or logged. Choose this to analyze your own files.
- **OpenRouter:** your key goes straight from your browser to `openrouter.ai`, never through us.
- **Your files:** they stay in your browser. Only the fields Jev needs leave it, one request per process.

The page's security policy only allows connections to its own site and `openrouter.ai`, so you can check every request in your browser's developer tools. The providers receive the telemetry you analyze, under their own terms.

## New engine (preview)

[`engine/`](engine/README.md) is the rewrite this project is moving to. It takes the 1 GB, 311,000-event CLA-WS-214 export from file to finished incident in under 3 seconds of local work.

- **Links beyond lineage:** it follows parent/child lineage, process injection, dropped-and-executed files, loaded DLLs, named pipes and persistence.
- **Jev calls grow with the incident, not the logs:** Jev is asked only about processes linked to the incident, one per request, sent in parallel. On the CLA-WS-214 export a full live investigation took 364 Jev requests and under 8 seconds.
- **Same telemetry, same requests:** the same incident in different telemetry produces the same Jev requests, and a test enforces it.

```bash
node engine/src/cli.ts analyze export.ndjson --seed name:2.8.exe --context "Analyst-confirmed 2.8.exe execution."
```

The portal and the command line below still use the original engine until they switch over.

## Quick start

You need **Python 3.9 or newer** (the `python3` that ships with macOS works) and a **TypeSafe API key** ([TypeSafe Quick Start](https://docs.typesafe.ai/introduction/quickstart)).

```bash
git clone https://github.com/tsale/jevline.git
cd jevline
python3 web_app.py --setup-keys   # paste your key; input is hidden and saved to .env
python3 web_app.py                # start the portal
```

Open **http://127.0.0.1:8765** and:

1. Click **Load bundled malicious-events example** (or drop in your own log file: JSON, NDJSON, CSV or plain text).
2. Check the **Starting execution**, the process you have confirmed as malicious, and add a sentence of **Analyst context**.
3. Click **Analyze with Jev**. The **Event timeline** opens when the answers are in.

Press `Ctrl+C` to stop. Run `python3 web_app.py` again whenever you need it; your keys and recent runs are kept.

## Adding your API keys

| Key | Needed for | Sent to |
|---|---|---|
| `TYPESAFE_API_KEY` | **Analyze with Jev** (required) | `api.typesafe.ai` |
| `OPENROUTER_API_KEY` | **Request narrative** (optional AI-drafted titles and summaries) | `openrouter.ai` |

Choose one of these ways to add them:

- **Guided (recommended):** `python3 web_app.py --setup-keys` asks for each key with hidden input and writes them to `.env` with private permissions. Run it again to change a key; press Enter to keep the current one.
- **By hand:** copy the template, make it private, then fill in the values:

  ```bash
  cp .env.example .env
  chmod 600 .env
  ```

- **Environment variables:** if `TYPESAFE_API_KEY` or `OPENROUTER_API_KEY` is already set in the server's environment (for example by a secret manager), it takes precedence over `.env`.

The server reads the keys on every request, so after you edit `.env`, click **Refresh** in the portal; there's no need to restart. Keys stay on the server: the browser only ever sees "ready" or "missing". On macOS and Linux the server refuses a key file that other users can read, and the portal tells you the exact `chmod` to run.

## Using the portal

| Tab | What it does |
|---|---|
| **Source & analysis** | Import a log file (JSON, NDJSON, CSV/TSV or plain text), choose the confirmed starting execution (the *seed*), add context, and run **Analyze with Jev**. Importing never leaves your browser. |
| **Event timeline** | One compact row per linked event in time order, with a count such as "21 linked of 100 source events". |
| **Execution chain** | The process-to-process flow and what each process did, as Markdown you can copy. It's built from Jev's results alone until you request a narrative, then the AI-drafted version (with an ATT&CK summary) replaces it; one click switches back. |
| **Evidence table** | The incident rows in an 11-column, colour-coded table: Timestamp, Host, Phase, Title, Description, Tools, TTPs, Command Line, Indicator, Type, Pyramid. |

Every results tab says which kind of results it shows. **Jev results only, no AI enrichment** means every row, score and link comes straight from Jev and exact process matches. After a narrative it reads **AI-enriched draft** and names the model.

How to read the labels:

| Label | Meaning |
|---|---|
| `Seed · 100%` (amber) | The seed. This is your confirmation, not a Jev prediction. |
| `Jev 94%` (blue) | Jev's probability that this execution belongs to the same incident. Linked at 0.8 or above. Relatedness, not a malware verdict. |
| `Same process` (teal) | A file, network or registry event from the same host and process as a linked execution. An exact identity match, not a Jev score. |

**Request narrative** is an optional second step. It sends the linked events (50 at most), each marked with how it's linked, to OpenRouter. The model defaults to `deepseek/deepseek-v4.1-flash`, and you can enter any OpenRouter model ID in **Narrative model**. The draft adds:

- **Titles and summaries** for each row.
- **ATT&CK mapping:** a MITRE ATT&CK tactic (shown in Phase) and up to three technique IDs (shown in TTPs, linked to attack.mitre.org). Only the 14 Enterprise tactics and `T1234` / `T1234.001`-style IDs are accepted; anything else is dropped rather than guessed. Without a narrative, Phase shows the observed event type and TTPs stay empty, because Jev doesn't map techniques.
- **An execution chain** in Markdown with an ATT&CK summary table. Citations of unknown event IDs are replaced with `[unknown event]`.

The narrative is a draft for you to verify, never a verdict.

If an analysis fails partway (for example, during a provider outage), a **Resume** button reuses every Jev answer you already paid for and asks only the remaining questions. Resume points are saved on disk, so they survive a restart.

### Portal options

| Option | Default | Purpose |
|---|---|---|
| `--port` | `8765` | Port on `127.0.0.1` |
| `--setup-keys` | | Prompt for the API keys, save them to `.env`, and exit |
| `--env-file` | `.env` | Where keys are read from |
| `--run-root` | `.local-runs/` | Private evidence bundle for each analysis |
| `--retention-days` | `14` | Delete web runs this many days after their last write |
| `--replit-preview` | | Serve through a Replit workspace preview, with an access code printed to the console for provider calls |

## Command line

The same analysis runs without the portal:

```bash
python3 jev_incident.py examples/malicious_events.json \
  --seed-id VvT8xKABOYkemEz9sgQR \
  --description "Analyst-confirmed 2.8.exe execution on CLA-WS-214." \
  --run-dir runs/first-run
```

It prints one line per execution with the decision, probability and the evidence category Jev selected (`lineage`, `interaction`, `artifact`, `user_host_time` or `no_link`; Jev chooses a category rather than writing prose). It reads the key from the environment or `.env`.

- `--run-dir DIR` writes an auditable bundle: `summary.json` (time, calls, tokens, input hash), `attempts.jsonl` (every call, including retried failures), `decisions.json` and `evidence/`.
- `--resume-run OLD --run-dir NEW` continues a failed run, reusing only answers whose exact request matches.
- `--format` (`auto`, `json`, `ndjson`, `csv` or `text`) overrides the detected [input format](#input-format).
- `--threshold` (default `0.8`), `--model` (default `jev-1.13.0`) and `--output decisions.json` are also available.

The command line has no size limit. A 1 GB NDJSON export (311,000 events, 28,800 process starts) loads in about 15 seconds on a laptop, and everything except the Jev calls themselves takes about 40 seconds. Every process start is still one Jev request (two if the second pass runs), so trim the export to the time window you care about before a live run.

## How it works

For each other process start in the export, in time order, the tool sends Jev one request containing:

- the **seed** and your description,
- the **candidate** process,
- up to six **recently linked** executions, so the evidence builds up as links are found,
- up to eight **nearby events** from the same host (same process lineage, or within 10 minutes).

Jev returns a probability that the candidate is related, plus an evidence category. Candidates at 0.8 or above are linked and become context for later questions. If the first pass found any new links, the remaining candidates are asked once more with the expanded context.

[ARCHITECTURE.md](ARCHITECTURE.md) covers the exact request shape, field mapping, evidence files, resume rules, measured results and limitations in detail.

## Input format

Jevline reads any line-delimited log, and detects the format from the first line:

| Format | Detected when the first line | Notes |
|---|---|---|
| **JSON** | starts with `[{`, `[]` or a bare `[`, or is a `{` that continues on later lines | An array of events, `{"events": [...]}`, or an Elasticsearch search response (`hits.hits`) |
| **NDJSON** (JSON Lines) | is a complete JSON object | One event per line, for example an Elasticsearch or EDR export |
| **CSV / TSV** | is a header of field names separated by `,` tab `;` or `\|` | Quoted fields may contain the separator, `""` and line breaks |
| **Plain text** | is anything else | One event per line: the whole line is kept as `message`, `key=value` pairs (values may be `"quoted"`) become fields, and a leading ISO 8601 time becomes `@timestamp` |

The CLI's `--format` overrides the detection. Blank lines are skipped, and a UTF-8 byte-order mark and Windows line endings are fine.

Events can be ECS documents, Elasticsearch hits (with `_source` or the dotted `fields` format), or flat records. CSV columns and text keys can use dotted ECS names (`process.parent.entity_id`) or the usual Windows, Sysmon and Splunk names, which are mapped to ECS: for example `_time`, `Computer`, `Image`, `CommandLine`, `ProcessId`, `ProcessGuid`, `ParentImage`, `ParentProcessGuid`, `Hashes` (its `SHA256=`), `TargetFilename`, `DestinationIp` and `QueryName`. A row with `EventID` 4688, or `EventID` 1 from a Sysmon channel or source, is a process start. Process and parent names come from their paths, and decimal or `0x` PIDs and ports become numbers.

Each event keeps its own `id`, `_id` or `event.id`. An event without one gets `line-N`, the line where it starts in the file (`event-N` inside a JSON document), so you can always find it in the source file again. The seed must be a process start. The portal accepts up to 500 events and 2 MiB; the command line has no limit.

A minimal input looks like this (see [tests/fixtures/synthetic.json](tests/fixtures/synthetic.json)):

```json
{"events": [
  {"id": "seed", "@timestamp": "2026-09-21T17:18:50Z", "kind": "execution", "host": "WS-01",
   "process": {"name": "powershell.exe", "pid": 400, "entity_id": "proc-seed"}},
  {"id": "child", "@timestamp": "2026-09-21T17:18:52Z", "kind": "execution", "host": "WS-01",
   "process": {"name": "stage.exe", "pid": 410, "entity_id": "proc-child", "parent": {"entity_id": "proc-seed"}}}
]}
```

### The bundled example

[examples/malicious_events.json](examples/malicious_events.json) holds 100 Elasticsearch (Sysmon) records from a lab detonation of `2.8.exe` on host `CLA-WS-214`. The seed is `VvT8xKABOYkemEz9sgQR`. The export covers about 11 seconds, so it doesn't include the incident's later steps. SHA-256: `d9b1c28d03053099878a8816333b0ca31b0b3abc460a473fe9b72714a1dd39b4`.

## What leaves your machine

This applies to both the website and the local portal.

| Action | What is sent | Where |
|---|---|---|
| Open the portal or import a file | Nothing | |
| **Analyze with Jev** | For each candidate: selected fields only (IDs, time, host, user, process name, path, command line, PIDs, entity IDs, hashes, file and destination fields) of the seed, the candidate and its context events | TypeSafe (on the website, via the site's relay) |
| **Request narrative** | The seed, the linked executions and their same-process events (50 at most) | OpenRouter (directly) |

Only analyze telemetry you're allowed to share with these providers. On the website, your keys live in the page's memory unless you tick **Remember on this device** (then in that browser's local storage; **Forget keys** removes them), and the relay keeps nothing. In the local portal, each analysis writes an evidence bundle to `.local-runs/`, which is private, git-ignored and deleted 14 days after its last write. The server listens on `127.0.0.1` only, rejects cross-origin requests and never sends keys to the browser. It's a single-user local tool, so don't expose it to a network.

## Limitations

- **No accuracy claim.** The tests mock both providers, and the 0.8 threshold is an experimental cut-off. Below the threshold means "not enough evidence to link", not "benign".
- **Local files only.** There is no live Elasticsearch or SIEM query. Context selection is indexed (by host, time and process entity ID), so large exports are fine locally; the limit is the number of Jev calls, one per process start.
- **Context is not proof.** Nearby events are hints for Jev, and PIDs can be reused. The CLI doesn't require candidates to come after the seed, so prepare the time window you want.

## Development

```bash
python3 -m unittest -v test_jev_incident.py test_web_app.py
node ui/test_engine.js && node ui/test_app.js && node ui/test_access.js && node ui/test_browser.js && node tests/test_relay.js
```

All tests run offline with mocked providers. The JavaScript tests need Node.js; the app itself doesn't. `ui/engine.js` and `ui/formats.js` are ports of `jev_incident.py`, and `ui/test_engine.js` checks that the browser parses every format into the same events and sends Jev byte-for-byte the same requests on four fixtures. After an intentional change to the Python engine, regenerate the reference with `python3 -c "import test_jev_incident as t; t.write_golden()"` and update the port until both suites pass.

### The website on Vercel

The website is `site/index.html` plus the shared `ui/` files, built into `_site/` by `node scripts/build_site.js`, and the relay function in `api/`. `vercel.json` sets the build and the security headers. To preview it locally with the relay:

```bash
node scripts/build_site.js
node scripts/serve_site.js        # http://127.0.0.1:8000
```

To deploy your own copy, import the repository in Vercel (or run `vercel deploy --prod`), then add the demo key as a secret: `vercel env add TYPESAFE_API_KEY production`, and redeploy. Without it the site still works with visitors' own keys. Set a spending limit on that TypeSafe key: the relay rate-limits each visitor and caches repeated demo requests, but per running instance only, so add a Vercel Firewall rate-limit rule on `/api/jev` for a hard limit. The [Tests workflow](.github/workflows/tests.yml) runs every suite on each push and pull request.

| Path | Contents |
|---|---|
| `jev_incident.py` | Normalization, context selection, Jev requests, evidence bundles, CLI |
| `web_app.py` | Jevline server: static UI, `/api/analyze`, `/api/narrate`, key handling, retention |
| `ui/` | Shared portal JavaScript and CSS, the local portal page, and `engine.js` (the browser port of the engine) |
| `site/index.html` | The website page: Jev access choice, key panel, privacy notice, connection policy |
| `api/jev.js`, `api/_relay.js` | The website's Jev relay (Vercel function): demo key limited to the bundled example, visitors' keys forwarded |
| `scripts/build_site.js`, `scripts/serve_site.js`, `vercel.json` | Website build, local preview with the relay, Vercel settings |
| `ui/formats.js` | The browser port of the format loader (JSON, NDJSON, CSV/TSV, plain text) |
| `examples/`, `tests/fixtures/` | Bundled lab export; synthetic, edge-case and per-format fixtures; the engine and format parity references |
| `docs/` | README illustration |
