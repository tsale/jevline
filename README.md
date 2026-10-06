# Jevline

*One confirmed starting point in, the whole incident out.*

**Start from one process, address, account or host you know is malicious. Get back the incident.**

**[Try it in your browser →](https://jev-incident-timeline.vercel.app/)** · [Command line](#command-line)

<p align="center">
  <img src="docs/how-it-works.svg" alt="Three steps: a telemetry export with one confirmed-malicious process; Jev asks of every other process whether it belongs to the same incident; the result is a timeline of only the linked activity." width="100%">
</p>

Once an analyst confirms one malicious process, the next question is always *what else is part of this?*

Jevline follows every link the telemetry records out of it:
- **between processes:** children, code injection, files dropped and then run, persistence;
- **to the wider environment:** network contacts, logons, web requests.

It then asks [Jev](https://docs.typesafe.ai/), TypeSafe's structured-decision model, about each process, account, host, address or domain those links reach. What Jev links is followed further, round by round, until nothing new joins. The result is the incident, a timeline of what it did, and how each part joined.

> [!NOTE]
> Experimental, not a validated detector. A Jev score measures **relatedness to the incident**, not whether something is malicious. Every result needs analyst review.

## Results on a real intrusion

Six days of telemetry from one Windows host, CLA-WS-214, where a loader (`2.8.exe`) led to credential theft, Cobalt Strike and several waves of payloads. Each run started from `2.8.exe` alone. It was scored against the analyst's attack chain: the 41 processes that followed, up to September 24.

| Logs analyzed | Decisions by | Attack-chain processes found | Other processes included | Time | Cost |
|---|---|:---:|:---:|---:|---:|
| Elastic Defend (EDR): 705,017 records | **Jev** | **33 of 41** | 1 | **10 s** | **$0.03** |
| Windows event logs: 310,942 records | **Jev** | **37 of 41** | **0** | **6 s** | **$0.03** |
| Both together: 1,015,959 records | **Jev** | **40 of 41** | 1 | **21 s** | **$0.11** |
| Both together: 1,015,959 records | GLM 5.3 Flash, in Jev's place | 41 of 41 | 8 | 32.6 min | $1.06 |

- **Same engine, same questions, a different model.** In the last row, GLM 5.3 Flash answered the questions Jev answers.
  - **Time:** 94 times longer. GLM reasons before each answer and took 9 s per question (median), against Jev's 0.08 s.
  - **Cost:** 10 times more.
  - **Accuracy:** it found one more attack-chain process, and brought in 8 processes the attack chain doesn't list, such as `cmd.exe`, `whoami.exe` and `nltest.exe` started by the injected `explorer.exe`.
- **Each source sees part of the attack.** The EDR export doesn't record four of the injections; the Windows logs miss two browser steps and two launches of the implant, which Jev scored 0.65 to 0.77. Together they find 40 of 41. The one miss, `FnHotkeyUtility.exe` (9644), scored 0.78, just under the 0.8 threshold, and is marked for review.
- **Questions grow with the incident, not the logs:** 337 to 1,123 Jev requests for more than 25,000 process starts.

**How to read it.**
- **Other processes included:** processes in the incident before September 24 that the analyst's chain doesn't list.
- **Time:** from opening the files to the finished incident, including 4 to 8 s of reading and linking, with 8 requests in flight.
- **Cost:** Jev at TypeSafe's published $42 per billion input tokens; GLM 5.3 Flash at OpenRouter's list price ($0.15 per million input tokens, $0.50 per million output).
- **The incident is larger than the scored window.** It also has the C2 and Telegram addresses, generated malware domains, and the activity after September 24, such as hundreds of relaunches of a beacon.

Reproduce with [`engine/bench/compare.ts`](engine/bench/compare.ts).

## Any logs. No schema, no pre-mapping.

Jevline doesn't expect a specific schema, and there's nothing to map before you start. Give it whatever your tools export, as one file or several:

- **Any format.** JSON, NDJSON, CSV/TSV or plain text, detected from the first line.
- **Any source.** Windows event logs (Sysmon, Security, System) and ECS data such as Elastic Defend are read with built-in rules. Logs from anything else are understood by asking Jev what each kind of event is and what its fields hold. Jev answers two small questions per event type (not per record), and the answer is remembered for next time. Examples are Microsoft Defender for Endpoint, CrowdStrike Falcon, a SIEM export, authentication, firewall or web server logs, and your own JSON or CSV.
- **Several sources at once.** The same process seen by Sysmon and by an EDR becomes one process, and a record that appears in two exports counts once.
- **Logs without processes count too.** Authentication, firewall, proxy and web logs bring in the accounts, hosts, addresses and domains the attacker went through.

Tested this way: the same incident as Sysmon, Defender for Endpoint (five Advanced Hunting tables) and CrowdStrike Falcon FDR events gives the same result. So does an intrusion seen only through a JSON authentication log, CSV firewall flows and a web access log. The engine had no rules for any of those formats.

## Two ways to use it

| | **Website** | **Command line** |
|---|---|---|
| Start | Open **[jev-incident-timeline.vercel.app](https://jev-incident-timeline.vercel.app/)** | `node engine/src/cli.ts analyze …` (Node.js 22.18+, nothing to install) |
| Where the analysis runs | In your browser, on your device | On your machine, on up to 8 cores |
| Jev (TypeSafe) | Our **demo key** on the bundled example, or **your own key** for your files | Your key, from `TYPESAFE_API_KEY` or a private `.env` |
| Narrative (optional) | Your OpenRouter key, typed into the page | |
| Results | Incident, timeline, execution chain and evidence table; download the report and every Jev request | The incident table; `--out` writes the report and every Jev request |

### The website

1. Drop in your log files (or click **Load bundled lab example**).
2. Pick the **starting point**, the process you've confirmed as malicious, from the process starts in your logs. Or type an address, domain, account or host. Add a sentence of **analyst context**.
3. Click **Analyze with Jev**.

The **Incident** tab lists every member: how it joined, Jev's probability, and a **review** marker within 0.05 of the 0.8 threshold. The **Event timeline**, **Execution chain** and **Evidence table** show what the incident did. The same activity repeated without change (a beacon, a brute force, a relaunch) is one row with a count, until when and how often. **Request narrative** optionally drafts titles, ATT&CK mapping and a written chain with an OpenRouter model, labelled as an AI draft.

**How the website handles keys and data.**
- **Your files** are read and linked in your browser and never uploaded. Only a short summary of each candidate Jev is asked about leaves it.
- **Jev requests** go through a small relay on the same site, [`api/jev.js`](api/jev.js), which forwards each one to TypeSafe unchanged. Browsers can't call TypeSafe directly.
- **Demo key:** our TypeSafe key, stored as a server secret, answers only questions about the bundled lab example. The relay refuses any request containing words that aren't in that example or in the engine's own wording.
- **Your own key** travels with each request through the relay to TypeSafe and is never stored or logged.
- **OpenRouter:** your key goes straight from your browser to `openrouter.ai`, never through us.

The page's security policy only allows connections to its own site and `openrouter.ai`, so you can check every request in your browser's developer tools.

### Command line

```bash
git clone https://github.com/tsale/jevline.git && cd jevline
cp .env.example .env && chmod 600 .env      # add TYPESAFE_API_KEY
node engine/src/cli.ts inspect export.ndjson --find 2.8.exe
node engine/src/cli.ts analyze export.ndjson more-logs.csv --seed name:2.8.exe \
  --context "Analyst-confirmed 2.8.exe execution on CLA-WS-214." --out runs/2.8
```

`inspect` reads the logs and reports what it found without calling Jev. `analyze` runs the investigation and prints the incident. The seed can be a process (`name:<image>`, an event ID, or `guid:<ID>` with any source's process ID) or `ip:`, `domain:`, `user:` or `host:`. Every option, and how the engine works in detail, is in the [engine README](engine/README.md).

## How it works

```
log files ─▶ read ─▶ normalize ─▶ processes ─▶ links ─▶ rounds of Jev questions ─▶ incident + timeline
```

1. **Read and normalize** every record into one model, in any format and schema (above).
2. **Identify processes** across sources and PID reuse.
3. **Link** them: lineage, injection, dropped and run files, loaded DLLs, named pipes, persistence. Also link the accounts, hosts, addresses and domains of network, logon and web activity.
4. **Ask Jev**, round by round from the starting point, about everything the incident's links reach.
   - Only what a member did after it joined can carry the incident further.
   - Each question is one candidate with its links and activity.
   - Identical candidates share one question, and common infrastructure is recognised by how widely it is used.
5. **Report** the incident and its timeline with repeats folded.

Jev is asked about what the telemetry connects to the incident, not about every process in the logs. So the number of questions grows with the incident, not with the logs: 337 to 1,123 requests for six days of one host's telemetry. The same telemetry gives Jev byte-identical requests, so answers can be cached and runs replayed exactly. Details: [engine/README.md](engine/README.md); architecture of the website and relay: [ARCHITECTURE.md](ARCHITECTURE.md).

## What leaves your machine

| Action | What is sent | Where |
|---|---|---|
| Load logs | Nothing | |
| **Analyze with Jev** | For each candidate, a summary: names, paths, command lines, PIDs, hashes and users of the starting point, the candidate and the incident members it links to; the links themselves; samples of what the candidate did. Your analyst context. | TypeSafe (on the website, through the site's relay) |
| Logs from an unknown schema | Field names with a few example values per field, once per event type | TypeSafe (your key only) |
| **Request narrative** | At most 60 timeline rows of the incident | OpenRouter (directly) |

Only analyze telemetry you're allowed to share with these providers.

## Limitations

- **Validated on one incident.** The scores above are one host and one analyst's attack chain. Jev's answer to an identical question varies by a few hundredths, so decisions near the threshold (marked **review**) can go either way on a fresh run, and a linked hub can bring in more.
- **Only what the telemetry records.** Without Sysmon 8/10 or EDR API events there are no injection links; with process creation alone, only lineage.
- **Not yet linked:** remote execution across hosts (PsExec, WMI, WinRM), and an account to the processes it ran. Free-form syslog messages are only lightly understood.
- **Browser memory.** The website reads files on one core, in your tab's memory: the 1.2 GB EDR export took 12.6 s and 1.5 GB. Use the command line for larger exports.

## Development

```bash
npm test                        # relay, build, website and engine tests (offline; providers mocked)
npm run preview                 # build the site and serve it with the relay at http://127.0.0.1:8000
```

The engine needs `npm ci` in `engine/` once, for type checking only (`npm --prefix engine run typecheck`). The website is `site/index.html`, `ui/` and the engine's browser modules, built into `_site/` by `node scripts/build_site.js`, plus the relay function in `api/`. `vercel.json` sets the build and the security headers.

To deploy your own copy, import the repository in Vercel (or run `vercel deploy --prod`). Then add the demo key as a secret with `vercel env add TYPESAFE_API_KEY production`, and redeploy. Without it the site still works with visitors' own keys. The relay rate-limits each visitor and caches repeated demo requests, but per running instance only, so add a Vercel Firewall rate-limit rule on `/api/jev` for a hard limit. The [Tests workflow](.github/workflows/tests.yml) runs every suite on each push and pull request.

| Path | Contents |
|---|---|
| `engine/` | The engine: TypeScript, no runtime dependencies; command line, tests and benchmarks ([README](engine/README.md)) |
| `site/index.html`, `ui/` | The website page and its scripts and styles |
| `api/jev.js`, `api/_relay.js` | The website's Jev relay (Vercel function) |
| `scripts/` | Website build and local preview |
| `examples/` | The bundled lab example: 100 Sysmon and Security records from the detonation of `2.8.exe` on CLA-WS-214 |
| `docs/` | README illustration |

The original Python engine and local portal are in the git history up to the tag `python-engine-final`.
