# Jevline: architecture

**Status:** experimental. Jevline turns one analyst-confirmed starting point into an incident, with Jev deciding what belongs to it. It is not a validated detector: a Jev score measures relatedness to the incident, not maliciousness, and every result needs review. See the [README](README.md) for use, and the [engine README](engine/README.md) for the engine in detail (input, links, rounds, questions, reproducibility, performance).

## One engine, two places

```mermaid
flowchart LR
    subgraph Browser["Visitor's browser (website)"]
      P[Page: ui/app.js, ui/view.js] -- File objects --> W[Web Worker: engine/web-worker.js]
      W -- progress, report --> P
    end
    subgraph Node["Command line"]
      C[engine/src/cli.ts] --> A[analyze.ts: files on several cores]
    end
    W --> E[engine/src: read, normalize, schemas, processes, links, rounds, report]
    A --> E
    E -- one candidate per request --> R[/api/jev relay on Vercel/] --> T[TypeSafe: Jev]
    C -. direct .-> T
    P -. optional narrative, direct .-> O[OpenRouter]
```

- **The same code.** `engine/src` is TypeScript with erasable syntax only. Node runs it as it is. The website publishes the modules the browser needs as JavaScript by erasing the types (`scripts/build_site.js`, using Node's own `stripTypeScriptTypes`), with no bundler, compiler or dependency.
- **Where Node and the browser differ.** File access is `files.ts` and `analyze.ts` (files, worker threads) in Node, and `browser.ts` (`File` objects read in chunks) in the browser. Everything after reading is `pipeline.ts`, the same in both. A test reads every test format through both paths and requires identical events. The build fails if a browser module imports anything from Node.
- **Results.** The report has the incident (members, each with how it joined and Jev's probability, identical repeats folded), the timeline (repeats of the same activity folded), the schemas learned, timings and Jev usage. The website shows it as the Incident, Event timeline, Execution chain and Evidence table tabs, and offers it as `report.json` with every exact Jev request as `requests.jsonl`.

## The website (Vercel)

`node scripts/build_site.js` assembles `_site/`: `site/index.html`, `ui/app.js`, `ui/view.js`, `ui/styles.css`, the engine modules under `engine/`, and the bundled example `examples/malicious_events.json`. Vercel serves it together with the function `api/jev.js` (`vercel.json`).

- **Analysis in the browser.** Files are read, normalized and linked in a Web Worker, so the page stays responsive on large files. Nothing about them leaves the browser except the Jev requests below.
- **Why a relay.** `api.typesafe.ai` answers the browser's CORS preflight without `Access-Control-Allow-Origin` (checked October 2026), so a page cannot call it. Each Jev request goes to `/api/jev` on the same site, which forwards the body unchanged to TypeSafe and returns TypeSafe's status and body. The relay's own refusals carry `"source": "relay"` and are shown as written. An unreachable TypeSafe returns 502/504, which the engine retries like any temporary failure.
- **Every request is checked.** The relay forwards only a Jev request as the engine builds it: the engine's model, an object state with an analyst context of at most 500 characters, and 1 to 60 Noul or Choice questions with instructions. Incident questions are Nouls; schema-learning questions are Choices. Anything else is refused before it reaches TypeSafe.
- **The site's key.** A request without `Authorization` uses the `TYPESAFE_API_KEY` environment secret, for any logs: visitors can analyze their own files without a TypeSafe account. Each visitor address may send 2,500 requests per 10 minutes per instance, about two investigations of a six-day host. Identical requests are answered from memory. Set a spending limit on that key and a Vercel Firewall rate-limit rule on `/api/jev` for hard limits. One investigation of CLA-WS-214 cost $0.03 to $0.11.
- **Visitor keys.** A request with `Authorization: Bearer <key>` is forwarded with that key for that request only: any Jev-shaped body, 256 KiB at most, 5,000 requests per 10 minutes per address per instance. The relay never logs or stores keys or bodies; `tests/test_relay.js` fails if it writes to the console. Requests must come from the site's own origin as JSON.
- **Connection policy.** The page and `vercel.json` set `default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; connect-src 'self' https://openrouter.ai; base-uri 'none'; form-action 'none'` (plus `frame-ancestors 'none'` as a header). So the page, and the engine thread started from the site's own script, can contact only the site itself (the relay) and OpenRouter.
- **Keys in the page.** OpenRouter and own TypeSafe keys are typed into password fields and kept in page memory. **Remember on this device** stores them in that browser's `localStorage`; **Forget keys** clears both. Learned schema mappings (field names and roles, no data) are kept in `localStorage` so a log format is learned once per browser.
- **Narrative.** Optional. `ui/view.js` sends at most 60 timeline rows straight from the browser to OpenRouter (`credentials: 'omit'`, `referrerPolicy: 'no-referrer'`). Each row comes with how it belongs to the incident: the seed, the event that brought a member in (with Jev's probability and links), or later activity of a member. Rows are chosen with the seed's and members' joining events first. The reply is validated: event IDs must be ones that were sent, ATT&CK tactics must be one of the 14 Enterprise tactics, and technique IDs must look like `T1234` or `T1234.001`. Anything else is dropped. The drafted chain's unknown citations become `[unknown event]`.
- **Retrying.** The engine thread keeps every Jev answer of the session by request hash, so analyzing again after a failure reuses the answers already received.

## Data handling checklist

- Keep `.env`, run outputs and telemetry you aren't authorized to publish outside version control. The bundled lab export `examples/malicious_events.json` is the one intentional data file. Check every staged path before committing.
- A live run sends a summary of the starting point, each candidate and its links to TypeSafe (through the relay on the website). A narrative sends the selected timeline rows to OpenRouter. Only analyze telemetry you may share with them.
- Offline tests mock both providers; they don't measure Jev's accuracy: `npm test` from the repository root runs the relay, build, website and engine suites.

## Code map

| Path | Contents |
|---|---|
| `engine/src` | The engine; see the table in [engine/README.md](engine/README.md#development) |
| `site/index.html` | The website page: Jev access choice, key panel, privacy notice, connection policy |
| `ui/app.js` | The page: loading files into the engine thread, choosing the starting point, the result tabs, downloads |
| `ui/view.js` | What the page shows from a report: members, origins, evidence fields, the Jev-only chain, the OpenRouter narrative |
| `api/jev.js`, `api/_relay.js` | The Jev relay (Vercel function): the site's key within a per-visitor limit, or the visitor's key |
| `scripts/build_site.js`, `scripts/serve_site.js`, `vercel.json` | Website build (including the engine's browser modules), local preview with the relay, Vercel settings |
| `tests/`, `ui/test_site.js` | Relay, build and website tests |
| `examples/` | The bundled lab example: 100 Sysmon and Security records from the detonation of `2.8.exe` on CLA-WS-214 |

The original Python engine and local portal were replaced by this engine; they are in the git history up to the tag `python-engine-final`.
