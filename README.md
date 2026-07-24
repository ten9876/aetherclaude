# AetherClaude

Autonomous GitHub issue triage agent for [AetherSDR](https://github.com/aethersdr/AetherSDR) —
a security-first AI coding agent that triages issues, implements fixes, reviews
community PRs, detects duplicates, explains CI failures, and compiles release notes.

## What it does

Runs on a local machine triggered by GitHub webhooks in real time (with an
hourly fallback timer). Each cycle:

1. Detects issue state from a SQLite action log
2. Triages new issues (Claude Code with the AetherSDR CLAUDE.md in context)
3. Posts analysis, requests missing info, or transitions to implementation
4. Implements fixes in a clean git worktree, runs validation, creates a PR
5. Reviews incoming community PRs for convention compliance
6. Localizes candidate vulnerabilities with a local Cisco Foundation AI model
   (Antares-1B) and confirms them under sanitizers before feeding the fixer
7. Auto-closes zero-effort submissions
8. Logs every run to Galileo and scores its own triage/implement/review
   quality against curated datasets (the "is the agent any good?" layer)

## Security architecture

Every agent run is wrapped in multiple enforcement layers:

- **pf firewall** — `aetherclaude` UID can only reach GitHub, Anthropic,
  Cloudflare tunnel, and telemetry endpoints. Everything else dropped.
- **tinyproxy** — HTTP proxy with domain allowlist
- **Cisco DefenseClaw CodeGuard** — static analysis of every changed file
  before a PR is pushed (blocks HIGH/CRITICAL findings)
- **Cisco MCP Scanner** — YARA + prompt-defense scan of MCP tool declarations
- **Cisco Skill Scanner** — blocks injected `.claude/` skills in the workspace
- **Validation gate** — blocks modifications to `.github/`, `Dockerfile`, and
  other protected paths
- **DB-driven state machine** — no "proceeding with best judgment" bypass;
  issues in `waiting` state stay there until user replies or 7 days elapse
- **Tetragon** (eBPF observability) — records every tool invocation
- **Token scrubbing** — session JSONL files are scanned on every run for
  `ghs_`, `ghp_`, `github_pat_`, `sk-ant-`, and Galileo key leaks

## Vulnerability detection (Antares · Cisco Cyber AI Foundry pipeline)

Beyond containing the agent, AetherClaude hunts for vulnerabilities in the
*target* code, mirroring Cisco's Cyber AI Foundry evaluation pipeline
(Cartographer → Detector → Validator → Patcher). Everything runs locally — the model never leaves the box.

- **Cartographer** — `bin/codegraph-cartographer.py` turns the clangd/libclang
  code graph into a repo-context pack and a per-CWE **security overlay** (tagged
  buffer/alloc/deserialize/cmd-exec sites). It seeds the Detector and grounds
  `implement-fix`; browse it at `/cartographer`.
- **Detector — Antares-1B** — Cisco Foundation AI's
  [Antares-1B](https://huggingface.co/fdtn-ai/antares-1b) (IBM Granite 4.0,
  Apache 2.0) served locally via Ollama on loopback. On **every issue and PR**
  it explores the repo in a **read-only allowlist-jail sandbox** (`grep`/`find`/
  `cat`/`ls`/`head`/… + pipes, no writes or exec — red-teamed), seeded by the
  Cartographer overlay, and localizes candidate vulnerable files. It posts an
  advisory comment only on a positive verdict, feeds candidates into the fixer,
  and is fully fail-open (`bin/antares-detector.py`).
- **Validator** — for files with a harness, `bin/validate-finding.sh` /
  `bin/fuzz-finding.sh` build the localized code under **AddressSanitizer +
  UndefinedBehaviorSanitizer** (and **libFuzzer**) against crafted/generated
  input, turning a speculative finding into ground truth (`CONFIRMED` /
  `UNCONFIRMED`) with a reproducer — it caught a real signed-overflow in the
  ADIF parser this way. Wired into the orchestrator after the Detector.
- **Nightly sweep** — `bin/antares-sweep.sh` (02:00 PT) runs the Detector across
  ~20 CWE categories × 3 passes, unions the candidates by confidence, fuzz-
  validates the ones with a harness, and writes a ranked report.

Findings surface as GitHub advisory comments and on the dashboard's
**Antares Detector** scanner panel (Ops view).

## Evaluation (Galileo)

Enforcement proves a run stayed *contained*; evaluation measures whether it was
*good*. Every Claude invocation is logged to [Galileo](https://galileo.ai) as a
trace, and the three flows are scored against datasets built from our own action
history:

- **Trace path** — the sandboxed agent never touches Galileo. `run_claude` POSTs
  a compact record to the dashboard over localhost (`/api/eval-ingest`); only the
  trusted dashboard holds `GALILEO_API_KEY` and forwards the trace (through
  tinyproxy). The agent shares that proxy allowlist, so the boundary is the
  credential it lacks, not the network path — without `GALILEO_API_KEY` a reachable
  Galileo host grants it nothing.
- **Scorecard** — `bin/build-eval-datasets.py` curates triage / implement / review
  cases (incl. a known stale-code regression); `bin/run-eval.sh` scores the flows
  and publishes per-flow results to Galileo and the dashboard's **Eval panel**,
  each run deep-linking to the Agent Walk swimlane and its Galileo trace.
- **Operator skills** — the pinned, scanner-vetted `eval-*` skill pack
  (`.claude/skills/PROVENANCE.md`) drives interactive fetch / measure / diagnose.

## Repository layout

```
bin/             Scripts executed by the agent
skills/          Claude Code prompt templates (triage, implement, review, …)
tools/validator/ Antares Validator harnesses + ADIF corpus (sanitizer testbed)
config/
  launchd/       macOS service definitions
  antares/       Antares-1B Ollama Modelfile + model-import doc
  pf/            firewall anchor
  cloudflared/   tunnel config (no credentials)
scripts/
  deploy.sh      pull + restart on the Mac Mini
```

Copy `.env.example` to `~/.env` and fill in the two values to bootstrap.

## Deploying

```bash
git clone https://github.com/ten9876/aetherclaude.git ~/src/aetherclaude
cd ~/src/aetherclaude
./scripts/deploy.sh
```

The deploy script symlinks `bin/` scripts into `/Users/aetherclaude/bin/`,
copies configs into their system locations, and restarts affected launchd
services.

Subsequent edits: commit to `main`, then on the Mac Mini run
`~/src/aetherclaude/scripts/deploy.sh`.

**Standing up an independent instance against your own repo**? See [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

AGPL-3.0's network copyleft clause matters here: AetherClaude is a hosted
agent that interacts with users over GitHub. Anyone running a modified
version of this code as a hosted service must make their modifications
available to the users they're serving.

---

Part of the [AetherSDR](https://github.com/aethersdr/AetherSDR) project.
Maintained by Jeremy KK7GWY with AI assistance.
