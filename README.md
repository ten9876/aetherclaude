# AetherClaude

Autonomous GitHub issue triage agent for [AetherSDR](https://github.com/aethersdr/AetherSDR) —
a security-first AI coding agent that triages issues, implements fixes, reviews
community PRs, detects duplicates, explains CI failures, and compiles release notes.

## What it does

Runs on a dedicated Mac Mini, triggered by GitHub webhooks in real time (with an
hourly fallback timer). Each cycle:

1. Detects issue state from a SQLite action log
2. Triages new issues (Claude Code with the AetherSDR CLAUDE.md in context)
3. Posts analysis, requests missing info, or transitions to implementation
4. Implements fixes in a clean git worktree, runs validation, creates a PR
5. Reviews incoming community PRs for convention compliance
6. Auto-closes zero-effort submissions
7. Logs every run to Galileo and scores its own triage/implement/review
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

## Evaluation (Galileo)

Enforcement proves a run stayed *contained*; evaluation measures whether it was
*good*. Every Claude invocation is logged to [Galileo](https://galileo.ai) as a
trace, and the three flows are scored against datasets built from our own action
history:

- **Trace path** — the sandboxed agent never touches Galileo. `run_claude` POSTs
  a compact record to the dashboard over localhost (`/api/eval-ingest`); only the
  trusted dashboard holds `GALILEO_API_KEY` and forwards the trace. The agent is
  additionally denied `galileo.ai` at the tinyproxy layer (defense in depth).
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
config/
  launchd/       macOS service definitions
  pf/            firewall anchor
  cloudflared/   tunnel config (no credentials)
scripts/
  deploy.sh      pull + restart on the Mac Mini
```

Copy `.env.example` to `~/.env` and fill in the two values to bootstrap.

## Deploying

On the Mac Mini:

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

**Standing up an independent instance against your own repo** (not the
AetherSDR Mac Mini)? See [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

AGPL-3.0's network copyleft clause matters here: AetherClaude is a hosted
agent that interacts with users over GitHub. Anyone running a modified
version of this code as a hosted service must make their modifications
available to the users they're serving.

---

Part of the [AetherSDR](https://github.com/aethersdr/AetherSDR) project.
Maintained by Jeremy KK7GWY with AI assistance.
