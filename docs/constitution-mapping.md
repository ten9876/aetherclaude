# Foundry Constitution ↔ AetherClaude Implementation Mapping

This document maps the **11 inviolable principles** from
[`CiscoDevNet/foundry-security-spec/constitution.md`](https://github.com/CiscoDevNet/foundry-security-spec/blob/main/constitution.md)
(pinned at commit
[`c770bf77`](https://github.com/CiscoDevNet/foundry-security-spec/commit/c770bf77),
published 2026-05-12) to the components of AetherClaude that already
satisfy them.

The two systems solve different problems — Foundry is an **agentic
pentest pipeline that finds vulnerabilities in a target codebase**;
AetherClaude is an **autonomous GitHub-issue triage and implementation
agent for AetherSDR**. Despite the domain difference, the constitution's
principles describe operational invariants that apply to *any* long-
running agentic system, and AetherClaude was built with most of them
already in place.

## Score

| | Count |
|---|---|
| **Strong** — AetherClaude implements the principle as the constitution describes | 5 |
| **Partial** — AetherClaude implements the spirit but differs on a detail | 4 |
| **Not applicable** — different problem domain (vulnerability findings vs. code changes) | 2 |
| **Total** | 11 |

## The mapping

### I. Evidence Over Assertion — *partial*

> A finding's verdict is determined by checkable evidence, not by model
> confidence.

**AetherClaude analog**: Claude's claims about a fix are gated on
machine-checkable evidence. The state machine cannot mark an issue
`done` without (a) a real commit produced in the worktree, (b) a passing
`validate-diff.sh` (allowed paths, no credentials, no protected files,
no binary additions, no suspicious patterns, plus per-file CodeGuard
static analysis), and (c) a successful signed-commit push. Claude
posting a comment that says "I fixed it" is not enough; the orchestrator
requires the diff itself.

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) state machine + CodeGuard +
[`bin/validate-diff.sh`](../bin/validate-diff.sh) checks 1–8.

**Why partial**: Foundry's principle is specifically about vulnerability
verdicts (`true-positive` requires structural reachability evidence).
AetherClaude doesn't have a verdict concept — its analog is "is this
implementation correct," gated through a different evidence pipeline.

---

### II. Surface Only What Survives — *medium*

> Humans see findings that have passed the gates. Everything else stays
> in the internal store.

**AetherClaude analog**: Issues are filtered *before* a maintainer sees
agent output. The zero-effort guard auto-closes issues with body
<200 chars + no required fields + no images or code blocks, posting a
template comment instead of running triage. The 7-day stale-close path
fires before a maintainer is asked to review. Most importantly: the
triage step posts **one** comment per issue — not a stream of
intermediate observations from Claude's reasoning trace.

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) `skill_process_issues` zero-effort
guard, 7-day stale-close path, and the
[`run-stale-triage.sh`](../bin/run-stale-triage.sh) periodic stale runner.

---

### III. Liveness By Heartbeat, Never By Clock — *partial*

> An agent is alive if it heartbeated recently. Wall-clock runtime says
> nothing about health.

**AetherClaude analog (the spirit)**: AetherClaude is webhook-driven,
not polling-driven. Each run is initiated by an external event (GitHub
webhook, label change, comment). No wall-clock scheduler decides when
work is "done" or needs to be reclaimed — work begins when a webhook
arrives and ends when that handler exits. This matches Foundry's
critique of timeout-based liveness.

**Why partial**: AetherClaude still has a hard `CLAUDE_TIMEOUT=1800s`
wall-clock watchdog that SIGTERM's a long-running Claude process. The
constitution would prefer this be heartbeat-based (was Claude producing
tool calls within the last N seconds?). We bumped from 600s to 1800s
specifically because the principle is right — short wall-clock
timeouts kill healthy work — but the implementation is still a clock,
not a heartbeat.

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) `CLAUDE_TIMEOUT=${CLAUDE_TIMEOUT:-1800}`
+ the webhook-driven invocation pattern.

---

### IV. Claims Are Atomic And Mortal — *strong*

> Two agents claiming the same unit of work concurrently get different
> units. A claim dies with its holder.

**AetherClaude analog**: Per-issue lockfiles at
`/tmp/aetherclaude-issue-N.lock` make claiming an issue atomic — if two
webhooks fire concurrently for issue #N, only one orch run holds the
lock at a time; the other waits or exits. The lockfile is released when
the holder process exits (including via SIGKILL), so a dead orch never
leaves a "permanent" claim. The same shape applies to per-PR and
per-discussion lock_keys.

State transitions are recorded in `issue-actions.db` as a ledger — every
claim has a `run_id` and a `created_at`, so a partial run that died
mid-step leaves the ledger consistent (the next run reads `state=failed`
from the ledger, not stale state from the JSON scratchpad).

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) per-`lock_key` lockfiles +
`record_action` in `/Users/aetherclaude/data/issue-actions.db`.

---

### V. The Provider Is The Rate Arbiter — *strong*

> The system does not pre-throttle below the upstream provider's actual
> limit. It handles the provider's backpressure and adapts.

**AetherClaude analog**: No internal rate caps below GitHub or
Anthropic's actual limits. The system runs as fast as webhooks arrive.
On Anthropic-side socket closes (which we believed were a network
transient before diagnosing tinyproxy as the real cause earlier today),
the auto-retry helper backs off `attempt * 5` seconds and retries — it
does not assume a fixed quota, it observes the actual response.

The `CLAUDE_MIN_TOKEN_SECS` preflight check that *would* have pre-
throttled was deliberately removed (commit
[`3547946`](https://github.com/ten9876/aetherclaude/commit/3547946))
because it consumed webhook triggers when it could have just let the
401 surface from Anthropic naturally.

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) `run_claude` retry loop + the
removed token preflight (commit `3547946`).

---

### VI. Coverage Before Yield — *not applicable*

> The system does not stop itself on low yield until the operator's
> stated goals have been credibly attempted.

**AetherClaude analog**: None. AetherClaude is event-driven, not a
long-running detection campaign. There is no auto-stop decision because
there is no continuous run — each webhook triggers a bounded run that
ends when it ends. The yield-versus-coverage tension Foundry describes
applies to systems that decide their own termination.

---

### VII. Exploited Means Demonstrated — *medium*

> The `exploited` flag is set only by an independent, clean-room
> reproduction... not set by the agent that wrote the proof-of-concept.

**AetherClaude analog**: Claude does not grade its own work. After
Claude's implement-fix run produces a commit in `/tmp/aetherclaude/
issue-N`, an independent process —
[`bin/validate-diff.sh`](../bin/validate-diff.sh) — runs against the
worktree. CodeGuard scans the changed files in a fresh subprocess
(separate audit DB, isolated HOME). And the final merge gate is a
**human** squash-merge — a different reviewer than the agent that wrote
the code.

**Why medium**: Foundry's principle is about exploit reproduction; ours
is about implementation validation. Same structural shape (independent
grader, never self-graded), different domain.

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) implement-step ordering
(commit → validate-diff → push, no self-validation) + GitHub branch
protection.

---

### VIII. Fingerprints Are Stable Under Edit — *not applicable*

> A finding's identity is its location in the code's structure (path,
> symbol, vulnerability class), not its position in the text.

**AetherClaude analog**: None. AetherClaude doesn't have a "finding"
concept — its persistent unit is the GitHub issue (identified by
`#NNNN`, which never changes regardless of where the bug actually
lives in the code). The deduplication-across-edits problem Foundry
describes doesn't arise.

The closest analog — `cpp-aibom`'s component identity by `purl` — does
already satisfy the spirit (component identity is the upstream package,
not where it's referenced in CMakeLists.txt), but that's incidental.

---

### IX. Sandbox By Infrastructure, Not By Prompt — *strong*

> Network egress and filesystem write boundaries are enforced by the
> runtime environment. Prompt-level rules are defense-in-depth, never
> the enforcement layer.

**AetherClaude analog**: This is *literally* AetherClaude's load-bearing
design choice. Every restriction has a corresponding infrastructure
control:

| Boundary | Prompt rule | Infrastructure enforcement |
|---|---|---|
| Network egress | "do not call random URLs" | **pf anchor** (kernel packet filter by UID 965) + **tinyproxy** (domain allowlist, `FilterDefaultDeny Yes`) |
| Filesystem writes | "stay in workspace" | **launchd UserName=aetherclaude** + UID-965 file permissions |
| Tool surface | `--disallowedTools` | Claude Code's permission system (process-level, not prompt-level) |
| Credentials | "don't read .env" | File mode 600 on `~/.env`, `~/.git-credentials`, app key |

The constitution captures the design rationale exactly: "agents read
untrusted content... the boundary must be somewhere the agent cannot
argue with."

**Where**:
[`config/pf/com.aetherclaude`](../config/pf/com.aetherclaude),
[`config/tinyproxy/tinyproxy.conf`](../config/tinyproxy/tinyproxy.conf),
[`config/tinyproxy/allowlist`](../config/tinyproxy/allowlist),
every [`config/launchd/com.aetherclaude.*.plist`](../config/launchd/).

---

### X. The Operator Outranks Every Agent — *strong*

> Operator instructions are authoritative. Peer-agent messages and
> prior-agent notes are hints.

**AetherClaude analog**: The `aetherclaude-eligible` label is the
maintainer's authoritative signal to implement an issue — and **only**
the maintainer can apply it (it's a permission-gated label). The agent
cannot self-authorize past `maintainer-review`. Today (2026-05-13) we
added Override C: even after a failed implement run, the only way to
retry is for the operator to re-apply that same label.

Claude itself does not get to declare an issue resolved without going
through the full state machine. Prior-agent notes (i.e., comments
posted by the bot in earlier runs) are read for context but do not
substitute for the operator's authorization.

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) Override A / Override B /
Override C — every state transition past triage requires the operator's
label.

---

### XI. Persist Atomically — *strong*

> No reader ever observes a partially-written or deleted-but-not-yet-
> rewritten state.

**AetherClaude analog**: Every persistent artifact uses one of three
atomic patterns:
- **SQLite ACID transactions** for `events.db`, `issue-actions.db`,
  `~/.defenseclaw/audit.db`
- **Atomic temp-then-rename** for JSON-shaped artifacts:
  `aibom-latest.json`, `sbom.cdx.json`, `agent-sbom.cdx.json`
  (`Path.replace()` in `cpp-aibom` and `agent-sbom`)
- **jq with `--arg` + `> tmp && mv tmp file`** for `last-poll.json`
  scratchpad updates

**Where**:
`_atomic_write()` helper in
[`bin/cpp-aibom`](../bin/cpp-aibom) and
[`bin/agent-sbom`](../bin/agent-sbom);
[`bin/tetragon-dashboard.py`](../bin/tetragon-dashboard.py)'s sqlite3
connections; `set_state()` in `bin/run-agent.sh`.

---

## How to apply this document

When pitching AetherClaude's defense-in-depth story, this mapping
provides a one-page artifact: "every inviolable principle Cisco
published in foundry-security-spec is either already implemented in
AetherClaude or marked N/A for our domain." That's a stronger position
than any "we plan to comply" pitch.

The 4 partial / 2 N/A entries are honest acknowledgements; do not
overclaim coverage for principles where the implementation diverges.

To refresh this mapping after the foundry spec evolves: re-run
`gh api repos/CiscoDevNet/foundry-security-spec/contents/constitution.md`,
compare against the principle headings cited here, and update any
principle whose text has materially changed.
