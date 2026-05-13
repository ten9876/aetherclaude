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
| **Strong** — AetherClaude implements the principle as the constitution describes | 7 |
| **Partial** — AetherClaude implements the spirit but differs on a detail | 2 |
| **Not applicable** — different problem domain (vulnerability findings vs. code changes) | 2 |
| **Total** | 11 |

The 7 STRONG entries cover II (surface-filtering), III (heartbeat liveness), and
IV/V/IX/X/XI (atomic-and-mortal claims, provider-as-arbiter, infrastructure-
enforced sandbox, operator-outranks-agent, atomic persistence). PARTIAL: I
(evidence — implemented as a non-blocking citation-resolution footnote rather
than a verdict-gating demotion) and VII (independent grading — same shape,
different domain than "exploited"). N/A: VI (no termination decision in our
event-driven model) and VIII (no finding-fingerprint domain — issue numbers
are stable by definition).

## The mapping

### I. Evidence Over Assertion — *partial*

> A finding's verdict is determined by checkable evidence, not by model
> confidence.

**AetherClaude analog**: Two layers, one per claim type.

For "this fix is correct" claims: the state machine cannot mark an
issue `done` without (a) a real commit produced in the worktree, (b)
a passing `validate-diff.sh` (allowed paths, no credentials, no
protected files, no binary additions, no suspicious patterns, plus
per-file CodeGuard static analysis), and (c) a successful signed-
commit push.

For "this code lives at path:line" claims in the triage comment:
`check_citations()` (in `bin/run-agent.sh`) runs after every triage
completes, parses every `path:line` and `path:line-line` token from
the agent's comment, and verifies each against the workspace clone of
AetherSDR at `origin/main`. Resolved counts and unresolved-citation
tables are PATCHed onto the comment itself as a footnote so a human
reading the issue can see which citations to trust.

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) `check_citations()` + state
machine + [`bin/validate-diff.sh`](../bin/validate-diff.sh) checks 1–8.

**Why still partial**: per operator decision in this session, the
citation footnote is **non-blocking** — unresolved claims are
annotated, not retracted. Foundry's principle demotes the claim;
ours surfaces it. Same evidence, different consequence.

---

### II. Surface Only What Survives — *strong*

> Humans see findings that have passed the gates. Everything else stays
> in the internal store.

**AetherClaude analog**: Issues are filtered *before* a maintainer sees
agent output, at four distinct gates:

1. The zero-effort guard auto-closes issues with body <200 chars + no
   required fields + no images or code blocks, posting a template
   comment instead of running triage.
2. The 7-day stale-close path retires waiting issues that never got a
   user reply.
3. The triage step posts **one** comment per issue — never a stream of
   Claude's intermediate observations.
4. The `aetherclaude-eligible` label is the maintainer's explicit
   "this survived the gates, surface it for implementation" signal;
   without that label, an issue stays parked in `maintainer-review`.

The shape matches Foundry's principle even though the architecture
differs (event-driven per-issue runs instead of a continuous detection
store): the operator-facing surface only ever shows promoted output.

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) `skill_process_issues` zero-
effort guard, 7-day stale-close path, the `aetherclaude-eligible`
label gate, and the [`run-stale-triage.sh`](../bin/run-stale-triage.sh)
periodic stale runner.

---

### III. Liveness By Heartbeat, Never By Clock — *strong*

> An agent is alive if it heartbeated recently. Wall-clock runtime says
> nothing about health.

**AetherClaude analog**: The Claude watchdog polls the active session
JSONL's mtime — Claude appends to that file on every `tool_use` /
`tool_result` / `text` block, so a fresh mtime is proof of life.
Kill only fires when:

- The JSONL has been quiet for more than `CLAUDE_MAX_IDLE` seconds
  (default **180**), AND total elapsed > 60s (startup grace).
- OR the absolute `CLAUDE_HARD_CEILING` (default **3600s** / 60 min)
  is hit — a runaway loop that produces output indefinitely still
  gets stopped, but a productive 25-minute implement run keeps going.

The previous fixed wall-clock kill (`CLAUDE_TIMEOUT=1800s`) was
explicitly the failure mode the principle warns about — trace
`50f9d8d0` on #2624 was actively making tool calls at the 18-min
mark when the old watchdog SIGTERM'd it. Heartbeat-based liveness
lets that exact run keep going.

`CLAUDE_TIMEOUT` is retained as a backward-compat alias for
`CLAUDE_HARD_CEILING` so existing env overrides still take effect.

**Where**:
[`bin/run-agent.sh`](../bin/run-agent.sh) `run_claude()` heartbeat
watchdog (`session_dir` derived from `pwd -P`; polls `stat -f %m` on
the newest JSONL every 10s).

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
