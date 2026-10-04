# Contributor leaderboard

A points system for contributions to [aethersdr/AetherSDR](https://github.com/aethersdr/AetherSDR).
Each weekly release names the top contributor of the week. Points reward
taking part in as many ways as possible; they depend on the **kind** of action,
never its size, so a longer comment or a bigger PR earns nothing extra.
Breaking `main` costs points, and costs the reviewer who approved it most.

## Who is ranked

| Who | Shown | Can win |
|---|---|---|
| Community contributors and org members | yes | yes |
| Maintainer (`ten9876`) | yes, scored like everyone else, penalties included | no |
| Bots (the AetherClaude agent, under both its App and its `AetherClaude` user account; the `claude` co-author account; Dependabot, Copilot) | no | no |

A bot's action still counts for the humans involved: merging an agent PR earns
merge points, and an agent PR that breaks `main` still costs its approvers and
merger.

## Points

| Action | Points |
|---|---|
| Comment on a discussion | 1 |
| Comment on an issue | 2 |
| Comment on a PR (or reply in a review thread) | 3 |
| Start a discussion | 2 |
| Your discussion answer is accepted | 4 |
| Open an issue | 4 |
| Your issue is confirmed (labelled `bug`/`enhancement` by someone else) | +2 |
| Your issue is fixed by a merged PR | +5 |
| Open a PR | 5 |
| Your PR is merged | +10 |
| Your merged PR closes a linked issue | +5 |
| Your merged PR adds or changes tests | +2 |
| First merged PR ever | +25 |
| Review that approves | 10 |
| Review that requests changes | 8 |
| Comment-only review | 6 |
| Merge someone else's PR | 10 |
| Your merged PR turns a red `main` green | +15 |
| Your revert is merged | +3 |

### Stewardship

The work that keeps other people's contributions moving, and is easy to
overlook:

| Action | Points |
|---|---|
| Triage someone else's issue: the first label anyone but its author (and not a bot) puts on it | 2 |
| Close someone else's issue by hand: duplicate, not planned, or already fixed (not closes done by a merged PR) | 2 |
| Shepherd someone else's PR: push commits to it (rebase, conflicts, finishing touches) before it merges | 4 |
| Give a PR its first review within 24 hours of it opening | 3 |
| Publish an AetherSDR release | 15 |

Opening a PR pays 5 and merging it 10 more, so most of a PR's value
arrives when it merges.

### Financial support

Contributions to the project's [Open Collective](https://opencollective.com/aethersdr)
earn **10 backer points per $1** (USD, refunds excluded). Backer points are a
third score of their own: they count in the Total ranking and name a
**backer of the week**, but never count toward contributor or steward of the
week. Donors appear under their Open Collective name (gifts under the same
name are merged); `config/contributors/opencollective-map.json` links a
donor's Open Collective slug or name to a GitHub login, merging their backer
points into that person's row.

### Two separate scores

Every action counts toward exactly one of two scores, and each names its own
winner at every release:

- **Contributor points** rank the **contributor of the week**: comments,
  discussions, issues, PRs, fixing `main` and reverts, less the author's own
  breaking-main penalty (with its refund) and spam. The page shows these
  penalties in their own column, never netted against fixes.
- **Steward points** rank the **steward of the week**: reviews, merges,
  triage, closing issues, shepherding PRs, fast first reviews and releases,
  less the approver and merger breaking-main penalties.

A steward is top contributor only if their contributor points alone put them
there, and the other way round. The page shows both scores and ranks by
either.

### How points stack: from issue to merged PR

Points add up along the way, and several people earn from the same fix:

| Who | What happens | Points | Running total |
|---|---|---|---|
| Alice | opens an issue describing the bug | +4 | 4 |
| Alice | a maintainer labels it `bug` | +2 | 6 |
| Bob | comments on the issue with a reproduction | +2 | 2 |
| Bob | opens a PR that fixes it and links the issue | +5 | 7 |
| Carol | reviews the PR and requests changes | +8 | 8 |
| Carol | that was the PR's first review, within 24 hours of it opening | +3 | 11 |
| Bob | replies on the PR after pushing the fix | +3 | 10 |
| Carol | approves the updated PR (on a later day) | +10 | 21 |
| Carol | arms auto-merge, so the PR merges once checks pass | +10 | 31 |
| Bob | his PR is merged | +10 | 20 |
| Bob | the merged PR closes the linked issue | +5 | 25 |
| Bob | the PR added a test | +2 | 27 |
| Bob | it was his first merged PR ever | +25 | 52 |
| Alice | her issue is fixed by the merged PR | +5 | 11 |

Totals: Alice 11 and Bob 52 contributor points; Carol 31 steward points. Bob's
PR alone is worth 50 (25 without the one-time first-PR bonus). Carol's two
reviews both score only because they were on different days. Merging usually
happens this way: the approver arms auto-merge, and GitHub credits them with
the merge. If the PR had broken `main`, Carol would lose 60 (approved and
merged; only the largest penalty counts) and Bob 45, with 15 back for fixing
it within 24 hours; anyone else who turned `main` green would earn 15.

The rules popup on the page builds this example from the live point values.

### Breaking main

| Role in the PR that broke `main` | Points |
|---|---|
| Approved it | −60 |
| Authored it | −45 |
| Merged it | −30 |
| Author fixes their own break within 24 hours | +15 back |
| Issue or PR labelled `spam` | −3 (and no points for opening it) |
| Issue or PR labelled `invalid` | no points for opening it, no penalty |

- A **break** is the first failed `CI` or `Full Suite` run on `main` after a
  green one; both run on every push, so the commit is attributable. The PR is
  the one that commit came from.
- While `main` is already red, a later commit is a break too if its run fails
  something **new**: a test (or, for build failures, a file) that has not
  failed at any point since `main` went red. Landing into a red `main`
  without breaking anything further costs nothing, and a test that flips
  between runs during the stretch is not counted twice.
- Whoever turns `main` green again earns "fixed main" once per green run,
  however many breaks it closes.
- Failures caused by the runner rather than the code (out of disk, out of
  memory, timeout, lost runner) don't count, and neither do failures that pass
  when re-run (a re-run that passes replaces the failure).
- Only approvals of the commit that was merged count; an approval of an
  earlier push, or one GitHub dismissed, does not.
- Every approver pays. A person with several roles in the same PR takes only
  their largest penalty.

### Anti-farming rules

- Comments must be at least 15 characters and not just `+1`/`thanks`/`LGTM`.
- At most one scored comment per person per thread per day, and 10 scored comments a day overall.
- Replies on your own PR: at most 2 scored per PR.
- One scored review per reviewer per PR per day (the strongest state that day).
- A comment counts once, however it is threaded. GitHub stores each reply in
  an inline review thread as a review of its own; a comment-only review that
  has no summary and opens no new thread is a **reply**, scored as a PR comment
  (under the comment caps), not as another review. Inline comments
  are part of their review and never score separately, and a discussion
  comment and its replies share the thread's daily cap.
- Once a reviewer's review scores on a PR, their other comments and replies on
  that PR the same day add nothing.
- A PR author's replies on their own PR are comments, capped as above, never
  reviews.
- At most 4 issue opens and 15 issue closes score per person per day.

## Weekly windows

A week runs from one non-prerelease AetherSDR release to the next, so the
winners are known when the release is published. The current week is shown as
"leading" until the next release lands. Contributor ties break on more PR points, then more issue points; steward
ties on more review points.

## Data model

`bin/contributor-points.py` stores **facts** from GitHub and rebuilds the
**ledger** from them on every run. Facts never change once written; a rule
change or a revocation (a spam label, a dismissed approval, a re-run that went
green) is just a re-score, and the all-time board stays consistent.

| Table | Holds |
|---|---|
| `people` | login, user/bot, role (maintainer, contributor, bot), avatar |
| `items` | issues, PRs and discussions: author, created/closed, close reason, labels, title; for PRs merged at/by, head and merge commits, linked issues closed, whether `tests/` changed |
| `comments` | issue, PR and discussion comments and replies: who, when, whether substantive (length floor only) |
| `reviews` | reviewer, state, commit reviewed, when, whether it has a summary |
| `review_comments` | inline review comments: which review, and whether each is a reply to an existing thread |
| `labels` | who added which label when (confirmation, spam) |
| `answers` | accepted discussion answers |
| `releases` | tags, publish times (the weekly windows) and who published them |
| `closes` | who closed which issue, how (duplicate, not planned, completed) and whether a commit closed it |
| `pr_commits` | the commits on each merged PR and who authored them (shepherding) |
| `runs` | `CI`/`Full Suite` runs on `main`: commit, result, failure cause, and the failure signature (failing tests, else the failing file) |
| `first_merges` | each person's first merged PR |
| `oc_contributions` | every Open Collective contribution: amount, date, donor and the raw record |
| `ci_logs` | every failed CI job's log (zlib-compressed), with workflow, branch, commit, cause and failing tests |
| `http_cache` | raw GitHub responses for fixed URLs (PRs with their diffs, reviews, inline comments, commits, issue events), kept with their ETags |
| `state` | collection cursors and commit → PR lookups |

Beyond what scoring needs, the database keeps the raw text: issue, PR and
discussion descriptions, every comment and reply, review summaries, inline
review comments with their file and line, and the logs of failed CI jobs.
GitHub deletes Actions logs after 90 days, so these copies are the lasting
record. The collector makes a compressed backup of the database once a day,
keeping the last seven.

The scorer turns facts into ledger entries `(login, rule, points, when,
item, note)`, applying the caps in time order, and the page groups them by
window and by category.

## Collection

| Fact | Source |
|---|---|
| Issues and PRs | `GET /repos/{repo}/issues?state=all&since=…` (one feed for both) |
| PR merger, head commit | `GET /pulls/{n}` |
| Linked issues closed | GraphQL `pullRequest.closingIssuesReferences` |
| Tests changed | `GET /pulls/{n}/files` |
| Reviews | `GET /pulls/{n}/reviews` |
| Inline review comments (to tell replies from reviews) | `GET /pulls/{n}/comments` |
| Comments | `GET /repos/{repo}/issues/comments?since=…` (issue and PR conversation) |
| Labels | `GET /repos/{repo}/issues/events` (`labeled`) |
| Discussions, replies, answers | GraphQL `repository.discussions` |
| Releases (and who published them) | `GET /repos/{repo}/releases` |
| Issue closes | `GET /repos/{repo}/issues/events` (`closed`) |
| Commits on merged PRs | `GET /pulls/{n}/commits`, once per merged PR |
| Breaks | `GET /actions/workflows/{ci,full-suite}.yml/runs?branch=main`, the failed job's log (cause), `GET /commits/{sha}/pulls` |
| First merged PR | search `is:pr is:merged author:{login}` |

Collection is incremental from a `since` cursor and throttled so it never uses
more than a fixed share of the hourly API budget. Inline review comments are
fetched only to classify reviews; they never score on their own.

## Public mirror

**contributors.aethersdr.com** is a Cloudflare Worker (in the
`aethersdr/aetherweb` repo) that copies `/leaderboard` and
`/api/leaderboard` into its own store and serves only that copy, so it stays
up when this host is unreachable. To keep the two from drifting:

- The standings carry a content hash and the hash of the page they render
  with; the mirror's `/healthz` reports the hashes it copied, when it synced
  and why, warnings, and the commit it was deployed from.
- The dashboard asks the mirror to sync (`POST /sync`, shared token) as soon
  as its standings change; the mirror's 15-minute cron is the fallback.
- Every 5 minutes the dashboard compares the mirror's `/healthz` with its own
  hashes. A mirror more than 30 minutes behind, serving a different page or
  different standings once a sync has had 20 minutes to land, reporting a
  warning, or unreachable raises a dashboard alert.
- The Worker is deployed only from CI, which stamps the version with the
  commit and checks the mirror reports it.

## Page

`/leaderboard` on the dashboard: tabs for this week, the last releases and all
time; the leader (or the week's winner) at the top; a row per person with
points by category, the maintainer in score order but unranked, with a
**MAINTAINER** badge (its tooltip says the maintainer can't win); each row expands into the point-by-point ledger; the main
breaks in the window; and the rules.
