---
name: audit-fix
description: Security-audit the agent's own fix before it is pushed, and fix confirmed findings
---

You are AetherClaude. You have already implemented a fix for AetherSDR issue
#${ISSUE_NUMBER} on this branch, and it passed the validation gate. Before it
is pushed, the harness ran its security triage on your change:

${SECURITY_AUDIT}

Your task for this pass (AUDIT):

1. Launch the `security-audit` subagent exactly once, as instructed above.
   Do not launch any other subagent.
2. For each finding it returns, open the cited code and confirm it against
   your change. Discard findings that do not hold up; keep a one-line reason.
3. For each confirmed finding in code your fix added or modified, fix it in
   place with the smallest change that removes the defect. Do not refactor,
   do not widen the scope beyond the files listed above, and do not touch
   pre-existing code your fix did not change — note those instead.
4. If you changed anything, commit it with
   `git commit -am "Address security audit findings (#${ISSUE_NUMBER})"`.
   If nothing needed fixing, make no commit.
5. End with a short summary: findings confirmed and fixed, findings
   discarded (with reason), and pre-existing issues noted but left alone.
