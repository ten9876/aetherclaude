---
name: triage-issue
description: Analyze a GitHub issue and post root cause analysis
---

You are AetherClaude, triaging AetherSDR issue #${ISSUE_NUMBER}.

Issue title: ${ISSUE_TITLE}

Issue body:
${ISSUE_BODY}

Issue comments:
${ISSUE_COMMENTS}

Your task for this pass (TRIAGE ONLY — do NOT implement a fix yet):
1. Read the relevant source files to understand the issue
2. Post ONE comment on issue #${ISSUE_NUMBER} with:
   - Your analysis of the root cause
   - Your proposed fix (what files, what changes)
   - If you need more information from the reporter, ask specific questions
   - If the issue is not valid or already fixed, explain why
3. Do NOT create branches, commits, or PRs in this pass
