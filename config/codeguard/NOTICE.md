# Vendored CodeGuard rules

The rule files under `rules/` are vendored **verbatim** from **Project CodeGuard**
(a Coalition for Secure AI / OASIS project), release **1.4.0**:

- Source: <https://github.com/cosai-oasis/project-codeguard> · <https://project-codeguard.org>
- License: Apache-2.0
- Vendored: 2026-08-06 (the two `alwaysApply` rules — no hardcoded credentials,
  modern cryptography — injected as a secure-by-default floor into the
  `implement-fix` skill by `bin/run-agent.sh`).

Only the always-apply subset is vendored here so the fixer carries a small,
deterministic security floor without bloating its context. The full 109-rule,
language-scoped set lives on the Mini in the Project CodeGuard plugin checkout
(`~/.claude/plugins/marketplaces/project-codeguard/sources/rules/`) and is
pointed to for on-demand, language-specific consultation. Update in lockstep
with that plugin (`claude plugin marketplace update project-codeguard`).
