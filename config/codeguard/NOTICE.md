# Vendored CodeGuard rules

The rule files under `rules/` are vendored **verbatim** from **Project CodeGuard**
(a Coalition for Secure AI / OASIS project), release **1.5.0**:

- Source: <https://github.com/cosai-oasis/project-codeguard> · <https://project-codeguard.org>
- License: Apache-2.0
- Vendored: 2026-08-06; re-verified byte-identical at 1.5.0 on 2026-10-01
  (the two `alwaysApply` rules — no hardcoded credentials, modern
  cryptography — injected as a secure-by-default floor into the
  `implement-fix` skill by `bin/run-agent.sh`).
- `codeguard-0-safe-c-functions.md` added 2026-10-01 from 1.5.0. AetherSDR is
  C/C++, and the fixer did not open the on-demand rules it was pointed at, so
  this one is injected alongside the always-apply pair.

Only this subset is vendored here so the fixer carries a small, deterministic
security floor without bloating its context. The full language-scoped set
lives on the Mini in the Project CodeGuard plugin checkout
(`~/.claude/plugins/marketplaces/project-codeguard/sources/rules/`) and is
pointed to for optional, language-specific consultation. Update in lockstep
with that plugin (`claude plugin marketplace update project-codeguard`, then
`claude plugin update codeguard-security@project-codeguard`).
