# Vendored CodeGuard rules

The rule files under `rules/` are vendored **verbatim** (no changes) from
**Project CodeGuard** (a Coalition for Secure AI / OASIS project), release
**1.5.0**:

- Source: <https://github.com/cosai-oasis/project-codeguard> · <https://project-codeguard.org>
- License: the rules are licensed under Creative Commons Attribution 4.0
  International (CC BY 4.0) — <https://creativecommons.org/licenses/by/4.0/>.
  Project CodeGuard's tooling is Apache-2.0; none of it is vendored here.
- Vendored rules:
  - `codeguard-1-hardcoded-credentials.md`, `codeguard-1-crypto-algorithms.md`,
    `codeguard-1-digital-certificates.md` — the three `alwaysApply` rules
    (vendored 2026-08-06 and 2026-10-01; re-verified byte-identical at 1.5.0).
  - `codeguard-0-safe-c-functions.md` — added 2026-10-01. AetherSDR is C/C++,
    and the fixer did not open the on-demand rules it was pointed at.

`bin/run-agent.sh` injects all four into the `implement-fix` prompt as a
secure-by-default floor. Only this subset is vendored so the fixer's context
stays small and deterministic. The full language-scoped set lives on the Mini
in the Project CodeGuard plugin checkout
(`~/.claude/plugins/marketplaces/project-codeguard/sources/rules/`), which the
`security-audit` subagent reads. Update in lockstep with that plugin
(`claude plugin marketplace update project-codeguard`, then
`claude plugin update codeguard-security@project-codeguard`).
