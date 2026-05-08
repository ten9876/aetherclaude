#!/opt/homebrew/bin/bash
# Wraps `skill-scanner` to always activate the new ATR + PromptGuard rule packs
# alongside the default `core` pack on every scan invocation. Without explicit
# --rule-packs, only `core` rules fire — the new packs (added in 2.0.8 / 2.0.9
# and expanded to ~314 rules in 2.0.10) ship installed but inactive.
#
# Used by the DefenseClaw gateway watcher via the binary: line in
# ~/.defenseclaw/config.yaml under scanners.skill_scanner. Other subcommands
# (validate-rules, generate-policy, list-analyzers, etc.) pass through
# unchanged — only scan / scan-all need the rule-pack injection.

set -euo pipefail

SCANNER="/Users/aetherclaude/defenseclaw/.venv/bin/skill-scanner"

case "${1:-}" in
    scan|scan-all)
        sub="$1"
        shift
        # Append at the end so the user's positional skill_directory can't get
        # absorbed by --rule-packs' nargs='+' consumer — there's nothing after
        # the rule-pack list to be confused for a path.
        exec "$SCANNER" "$sub" "$@" --rule-packs core atr promptguard
        ;;
    *)
        exec "$SCANNER" "$@"
        ;;
esac
