# eval-engineer skill pack — provenance & vetted-install procedure

The `eval-*` operator skills (used interactively to fetch Galileo traces, build
datasets, measure, diagnose) come from a third party. Per AetherClaude's
skill-scanner discipline we do **not** commit their bodies unvetted, and we pin
to a specific upstream commit — the same treatment as the Cisco AI-defense
pinned baseline.

## Pin

- Upstream: https://github.com/Galileo-Agent-Labs/eval-engineer
- License: MIT
- Pinned commit: `4056a2334c75c2c298b87c42d91a76a6494959cd` (2026-05-29)

Bump the pin only via the same delta-check discipline used for `ai-defense`:
diff upstream against the pinned SHA, re-scan, then update this file.

## Vetted install (run on the Mac Mini, NOT from `uvx` blind)

```bash
# 1. Fetch the pinned revision into a scratch dir
git clone https://github.com/Galileo-Agent-Labs/eval-engineer /tmp/eval-engineer
git -C /tmp/eval-engineer checkout 4056a2334c75c2c298b87c42d91a76a6494959cd

# 2. Gate it through the SAME scanners every skill must pass BEFORE activation
/Users/aetherclaude/bin/skill-scanner-with-packs.sh /tmp/eval-engineer/skills
#   (and the Cisco AI-defense scanners, per the ai-defense procedure)
#   Do not proceed if any HIGH/CRITICAL finding is reported.

# 3. Only if clean: vendor the eval-* skills into this repo's operator scope
cp -R /tmp/eval-engineer/skills/eval-* /Users/aetherclaude/src/aetherclaude/.claude/skills/
```

The vendored `.claude/skills/eval-*/` directories are gitignored until they have
passed the scanners — commit them explicitly (a `git add -f`) once vetted, so the
pin and the audited bodies land together.

## Scope note

These skills are **operator tooling** run in an interactive Claude Code session
against Galileo. They are NOT part of the autonomous `run-agent.sh` loop and live
in the aetherclaude repo, separate from the scanned agent workspace
(`/Users/aetherclaude/workspace/AetherSDR`) — so they never enter the sandbox's
skill-scan surface.
