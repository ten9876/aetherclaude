#!/usr/bin/env python3
"""Convert AetherClaude skill templates into MCP `prompts/list` JSON for
mcp-scanner's `static --prompts` analyzer.

Each `~/skills/*.md` file has YAML frontmatter (name, description) and a
template body (the actual prompt the orchestrator feeds to Claude). For
prompt_defense scanning we want the analyzer to see the FULL body, so we
emit the body as the `description` field. The frontmatter `name` becomes
the prompt name.

Usage:
    skills-to-prompts-json.py [SKILLS_DIR]

Writes JSON to stdout.
"""
import json, os, sys

SKILLS_DIR = sys.argv[1] if len(sys.argv) > 1 else '/Users/aetherclaude/skills'

prompts = []
for fname in sorted(os.listdir(SKILLS_DIR)):
    if not fname.endswith('.md'):
        continue
    path = os.path.join(SKILLS_DIR, fname)
    with open(path) as f:
        text = f.read()

    name = fname[:-3]
    body = text

    # Strip YAML frontmatter (between --- markers at top of file)
    if text.startswith('---\n'):
        end = text.find('\n---\n', 4)
        if end > 0:
            front = text[4:end]
            body = text[end + 5:].lstrip('\n')
            for line in front.split('\n'):
                if ':' in line:
                    k, _, v = line.partition(':')
                    if k.strip() == 'name':
                        name = v.strip()

    prompts.append({
        'name': name,
        'description': body,
    })

print(json.dumps({'prompts': prompts}, indent=2))
