#!/Users/aetherclaude/defenseclaw/.venv/bin/python
"""Run mcp-scanner's PROMPT_DEFENSE analyzer (and YARA) against a prompts/list
JSON file by calling Scanner directly.

Bypasses the upstream CLI bug in mcp-scanner v4.6.0 where the `static`
subcommand's analyzer-list builder silently drops `prompt_defense` (and
several other analyzers) — see cli.py main() around the
"No analyzers available" branch. The Scanner class internally instantiates
PromptDefenseAnalyzer correctly; we just need to bypass the broken CLI
analyzer-list builder.

Output format: same shape as `mcp-scanner ... --format raw static --prompts FILE`.
{
  "scan_results": [
    {
      "prompt_name": "...",
      "prompt_description": "...",
      "is_safe": true|false,
      "findings": {<analyzer_name>: {severity, threat_summary, threats: {...}, ...}, ...},
      "item_type": "prompt",
      "status": "completed"
    },
    ...
  ],
  "requested_analyzers": ["yara", "prompt_defense"]
}

Usage:
    scan-prompts-pd.py PROMPTS_JSON > output.json
"""
import asyncio
import json
import sys

from mcp.types import Prompt as MCPPrompt
from mcpscanner.config.config import Config
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.scanner import Scanner


def _serialize_findings(findings):
    """Group findings by analyzer name into the per-analyzer dict shape that
    --format raw emits. Mirrors mcpscanner.core.report_generator behavior."""
    grouped = {}
    for f in findings:
        analyzer_key = f"{f.analyzer.lower()}_analyzer" if f.analyzer else "unknown_analyzer"
        slot = grouped.setdefault(analyzer_key, {
            "severity": "SAFE",
            "threat_names": [],
            "threat_summary": "",
            "total_findings": 0,
            "threats": {"items": []},
        })
        # Severity: highest wins (HIGH > MEDIUM > LOW > SAFE)
        sev_rank = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if sev_rank.get(getattr(f, "severity", "SAFE"), 0) > sev_rank.get(slot["severity"], 0):
            slot["severity"] = getattr(f, "severity", "SAFE")
        if getattr(f, "threat_name", None):
            slot["threat_names"].append(f.threat_name)
        slot["threats"]["items"].append({
            "technique_name": getattr(f, "threat_name", "") or getattr(f, "title", ""),
            "severity": getattr(f, "severity", "SAFE"),
            "summary": getattr(f, "summary", "") or getattr(f, "description", ""),
        })
        slot["total_findings"] += 1
    for slot in grouped.values():
        if slot["total_findings"]:
            names = sorted(set(slot["threat_names"]))
            slot["threat_summary"] = (
                f"Detected {slot['total_findings']} threat"
                + ("s" if slot["total_findings"] > 1 else "")
                + (": " + ", ".join(names) if names else "")
            )
        else:
            slot["threat_summary"] = "No threats detected"
    return grouped


async def main():
    if len(sys.argv) < 2:
        print("usage: scan-prompts-pd.py PROMPTS_JSON", file=sys.stderr)
        sys.exit(2)

    with open(sys.argv[1]) as f:
        data = json.load(f)
    prompts = data.get("prompts", [])

    cfg = Config()
    scanner = Scanner(config=cfg)
    analyzers = [AnalyzerEnum.YARA, AnalyzerEnum.PROMPT_DEFENSE]

    results = []
    for p in prompts:
        prompt = MCPPrompt(
            name=p.get("name", "unknown"),
            description=p.get("description", "") or "",
        )
        try:
            # _analyze_prompt is the (private) method that the public
            # CLI plumbing eventually calls per-prompt. The public
            # surface only exposes scan_remote_server_prompt /
            # scan_stdio_server_prompts which require a live server, so
            # we bypass that for our static-prompts use case.
            scan_result = await scanner._analyze_prompt(prompt, analyzers)
            findings = scan_result.findings if hasattr(scan_result, "findings") else []
            # PromptDefense is an ADVISORY hardening checklist (12 vectors of
            # "does this prompt include defensive language?"). It does not
            # detect attacks — it audits hardening completeness. So a prompt
            # without explicit hardening language gets up to 12 HIGH findings
            # even if it's totally benign. Don't conflate that with threats.
            #
            # is_safe is decided by the OTHER analyzers (yara is the threat
            # detector for our purposes) plus any CRITICAL severity finding.
            threat_findings = [
                f for f in findings
                if getattr(f, "analyzer", "") != "PromptDefense"
                or getattr(f, "severity", "SAFE") == "CRITICAL"
            ]
            advisory_count = sum(
                1 for f in findings if getattr(f, "analyzer", "") == "PromptDefense"
            )
            is_safe = not any(
                getattr(f, "severity", "SAFE") in ("HIGH", "CRITICAL", "MEDIUM")
                for f in threat_findings
            )
            results.append({
                "prompt_name": prompt.name,
                "prompt_description": prompt.description[:300],
                "is_safe": is_safe,
                "advisory_hardening_findings": advisory_count,
                "findings": _serialize_findings(findings),
                "item_type": "prompt",
                "status": "completed",
            })
        except Exception as e:
            results.append({
                "prompt_name": prompt.name,
                "is_safe": True,
                "findings": {},
                "item_type": "prompt",
                "status": "error",
                "error": str(e),
            })

    print(json.dumps({
        "scan_results": results,
        "requested_analyzers": ["yara", "prompt_defense"],
    }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
