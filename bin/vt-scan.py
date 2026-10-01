#!/Users/aetherclaude/defenseclaw/.venv/bin/python
"""Run mcp-scanner's VirusTotal analyzer on a path by calling it directly.

Bypasses the mcp-scanner CLI's `virustotal` subcommand, which crashes in
4.7.0 through 4.8.4 with UnboundLocalError: a function-local `import os` in
cli.py main() shadows the module import (upstream issue
cisco-ai-defense/mcp-scanner#251). This mirrors that subcommand's analyzer
setup and result shape.

Output: same JSON as `mcp-scanner virustotal PATH --format raw`, wrapped as
{"scan_results": [...]} — the shape run-vt-scan.sh parses.

Usage: vt-scan.py PATH   (VIRUSTOTAL_API_KEY must be set)
"""
import json
import os
import sys

from mcpscanner.config.constants import MCPScannerConstants as CONSTANTS
from mcpscanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer


def _result(path, is_safe, finding=None):
    if finding is None:
        analyzer_finding = {'severity': 'SAFE', 'threat_summary': 'No threats detected',
                            'threat_names': [], 'total_findings': 0, 'mcp_taxonomies': []}
    else:
        analyzer_finding = {'severity': finding.severity, 'threat_summary': finding.summary,
                            'threat_names': [finding.threat_category], 'total_findings': 1,
                            'mcp_taxonomies': []}
    return {'tool_name': path, 'tool_description': f'VirusTotal scan of {os.path.basename(path)}',
            'status': 'completed', 'is_safe': is_safe,
            'findings': {'virustotal_analyzer': analyzer_finding}}


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    scan_path = sys.argv[1]
    api_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        print('Error: VIRUSTOTAL_API_KEY environment variable is not set.', file=sys.stderr)
        return 1
    analyzer = VirusTotalAnalyzer(
        api_key=api_key,
        enabled=os.environ.get('MCP_SCANNER_VIRUSTOTAL_ENABLED', 'true').lower() != 'false',
        upload_files=os.environ.get('MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES', 'false').lower() == 'true',
        max_files=CONSTANTS.VIRUSTOTAL_MAX_FILES,
        inclusion_extensions=CONSTANTS.VIRUSTOTAL_INCLUSION_EXTENSIONS,
        exclusion_extensions=CONSTANTS.VIRUSTOTAL_EXCLUSION_EXTENSIONS,
    )
    if os.path.isfile(scan_path):
        finding = analyzer.analyze_file(scan_path)
        findings = [finding] if finding else []
    elif os.path.isdir(scan_path):
        findings = analyzer.analyze_directory(scan_path)
    else:
        print(f'Error: Path does not exist: {scan_path}', file=sys.stderr)
        return 1

    results = []
    for f in findings or []:
        path = (f.details or {}).get('file_path', scan_path)
        results.append(_result(path, False, f))
    if not results:
        results.append(_result(scan_path, True))
    summary = getattr(analyzer, 'last_scan_summary', None)
    if summary:
        print('VT scan summary: %d scanned, %d clean, %d malicious, %d not found' % (
            summary.get('scanned', 0), summary.get('clean', 0),
            summary.get('malicious', 0), summary.get('not_found', 0)), file=sys.stderr)
    print(json.dumps({'scan_results': results}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
