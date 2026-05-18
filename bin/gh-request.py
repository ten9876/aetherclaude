#!/usr/bin/env python3
"""GitHub API helper — credentials via stdin, never in process args.
Usage: echo TOKEN | gh-request.py METHOD ENDPOINT [BODY_FILE]"""
import sys, io, json, urllib.request, os, datetime

# Force UTF-8 on stdout/stderr to handle unicode in API responses
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

method = sys.argv[1]
endpoint = sys.argv[2]
body_file = sys.argv[3] if len(sys.argv) > 3 else None

token = sys.stdin.readline().strip()

proxy = os.environ.get("HTTPS_PROXY", "")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy}) if proxy else urllib.request.BaseHandler())
headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json", "User-Agent": "AetherClaude"}
data = None
if body_file and os.path.exists(body_file):
    data = open(body_file, "rb").read()
    headers["Content-Type"] = "application/json"

try:
    req = urllib.request.Request(f"https://api.github.com{endpoint}", data=data, headers=headers, method=method)
    resp = opener.open(req, timeout=30)
    result = resp.read().decode("utf-8", errors="replace")
    print(result)
    try:
        audit = json.dumps({"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "operation": f"{method} {endpoint}", "args": [], "result": result[:200]})
        with open("/Users/aetherclaude/logs/mcp-audit.log", "a") as f:
            f.write(audit + "\n")
    except: pass
except urllib.error.HTTPError as e:
    # Print GitHub's own error JSON to stdout AND exit 0. Callers in
    # run-agent.sh use bare `var=$(github_api ... | jq ...)` assignments
    # under `set -euo pipefail`; a non-zero exit from this script
    # propagates through the pipeline and kills the entire orchestrator
    # silently. Many sites then do `echo "$var" | jq -e '.error'` to
    # detect failures — that pattern only works if we hand them well-
    # formed JSON via stdout (which GitHub already does for 4xx/5xx).
    # Transient blips (429 rate-limit, 5xx, network) should NOT take
    # down a 20-minute orch run that's made 200 successful calls and
    # has one bad luck on call 201.
    try:
        body = e.read().decode("utf-8", errors="replace")
        # If body is already valid JSON (the common GitHub case), pass
        # through. Otherwise wrap in our own error envelope.
        try:
            json.loads(body)
            sys.stdout.write(body)
        except (ValueError, json.JSONDecodeError):
            sys.stdout.write(json.dumps({"error": body[:500], "http_status": e.code}))
    except Exception:
        sys.stdout.write(json.dumps({"error": f"HTTPError {e.code} with unreadable body"}))
    sys.exit(0)
except Exception as e:
    # Network / timeout / DNS / proxy / etc. Emit error JSON on
    # stdout (so jq can parse), log diagnostic to stderr (visible
    # in launchd logs for forensics), exit 0.
    print(str(e), file=sys.stderr)
    sys.stdout.write(json.dumps({"error": str(e)[:500], "kind": type(e).__name__}))
    sys.exit(0)
