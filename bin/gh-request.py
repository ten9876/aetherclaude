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
    print(e.read().decode("utf-8", errors="replace"), file=sys.stderr); sys.exit(1)
except Exception as e:
    print(str(e), file=sys.stderr); sys.exit(1)
