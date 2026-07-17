#!/usr/bin/env python3
"""galileo-log-run.py — post-run eval-trace emitter (agent side).

Called by run-agent.sh's run_claude() after every Claude Code invocation.
It does NOT talk to Galileo directly — the sandboxed agent shares uid 965 with
the firewall and is denied galileo.ai at the tinyproxy layer by design. Instead
it POSTs a compact eval record to the trusted dashboard over localhost (already
allowed by pf), and the dashboard forwards the trace to Galileo (it alone holds
GALILEO_API_KEY and bypasses the proxy). See config/pf/com.aetherclaude and the
/api/eval-ingest handler in tetragon-dashboard.py.

Failures are swallowed: eval logging must never block or fail an agent run.

Usage:
  galileo-log-run.py --flow review --ref 2624 --status ok \
      --jsonl /Users/aetherclaude/.claude/projects/-.../abc.jsonl \
      --log /Users/aetherclaude/logs/pr-review-2624-....log
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import urllib.request

# --- Self-contained ~/.env loader (mirrors eslogger-bridge.py lines 4-14) so we
# see WEBHOOK_SECRET regardless of how we're launched. Never reads GALILEO_*. ---
_ENV_PATH = os.path.expanduser('~/.env')
if os.path.exists(_ENV_PATH):
    with open(_ENV_PATH) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _, _v = _line.partition('=')
                os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

DASHBOARD_URL = 'http://localhost:8080/api/eval-ingest'
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--trace-id', default=os.environ.get('AETHER_TRACE_ID', ''))
    ap.add_argument('--flow', required=True)      # triage|implement|review|ci|duplicate|mention
    ap.add_argument('--ref', default='')          # issue / PR number
    ap.add_argument('--status', default='ok')     # ok | fail
    ap.add_argument('--jsonl', default='')        # Claude session transcript path
    ap.add_argument('--log', default='')          # per-skill text log path
    args = ap.parse_args()

    payload = json.dumps({
        'kind': 'run',
        'trace_id': args.trace_id,
        'flow': args.flow,
        'ref': args.ref,
        'status': args.status,
        'jsonl_path': args.jsonl,
        'log_path': args.log,
    }).encode()

    try:
        headers = {'Content-Type': 'application/json'}
        if WEBHOOK_SECRET:
            headers['X-Ingest-Signature'] = hmac.new(
                WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        req = urllib.request.Request(DASHBOARD_URL, data=payload,
                                     method='POST', headers=headers)
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        # Dashboard may be down; eval logging is best-effort. Never fail a run.
        print(f'galileo-log-run: dashboard unreachable ({e})', file=sys.stderr)
        return 0
    return 0


if __name__ == '__main__':
    sys.exit(main())
