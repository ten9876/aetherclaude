#!/usr/bin/env python3

# ── .env loader — required so launchd children see WEBHOOK_SECRET etc. ──
import os as _os
_env_path = _os.path.expanduser('~/.env')
if _os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if not _line or _line.startswith('#') or '=' not in _line:
                continue
            _k, _v = _line.split('=', 1)
            _os.environ.setdefault(_k.strip(), _v.strip())
# ──────────────────────────────────────────────────────────────────────────
"""
eslogger → AetherClaude Dashboard bridge.
Tails macOS Endpoint Security events for the aetherclaude user (UID 965)
and feeds them into the dashboard's append_event() format.

Usage: sudo python3 eslogger-bridge.py
"""
import json, re, subprocess, sys, time, threading, os

AETHERCLAUDE_UID = 965

# --- Secret redaction ---
_SECRET_PATTERNS = [
    re.compile(r'ghs_[A-Za-z0-9]{30,}'),
    re.compile(r'ghp_[A-Za-z0-9]{30,}'),
    re.compile(r'github_pat_[A-Za-z0-9_]{80,}'),
    re.compile(r'sk-ant-[A-Za-z0-9_-]{20,}'),
    re.compile(r'ANTHROPIC_API_KEY=[^\s]+'),
    re.compile(r'GIT_ASKPASS_TOKEN=[^\s]+'),
    re.compile(r'WEBHOOK_SECRET=[^\s]+'),
    re.compile(r'GITHUB_TOKEN=[^\s]+'),
    re.compile(r'-----BEGIN[A-Z ]*PRIVATE KEY-----'),
    re.compile(r'Bearer\s+[A-Za-z0-9_.-]{20,}'),
]

def redact(text):
    """Scrub secrets from any string before it leaves this process."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub('***', text)
    return text
EVENT_TYPES = ['exec', 'fork', 'exit', 'rename', 'unlink', 'signal']  # skip open/write — too noisy

# Dashboard ingest (local — same machine)
DASHBOARD_URL = 'http://localhost:8080/api/ingest'
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')

def send_to_dashboard(events):
    """POST events to dashboard's /api/ingest endpoint."""
    import urllib.request
    try:
        payload = json.dumps({'events': events, 'hmac': WEBHOOK_SECRET}).encode()
        req = urllib.request.Request(DASHBOARD_URL, data=payload, method='POST',
            headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # Dashboard may be down, don't crash

def parse_event(line):
    """Parse an eslogger JSON line and extract relevant fields for the dashboard."""
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Extract process info
    proc = ev.get('process', {})
    audit = proc.get('audit_token', {})
    uid = audit.get('euid', -1)

    # Only track aetherclaude user
    if uid != AETHERCLAUDE_UID:
        return None

    event_type = ev.get('event_type', -1)
    timestamp = ev.get('time', time.strftime('%Y-%m-%dT%H:%M:%S'))

    # Get executable path
    exe = proc.get('executable', {}).get('path', '')

    # Get event-specific details
    event_data = ev.get('event', {})
    args = ''
    es_type = ''

    if 'exec' in event_data:
        es_type = 'EXEC'
        exec_info = event_data['exec']
        # Never capture env — it contains secrets (GIT_ASKPASS_TOKEN, etc.)
        args = ' '.join(exec_info.get('args', []))[:500]
    elif 'open' in event_data:
        es_type = 'OPEN'
        args = event_data['open'].get('file', {}).get('path', '')
    elif 'write' in event_data:
        es_type = 'WRITE'
        # write events don't always have a path in the event, use target if available
        target = event_data.get('write', {}).get('target', {})
        args = target.get('executable', {}).get('path', '') if isinstance(target, dict) else ''
    elif 'rename' in event_data:
        es_type = 'RENAME'
        rename = event_data['rename']
        src = rename.get('source', {}).get('path', '')
        dst = rename.get('destination', {}).get('path', '') if 'destination' in rename else rename.get('new_path', {}).get('path', '')
        args = f'{src} → {dst}'
    elif 'unlink' in event_data:
        es_type = 'UNLINK'
        args = event_data['unlink'].get('target', {}).get('path', '')
    elif 'signal' in event_data:
        es_type = 'SIGNAL'
        sig = event_data['signal']
        args = f"sig={sig.get('sig', '?')} target_pid={sig.get('target', {}).get('audit_token', {}).get('pid', '?')}"
    elif 'fork' in event_data:
        es_type = 'FORK'
        child = event_data['fork'].get('child', {})
        args = f"child_pid={child.get('audit_token', {}).get('pid', '?')}"
    elif 'exit' in event_data:
        es_type = 'EXIT'
        args = f"status={event_data['exit'].get('stat', '?')}"
    else:
        return None

    if not es_type:
        return None

    return {
        'time': timestamp[:19],  # Trim to seconds
        'type': es_type,
        'uid': uid,
        'binary': redact(exe),
        'args': redact(args[:500]),
        'policy': '',
        'is_agent': True,
        'source': 'eslogger'
    }


def main():
    print(f"Starting eslogger bridge for UID {AETHERCLAUDE_UID}")
    print(f"Event types: {', '.join(EVENT_TYPES)}")
    print(f"Dashboard: {DASHBOARD_URL}")

    cmd = ['/usr/bin/eslogger'] + EVENT_TYPES + ['--format', 'json']
    print(f"Running: {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Check for immediate failure
    import select
    if select.select([proc.stderr], [], [], 2.0)[0]:
        err = proc.stderr.readline()
        if err:
            print(f"eslogger error: {err.strip()}", flush=True)

    batch = []
    last_flush = time.time()
    BATCH_SIZE = 10
    FLUSH_INTERVAL = 2.0  # seconds

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            event = parse_event(line)
            if event:
                batch.append(event)
                print(f"  [{event['type']}] {event['binary']} {event['args'][:80]}")

            # Flush batch to dashboard
            now = time.time()
            if len(batch) >= BATCH_SIZE or (batch and now - last_flush >= FLUSH_INTERVAL):
                send_to_dashboard(batch)
                batch = []
                last_flush = now

    except KeyboardInterrupt:
        print("\nShutdown", flush=True)
    finally:
        rc = proc.poll()
        if rc is not None:
            stderr_out = proc.stderr.read()
            print(f"eslogger exited with code {rc}: {stderr_out}", flush=True)
        else:
            proc.terminate()
        if batch:
            send_to_dashboard(batch)


if __name__ == '__main__':
    sys.stdout.reconfigure(line_buffering=True)
    main()
