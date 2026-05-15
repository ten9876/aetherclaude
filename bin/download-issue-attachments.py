#!/usr/bin/env python3
"""
download-issue-attachments — fetch every GitHub-hosted attachment URL
referenced in an issue/PR body or comment thread to a local directory
so Claude (sandboxed; no WebFetch outbound) can Read them via the
filesystem.

Reads issue/comment text from stdin. For each attachment URL we
recognize (github.com/user-attachments/, user-images.githubuser
content.com, the private variant, repo files/raw URLs), downloads
via curl. Prints `<local_path>\t<url>` pairs to stdout — one per
successful download — so the caller can compose a "Local attachments"
section into the skill prompt.

Auth: uses GH_TOKEN / GITHUB_TOKEN env var (orchestrator exports it
before spawning child processes). Public repos work without it; the
header just gets sent harmlessly.

Usage:
    cat issue_body.txt | download-issue-attachments.py <dest_dir>

Exit codes:
    0  always (failures are reported on stderr, never block the
       orchestrator — better to proceed without the attachment than
       to halt the whole pipeline).
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

# URL shapes GitHub uses for attachments. Order matters for dedup —
# the first match wins per character position.
ATTACHMENT_PATTERNS = [
    # Modern path: drag-and-drop or paste-image attachments under
    # github.com/user-attachments/<files-or-assets>/<UUID>/<name>
    r'https?://github\.com/user-attachments/[^\s\)\]"<>]+',
    # Legacy issue images uploaded by drag-and-drop
    r'https?://user-images\.githubusercontent\.com/[^\s\)\]"<>]+',
    # Same content behind a token-gated URL when posted to a private
    # repo (orchestrator's GH_TOKEN authenticates these)
    r'https?://private-user-images\.githubusercontent\.com/[^\s\)\]"<>]+',
    # Files attached to releases or raw blob URLs from this repo
    r'https?://github\.com/[^\s/]+/[^\s/]+/(?:files|raw)/[^\s\)\]"<>]+',
]

# Cap so a copy-pasted log explosion doesn't try to download
# hundreds of files. Practical issue threads top out around 5-10
# attachments; 25 leaves headroom.
MAX_ATTACHMENTS = 25
# Per-file timeout so a slow CDN or 404 doesn't stall a triage run.
DOWNLOAD_TIMEOUT_S = 60


def safe_extension(url: str) -> str:
    """Pull the extension off a URL path; fall back to .bin. Reject
    suspicious extensions (anything with a path-traversal char or
    shell metachar) to keep the local filesystem safe."""
    path = urllib.parse.urlparse(url).path
    ext = Path(path).suffix
    if re.fullmatch(r'\.[a-zA-Z0-9]{1,8}', ext):
        return ext
    return '.bin'


def main() -> int:
    if len(sys.argv) < 2:
        print('usage: download-issue-attachments.py <dest_dir>',
              file=sys.stderr)
        return 2
    dest = Path(sys.argv[1])
    dest.mkdir(parents=True, exist_ok=True)
    text = sys.stdin.read()

    # Dedup URLs across the body + comments concat.
    seen: set[str] = set()
    urls: list[str] = []
    for pat in ATTACHMENT_PATTERNS:
        for m in re.finditer(pat, text):
            url = m.group(0).rstrip('.,;:)')
            if url not in seen:
                seen.add(url)
                urls.append(url)
            if len(urls) >= MAX_ATTACHMENTS:
                break
        if len(urls) >= MAX_ATTACHMENTS:
            break
    if not urls:
        # No attachments to fetch — exit silently. Caller checks the
        # stdout output for an empty list.
        return 0

    token = (os.environ.get('GH_TOKEN')
             or os.environ.get('GITHUB_TOKEN', '')).strip()

    for url in urls:
        # Hash URL → filename so colliding basenames (image.png from
        # multiple comments) don't overwrite each other. 8 hex chars
        # is collision-safe at this scale.
        h = hashlib.sha1(url.encode()).hexdigest()[:8]
        ext = safe_extension(url)
        local = dest / f'attachment-{h}{ext}'

        # Skip if cached from a prior pass on the same issue.
        if local.exists() and local.stat().st_size > 0:
            print(f'{local}\t{url}')
            print(f'  cached: {local.name} <- {url}', file=sys.stderr)
            continue

        curl_args = ['curl', '-fsSL', '--max-time', str(DOWNLOAD_TIMEOUT_S),
                     '-o', str(local)]
        # Only attach the token to *.github.com / *.githubusercontent.com
        # so we don't accidentally leak it to a redirected third-party
        # CDN (rare but possible).
        host = urllib.parse.urlparse(url).netloc
        if token and (host.endswith('github.com')
                      or host.endswith('githubusercontent.com')):
            curl_args.extend(['-H', f'Authorization: Bearer {token}'])
        curl_args.append(url)

        try:
            subprocess.run(curl_args, check=True,
                           timeout=DOWNLOAD_TIMEOUT_S + 5,
                           capture_output=True)
            size = local.stat().st_size
            print(f'{local}\t{url}')
            print(f'  ok: {local.name} ({size} bytes) <- {url}',
                  file=sys.stderr)
        except subprocess.CalledProcessError as e:
            # curl exit 22 = HTTP 4xx; 28 = timeout; etc.
            print(f'  fail (curl exit {e.returncode}): {url}',
                  file=sys.stderr)
            # Best-effort cleanup: curl may have written a 0-byte
            # file on failure depending on -f / -o ordering.
            try:
                if local.exists() and local.stat().st_size == 0:
                    local.unlink()
            except OSError:
                pass
        except subprocess.TimeoutExpired:
            print(f'  fail (timeout): {url}', file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
