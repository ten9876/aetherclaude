#!/opt/homebrew/bin/bash
# Generate a GitHub App installation token
# SECURITY: Uses Python urllib instead of curl to avoid token in process args
set -euo pipefail

# Signing the App JWT needs the `cryptography` module, so use the first
# interpreter that has it: the project venv, then Homebrew's python@3.14,
# then whatever /opt/homebrew/bin/python3 is. Never PATH's python3: the
# system /usr/bin/python3 (3.9.x) lacks the module, and PATH puts /usr/bin
# first for interactive shells (sudo -u aetherclaude). A Homebrew upgrade
# that repoints python3 to a new minor version without the module must
# not take every GitHub call down with it.
PY=
for c in /Users/Shared/aetherclaude/.venv/bin/python3 \
         /opt/homebrew/opt/python@3.14/bin/python3.14 \
         /opt/homebrew/bin/python3; do
    if [ -x "$c" ] && "$c" -c 'import cryptography' 2>/dev/null; then PY=$c; break; fi
done
if [ -z "$PY" ]; then
    echo "github-app-token: no python3 with the cryptography module" >&2
    exit 1
fi
exec "$PY" -c "
import json, time, sys, os, urllib.request, urllib.error


# Read config
env = {}
for line in open(\"/Users/aetherclaude/.env\"):
    if \"=\" in line and not line.startswith(\"#\"):
        k, v = line.strip().split(\"=\", 1)
        env[k] = v

app_id = env.get(\"GITHUB_APP_ID\", \"\")
pk = open(\"/Users/aetherclaude/.github-app-key.pem\").read()

# Generate JWT
import hashlib, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

now = int(time.time())
header = base64.urlsafe_b64encode(json.dumps({\"alg\":\"RS256\",\"typ\":\"JWT\"}).encode()).rstrip(b\"=\").decode()
payload = base64.urlsafe_b64encode(json.dumps({\"iat\":now-60,\"exp\":now+600,\"iss\":app_id}).encode()).rstrip(b\"=\").decode()

key = serialization.load_pem_private_key(pk.encode(), password=None)
sig_input = f\"{header}.{payload}\".encode()
signature = key.sign(sig_input, padding.PKCS1v15(), hashes.SHA256())
sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b\"=\").decode()
jwt = f\"{header}.{payload}.{sig_b64}\"



proxy = os.environ.get(\"HTTPS_PROXY\", \"\"); opener = urllib.request.build_opener(urllib.request.ProxyHandler({\"https\": proxy}) if proxy else urllib.request.BaseHandler())

# Get installation ID
req = urllib.request.Request(\"https://api.github.com/app/installations\",
    headers={\"Authorization\": f\"Bearer {jwt}\", \"Accept\": \"application/vnd.github+json\", \"User-Agent\": \"AetherClaude\"})
installs = json.loads(opener.open(req).read())
# Pick the aethersdr installation (upstream repo) — not AetherClaude (fork)
install_id = None
for inst in installs:
    if inst['account']['login'] == 'aethersdr':
        install_id = inst['id']
        break
if not install_id:
    install_id = installs[0]['id']

# Get installation token with explicit permissions
_perms = {\"contents\": \"write\", \"issues\": \"write\", \"pull_requests\": \"write\", \"actions\": \"read\", \"metadata\": \"read\"}
_body = json.dumps({\"permissions\": _perms}).encode()
req2 = urllib.request.Request(f\"https://api.github.com/app/installations/{install_id}/access_tokens\",
    data=_body,
    method=\"POST\",
    headers={\"Authorization\": f\"Bearer {jwt}\", \"Accept\": \"application/vnd.github+json\", \"User-Agent\": \"AetherClaude\"})
token_data = json.loads(opener.open(req2).read())
print(token_data[\"token\"])
"
