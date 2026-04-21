#!/opt/homebrew/bin/bash
# Refresh Claude Code OAuth token for AetherClaude
# Run via cron every 6 hours to prevent token expiry
# Cron: 0 */6 * * * /Users/aetherclaude/bin/refresh-claude-token.sh

set -euo pipefail

CREDS_FILE="/Users/aetherclaude/.claude/.credentials.json"
LOGFILE="/Users/aetherclaude/logs/token-refresh.log"
PROXY=""
CLIENT_ID="9d1c250a-e61b-44d9-88ed-5944d1962f5e"
TOKEN_URL="https://claude.com/cai/oauth/token"

log() { echo "$(date "+%Y-%m-%dT%H:%M:%S") TOKEN: $1" >> "$LOGFILE"; }

# Check if token exists
if [ ! -f "$CREDS_FILE" ]; then
    log "ERROR: No credentials file found"
    exit 1
fi

# Check if token is about to expire (within 2 hours)
EXPIRES_AT=$(python3 -c "
import json
with open('$CREDS_FILE') as f:
    d = json.load(f)
print(d.get('claudeAiOauth', {}).get('expiresAt', 0))
")

NOW_MS=$(python3 -c "import time; print(int(time.time() * 1000))")
TWO_HOURS_MS=7200000
REMAINING=$((EXPIRES_AT - NOW_MS))

if [ "$REMAINING" -gt "$TWO_HOURS_MS" ]; then
    log "Token still valid for $((REMAINING / 3600000))h $((REMAINING % 3600000 / 60000))m — no refresh needed"
    exit 0
fi

log "Token expires in $((REMAINING / 60000))m — refreshing"

# Extract refresh token
REFRESH_TOKEN=$(python3 -c "
import json
with open('$CREDS_FILE') as f:
    d = json.load(f)
print(d.get('claudeAiOauth', {}).get('refreshToken', ''))
")

if [ -z "$REFRESH_TOKEN" ]; then
    log "ERROR: No refresh token found"
    exit 1
fi

# Exchange refresh token for new access token
RESPONSE=$(curl -s -X POST \
    --proxy "$PROXY" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}&client_id=${CLIENT_ID}" \
    "$TOKEN_URL" 2>/dev/null)

# Parse response
NEW_ACCESS=$(echo "$RESPONSE" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('access_token', ''))
except:
    print('')
" 2>/dev/null)

if [ -z "$NEW_ACCESS" ]; then
    log "ERROR: Token refresh failed — response: $(echo "$RESPONSE" | head -c 200)"
    exit 1
fi

# Extract new refresh token and expiry
python3 -c "
import json, time

with open('$CREDS_FILE') as f:
    creds = json.load(f)

response = json.loads('''$RESPONSE''')

oauth = creds.get('claudeAiOauth', {})
oauth['accessToken'] = response['access_token']
if 'refresh_token' in response:
    oauth['refreshToken'] = response['refresh_token']
if 'expires_in' in response:
    oauth['expiresAt'] = int(time.time() * 1000) + (response['expires_in'] * 1000)

creds['claudeAiOauth'] = oauth

with open('$CREDS_FILE', 'w') as f:
    json.dump(creds, f)

print(f'Token refreshed. New expiry: {oauth.get(\"expiresAt\", 0)}')
"

log "Token refreshed successfully"
