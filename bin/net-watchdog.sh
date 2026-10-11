#!/bin/bash
# Network watchdog for the mini's wired uplink.
#
# Invoked every minute by com.aetherclaude.net-watchdog (as root). The
# network is healthy when the interface has link, a DHCP (non link-local)
# IPv4 address and a default route through it whose router answers ping.
# Once it has been unhealthy for RESET_AFTER seconds, the interface is
# reset (down, up, DHCP renew), and again every RESET_EVERY seconds until
# it is healthy. After a power blip the Ethernet link can stay down until
# the interface is reset; a reset is harmless when the cause is elsewhere.
#
# Runs on macOS's /bin/bash (3.2) with system tools only, so it works
# before Homebrew or the network is up. State and log live in root-owned
# locations.
#
# Test hooks (env): NET_WATCHDOG_DRYRUN=1 logs a reset instead of doing it;
# NET_WATCHDOG_FORCE_DOWN=1 treats the network as down; NET_WATCHDOG_NOW
# overrides the clock (epoch seconds); NET_WATCHDOG_STATE_DIR and
# NET_WATCHDOG_LOG relocate state and log.

set -u

IFACE="${NET_WATCHDOG_IFACE:-en0}"
RESET_AFTER=300     # seconds of outage before the first reset
RESET_EVERY=300     # seconds between resets while still down
STATE_DIR="${NET_WATCHDOG_STATE_DIR:-/var/db/aetherclaude-net-watchdog}"
LOG_FILE="${NET_WATCHDOG_LOG:-/var/log/aetherclaude-net-watchdog.log}"
NOW="${NET_WATCHDOG_NOW:-$(date +%s)}"

PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
mkdir -p "$STATE_DIR"

log() { printf '%s %s\n' "$(date -u -r "$NOW" +'%Y-%m-%dT%H:%M:%SZ')" "$*" >> "$LOG_FILE"; }
get() { cat "$STATE_DIR/$1" 2>/dev/null || echo "${2:-0}"; }
put() { printf '%s' "$2" > "$STATE_DIR/$1"; }

# Prints why the network is unhealthy; prints nothing when it is healthy.
problem() {
    if [ "${NET_WATCHDOG_FORCE_DOWN:-0}" = 1 ]; then echo "forced down (test)"; return; fi
    local info addr gw gwif
    info=$(ifconfig "$IFACE" 2>/dev/null) || { echo "no interface $IFACE"; return; }
    case "$info" in *"status: active"*) ;; *) echo "no link on $IFACE"; return ;; esac
    addr=$(printf '%s\n' "$info" | awk '$1=="inet" && $2 !~ /^169\.254\./ {print $2; exit}')
    [ -n "$addr" ] || { echo "no DHCP address on $IFACE"; return; }
    gw=$(route -n get default 2>/dev/null | awk '$1=="gateway:" {print $2}')
    gwif=$(route -n get default 2>/dev/null | awk '$1=="interface:" {print $2}')
    [ -n "$gw" ] || { echo "no default route"; return; }
    [ "$gwif" = "$IFACE" ] || { echo "default route is on ${gwif:-?}, not $IFACE"; return; }
    ping -c 2 -t 4 -q "$gw" >/dev/null 2>&1 || echo "router $gw not answering"
}

reset_iface() {
    if [ "${NET_WATCHDOG_DRYRUN:-0}" = 1 ]; then log "dry run: would reset $IFACE"; return; fi
    ifconfig "$IFACE" down
    sleep 5
    ifconfig "$IFACE" up
    sleep 2
    ipconfig set "$IFACE" DHCP
}

why=$(problem)
down_since=$(get down_since)
if [ -z "$why" ]; then
    if [ "$down_since" -gt 0 ]; then
        log "network restored after $((NOW - down_since))s and $(get resets) reset(s)"
        put down_since 0; put last_reset 0; put resets 0
    fi
    exit 0
fi

if [ "$down_since" -eq 0 ]; then
    down_since=$NOW
    put down_since "$NOW"
    log "network down: $why"
fi
last_reset=$(get last_reset)
if [ $((NOW - down_since)) -ge "$RESET_AFTER" ] && [ $((NOW - last_reset)) -ge "$RESET_EVERY" ]; then
    resets=$(( $(get resets) + 1 ))
    put resets "$resets"; put last_reset "$NOW"
    log "down $((NOW - down_since))s ($why): resetting $IFACE (reset $resets)"
    reset_iface
fi
exit 0
