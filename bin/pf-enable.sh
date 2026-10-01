#!/bin/bash
# AetherClaude — enable the pf firewall and create the pflog interface at boot.
#
# macOS loads /etc/pf.conf at boot (via com.apple.pfctl) but leaves pf DISABLED,
# and does not create the pflog0 interface used for blocked-traffic logging.
# Without this, after every reboot:
#   * the com.aetherclaude outbound-isolation anchor is loaded but NOT enforced
#     (pf Status: Disabled), so the agent UID has unrestricted network egress; and
#   * com.aetherclaude.pflog fails with "pflog0: No such device exists".
#
# Invoked by com.aetherclaude.pf-enable (RunAtLoad). Runs as root — pfctl and
# ifconfig require it. Idempotent: safe to run on every boot or re-run by hand.
#
# Uses only base-system paths (/sbin) so it carries no machine-specific config.
set -euo pipefail

# Enable pf and (re)load the full ruleset, including the com.aetherclaude anchor
# that /etc/pf.conf references. -E increments pf's enable reference count; running
# it again when pf is already enabled is harmless.
/sbin/pfctl -E -f /etc/pf.conf

# (Re)create the pf logging interface so com.aetherclaude.pflog's tcpdump can
# attach. pflog0 is a cloned interface that does not survive a pf disable / boot.
if ! /sbin/ifconfig pflog0 >/dev/null 2>&1; then
    /sbin/ifconfig pflog0 create
fi
/sbin/ifconfig pflog0 up
