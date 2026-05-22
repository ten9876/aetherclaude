# AetherClaude eBPF Observability — Cisco Demo Plan

## Objective

Deploy Cilium Tetragon (Isovalent/Cisco) on a Raspberry Pi 5 to provide
kernel-level observability of the AetherClaude AI agent. The demo shows
Cisco's own technology stack (Tetragon + DefenseClaw CodeGuard) protecting
an autonomous AI coding agent on live open-source infrastructure.

**Demo narrative:** "Here's an AI agent writing code on a public open-source
project. Here's Tetragon showing you every syscall, file access, and network
connection it makes in real-time."

---

## Prerequisites

### Hardware
- **Test Pi 5:** Separate from production AetherClaude (192.168.50.111)
- **Arch Linux ARM** on NVMe (same install process as production Pi)
- **Network:** Same subnet (192.168.50.x), SSH access

### Kernel Rebuild (Required)
The RPi Foundation kernel (`linux-rpi`) ships with `CONFIG_DEBUG_INFO_NONE=y`
— no BTF, no DWARF. Tetragon requires BTF.

Must rebuild with:
```
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_DEBUG_INFO_DWARF5=y    (prerequisite for BTF)
CONFIG_BPF_LSM=y              (optional, for LSM hooks)
```

### Software
- Tetragon v1.6.1 (`tetragon-v1.6.1-arm64.tar.gz`, 71 MB)
- Grafana + Loki (optional, for dashboard — or use tetra CLI for demo)
- DefenseClaw gateway (already built for aarch64)

---

## Phase 1: Install Arch on Test Pi

Same process as production Pi:
1. Partition NVMe (512MB FAT32 boot + ext4 root)
2. Extract `ArchLinuxARM-aarch64-latest.tar.gz`
3. Install `linux-rpi` + `raspberrypi-bootloader`
4. Configure networking (systemd-networkd, DHCP)
5. Enable SSH, create `jeremy` user with sudo
6. Set EEPROM boot order to NVMe first

**IP assignment:** Configure DHCP lease or static IP on router.

---

## Phase 2: Rebuild linux-rpi with BTF

```bash
# Install build dependencies
sudo pacman -S --needed base-devel bc cpio pahole xmlto python \
  linux-rpi-headers git

# Get the RPi Foundation kernel source
# Option A: from the ALARM PKGBUILD
asp checkout linux-rpi
cd linux-rpi/trunk

# Option B: clone directly
git clone --depth=1 --branch rpi-6.18.y \
  https://github.com/raspberrypi/linux.git
cd linux

# Start from the current running config
zcat /proc/config.gz > .config

# Enable BTF
scripts/config --enable CONFIG_DEBUG_INFO
scripts/config --enable CONFIG_DEBUG_INFO_DWARF5
scripts/config --enable CONFIG_DEBUG_INFO_BTF
scripts/config --enable CONFIG_DEBUG_INFO_BTF_MODULES
scripts/config --enable CONFIG_BPF_LSM

# Verify
grep CONFIG_DEBUG_INFO_BTF .config
# Should show: CONFIG_DEBUG_INFO_BTF=y

# Build (Pi 5 has 4 cores)
make -j4

# Install
sudo make modules_install
sudo cp arch/arm64/boot/Image /boot/kernel8-btf.img

# Add boot entry for the new kernel
# Edit /boot/config.txt:
#   kernel=kernel8-btf.img

# Reboot and verify
sudo reboot
# After boot:
ls /sys/kernel/btf/vmlinux    # Should exist
uname -r                       # Should show new kernel
```

**Time estimate:** 1-2 hours compile on Pi 5.

**Safety:** Keep the original kernel as `kernel8.img`. If the new kernel
doesn't boot, edit `config.txt` from the SD card to revert.

---

## Phase 3: Install Tetragon

```bash
# Download ARM64 release
wget https://github.com/cilium/tetragon/releases/download/v1.6.1/tetragon-v1.6.1-arm64.tar.gz
tar xzf tetragon-v1.6.1-arm64.tar.gz
cd tetragon-v1.6.1-arm64

# Install (places binaries + systemd unit + BPF programs)
sudo ./install.sh

# Verify
sudo systemctl status tetragon
sudo tetra probe config    # checks kernel compatibility
sudo tetra probe           # probes BPF features

# Test: watch all events
sudo tetra getevents -o compact
```

---

## Phase 4: AetherClaude TracingPolicies

### Policy 1: File Access Monitoring

Track all file opens by the aetherclaude user (UID 965).

File: `/etc/tetragon/tetragon.tp.d/file-access.yaml`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "aetherclaude-file-access"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    returnArg:
      index: 0
      type: "int"
    returnArgAction: "Post"
```

Filter for UID 965:
```bash
sudo tetra getevents -o json | \
  jq 'select(.process_kprobe.process.uid == 965)'
```

### Policy 2: Network Connection Monitoring

Track all TCP connections by aetherclaude.

File: `/etc/tetragon/tetragon.tp.d/network.yaml`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "aetherclaude-network"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
  - call: "tcp_close"
    syscall: false
    args:
    - index: 0
      type: "sock"
```

### Policy 3: Process Execution (built-in)

Process exec/exit events are always emitted by Tetragon. No policy needed.

```bash
sudo tetra getevents -o json | \
  jq 'select(.process_exec.process.uid == 965) |
      {event: "exec", binary: .process_exec.process.binary,
       args: .process_exec.process.arguments, pid: .process_exec.process.pid}'
```

### Policy 4: Canary Tripwires

Alert and optionally kill on access to planted fake credential files.

File: `/etc/tetragon/tetragon.tp.d/canary.yaml`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "aetherclaude-canary"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    returnArg:
      index: 0
      type: "int"
    returnArgAction: "Post"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/home/aetherclaude/.canary/aws-credentials"
        - "/home/aetherclaude/.canary/id_rsa"
        - "/home/aetherclaude/.canary/secrets.env"
      matchActions:
      - action: Sigkill
```

Plant the canary files:
```bash
sudo -u aetherclaude mkdir -p /home/aetherclaude/.canary
echo "AKIAIOSFODNN7EXAMPLE" | sudo -u aetherclaude tee /home/aetherclaude/.canary/aws-credentials
echo "-----BEGIN RSA PRIVATE KEY-----" | sudo -u aetherclaude tee /home/aetherclaude/.canary/id_rsa
echo "GITHUB_TOKEN=ghp_FAKE" | sudo -u aetherclaude tee /home/aetherclaude/.canary/secrets.env
```

If the AI agent is tricked into reading these files, Tetragon kills the
process immediately.

### Policy 5: Unexpected Syscalls

Alert on privilege escalation attempts.

File: `/etc/tetragon/tetragon.tp.d/priv-escalation.yaml`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "aetherclaude-priv-escalation"
spec:
  kprobes:
  - call: "sys_ptrace"
    syscall: true
  - call: "sys_mount"
    syscall: true
  - call: "sys_setuid"
    syscall: true
  - call: "sys_setgid"
    syscall: true
  - call: "sys_unshare"
    syscall: true
  - call: "sys_pivot_root"
    syscall: true
```

---

## Phase 5: Dashboard Options

### Option A: tetra CLI (zero setup — good for live demo)

```bash
# Real-time compact view of aetherclaude activity
sudo tetra getevents -o compact | grep "aetherclaude\|uid=965"

# Formatted JSON view
sudo tetra getevents -o json | \
  jq 'select(.process_exec.process.uid == 965 or
             .process_kprobe.process.uid == 965) |
      {time: .time, event: (if .process_exec then "EXEC"
       elif .process_kprobe then .process_kprobe.function_name
       elif .process_exit then "EXIT" else "OTHER" end),
       binary: (.process_exec // .process_kprobe // .process_exit).process.binary,
       pid: (.process_exec // .process_kprobe // .process_exit).process.pid}'
```

### Option B: Grafana + Loki (polished dashboard)

```bash
# Install on the test Pi or a separate machine
sudo pacman -S grafana loki promtail

# Promtail config — ship Tetragon JSON logs to Loki
# /etc/promtail/config.yml:
server:
  http_listen_port: 9080

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  - job_name: tetragon
    static_configs:
    - targets: [localhost]
      labels:
        job: tetragon
        __path__: /var/run/cilium/tetragon/tetragon.log

# Grafana: import Tetragon community dashboard or build custom panels
# showing:
#   - Process tree (parent → child → grandchild)
#   - File access timeline
#   - Network connections map
#   - Canary tripwire alerts
#   - Syscall histogram
```

### Option C: Custom Python dashboard (lightweight, demo-friendly)

A simple Flask app that reads the Tetragon JSON log and renders a live
dashboard with:
- Process tree visualization
- File access heatmap (which dirs are being read/written)
- Network connection graph
- Alert feed (canary access, unexpected syscalls)

~200 lines of Python. Could run on the Pi itself or on Jeremy's desktop.

---

## Phase 6: Demo Script

### Setup (before the demo)

1. Start Tetragon with all 5 policies loaded
2. Start Grafana/dashboard (if using)
3. Have AetherClaude timer running
4. Label a test issue as `aetherclaude-eligible`

### Demo Flow (5-10 minutes)

**Slide 1: "The Problem"**
- AI agents are writing code on public repos
- They read untrusted input (GitHub issues) and have system access
- How do you know what they're doing?

**Slide 2: "The Architecture"**
- Show the 7-ring defense-in-depth diagram
- Highlight: nftables, MCP token isolation, CodeGuard, human review
- "But we can't see inside the agent's execution"

**Live Demo 1: "What does AetherClaude look like to Tetragon?"**
- Show the Tetragon event stream filtering UID 965
- AetherClaude picks up the labeled issue
- Watch: process_exec (claude binary starts), file reads (source code),
  network connections (GitHub API, Anthropic API), process_exit
- "Every syscall, every file open, every TCP connection — visible"

**Live Demo 2: "What happens when something goes wrong?"**
- Trigger the canary: manually run `sudo -u aetherclaude cat .canary/aws-credentials`
- Tetragon fires alert, process is killed
- "The agent never saw the file contents — Tetragon killed it in-kernel"

**Live Demo 3: "CodeGuard catches malicious code"**
- Show a pre-staged file with `eval()` or hardcoded credentials
- Run `defenseclaw-gateway scan code` on it
- "Cisco's static analyzer catches it before it reaches the PR"

**Slide 3: "The Stack"**
- Tetragon (Isovalent/Cisco) — kernel-level observability
- DefenseClaw CodeGuard (Cisco AI Defense) — static analysis
- Claude Code (Anthropic) — the AI agent
- MCP token isolation — our novel contribution
- All running on a $80 Raspberry Pi 5

**Slide 4: "What we need from DefenseClaw"**
- claudecode mode for real-time tool call interception
- PR #34 merged for guardrail proxy support
- "The pieces are all here — they just need to be connected"

---

## Hardware Bill of Materials

| Item | Cost | Purpose |
|------|------|---------|
| Raspberry Pi 5 (8GB) | ~$80 | Agent host |
| NVMe SSD (500GB) | ~$40 | Boot + workspace |
| NVMe HAT/base | ~$15 | Pi ↔ NVMe adapter |
| Power supply (27W USB-C) | ~$12 | Pi power |
| **Total** | **~$147** | Complete AI agent + eBPF observability platform |

"Enterprise AI agent governance on $147 of hardware."

---

## Timeline

| Phase | Effort | Dependencies |
|-------|--------|-------------|
| 1. Arch Linux on test Pi | 1 hour | Second Pi online |
| 2. Kernel rebuild with BTF | 2-3 hours | Phase 1 |
| 3. Install Tetragon | 30 min | Phase 2 (BTF kernel booted) |
| 4. TracingPolicies | 1 hour | Phase 3 |
| 5. Dashboard | 2-4 hours | Phase 4 (Grafana) or 30 min (CLI only) |
| 6. Demo rehearsal | 1 hour | Phase 5 |
| **Total** | **7-10 hours** | |

---

*Document version: 1.0 — 2026-04-05*
*Author: Jeremy Fielder (KK7GWY) & Claude (AI dev partner)*
