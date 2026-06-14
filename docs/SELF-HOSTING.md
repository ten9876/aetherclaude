# Self-hosting AetherClaude

AetherClaude is built for the [AetherSDR](https://github.com/aethersdr/AetherSDR)
project, but it's AGPL-3.0 and fully self-hostable. This guide covers standing
up an **independent instance against your own repository**. The README's
[Deploying](../README.md#deploying) section covers *updating* an
already-bootstrapped host; this covers the one-time bootstrap that comes first.

> [!IMPORTANT]
> **AetherClaude is single-instance-per-repo.** State lives in a local SQLite
> action log and it posts as one GitHub App, and GitHub delivers webhooks to a
> single URL. Don't point two instances at the same repository — they don't
> coordinate and will both triage every new issue. Run one instance per repo.

> [!NOTE]
> **Platform: macOS.** The runtime is macOS `launchd` services, the `pf` packet
> filter, and Tetragon eBPF. It is not portable to Linux as-is.

## 1. Create a GitHub App

Create a GitHub App (Settings → Developer settings → GitHub Apps) under your
account/org and **install it on the repo you want triaged**.

**Repository permissions:**

| Permission    | Access         |
|---------------|----------------|
| Issues        | Read and write |
| Pull requests | Read and write |
| Contents      | Read and write |
| Discussions   | Read and write |
| Actions       | Read           |
| Metadata      | Read (mandatory) |

**Subscribe to webhook events:** `issues`, `issue_comment`, `pull_request`,
`pull_request_review`, `pull_request_review_comment`, `discussion`,
`discussion_comment`, `workflow_run`.

Set the **Webhook URL** to your dashboard's `/webhook` endpoint (see step 4) and
a **Webhook secret** (`openssl rand -hex 32` — you'll reuse it as
`WEBHOOK_SECRET`). From the App you'll need its **numeric App ID** and a
generated **private key** (`.pem`).

## 2. Choose Claude authentication — read before June 15, 2026

The agent runs `claude -p`, so how you authenticate the Claude Code CLI
determines your cost model:

- **API key — recommended for automation.** Pay-as-you-go, no monthly cap, and
  excluded from the Agent SDK credit change below. Anthropic explicitly
  recommends an API key for "shared production automation." Set a monthly spend
  limit in the Claude Platform console.
- **Max / Pro subscription.** Starting **June 15, 2026**, subscription-
  authenticated Agent SDK / `claude -p` usage draws from a fixed **monthly
  Agent SDK credit** ($20 Pro / $100 Max 5× / $200 Max 20×). Once exhausted it
  either bills at standard API rates (if usage credits are enabled) or **stops
  until the credit refreshes**. At continuous-triage volume that credit lasts a
  fraction of a month, so it's a poor fit for an always-on instance. If you use
  a subscription you must also **one-time claim the credit** in your account.

Reference:
<https://support.claude.com/en/articles/15036540-use-the-claude-agent-sdk-with-your-claude-plan>

## 3. Bootstrap the host

`scripts/deploy.sh` syncs the repo into an **existing** layout — it does not
create the host from scratch. Set up the following first:

- A dedicated unprivileged **`aetherclaude` user** with `~/bin`, `~/skills`,
  `~/.claude`, `~/.cloudflared`, and `~/data` directories.
- **Homebrew**, plus `tinyproxy`, `cloudflared`, and a recent `python3` (the
  services run under `/opt/homebrew/bin/python3` with the `cryptography`
  module installed).
- The **Claude Code CLI** installed and authenticated for the `aetherclaude`
  user (per step 2).
- Your App private key at `~aetherclaude/.github-app-key.pem` (`chmod 600`).
- `~aetherclaude/.env`, copied from [`.env.example`](../.env.example):

  ```
  GITHUB_APP_ID=<your app id>
  WEBHOOK_SECRET=<the secret from step 1>
  ```

- An MCP config at `~aetherclaude/.claude/mcp-servers.json` (an empty
  `{"mcpServers":{}}` is fine if you aren't running the Cisco MCP gateway).
- **Point it at your repo:** `bin/run-agent.sh` hardwires the target as
  `REPO="aethersdr/AetherSDR"`. Change it to your `owner/repo`.

## 4. Expose the dashboard to GitHub

GitHub must be able to reach your dashboard's `/webhook` (the dashboard listens
on `127.0.0.1:8080`). AetherClaude uses a **Cloudflare tunnel**
([`config/cloudflared/config.yml`](../config/cloudflared/config.yml), origin
`127.0.0.1`). Create your own named tunnel, route a hostname to it, and use that
hostname as the App's Webhook URL. Any equivalent public ingress works.

## 5. Deploy

```bash
git clone https://github.com/ten9876/aetherclaude.git ~/src/aetherclaude
cd ~/src/aetherclaude
./scripts/deploy.sh
```

This symlinks `bin/` and `skills/`, installs the `launchd` plists, syncs the
`pf` anchor + tinyproxy + cloudflared configs, and starts the services. Then:

1. `curl -s 127.0.0.1:8080/api/events` should return JSON.
2. Open a test issue on your repo; confirm a delivery hits `/webhook` (App →
   Advanced → Recent Deliveries) and the agent posts a triage comment.

## 6. Security rings (optional, but they're the point)

The defense-in-depth layers run independently; omit the Cisco pieces and the
agent still functions, losing those checks:

- **pf + tinyproxy** egress allowlists — config ships in `config/`. macOS does
  not enable `pf` at boot, so the `pf-enable` daemon does it on startup.
- **Tetragon** eBPF observability — optional.
- **Cisco DefenseClaw / MCP Scanner / Skill Scanner** (`dc-gateway`) — require
  Cisco access; without them you lose pre-PR static analysis and MCP/skill
  scanning of the agent's output.

## License

AGPL-3.0. Its network-copyleft clause applies here: if you run a **modified**
AetherClaude as a service others interact with, you must make your
modifications available to those users.
