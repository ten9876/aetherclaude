# Antares Detector — model + service setup (Mac Mini)

The **Detector** stage of the Foundry pipeline: Cisco Foundation AI's
**Antares-1B** vulnerability-localization model, served locally by Ollama and
driven by `bin/antares-detector.py`. This is a one-time deploy on the Mini;
everything is Apple-Silicon-Metal native and loopback-only.

## 1. Install Ollama (once)

```bash
brew install ollama            # /opt/homebrew/bin/ollama
```

## 2. Get an Antares-1B GGUF

The base model is `fdtn-ai/antares-1b` (Apache 2.0). Community Q8_0 GGUFs
exist (a 1B at Q8_0 is ~1.1 GB). Either pull directly from Hugging Face via
Ollama, or download a GGUF and import with the Modelfile.

**Quick path — Ollama HF pull, then tag:**
```bash
ollama pull hf.co/mitkox/antares-1b-Q8_0-GGUF
ollama cp   hf.co/mitkox/antares-1b-Q8_0-GGUF antares-1b
```
(Any of the `*/antares-1b-Q8_0-GGUF` repos works; pick one you trust.)

**Template-control path — download the GGUF + Modelfile import:**
```bash
mkdir -p /Users/Shared/aetherclaude/models
# download antares-1b-Q8_0.gguf into that dir (huggingface-cli or a browser)
ollama create antares-1b -f /Users/Shared/aetherclaude/config/antares/Modelfile
```

Smoke-test:
```bash
OLLAMA_HOST=127.0.0.1:11434 ollama run antares-1b "Say OK."
```

## 3. Start the service

`config/launchd/com.aetherclaude.ollama.plist` runs `ollama serve` bound to
`127.0.0.1:11434` as `aetherclaude`. `deploy.sh` installs + bootstraps it like
every other plist. Confirm:
```bash
curl -s http://127.0.0.1:11434/api/tags | python3 -m json.tool   # lists antares-1b
```

## 4. Confirm the harness reaches it

```bash
/Users/aetherclaude/bin/antares-detector.py \
    --repo /Users/aetherclaude/workspace/AetherSDR --cwe CWE-787 \
    --context "buffer overflow when parsing a network packet" --issue 0
```
A JSON verdict with `candidates` (or `verdict: clean`) prints. If Ollama is
down, `verdict: server_unreachable` and the Detector no-ops — it never blocks.

## Notes / gotchas

- **Loopback only.** `OLLAMA_HOST=127.0.0.1:11434` — the model server is never
  exposed off-box. The detector reaches it over the pf loopback rule (uid 965
  → 127.0.0.1) and bypasses tinyproxy via `NO_PROXY`; no firewall change.
- **Chat template.** If tool calls come out malformed (Ollama didn't infer the
  Granite 4.0 template from the GGUF), add an explicit `TEMPLATE` to the
  Modelfile matching the model card's chat format and re-`ollama create`.
- **Server-agnostic.** The harness speaks the OpenAI-compatible `/api/chat`; if
  Ollama can't load the Granite 4.0 GGUF, `llama-server` (llama.cpp) or vLLM
  serve the same shape — set `ANTARES_OLLAMA_URL` to point at it.
- **Memory.** `OLLAMA_KEEP_ALIVE=5m` unloads the model between the bursty
  per-issue runs so it isn't resident 24/7.
