# Antares Detector — model + service setup (Mac Mini)

The **Detector** stage of the Foundry pipeline: Cisco Foundation AI's
**Antares-1B** vulnerability-localization model, served locally by Ollama and
driven by `bin/antares-detector.py`. This is a one-time deploy on the Mini;
everything is Apple-Silicon-Metal native and loopback-only.

Antares-1B is `GraniteMoeHybridForCausalLM` (IBM Granite 4.0 — a **Mamba2 + MoE
hybrid**, ~1.8 B params, Apache 2.0, 131072 context). That architecture drives
two of the gotchas below.

## 1. Install Ollama (once)

```bash
brew install ollama            # /opt/homebrew/bin/ollama
```

## 2. Convert the model to a GGUF (first-party)

Cisco ships `fdtn-ai/antares-1b` as **safetensors** (not GGUF) and the repo is
**gated** — accept the license on Hugging Face and set an `HF_TOKEN` first.
We convert the official weights ourselves (first-party provenance) with
llama.cpp:

```bash
mkdir -p ~/antares-build && cd ~/antares-build
python3.14 -m venv .venv                      # torch has no 3.9 wheel; use 3.12+/3.14
git clone --depth 1 https://github.com/ggml-org/llama.cpp
.venv/bin/pip install -r llama.cpp/requirements/requirements-convert_hf_to_gguf.txt

# download the gated weights (needs HF_TOKEN with access granted)
.venv/bin/python - <<'PY'
import os
from huggingface_hub import snapshot_download
snapshot_download("fdtn-ai/antares-1b", local_dir="antares-hf",
    allow_patterns=["*.safetensors","*.json","tokenizer*","chat_template.jinja"],
    token=os.environ["HF_TOKEN"])
PY

# convert to bf16 (NOT Q8_0 — see gotcha) and place where the Modelfile expects
.venv/bin/python llama.cpp/convert_hf_to_gguf.py antares-hf \
    --outtype bf16 --outfile antares-1b-bf16.gguf
sudo cp antares-1b-bf16.gguf /Users/Shared/aetherclaude/models/antares-1b-bf16.gguf
sudo chmod 644 /Users/Shared/aetherclaude/models/antares-1b-bf16.gguf
```

Then import with the Modelfile (which pins the chat template + sampling), and
smoke-test:

```bash
ollama create antares-1b -f /Users/Shared/aetherclaude/config/antares/Modelfile
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

## Notes / gotchas (learned at deploy)

- **Do NOT quantize to Q8_0.** Q8_0 corrupts this model's Mamba2/SSM recurrent
  tensors — output becomes pure garbage (`"isot isot … Attempt Attempt"`) even
  on trivial prompts. **bf16** (full precision, ~3.4 GB) is correct and trivial
  for a 1 B model on Metal. This is a known hazard for hybrid/SSM models.
- **Chat template must be explicit.** Ollama does not infer the Granite 4.0
  template from the GGUF (it falls back to a bare `{{ .Prompt }}` passthrough →
  garbage). The Modelfile carries a `TEMPLATE` that reproduces
  `chat_template.jinja` (`<|start_of_role|>…<|end_of_role|>…<|end_of_text|>`,
  assistant primed with `<think>`). Download `chat_template.jinja` alongside the
  weights so the format is on hand.
- **num_ctx.** Ollama defaults to 4096, which the agentic loop overflows after a
  few commands (`request exceeds available context`). The Modelfile sets
  `num_ctx 32768`.
- **Loopback only.** `OLLAMA_HOST=127.0.0.1:11434` — the model server is never
  exposed off-box. The detector reaches it over the pf loopback rule (uid 965
  → 127.0.0.1) and bypasses tinyproxy via `NO_PROXY`; no firewall change.
- **Server-agnostic.** The harness speaks the OpenAI-compatible `/api/chat`; if
  Ollama can't serve the hybrid GGUF, `llama-server` (llama.cpp) or vLLM serve
  the same shape — set `ANTARES_OLLAMA_URL` to point at it.
- **Memory.** `OLLAMA_KEEP_ALIVE=5m` unloads the model between the bursty
  per-issue runs so it isn't resident 24/7.
