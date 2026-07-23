# Foundry Validator (prototype)

The **Validator** stage of the Cisco Cyber AI Foundry pipeline: turn an
**Antares Detector** finding (`file` + `CWE`) into ground truth by executing the
*real* code under **AddressSanitizer + UndefinedBehaviorSanitizer** against
crafted malicious input.

```
Detector (Antares-1B)  ──►  Validator  ──►  CONFIRMED / UNCONFIRMED  ──►  Patcher
   "AdifParser.cpp             build that file + a driver under          fix, re-run
    is CWE-787"                ASan/UBSan, feed the corpus               → UNCONFIRMED
```

## What's here
- `adif_validate.cpp` — driver that runs the real `AetherSDR::AdifParser::parseFile`.
- `corpus/*.adi` — crafted inputs + `valid.adi`, a control that must stay clean
  (the "preserved valid use" check).
- `../../bin/validate-finding.sh` — the runner: builds the localized file + the
  driver under ASan/UBSan (runs `moc`, stubs the one null-guarded `CtyDatParser`
  symbol to isolate the parser), runs the corpus, and emits a verdict JSON.

## Run it
```bash
# needs Homebrew Qt (brew install qt) + clang
bin/validate-finding.sh --repo /path/to/AetherSDR --cwe CWE-787 --out verdict.json
```

Verdict per input: **TRIP** (a sanitizer fired → the bug reproduces, with
`file:line`) or **CLEAN**. Any trip in the localized file outside the control ⇒
`CONFIRMED`.

## Proven result (AdifParser, CWE-787)
Antares localized `src/core/AdifParser.cpp` as CWE-787 (out-of-bounds write).
The Validator's ground truth **refined** it: the OOB write does *not* reproduce
(the bounds guard + Qt's `mid` are memory-safe), but a crafted `<CALL:2147483647>`
**does** trip a **signed-integer-overflow (CWE-190)** at the `start + len`
addition in `extractField`. The one-line fix
(`if (len < 0 || len > block.length() - start)`) makes every malicious input
clean while the control still parses — confirming the exploit *and* the patch.

## Scope / caveats
- **Coverage is parser-shaped.** File/network parsers (ADIF, TCI) are the sweet
  spot. Deep DSP paths (`AudioEngine` memcpy, PLC) that need a live audio/VITA
  stream would be driven via the AetherSDR **automation bridge** (`AutomationServer`,
  a headless `AETHER_MCP_TOKEN` control channel) or a targeted libFuzzer harness.
- **Build home.** This prototype builds locally against Homebrew Qt. The
  production testbed build belongs in **CI/Docker** (where AetherSDR already
  builds), instrumented with `-fsanitize=address,undefined`.
- The build list (`--file`, the `CtyDatParser` stub) is finding-specific; the
  runner mechanics are reusable.
