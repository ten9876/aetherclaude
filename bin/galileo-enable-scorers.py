#!/usr/bin/env python3
"""galileo-enable-scorers.py — turn on Galileo's live scorer set for agent runs.

The dashboard forwards every triage/implement/review run to Galileo as a trace
(see galileo_forward in tetragon-dashboard.py). Enabling these scorers on the
`agent-runs` log stream makes Galileo score each trace *server-side as it lands*
— continuous evaluation, distinct from the nightly run-eval scorecard. Two
groups:

  quality   — did the agent do a good job (follow instructions, make progress,
              avoid tool errors)
  guardrail — the security lens (prompt-injection attempts, PII in the input or
              leaked in the output) — ties Galileo into AetherClaude's defense story

All are `preset` scorers: they run on Galileo's Luna-2 eval models, so no
per-metric LLM integration is needed. Idempotent + fail-open — safe to re-run
(deploy/bootstrap calls it once) and never fatal if Galileo is unreachable.

Env: GALILEO_API_KEY, GALILEO_PROJECT, GALILEO_LOG_STREAM, GALILEO_CONSOLE_URL
(the SDK reads the instance from GALILEO_CONSOLE_URL). On the sandboxed box this
must run with HTTPS_PROXY set (tinyproxy egress) — the dashboard/eval plists
already provide it.
"""
import os
import sys

# Quality — no ground truth required, tolerant of our trace shape.
QUALITY = ['instruction_adherence', 'action_advancement_luna', 'tool_error_rate_luna']
# Security guardrail — the injection + PII lens.
GUARDRAIL = ['prompt_injection', 'input_pii', 'output_pii']
SCORERS = QUALITY + GUARDRAIL


def main():
    project = os.environ.get('GALILEO_PROJECT', 'jefielde-aetherclaude')
    log_stream = os.environ.get('GALILEO_LOG_STREAM', 'agent-runs')
    if not os.environ.get('GALILEO_API_KEY'):
        print('galileo-enable-scorers: no GALILEO_API_KEY — skipping', file=sys.stderr)
        return 0
    try:
        from galileo.log_streams import enable_metrics
        enable_metrics(project_name=project, log_stream_name=log_stream, metrics=SCORERS)
        print(f'enabled {len(SCORERS)} scorers on {project}/{log_stream}:')
        print(f'  quality:   {", ".join(QUALITY)}')
        print(f'  guardrail: {", ".join(GUARDRAIL)}')
        return 0
    except Exception as e:
        # Fail-open: enabling scorers is best-effort setup, never a hard gate.
        print(f'galileo-enable-scorers: could not enable ({e})', file=sys.stderr)
        return 0


if __name__ == '__main__':
    sys.exit(main())
