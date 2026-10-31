"""API-equivalent cost of one Claude request, from config/model-pricing.json.

The one price table and model-name normaliser shared by the post footer
(bot-cost.py) and the dashboard (tetragon-dashboard.py). Update prices in
the JSON file only.
"""
import json
import os

PRICING_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
                            'config', 'model-pricing.json')

with open(PRICING_FILE) as _fh:
    _DATA = json.load(_fh)

MODELS = _DATA['models']
TIERS = _DATA['tiers']
FALLBACK_MODEL = _DATA['fallback']


def normalize(model):
    """Map a transcript's model ID to its price-list key. Earlier models
    appear as dated snapshots (claude-sonnet-4-5-20250929) or as -4-0."""
    model = model or ''
    base, _, date = model.rpartition('-')
    if len(date) == 8 and date.isdigit():
        model = base
    if model in ('claude-opus-4-0', 'claude-sonnet-4-0'):
        model = model[:-2]
    return model


def rates(model, prompt_tokens):
    """Rates for one request. A tiered model's prompt length counts all of
    its input tokens, cache reads and writes included, but not output."""
    model = normalize(model)
    tier = TIERS.get(model)
    if tier and prompt_tokens > tier['above_prompt_tokens']:
        return tier['rates']
    return MODELS.get(model) or MODELS[FALLBACK_MODEL]


def request_cost(model, inp, out, cache_read, cache_create):
    """USD for one request. Price each request on its own: a tier applies
    per request, never to a session's summed tokens."""
    r = rates(model, inp + cache_read + cache_create)
    return (inp * r['input'] + out * r['output']
            + cache_read * r['cache_read'] + cache_create * r['cache_create']) / 1_000_000
