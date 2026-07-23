#!/usr/bin/env python3
"""codegraph-cartographer — repo-context pack for the Foundry Cartographer stage.

Turns the codegraph SQLite graph (+ cpp-aibom CVE data) into a layered,
machine-consumable "Repo context" artifact — the input the Detector stage
(Antares-1B) and Claude Code's implement-fix flow both read to understand the
target repo before touching it.

Layers:
  L0 repo card      — identity, freshness (HEAD sha), size, deps + open CVEs
  L1 subsystem map  — Louvain communities (= subsystems) with key members
  L2 security overlay — dangerous-API call sites by category (from call_tags),
                        input boundaries, dependency CVEs
  L3 key symbols    — top symbols by betweenness (the graph's load-bearing nodes)

Emits BOTH repo-context.md (human/Claude) and repo-context.json (harness), read
from the same DB. `--cwe CWE-787` prints a focused slice to stdout for the
Detector harness. Read-only, stdlib-only, atomic tmp+rename writes — mirrors
codegraph-report.py. Degrades gracefully when call_tags or the AIBOM file are
absent (older DB / dependency scan not run).
"""
import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

DEFAULT_DB = os.environ.get('CODEGRAPH_DB', '/Users/Shared/aetherclaude/data/codegraph.db')
DEFAULT_OUT_DIR = '/Users/Shared/aetherclaude/data'
DEFAULT_AIBOM = '/Users/aetherclaude/logs/aibom-latest.json'

# CWE family -> overlay categories the Detector should focus on. Keyed by the
# numeric CWE id (string). 'default' covers anything unmapped (whole overlay).
CWE_MAP = {
    '787': ['buffer_ops'], '121': ['buffer_ops'], '122': ['buffer_ops'],
    '120': ['buffer_ops'], '125': ['buffer_ops'],
    '78': ['cmd_exec'], '134': ['format'], '22': ['path_ops'],
    '415': ['alloc_free'], '416': ['alloc_free'],
    '502': ['deserial'], '190': ['buffer_ops', 'alloc_free'],
    '191': ['buffer_ops', 'alloc_free'], '20': ['input_read'],
}
ALL_CATEGORIES = ['buffer_ops', 'format', 'cmd_exec', 'path_ops',
                  'alloc_free', 'deserial', 'input_read']
CATEGORY_DESC = {
    'buffer_ops': 'memory/string writes (overflow — CWE-120/787)',
    'format': 'printf-family format strings (CWE-134)',
    'cmd_exec': 'process/command execution (CWE-78)',
    'path_ops': 'filesystem path operations (CWE-22)',
    'alloc_free': 'heap allocate/free (UAF/double-free — CWE-415/416)',
    'deserial': 'deserialization / parsers (CWE-502)',
    'input_read': 'external-input entry points (attack surface)',
}


def _ro(db_path):
    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _has_table(conn, name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _meta(conn):
    return dict(conn.execute("SELECT key, value FROM metadata").fetchall())


def _load_aibom(path):
    """Return (components, summary) or ([], {}) if unreadable."""
    try:
        with open(path) as f:
            d = json.load(f)
        a = d.get('aibom_analysis', {})
        return a.get('components', []), a.get('summary', {})
    except Exception:
        return [], {}


# --------------------------------------------------------------------------
# Layer builders — each returns a plain dict (the JSON pack); the Markdown
# renderer consumes the same dicts so the two artifacts never drift.
# --------------------------------------------------------------------------

def build_l0(conn, meta, aibom_summary, components):
    open_cves = sum(len(c.get('vulnerabilities', [])) for c in components)
    # "Subsystems" = meaningful communities (size>=3), matching the L1 map and
    # the viewer. The raw analyze count (metadata.community_count) includes
    # thousands of singletons (median size 1) and would read as ~3500 — not a
    # useful subsystem number.
    community_count = conn.execute(
        "SELECT COUNT(*) FROM (SELECT community_id FROM symbols "
        "WHERE community_id IS NOT NULL AND kind!='concept' "
        "GROUP BY community_id HAVING COUNT(*)>=3)").fetchone()[0]
    return {
        'repo': 'AetherSDR',
        'head_sha': meta.get('src_head_sha', ''),
        'extractor_version': meta.get('extractor_version', ''),
        'overlay_version': meta.get('overlay_version'),
        'extracted_at': meta.get('extracted_at', ''),
        'symbol_count': int(meta.get('symbol_count', 0) or 0),
        'edge_count': int(meta.get('edge_count', 0) or 0),
        'community_count': community_count,
        'call_tag_count': int(meta.get('call_tag_count', 0) or 0),
        'language': 'C++ / Qt6',
        'build_system': 'CMake + Ninja',
        'dependencies': [c.get('name') for c in components],
        'dependency_count': aibom_summary.get('total_components', len(components)),
        'open_cve_count': open_cves,
    }


def build_l1(conn, limit=25, members_per=5):
    """Subsystems = Louvain communities (size>=3), labeled by directory."""
    rows = conn.execute(
        "SELECT community_id, community_label, COUNT(*) n "
        "FROM symbols WHERE kind!='concept' AND community_id IS NOT NULL "
        "GROUP BY community_id HAVING n>=3 ORDER BY n DESC LIMIT ?", (limit,)
    ).fetchall()
    subsystems = []
    for r in rows:
        cid = r['community_id']
        members = conn.execute(
            "SELECT name, qualified_name, file_path, betweenness "
            "FROM symbols WHERE community_id=? AND kind!='concept' "
            "ORDER BY degree DESC LIMIT ?", (cid, members_per)
        ).fetchall()
        concepts = [x['name'] for x in conn.execute(
            "SELECT DISTINCT c.name FROM symbols c "
            "JOIN edges e ON e.src_id=c.id JOIN symbols t ON t.id=e.dst_id "
            "WHERE c.kind='concept' AND t.community_id=? LIMIT 4", (cid,)
        ).fetchall()]
        subsystems.append({
            'label': r['community_label'] or f'community-{cid}',
            'size': r['n'],
            'key_symbols': [m['qualified_name'] for m in members],
            'concepts': concepts,
        })
    return subsystems


def build_l2(conn, components, top_sites=8):
    """Security overlay. Empty categories omitted; boundaries derived from
    input_read sites' enclosing functions."""
    overlay = {'available': _has_table(conn, 'call_tags'), 'categories': {},
               'input_boundaries': [], 'dependency_cves': []}
    if overlay['available']:
        cats = dict(conn.execute(
            "SELECT category, COUNT(*) FROM call_tags GROUP BY category"
        ).fetchall())
        for cat in ALL_CATEGORIES:
            n = cats.get(cat, 0)
            if not n:
                continue
            sites = conn.execute(
                "SELECT ct.file_path, ct.line_number, ct.api_name, "
                "s.qualified_name enc, s.betweenness bet "
                "FROM call_tags ct LEFT JOIN symbols s ON s.id=ct.symbol_id "
                "WHERE ct.category=? ORDER BY COALESCE(s.betweenness,0) DESC, "
                "ct.file_path LIMIT ?", (cat, top_sites)
            ).fetchall()
            overlay['categories'][cat] = {
                'count': n, 'desc': CATEGORY_DESC.get(cat, ''),
                'top_sites': [{'file': s['file_path'], 'line': s['line_number'],
                               'api': s['api_name'], 'function': s['enc'],
                               'betweenness': round(s['bet'] or 0, 4)} for s in sites],
            }
        # input boundaries = distinct enclosing functions of input_read sites
        overlay['input_boundaries'] = [
            {'function': b['qualified_name'], 'file': b['file_path'],
             'betweenness': round(b['betweenness'] or 0, 4)}
            for b in conn.execute(
                "SELECT DISTINCT s.qualified_name, s.file_path, s.betweenness "
                "FROM call_tags ct JOIN symbols s ON s.id=ct.symbol_id "
                "WHERE ct.category='input_read' "
                "ORDER BY COALESCE(s.betweenness,0) DESC LIMIT 15").fetchall()]
    # dependency CVEs from AIBOM (independent of the graph)
    for c in components:
        for v in c.get('vulnerabilities', []):
            overlay['dependency_cves'].append({
                'component': c.get('name'), 'id': v.get('id'),
                'severity': v.get('severity'), 'score': v.get('score'),
                'summary': (v.get('summary') or '')[:160],
            })
    overlay['dependency_cves'].sort(
        key=lambda v: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(v['severity'], 4))
    return overlay


def build_l3(conn, limit=40):
    rows = conn.execute(
        "SELECT qualified_name, file_path, line_number, signature, "
        "betweenness, community_label FROM symbols "
        "WHERE kind!='concept' AND betweenness>0 "
        "ORDER BY betweenness DESC LIMIT ?", (limit,)
    ).fetchall()
    return [{'symbol': r['qualified_name'],
             'loc': f"{r['file_path']}:{r['line_number']}",
             'signature': (r['signature'] or '')[:120],
             'betweenness': round(r['betweenness'] or 0, 4),
             'subsystem': r['community_label']} for r in rows]


def build_pack(db_path, aibom_path):
    conn = _ro(db_path)
    meta = _meta(conn)
    components, aibom_summary = _load_aibom(aibom_path)
    pack = {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'l0_repo_card': build_l0(conn, meta, aibom_summary, components),
        'l1_subsystems': build_l1(conn),
        'l2_security': build_l2(conn, components),
        'l3_key_symbols': build_l3(conn),
    }
    conn.close()
    return pack


# --------------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------------

def _esc(s):
    return (str(s or '')).replace('|', '\\|').replace('`', "'")


def render_md(pack):
    l0, subs, sec, keys = (pack['l0_repo_card'], pack['l1_subsystems'],
                           pack['l2_security'], pack['l3_key_symbols'])
    o = []
    o.append(f"# Repo Context Pack — {l0['repo']}\n")
    o.append(f"_Cartographer · generated {pack['generated_at']} · "
             f"HEAD `{l0['head_sha'][:12] or 'unknown'}`_\n")

    o.append("## L0 · Repo card\n")
    o.append(f"- **{l0['language']}**, {l0['build_system']}")
    o.append(f"- {l0['symbol_count']:,} symbols · {l0['edge_count']:,} edges · "
             f"{l0['community_count']} subsystems")
    o.append(f"- {l0['dependency_count']} tracked dependencies · "
             f"**{l0['open_cve_count']} open CVEs**")
    o.append(f"- Security overlay: {'yes, ' + format(l0['call_tag_count'], ',') + ' tagged call sites' if l0.get('overlay_version') else 'not available (rerun clangd extractor)'}\n")

    o.append("## L1 · Subsystem map\n")
    o.append("| Subsystem | Symbols | Key members | Concepts |")
    o.append("|---|--:|---|---|")
    for s in subs:
        km = ', '.join(_esc(k.split('::')[-1]) for k in s['key_symbols'][:4])
        cc = ', '.join(_esc(c) for c in s['concepts'][:3]) or '—'
        o.append(f"| {_esc(s['label'])} | {s['size']} | {km} | {cc} |")
    o.append("")

    o.append("## L2 · Security overlay\n")
    if not sec['available']:
        o.append("_Call-site overlay unavailable (DB predates the tagger)._\n")
    else:
        for cat, d in sec['categories'].items():
            o.append(f"### {cat} — {d['count']} site{'' if d['count']==1 else 's'}  \n_{d['desc']}_\n")
            o.append("| File:line | API | Enclosing function |")
            o.append("|---|---|---|")
            for st in d['top_sites']:
                o.append(f"| {_esc(st['file'])}:{st['line']} | `{_esc(st['api'])}` | "
                         f"{_esc((st['function'] or '?').split('::')[-1])} |")
            o.append("")
        if sec['input_boundaries']:
            o.append("### Input boundaries (attack surface)\n")
            for b in sec['input_boundaries'][:10]:
                o.append(f"- `{_esc(b['function'])}` — {_esc(b['file'])}")
            o.append("")
    if sec['dependency_cves']:
        o.append("### Dependency CVEs\n")
        o.append("| Component | CVE | Severity | Summary |")
        o.append("|---|---|---|---|")
        for v in sec['dependency_cves'][:20]:
            o.append(f"| {_esc(v['component'])} | {_esc(v['id'])} | {_esc(v['severity'])} | "
                     f"{_esc(v['summary'][:80])} |")
        o.append("")

    o.append("## L3 · Key symbols (by betweenness)\n")
    o.append("| Symbol | Location | Subsystem |")
    o.append("|---|---|---|")
    for k in keys[:30]:
        o.append(f"| {_esc(k['symbol'].split('::')[-1])} | {_esc(k['loc'])} | "
                 f"{_esc(k['subsystem'])} |")
    o.append("")
    return '\n'.join(o)


def render_implement_context(pack):
    """Compact L0+L1 slice (~repo card + subsystem map) for injection into
    the implement-fix prompt — grounding before Claude reads source. Kept
    small (no per-symbol overlay); the full pack is at /repo-context.md and
    the codegraph MCP serves on-demand detail."""
    l0, subs = pack['l0_repo_card'], pack['l1_subsystems']
    if not l0.get('head_sha') and not subs:
        return ''  # no usable pack — caller substitutes empty
    nsub = l0['community_count'] or len(subs)
    o = [f"## Repo map (Cartographer @ {l0['head_sha'][:12] or 'unknown'})\n",
         f"{l0['language']}, {l0['build_system']} · {l0['symbol_count']:,} symbols · "
         f"{nsub} subsystems · {l0['open_cve_count']} open dependency CVEs\n",
         "Subsystems (Louvain communities, key members):"]
    for s in subs[:15]:
        km = ', '.join(k.split('::')[-1] for k in s['key_symbols'][:4])
        o.append(f"- **{s['label']}** ({s['size']}): {km}")
    o.append("\n_Full security overlay + symbol index: the /cartographer pack; "
             "call `mcp__codegraph__impact` for blast radius before structural edits._")
    return '\n'.join(o)


def render_cwe_slice(pack, cwe):
    """Focused Markdown slice for the Detector harness: repo card + only the
    overlay categories a given CWE implicates + input boundaries."""
    num = ''.join(ch for ch in str(cwe) if ch.isdigit())
    cats = CWE_MAP.get(num, ALL_CATEGORIES)
    l0, sec = pack['l0_repo_card'], pack['l2_security']
    o = [f"# Detector context — {l0['repo']} @ {l0['head_sha'][:12]} · CWE-{num or '?'}\n",
         f"Focus categories: {', '.join(cats)}\n"]
    if not sec['available']:
        o.append("_No security overlay available._")
    else:
        for cat in cats:
            d = sec['categories'].get(cat)
            if not d:
                continue
            o.append(f"## {cat} — {d['count']} sites ({d['desc']})")
            for st in d['top_sites']:
                o.append(f"- {st['file']}:{st['line']}  {st['api']}  in {st['function']}")
            o.append("")
        o.append("## Input boundaries")
        for b in sec['input_boundaries'][:12]:
            o.append(f"- {b['function']} — {b['file']}")
    return '\n'.join(o)


def _atomic_write(path, text):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + '.tmp')
    tmp.write_text(text, encoding='utf-8')
    os.replace(tmp, p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default=DEFAULT_DB)
    ap.add_argument('--aibom', default=DEFAULT_AIBOM)
    ap.add_argument('--out-dir', default=DEFAULT_OUT_DIR)
    ap.add_argument('--cwe', help='Print a focused CWE slice to stdout (e.g. CWE-787) instead of writing packs.')
    ap.add_argument('--implement-context', action='store_true',
                    help='Print the compact L0+L1 slice to stdout (for the implement-fix prompt).')
    ap.add_argument('--stdout', action='store_true', help='Print full markdown pack to stdout.')
    args = ap.parse_args()

    if not os.path.exists(args.db):
        # Graceful: consumers that inline our stdout (implement-fix) get an
        # empty string rather than a hard error, so a missing DB never breaks
        # the agent — it just proceeds without the map.
        if args.implement_context or args.cwe:
            return 0
        print(f'ERROR: db not found: {args.db}', file=sys.stderr)
        return 2
    pack = build_pack(args.db, args.aibom)

    if args.implement_context:
        sys.stdout.write(render_implement_context(pack))
        return 0
    if args.cwe:
        sys.stdout.write(render_cwe_slice(pack, args.cwe))
        return 0
    md = render_md(pack)
    if args.stdout:
        sys.stdout.write(md)
        return 0
    _atomic_write(os.path.join(args.out_dir, 'repo-context.md'), md)
    _atomic_write(os.path.join(args.out_dir, 'repo-context.json'),
                  json.dumps(pack, indent=2))
    print(f"cartographer: wrote repo-context.md ({len(md):,} B) + "
          f"repo-context.json to {args.out_dir}", file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
