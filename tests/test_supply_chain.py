"""Tests for the supply-chain data path: cpp-aibom's OSV summary (real CVSS
base scores, alias merging, fix points, lookup status) and
bin/supply_chain.py, which builds /api/supply-chain.

Run: python3 tests/test_supply_chain.py   (offline; OSV calls are stubbed)
"""
import importlib.machinery
import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / 'bin'))
_loader = importlib.machinery.SourceFileLoader('cpp_aibom_sc', str(_HERE.parent / 'bin' / 'cpp-aibom'))
_spec = importlib.util.spec_from_loader('cpp_aibom_sc', _loader)
aibom = importlib.util.module_from_spec(_spec)
_loader.exec_module(aibom)
import supply_chain  # noqa: E402

failures = []


def check(label, got, want):
    if got != want:
        failures.append(f'{label}: got {got!r}, want {want!r}')


# Real base scores from the vendored calculator.
check('cvss 3.1', aibom.cvss_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), (9.8, '3.1'))
check('cvss 4.0', aibom.cvss_base_score('CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'), (6.8, '4.0'))
check('cvss garbage', aibom.cvss_base_score('CVSS:3.1/AV:Q'), None)
check('severity bands', [aibom._severity_for(s) for s in (9.8, 7.0, 4.0, 0.9, 0.0, None)],
      ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'])

# A record without a vector borrows its CVE alias's vector.
aliases = {'CVE-2026-1': {'id': 'CVE-2026-1', 'severity': [
    {'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}]}}
aibom.osv_vuln = lambda vid: aliases.get(vid)
query = {'package': {'purl': 'pkg:golang/golang.org/x/net@v0.59.0'}}
raw = [
    {'id': 'GO-2026-1', 'aliases': ['CVE-2026-1'], 'summary': 'HTTP/2 exhaustion',
     'affected': [{'package': {'purl': 'pkg:golang/golang.org/x/net'},
                   'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '0.60.0'}]}]},
                  {'package': {'purl': 'pkg:golang/stdlib'},
                   'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '1.26.9'}]}]}]},
    {'id': 'GO-2026-2', 'withdrawn': '2026-11-01T00:00:00Z'},
    {'id': 'GO-2026-3', 'summary': 'no score anywhere'},
]
s = aibom._summarize_vulns(raw, query)
check('withdrawn dropped', [v['id'] for v in s], ['GO-2026-1', 'GO-2026-3'])
check('score from alias', (s[0]['score'], s[0]['severity'], s[0]['score_source']), (7.5, 'HIGH', 'CVE-2026-1'))
check('fix point for this package only', s[0]['fixed'], ['fixed in 0.60.0'])
check('no score published', (s[1]['score'], s[1]['severity'], s[1]['cvss_vector']), (None, 'UNKNOWN', ''))

# Records naming the same vulnerability merge; the best score wins.
merged = aibom._merge_aliases([
    {'id': 'GHSA-x', 'aliases': ['CVE-2026-9'], 'score': None, 'references': ['a'], 'fixed': []},
    {'id': 'CVE-2026-9', 'aliases': [], 'score': 8.1, 'references': ['b'], 'fixed': ['fixed in 2']},
    {'id': 'CVE-2026-5', 'aliases': [], 'score': 9.0, 'references': [], 'fixed': []},
])
check('merge count', len(merged), 2)
check('merge order', [m['id'] for m in merged], ['CVE-2026-5', 'CVE-2026-9'])
check('merge keeps union', (merged[1]['cve'], merged[1]['aliases'], merged[1]['references']),
      ('CVE-2026-9', ['GHSA-x'], ['a', 'b']))

# Lookup status: nothing to ask, failure, success.
rec = {'name': 'Qt6', 'purl': 'pkg:generic/qt', 'version': '', 'commit': '', 'repo_url': ''}
check('unchecked returns none', aibom.osv_lookup(rec), [])
check('unchecked status', rec['osv_status'], 'not checked: version unknown')
aibom.osv_query = lambda q: None
rec = {'name': 'zlib', 'version': '1.3.1', 'commit': '', 'repo_url': 'https://github.com/madler/zlib', 'purl': ''}
aibom.osv_lookup(rec)
check('failed status', rec['osv_status'], 'lookup failed')
aibom.osv_query = lambda q: []
aibom.osv_lookup(rec)
check('checked status', rec['osv_status'], 'checked')

# /api/supply-chain
v = lambda i, score, sev: {'id': i, 'cve': i if i.startswith('CVE') else '', 'score': score, 'severity': sev,
                           'aliases': [], 'fixed': [], 'references': []}
data = supply_chain.build({'scan_time': 't', 'version': '2.1.0', 'target_commit': 'abc', 'aibom_analysis': {'components': [
    {'name': 'quiet', 'version': '1', 'osv_status': 'checked', 'vulnerabilities': []},
    {'name': 'unscored', 'version': '1', 'osv_status': 'checked', 'vulnerabilities': [v('GO-1', None, 'UNKNOWN')]},
    {'name': 'zlib', 'version': '1.3.1', 'osv_status': 'checked',
     'vulnerabilities': [v('CVE-2', 4.6, 'MEDIUM'), v('CVE-1', 9.8, 'CRITICAL')]},
    {'name': 'Qt6', 'osv_status': 'not checked: version unknown', 'vulnerabilities': []},
    {'name': 'littlefs', 'version': '2', 'osv_status': 'checked', 'vulnerabilities': [v('CVE-3', 6.8, 'MEDIUM')]},
]}})
check('package order', [p['name'] for p in data['packages']], ['zlib', 'littlefs', 'unscored', 'quiet', 'Qt6'])
z = data['packages'][0]
check('top advisory', (z['max_score'], z['max_severity'], z['top_cve']), (9.8, 'CRITICAL', 'CVE-1'))
check('advisories most severe first', [x['id'] for x in z['vulns']], ['CVE-1', 'CVE-2'])
check('summary', data['summary'], {'total': 5, 'checked': 4, 'not_checked': 1, 'affected': 3, 'open_advisories': 4,
                                   'by_severity': {'UNKNOWN': 1, 'MEDIUM': 2, 'CRITICAL': 1}})
check('commit', data['commit'], 'abc')

for f in failures:
    print('FAIL', f)
print(f'{"FAILED" if failures else "ok"}: {len(failures)} failure(s)')
sys.exit(1 if failures else 0)
