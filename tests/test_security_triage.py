"""Unit tests for bin/security-triage.py.

Run: python3 tests/test_security_triage.py
Exits non-zero on any failure with a one-line summary per case.

The invariant under test: an audit is required exactly when a change carries
a strong security signal — CodeGuard findings other than CG-PATH-001, an added
command-exec / deserialization / input API, an edit inside a function that
holds such a call site, or a non-GUI protocol/network/auth source file — and
never for tests, docs, GUI-only names, or weak memory/format APIs alone.

Covers:
  - one positive per signal: codeguard, api (strong), boundary, path
  - weak api categories alone do not require an audit
  - CG-PATH-001 findings are ignored
  - tests/, docs/ and src/gui/ files never trigger
  - path matching is by whole CamelCase word (RtlSdr is not Tls)
  - boundary matches by function line range, not by file
  - a missing codegraph DB fails open (no boundary signal, no error)
  - --force requires an audit and lists every changed code file
"""
import importlib.util
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    'security_triage', os.path.join(HERE, '..', 'bin', 'security-triage.py'))
st = importlib.util.module_from_spec(spec)
spec.loader.exec_module(st)

failures = []


def check(name, cond):
    if not cond:
        failures.append(name)
        print(f'FAIL {name}')


def diff(path, added, old_start=10, old_count=1):
    body = '\n'.join('+' + l for l in added)
    return (f'diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n'
            f'@@ -{old_start},{old_count} +{old_start},{len(added)} @@\n{body}\n')


tmp = tempfile.mkdtemp(prefix='security-triage-')
try:
    db = os.path.join(tmp, 'codegraph.db')
    conn = sqlite3.connect(db)
    conn.executescript('''
        CREATE TABLE symbols (id INTEGER PRIMARY KEY, qualified_name TEXT,
            file_path TEXT, line_number INTEGER, end_line INTEGER);
        CREATE TABLE call_tags (id INTEGER PRIMARY KEY, symbol_id INTEGER,
            file_path TEXT, line_number INTEGER, api_name TEXT, category TEXT);
        INSERT INTO symbols VALUES (1, 'Radio::onDatagram', 'src/core/Radio.cpp', 100, 140);
        INSERT INTO call_tags VALUES (1, 1, 'src/core/Radio.cpp', 110,
            'QUdpSocket::readDatagram', 'input_read');
    ''')
    conn.commit()
    conn.close()
    nodb = os.path.join(tmp, 'missing.db')

    def run(d, findings=None, dbp=db):
        return st.triage(d, findings, dbp)

    r = run(diff('src/core/Foo.cpp', ['int x = 1;']),
            [{'id': 'CG-EXEC-001', 'file': 'src/core/Foo.cpp'}])
    check(f'codeguard finding requires audit ({r})', r['required'])

    r = run(diff('src/core/Foo.cpp', ['int x = 1;']),
            [{'id': 'CG-PATH-001', 'file': 'src/core/Foo.cpp'}])
    check(f'CG-PATH-001 alone is ignored ({r})', not r['required'])

    r = run(diff('src/core/Foo.cpp', ['QProcess p; p.start(cmd, args);']))
    check(f'QProcess added requires audit ({r})', r['required'] and 'cmd_exec' in r['categories'])

    r = run(diff('src/core/Foo.cpp', ['memcpy(dst, src, n);', 'printf("%d", n);']))
    check(f'weak apis alone do not require audit ({r})', not r['required']
          and 'buffer_ops' in r['categories'])

    r = run(diff('src/core/Radio.cpp', ['len = 0;'], old_start=120))
    check(f'edit inside a boundary function requires audit ({r})', r['required']
          and any(x.startswith('boundary') for x in r['reasons']))

    r = run(diff('src/core/Radio.cpp', ['len = 0;'], old_start=300))
    check(f'edit outside the boundary function does not ({r})', not r['required'])

    r = run(diff('src/core/Radio.cpp', ['len = 0;'], old_start=120), dbp=nodb)
    check(f'missing DB fails open ({r})', not r['required'] and 'error' not in r)

    r = run(diff('src/core/TciProtocol.cpp', ['int x = 1;']))
    check(f'protocol source path requires audit ({r})', r['required'])

    r = run(diff('src/core/backends/rtl/RtlSdrBackend.cpp', ['int x = 1;']))
    check(f'RtlSdr does not match Tls ({r})', not r['required'])

    r = run(diff('src/gui/TciApplet.cpp', ['QTcpSocket s;']))
    check(f'src/gui is ignored ({r})', not r['required'])

    r = run(diff('tests/tci_server_test.cpp', ['QProcess p; system("x");']))
    check(f'tests are ignored ({r})', not r['required'])

    r = run(diff('docs/agents/backends.md', ['system("rm")']))
    check(f'docs are ignored ({r})', not r['required'])

    r = st.triage(diff('src/gui/Panel.cpp', ['int x = 1;']), None, db,
                  'maintainer @alice requested a security audit')
    check(f'force requires audit and lists the file ({r})', r['required']
          and r['reasons'][0].startswith('forced:') and r['files'] == ['src/gui/Panel.cpp'])

    r = run(diff('src/core/Foo.cpp', ['// QProcess is not used here']))
    check(f'apis in comments do not count ({r})', not r['required'])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

if failures:
    print(f'{len(failures)} failure(s)')
    sys.exit(1)
print('all security-triage checks passed')
