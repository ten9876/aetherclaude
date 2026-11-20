"""Tests for bin/cpp-aibom's declared inventory (THIRD_PARTY_LICENSES,
third_party/ directories, FetchContent) and its merge with KB detections.

Run: python3 tests/test_cpp_aibom.py

Covers:
  - manifest sections give name, version, pinned commit, license, source
  - reference-only sections are skipped; model downloads are ML models
  - Go module tables become pkg:golang components; "not linked" rows are excluded
  - libraries bundled inside a prebuilt binary are listed
  - vendored directories: VERSION.txt, COMMIT, quoted and MAJOR/MINOR defines,
    license files (two distinct files read as a choice)
  - FetchContent pins from the project's own CMake files only
  - a KB match merges into the vendored record named by its third_party key
  - OSV.dev query forms: purl for Go, commit or tag for git sources
  - CycloneDX output carries version, scope, license expressions, VCS links
"""
import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_loader = importlib.machinery.SourceFileLoader('cpp_aibom', str(_HERE.parent / 'bin' / 'cpp-aibom'))
_spec = importlib.util.spec_from_loader('cpp_aibom', _loader)
aibom = importlib.util.module_from_spec(_spec)
_loader.exec_module(aibom)

failures = []


def check(label, got, want):
    if got != want:
        failures.append(f'{label}: got {got!r}, want {want!r}')


MANIFEST = """Project Third-Party Software Licenses
=====================================

1. WDSP 2.11 — engine-side SDR DSP
----------------------------------
Bundled as an isolated static library at third_party/wdsp/ from the exact
revision below.

  Copyright (C) 2011-2026 Warren Pratt
  License: GPL-2.0-or-later
  Source:  https://github.com/TAPR/OpenHPSDR-wdsp
  Pinned commit: e69de50d1d702216098019013899ad87534c64e0


2. TCI Protocol Specification — Transceiver Control Interface
---------------------------------------------------------------
The server implements the published specification. No code was
copied from ExpertSDR3.

  License: MIT
  Spec:    https://github.com/ExpertSDR3/TCI


3. zlib — Compression Library
-------------------------------
Bundled at third_party/zlib/ (v1.3.1) for raw-deflate decompression.

  License: zlib license (permissive, similar to MIT)
  Source:  https://github.com/madler/zlib


4. Silero VAD — Voice-Activity-Detection Model (download-on-demand)
-------------------------------------------------------------------
Model weights only; NOT bundled in the binary.

  License: MIT
  Source:  https://github.com/snakers4/silero-vad


5. sherpa-onnx — ASR Engine (optional)
---------------------------------------
Pre-built library staged at third_party/sherpa-onnx/ by a setup script.
Absent unless the setup script has been run.

  License: Apache-2.0
  Source:  https://github.com/k2-fsa/sherpa-onnx

  Bundled inside the sherpa-onnx shared library:
    - kaldifst            Apache-2.0  https://github.com/k2-fsa/kaldifst


6. shim — In-Radio Relay (Go modules, vendored)
------------------------------------------------
A separate Go program. It is never linked
into AetherSDR.

  Module                                           Version                            License
  golang.org/x/net                                 v0.59.0                            BSD-3-Clause

  Vendored but not linked into the image:
  github.com/google/go-cmp                         v0.7.0                             BSD-3-Clause


7. DeepFist — CW model weights (download-on-demand)
----------------------------------------------------
  License understanding: GPL-3.0-or-later, following the published release's
             LICENSE and README.
  Source:    https://github.com/n9bc/DeepFist/tree/930bd3cea7d9bf19fd45413acc9064b54c722871
  License:   https://raw.githubusercontent.com/n9bc/DeepFist/x/LICENSE
"""

GPL2 = "                    GNU GENERAL PUBLIC LICENSE\n                       Version 2, June 1991\n" \
       "... the GNU Library General Public License instead ...\n"
BSD3 = "Redistribution and use in source and binary forms, with or without modification, " \
       "are permitted ... Neither the name of the copyright holder ..."


def build_tree(root: Path):
    (root / 'THIRD_PARTY_LICENSES').write_text(MANIFEST)
    tp = root / 'third_party'
    for d in ('wdsp', 'zlib', 'zstd', 'rtmidi', 'littlefs', 'libmodem_core'):
        (tp / d).mkdir(parents=True)
    (tp / 'zlib' / 'zlib.h').write_text('#define ZLIB_VERSION "1.3.1"\n')
    (tp / 'zstd' / 'VERSION.txt').write_text('1.5.7 (https://github.com/facebook/zstd, release tarball)\n')
    (tp / 'zstd' / 'COPYING').write_text(GPL2)
    (tp / 'zstd' / 'LICENSE').write_text(BSD3)
    (tp / 'rtmidi' / 'RtMidi.h').write_text('#define RTMIDI_VERSION_MAJOR 6\n#define RTMIDI_VERSION_MINOR 0\n'
                                            '#define RTMIDI_VERSION_PATCH 0\n#include <string>\n')
    (tp / 'rtmidi' / 'LICENSE').write_text('Permission is hereby granted, free of charge, to any person')
    (tp / 'littlefs' / 'VERSION.txt').write_text('littlefs v2.11.3 (https://github.com/littlefs-project/littlefs)\n')
    (tp / 'libmodem_core' / 'README.aethersdr.md').write_text(
        'Upstream: https://github.com/iontodirel/libmodem\nCommit: `a8a387bc235230b4cefba64c86a5d5363677997c`\n')
    (root / 'CMakeLists.txt').write_text(
        'pkg_check_modules(rtmidi REQUIRED IMPORTED_TARGET rtmidi)\n'
        'FetchContent_Declare(libASPL\n    GIT_REPOSITORY https://github.com/gavv/libASPL.git\n'
        '    GIT_TAG        v3.1.2\n)\n')
    (tp / 'zstd' / 'CMakeLists.txt').write_text(
        'FetchContent_Declare(ignored GIT_REPOSITORY https://github.com/x/y GIT_TAG v9.9)\n')
    (root / 'src').mkdir()
    (root / 'src' / 'midi.cpp').write_text('#include <RtMidi.h>\n')


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp) / 'Proj'
    root.mkdir()
    build_tree(root)

    declared = aibom.parse_third_party_licenses(root)
    names = [r['name'] for r in declared]
    by = {r['name']: r for r in declared}
    check('reference-only section skipped', 'TCI Protocol Specification' in names, False)
    check('wdsp version', by['WDSP']['version'], '2.11')
    check('wdsp commit', by['WDSP']['commit'], 'e69de50d1d702216098019013899ad87534c64e0')
    check('wdsp dir', by['WDSP']['third_party'], 'wdsp')
    check('wdsp repo', by['WDSP']['repo_url'], 'https://github.com/TAPR/OpenHPSDR-wdsp')
    check('zlib version', by['zlib']['version'], '1.3.1')
    check('zlib license', by['zlib']['license'], 'Zlib')
    check('model type', (by['Silero VAD']['type'], by['Silero VAD']['scope']),
          ('machine-learning-model', 'optional'))
    check('optional prebuilt', (by['sherpa-onnx']['scope'], by['sherpa-onnx']['delivery']),
          ('optional', 'prebuilt'))
    check('bundled inside', by['kaldifst']['repo_url'], 'https://github.com/k2-fsa/kaldifst')
    check('go module purl', by['golang.org/x/net']['purl'], 'pkg:golang/golang.org/x/net@v0.59.0')
    check('go module scope', by['golang.org/x/net']['scope'], 'required')
    check('go not-linked scope', by['github.com/google/go-cmp']['scope'], 'excluded')
    check('helper program has no version', (by['shim']['type'], by['shim']['version']), ('application', ''))
    check('license prose trimmed, URL skipped', by['DeepFist']['license'], 'GPL-3.0-or-later')

    vendored = aibom.scan_vendored(root)
    check('quoted define', vendored['zlib']['version'], '1.3.1')
    check('VERSION.txt', vendored['zstd']['version'], '1.5.7')
    check('dual license files', vendored['zstd']['license'], 'GPL-2.0-or-later OR BSD-3-Clause')
    check('MAJOR/MINOR/PATCH', vendored['rtmidi']['version'], '6.0.0')
    check('VERSION.txt with v', vendored['littlefs']['version'], '2.11.3')
    check('README commit', vendored['libmodem_core']['commit'], 'a8a387bc235230b4cefba64c86a5d5363677997c')
    check('README upstream', vendored['libmodem_core']['repo_url'], 'https://github.com/iontodirel/libmodem')

    sources, cmakes = aibom.walk_codebase(root)
    fetched = aibom.scan_fetchcontent(cmakes, root)
    check('fetchcontent', [(r['name'], r['version'], r['repo_url']) for r in fetched],
          [('libASPL', '3.1.2', 'https://github.com/gavv/libASPL')])

    kb = [{'name': 'RtMidi', 'category': 'hardware', 'license': 'MIT', 'purl': 'pkg:github/thestk/rtmidi',
           'third_party': 'rtmidi', 'detect': {'include': ['RtMidi.h'], 'cmake': ['rtmidi']}},
          {'name': 'Vulkan', 'category': 'system', 'license': 'Apache-2.0', 'purl': 'pkg:generic/vulkan-loader',
           'scope': 'optional', 'detect': {'include': [], 'cmake': ['rtmidi']}}]
    sig = aibom.extract_signals(root, sources, cmakes)
    detected = [r for r in (aibom.match_component(c, sig) for c in kb) if r]
    merged = aibom.merge_inventory(detected, declared, aibom.scan_vendored(root), fetched, kb)
    mby = {}
    for r in merged:
        mby.setdefault(r['name'], []).append(r)
    check('one record per vendored dir', [r['name'] for r in merged if r['third_party'] == 'rtmidi'], ['rtmidi'])
    rt = mby['rtmidi'][0]
    check('KB merged into vendored record', (rt['category'], rt['confidence'], rt['version']),
          ('hardware', 'high', '6.0.0'))
    check('purl gains repo version', rt['purl'], 'pkg:github/thestk/rtmidi@6.0.0')
    check('KB scope kept for system lib', mby['Vulkan'][0]['scope'], 'optional')
    check('manifest record takes vendored data', mby['WDSP'][0]['license'], 'GPL-2.0-or-later')
    check('vendored dir covered by manifest not duplicated', 'wdsp' in mby, False)

    check('osv go', aibom.osv_queries(mby['golang.org/x/net'][0]),
          [{'package': {'purl': 'pkg:golang/golang.org/x/net@v0.59.0'}}])
    check('osv commit', aibom.osv_queries(mby['WDSP'][0]),
          [{'commit': 'e69de50d1d702216098019013899ad87534c64e0'}])
    check('osv tags', aibom.osv_queries(mby['zlib'][0]),
          [{'version': '1.3.1', 'package': {'name': 'https://github.com/madler/zlib', 'ecosystem': 'GIT'}},
           {'version': 'v1.3.1', 'package': {'name': 'https://github.com/madler/zlib', 'ecosystem': 'GIT'}}])
    check('osv nothing to ask', aibom.osv_queries(mby['Vulkan'][0]), [])

    for r in merged:
        r.setdefault('vulnerabilities', [])
    cdx = aibom.emit_cyclonedx(root, merged)
    cby = {c['name']: c for c in cdx['components']}
    check('cdx version', cby['zlib']['version'], '1.3.1')
    check('cdx scope', cby['github.com/google/go-cmp']['scope'], 'excluded')
    check('cdx expression', cby['zstd']['licenses'], [{'expression': 'GPL-2.0-or-later OR BSD-3-Clause'}])
    check('cdx MIT id', cby['rtmidi']['licenses'], [{'license': {'id': 'MIT'}}])
    check('cdx vcs', cby['WDSP']['externalReferences'],
          [{'type': 'vcs', 'url': 'https://github.com/TAPR/OpenHPSDR-wdsp'}])
    check('cdx unique refs', len({c['bom-ref'] for c in cdx['components']}), len(cdx['components']))
    json.dumps(cdx)

for f in failures:
    print('FAIL', f)
print(f'{"FAILED" if failures else "ok"}: {len(failures)} failure(s)')
sys.exit(1 if failures else 0)
