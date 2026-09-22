"""Unit tests for tetragon-dashboard.py's log-follower rotation handling.

Run: python3 tests/test_tail_rotation.py
Exits non-zero on any failure with a one-line summary per case.

The invariant under test: a tail_* follower stays anchored to the live file
across a rotation, for both rotation shapes in use here — rotate-logs.sh
copy-truncates (inode kept, file shrinks) and the DefenseClaw daemon renames
and recreates (inode swaps). Followers that are only anchored at open time
stop tracking the file after it rotates, and the stages they feed stop
gaining rows.

tail_orchestrator_skills gets an end-to-end case of its own because it is the
sole producer of source='skill-dispatch', which _classify_agent_walk_stage
maps to the Agent Walk's Orchestrator and Skill stages.

Covers:
  - _tail_rotation_check: copy-truncate (inode kept, file shrinks) rewinds
  - _tail_rotation_check: rename-and-recreate (inode swaps) reopens
  - _tail_rotation_check: no rotation is a no-op (no replay of live lines)
  - _tail_rotation_check: momentarily-absent file is tolerated
  - tail_orchestrator_skills keeps emitting skill-dispatch across a rotation
  - _classify_agent_walk_stage routes those events to the right stages
"""
import importlib.util
import os
import shutil
import sys
import tempfile
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_DASH_PATH = os.path.join(_HERE, '..', 'bin', 'tetragon-dashboard.py')

spec = importlib.util.spec_from_file_location('tetragon_dashboard', _DASH_PATH)
td = importlib.util.module_from_spec(spec)
spec.loader.exec_module(td)


_FAILED = []


def check(name, cond, detail=''):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}{(' — ' + detail) if detail else ''}")
        _FAILED.append(name)


# ── _tail_rotation_check ────────────────────────────────────────────────

def test_copy_truncate_rewinds():
    """rotate-logs.sh copy-truncates: same inode, file shrinks to 0. The
    follower's offset is then past EOF, so it must rewind to stay on the
    file."""
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, 'orchestrator.log')
        with open(path, 'w') as w:
            w.write('old line\n' * 100)
        f = open(path)
        f.seek(0, 2)
        inode = os.fstat(f.fileno()).st_ino
        offset_at_eof = f.tell()
        check("copy-truncate: offset starts past EOF", offset_at_eof > 0)

        # cp + `: > file` — the inode survives, the size goes to 0.
        shutil.copy(path, path + '.1')
        open(path, 'w').close()
        with open(path, 'a') as w:
            w.write('post-rotation line\n')

        # Without the fix this readline() returns '' forever.
        check('copy-truncate: unanchored follower reads nothing', f.readline() == '')

        f, inode = td._tail_rotation_check(f, path, inode)
        check('copy-truncate: rewound to 0', f.tell() == 0, f'tell={f.tell()}')
        check('copy-truncate: reads the new line',
              f.readline().strip() == 'post-rotation line')
        f.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_rename_recreate_reopens():
    """The DefenseClaw daemon rotates by rename-and-recreate: the path gets
    a brand-new inode, so the follower must reopen the path to stay on the
    live file."""
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, 'gateway.jsonl')
        with open(path, 'w') as w:
            w.write('old line\n')
        f = open(path)
        f.seek(0, 2)
        inode = os.fstat(f.fileno()).st_ino

        os.rename(path, path + '.rotated')
        with open(path, 'w') as w:
            w.write('post-rotation line\n')

        check('rename: unanchored follower reads nothing', f.readline() == '')

        f, new_inode = td._tail_rotation_check(f, path, inode)
        check('rename: inode swapped', new_inode != inode)
        check('rename: reads the new line',
              f.readline().strip() == 'post-rotation line')
        f.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_no_rotation_is_noop():
    """The check runs on every EOF cycle, so the common case must not
    rewind — replaying live lines would double-count every event."""
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, 'quiet.log')
        with open(path, 'w') as w:
            w.write('line one\n')
        f = open(path)
        f.seek(0, 2)
        inode = os.fstat(f.fileno()).st_ino
        offset = f.tell()

        f, new_inode = td._tail_rotation_check(f, path, inode)
        check('no rotation: offset unchanged', f.tell() == offset)
        check('no rotation: inode unchanged', new_inode == inode)
        check('no rotation: no replay', f.readline() == '')
        f.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_missing_file_tolerated():
    """A log briefly absent mid-rotation must not kill the thread — the
    follower retries on the next pass."""
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, 'gone.log')
        with open(path, 'w') as w:
            w.write('line\n')
        f = open(path)
        f.seek(0, 2)
        inode = os.fstat(f.fileno()).st_ino
        os.unlink(path)
        try:
            f, new_inode = td._tail_rotation_check(f, path, inode)
            check('missing file: tolerated', new_inode == inode)
        except Exception as e:
            check('missing file: tolerated', False, repr(e))
        f.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ── tail_orchestrator_skills end-to-end ─────────────────────────────────

def test_orchestrator_follower_survives_rotation():
    """skill-dispatch events must keep landing after orchestrator.log is
    copy-truncated under the follower."""
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, 'orchestrator.log')
        with open(path, 'w') as w:
            w.write('preamble\n' * 50)

        captured = []
        orig_append = td.append_event
        td.append_event = lambda e: captured.append(e)
        try:
            t = threading.Thread(target=td.tail_orchestrator_skills,
                                 args=(path,), daemon=True)
            t.start()
            time.sleep(0.5)  # let it open and seek to EOF

            with open(path, 'a') as w:
                w.write('2026-09-21T10:00:00 [abcd1234] === Agent run starting ===\n')
            _wait_for(captured, 1)
            check('pre-rotation: event captured', len(captured) >= 1,
                  f'captured={len(captured)}')

            # Rotate exactly as rotate-logs.sh does.
            shutil.copy(path, path + '.1')
            open(path, 'w').close()

            before = len(captured)
            with open(path, 'a') as w:
                w.write('2026-09-21T10:05:00 [abcd1234] --- Skill: PR Review ---\n')
            _wait_for(captured, before + 1)
            check('post-rotation: event still captured', len(captured) > before,
                  'follower stopped tracking the file after copy-truncate')

            if len(captured) > before:
                ev = captured[-1]
                check('post-rotation: source is skill-dispatch',
                      ev.get('source') == 'skill-dispatch', repr(ev.get('source')))
                check('post-rotation: detail parsed',
                      ev.get('args') == 'PR Review', repr(ev.get('args')))
        finally:
            td.append_event = orig_append
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _wait_for(lst, n, timeout=6.0):
    """The follower polls at 1s, so give it room without sleeping blind."""
    deadline = time.time() + timeout
    while len(lst) < n and time.time() < deadline:
        time.sleep(0.1)


# ── classifier contract ─────────────────────────────────────────────────

def test_walk_stages_for_skill_dispatch():
    """Stage 2 and Stage 3 exist only for source='skill-dispatch'. If this
    ever stops holding, the follower above is no longer what feeds them."""
    stage2 = td._classify_agent_walk_stage(
        'SKILL', 'skill-dispatch', 'starting', 'skill:agent-run')
    check('agent-run → Stage 2 (Orchestrator)', stage2 == 2, f'got {stage2}')

    stage2b = td._classify_agent_walk_stage(
        'SKILL', 'skill-dispatch', 'Issue #1 → implement', 'skill:orch-transition')
    check('orch-* → Stage 2 (Orchestrator)', stage2b == 2, f'got {stage2b}')

    stage3 = td._classify_agent_walk_stage(
        'SKILL', 'skill-dispatch', 'PR Review', 'skill:skill-section')
    check('skill-section → Stage 3 (Skill)', stage3 == 3, f'got {stage3}')


if __name__ == '__main__':
    print('_tail_rotation_check')
    test_copy_truncate_rewinds()
    test_rename_recreate_reopens()
    test_no_rotation_is_noop()
    test_missing_file_tolerated()
    print('tail_orchestrator_skills')
    test_orchestrator_follower_survives_rotation()
    print('_classify_agent_walk_stage')
    test_walk_stages_for_skill_dispatch()

    if _FAILED:
        print(f"\n{len(_FAILED)} failure(s): {', '.join(_FAILED)}")
        sys.exit(1)
    print('\nall passed')
