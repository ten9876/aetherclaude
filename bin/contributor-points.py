#!/usr/bin/env python3
"""Contributor points for aethersdr/AetherSDR.

Collects immutable GitHub facts (issues, PRs, comments, reviews, labels,
discussions, releases, main-branch CI breaks) into SQLite, then rebuilds the
points ledger from those facts on every run. Rules live in RULES below; a
rule change or a revocation (spam label, dismissed approval, a re-run that
went green) needs no migration, only a re-score.

Points depend on the kind of action, never on its size.

Collection is incremental: a cursor in the database remembers where the last
run stopped, PR details are refetched only when the PR changed after they
were fetched, completed CI runs and commit->PR lookups are never refetched,
and fixed-URL responses are cached with their ETag so an unchanged answer
comes back as a 304, which GitHub does not charge against the rate limit.
Progress is committed in batches, so an interrupted backfill resumes.

Usage:
  contributor-points.py collect                 # since the stored cursor (first run: full backfill)
  contributor-points.py collect --since 2026-09-20T00:00:00Z
  contributor-points.py score --json out.json
"""
import argparse, base64, gzip, json, os, re, shutil, sqlite3, subprocess, sys, time, urllib.error, urllib.parse, urllib.request, zlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import ci_diagnose  # noqa: E402

REPO = 'aethersdr/AetherSDR'
REPO_START = '2026-03-12T00:00:00Z'   # first backfill starts here
CURSOR_OVERLAP = timedelta(minutes=10)
OWNER, NAME = REPO.split('/')
DB_PATH = os.environ.get('CONTRIBUTOR_DB', '/Users/aetherclaude/data/contributors.db')
MAINTAINERS = {'ten9876'}
# Core dev team: shown with a shield badge. Doesn't affect scoring or who can
# win (only the maintainer is excluded). Compared case-insensitively.
CORE_TEAM = {c.lower() for c in ('ten9876', 'jensenpat', 'rfoust', 'NF0T', 'nigelfenton', 'K5PTB', 'Ozy311',
                                 'chibondking')}           # scored and shown, never eligible to win
# Not ranked. AetherClaude is the agent's GitHub user account (its PRs are
# opened under it as well as under the App); claude is the account commits
# co-authored by Claude are attributed to. Compared case-insensitively.
BOTS = {b.lower() for b in ('aethersdr-agent[bot]', 'aethersdr-agent', 'AetherClaude', 'claude',
                            'dependabot[bot]', 'dependabot', 'Copilot', 'copilot-pull-request-reviewer[bot]',
                            'github-actions[bot]')}
BREAK_WORKFLOWS = ('ci.yml', 'full-suite.yml')   # run on every push to main
INFRA_CAUSES = {'disk', 'oom', 'timeout', 'runner'}
CONFIRM_LABELS = {'bug', 'enhancement'}
SPAM_LABELS = {'spam'}          # -3, and no points for opening it
VOID_LABELS = {'invalid'}        # no points for opening it, no penalty
TRIVIAL_COMMENT = re.compile(r'^\W*(\+1|thanks?( you)?|thx|ty|lgtm|same( here)?|bump|me too)\W*$', re.I)
MIN_COMMENT_CHARS = 15              # a floor, not a scale

# rule -> (points, category). Categories drive the page's breakdown columns.
RULES = {
    'discussion_comment':  (1, 'comments'),
    'issue_comment':       (2, 'comments'),
    'pr_comment':          (3, 'comments'),
    'discussion_open':     (2, 'discussions'),
    'discussion_answer':   (4, 'discussions'),
    'issue_open':          (4, 'issues'),
    'issue_confirmed':     (2, 'issues'),
    'issue_fixed':         (5, 'issues'),
    'pr_open':             (5, 'prs'),
    'pr_merged':           (10, 'prs'),
    'pr_closes_issue':     (5, 'prs'),
    'pr_tests':            (2, 'prs'),
    'first_merged_pr':     (25, 'prs'),
    'review_approve':      (10, 'reviews'),
    'review_changes':      (8, 'reviews'),
    'review_comment':      (6, 'reviews'),
    'merge_other':         (10, 'merges'),
    # Stewardship: the necessary admin that keeps other people's work moving.
    'issue_triaged':       (2, 'stewardship'),
    'issue_closed':        (2, 'stewardship'),
    'pr_shepherd':         (4, 'stewardship'),
    'review_first_fast':   (3, 'stewardship'),
    'release_published':   (15, 'stewardship'),
    'main_fixed':          (15, 'main'),
    'revert_merged':       (3, 'main'),
    'break_approver':      (-60, 'penalties'),
    'break_author':        (-45, 'cpenalties'),  # contributor-side penalties
    'break_merger':        (-30, 'penalties'),
    'break_self_fix':      (15, 'main'),         # a fix credit, shown with main health
    'spam':                (-3, 'cpenalties'),
    # Financial support on Open Collective: points per US dollar given.
    'backer_contribution': (10, 'backer'),
}
BACKER_RULES = {'backer_contribution'}
PROFILES_PER_RUN = 150
PROFILE_MAX_AGE = timedelta(days=30)
BACKER_PEOPLE = {}   # login -> (kind, role, avatar, display_name) for donors without a GitHub login   # the Backer score; not contributor or steward points
OC_SLUG = 'aethersdr'
OC_API = 'https://api.opencollective.com/graphql/v2'
OC_MAP_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
                           'config', 'contributors', 'opencollective-map.json')
CAP_COMMENT_PER_THREAD_DAY = 1
CAP_OWN_PR_REPLIES = 2
CAP_COMMENTS_PER_DAY = 10
CAP_ISSUE_OPENS_PER_DAY = 4
CAP_ISSUE_CLOSES_PER_DAY = 15
FAST_REVIEW_WINDOW = timedelta(hours=24)
# Labels that are workflow plumbing, not triage judgement.
NON_TRIAGE_LABELS = {'claude-active', 'aetherclaude-eligible', 'full-suite', 'sanitizer', 'asan-ubsan', 'tsan'}
# Two separate scores, no overlap: steward points (reviewing, merging,
# triage, cleanup, shepherding, releases, and the approver and merger
# penalties) rank the steward of the week; everything else is contributor
# points and ranks the contributor of the week.
STEWARD_RULES = {'review_approve', 'review_changes', 'review_comment', 'merge_other', 'issue_triaged',
                 'issue_closed', 'pr_shepherd', 'review_first_fast', 'release_published',
                 'break_approver', 'break_merger'}
SELF_FIX_WINDOW = timedelta(hours=24)


# ── GitHub access ────────────────────────────────────────────────────────
class GH:
    def __init__(self, token, proxy=None, max_per_hour=1000, db=None):
        self.db = db
        self.not_modified = 0
        self.proxy = urllib.request.ProxyHandler({'https': proxy} if proxy else {})
        self.opener = urllib.request.build_opener(self.proxy)
        self.hdrs = {'Authorization': f'token {token}', 'Accept': 'application/vnd.github+json',
                     'User-Agent': 'AetherClaude-Contributors'}
        self.min_gap = 3600.0 / max_per_hour   # leave the agent its share of the budget
        self.last = 0.0
        self.calls = 0

    def _open(self, req, timeout=30):
        wait = self.min_gap - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.last = time.time()
        self.calls += 1
        return self.opener.open(req, timeout=timeout)

    def get(self, path):
        url = path if path.startswith('https://') else f'https://api.github.com/{path}'
        # Fixed URLs (a PR, its reviews, its files, the releases) are cached
        # with their ETag; `since=` feeds and searches change every run.
        cacheable = self.db is not None and not any(k in url for k in ('since=', 'created=', '/search/'))
        hdrs = dict(self.hdrs)
        cached = None
        if cacheable:
            cached = self.db.execute('SELECT etag, body, link FROM http_cache WHERE url=?', (url,)).fetchone()
            if cached and cached[0]:
                hdrs['If-None-Match'] = cached[0]
        try:
            with self._open(urllib.request.Request(url, headers=hdrs)) as r:
                text = r.read().decode()
                link = r.headers.get('Link') or ''
                etag = r.headers.get('ETag')
            if cacheable and etag:
                self.db.execute('INSERT OR REPLACE INTO http_cache VALUES(?,?,?,?,?)',
                                (url, etag, text, link, datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')))
            body = json.loads(text)
        except urllib.error.HTTPError as e:
            if e.code != 304 or not cached:
                raise
            self.not_modified += 1
            body, link = json.loads(cached[1]), cached[2] or ''
        nxt = re.search(r'<([^>]+)>;\s*rel="next"', link)
        return body, (nxt.group(1) if nxt else None)

    def pages(self, path, stop=None):
        url = path
        while url:
            body, url = self.get(url)
            items = body if isinstance(body, list) else next(
                (body[k] for k in ('items', 'workflow_runs', 'jobs', 'actions_caches') if k in body), [])
            for it in items:
                if stop and stop(it):
                    return
                yield it

    def graphql(self, query, variables):
        data = json.dumps({'query': query, 'variables': variables}).encode()
        req = urllib.request.Request('https://api.github.com/graphql', data=data, headers=self.hdrs)
        with self._open(req) as r:
            out = json.loads(r.read().decode())
        if out.get('errors'):
            raise RuntimeError(out['errors'])
        return out['data']

    def job_log(self, job_id):
        """Job log text; the API redirects to a pre-signed storage URL that
        must be fetched without the GitHub Authorization header."""
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        url = f'https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs'
        op = urllib.request.build_opener(urllib.request.ProxyHandler(self.proxy.proxies), NoRedirect())
        wait = self.min_gap - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)   # the same throttle as every other API call
        self.last = time.time()
        try:
            self.calls += 1
            op.open(urllib.request.Request(url, headers=self.hdrs), timeout=30)
            return ''
        except urllib.error.HTTPError as e:
            loc = e.headers.get('Location')
            if not loc:
                return ''
        with self.opener.open(urllib.request.Request(loc, headers={'User-Agent': 'AetherClaude-Contributors'}),
                              timeout=60) as r:
            return r.read(24 * 1024 * 1024).decode('utf-8', 'replace')


# ── Storage ──────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS people(login TEXT PRIMARY KEY, kind TEXT, role TEXT, avatar TEXT);
CREATE TABLE IF NOT EXISTS items(type TEXT, number INTEGER, author TEXT, created_at TEXT,
  closed_at TEXT, state_reason TEXT, labels TEXT, title TEXT,
  merged_at TEXT, merged_by TEXT, head_sha TEXT, merge_sha TEXT,
  closes TEXT, touches_tests INTEGER, PRIMARY KEY(type, number));
CREATE TABLE IF NOT EXISTS comments(id TEXT PRIMARY KEY, type TEXT, number INTEGER,
  login TEXT, created_at TEXT, substantive INTEGER);
CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, pr INTEGER, login TEXT, state TEXT,
  commit_id TEXT, submitted_at TEXT);
CREATE TABLE IF NOT EXISTS labels(number INTEGER, label TEXT, actor TEXT, at TEXT,
  PRIMARY KEY(number, label, at));
CREATE TABLE IF NOT EXISTS answers(number INTEGER PRIMARY KEY, login TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS releases(tag TEXT PRIMARY KEY, published_at TEXT, prerelease INTEGER);
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, workflow TEXT, sha TEXT, created_at TEXT,
  conclusion TEXT, url TEXT, cause TEXT);
CREATE TABLE IF NOT EXISTS first_merges(login TEXT PRIMARY KEY, number INTEGER, merged_at TEXT);
CREATE TABLE IF NOT EXISTS state(name TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS review_comments(id INTEGER PRIMARY KEY, pr INTEGER, review_id INTEGER,
  login TEXT, in_reply_to INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS closes(id INTEGER PRIMARY KEY, number INTEGER, actor TEXT, at TEXT,
  state_reason TEXT, commit_id TEXT);
CREATE TABLE IF NOT EXISTS pr_commits(pr INTEGER, sha TEXT, author TEXT, committer TEXT, at TEXT,
  PRIMARY KEY(pr, sha));
CREATE TABLE IF NOT EXISTS ci_logs(job_id INTEGER PRIMARY KEY, run_id INTEGER, workflow TEXT, branch TEXT,
  event TEXT, sha TEXT, job_name TEXT, conclusion TEXT, created_at TEXT, cause TEXT, failed_tests TEXT,
  log_bytes INTEGER, log BLOB);
CREATE TABLE IF NOT EXISTS webhook_events(delivery TEXT PRIMARY KEY, event TEXT, action TEXT,
  received_at TEXT, payload TEXT, applied INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS profiles(login TEXT PRIMARY KEY, name TEXT, bio TEXT, location TEXT, blog TEXT,
  created_at TEXT, fetched_at TEXT, raw TEXT);
CREATE TABLE IF NOT EXISTS oc_contributions(id TEXT PRIMARY KEY, created_at TEXT, amount_cents INTEGER,
  currency TEXT, from_slug TEXT, from_name TEXT, from_type TEXT, from_image TEXT, refunded INTEGER, raw TEXT);
CREATE TABLE IF NOT EXISTS codeowners(tier INTEGER, login TEXT, team TEXT, first_seen TEXT, last_seen TEXT,
  PRIMARY KEY(tier, login));
CREATE TABLE IF NOT EXISTS http_cache(url TEXT PRIMARY KEY, etag TEXT, body TEXT, link TEXT, fetched_at TEXT);
"""
# Columns added after the first schema; applied to existing databases.
MIGRATIONS = [
    'ALTER TABLE items ADD COLUMN updated_at TEXT',   # from the issues feed
    'ALTER TABLE items ADD COLUMN detail_at TEXT',    # when PR details were last fetched
    'ALTER TABLE reviews ADD COLUMN body_len INTEGER',  # summary text present (0 = none)
    'ALTER TABLE items ADD COLUMN reviews_v INTEGER',   # review data version stored for this PR
    'ALTER TABLE runs ADD COLUMN sig TEXT',             # failure signature: failing tests / errors
    'ALTER TABLE releases ADD COLUMN author TEXT',      # who published it
    'ALTER TABLE items ADD COLUMN commits_v INTEGER',   # PR commits stored (shepherding)
    # Raw text kept for analysis (patterns, regressions, bugs), not scoring.
    'ALTER TABLE items ADD COLUMN body TEXT',
    'ALTER TABLE comments ADD COLUMN body TEXT',
    'ALTER TABLE reviews ADD COLUMN body TEXT',
    'ALTER TABLE review_comments ADD COLUMN body TEXT',
    'ALTER TABLE review_comments ADD COLUMN path TEXT',
    'ALTER TABLE review_comments ADD COLUMN line INTEGER',
    'ALTER TABLE items ADD COLUMN webhook_at TEXT',     # PR state last delivered by a webhook
    'ALTER TABLE people ADD COLUMN display_name TEXT',  # for people without a GitHub login (backers)
    'ALTER TABLE items ADD COLUMN base TEXT',           # the branch a PR targets
]
BODIES_V = 1    # 1 = item, comment, review and discussion bodies stored
LOGS_V = 1      # 1 = failed-job logs kept back to GitHub's 90-day retention
# Webhooks keep the data live between collections; the collector trusts them
# for PR state, except once a day when it re-checks every changed PR.
FULL_RECONCILE_EVERY = timedelta(hours=24)
LOG_RETENTION = timedelta(days=90)   # GitHub keeps Actions logs this long
# Failed-job logs are kept for every workflow, on any branch.
LOG_WORKFLOWS = ('ci.yml', 'full-suite.yml', 'codeql.yml', 'sanitizers.yml', 'system-libs-canary.yml',
                 'static-checks.yml')
BACKUP_DIR = os.path.join(os.path.dirname(DB_PATH), 'backups')
BACKUP_KEEP = 7
EVENTS_V = 2    # 2 = issue events include closes (1 = labels only)
REVIEWS_V = 2   # 2 = reviews with body_len + inline review comments


def db_open(path):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    c = sqlite3.connect(path, timeout=30)   # the dashboard writes webhooks concurrently
    c.execute('PRAGMA journal_mode=WAL')
    c.executescript(SCHEMA)
    for m in MIGRATIONS:
        try:
            c.execute(m)
        except sqlite3.OperationalError:
            pass   # already applied
    c.commit()
    return c


def get_state(db, name, default=None):
    row = db.execute('SELECT value FROM state WHERE name=?', (name,)).fetchone()
    return row[0] if row else default


def set_state(db, name, value):
    db.execute('INSERT OR REPLACE INTO state VALUES(?,?)', (name, value))


def role_of(login, user_type=None):
    if not login:
        return 'ghost'
    if user_type == 'Bot' or login.lower() in BOTS or login.endswith('[bot]'):
        return 'bot'
    return 'maintainer' if login in MAINTAINERS else 'contributor'


def collect_reviews(gh, db, n):
    """A PR's reviews plus its inline review comments. GitHub stores each
    reply in an inline thread as its own review object, so the scorer needs
    the inline comments to tell a new review from a thread reply."""
    for rv in gh.pages(f'repos/{REPO}/pulls/{n}/reviews?per_page=100'):
        note_person(db, rv.get('user'))
        db.execute('INSERT OR REPLACE INTO reviews(id,pr,login,state,commit_id,submitted_at,body_len,body)'
                   ' VALUES(?,?,?,?,?,?,?,?)',
                   (rv['id'], n, (rv.get('user') or {}).get('login'), rv['state'],
                    rv.get('commit_id'), rv.get('submitted_at'), len((rv.get('body') or '').strip()), rv.get('body')))
    for c in gh.pages(f'repos/{REPO}/pulls/{n}/comments?per_page=100'):
        store_review_comment(db, n, c)
    db.execute('UPDATE items SET reviews_v=? WHERE type="pr" AND number=?', (REVIEWS_V, n))


def store_review_comment(db, pr, c):
    db.execute('INSERT OR REPLACE INTO review_comments(id,pr,review_id,login,in_reply_to,created_at,body,path,line)'
               ' VALUES(?,?,?,?,?,?,?,?,?)',
               (c['id'], pr, c.get('pull_request_review_id'), (c.get('user') or {}).get('login'),
                c.get('in_reply_to_id'), c.get('created_at'), c.get('body'), c.get('path'),
                c.get('line') or c.get('original_line')))


def store_ci_log(db, run, job, log, dg=None, tests=None):
    """Keep a failed job's log (zlib-compressed) with its context: GitHub
    deletes Actions logs after 90 days, so this is the only lasting copy."""
    raw = (log or '').encode('utf-8', 'replace')
    if dg is None:
        dg = ci_diagnose._diagnose_log_clean(log) or {}
    if tests is None:
        tests = ci_diagnose.failed_tests_from_log(log)
    db.execute('INSERT OR REPLACE INTO ci_logs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (job['id'], run['id'], (run.get('path') or '').rsplit('/', 1)[-1] or run.get('name'),
                run.get('head_branch'), run.get('event'), run.get('head_sha'), job.get('name'),
                job.get('conclusion'), job.get('completed_at') or run.get('created_at'),
                dg.get('kind'), json.dumps(tests), len(raw), zlib.compress(raw, 9)))


def fill_from_cache(db):
    """One-off: copy review, inline-comment and PR bodies out of responses
    already in http_cache, so stored history gains its text without calls."""
    n = 0
    for url, body in db.execute("SELECT url, body FROM http_cache WHERE url LIKE '%/pulls/%'").fetchall():
        m = re.search(r'/pulls/(\d+)(/reviews|/comments)?(?:\?|$)', url)
        if not m:
            continue
        pr, kind = int(m.group(1)), m.group(2)
        try:
            data = json.loads(body)
        except ValueError:
            continue
        if kind == '/reviews':
            for rv in data:
                db.execute('UPDATE reviews SET body=? WHERE id=?', (rv.get('body'), rv['id']))
                n += 1
        elif kind == '/comments':
            for c in data:
                store_review_comment(db, pr, c)
                n += 1
        elif isinstance(data, dict) and data.get('number') == pr:
            db.execute('UPDATE items SET body=? WHERE type="pr" AND number=?', (data.get('body'), pr))
            n += 1
    db.commit()
    return n


def backup(db_path=None):
    """Daily compressed copy of the database (SQLite online backup, so safe
    while the collector writes), keeping the newest BACKUP_KEEP."""
    db_path = db_path or DB_PATH
    os.makedirs(BACKUP_DIR, exist_ok=True)
    day = datetime.now(timezone.utc).strftime('%Y%m%d')
    dest = os.path.join(BACKUP_DIR, f'contributors-{day}.db.gz')
    if os.path.exists(dest):
        return None
    tmp = os.path.join(BACKUP_DIR, f'.contributors-{day}.db')
    src = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    dst = sqlite3.connect(tmp)
    src.backup(dst)
    dst.close()
    src.close()
    with open(tmp, 'rb') as f, gzip.open(dest + '.part', 'wb', compresslevel=6) as g:
        shutil.copyfileobj(f, g, 1 << 20)
    os.replace(dest + '.part', dest)
    os.remove(tmp)
    for old in sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith('contributors-') and f.endswith('.db.gz'))[:-BACKUP_KEEP]:
        os.remove(os.path.join(BACKUP_DIR, old))
    return dest


def _upsert_issue_like(db, t, obj, extra=None):
    """Upsert an issue or PR row from a webhook object (same columns as the
    issues feed, plus PR state when present)."""
    db.execute('INSERT INTO items(type,number,author,created_at,closed_at,state_reason,labels,title,updated_at,body)'
               ' VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(type,number) DO UPDATE SET author=excluded.author,'
               ' closed_at=excluded.closed_at, state_reason=excluded.state_reason, labels=excluded.labels,'
               ' title=excluded.title, updated_at=excluded.updated_at, body=excluded.body',
               (t, obj['number'], (obj.get('user') or {}).get('login'), obj.get('created_at'), obj.get('closed_at'),
                obj.get('state_reason'), json.dumps([l['name'] for l in obj.get('labels') or []]),
                (obj.get('title') or '')[:200], obj.get('updated_at'), obj.get('body')))
    if extra:
        db.execute('UPDATE items SET ' + ', '.join(f'{k}=?' for k in extra) + ' WHERE type=? AND number=?',
                   (*extra.values(), t, obj['number']))


def apply_webhook(db, event, payload):
    """Apply one verified webhook payload to the fact tables. Idempotent: a
    later REST collection of the same objects writes the same rows. Label
    and close history still come from the issue-events feed, which carries
    event ids; CI runs and logs from the Actions API."""
    if ((payload.get('repository') or {}).get('full_name') or '').lower() != REPO.lower():
        return False
    note_person(db, payload.get('sender'))
    action = payload.get('action')
    if event == 'issues' and payload.get('issue'):
        note_person(db, payload['issue'].get('user'))
        _upsert_issue_like(db, 'issue', payload['issue'])
    elif event == 'issue_comment' and payload.get('comment'):
        iss, c = payload['issue'], payload['comment']
        t = 'pr' if 'pull_request' in iss else 'issue'   # key present on PR comments, like the REST feed
        note_person(db, c.get('user'))
        _upsert_issue_like(db, t, iss)
        if action == 'deleted':
            db.execute('DELETE FROM comments WHERE id=?', (f"ic{c['id']}",))
        else:
            db.execute('INSERT OR REPLACE INTO comments(id,type,number,login,created_at,substantive,body)'
                       ' VALUES(?,?,?,?,?,?,?)',
                       (f"ic{c['id']}", t, iss['number'], (c.get('user') or {}).get('login'), c.get('created_at'),
                        substantive(c.get('body')), c.get('body')))
    elif event in ('pull_request', 'pull_request_review', 'pull_request_review_comment') and payload.get('pull_request'):
        pr = payload['pull_request']
        note_person(db, pr.get('user'))
        note_person(db, pr.get('merged_by'))
        extra = {'webhook_at': pr.get('updated_at'), 'base': (pr.get('base') or {}).get('ref')}
        if event == 'pull_request':
            # The full PR object: its state is current as of this delivery.
            extra.update(merged_at=pr.get('merged_at'), merged_by=(pr.get('merged_by') or {}).get('login'),
                         head_sha=(pr.get('head') or {}).get('sha'), merge_sha=pr.get('merge_commit_sha'))
        _upsert_issue_like(db, 'pr', pr, extra)
        if event == 'pull_request_review' and payload.get('review'):
            rv = payload['review']
            note_person(db, rv.get('user'))
            db.execute('INSERT OR REPLACE INTO reviews(id,pr,login,state,commit_id,submitted_at,body_len,body)'
                       ' VALUES(?,?,?,?,?,?,?,?)',
                       (rv['id'], pr['number'], (rv.get('user') or {}).get('login'), (rv.get('state') or '').upper(),
                        rv.get('commit_id'), rv.get('submitted_at'), len((rv.get('body') or '').strip()), rv.get('body')))
        elif event == 'pull_request_review_comment' and payload.get('comment'):
            if action == 'deleted':
                db.execute('DELETE FROM review_comments WHERE id=?', (payload['comment']['id'],))
            else:
                store_review_comment(db, pr['number'], payload['comment'])
    elif event in ('discussion', 'discussion_comment') and payload.get('discussion'):
        d = payload['discussion']
        note_person(db, d.get('user'))
        db.execute('INSERT INTO items(type,number,author,created_at,title,updated_at,body) VALUES("discussion",?,?,?,?,?,?)'
                   ' ON CONFLICT(type,number) DO UPDATE SET title=excluded.title, updated_at=excluded.updated_at,'
                   ' body=excluded.body',
                   (d['number'], (d.get('user') or {}).get('login'), d.get('created_at'), (d.get('title') or '')[:200],
                    d.get('updated_at'), d.get('body')))
        if event == 'discussion' and action == 'answered' and payload.get('answer'):
            db.execute('INSERT OR REPLACE INTO answers VALUES(?,?,?)',
                       (d['number'], (payload['answer'].get('user') or {}).get('login'),
                        d.get('answer_chosen_at') or payload['answer'].get('updated_at')))
        elif event == 'discussion' and action == 'unanswered':
            db.execute('DELETE FROM answers WHERE number=?', (d['number'],))
        elif event == 'discussion_comment' and payload.get('comment'):
            c = payload['comment']
            note_person(db, c.get('user'))
            cid = f"dc{c.get('node_id')}"
            if action == 'deleted':
                db.execute('DELETE FROM comments WHERE id=?', (cid,))
            else:
                db.execute('INSERT OR REPLACE INTO comments(id,type,number,login,created_at,substantive,body)'
                           ' VALUES(?,?,?,?,?,?,?)',
                           (cid, 'discussion', d['number'], (c.get('user') or {}).get('login'), c.get('created_at'),
                            substantive(c.get('body')), c.get('body')))
    elif event == 'release' and payload.get('release'):
        r = payload['release']
        if action == 'deleted':
            db.execute('DELETE FROM releases WHERE tag=?', (r['tag_name'],))
        else:
            db.execute('INSERT OR REPLACE INTO releases(tag,published_at,prerelease,author) VALUES(?,?,?,?)',
                       (r['tag_name'], r.get('published_at'), int(bool(r.get('prerelease'))),
                        (r.get('author') or {}).get('login')))
    return True


def record_webhook(db, delivery, event, body):
    """Store a verified webhook's raw payload and apply it. Returns True if
    it was new. The raw payload is kept whether or not it maps to a table."""
    payload = json.loads(body)
    cur = db.execute('INSERT OR IGNORE INTO webhook_events(delivery,event,action,received_at,payload)'
                     ' VALUES(?,?,?,?,?)',
                     (delivery, event, payload.get('action'), datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                      body if isinstance(body, str) else body.decode('utf-8', 'replace')))
    if not cur.rowcount:
        return False   # a redelivery we already have
    apply_webhook(db, event, payload)
    db.execute('UPDATE webhook_events SET applied=1 WHERE delivery=?', (delivery,))
    db.commit()
    return True


def collect_open_collective(db, proxy_handler=None):
    """Every contribution to the Open Collective, stored with the raw record.
    Public data, no token; the whole history is a page or two."""
    opener = urllib.request.build_opener(*( [urllib.request.ProxyHandler(proxy_handler.proxies)] if proxy_handler else []))
    query = ('query($slug:String!,$offset:Int!){account(slug:$slug){transactions(type:CREDIT,kind:[CONTRIBUTION],'
             'limit:100,offset:$offset){totalCount nodes{id createdAt amount{valueInCents currency} isRefunded '
             'fromAccount{slug name type imageUrl githubHandle}}}}}')
    offset, n = 0, 0
    while True:
        req = urllib.request.Request(OC_API, data=json.dumps({'query': query, 'variables': {'slug': OC_SLUG, 'offset': offset}}).encode(),
                                     headers={'Content-Type': 'application/json', 'User-Agent': 'AetherClaude-Contributors'})
        with opener.open(req, timeout=30) as r:
            tx = json.loads(r.read().decode())['data']['account']['transactions']
        for t in tx['nodes']:
            a = t.get('fromAccount') or {}
            db.execute('INSERT OR REPLACE INTO oc_contributions VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (t['id'], t['createdAt'], t['amount']['valueInCents'], t['amount']['currency'], a.get('slug'),
                        a.get('name'), a.get('type'), a.get('imageUrl'), int(bool(t.get('isRefunded'))), json.dumps(t)))
            n += 1
        offset += len(tx['nodes'])
        if not tx['nodes'] or offset >= tx['totalCount']:
            break
    db.commit()
    return n


def _oc_identity(db, slug, name, github, oc_map):
    """The leaderboard identity for an Open Collective donor: a GitHub login
    from the mapping file (or the donor's own linked handle), else one row per
    donor name (callsign), so the same person giving as several guests is
    merged. Unnamed guests stay separate."""
    login = oc_map.get((slug or '').lower()) or oc_map.get((name or '').strip().lower()) or github
    if login:
        return login, None
    nm = (name or '').strip()
    if not nm or nm.lower() in ('guest', 'incognito', 'anonymous'):
        return f'oc:{slug}', nm or 'Anonymous backer'
    return 'oc:' + re.sub(r'\s+', '-', nm.lower()), nm


def note_person(db, user):
    if not user or not user.get('login'):
        return
    db.execute('INSERT OR IGNORE INTO people(login,kind,role,avatar) VALUES(?,?,?,?)',
               (user['login'], user.get('type', 'User'), role_of(user['login'], user.get('type')),
                user.get('avatar_url', '')))


def substantive(body):
    b = (body or '').strip()
    return int(len(b) >= MIN_COMMENT_CHARS and not TRIVIAL_COMMENT.match(b))


# ── Collection ───────────────────────────────────────────────────────────
CODEOWNER_TEAMS = {1: 'maintainers', 2: 'infrastructure', 3: 'reviewers'}   # CODEOWNERS tiers


def collect_codeowners(gh, db):
    """Who is in each CODEOWNERS tier: the org teams when this token can read
    them, else the rosters the CODEOWNERS file lists ("currently: @a, @b")."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    tiers = {}
    try:
        for tier, team in CODEOWNER_TEAMS.items():
            tiers[tier] = [m['login'] for m in gh.pages(f'orgs/{OWNER}/teams/{team}/members?per_page=100')]
    except urllib.error.HTTPError:
        tiers = {}
        try:
            d, _ = gh.get(f'repos/{REPO}/contents/.github/CODEOWNERS')
            text = base64.b64decode(d['content']).decode()
        except (urllib.error.HTTPError, KeyError, ValueError):
            return
        comments = ' '.join(l.lstrip('#').strip() for l in text.splitlines() if l.startswith('#'))
        for tier, team, names in re.findall(r'Tier (\d) \S+ @[\w-]+/([\w-]+) \(currently: ([^)]*)\)', comments):
            tiers[int(tier)] = re.findall(r'@([\w-]+)', names)
    for tier, logins in tiers.items():
        for login in logins:
            db.execute('INSERT INTO codeowners VALUES(?,?,?,?,?) ON CONFLICT(tier, login) DO UPDATE SET'
                       ' last_seen=excluded.last_seen', (tier, login, CODEOWNER_TEAMS.get(tier), now, now))
    db.commit()


def collect(gh, db, since):
    q = urllib.parse.quote
    run_start = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    # Webhooks the dashboard stored but could not apply (e.g. it restarted).
    pending = db.execute('SELECT delivery, event, payload FROM webhook_events WHERE applied=0').fetchall()
    for delivery, event, payload in pending:
        try:
            apply_webhook(db, event, json.loads(payload))
        except Exception as e:
            print(f'  webhook {delivery} ({event}) not applied: {str(e)[:80]}', file=sys.stderr)
        db.execute('UPDATE webhook_events SET applied=1 WHERE delivery=?', (delivery,))
    db.commit()
    if pending:
        print(f'  applied {len(pending)} stored webhooks', file=sys.stderr, flush=True)
    last_full = get_state(db, 'full_reconcile_at')
    full = not last_full or (datetime.now(timezone.utc) -
                             datetime.fromisoformat(last_full.replace('Z', '+00:00'))) >= FULL_RECONCILE_EVERY
    # Databases from before bodies were stored re-read the item and comment
    # feeds once from the start, and copy what the cache already holds.
    text_since = since if int(get_state(db, 'bodies_v', '0')) >= BODIES_V else REPO_START
    if text_since != since:
        print(f'  copied {fill_from_cache(db)} bodies from cached responses', file=sys.stderr, flush=True)
    # Releases: the weekly windows run between non-prerelease v-tags.
    for r in gh.pages(f'repos/{REPO}/releases?per_page=100'):
        db.execute('INSERT OR REPLACE INTO releases(tag,published_at,prerelease,author) VALUES(?,?,?,?)',
                   (r['tag_name'], r.get('published_at'), int(bool(r.get('prerelease'))),
                    (r.get('author') or {}).get('login')))

    # Issues and PRs (one feed), updated since the cursor.
    prs = []
    for it in gh.pages(f'repos/{REPO}/issues?state=all&sort=updated&direction=desc&per_page=100&since={q(text_since)}'):
        note_person(db, it.get('user'))
        is_pr = 'pull_request' in it
        t = 'pr' if is_pr else 'issue'
        # Upsert the feed's columns only; PR details stay as fetched.
        db.execute('INSERT INTO items(type,number,author,created_at,closed_at,state_reason,labels,title,updated_at,body)'
                   ' VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(type,number) DO UPDATE SET author=excluded.author,'
                   ' closed_at=excluded.closed_at, state_reason=excluded.state_reason, labels=excluded.labels,'
                   ' title=excluded.title, updated_at=excluded.updated_at, body=excluded.body',
                   (t, it['number'], (it.get('user') or {}).get('login'), it['created_at'], it.get('closed_at'),
                    it.get('state_reason'), json.dumps([l['name'] for l in it.get('labels') or []]),
                    (it.get('title') or '')[:200], it.get('updated_at'), it.get('body')))
        if is_pr:
            det = db.execute('SELECT detail_at, webhook_at, merged_at, closes FROM items WHERE type="pr" AND number=?',
                             (it['number'],)).fetchone()
            upd = it.get('updated_at') or ''
            stale = not det or not det[0] or upd > det[0]
            # A webhook already delivered this PR's latest state: skip the
            # refetch, except on the daily full reconcile (a missed webhook
            # can't leave a gap for more than a day) and for a merged PR whose
            # linked issues and tests (REST only) aren't recorded yet.
            needs_merge_detail = det and det[2] and det[3] is None
            covered = det and det[1] and det[1] >= upd and not full and not needs_merge_detail
            if stale and not covered:
                prs.append(it['number'])
    db.commit()
    print(f'  {len(prs)} PRs changed since their details were fetched', file=sys.stderr)

    # PR details: merger, head, linked issues, tests touched, reviews.
    for i, n in enumerate(prs):
        p, _ = gh.get(f'repos/{REPO}/pulls/{n}')
        note_person(db, p.get('merged_by'))
        closes, tests = [], 0
        had = db.execute('SELECT merged_by, closes, touches_tests FROM items WHERE type="pr" AND number=?', (n,)).fetchone()
        if p.get('merged_at') and had and had[0] and had[1] is not None:
            closes, tests = json.loads(had[1]), had[2] or 0   # fixed at merge; never refetched
        elif p.get('merged_at'):
            d = gh.graphql('query($o:String!,$r:String!,$n:Int!){repository(owner:$o,name:$r){pullRequest(number:$n)'
                           '{closingIssuesReferences(first:20){nodes{number}}}}}', {'o': OWNER, 'r': NAME, 'n': n})
            closes = [x['number'] for x in d['repository']['pullRequest']['closingIssuesReferences']['nodes']]
            tests = int(any(f['filename'].startswith('tests/') for f in gh.pages(f'repos/{REPO}/pulls/{n}/files?per_page=100')))
        db.execute('UPDATE items SET merged_at=?, merged_by=?, head_sha=?, merge_sha=?, closes=?, touches_tests=?,'
                   ' base=? WHERE type="pr" AND number=?',
                   (p.get('merged_at'), (p.get('merged_by') or {}).get('login'), p['head']['sha'],
                    p.get('merge_commit_sha'), json.dumps(closes), tests, (p.get('base') or {}).get('ref'), n))
        collect_reviews(gh, db, n)
        db.execute('UPDATE items SET detail_at=? WHERE type="pr" AND number=?', (run_start, n))
        if i % 25 == 24:
            db.commit()   # resumable: a restart skips PRs already done
        if i % 100 == 99:
            print(f'  PR details {i + 1}/{len(prs)} ({gh.calls} calls)', file=sys.stderr, flush=True)
    db.commit()

    # PRs whose stored reviews predate the current review data version get
    # their reviews and inline comments refreshed (no other PR calls).
    stale = [n for (n,) in db.execute('SELECT number FROM items WHERE type="pr" AND detail_at IS NOT NULL'
                                      ' AND IFNULL(reviews_v,0)<?', (REVIEWS_V,))]
    if stale:
        print(f'  refreshing review data for {len(stale)} PRs', file=sys.stderr)
    for i, n in enumerate(stale):
        collect_reviews(gh, db, n)
        if i % 25 == 24:
            db.commit()
    db.commit()

    # Commits on merged PRs: who besides the author pushed to them
    # (shepherding). Fetched once per PR, after its merge.
    todo = [n for (n,) in db.execute('SELECT number FROM items WHERE type="pr" AND merged_at IS NOT NULL'
                                     ' AND IFNULL(commits_v,0)<1')]
    if todo:
        print(f'  fetching commits for {len(todo)} merged PRs', file=sys.stderr, flush=True)
    for i, n in enumerate(todo):
        for c in gh.pages(f'repos/{REPO}/pulls/{n}/commits?per_page=100'):
            db.execute('INSERT OR REPLACE INTO pr_commits VALUES(?,?,?,?,?)',
                       (n, c['sha'], (c.get('author') or {}).get('login'), (c.get('committer') or {}).get('login'),
                        ((c.get('commit') or {}).get('author') or {}).get('date')))
        db.execute('UPDATE items SET commits_v=1 WHERE type="pr" AND number=?', (n,))
        if i % 25 == 24:
            db.commit()
        if i % 200 == 199:
            print(f'  PR commits {i + 1}/{len(todo)} ({gh.calls} calls)', file=sys.stderr, flush=True)
    db.commit()

    print(f'  step: issue and pr conversation comments ({gh.calls} calls)', file=sys.stderr, flush=True)
    # Issue and PR conversation comments (inline review comments are part of
    # the review and are not fetched).
    types = dict(db.execute('SELECT number, type FROM items'))
    for c in gh.pages(f'repos/{REPO}/issues/comments?sort=created&direction=asc&per_page=100&since={q(text_since)}'):
        note_person(db, c.get('user'))
        n = int(c['issue_url'].rsplit('/', 1)[1])
        db.execute('INSERT OR REPLACE INTO comments(id,type,number,login,created_at,substantive,body) VALUES(?,?,?,?,?,?,?)',
                   (f"ic{c['id']}", types.get(n, 'issue'), n, (c.get('user') or {}).get('login'),
                    c['created_at'], substantive(c.get('body')), c.get('body')))

    print(f'  step: label events ({gh.calls} calls)', file=sys.stderr, flush=True)
    # Issue events: labels (triage, confirmation, spam) and closes (cleanup).
    # Databases collected before closes were stored re-read the whole feed once.
    ev_since = since if int(get_state(db, 'events_v', '1')) >= EVENTS_V else REPO_START
    for ev in gh.pages(f'repos/{REPO}/issues/events?per_page=100',
                       stop=lambda e: e['created_at'] < ev_since):
        num = (ev.get('issue') or {}).get('number')
        actor = (ev.get('actor') or {}).get('login')
        if ev.get('event') == 'labeled' and ev.get('label'):
            db.execute('INSERT OR IGNORE INTO labels VALUES(?,?,?,?)', (num, ev['label']['name'], actor, ev['created_at']))
        elif ev.get('event') == 'closed':
            db.execute('INSERT OR IGNORE INTO closes VALUES(?,?,?,?,?,?)',
                       (ev['id'], num, actor, ev['created_at'], ev.get('state_reason'), ev.get('commit_id')))
    set_state(db, 'events_v', str(EVENTS_V))
    db.commit()

    print(f'  step: discussions ({gh.calls} calls)', file=sys.stderr, flush=True)
    # Discussions (GraphQL only): open, comments, replies, accepted answers.
    cursor = None
    while True:
        d = gh.graphql('query($o:String!,$r:String!,$c:String){repository(owner:$o,name:$r){discussions(first:25,after:$c,'
                       'orderBy:{field:UPDATED_AT,direction:DESC}){pageInfo{hasNextPage endCursor} nodes{number updatedAt '
                       'createdAt title bodyText author{login avatarUrl __typename} answer{author{login}} answerChosenAt '
                       'comments(first:50){nodes{id createdAt bodyText author{login avatarUrl __typename} '
                       'replies(first:50){nodes{id createdAt bodyText author{login avatarUrl __typename}}}}}}}}}',
                       {'o': OWNER, 'r': NAME, 'c': cursor})['repository']['discussions']
        done = False
        for x in d['nodes']:
            if x['updatedAt'] < text_since:
                done = True
                break
            a = x.get('author') or {}
            note_person(db, {'login': a.get('login'), 'type': a.get('__typename'), 'avatar_url': a.get('avatarUrl')})
            db.execute('INSERT INTO items(type,number,author,created_at,title,updated_at,body) VALUES("discussion",?,?,?,?,?,?)'
                       ' ON CONFLICT(type,number) DO UPDATE SET title=excluded.title, updated_at=excluded.updated_at,'
                       ' body=excluded.body',
                       (x['number'], a.get('login'), x['createdAt'], (x.get('title') or '')[:200], x['updatedAt'],
                        x.get('bodyText')))
            if x.get('answer') and x.get('answerChosenAt'):
                db.execute('INSERT OR REPLACE INTO answers VALUES(?,?,?)',
                           (x['number'], x['answer']['author']['login'], x['answerChosenAt']))
            for c in x['comments']['nodes']:
                for node in [c] + c['replies']['nodes']:
                    ca = node.get('author') or {}
                    note_person(db, {'login': ca.get('login'), 'type': ca.get('__typename'),
                                     'avatar_url': ca.get('avatarUrl')})
                    db.execute('INSERT OR REPLACE INTO comments(id,type,number,login,created_at,substantive,body)'
                               ' VALUES(?,?,?,?,?,?,?)',
                               (f"dc{node['id']}", 'discussion', x['number'], ca.get('login'),
                                node['createdAt'], substantive(node.get('bodyText')), node.get('bodyText')))
        if done or not d['pageInfo']['hasNextPage']:
            break
        cursor = d['pageInfo']['endCursor']

    print(f'  step: main-branch ci verdicts ({gh.calls} calls)', file=sys.stderr, flush=True)
    # Main-branch CI verdicts (the break detector), with the cause of each
    # failure so infrastructure failures can be excluded.
    # The runs API returns at most 1,000 runs per query, so long ranges are
    # fetched a month at a time.
    start = datetime.fromisoformat(since.replace('Z', '+00:00')) - timedelta(days=2)
    now = datetime.now(timezone.utc)
    spans = []
    while start < now:
        end = min(start + timedelta(days=30), now + timedelta(days=1))
        spans.append(f"{start.strftime('%Y-%m-%dT%H:%M:%SZ')}..{end.strftime('%Y-%m-%dT%H:%M:%SZ')}")
        start = end

    def month_runs(wf):
        for span in spans:
            yield from gh.pages(f'repos/{REPO}/actions/workflows/{wf}/runs?branch=main&event=push&per_page=100'
                                f'&created={q(span)}')
    for wf in BREAK_WORKFLOWS:
        for r in month_runs(wf):
            if r.get('status') != 'completed':
                continue
            known = db.execute('SELECT cause, sig FROM runs WHERE id=?', (r['id'],)).fetchone()
            cause, sig = known if known else (None, None)
            if r['conclusion'] == 'failure' and sig is None:
                # Cause (first non-infrastructure one) and the failure
                # signature: the failing tests, else the failing file or kind.
                # A later run in a red stretch is a new break only if its
                # signature has something the stretch has not had yet.
                cause, elems = 'unknown', set()
                for j in gh.pages(f"repos/{REPO}/actions/runs/{r['id']}/jobs?per_page=100"):
                    if j.get('conclusion') != 'failure':
                        continue
                    try:
                        log = gh.job_log(j['id'])
                    except Exception:
                        log = ''
                    dg = ci_diagnose._diagnose_log_clean(log) or {}
                    kind = dg.get('kind') or 'unknown'
                    if cause in ('unknown',) or cause in INFRA_CAUSES:
                        cause = kind
                    tests = ci_diagnose.failed_tests_from_log(log)
                    if log:
                        store_ci_log(db, r, j, log, dg, tests)
                    if tests:
                        elems.update('test:' + t for t in tests)
                    elif kind in ('compile', 'link', 'configure', 'ice') and dg.get('file'):
                        elems.add(f"{kind}:{dg['file'].rsplit(':', 1)[0]}")
                    else:
                        elems.add(f"{kind}:{j.get('name', '')}")
                sig = json.dumps(sorted(elems))
            db.execute('INSERT OR REPLACE INTO runs(id,workflow,sha,created_at,conclusion,url,cause,sig)'
                       ' VALUES(?,?,?,?,?,?,?,?)',
                       (r['id'], wf, r['head_sha'], r['created_at'], r['conclusion'], r['html_url'], cause, sig))
        db.commit()

    print(f'  step: failed ci job logs ({gh.calls} calls)', file=sys.stderr, flush=True)
    # Failed-job logs from every workflow on every branch, while GitHub still
    # has them (90 days). Stored compressed with their cause and failing tests.
    oldest = datetime.now(timezone.utc) - LOG_RETENTION
    log_from = max(datetime.fromisoformat(since.replace('Z', '+00:00')) - timedelta(days=2), oldest)
    if int(get_state(db, 'logs_v', '0')) < LOGS_V:
        log_from = oldest   # first run: everything GitHub still has
    have = {jid for (jid,) in db.execute('SELECT job_id FROM ci_logs')}
    kept = 0
    for wf in LOG_WORKFLOWS:
        span = f"{log_from.strftime('%Y-%m-%dT%H:%M:%SZ')}..{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"
        for r in gh.pages(f'repos/{REPO}/actions/workflows/{wf}/runs?status=failure&per_page=100&created={q(span)}'):
            for j in gh.pages(f"repos/{REPO}/actions/runs/{r['id']}/jobs?per_page=100"):
                if j.get('conclusion') not in ('failure', 'timed_out') or j['id'] in have:
                    continue
                try:
                    log = gh.job_log(j['id'])
                except Exception as e:
                    print(f'    log {j["id"]} unavailable: {str(e)[:80]}', file=sys.stderr)
                    continue
                if log:
                    store_ci_log(db, r, j, log)
                    have.add(j['id'])
                    kept += 1
                    if kept % 25 == 0:
                        db.commit()
                        print(f'    {kept} logs kept ({gh.calls} calls)', file=sys.stderr, flush=True)
    db.commit()

    print(f'  step: pr base branches ({gh.calls} calls)', file=sys.stderr, flush=True)
    # The branch each merged PR targeted (only merges into main pass branch
    # protection). Cached PR details first, then a bounded number of fetches.
    if get_state(db, 'base_v') != '1':
        for url, body in db.execute("SELECT url, body FROM http_cache WHERE url LIKE '%/pulls/%'").fetchall():
            m = re.search(r'/pulls/(\d+)$', url)
            try:
                d = json.loads(body) if m else None
            except ValueError:
                d = None
            if isinstance(d, dict) and d.get('number') == int(m.group(1)) and d.get('base'):
                db.execute('UPDATE items SET base=? WHERE type="pr" AND number=? AND base IS NULL',
                           (d['base']['ref'], d['number']))
        set_state(db, 'base_v', '1')
        db.commit()
    for (n,) in db.execute('SELECT number FROM items WHERE type="pr" AND merged_at IS NOT NULL AND base IS NULL'
                           ' ORDER BY number DESC LIMIT 200').fetchall():
        p, _ = gh.get(f'repos/{REPO}/pulls/{n}')
        db.execute('UPDATE items SET base=? WHERE type="pr" AND number=?', ((p.get('base') or {}).get('ref'), n))
    db.commit()

    print(f'  step: code owners ({gh.calls} calls)', file=sys.stderr, flush=True)
    collect_codeowners(gh, db)

    print(f'  step: profiles ({gh.calls} calls)', file=sys.stderr, flush=True)
    # Public GitHub profiles (display name, bio) for contributor bios and
    # callsigns: new people first, then any older than a month, a bounded
    # number per run.
    stale = (datetime.now(timezone.utc) - PROFILE_MAX_AGE).strftime('%Y-%m-%dT%H:%M:%SZ')
    todo = [l for (l,) in db.execute(
        "SELECT p.login FROM people p LEFT JOIN profiles f ON f.login=p.login WHERE p.kind!='Bot'"
        " AND p.login NOT LIKE '%[bot]' AND p.login NOT LIKE 'oc:%' AND (f.fetched_at IS NULL OR f.fetched_at<?)"
        " ORDER BY f.fetched_at IS NOT NULL, f.fetched_at LIMIT ?", (stale, PROFILES_PER_RUN))
        if role_of(l) != 'bot']
    for login in todo:
        try:
            u, _ = gh.get(f'users/{urllib.parse.quote(login)}')
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            u = {}
        db.execute('INSERT OR REPLACE INTO profiles VALUES(?,?,?,?,?,?,?,?)',
                   (login, u.get('name'), u.get('bio'), u.get('location'), u.get('blog'), u.get('created_at'),
                    datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), json.dumps(u)))
    db.commit()

    print(f'  step: open collective ({gh.calls} calls)', file=sys.stderr, flush=True)
    try:
        print(f'    {collect_open_collective(db, gh.proxy)} contributions', file=sys.stderr, flush=True)
    except Exception as e:
        print(f'    open collective unavailable: {str(e)[:100]}', file=sys.stderr)

    print(f'  step: prs behind the commits ({gh.calls} calls)', file=sys.stderr, flush=True)
    # PRs behind the commits that broke or fixed main.
    # Only the failing runs and the green run that follows each red stretch
    # matter, so only those commits are looked up.
    needed = set()
    for wf in BREAK_WORKFLOWS:
        prev = None
        for sha, concl in db.execute('SELECT sha, conclusion FROM runs WHERE workflow=? ORDER BY created_at', (wf,)):
            if concl == 'failure' or (concl == 'success' and prev == 'failure'):
                needed.add(sha)
            if concl in ('success', 'failure'):
                prev = concl
    for sha in sorted(needed):
        if db.execute('SELECT 1 FROM state WHERE name=?', ('pr_of:' + sha,)).fetchone():
            continue
        prl, _ = gh.get(f'repos/{REPO}/commits/{sha}/pulls')
        num = next((p['number'] for p in prl if p.get('merged_at')), None)
        db.execute('INSERT OR REPLACE INTO state VALUES(?,?)', ('pr_of:' + sha, str(num or '')))
        if num and not db.execute('SELECT merged_by FROM items WHERE type="pr" AND number=?', (num,)).fetchone():
            p, _ = gh.get(f'repos/{REPO}/pulls/{num}')
            note_person(db, p.get('user'))
            db.execute('INSERT INTO items(type,number,author,created_at,closed_at,labels,title,merged_at,'
                       'merged_by,head_sha,merge_sha) VALUES("pr",?,?,?,?,?,?,?,?,?,?) ON CONFLICT(type,number) DO UPDATE SET'
                       ' merged_at=excluded.merged_at, merged_by=excluded.merged_by, head_sha=excluded.head_sha,'
                       ' merge_sha=excluded.merge_sha',
                       (num, p['user']['login'], p['created_at'], p.get('closed_at'), '[]', p['title'][:200],
                        p.get('merged_at'), (p.get('merged_by') or {}).get('login'), p['head']['sha'],
                        p.get('merge_commit_sha')))
            collect_reviews(gh, db, num)

    print(f'  step: first merged pr ever ({gh.calls} calls)', file=sys.stderr, flush=True)
    # First merged PR ever, per person seen merging a PR since the cursor.
    # With the full history stored it is a lookup; until then, a search.
    if since <= REPO_START:
        set_state(db, 'history_complete_pending', '1')
    full = get_state(db, 'history_complete') == '1'
    for (login,) in db.execute('SELECT DISTINCT author FROM items WHERE type="pr" AND merged_at>=?', (since,)).fetchall():
        if db.execute('SELECT 1 FROM first_merges WHERE login=?', (login,)).fetchone() or role_of(login) == 'bot':
            continue
        if full:
            row = db.execute('SELECT number, merged_at FROM items WHERE type="pr" AND author=? AND merged_at IS NOT NULL'
                             ' ORDER BY merged_at LIMIT 1', (login,)).fetchone()
            if row:
                db.execute('INSERT OR REPLACE INTO first_merges VALUES(?,?,?)', (login, row[0], row[1]))
            continue
        time.sleep(2.1)   # search API: 30 requests a minute
        body, _ = gh.get('search/issues?q=' + q(f'repo:{REPO} type:pr is:merged author:{login}') +
                         '&sort=created&order=asc&per_page=1')
        first = (body.get('items') or [None])[0]
        if first:
            p, _ = gh.get(f'repos/{REPO}/pulls/{first["number"]}')
            db.execute('INSERT OR REPLACE INTO first_merges VALUES(?,?,?)', (login, first['number'], p.get('merged_at')))
    # Only a complete run advances the cursor; an interrupted one re-reads
    # its feeds next time but skips the PRs it already finished.
    set_state(db, 'cursor', run_start)
    if full:
        set_state(db, 'full_reconcile_at', run_start)
    set_state(db, 'bodies_v', str(BODIES_V))
    set_state(db, 'logs_v', str(LOGS_V))
    if get_state(db, 'history_complete_pending') == '1':
        set_state(db, 'history_complete', '1')
        db.execute("DELETE FROM state WHERE name='history_complete_pending'")
        # Full history stored: first merges come from it, replacing any
        # search results (one source of truth).
        db.execute('DELETE FROM first_merges')
        db.execute('INSERT INTO first_merges SELECT author, number, MIN(merged_at) FROM items'
                   ' WHERE type="pr" AND merged_at IS NOT NULL GROUP BY author')
    db.commit()


# ── Scoring (pure function of the stored facts) ──────────────────────────
def score(db):
    led = []   # (login, rule, at, ref, note)

    def add(login, rule, at, ref, note='', pts=None):
        if login and role_of(login, (db.execute('SELECT kind FROM people WHERE login=?', (login,)).fetchone() or [None])[0]) != 'bot':
            led.append((login, rule, at, ref, note) + ((pts,) if pts is not None else ()))

    items = {(t, n): dict(zip(('author', 'created_at', 'closed_at', 'state_reason', 'labels', 'title', 'merged_at',
                               'merged_by', 'head_sha', 'merge_sha', 'closes', 'touches_tests'), rest))
             for t, n, *rest in db.execute('SELECT type, number, author, created_at, closed_at, state_reason, labels,'
                                           ' title, merged_at, merged_by, head_sha, merge_sha, closes, touches_tests FROM items')}
    labels = defaultdict(list)
    for n, lab, actor, at in db.execute('SELECT number, label, actor, at FROM labels'):
        labels[n].append((lab, actor, at))

    spam = set()
    for (t, n), it in items.items():
        labs = set(json.loads(it['labels'] or '[]'))
        if labs & SPAM_LABELS:
            spam.add((t, n))
            add(it['author'], 'spam', it['closed_at'] or it['created_at'], f'{t}#{n}')
            continue
        if labs & VOID_LABELS:
            continue   # an honest report that didn't pan out: no points either way
        if t == 'issue':
            add(it['author'], 'issue_open', it['created_at'], f'issue#{n}')
            conf = sorted((at, actor) for lab, actor, at in labels[n]
                          if lab in CONFIRM_LABELS and actor and actor != it['author'] and role_of(actor) != 'bot')
            if conf:
                add(it['author'], 'issue_confirmed', conf[0][0], f'issue#{n}', f'labelled by {conf[0][1]}')
        elif t == 'discussion':
            add(it['author'], 'discussion_open', it['created_at'], f'discussion#{n}')
        elif t == 'pr':
            add(it['author'], 'pr_open', it['created_at'], f'pr#{n}')
            if it['merged_at']:
                add(it['author'], 'pr_merged', it['merged_at'], f'pr#{n}')
                closes = json.loads(it['closes'] or '[]')
                if closes:
                    add(it['author'], 'pr_closes_issue', it['merged_at'], f'pr#{n}', 'closes ' + ', '.join(f'#{c}' for c in closes))
                    for c in closes:
                        iss = items.get(('issue', c))
                        if iss and iss['author'] != it['author'] and iss['state_reason'] == 'completed':
                            add(iss['author'], 'issue_fixed', it['merged_at'], f'issue#{c}', f'by PR #{n}')
                if it['touches_tests']:
                    add(it['author'], 'pr_tests', it['merged_at'], f'pr#{n}')
                if it['merged_by'] and it['merged_by'] != it['author']:
                    add(it['merged_by'], 'merge_other', it['merged_at'], f'pr#{n}')
                if (it['title'] or '').startswith('Revert '):
                    add(it['author'], 'revert_merged', it['merged_at'], f'pr#{n}')

    for login, num, at in db.execute('SELECT login, number, merged_at FROM first_merges'):
        add(login, 'first_merged_pr', at, f'pr#{num}')

    for n, login, at in db.execute('SELECT number, login, at FROM answers'):
        add(login, 'discussion_answer', at, f'discussion#{n}')

    # Reviews: one scored review per reviewer per PR per day, the best state
    # that day; the PR author's own thread replies are not reviews.
    # A comment-only review whose inline comments are all replies to existing
    # threads is a thread reply, not a new review: it joins the comment
    # stream below (1 point, under the comment caps) instead.
    threads = defaultdict(lambda: [0, 0])   # review_id -> [new threads, replies]
    for rid, reply in db.execute('SELECT review_id, in_reply_to FROM review_comments'):
        threads[rid][1 if reply else 0] += 1
    best, replies = {}, []
    for rid, pr, login, state, commit_id, at, body_len in db.execute(
            'SELECT id, pr, login, state, commit_id, submitted_at, body_len FROM reviews'):
        it = items.get(('pr', pr))
        if not at or not it or state in ('PENDING', 'DISMISSED'):
            continue
        new, rep_n = threads[rid]
        if state == 'COMMENTED' and body_len is not None and not body_len and not new:
            if rep_n:
                replies.append((f'rv{rid}', 'pr', pr, login, at, 1))
            continue
        if login == it['author']:
            continue
        rule = {'APPROVED': 'review_approve', 'CHANGES_REQUESTED': 'review_changes'}.get(state, 'review_comment')
        key = (login, pr, at[:10])
        if key not in best or RULES[rule][0] > RULES[best[key][0]][0]:
            best[key] = (rule, at)
    for (login, pr, _), (rule, at) in best.items():
        add(login, rule, at, f'pr#{pr}')

    # First human review on a PR within 24 hours of it opening.
    first = {}
    for (login, pr, _), (rule, at) in best.items():
        if role_of(login) == 'bot':
            continue
        if pr not in first or at < first[pr][1]:
            first[pr] = (login, at)
    for pr, (login, at) in first.items():
        it = items.get(('pr', pr))
        if it and it['created_at'] and _secs(it['created_at'], at) <= FAST_REVIEW_WINDOW.total_seconds():
            add(login, 'review_first_fast', at, f'pr#{pr}', 'first review within 24h')

    # Triage: the first label someone other than the author (and not a bot)
    # puts on an issue.
    for n, evs in labels.items():
        it = items.get(('issue', n))
        if not it or ('issue', n) in spam:
            continue
        tri = sorted((at, actor) for lab, actor, at in evs if actor and actor != it['author']
                     and role_of(actor) != 'bot' and lab not in NON_TRIAGE_LABELS)
        if tri:
            add(tri[0][1], 'issue_triaged', tri[0][0], f'issue#{n}')

    # Cleanup: closing someone else's issue by hand (as a duplicate, not
    # planned, or already fixed). Closes done by a merged PR are the PR's.
    fixed_by_pr = {c for (t, n), it in items.items() if t == 'pr' and it['merged_at']
                   for c in json.loads(it['closes'] or '[]')}
    done, per_day = set(), defaultdict(int)
    for cid, n, actor, at, reason, commit_id in db.execute('SELECT * FROM closes ORDER BY at'):
        it = items.get(('issue', n))
        if (not it or not actor or actor == it['author'] or role_of(actor) == 'bot' or commit_id
                or n in fixed_by_pr or (actor, n) in done):
            continue
        if per_day[(actor, at[:10])] >= CAP_ISSUE_CLOSES_PER_DAY:
            continue
        done.add((actor, n))
        per_day[(actor, at[:10])] += 1
        add(actor, 'issue_closed', at, f'issue#{n}', (reason or 'closed').replace('_', ' '))

    # Shepherding: pushing commits to someone else's PR before it merged.
    for pr, who in db.execute('SELECT pr, IFNULL(author, committer) FROM pr_commits GROUP BY pr, IFNULL(author, committer)'):
        it = items.get(('pr', pr))
        if it and it['merged_at'] and who and who not in ('web-flow', it['author']) and role_of(who) != 'bot':
            add(who, 'pr_shepherd', it['merged_at'], f'pr#{pr}')

    # Financial support: 10 points per dollar (USD), refunds excluded.
    try:
        oc_map = {k.lower(): v for k, v in json.load(open(OC_MAP_FILE)).items() if not k.startswith('_')}
    except (OSError, ValueError):
        oc_map = {}
    for tid, at, cents, cur, slug, name, img, raw in db.execute(
            'SELECT id, created_at, amount_cents, currency, from_slug, from_name, from_image, raw FROM oc_contributions'
            ' WHERE refunded=0'):
        if (cur or 'USD') != 'USD' or not cents:
            continue
        github = (json.loads(raw).get('fromAccount') or {}).get('githubHandle')
        login, display = _oc_identity(db, slug, name, github, oc_map)
        if display is not None:
            # Donors without a GitHub login; kept in memory so scoring stays
            # read-only (readers never wait on the collector's writes).
            BACKER_PEOPLE.setdefault(login, ('Backer', 'contributor', img or '', display))
        dollars = cents / 100
        add(login, 'backer_contribution', at.replace('.000Z', 'Z') if at else at, f'oc#{tid}',
            f'${dollars:,.2f} on Open Collective', round(dollars * RULES['backer_contribution'][0]))

    # Releases.
    for tag, at, author in db.execute('SELECT tag, published_at, author FROM releases WHERE prerelease=0'
                                      ' AND author IS NOT NULL'):
        if not is_release(tag):
            continue
        add(author, 'release_published', at, f'release#{tag}')

    # Comments, with caps applied in time order.
    thread_day, own_pr, per_day = defaultdict(int), defaultdict(int), defaultdict(int)
    # A reviewer whose review scored on a PR that day gets nothing more for
    # commenting or replying on that PR the same day.
    for (login, pr, day) in best:
        thread_day[(login, 'pr', pr, day)] = CAP_COMMENT_PER_THREAD_DAY
    stream = sorted(list(db.execute('SELECT id, type, number, login, created_at, substantive FROM comments')) + replies,
                    key=lambda c: c[4] or '')
    for cid, t, n, login, at, subst in stream:
        it = items.get((t, n))
        if not subst or not login or (t, n) in spam:
            continue
        rule = {'discussion': 'discussion_comment', 'pr': 'pr_comment'}.get(t, 'issue_comment')
        day = at[:10]
        if thread_day[(login, t, n, day)] >= CAP_COMMENT_PER_THREAD_DAY or per_day[(login, day)] >= CAP_COMMENTS_PER_DAY:
            continue
        if t == 'pr' and it and it['author'] == login:
            if own_pr[(login, n)] >= CAP_OWN_PR_REPLIES:
                continue
            own_pr[(login, n)] += 1
        thread_day[(login, t, n, day)] += 1
        per_day[(login, day)] += 1
        add(login, rule, at, f'{t}#{n}')

    # Issue opens per day cap: drop opens past the cap (oldest kept).
    opens = defaultdict(int)
    kept = []
    for e in sorted(led, key=lambda e: e[2] or ''):
        if e[1] == 'issue_open':
            opens[(e[0], (e[2] or '')[:10])] += 1
            if opens[(e[0], (e[2] or '')[:10])] > CAP_ISSUE_OPENS_PER_DAY:
                continue
        kept.append(e)
    led = kept

    # Breaking main, per workflow in push order. The first failure after a
    # green run is a break; while main stays red, a later run is a break too
    # if it fails something new: a test (or error) not already failing at any
    # point since main went red. Infrastructure failures are skipped. A
    # commit that breaks both workflows counts once.
    runs = db.execute('SELECT id, workflow, sha, created_at, conclusion, url, cause, sig FROM runs'
                      ' ORDER BY created_at').fetchall()
    pr_of = {k[6:]: v for k, v in db.execute("SELECT name, value FROM state WHERE name LIKE 'pr_of:%'")}
    breaks = []
    for wf in BREAK_WORKFLOWS:
        stretch, open_breaks, seen_green = set(), [], False
        for rid, w, sha, at, concl, url, cause, sig in [r for r in runs if r[1] == wf]:
            if concl not in ('success', 'failure') or (concl == 'failure' and cause in INFRA_CAUSES):
                continue
            if concl == 'success':
                for ob in open_breaks:
                    ob['fixed_sha'], ob['fixed_at'] = sha, at
                    ob['fixed_pr'] = int(pr_of.get(sha) or 0) or None
                stretch, open_breaks, seen_green = set(), [], True
                continue
            elems = set(json.loads(sig or '[]')) or {f'{cause}:'}
            new = elems - stretch
            if seen_green and new:
                b = {'sha': sha, 'at': at, 'url': url, 'workflow': wf, 'cause': cause,
                     'pr': int(pr_of.get(sha) or 0) or None, 'first': not stretch,
                     'new': sorted(x.split(':', 1)[1] or x for x in new)[:10]}
                breaks.append(b)
                open_breaks.append(b)
            stretch |= elems
    seen, fix_credit = set(), set()
    for b in sorted(breaks, key=lambda b: b['at']):
        if b['sha'] in seen or not b['pr']:
            continue
        seen.add(b['sha'])
        it = items.get(('pr', b['pr'])) or {}
        ref = f"pr#{b['pr']}"
        what = ', '.join(b['new'][:3]) + (f" +{len(b['new']) - 3} more" if len(b['new']) > 3 else '')
        note = (f"{b['workflow'].replace('.yml', '')} red at {b['sha'][:7]}" if b['first']
                else f"{b['workflow'].replace('.yml', '')} new failure at {b['sha'][:7]} while red") + f": {what}"
        roles = defaultdict(set)
        if it.get('author'):
            roles[it['author']].add('break_author')
        if it.get('merged_by'):
            roles[it['merged_by']].add('break_merger')
        for login, state, commit_id in db.execute('SELECT login, state, commit_id FROM reviews WHERE pr=?', (b['pr'],)):
            if state == 'APPROVED' and commit_id == it.get('head_sha') and login != it.get('author'):
                roles[login].add('break_approver')
        for login, rs in roles.items():
            worst = min(rs, key=lambda r: RULES[r][0])    # one penalty per person, the largest
            add(login, worst, b['at'], ref, note)
        fx = items.get(('pr', b.get('fixed_pr'))) if b.get('fixed_pr') else None
        if fx and fx.get('author'):
            fixed_quick = b.get('fixed_at') and (datetime.fromisoformat(b['fixed_at'].replace('Z', '+00:00')) -
                                                 datetime.fromisoformat(b['at'].replace('Z', '+00:00'))) <= SELF_FIX_WINDOW
            if fx['author'] == it.get('author'):
                if fixed_quick:
                    add(fx['author'], 'break_self_fix', b['fixed_at'], f"pr#{b['fixed_pr']}", f"fixed own break {b['sha'][:7]}")
            elif b['fixed_pr'] != b['pr'] and (fx['author'], b['fixed_pr']) not in fix_credit:
                # One "fixed main" per green run, however many breaks it closed.
                fix_credit.add((fx['author'], b['fixed_pr']))
                add(fx['author'], 'main_fixed', b['fixed_at'], f"pr#{b['fixed_pr']}", f"main green after {b['sha'][:7]}")
    return led, breaks


def _secs(a, b):
    try:
        return (datetime.fromisoformat(b.replace('Z', '+00:00')) - datetime.fromisoformat(a.replace('Z', '+00:00'))).total_seconds()
    except (AttributeError, ValueError):
        return float('inf')


# An AetherSDR release is a v-tag (v26.10.1). Other releases in the repo,
# such as a component's own (flex-tailnet-shim-v0.4.0), neither open a week
# nor score release_published.
RELEASE_TAG = re.compile(r'v[0-9]')


def is_release(tag):
    return bool(tag and RELEASE_TAG.match(tag))


def board_of(rule):
    return 'steward' if rule in STEWARD_RULES else 'backer' if rule in BACKER_RULES else 'contributor'


def windows(db):
    rel = [(t, p) for t, p, pre in db.execute('SELECT tag, published_at, prerelease FROM releases ORDER BY published_at')
           if not pre and p and is_release(t)]
    out = [{'tag': t, 'start': rel[i - 1][1] if i else None, 'end': p} for i, (t, p) in enumerate(rel)]
    out.append({'tag': 'current', 'start': rel[-1][1] if rel else None, 'end': None})
    return out


# Amateur-radio callsign: a prefix (one or two letters, or a letter and a
# digit either way round), a digit, then a one-to-four-letter suffix.
_CALLSIGN = re.compile(r'(?<![A-Z0-9])((?:[A-Z]{1,2}|[A-Z][0-9]|[0-9][A-Z])[0-9][A-Z]{1,4})(?![A-Z0-9])')
# Labels that say what kind of item it is, not which part of AetherSDR.
NON_AREA_LABELS = {'bug', 'enhancement', 'documentation', 'question', 'duplicate', 'invalid', 'wontfix',
                   'good first issue', 'help wanted', 'maintainer-review', 'awaiting-response', 'claude-active',
                   'aetherclaude-eligible', 'full-suite', 'sanitizer', 'asan-ubsan', 'tsan', 'refactor', 'dependencies',
                   'needs-triage', 'release', 'stale', 'spam', 'new feature', 'feature request', 'rfc', 'discussion', 'wip', 'blocked',
                   'awaiting-confirmation', 'insufficient-info', 'no-claude', 'rfc approved', 'hold-until-ready',
                   'needs-hardware', 'unsupported-radio', 'upstream', 'warning', 'governance', 'github_actions',
                   'javascript', 'float32-regression'}


def find_callsign(*texts):
    for t in texts:
        if not t:
            continue
        for tok in re.split(r'[^A-Za-z0-9]+', t):
            m = _CALLSIGN.fullmatch(tok.upper()) if 4 <= len(tok) <= 7 else None
            if m and any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok):
                return m.group(1)
    return None


def bios(db, led, logins=None):
    """All-time profile for each person: identity, firsts, lifetime counts,
    weekly awards and the areas they work in. Independent of the window."""
    want = set(logins) if logins is not None else None
    prof = {l: (n, b) for l, n, b in db.execute('SELECT login, name, bio FROM profiles')}
    people = {l: (k, a, n) for l, k, a, n in db.execute('SELECT login, kind, avatar, display_name FROM people')}
    for l, row in BACKER_PEOPLE.items():
        people.setdefault(l, (row[0], row[2], row[3]))
    count = lambda sql: dict(db.execute(sql))
    issues = count("SELECT author, COUNT(*) FROM items WHERE type='issue' GROUP BY author")
    prs = count("SELECT author, COUNT(*) FROM items WHERE type='pr' GROUP BY author")
    merged = count("SELECT author, COUNT(*) FROM items WHERE type='pr' AND merged_at IS NOT NULL GROUP BY author")
    discussions = count("SELECT author, COUNT(*) FROM items WHERE type='discussion' GROUP BY author")
    comments = count('SELECT login, COUNT(*) FROM comments GROUP BY login')
    reviewed = count("SELECT r.login, COUNT(DISTINCT r.pr) FROM reviews r JOIN items i ON i.type='pr' AND i.number=r.pr"
                     " WHERE r.login!=i.author AND r.state NOT IN ('PENDING','DISMISSED') GROUP BY r.login")
    merges = count("SELECT merged_by, COUNT(*) FROM items WHERE type='pr' AND merged_at IS NOT NULL"
                   " AND merged_by!=author GROUP BY merged_by")
    areas = defaultdict(lambda: defaultdict(int))
    for author, labels in db.execute("SELECT author, labels FROM items WHERE type IN ('issue','pr') AND labels!='[]'"):
        for lab in json.loads(labels or '[]'):
            if lab.lower() not in NON_AREA_LABELS and not lab.lower().startswith(('priority', 'size', 'status')):
                areas[author][lab] += 1
    first, first_merge, donated = {}, {}, defaultdict(float)
    for e in led:
        login, rule, at, ref = e[0], e[1], e[2], e[3]
        if not at:
            continue
        if login not in first or at < first[login]:
            first[login] = at
        if rule == 'pr_merged' and (login not in first_merge or at < first_merge[login][0]):
            first_merge[login] = (at, ref)
        if rule == 'backer_contribution':
            donated[login] += (e[5] if len(e) > 5 else 0) / RULES['backer_contribution'][0]
    # Weekly awards: winners of every completed release window, one pass.
    ws = [w for w in windows(db) if w['tag'] != 'current']
    starts = [w['start'] or '' for w in ws]
    import bisect
    agg = [defaultdict(lambda: [0, 0, 0, 0, 0]) for _ in ws]   # contributor, steward, backer, prs, issues
    for e in led:
        at = e[2] or ''
        i = bisect.bisect_right(starts, at) - 1
        if i < 0 or (ws[i]['end'] and at >= ws[i]['end']):
            continue
        pts = e[5] if len(e) > 5 else RULES[e[1]][0]
        a = agg[i][e[0]]
        if e[1] in STEWARD_RULES:
            a[1] += pts
        elif e[1] in BACKER_RULES:
            a[2] += pts
        else:
            a[0] += pts
            cat = RULES[e[1]][1]
            a[3] += pts if cat == 'prs' else 0
            a[4] += pts if cat == 'issues' else 0
    awards = defaultdict(lambda: defaultdict(list))
    for w, a in zip(ws, agg):
        elig = {l: v for l, v in a.items()
                if role_of(l, (people.get(l) or ('User',))[0]) == 'contributor'}
        for idx, kind in ((0, 'contributor'), (1, 'steward'), (2, 'backer')):
            cand = [(v[idx], v[3], v[4], l) for l, v in elig.items() if v[idx] > 0]
            if cand:
                top = max(cand, key=lambda c: (c[0], c[1], c[2], [-ord(ch) for ch in c[3].lower()]))
                awards[top[3]][kind].append(w['tag'])
    badges = achievements(db, led)
    out = {}
    for login in (want if want is not None else set(first)):
        kind, avatar, display = people.get(login, ('User', '', None))
        name, bio = prof.get(login, (None, None))
        a = areas.get(login, {})
        out[login] = {
            'name': display or name or None,
            'callsign': find_callsign(login, name, display, bio),
            'avatar': avatar or None,
            'github': None if login.startswith('oc:') else f'https://github.com/{login}',
            'first_at': first.get(login),
            'first_merged': ({'at': first_merge[login][0], 'pr': int(first_merge[login][1].split('#')[1])}
                             if login in first_merge else None),
            'counts': {'issues': issues.get(login, 0), 'prs': prs.get(login, 0), 'merged': merged.get(login, 0),
                       'comments': comments.get(login, 0), 'reviews': reviewed.get(login, 0),
                       'merges': merges.get(login, 0), 'discussions': discussions.get(login, 0)},
            'donated': round(donated.get(login, 0), 2),
            'awards': {k: {'count': len(v), 'latest': v[-1]} for k, v in awards.get(login, {}).items()},
            'areas': [l for l, _ in sorted(a.items(), key=lambda kv: -kv[1])[:4]],
            'badges': badges.get(login, []),
        }
    return out


# Achievement badges: earned once, kept for good. Each is computed from the
# ledger (so the fair-play caps apply) plus item labels and authors.
ACHIEVEMENTS = (
    ('broke_main', 'I Broke Main', 'A PR you wrote, approved or merged turned main red. It happens to everyone.'),
    ('smoke_jumper', 'Smoke Jumper', "Merged the fix that turned main green after someone else's break."),
    ('self_healing', 'Self-Healing', 'Broke main and fixed it yourself within 24 hours.'),
    ('clean_sweep', 'Clean Sweep', '50 merged PRs in a row without breaking main.'),
    ('first_contact', 'First Contact', 'Your first merged PR.'),
    ('signal_report', 'Signal Report', "Your first approving review of someone else's PR."),
    ('qsl_confirmed', 'QSL Confirmed', 'A PR of yours closed an issue someone else opened.'),
    ('dxcc', 'DXCC', 'Merged PRs: 10, 50, 100 and 250.'),
    ('rag_chewer', 'Rag Chewer', '500 scoring comments.'),
    ('net_control', 'Net Control', '100 PRs merged for other people.'),
    ('elmer', 'Elmer', '50 reviews of PRs by newcomers (fewer than 3 merged PRs).'),
    ('fast_qsy', 'Fast QSY', '10 first reviews within 24 hours of a PR opening.'),
    ('test_pilot', 'Test Pilot', '25 merged PRs that add or change tests.'),
    ('bug_hunter', 'Bug Hunter', '10 of your bug reports fixed by someone else.'),
    ('grey_line', 'Grey Line', 'Active between 00:00 and 05:00 UTC on 10 different days.'),
    ('contest_weekend', 'Contest Weekend', '20 scoring actions in one UTC day.'),
    ('was', 'Worked All Sections', 'Merged PRs in 5 different areas of AetherSDR.'),
    ('old_timer', 'Old Timer', 'Contributing for 6 months, active in at least 4 of them.'),
    ('every_release', 'Every Release', 'Active in 5 release weeks in a row.'),
    ('backer', 'Backer', 'Supports AetherSDR on Open Collective.'),
    ('codeowner_t3', 'Technician Class', 'Tier 3 code owner: reviews AetherSDR source (@aethersdr/reviewers).'),
    ('codeowner_t2', 'General Class', 'Tier 2 code owner: project infrastructure (@aethersdr/infrastructure).'),
    ('codeowner_t1', 'Amateur Extra', 'Tier 1 code owner: governance and security (@aethersdr/maintainers).'),
    ('admin_merge', 'Admin Merge', 'Merged a PR into main past branch protection, with no approval but your own.'),
)
DXCC_TIERS = (10, 50, 100, 250)
# Things a person did at the time recorded (not, say, their PR being merged).
OWN_ACTIONS = {'discussion_comment', 'issue_comment', 'pr_comment', 'discussion_open', 'discussion_answer',
               'issue_open', 'pr_open', 'review_approve', 'review_changes', 'review_comment', 'merge_other',
               'issue_triaged', 'issue_closed', 'release_published'}
COUNTED = {'smoke_jumper', 'self_healing', 'backer', 'admin_merge'}   # tallied, not just earned
REVIEW_RULES = {'review_approve', 'review_changes', 'review_comment'}
BREAK_RULES = {'break_author', 'break_approver', 'break_merger'}


def achievements(db, led, now=None):
    """login -> [{id, at, ref?, count?, tier?}] for every badge earned."""
    now = now or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    items = {(t, n): (a, json.loads(l or '[]'), m, json.loads(c or '[]')) for t, n, a, l, m, c in
             db.execute('SELECT type, number, author, labels, merged_at, closes FROM items')}
    merged_at = defaultdict(list)   # author -> merge times, for "newcomer"
    for (t, n), (a, _, m, _c) in items.items():
        if t == 'pr' and m:
            merged_at[a].append(m)
    for v in merged_at.values():
        v.sort()
    num = lambda ref: int(ref.split('#')[1]) if ref and '#' in ref else None
    areas = lambda labs: {l for l in labs if l.lower() not in NON_AREA_LABELS
                          and not l.lower().startswith(('priority', 'size', 'status'))}
    ws = [w for w in windows(db) if w['tag'] != 'current']
    # Merges into main that no one but the author approved first: main
    # requires an approval, so only an admin override gets these through.
    approved = defaultdict(list)
    for pr, login, at in db.execute("SELECT pr, login, submitted_at FROM reviews WHERE state='APPROVED'"):
        if role_of(login) != 'bot':
            approved[pr].append((login, at))
    admin = defaultdict(list)
    for n, author, by_, at in db.execute("SELECT number, author, merged_by, merged_at FROM items WHERE type='pr'"
                                         " AND merged_at IS NOT NULL AND base='main' ORDER BY merged_at"):
        if by_ and not any(l != author and a and a <= at for l, a in approved.get(n, ())):
            admin[by_].append((at, f'pr#{n}'))
    owners = {(t, l): f for t, l, f in db.execute('SELECT tier, login, first_seen FROM codeowners')}
    by = defaultdict(list)
    for e in led:
        if e[2]:
            by[e[0]].append(e)
    out = {}
    for login, evs in by.items():
        evs.sort(key=lambda e: e[2])
        got = {}

        def earn(bid, at, ref=None, **kw):
            if bid not in got:
                got[bid] = dict({'id': bid, 'at': at}, **({'ref': ref} if ref else {}), **kw)

        def nth(rules, n, bid, pred=lambda e: True):
            hits = [e for e in evs if e[1] in rules and pred(e)]
            if len(hits) >= n:
                earn(bid, hits[n - 1][2], hits[n - 1][3], **({'count': len(hits)} if bid in COUNTED else {}))

        breaks = {}
        for e in evs:
            if e[1] in BREAK_RULES:
                breaks.setdefault(e[3], e)
        if breaks:
            first = min(breaks.values(), key=lambda e: e[2])
            earn('broke_main', first[2], first[3], count=len(breaks))
        nth({'main_fixed'}, 1, 'smoke_jumper')
        nth({'break_self_fix'}, 1, 'self_healing')
        run = 0
        for e in evs:
            run = 0 if e[1] == 'break_author' else run + (e[1] == 'pr_merged')
            if run == 50:
                earn('clean_sweep', e[2], e[3])
        nth({'pr_merged'}, 1, 'first_contact')
        nth({'review_approve'}, 1, 'signal_report')
        nth({'pr_closes_issue'}, 1, 'qsl_confirmed',
            lambda e: any((items.get(('issue', int(c))) or (login,))[0] != login
                          for c in re.findall(r'#(\d+)', e[4] or '')))
        merges = [e for e in evs if e[1] == 'pr_merged']
        tiers = [t for t in DXCC_TIERS if len(merges) >= t]
        if tiers:
            got['dxcc'] = {'id': 'dxcc', 'at': merges[tiers[-1] - 1][2], 'ref': merges[tiers[-1] - 1][3],
                          'tier': tiers[-1], 'count': len(merges)}
        nth({'discussion_comment', 'issue_comment', 'pr_comment'}, 500, 'rag_chewer')
        nth({'merge_other'}, 100, 'net_control')

        def newcomer(e):
            author = (items.get(('pr', num(e[3]))) or (None,))[0]
            return (author and author != login and role_of(author) != 'bot'
                    and sum(1 for m in merged_at.get(author, ()) if m < e[2]) < 3)
        nth(REVIEW_RULES, 50, 'elmer', newcomer)
        nth({'review_first_fast'}, 10, 'fast_qsy')
        nth({'pr_tests'}, 25, 'test_pilot')
        nth({'issue_fixed'}, 10, 'bug_hunter',
            lambda e: 'bug' in {l.lower() for l in (items.get(('issue', num(e[3]))) or (0, []))[1]})
        own = [e for e in evs if e[1] in OWN_ACTIONS]
        grey = []
        for e in own:
            if '00' <= e[2][11:13] < '05' and e[2][:10] not in grey:
                grey.append(e[2][:10])
                if len(grey) == 10:
                    earn('grey_line', e[2], e[3])
        per_day = defaultdict(list)
        for e in own:
            per_day[e[2][:10]].append(e)
            if len(per_day[e[2][:10]]) == 20:
                earn('contest_weekend', e[2], e[3])
        seen = set()
        for e in merges:
            pr = items.get(('pr', num(e[3]))) or (0, [], 0, [])
            seen |= areas(pr[1])
            for c in pr[3]:   # and the areas of the issues it closed
                seen |= areas((items.get(('issue', c)) or (0, []))[1])
            if len(seen) >= 5:
                earn('was', e[2], e[3], areas=sorted(seen))
                break
        act = [e for e in evs if e[1] in OWN_ACTIONS or e[1] == 'pr_merged']
        if act:
            start = datetime.fromisoformat(act[0][2].replace('Z', '+00:00'))
            months, fourth = set(), None
            for e in act:
                months.add(e[2][:7])
                if len(months) == 4:
                    fourth = e[2]
                    break
            six = (start + timedelta(days=182)).strftime('%Y-%m-%dT%H:%M:%SZ')
            if fourth and six <= now:
                earn('old_timer', max(six, fourth), act[0][3])   # links to where they started
        streak = best = 0
        for w in ws:
            active = any((not w['start'] or e[2] >= w['start']) and e[2] < w['end'] for e in own)
            streak = streak + 1 if active else 0
            best = max(best, streak)
            if streak == 5:
                earn('every_release', w['end'], f"release#{w['tag']}", release=w['tag'])
        if 'every_release' in got:
            got['every_release']['count'] = best
        nth({'backer_contribution'}, 1, 'backer')
        for tier in (3, 2, 1):
            if (tier, login) in owners:
                earn(f'codeowner_t{tier}', owners[(tier, login)], 'file#.github/CODEOWNERS', tier=tier)
        if admin.get(login):
            earn('admin_merge', admin[login][0][0], admin[login][0][1], count=len(admin[login]))
        if got:
            order = [a[0] for a in ACHIEVEMENTS]
            out[login] = sorted(got.values(), key=lambda b: order.index(b['id']))
    return out


# Kinds of "first" a contributor can have, by the ledger rules that count as
# doing that thing. A week shows a person's firsts when the earliest such
# event they have ever had falls inside it.
FIRSTS = (
    ('issue', 'first issue', {'issue_open'}),
    ('comment', 'first comment', {'issue_comment', 'pr_comment', 'discussion_comment'}),
    ('discussion', 'first discussion', {'discussion_open'}),
    ('pr', 'first PR', {'pr_open'}),
    ('merged', 'first merged PR', {'pr_merged'}),
    ('review', 'first review', {'review_approve', 'review_changes', 'review_comment'}),
    ('merge', 'first PR merged for someone else', {'merge_other'}),
    ('answer', 'first accepted answer', {'discussion_answer'}),
    ('backer', 'first donation', {'backer_contribution'}),
)


def standings(db, led, start=None, end=None):
    earliest = {}   # (login, kind) -> the first time they ever did it
    for e in led:
        for kind, _, rules in FIRSTS:
            if e[1] in rules and e[2]:
                k = (e[0], kind)
                if k not in earliest or e[2] < earliest[k]:
                    earliest[k] = e[2]
    people = {l: (k, r, a, n) for l, k, r, a, n in db.execute('SELECT login, kind, role, avatar, display_name FROM people')}
    for login, row in BACKER_PEOPLE.items():
        people.setdefault(login, row)
    rows = defaultdict(lambda: {'points': 0, 'cats': defaultdict(int), 'events': []})
    for e in led:
        login, rule, at, ref, note = e[:5]
        if (start and (at or '') < start) or (end and (at or '') >= end):
            continue
        pts, cat = (e[5] if len(e) > 5 else RULES[rule][0]), RULES[rule][1]
        r = rows[login]
        r['points'] += pts
        r['cats'][cat] += pts
        r['events'].append({'rule': rule, 'points': pts, 'at': at, 'ref': ref, 'note': note})
    out = []
    for login, r in rows.items():
        kind, role, avatar, name = people.get(login, ('User', None, '', None))
        if role != 'contributor' or kind != 'Backer':
            role = role_of(login, kind)   # current rules, not the role stored when first seen
        steward = sum(e['points'] for e in r['events'] if e['rule'] in STEWARD_RULES)
        backer = sum(e['points'] for e in r['events'] if e['rule'] in BACKER_RULES)
        out.append({'login': login, 'name': name, 'role': role, 'eligible': role == 'contributor', 'avatar': avatar,
                    'core': login.lower() in CORE_TEAM,
                    # Firsts that happened in this window (none for all-time).
                    'firsts': [label for kind, label, _ in FIRSTS
                               if (start or end) and (login, kind) in earliest
                               and (not start or earliest[(login, kind)] >= start)
                               and (not end or earliest[(login, kind)] < end)],
                    'points': r['points'] - steward - backer,   # contributor points
                    'steward': steward, 'backer': backer, 'total': r['points'], 'cats': dict(r['cats']),
                    'events': sorted(r['events'], key=lambda e: e['at'] or '', reverse=True)})
    out.sort(key=lambda r: (-r['points'], -r['cats'].get('prs', 0), -r['cats'].get('issues', 0), r['login'].lower()))
    rank = 0
    for r in out:
        if r['eligible']:
            rank += 1
            r['rank'] = rank
    # Backer of the week: ranked on backer points alone.
    brank = 0
    for r in sorted(out, key=lambda r: (-r['backer'], r['login'].lower())):
        if r['eligible'] and r['backer'] > 0:
            brank += 1
            r['backer_rank'] = brank
    # Steward of the week: ranked on steward points alone.
    srank = 0
    for r in sorted(out, key=lambda r: (-r['steward'], -r['cats'].get('reviews', 0), r['login'].lower())):
        if r['eligible'] and r['steward'] > 0:
            srank += 1
            r['steward_rank'] = srank
    return out


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('collect')
    c.add_argument('--since', help='default: the stored cursor, or a full backfill on the first run')
    c.add_argument('--max-per-hour', type=int, default=1000)
    s = sub.add_parser('score')
    s.add_argument('--json', default='-')
    s.add_argument('--windows', type=int, default=3, help='recent release windows to include')
    a = ap.parse_args()
    db = db_open(DB_PATH)
    if a.cmd == 'collect':
        token = os.environ.get('GH_TOKEN') or subprocess.check_output(
            ['/Users/aetherclaude/bin/github-app-token.sh'], text=True).strip()
        gh = GH(token, os.environ.get('HTTPS_PROXY'), a.max_per_hour, db)
        since = a.since
        if not since:
            cur = get_state(db, 'cursor')
            since = ((datetime.fromisoformat(cur.replace('Z', '+00:00')) - CURSOR_OVERLAP).strftime('%Y-%m-%dT%H:%M:%SZ')
                     if cur else REPO_START)
        collect(gh, db, since)
        print(f'collected since {since}: {gh.calls} API calls, {gh.not_modified} answered 304 (free)', file=sys.stderr)
        db.close()
        made = backup()
        if made:
            print(f'backup: {made}', file=sys.stderr)
        return
    led, breaks = score(db)
    ws = windows(db)[-a.windows:]
    out = {'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'repo': REPO,
           'rules': {k: {'points': v[0], 'category': v[1], 'board': board_of(k)} for k, v in RULES.items()},
           'windows': [dict(w, standings=standings(db, led, w['start'], w['end'])) for w in ws],
           'all_time': standings(db, led),
           'breaks': breaks}
    txt = json.dumps(out, indent=1)
    if a.json == '-':
        print(txt)
    else:
        open(a.json, 'w').write(txt)


if __name__ == '__main__':
    main()
