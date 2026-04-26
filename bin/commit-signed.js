#!/usr/bin/env node
// Create a SIGNED commit on a remote branch via GitHub's GraphQL
// createCommitOnBranch mutation. Commits made via the API on behalf of a
// GitHub App are automatically signed with GitHub's key, so the resulting
// commit shows as Verified.
//
// Replaces the local `git push` step in the orchestrator. Reads the file
// changes from the worktree (compared to main), creates the remote branch
// if it doesn't exist, then commits all changes in one signed commit.
//
// Usage:
//   commit-signed.js <branch> <commit-message> <worktree-path>
//
// Outputs JSON: {sha: "...", verified: true} on success, {error: "..."} on failure.

const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const HOME = process.env.HOME || '/Users/aetherclaude';
const UPSTREAM_REPO = 'ten9876/AetherSDR';
const [REPO_OWNER, REPO_NAME] = UPSTREAM_REPO.split('/');

function loadEnv() {
    const env = {};
    try {
        fs.readFileSync(path.join(HOME, '.env'), 'utf8').split('\n').forEach(l => {
            if (l && !l.startsWith('#') && l.includes('=')) {
                const [k, ...v] = l.split('=');
                env[k.trim()] = v.join('=').trim();
            }
        });
    } catch (e) {}
    return env;
}

function makeJWT(env) {
    const pk = fs.readFileSync(path.join(HOME, '.github-app-key.pem'), 'utf8');
    const now = Math.floor(Date.now() / 1000);
    const h = Buffer.from('{"alg":"RS256","typ":"JWT"}').toString('base64url');
    const p = Buffer.from(JSON.stringify({iat: now - 60, exp: now + 600, iss: env.GITHUB_APP_ID})).toString('base64url');
    const s = crypto.createSign('RSA-SHA256');
    s.update(`${h}.${p}`);
    return `${h}.${p}.${s.sign(pk, 'base64url')}`;
}

function apiCall(method, apiPath, body, token, bearer) {
    return new Promise((resolve, reject) => {
        const data = body ? JSON.stringify(body) : null;
        const opts = {
            hostname: 'api.github.com',
            path: apiPath,
            method: method,
            headers: {
                'Authorization': `${bearer ? 'Bearer' : 'token'} ${token}`,
                'Accept': 'application/vnd.github+json',
                'User-Agent': 'AetherClaude-Commit/1.0',
                'Content-Type': 'application/json'
            }
        };
        if (data) opts.headers['Content-Length'] = Buffer.byteLength(data);
        const req = https.request(opts, res => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(body);
                    if (res.statusCode >= 400) {
                        reject(new Error(`HTTP ${res.statusCode}: ${body.substring(0, 500)}`));
                    } else {
                        resolve(parsed);
                    }
                } catch (e) {
                    reject(new Error(`Parse error: ${body.substring(0, 200)}`));
                }
            });
        });
        req.on('error', reject);
        if (data) req.write(data);
        req.end();
    });
}

function git(args, cwd) {
    return execSync(`git ${args}`, { cwd, encoding: 'utf8' }).trim();
}

async function main() {
    const branch = process.argv[2];
    const message = process.argv[3];
    const worktree = process.argv[4];
    if (!branch || !message || !worktree) {
        console.log(JSON.stringify({error: 'Usage: commit-signed.js <branch> <message> <worktree-path>'}));
        process.exit(1);
    }

    // 1. Get installation token (using App ten9876 install)
    const env = loadEnv();
    const jwt = makeJWT(env);
    const installs = await apiCall('GET', '/app/installations', null, jwt, true);
    const inst = installs.find(i => i.account.login === 'ten9876') || installs[0];
    const perms = {permissions: {contents: 'write', pull_requests: 'write', metadata: 'read'}};
    const tokResp = await apiCall('POST', `/app/installations/${inst.id}/access_tokens`, perms, jwt, true);
    const token = tokResp.token;

    // 2. Compute file changes vs origin/main
    git('fetch origin main --quiet', worktree);
    const baseSha = git('rev-parse origin/main', worktree);
    const status = git('diff --name-status origin/main', worktree);

    const additions = [];
    const deletions = [];
    for (const line of status.split('\n').filter(Boolean)) {
        // git diff --name-status format: "M\tpath", "A\tpath", "D\tpath", "R100\told\tnew"
        const parts = line.split('\t');
        const code = parts[0][0];  // first char: M/A/D/R
        if (code === 'D') {
            deletions.push({path: parts[1]});
        } else if (code === 'R') {
            // rename: delete old, add new
            deletions.push({path: parts[1]});
            const newPath = parts[2];
            additions.push({path: newPath, contents: fs.readFileSync(path.join(worktree, newPath)).toString('base64')});
        } else {
            // A or M (or copy C)
            const filePath = parts[parts.length - 1];
            additions.push({path: filePath, contents: fs.readFileSync(path.join(worktree, filePath)).toString('base64')});
        }
    }

    if (additions.length === 0 && deletions.length === 0) {
        console.log(JSON.stringify({error: 'No changes to commit'}));
        process.exit(1);
    }

    // 3. Ensure remote branch exists (create from main HEAD if not).
    //    GraphQL createCommitOnBranch requires the branch to exist.
    let branchHeadSha = baseSha;
    try {
        const ref = await apiCall('GET', `/repos/${UPSTREAM_REPO}/git/ref/heads/${branch}`, null, token, false);
        branchHeadSha = ref.object.sha;
    } catch (e) {
        // 404 - create it
        await apiCall('POST', `/repos/${UPSTREAM_REPO}/git/refs`,
            {ref: `refs/heads/${branch}`, sha: baseSha}, token, false);
    }

    // 4. Build createCommitOnBranch GraphQL mutation
    const lines = message.split('\n');
    const headline = lines[0];
    const body = lines.slice(1).join('\n').trim();

    const mutation = `
        mutation($input: CreateCommitOnBranchInput!) {
            createCommitOnBranch(input: $input) {
                commit { oid url signature { isValid wasSignedByGitHub } }
            }
        }`;
    const input = {
        branch: { repositoryNameWithOwner: UPSTREAM_REPO, branchName: branch },
        message: { headline, body: body || undefined },
        expectedHeadOid: branchHeadSha,
        fileChanges: { additions, deletions }
    };

    const gql = await apiCall('POST', '/graphql', {query: mutation, variables: {input}}, token, false);
    if (gql.errors && gql.errors.length) {
        console.log(JSON.stringify({error: gql.errors.map(e => e.message).join('; ')}));
        process.exit(1);
    }
    const commit = gql.data.createCommitOnBranch.commit;
    console.log(JSON.stringify({
        sha: commit.oid,
        url: commit.url,
        verified: commit.signature ? commit.signature.isValid : null,
        signedByGitHub: commit.signature ? commit.signature.wasSignedByGitHub : null
    }));
}

main().catch(e => {
    console.log(JSON.stringify({error: e.message}));
    process.exit(1);
});
