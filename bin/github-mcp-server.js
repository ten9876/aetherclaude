#!/usr/bin/env node
/**
 * AetherClaude GitHub MCP Server v3
 * SECURITY: All HTTP requests use Node.js native https module.
 * No subprocess calls for API requests. Credentials never in process args.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const url = require('url');

const UPSTREAM_REPO = 'ten9876/AetherSDR';
const FORK_OWNER = 'AetherClaude';
const ENV_FILE = '/Users/aetherclaude/.env';
const APP_KEY_FILE = '/Users/aetherclaude/.github-app-key.pem';
const AUDIT_LOG = '/Users/aetherclaude/logs/mcp-audit.log';
const PROXY = process.env.HTTPS_PROXY || '';
const MAX_COMMENT_LENGTH = 16000;
const MAX_PR_BODY_LENGTH = 8000;

const rateLimits = {};
function checkRateLimit(key, max) {
    const now = Date.now();
    if (!rateLimits[key]) rateLimits[key] = [];
    rateLimits[key] = rateLimits[key].filter(t => now - t < 3600000);
    if (rateLimits[key].length >= max) throw new Error(`RATE LIMITED: ${key}`);
    rateLimits[key].push(now);
}

const CRED_RE = [/ghp_[A-Za-z0-9]{36}/, /ghs_[A-Za-z0-9]{36}/, /github_pat_[A-Za-z0-9_]{80,}/, /sk-ant-[A-Za-z0-9\-]{40,}/, /-----BEGIN.*PRIVATE KEY-----/, /AKIA[A-Z0-9]{16}/];
function validateContent(text, maxLen) {
    if (text.length > (maxLen || MAX_COMMENT_LENGTH)) throw new Error(`BLOCKED: Content too long (${text.length})`);
    if (CRED_RE.some(p => p.test(text))) throw new Error('BLOCKED: Content contains credential pattern');
}

function loadEnv() {
    const env = {};
    for (const line of fs.readFileSync(ENV_FILE, 'utf8').split('\n')) {
        const m = line.match(/^([A-Z_]+)=(.+)$/);
        if (m) env[m[1]] = m[2];
    }
    return env;
}

function audit(op, args, result) {
    const safe = String(result).replace(/ghp_[A-Za-z0-9]{36}/g,'ghp_***').replace(/ghs_[A-Za-z0-9]{36}/g,'ghs_***').replace(/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,'***jwt***').substring(0,200);
    const nums = {};
    if (typeof args === 'object' && args) {
        for (const k of ['issue_number','pr_number','discussion_number','discussion_id','sha','run_id','max_results','query','title','head','base']) {
            if (args[k] !== undefined) nums[k] = args[k];
        }
    }
    try { fs.appendFileSync(AUDIT_LOG, JSON.stringify({timestamp:new Date().toISOString(),operation:op,args:typeof args==='object'?Object.keys(args):[],args_data:nums,result:safe})+'\n'); } catch{}
}

// --- JWT + App Token ---
let cachedToken = null, cachedExpiry = 0;
function makeJWT() {
    const env = loadEnv(), pk = fs.readFileSync(APP_KEY_FILE,'utf8'), now = Math.floor(Date.now()/1000);
    const h = Buffer.from('{"alg":"RS256","typ":"JWT"}').toString('base64url');
    const p = Buffer.from(JSON.stringify({iat:now-60,exp:now+600,iss:env.GITHUB_APP_ID})).toString('base64url');
    const s = crypto.createSign('RSA-SHA256'); s.update(`${h}.${p}`);
    return `${h}.${p}.${s.sign(pk,'base64url')}`;
}
async function getAppToken() {
    if (cachedToken && Date.now() < cachedExpiry) return cachedToken;
    const jwt = makeJWT();
    const installs = await ghAPI('GET','/app/installations',null,jwt,true);
    // Pick the upstream (ten9876) installation, not the fork
    const upstream = installs.find(i => i.account.login === UPSTREAM_REPO.split('/')[0]) || installs[0];
    const tok = await ghAPI('POST',`/app/installations/${upstream.id}/access_tokens`,{permissions:{contents:'write',issues:'write',pull_requests:'write',actions:'read',metadata:'read'}},jwt,true);
    cachedToken = tok.token; cachedExpiry = Date.now() + 50*60*1000;
    return cachedToken;
}

// --- Native HTTPS through proxy (NO curl, NO subprocess) ---
function ghAPI(method, path, body, token, bearer) {
    return new Promise((resolve, reject) => {
        const p = url.parse(PROXY);
        const cr = http.request({host:p.hostname,port:parseInt(p.port)||8888,method:'CONNECT',path:'api.github.com:443'});
        cr.on('connect',(res,sock) => {
            if (res.statusCode !== 200) { reject(new Error(`Proxy CONNECT ${res.statusCode}`)); return; }
            const hdrs = {'Authorization':`${bearer?'Bearer':'token'} ${token}`,'Accept':'application/vnd.github+json','User-Agent':'AetherClaude-MCP/3.0','Host':'api.github.com'};
            if (body) hdrs['Content-Type'] = 'application/json';
            const r = https.request({host:'api.github.com',socket:sock,rejectUnauthorized:true,servername:'api.github.com',method,path,headers:hdrs},(resp) => {
                let d=''; resp.on('data',c=>d+=c); resp.on('end',()=>{
                    try{const parsed=JSON.parse(d);if(resp.statusCode>=400){reject(new Error(`GitHub API ${resp.statusCode}: ${parsed.message||d.substring(0,100)}`))}else{resolve(parsed)}}
                    catch{if(resp.statusCode>=400){reject(new Error(`GitHub API ${resp.statusCode}: ${d.substring(0,100)}`))}else{resolve(d)}}
                });
            });
            r.on('error',reject);
            if (body) r.write(JSON.stringify(body));
            r.end();
        });
        cr.on('error',reject); cr.end();
    });
}
function ghDiff(path, token) {
    return new Promise((resolve, reject) => {
        const p = url.parse(PROXY);
        const cr = http.request({host:p.hostname,port:parseInt(p.port)||8888,method:'CONNECT',path:'api.github.com:443'});
        cr.on('connect',(res,sock) => {
            if (res.statusCode !== 200) { reject(new Error(`Proxy CONNECT ${res.statusCode}`)); return; }
            const r = https.request({host:'api.github.com',socket:sock,rejectUnauthorized:true,servername:'api.github.com',method:'GET',path,headers:{'Authorization':`token ${token}`,'Accept':'application/vnd.github.diff','User-Agent':'AetherClaude-MCP/3.0','Host':'api.github.com'}},(resp) => {
                let d=''; resp.on('data',c=>d+=c); resp.on('end',()=>resolve(d));
            });
            r.on('error',reject); r.end();
        });
        cr.on('error',reject); cr.end();
    });
}
async function ghGQL(query, vars, token) { return await ghAPI('POST','/graphql',{query,...(vars?{variables:vars}:{})},token,false); }

// --- Tools ---
const tools = {
    read_issue:{description:'Read a GitHub issue',inputSchema:{type:'object',properties:{issue_number:{type:'number'}},required:['issue_number']}},
    list_issue_comments:{description:'List comments on an issue',inputSchema:{type:'object',properties:{issue_number:{type:'number'}},required:['issue_number']}},
    comment_on_issue:{description:'Post a comment on an issue',inputSchema:{type:'object',properties:{issue_number:{type:'number'},body:{type:'string'}},required:['issue_number','body']}},
    search_issues:{description:'Search issues',inputSchema:{type:'object',properties:{query:{type:'string'},max_results:{type:'number'}},required:['query']}},
    list_open_prs:{description:'List open PRs',inputSchema:{type:'object',properties:{max_results:{type:'number'}},required:[]}},
    create_pull_request:{description:'Create a PR from fork',inputSchema:{type:'object',properties:{title:{type:'string'},body:{type:'string'},head:{type:'string'},base:{type:'string'}},required:['title','body','head','base']}},
    create_pr_review:{description:'Post a PR review (COMMENT only)',inputSchema:{type:'object',properties:{pr_number:{type:'number'},body:{type:'string'}},required:['pr_number','body']}},
    list_pr_files:{description:'List files changed in a PR',inputSchema:{type:'object',properties:{pr_number:{type:'number'}},required:['pr_number']}},
    get_pr_diff:{description:'Get raw diff of a PR',inputSchema:{type:'object',properties:{pr_number:{type:'number'}},required:['pr_number']}},
    get_check_runs:{description:'Get CI check runs for a commit',inputSchema:{type:'object',properties:{sha:{type:'string'}},required:['sha']}},
    get_ci_run_log:{description:'Get failed CI job info',inputSchema:{type:'object',properties:{run_id:{type:'number'}},required:['run_id']}},
    list_discussions:{description:'List recent Discussions',inputSchema:{type:'object',properties:{max_results:{type:'number'}},required:[]}},
    read_discussion:{description:'Read a Discussion with comments',inputSchema:{type:'object',properties:{discussion_number:{type:'number'}},required:['discussion_number']}},
    comment_on_discussion:{description:'Reply to a Discussion',inputSchema:{type:'object',properties:{discussion_id:{type:'string'},body:{type:'string'}},required:['discussion_id','body']}}
};

async function handleToolCall(name, args) {
    try {
        const t = await getAppToken(), env = loadEnv();
        let result;
        switch(name) {
        case 'read_issue': { const i=await ghAPI('GET',`/repos/${UPSTREAM_REPO}/issues/${args.issue_number}`,null,t); result=JSON.stringify({number:i.number,title:i.title,body:i.body,state:i.state,labels:(i.labels||[]).map(l=>l.name),user:i.user.login,author_association:i.author_association,created_at:i.created_at,updated_at:i.updated_at,assignees:(i.assignees||[]).map(a=>a.login)}); break; }
        case 'list_issue_comments': { const c=await ghAPI('GET',`/repos/${UPSTREAM_REPO}/issues/${args.issue_number}/comments?per_page=50`,null,t); result=JSON.stringify(c.map(x=>({id:x.id,user:x.user.login,author_association:x.author_association,body:x.body,created_at:x.created_at}))); break; }
        case 'comment_on_issue': { checkRateLimit(`ci_${args.issue_number}`,4); checkRateLimit('cg',100); validateContent(args.body); const c=await ghAPI('POST',`/repos/${UPSTREAM_REPO}/issues/${args.issue_number}/comments`,{body:args.body},t); result=JSON.stringify({id:c.id,url:c.html_url}); break; }
        case 'search_issues': { const q=encodeURIComponent(`repo:${UPSTREAM_REPO} ${args.query}`); const d=await ghAPI('GET',`/search/issues?q=${q}&per_page=${Math.min(args.max_results||10,30)}`,null,t); result=JSON.stringify({total_count:d.total_count,items:(d.items||[]).map(i=>({number:i.number,title:i.title,state:i.state,user:i.user.login,labels:(i.labels||[]).map(l=>l.name),created_at:i.created_at,updated_at:i.updated_at,is_pull_request:!!i.pull_request}))}); break; }
        case 'list_open_prs': { const ps=await ghAPI('GET',`/repos/${UPSTREAM_REPO}/pulls?state=open&sort=created&direction=desc&per_page=${Math.min(args.max_results||10,30)}`,null,t); result=JSON.stringify(ps.map(p=>({number:p.number,title:p.title,user:p.user.login,author_association:p.author_association,head_sha:p.head.sha,head_ref:p.head.ref,labels:(p.labels||[]).map(l=>l.name),draft:p.draft,created_at:p.created_at,updated_at:p.updated_at}))); break; }
        case 'create_pull_request': { checkRateLimit('pr',10); validateContent(args.title,200); validateContent(args.body,MAX_PR_BODY_LENGTH); const p=await ghAPI('POST',`/repos/${UPSTREAM_REPO}/pulls`,{title:args.title,body:args.body,head:`${FORK_OWNER}:${args.head}`,base:args.base,draft:true},t); result=JSON.stringify({number:p.number,url:p.html_url}); break; }
        case 'create_pr_review': { checkRateLimit(`rv_${args.pr_number}`,1); checkRateLimit('rvg',10); validateContent(args.body); const r=await ghAPI('POST',`/repos/${UPSTREAM_REPO}/pulls/${args.pr_number}/reviews`,{body:args.body,event:'COMMENT'},t); result=JSON.stringify({id:r.id,state:r.state}); break; }
        case 'list_pr_files': { const f=await ghAPI('GET',`/repos/${UPSTREAM_REPO}/pulls/${args.pr_number}/files?per_page=100`,null,t); result=JSON.stringify(f.map(x=>({filename:x.filename,status:x.status,additions:x.additions,deletions:x.deletions,changes:x.changes,patch:x.patch?x.patch.substring(0,2000):null}))); break; }
        case 'get_pr_diff': { const r=await ghDiff(`/repos/${UPSTREAM_REPO}/pulls/${args.pr_number}`,t); const l=r.split('\n'); result=l.length>500?l.slice(0,500).join('\n')+`\n...(${l.length} lines)`:r; break; }
        case 'get_check_runs': { const d=await ghAPI('GET',`/repos/${UPSTREAM_REPO}/commits/${args.sha}/check-runs`,null,t); result=JSON.stringify({total_count:d.total_count,check_runs:(d.check_runs||[]).map(c=>({id:c.id,name:c.name,status:c.status,conclusion:c.conclusion,html_url:c.html_url,run_id:c.details_url?c.details_url.match(/runs\/(\d+)/)?.[1]:null}))}); break; }
        case 'get_ci_run_log': { const j=await ghAPI('GET',`/repos/${UPSTREAM_REPO}/actions/runs/${args.run_id}/jobs`,null,t); const f=(j.jobs||[]).find(x=>x.conclusion==='failure'); if(!f){result=JSON.stringify({message:'No failed jobs'});break;} result=JSON.stringify({job_name:f.name,conclusion:f.conclusion,failed_steps:(f.steps||[]).filter(s=>s.conclusion==='failure').map(s=>s.name),steps:(f.steps||[]).map(s=>({name:s.name,status:s.status,conclusion:s.conclusion}))}); break; }
        case 'list_discussions': { const[o,r]=UPSTREAM_REPO.split('/'); const g=await ghGQL(`query($o:String!,$r:String!,$l:Int!){repository(owner:$o,name:$r){discussions(first:$l,orderBy:{field:CREATED_AT,direction:DESC}){nodes{id number title author{login}createdAt updatedAt category{name}comments{totalCount}locked}}}}`,{o,r,l:Math.min(args.max_results||10,20)},t); result=JSON.stringify((g.data?.repository?.discussions?.nodes||[]).map(d=>({id:d.id,number:d.number,title:d.title,author:d.author?.login,category:d.category?.name,comment_count:d.comments?.totalCount||0,locked:d.locked,created_at:d.createdAt,updated_at:d.updatedAt}))); break; }
        case 'read_discussion': { const[o,r]=UPSTREAM_REPO.split('/'); const g=await ghGQL(`query($o:String!,$r:String!,$n:Int!){repository(owner:$o,name:$r){discussion(number:$n){id number title body author{login}createdAt category{name}locked comments(first:50){nodes{id body author{login}createdAt}}}}}`,{o,r,n:args.discussion_number},t); const d=g.data?.repository?.discussion; if(!d)throw new Error(`Discussion #${args.discussion_number} not found`); result=JSON.stringify({id:d.id,number:d.number,title:d.title,body:d.body,author:d.author?.login,category:d.category?.name,locked:d.locked,created_at:d.createdAt,comments:(d.comments?.nodes||[]).map(c=>({id:c.id,author:c.author?.login,body:c.body,created_at:c.createdAt}))}); break; }
        case 'comment_on_discussion': { checkRateLimit(`dc_${args.discussion_id}`,4); checkRateLimit('dcg',10); validateContent(args.body); const g=await ghGQL(`mutation($id:ID!,$b:String!){addDiscussionComment(input:{discussionId:$id,body:$b}){comment{id url}}}`,{id:args.discussion_id,b:args.body},t); const c=g.data?.addDiscussionComment?.comment; if(!c)throw new Error(g.errors?.map(e=>e.message).join('; ')||'GraphQL error'); result=JSON.stringify({id:c.id,url:c.url}); break; }
        default: throw new Error(`Unknown tool: ${name}`);
        }
        audit(name,args,result); return {content:[{type:'text',text:result}]};
    } catch(e) { audit(name,args,`ERROR: ${e.message}`); return {content:[{type:'text',text:`Error: ${e.message}`}],isError:true}; }
}

// --- MCP stdio ---
let buf='';
process.stdin.setEncoding('utf8');
process.stdin.on('data',chunk=>{buf+=chunk;let i;while((i=buf.indexOf('\n'))!==-1){const l=buf.substring(0,i).trim();buf=buf.substring(i+1);if(l)handleMsg(l)}});
async function handleMsg(line){
    let m; try{m=JSON.parse(line)}catch{return}
    let r;
    switch(m.method){
    case 'initialize': r={jsonrpc:'2.0',id:m.id,result:{protocolVersion:'2024-11-05',capabilities:{tools:{}},serverInfo:{name:'aetherclaude-github',version:'3.0.0'}}}; break;
    case 'notifications/initialized': return;
    case 'tools/list': r={jsonrpc:'2.0',id:m.id,result:{tools:Object.entries(tools).map(([n,d])=>({name:n,description:d.description,inputSchema:d.inputSchema}))}}; break;
    case 'tools/call': const res=await handleToolCall(m.params.name,m.params.arguments); r={jsonrpc:'2.0',id:m.id,result:res}; break;
    default: r={jsonrpc:'2.0',id:m.id,error:{code:-32601,message:`Unknown: ${m.method}`}};
    }
    if(r) process.stdout.write(JSON.stringify(r)+'\n');
}
process.stdin.resume();
