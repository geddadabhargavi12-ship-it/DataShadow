'use strict';
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns').promises;
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { domainToASCII, domainToUnicode } = require('node:url');
const { MongoClient, ObjectId } = require('mongodb');

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const TIMEOUT = 4500;
const MAX_BODY = 300 * 1024;
const SCAN_WINDOW_MS = 60_000;
const SCAN_LIMIT_PER_WINDOW = 8;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_LIMIT_PER_WINDOW = 8;
const scryptAsync = promisify(crypto.scrypt);
let db = null;
let dbError = null;
let mongoClient = null;
let listenFailed = false;
const scanWindows = new Map();
const authWindows = new Map();

function json(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(data), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(data);
}
function fail(message, status = 400) { const e = new Error(message); e.status = status; throw e; }
function validUrl(input) {
  if (typeof input !== 'string' || input.length > 2048) fail('Enter a valid public website URL.');
  let u;
  try { u = new URL(input); } catch { fail('Enter a valid public website URL.'); }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || !u.hostname) fail('Only public HTTP and HTTPS URLs are supported.');
  u.hash = '';
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.test') || host.endsWith('.invalid')) fail('This hostname is not publicly routable.');
  if (net.isIP(host) && !isPublicIp(host)) fail('Private, loopback, and reserved IP addresses are not allowed.');
  return u;
}
function ipv4Public(ip) {
  const p = ip.split('.').map(Number); if (p.length !== 4 || p.some(n => n < 0 || n > 255)) return false;
  const [a,b] = p;
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 0 || b === 168 || (b === 88 && p[2] === 99))) || (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0));
}
function ipv6Groups(ip) {
  let s = ip.toLowerCase().split('%')[0];
  if (s.includes('.')) { const at=s.lastIndexOf(':'); const v4=s.slice(at+1).split('.').map(Number); if(v4.length!==4) return null; s=s.slice(0,at)+':'+((v4[0]<<8)|v4[1]).toString(16)+':'+((v4[2]<<8)|v4[3]).toString(16); }
  const halves=s.split('::'); if(halves.length>2) return null;
  const left=halves[0]?halves[0].split(':'):[], right=halves.length===2&&halves[1]?halves[1].split(':'):[];
  const groups=halves.length===2?[...left,...Array(8-left.length-right.length).fill('0'),...right]:left;
  if(groups.length!==8) return null; const n=groups.map(x=>parseInt(x||'0',16)); return n.some(Number.isNaN)?null:n;
}
function isPublicIp(ip) {
  const v=net.isIP(ip); if(v===4) return ipv4Public(ip); if(v!==6) return false;
  const g=ipv6Groups(ip); if(!g) return false;
  // Only global unicast 2000::/3 is accepted; exclude documentation and transition/special ranges.
  return (g[0]&0xe000)===0x2000 && !(g[0]===0x2001 && (g[1]<=0x01ff || g[1]===0x0db8 || g[1]===0x0002)) && !(g[0]===0x2002);
}
async function resolvePublic(host) {
  const ip = net.isIP(host);
  const records = ip ? [{ address: host, family: ip }] : await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length || records.some(r => !isPublicIp(r.address))) fail('The hostname resolves to a private or reserved address; the request was blocked.', 400);
  return records;
}
function withTimeout(promise, ms) { return new Promise((resolve,reject)=>{ const timer=setTimeout(()=>reject(Object.assign(new Error('The website request timed out.'),{code:'ETIMEDOUT'})),ms); Promise.resolve(promise).then(value=>{clearTimeout(timer);resolve(value)},error=>{clearTimeout(timer);reject(error)}); }); }
function requestOnce(u, method = 'GET', maxBytes = MAX_BODY, timeoutMs = TIMEOUT) {
  return new Promise(async (resolve, reject) => {
    let records;
    try { records = await withTimeout(resolvePublic(u.hostname.replace(/^\[|\]$/g, '')),timeoutMs); } catch (e) { reject(e); return; }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, { method, timeout: timeoutMs, headers: { 'user-agent': 'DataShadow/1.0 (website configuration inspection)', accept: 'text/html,application/xhtml+xml,*/*;q=0.5' }, lookup: (_host, opts, cb) => opts?.all ? cb(null, records) : cb(null, records[0].address, records[0].family), rejectUnauthorized: true, servername: u.hostname.replace(/^\[|\]$/g, '') }, res => {
      const socket=res.socket;
      const peer=socket?.encrypted&&socket.getPeerCertificate?socket.getPeerCertificate():null;
      const tls=socket?.encrypted?{authorized:socket.authorized===true,authorizationError:socket.authorizationError||null,validFrom:peer?.valid_from||null,validTo:peer?.valid_to||null,issuer:peer?.issuer?.O||peer?.issuer?.CN||null,subjectAltName:peer?.subjectaltname||null}:null;
      const chunks=[]; let size=0;
      res.on('data', c => { size += c.length; if(size <= maxBytes) chunks.push(c); else req.destroy(new Error('Response exceeded the size limit.')); });
      res.on('end', () => resolve({ status: res.statusCode || 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), url: u.href, tls }));
    });
    const timer=setTimeout(()=>req.destroy(Object.assign(new Error('The website request timed out.'),{code:'ETIMEDOUT'})),timeoutMs);
    req.on('close',()=>clearTimeout(timer));
    req.on('timeout', () => req.destroy(Object.assign(new Error('The website request timed out.'), { code: 'ETIMEDOUT' })));
    req.on('error', reject); req.end();
  });
}
async function fetchSafe(input, method='GET', maxBytes=MAX_BODY, deadline=Date.now()+8000) {
  let u=validUrl(input); const redirectChain=[]; const tlsObservations=[];
  for(let i=0;i<=3;i++) {
    const remaining=deadline-Date.now(); if(remaining<=0) fail('The website request timed out.',502);
    const r=await requestOnce(u,method,maxBytes,Math.min(TIMEOUT,remaining));
    if(u.protocol==='https:') tlsObservations.push({url:normalizedUrl(u.href),...r.tls});
    if([301,302,303,307,308].includes(r.status) && r.headers.location) {
      if(i===3) fail('The website exceeded the redirect limit.', 502);
      const next=validUrl(new URL(r.headers.location,u).href);
      redirectChain.push({from:u.href,status:r.status,to:next.href});
      u=next; continue;
    }
    return {...r,redirectChain,tlsObservations};
  }
}
const CATEGORIES={connection:'Connection security',configuration:'Security configuration',privacy:'Privacy transparency',behavior:'Observable behavior'};
const FINDING_CATEGORY={https:'connection',tls:'connection',redirect:'connection',csp:'configuration',hsts:'configuration',nosniff:'configuration',referrer:'configuration',permissions:'configuration',response:'behavior',privacy:'privacy',domain_similarity:'connection'};
function finding(id,name,status,explanation,evidence,action,details={}) {
  const category=details.category||FINDING_CATEGORY[id]||'behavior';
  const severity=details.severity||(status==='FAIL'?'high':status==='REVIEW'?(category==='configuration'?'low':'medium'):'info');
  return {id,name,status,category:details.categoryLabel||CATEGORIES[category]||category,severity,confidence:details.confidence||(status==='UNKNOWN'?'low':'high'),explanation,beginnerExplanation:details.beginnerExplanation||explanation,technicalExplanation:details.technicalExplanation||explanation,impact:details.impact||explanation,evidence,rawEvidence:details.rawEvidence??evidence,action,remediation:details.remediation||{summary:action,nginx:null,node:null,caution:null},observedAt:details.observedAt||new Date()};
}
function summarize(findings) { const counts={PASS:0,REVIEW:0,FAIL:0,UNKNOWN:0}; for(const f of findings) if(counts[f.status]!==undefined) counts[f.status]++; return counts; }
function checkPoints(status) { return status==='PASS'?100:status==='REVIEW'?50:status==='FAIL'?0:null; }
function categoryScores(findings,privacy,behaviorStatus) {
  const sets={connection:['https','redirect','tls'],configuration:['csp','hsts','nosniff','referrer','permissions']};
  const categories={};
  for(const [key,ids] of Object.entries(sets)) {
    const vals=findings.filter(f=>ids.includes(f.id)).map(f=>checkPoints(f.status)).filter(v=>v!==null);
    categories[key]={name:CATEGORIES[key],score:vals.length?Math.round(vals.reduce((a,b)=>a+b,0)/vals.length):null,assessed:vals.length,total:ids.length};
  }
  const privacyTopics=privacy?.topics||[];
  const privacyAssessed=privacyTopics.filter(t=>t.status!=='UNKNOWN').length;
  categories.privacy={name:CATEGORIES.privacy,score:null,assessed:privacyAssessed,total:privacyTopics.length,coveragePercent:privacyTopics.length?Math.round(privacyAssessed/privacyTopics.length*100):0,interpretation:'Privacy wording is shown as topic coverage, not a quality score; matching wording does not establish that practices are good or actually followed.'};
  const behaviorValue=checkPoints(behaviorStatus);
  categories.behavior={name:CATEGORIES.behavior,score:behaviorValue,assessed:behaviorValue===null?0:1,total:1};
  const weights={connection:40,configuration:40,privacy:0,behavior:20};
  const available=Object.entries(categories).filter(([,v])=>v.score!==null);
  const weightTotal=available.reduce((n,[k])=>n+weights[k],0);
  const score=weightTotal?Math.round(available.reduce((n,[k,v])=>n+v.score*weights[k],0)/weightTotal):null;
  const tech=findings.filter(f=>['https','redirect','tls','csp','hsts','nosniff','referrer','permissions'].includes(f.id));
  const observed=tech.filter(f=>f.status!=='UNKNOWN').length;
  const evidenceCoverage=Math.round(observed/8*100);
  const enoughEvidence=observed>=4;
  return {score:!enoughEvidence?null:score,label:!enoughEvidence?'Not enough data':score>=80?'Stronger signals':score>=55?'Mixed signals':'Needs attention',categories,evidenceCoverage,assessed:observed,total:8,formula:'Configuration scores: PASS = 100, REVIEW = 50, FAIL = 0; UNKNOWN is omitted. The indicator combines connection (40%), security configuration (40%), and observable response behavior (20%); unavailable categories are omitted and remaining weights are normalized. Privacy wording appears separately as topic coverage and does not affect this score. At least 4 of 8 connection/configuration checks must complete before an overall score is shown. This is not a probability of safety.'};
}
const POLICY_TOPICS=[
  ['personal_information','Personal information',/personal (?:information|data)|collect(?:s|ing)? (?:your )?(?:information|data)|information we collect/i],
  ['purposes','Collection purposes',/use (?:your )?(?:information|data) to|purpose of (?:processing|collection)|why we (?:collect|use)|process(?:ing)? purposes/i],
  ['cookies_tracking','Cookies and tracking',/cookies?|tracking technologies|pixel tags|web beacons/i],
  ['third_party_sharing','Third-party sharing',/third[- ]part(?:y|ies)|share(?:s|d)? (?:your )?(?:data|information)|disclos(?:e|ure).{0,30}(?:partner|vendor|service provider)/i],
  ['advertising_analytics','Advertising and analytics',/advertis(?:e|ing|ers)|analytics|personalized ads|targeted advertising/i],
  ['retention','Data retention',/data retention|retain.{0,40}(?:data|information)|how long.{0,40}(?:keep|store)/i],
  ['deletion_rights','Deletion and user rights',/delete.{0,40}(?:data|account|information)|right to (?:access|delete|correct|object)|privacy rights|opt[- ]out/i],
  ['security_practices','Security practices',/security measures|protect.{0,40}(?:data|information)|safeguards|encryption/i],
  ['contact','Contact information',/contact us|privacy officer|data protection officer|privacy@|email us/i],
  ['policy_updates','Policy updates',/last updated|effective date|updated on|changes to this (?:privacy )?policy/i]
];
function readableText(html) {
  return html.replace(/<(script|style|noscript)[\s\S]*?<\/\1>/gi,' ').replace(/<(br|\/p|\/li|\/div|\/h[1-6])\b[^>]*>/gi,'. ').replace(/<[^>]+>/g,' ')
    .replace(/&nbsp;|&#160;/gi,' ').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&lt;/gi,'<').replace(/&gt;/gi,'>')
    .replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Math.min(Number(n),0x10ffff))).replace(/&#x([\da-f]+);/gi,(_,n)=>String.fromCodePoint(Math.min(parseInt(n,16),0x10ffff))).replace(/\s+/g,' ').trim().slice(0,100000);
}
function analyzePolicy(text,policyUrl) {
  const sentences=text.split(/(?<=[.!?])\s+/).filter(Boolean);
  const topics=POLICY_TOPICS.map(([id,label,pattern])=>{
    const sentence=sentences.find(s=>pattern.test(s));
    return {id,label,status:sentence?'FOUND':'NOT_FOUND',excerpt:sentence?sentence.slice(0,360):null,explanation:sentence?`The accessible policy text contains a statement about ${label.toLowerCase()}.`:`No matching statement about ${label.toLowerCase()} was found in the text analyzed. This does not prove the practice is absent.`};
  });
  const fingerprint=crypto.createHash('sha256').update(text.toLowerCase().replace(/\s+/g,' ').trim()).digest('hex');
  return {status:'REVIEW',policyUrl,fingerprint,topics,indicators:topics.filter(t=>t.status==='FOUND').map(t=>({topic:t.id,statement:t.excerpt})),message:'This summarizes statements found in the linked policy, not the website’s actual data practices.'};
}
function findPolicyLinks(html,baseUrl) {
  const tags=html.match(/<a\b[^>]*href\s*=\s*["'][^"']+["'][^>]*>[\s\S]*?<\/a>/ig)||[];
  const links=[];
  for(const tag of tags) {
    const href=(tag.match(/href\s*=\s*["']([^"']+)["']/i)||[])[1];
    const label=(tag.replace(/<[^>]*>/g,' ').toLowerCase());
    if(href&&/privacy|data protection|your data/.test(label+' '+href.toLowerCase())) try { links.push(validUrl(new URL(href,baseUrl).href).href); } catch {}
  }
  const base=new URL(baseUrl); const paths=['/privacy-policy','/privacy','/privacy-notice','/policies/privacy','/legal/privacy'];
  for(const p of paths) { const candidate=new URL(p,base.origin).href; if(!links.includes(candidate)) links.push(candidate); }
  return links.slice(0,6);
}
function editDistance(a,b) {
  const row=Array.from({length:b.length+1},(_,i)=>i);
  for(let i=1;i<=a.length;i++){let diagonal=row[0];row[0]=i;for(let j=1;j<=b.length;j++){const old=row[j];row[j]=Math.min(row[j]+1,row[j-1]+1,diagonal+(a[i-1]===b[j-1]?0:1));diagonal=old;}}
  return row[b.length];
}
const CONFUSABLES={'\u0430':'a','\u0435':'e','\u043e':'o','\u0440':'p','\u0441':'c','\u0445':'x','\u0443':'y','\u0456':'i','\u0458':'j','0':'o','1':'l'};
function domainSimilarity(host,expectedDomain) {
  const unicode=domainToUnicode(host); const skeleton=[...unicode.toLowerCase()].map(c=>CONFUSABLES[c]||c).join('');
  const signals=[];
  if(host.toLowerCase().startsWith('xn--')||[...unicode].some(c=>c.codePointAt(0)>127)) signals.push({reason:'Internationalized hostname contains non-ASCII characters.',observed:unicode});
  if(skeleton!==unicode.toLowerCase()) signals.push({reason:'Hostname contains characters commonly used as visual lookalikes.',observed:unicode});
  if(expectedDomain) {
    let expected;
    try { const candidate=expectedDomain.includes('://')?new URL(expectedDomain):new URL(`https://${expectedDomain}`); if(candidate.pathname!=='/'||candidate.search||candidate.hash||candidate.username||candidate.password) expected=null; else expected=domainToASCII(candidate.hostname.toLowerCase().replace(/^www\./,'')); } catch { expected=null; }
    if(expected) {
      const actual=domainToASCII(host.toLowerCase().replace(/^www\./,''));
      if(actual!==expected) {
        if(actual.startsWith(`${expected}.`)) signals.push({reason:'The expected domain appears as a subdomain prefix, followed by a different domain.',observed:host,expected});
        else if(editDistance(actual,expected)<=2) signals.push({reason:'Hostname spelling is unusually close to the expected domain.',observed:host,expected,distance:editDistance(actual,expected)});
        else signals.push({reason:'The scanned hostname does not match the expected domain.',observed:host,expected});
      }
    }
  }
  return {status:signals.length?'REVIEW':'PASS',host:unicode,expectedDomain:expectedDomain||null,signals,disclaimer:'Similarity is a heuristic only. It does not establish domain ownership or prove phishing.'};
}
function normalizedUrl(input) {
  const u=new URL(input);u.hash='';
  for(const key of [...u.searchParams.keys()]) if(/^(utm_.+|gclid|gbraid|wbraid|fbclid|msclkid|dclid|mc_cid|mc_eid)$/i.test(key)) u.searchParams.delete(key);
  return u.href;
}
async function inspect(input,expectedDomain=null){ return inspectAdvanced(input,expectedDomain); }
const FIX_GUIDES={
  redirect:{summary:'Send plain HTTP traffic to the equivalent HTTPS URL.',nginx:'server {\n  listen 80;\n  server_name example.com www.example.com;\n  return 301 https://$host$request_uri;\n}',node:"if (!req.socket.encrypted) {\n  res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });\n  return res.end();\n}",caution:'Only enable the redirect after HTTPS is correctly configured for every hostname.'},
  csp:{summary:'Start with a policy tailored to the scripts, styles, and embeds your site actually uses.',nginx:"add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\" always;",node:"res.setHeader('Content-Security-Policy', \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\");",caution:'A restrictive CSP can block legitimate site features. Test with Content-Security-Policy-Report-Only first.'},
  hsts:{summary:'Ask browsers to remember HTTPS after confirming every affected subdomain supports it.',nginx:'add_header Strict-Transport-Security "max-age=31536000" always;',node:"res.setHeader('Strict-Transport-Security', 'max-age=31536000');",caution:'Do not add includeSubDomains or preload until all subdomains are HTTPS-ready.'},
  nosniff:{summary:'Tell browsers to respect the declared MIME type.',nginx:'add_header X-Content-Type-Options "nosniff" always;',node:"res.setHeader('X-Content-Type-Options', 'nosniff');",caution:'Make sure static assets use correct Content-Type values.'},
  referrer:{summary:'Limit how much URL information is sent to other sites.',nginx:'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',node:"res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');",caution:'Choose a policy that fits your analytics and cross-site flows.'},
  permissions:{summary:'Disable browser capabilities the site does not use, then allow only required features.',nginx:'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',node:"res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');",caution:'Review embedded services and features before disabling permissions.'}
};
function networkExplanation(error) {
  if(error?.code==='ETIMEDOUT') return 'The request timed out.';
  if(error?.code==='ENOTFOUND'||error?.code==='EAI_AGAIN') return 'The public hostname could not be resolved.';
  if(error?.status===400) return error.message;
  if(['CERT_HAS_EXPIRED','CERT_NOT_YET_VALID','UNABLE_TO_VERIFY_LEAF_SIGNATURE','ERR_TLS_CERT_ALTNAME_INVALID','DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_GET_ISSUER_CERT','UNABLE_TO_GET_ISSUER_CERT_LOCALLY'].includes(error?.code)) return 'TLS certificate validation failed.';
  return 'The website could not be reached from the scanner.';
}
function unknownPolicyTopics() { return POLICY_TOPICS.map(([id,label])=>({id,label,status:'UNKNOWN',excerpt:null,explanation:'Policy text could not be analyzed safely.'})); }
async function inspectAdvanced(input,expectedDomain=null) {
  const startedAt=new Date(); const requested=validUrl(input); const reportUrl=normalizedUrl(requested.href); const deadline=Date.now()+8000; const findings=[];
  let expected=(expectedDomain||'').trim()||null;
  if(expected) {
    try { const candidate=expected.includes('://')?new URL(expected):new URL(`https://${expected}`); if(candidate.pathname!=='/'||candidate.search||candidate.hash||candidate.username||candidate.password) fail('Expected domain must be a hostname without a path.'); expected=candidate.hostname; }
    catch(error) { if(error.status) throw error; fail('Expected domain must be a valid hostname without a path.'); }
  }
  findings.push(finding('https','HTTPS availability',requested.protocol==='https:'?'PASS':'REVIEW',requested.protocol==='https:'?'The submitted address uses HTTPS.':'The submitted address uses HTTP and does not encrypt the connection.',requested.protocol,requested.protocol==='https:'?'Continue using HTTPS and keep the certificate current.':'Enable HTTPS and redirect HTTP visitors.',{technicalExplanation:'The scanner records the submitted URL scheme; this check alone does not assess application security.',impact:'HTTP traffic can be observed or modified in transit.',remediation:FIX_GUIDES.redirect}));
  const redirectUrl=new URL(requested.href);
  if(requested.protocol==='https:'){redirectUrl.protocol='http:';if(!requested.port||requested.port==='443')redirectUrl.port='';}
  const requests=[fetchSafe(requested.href,'GET',MAX_BODY,deadline)];
  if(requested.protocol==='https:') requests.push(fetchSafe(redirectUrl.href,'GET',64*1024,deadline));
  const outcomes=await Promise.allSettled(requests);
  const primary=outcomes[0]; const response=primary.status==='fulfilled'?primary.value:null; const mainError=primary.status==='rejected'?primary.reason:null;
  let redirectProbe=requested.protocol==='https:'&&outcomes[1]?.status==='fulfilled'?outcomes[1].value:null;
  const redirectError=requested.protocol==='https:'&&outcomes[1]?.status==='rejected'?outcomes[1].reason:null;
  if(requested.protocol==='http:') {
    if(response) {
      const final=new URL(response.url); const status=final.protocol==='https:'?'PASS':'REVIEW';
      findings.push(finding('redirect','HTTP-to-HTTPS redirect',status,status==='PASS'?'The HTTP request ended at HTTPS.':'The HTTP request did not end at HTTPS.',JSON.stringify(response.redirectChain),status==='PASS'?'Keep the redirect enabled for all HTTP routes.':'Configure a permanent HTTP-to-HTTPS redirect.',{technicalExplanation:'The scanner followed and revalidated each redirect, then inspected the final scheme.',remediation:FIX_GUIDES.redirect}));
    } else findings.push(finding('redirect','HTTP-to-HTTPS redirect','UNKNOWN','Redirect behavior could not be verified because the site did not respond.',networkExplanation(mainError),'Retry when the site is available.'));
  } else {
    if(redirectProbe) {
      const status=new URL(redirectProbe.url).protocol==='https:'&&redirectProbe.redirectChain.length>0?'PASS':new URL(redirectProbe.url).protocol==='https:'?'PASS':'REVIEW';
      findings.push(finding('redirect','HTTP-to-HTTPS redirect',status,status==='PASS'?'The HTTP probe ended at HTTPS.':'The HTTP probe remained on HTTP.',JSON.stringify(redirectProbe.redirectChain),status==='PASS'?'Keep the redirect enabled for all HTTP routes.':'Configure a permanent HTTP-to-HTTPS redirect.',{technicalExplanation:'A separate HTTP request was sent to the same public host. Every redirect destination was revalidated.',remediation:FIX_GUIDES.redirect}));
    } else findings.push(finding('redirect','HTTP-to-HTTPS redirect','UNKNOWN','The separate HTTP probe could not be completed.',networkExplanation(redirectError),'Retry the scan when the website is reachable.',{confidence:'low'}));
  }
  let privacy={status:'UNKNOWN',policyUrl:null,fingerprint:null,topics:unknownPolicyTopics(),indicators:[],message:'No accessible privacy policy was analyzed.'};
  let behaviorStatus=null; let observations={headers:{},redirectChain:[],finalUrl:null,status:null,contentType:null,contentLength:null,tls:[]};
  if(response) {
    const finalUrl=new URL(response.url); const tlsObservation=[...(response.tlsObservations||[])].reverse().find(t=>t.authorized!==undefined)||null;
    observations.redirectChain=response.redirectChain.map(r=>({...r,from:normalizedUrl(r.from),to:normalizedUrl(r.to)}));
    observations.finalUrl=normalizedUrl(response.url);observations.status=response.status;observations.contentType=response.headers['content-type']||null;observations.contentLength=response.headers['content-length']||null;observations.tls=response.tlsObservations||[];
    if(finalUrl.protocol==='https:') {
      const status=tlsObservation?.authorized===true?'PASS':tlsObservation?.authorized===false?'FAIL':'UNKNOWN';
      const evidence=tlsObservation?JSON.stringify({authorized:tlsObservation.authorized,issuer:tlsObservation.issuer,validFrom:tlsObservation.validFrom,validTo:tlsObservation.validTo,hostnameMatched:tlsObservation.authorized}):'Certificate metadata unavailable.';
      findings.push(finding('tls','TLS certificate',status,status==='PASS'?'Node.js accepted the certificate chain and hostname.':status==='FAIL'?'The certificate validation did not succeed.':'The response arrived but certificate metadata was unavailable.',evidence,status==='FAIL'?'Renew or correctly configure the certificate for this hostname.':'Retry if certificate details remain unavailable.',{technicalExplanation:'Certificate verification uses Node.js TLS hostname and trust-chain validation with rejectUnauthorized enabled. Hostname matching follows that same verification result.'}));
    } else findings.push(finding('tls','TLS certificate','UNKNOWN','The final response URL uses HTTP, so its certificate could not be evaluated.','Final scheme: HTTP','Configure HTTPS for the destination hostname.'));
    const headerChecks=[
      ['csp','Content-Security-Policy','Helps limit the origins allowed to load active content.'],['hsts','Strict-Transport-Security','Tells browsers to prefer HTTPS on later visits.'],['nosniff','X-Content-Type-Options','Helps stop MIME-type guessing by browsers.'],['referrer','Referrer-Policy','Controls referrer information sent to other sites.'],['permissions','Permissions-Policy','Restricts selected browser capabilities.']
    ];
    const headerNames={csp:'content-security-policy',hsts:'strict-transport-security',nosniff:'x-content-type-options',referrer:'referrer-policy',permissions:'permissions-policy'};
    for(const [id,name,why] of headerChecks) {
      const value=response.headers[headerNames[id]]||null;if(value)observations.headers[name]=String(value).slice(0,500);
      const opts={technicalExplanation:why,rawEvidence:value||'Header absent from final response.',remediation:FIX_GUIDES[id]||null,impact:value?why:'A missing header is a hardening opportunity; by itself it does not prove a vulnerability.'};
      findings.push(finding(id,name,value?'PASS':'REVIEW',value?`${why} The header was present.`:`${why} The header was not present in the inspected response.`,value||'Header absent from final response.',value?'Review the value periodically and keep it aligned with the site.':(FIX_GUIDES[id]?.summary||'Review whether this header fits the site and configure it at the web server or CDN.'),opts));
    }
    behaviorStatus=response.status>=400?'REVIEW':'PASS';
    findings.push(finding('response','HTTP response',behaviorStatus,`The server returned HTTP ${response.status}.`,`Status ${response.status}; content type ${response.headers['content-type']||'not supplied'}; redirect hops ${response.redirectChain.length}.`,behaviorStatus==='PASS'?'Confirm this status is expected for the inspected page.':'Review the response and availability behavior for this route.',{technicalExplanation:'Only response status and selected non-sensitive metadata are retained; the response body is discarded after local policy extraction.',category:'behavior',severity:behaviorStatus==='REVIEW'?'medium':'info',rawEvidence:JSON.stringify({status:response.status,contentType:observations.contentType,contentLength:observations.contentLength,redirectChain:observations.redirectChain})}));
    const policyCandidates=findPolicyLinks(response.body,response.url);
    for(const candidate of policyCandidates) {
      if(Date.now()>=deadline)break;
      try {
        const policyResponse=await fetchSafe(candidate,'GET',256*1024,deadline);
        if(policyResponse.status<200||policyResponse.status>=400)continue;
        const type=String(policyResponse.headers['content-type']||'');if(type&&!/(html|text|xhtml)/i.test(type))continue;
        const text=readableText(policyResponse.body);if(text.length<80)continue;
        privacy=analyzePolicy(text,normalizedUrl(policyResponse.url));break;
      } catch { /* Try the next same-site conventional path while time remains. */ }
    }
  } else {
    const certCodes=['CERT_HAS_EXPIRED','CERT_NOT_YET_VALID','UNABLE_TO_VERIFY_LEAF_SIGNATURE','ERR_TLS_CERT_ALTNAME_INVALID','DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_GET_ISSUER_CERT','UNABLE_TO_GET_ISSUER_CERT_LOCALLY'];
    const certFail=certCodes.includes(mainError?.code);
    findings.push(finding('tls','TLS certificate',certFail?'FAIL':'UNKNOWN',certFail?'The TLS certificate chain or hostname failed validation.':'TLS could not be evaluated because the website response was unavailable.',networkExplanation(mainError),certFail?'Renew or correctly configure the certificate for this hostname.':'Retry when the website is reachable.',{confidence:certFail?'high':'low'}));
    for(const [id,name] of [['csp','Content-Security-Policy'],['hsts','Strict-Transport-Security'],['nosniff','X-Content-Type-Options'],['referrer','Referrer-Policy'],['permissions','Permissions-Policy']])findings.push(finding(id,name,'UNKNOWN','This check could not run because no website response was received.',networkExplanation(mainError),'Retry when the site is reachable.',{confidence:'low',remediation:FIX_GUIDES[id]}));
    findings.push(finding('response','HTTP response','UNKNOWN','No HTTP response metadata was available.',networkExplanation(mainError),'Retry when the site is reachable.',{category:'behavior',confidence:'low'}));
  }
  findings.push(finding('privacy','Privacy policy access',privacy.status==='UNKNOWN'?'UNKNOWN':'PASS',privacy.message,privacy.policyUrl||'No linked or conventional privacy-policy page could be retrieved.',privacy.status==='UNKNOWN'?'Add a clearly linked policy if applicable, then review it directly.':'Review the policy statements against actual site practices.',{category:'privacy',technicalExplanation:'The scanner extracts readable text only; scripts are not executed. Topic matches are keyword-based.'}));
  const similarity=domainSimilarity(requested.hostname,expected);
  if(expected||similarity.signals.length)findings.push(finding('domain_similarity','Domain similarity',similarity.signals.length?'REVIEW':'PASS',similarity.signals.length?'The hostname differs from or resembles the expected domain.':'No configured lookalike heuristic matched.',JSON.stringify(similarity.signals),similarity.signals.length?'Verify the hostname with the site owner using a trusted channel.':'No similarity warning was triggered.',{category:'connection',severity:similarity.signals.length?'medium':'info',confidence:'low',technicalExplanation:similarity.disclaimer}));
  const categoryRatings=categoryScores(findings,privacy,behaviorStatus);
  const complete=response?'complete':'partial';
  return {url:reportUrl,requestedUrl:reportUrl,hostname:requested.hostname.toLowerCase(),expectedDomain:expected,scannedAt:startedAt,completedAt:new Date(),completionStatus:complete,finalStatus:response?.status||null,finalUrl:observations.finalUrl,findings,privacy,observations,domainSimilarity:similarity,categories:categoryRatings.categories,rating:categoryRatings,summary:summarize(findings),evidenceCoverage:categoryRatings.evidenceCoverage,limitations:['This is a limited remote observation, not a vulnerability assessment or proof of safe behavior.','Header absence alone does not prove a vulnerability. Missing policy language does not prove that a data practice is absent.','Privacy policy text is not evidence that the site follows its statements.','Domain resemblance warnings are heuristic and do not establish ownership or phishing.'],errorDetails:mainError?networkExplanation(mainError):null};
}
async function readJson(req) {
  const parts=[]; let size=0;
  for await (const c of req) { size+=c.length; if(size>32768) fail('Request body is too large.',413); parts.push(c); }
  try { return JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { fail('Request body must be valid JSON.'); }
}
function consumeScanAllowance(key,cost=1) {
  const now=Date.now();const active=(scanWindows.get(key)||[]).filter(t=>now-t<SCAN_WINDOW_MS);
  if(active.length+cost>SCAN_LIMIT_PER_WINDOW){scanWindows.set(key,active);return false;}
  for(let i=0;i<cost;i++)active.push(now);scanWindows.set(key,active);
  if(scanWindows.size>1000)for(const [k,times] of scanWindows)if(!times.some(t=>now-t<SCAN_WINDOW_MS))scanWindows.delete(k);
  return true;
}
function consumeAuthAllowance(key) {
  const now=Date.now();const active=(authWindows.get(key)||[]).filter(t=>now-t<AUTH_WINDOW_MS);
  if(active.length>=AUTH_LIMIT_PER_WINDOW){authWindows.set(key,active);return false;}
  active.push(now);authWindows.set(key,active);
  if(authWindows.size>1000)for(const [k,times] of authWindows)if(!times.some(t=>now-t<AUTH_WINDOW_MS))authWindows.delete(k);
  return true;
}
function emailAddress(value) {
  if(typeof value!=='string')fail('Enter a valid email address.');
  const email=value.trim().toLowerCase();
  if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))fail('Enter a valid email address.');
  return email;
}
async function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')) {
  const hash=await scryptAsync(password,salt,64,{N:32768,r:8,p:1,maxmem:64*1024*1024});
  return {salt,hash:Buffer.from(hash).toString('hex')};
}
async function passwordMatches(password,user) {
  const computed=await hashPassword(password,user.passwordSalt);
  const expected=Buffer.from(user.passwordHash,'hex');const actual=Buffer.from(computed.hash,'hex');
  return expected.length===actual.length&&crypto.timingSafeEqual(expected,actual);
}
function sessionTokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function cookieToken(req) {
  const cookie=String(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('datashadow_session='));
  return cookie?cookie.slice('datashadow_session='.length):null;
}
function setSessionCookie(req,res,token,maxAge=Math.floor(SESSION_TTL_MS/1000)) {
  const secure=process.env.NODE_ENV==='production'?'; Secure':'';
  res.setHeader('set-cookie',`datashadow_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAge}${secure}`);
}
async function createSession(req,res,user) {
  const token=crypto.randomBytes(32).toString('base64url');const now=new Date();const expiresAt=new Date(now.getTime()+SESSION_TTL_MS);
  await db.collection('sessions').insertOne({tokenHash:sessionTokenHash(token),userId:user._id,createdAt:now,expiresAt});
  setSessionCookie(req,res,token);
  return {id:user._id.toString(),email:user.email};
}
async function authenticatedUser(req) {
  const token=cookieToken(req);if(!token||token.length>128)return null;
  const session=await db.collection('sessions').findOne({tokenHash:sessionTokenHash(token),expiresAt:{$gt:new Date()}});
  if(!session)return null;
  const user=await db.collection('users').findOne({_id:session.userId},{projection:{email:1}});
  return user?{id:user._id.toString(),email:user.email,_id:user._id}:null;
}
function checkSameOrigin(req) {
  const origin=req.headers.origin;
  if(!origin)return;
  try { if(new URL(origin).host!==req.headers.host)fail('This request origin is not allowed.',403); }
  catch(error) { if(error.status)throw error;fail('This request origin is not allowed.',403); }
}
function compareReports(first,second) {
  const ordered=[first,second].sort((a,b)=>new Date(a.scannedAt)-new Date(b.scannedAt));const [older,newer]=ordered;
  const before=new Map((older.findings||[]).map(f=>[f.id,f]));const after=new Map((newer.findings||[]).map(f=>[f.id,f]));
  const changes=[];
  for(const id of new Set([...before.keys(),...after.keys()])) {
    const a=before.get(id),b=after.get(id);
    if(!a)changes.push({id,kind:'added',before:null,after:b});
    else if(!b)changes.push({id,kind:'removed',before:a,after:null});
    else if(a.status!==b.status||a.rawEvidence!==b.rawEvidence)changes.push({id,kind:a.status!==b.status?'status_changed':'evidence_changed',before:a,after:b});
  }
  const headers={};for(const name of new Set([...Object.keys(older.observations?.headers||{}),...Object.keys(newer.observations?.headers||{})])){const a=older.observations?.headers?.[name]??null,b=newer.observations?.headers?.[name]??null;if(a!==b)headers[name]={before:a,after:b};}
  const oldHash=older.privacy?.fingerprint||null,newHash=newer.privacy?.fingerprint||null;
  const privacyTopics={};const oldTopics=new Map((older.privacy?.topics||[]).map(t=>[t.id,t.status]));const newTopics=new Map((newer.privacy?.topics||[]).map(t=>[t.id,t.status]));
  for(const id of new Set([...oldTopics.keys(),...newTopics.keys()]))if(oldTopics.get(id)!==newTopics.get(id))privacyTopics[id]={before:oldTopics.get(id)||null,after:newTopics.get(id)||null};
  const timeline=[...changes.map(c=>({at:newer.scannedAt,kind:c.kind,label:`${c.id} ${c.kind.replaceAll('_',' ')}`})),...Object.keys(headers).map(name=>({at:newer.scannedAt,kind:'header_changed',label:`${name} changed`})),...(oldHash&&newHash&&oldHash!==newHash?[{at:newer.scannedAt,kind:'policy_text_changed',label:'Privacy policy text fingerprint changed'}]:[])];
  return {hostname:older.hostname,older:{id:String(older._id||older.id||''),scannedAt:older.scannedAt},newer:{id:String(newer._id||newer.id||''),scannedAt:newer.scannedAt},changes,headers,redirect:{before:older.observations?.redirectChain||[],after:newer.observations?.redirectChain||[],changed:JSON.stringify(older.observations?.redirectChain||[])!==JSON.stringify(newer.observations?.redirectChain||[])},https:{before:older.findings?.find(f=>f.id==='https')?.status||'UNKNOWN',after:newer.findings?.find(f=>f.id==='https')?.status||'UNKNOWN'},privacy:{beforeFingerprint:oldHash,afterFingerprint:newHash,textChanged:!!(oldHash&&newHash&&oldHash!==newHash),topics:privacyTopics},overallScore:{before:older.rating?.score??null,after:newer.rating?.score??null},categoryScores:{before:older.categories||{},after:newer.categories||{}},timeline,note:'Differences were observed between scans taken at different times. A change may have benign causes and does not by itself prove improved security, reduced security, or malicious activity.'};
}
async function saveReport(report) {
  if(!db)return {saved:false,reason:'MongoDB is unavailable.'};
  try { const result=await db.collection('scans').insertOne(report);return {saved:true,id:result.insertedId.toString()}; }
  catch(error){dbError=error;db=null;if(mongoClient){mongoClient.close().catch(()=>{});mongoClient=null;}return {saved:false,reason:'MongoDB became unavailable before the report could be saved.'};}
}
const MIME={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml'};
async function route(req,res) {
  const u=new URL(req.url,'http://localhost');
  if(req.method==='GET'&&u.pathname==='/api/health') {
    if(db)try{await db.command({ping:1});}catch(error){dbError=error;db=null;if(mongoClient){mongoClient.close().catch(()=>{});mongoClient=null;}}
    return json(res,200,{status:'ok',database:db?'connected':'disconnected',...(dbError?{databaseError:'MongoDB connection unavailable; scans will run without saving.'}:{})});
  }
  if(req.method==='GET'&&u.pathname==='/api/auth/me') {
    if(!db)return json(res,503,{error:'Authentication is unavailable while MongoDB is disconnected.'});
    const user=await authenticatedUser(req);return user?json(res,200,{user:{id:user.id,email:user.email}}):json(res,401,{error:'Sign in to continue.'});
  }
  if(req.method==='POST'&&['/api/auth/register','/api/auth/login'].includes(u.pathname)) {
    checkSameOrigin(req);
    if(!db)return json(res,503,{error:'Authentication is unavailable while MongoDB is disconnected.'});
    if(!consumeAuthAllowance(req.socket.remoteAddress||'unknown'))return json(res,429,{error:'Too many account attempts. Wait 15 minutes and try again.'});
    const body=await readJson(req);const email=emailAddress(body.email);const password=body.password;
    if(typeof password!=='string'||password.length>128)return json(res,400,{error:'Password must be 10 to 128 characters.'});
    if(u.pathname==='/api/auth/register') {
      if(password.length<10)return json(res,400,{error:'Choose a password with at least 10 characters.'});
      const credentials=await hashPassword(password);
      try {
        const result=await db.collection('users').insertOne({email,passwordSalt:credentials.salt,passwordHash:credentials.hash,createdAt:new Date()});
        const user={_id:result.insertedId,email};const safeUser=await createSession(req,res,user);
        return json(res,201,{user:safeUser});
      } catch(error) { if(error.code===11000)return json(res,409,{error:'An account with this email already exists.'});throw error; }
    }
    const user=await db.collection('users').findOne({email});
    const valid=user?await passwordMatches(password,user):await passwordMatches(password,{passwordSalt:'datashadow-login-check-salt',passwordHash:'0'.repeat(128)});
    if(!user||!valid)return json(res,401,{error:'Email or password is incorrect.'});
    return json(res,200,{user:await createSession(req,res,user)});
  }
  if(req.method==='POST'&&u.pathname==='/api/auth/logout') {
    checkSameOrigin(req);const token=cookieToken(req);if(token&&db)await db.collection('sessions').deleteOne({tokenHash:sessionTokenHash(token)});
    setSessionCookie(req,res,'',0);return json(res,200,{loggedOut:true});
  }
  if(u.pathname.startsWith('/api/')&&!['/api/health'].includes(u.pathname)) {
    if(!db)return json(res,503,{error:'Authentication and saved reports are unavailable while MongoDB is disconnected.'});
    const user=await authenticatedUser(req);if(!user)return json(res,401,{error:'Sign in to continue.'});req.user=user;
    if(['POST','PUT','PATCH','DELETE'].includes(req.method))checkSameOrigin(req);
  }
  if(req.method==='POST'&&u.pathname==='/api/scan') {
    const body=await readJson(req);validUrl(body.url);
    if(body.expectedDomain!==undefined&&typeof body.expectedDomain!=='string')fail('Expected domain must be a hostname string.');
    if(!consumeScanAllowance(req.socket.remoteAddress||'unknown'))return json(res,429,{error:'Scan limit reached. Please wait a minute before scanning again.'});
    const report=await inspectAdvanced(body.url,body.expectedDomain||null);const persistence=await saveReport({...report,ownerId:req.user._id});
    return json(res,persistence.saved?201:200,{...report,...(persistence.id?{id:persistence.id}:{}),persistence});
  }
  if(req.method==='POST'&&u.pathname==='/api/compare') {
    const body=await readJson(req);const urls=Array.isArray(body.urls)?body.urls:[body.leftUrl,body.rightUrl];
    if(urls.length!==2||urls.some(x=>typeof x!=='string'))fail('Provide exactly two website URLs to compare.');urls.forEach(validUrl);
    if(!consumeScanAllowance(req.socket.remoteAddress||'unknown',2))return json(res,429,{error:'This comparison needs two scans; the scan limit has been reached.'});
    const reports=await Promise.all(urls.map(url=>inspectAdvanced(url)));
    const persistence=await Promise.all(reports.map(report=>saveReport({...report,ownerId:req.user._id})));
    reports.forEach((report,i)=>{if(persistence[i].id)report.id=persistence[i].id;report.persistence=persistence[i];});
    return json(res,200,{left:reports[0],right:reports[1],comparison:compareReports(reports[0],reports[1])});
  }
  if(req.method==='GET'&&u.pathname==='/api/privacy-policy') { const target=u.searchParams.get('url');validUrl(target);const report=await inspectAdvanced(target);return json(res,200,{privacy:report.privacy}); }
  if(req.method==='GET'&&u.pathname==='/api/scans') { const docs=await db.collection('scans').find({ownerId:req.user._id}, {projection:{findings:1,privacy:1,summary:1,url:1,hostname:1,scannedAt:1,finalStatus:1,rating:1,categories:1,evidenceCoverage:1,completionStatus:1}}).sort({scannedAt:-1}).limit(100).toArray();return json(res,200,docs.map(d=>({...d,id:d._id.toString(),_id:undefined}))); }
  const cmp=u.pathname.match(/^\/api\/scans\/([a-f\d]{24})\/compare\/([a-f\d]{24})$/i);
  if(req.method==='GET'&&cmp) { const [a,b]=await Promise.all(cmp.slice(1).map(id=>db.collection('scans').findOne({_id:new ObjectId(id),ownerId:req.user._id})));if(!a||!b)return json(res,404,{error:'One or both reports were not found.'});if(a.hostname!==b.hostname)return json(res,400,{error:'Saved-report comparisons require the same hostname. Use the comparison lab for two websites.'});return json(res,200,compareReports(a,b)); }
  const item=u.pathname.match(/^\/api\/scans\/([a-f\d]{24})$/i);
  if(item&&req.method==='GET') { const doc=await db.collection('scans').findOne({_id:new ObjectId(item[1]),ownerId:req.user._id}); return doc?json(res,200,{...doc,id:doc._id.toString(),_id:undefined}):json(res,404,{error:'Report not found.'}); }
  if(item&&req.method==='DELETE') { const out=await db.collection('scans').deleteOne({_id:new ObjectId(item[1]),ownerId:req.user._id}); return out.deletedCount?json(res,200,{deleted:true}):json(res,404,{error:'Report not found.'}); }
  if(req.method==='GET') { let file=path.resolve(PUBLIC, '.'+decodeURIComponent(u.pathname==='/'?'/':u.pathname)); if(!file.startsWith(PUBLIC+path.sep)&&file!==PUBLIC) return json(res,404,{error:'Not found.'}); if(u.pathname==='/') file=path.join(PUBLIC,'index.html'); try { const content=await fs.promises.readFile(file); res.writeHead(200,{'content-type':MIME[path.extname(file)]||'application/octet-stream','x-content-type-options':'nosniff','referrer-policy':'no-referrer','x-frame-options':'DENY','content-security-policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",'cache-control':'no-store'}); return res.end(content); } catch { return json(res,404,{error:'Not found.'}); } }
  return json(res,404,{error:'Not found.'});
}
async function main() {
  const connectMongo=async()=>{
    if(mongoClient) return;
    const client=new MongoClient(process.env.MONGODB_URI||'mongodb://127.0.0.1:27017',{serverSelectionTimeoutMS:2500});
    try { await client.connect(); const candidate=client.db(process.env.DB_NAME||'datashadow'); await candidate.collection('scans').createIndex({hostname:1,scannedAt:-1}); await candidate.collection('scans').createIndex({scannedAt:-1}); await candidate.collection('scans').createIndex({ownerId:1,scannedAt:-1}); await candidate.collection('users').createIndex({email:1},{unique:true}); await candidate.collection('sessions').createIndex({tokenHash:1},{unique:true}); await candidate.collection('sessions').createIndex({expiresAt:1},{expireAfterSeconds:0}); if(listenFailed){await client.close();return;} mongoClient=client;db=candidate;dbError=null;console.log('MongoDB connected.'); }
    catch(e) { await client.close().catch(()=>{});dbError=e;db=null;console.error('MongoDB unavailable; scans remain available without history.'); }
  };
  const server=http.createServer((req,res)=>{ route(req,res).catch(e=>{ if(!res.headersSent) json(res,e.status||500,{error:e.status?e.message:'The request could not be completed.'}); else res.destroy(); }); });
  server.requestTimeout=15000; server.headersTimeout=10000;
  server.on('error',error=>{listenFailed=true;if(error.code==='EADDRINUSE')console.error(`Port ${PORT} is already in use. Stop the existing server or set PORT to another value.`);else console.error('HTTP server failed to start.');process.exitCode=1;if(mongoClient){mongoClient.close().catch(()=>{});mongoClient=null;db=null;}});
  server.listen(PORT,()=>console.log(`DataShadow listening on http://localhost:${PORT} (MongoDB ${db?'connected':'disconnected'})`));
  connectMongo().catch(()=>{});
  const reconnect=setInterval(()=>{if(!db&&!mongoClient)connectMongo().catch(()=>{});},15000);reconnect.unref();
}
if(require.main===module) main();
module.exports={validUrl,ipv4Public,ipv6Groups,isPublicIp,domainSimilarity,analyzePolicy,categoryScores,compareReports,consumeScanAllowance,consumeAuthAllowance,emailAddress,hashPassword,passwordMatches,sessionTokenHash,inspectAdvanced,readableText,normalizedUrl,unknownPolicyTopics};
