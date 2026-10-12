'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { validUrl, safeRedirectTarget, resolvePublic, isPublicIp, domainSimilarity, analyzePolicy, categoryScores, compareReports, consumeScanAllowance, consumeAuthAllowance, emailAddress, hashPassword, passwordMatches, readableText, normalizedUrl, unknownPolicyTopics, tlsCheck, headerCheck, redirectCheck, responseCheck, networkExplanation, inspectAdvanced } = require('../server');

test('accepts public HTTP(S) URL syntax and rejects local or credentialed destinations', () => {
  assert.equal(validUrl('https://example.com/a#section').href, 'https://example.com/a');
  for (const url of ['file:///etc/passwd', 'http://127.0.0.1', 'http://localhost', 'https://user:pass@example.com']) assert.throws(() => validUrl(url));
});

test('public IP gate rejects common private, loopback, link-local and reserved ranges', () => {
  for (const ip of ['10.1.2.3', '127.0.0.1', '169.254.1.1', '192.168.1.2', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '2001:db8::1']) assert.equal(isPublicIp(ip), false, ip);
  assert.equal(isPublicIp('8.8.8.8'), true);
});

test('policy analysis returns per-topic wording matches and stable content fingerprint', () => {
  const source = 'We collect personal information to provide services. We use cookies and retain data for thirty days. Contact us about your privacy rights.';
  const text = readableText(`<html><p>${source}</p></html>`);
  const first = analyzePolicy(text, 'https://example.com/privacy');
  const second = analyzePolicy(text, 'https://example.com/privacy');
  assert.equal(first.fingerprint, second.fingerprint);
  assert.equal(first.topics.find(x => x.id === 'personal_information').status, 'FOUND');
  assert.equal(first.topics.find(x => x.id === 'retention').status, 'FOUND');
  assert.ok(first.topics.some(x => x.status === 'NOT_FOUND'));
});

test('domain similarity flags a close hostname and states the heuristic limit', () => {
  const report = domainSimilarity('paypa1.com', 'paypal.com');
  assert.equal(report.status, 'REVIEW');
  assert.match(report.disclaimer, /heuristic/i);
  assert.equal(domainSimilarity('pаypal.com', 'paypal.com').status, 'REVIEW');
  assert.equal(domainSimilarity('paypal.com', 'paypal.com').status, 'PASS');
});

test('category and overall scores omit UNKNOWN checks and require four technical checks', () => {
  const findings = ['https','redirect','tls','csp','hsts','nosniff','referrer','permissions'].map((id, i) => ({ id, status: i < 3 ? 'PASS' : 'UNKNOWN' }));
  const thin = categoryScores(findings, { topics: [] }, null);
  assert.equal(thin.score, null);
  findings[3].status = 'REVIEW';
  const sufficient = categoryScores(findings, { topics: [{ status: 'FOUND' }, { status: 'NOT_FOUND' }] }, 'PASS');
  assert.equal(sufficient.assessed, 4);
  assert.equal(sufficient.evidenceCoverage, 50);
  assert.equal(sufficient.categories.configuration.score, 50);
  assert.equal(sufficient.categories.privacy.score, null);
  assert.match(sufficient.formula, /not a probability of safety/i);
});

test('report diff identifies added, removed, status, header and policy changes', () => {
  const old = { hostname: 'example.com', scannedAt: '2026-01-01', findings: [{ id: 'csp', status: 'REVIEW', rawEvidence: 'absent' }, { id: 'hsts', status: 'PASS' }], observations: { headers: { 'Strict-Transport-Security': 'max-age=100' }, redirectChain: [] }, privacy: { fingerprint: 'old', topics: [{ id: 'cookies', status: 'FOUND' }] }, categories: {} };
  const newer = { hostname: 'example.com', scannedAt: '2026-01-02', findings: [{ id: 'csp', status: 'PASS', rawEvidence: 'default-src self' }, { id: 'permissions', status: 'REVIEW' }], observations: { headers: { 'Content-Security-Policy': 'default-src self' }, redirectChain: [] }, privacy: { fingerprint: 'new', topics: [{ id: 'cookies', status: 'NOT_FOUND' }] }, categories: {} };
  const diff = compareReports(old, newer);
  assert.ok(diff.changes.some(x => x.id === 'csp' && x.kind === 'status_changed'));
  assert.ok(diff.changes.some(x => x.id === 'hsts' && x.kind === 'removed'));
  assert.ok(diff.changes.some(x => x.id === 'permissions' && x.kind === 'added'));
  assert.equal(diff.privacy.textChanged, true);
  assert.ok(diff.headers['Strict-Transport-Security']);
});

test('scan allowance counts comparison scans against the rolling window', () => {
  const key = `test-${process.pid}-${Date.now()}`;
  for (let i = 0; i < 4; i++) assert.equal(consumeScanAllowance(key, 2), true);
  assert.equal(consumeScanAllowance(key), false);
});

test('account email normalization and salted password hashes work without storing plaintext', async () => {
  assert.equal(emailAddress('  User@Example.COM '), 'user@example.com');
  assert.throws(() => emailAddress('not-an-email'));
  const password = 'correct horse battery staple';
  const credentials = await hashPassword(password);
  assert.notEqual(credentials.hash, password);
  assert.notEqual(credentials.salt, (await hashPassword(password)).salt);
  const stored = { passwordSalt: credentials.salt, passwordHash: credentials.hash };
  assert.equal(await passwordMatches(password, stored), true);
  assert.equal(await passwordMatches('incorrect password', stored), false);
});

test('account attempt allowance blocks repeated login or registration attempts', () => {
  const key = `auth-test-${process.pid}-${Date.now()}`;
  for (let i = 0; i < 8; i++) assert.equal(consumeAuthAllowance(key), true);
  assert.equal(consumeAuthAllowance(key), false);
});

test('tracking parameters are removed from normalized report URLs', () => {
  assert.equal(normalizedUrl('https://example.com/page?x=1&utm_source=mail&gclid=abc#top'), 'https://example.com/page?x=1');
});

test('all DNS answers must be public, and redirect targets are revalidated', async () => {
  await assert.rejects(resolvePublic('mixed.example', async () => [
    { address: '8.8.8.8', family: 4 },
    { address: '127.0.0.1', family: 4 }
  ]), /private or reserved/);
  assert.equal(safeRedirectTarget('/next', 'https://public.example/start').href, 'https://public.example/next');
  for (const target of [
    'http://127.0.0.1/admin', 'http://10.0.0.1/', 'http://169.254.169.254/latest/meta-data/',
    'http://localhost/', 'http://service.internal/', 'file:///etc/passwd'
  ]) assert.throws(() => safeRedirectTarget(target, 'https://public.example/'), /public|private|reserved/i);
});

test('TLS outcomes distinguish valid, invalid, unavailable, and not-applicable checks', () => {
  assert.equal(tlsCheck('http:', null, null).status, 'NOT_APPLICABLE');
  const valid = tlsCheck('https:', { authorized: true, issuer: 'Example CA', validFrom: '2026-01-01', validTo: '2027-01-01' }, null);
  assert.equal(valid.status, 'PASS');
  assert.match(valid.evidence, /daysUntilExpiry/);
  assert.equal(tlsCheck('https:', { authorized: true, validTo: '2000-01-01' }, null).status, 'FAIL');
  assert.equal(tlsCheck('https:', { authorized: true, validFrom: '2999-01-01', validTo: '3000-01-01' }, null).status, 'FAIL');
  for (const code of ['CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE']) {
    assert.equal(tlsCheck('https:', null, { code }).status, 'FAIL', code);
  }
  assert.equal(tlsCheck('https:', null, { code: 'ETIMEDOUT' }).status, 'UNKNOWN');
});

test('header, redirect, and HTTP response evaluators use evidence-based statuses', () => {
  for (const name of ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']) {
    assert.equal(headerCheck(name, 'Header purpose.', null).status, 'REVIEW', name);
    assert.equal(headerCheck(name, 'Header purpose.', 'configured-value').status, 'PASS', name);
  }
  assert.equal(redirectCheck('https://public.example/').status, 'PASS');
  assert.equal(redirectCheck('http://public.example/').status, 'REVIEW');
  assert.equal(responseCheck(200).status, 'PASS');
  assert.equal(responseCheck(403).status, 'REVIEW', 'a bot-block response is review, not a site-wide failure');
  assert.match(networkExplanation({ code: 'ETIMEDOUT' }), /timed out/i);
});

test('missing or inaccessible policy text remains unknown rather than claiming no policy exists', () => {
  const topics = unknownPolicyTopics();
  assert.ok(topics.length > 0);
  assert.ok(topics.every(topic => topic.status === 'UNKNOWN' && topic.excerpt === null));
});

test('controlled local HTTP fixture returns live headers and does not fabricate TLS or policy results', async t => {
  const visited = [];
  const server = http.createServer((req, res) => {
    visited.push(req.url);
    if (req.url === '/redirect-private') {
      res.writeHead(302, { location: 'http://127.0.0.1/private' });
      return res.end();
    }
    if (req.url === '/private') {
      res.writeHead(200);
      return res.end('must never be reached');
    }
    if (req.url === '/blocked') {
      res.writeHead(403, { 'content-type': 'text/plain' });
      return res.end('Automated requests are not allowed.');
    }
    if (req.url !== '/') {
      res.writeHead(404);
      return res.end('not found');
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'x-content-type-options': 'nosniff' });
    res.end('<!doctype html><title>Test fixture</title><p>Controlled scanner test fixture.</p>');
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const port = server.address().port;
  const testResolver = async host => {
    assert.equal(host, 'fixture.example');
    return [{ address: '127.0.0.1', family: 4 }];
  };
  const report = await inspectAdvanced(`http://fixture.example:${port}/`, null, { resolvePublic: testResolver });
  const finding = id => report.findings.find(item => item.id === id);
  assert.equal(report.finalStatus, 200);
  assert.equal(finding('tls').status, 'NOT_APPLICABLE');
  assert.equal(finding('nosniff').status, 'PASS');
  assert.equal(finding('csp').status, 'REVIEW');
  assert.equal(finding('privacy').status, 'UNKNOWN');

  const blockedBySite = await inspectAdvanced(`http://fixture.example:${port}/blocked`, null, { resolvePublic: testResolver });
  assert.equal(blockedBySite.finalStatus, 403);
  assert.equal(blockedBySite.findings.find(item => item.id === 'response').status, 'REVIEW');
  assert.notEqual(blockedBySite.findings.find(item => item.id === 'tls').status, 'FAIL');

  const blocked = await inspectAdvanced(`http://fixture.example:${port}/redirect-private`, null, { resolvePublic: testResolver });
  assert.equal(blocked.finalStatus, null);
  assert.match(blocked.errorDetails, /private|reserved/i);
  assert.equal(visited.includes('/private'), false, 'the redirect target was blocked before it was requested');
});

test('controlled slow HTTP fixture times out as UNKNOWN and does not turn every check into FAIL', async t => {
  const server = http.createServer((_req, _res) => {});
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const port = server.address().port;
  const report = await inspectAdvanced(`http://slow-fixture.example:${port}/`, null, {
    resolvePublic: async () => [{ address: '127.0.0.1', family: 4 }]
  });
  assert.equal(report.completionStatus, 'partial');
  assert.match(report.errorDetails, /timed out/i);
  assert.ok(report.findings.some(item => item.status === 'UNKNOWN'));
  assert.equal(report.findings.find(item => item.id === 'tls').status, 'NOT_APPLICABLE');
  assert.equal(report.findings.some(item => item.status === 'FAIL'), false);
});

test('unreachable controlled HTTP target remains unavailable, not a blanket security failure', async t => {
  const server = http.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  const report = await inspectAdvanced(`http://closed-fixture.example:${port}/`, null, {
    resolvePublic: async () => [{ address: '127.0.0.1', family: 4 }]
  });
  assert.equal(report.completionStatus, 'partial');
  assert.equal(report.finalStatus, null);
  assert.equal(report.findings.find(item => item.id === 'response').status, 'UNKNOWN');
  assert.equal(report.findings.find(item => item.id === 'tls').status, 'NOT_APPLICABLE');
});

test('unknown and NOT APPLICABLE checks do not count as failures or evidence', () => {
  const findings = ['https','redirect','tls','csp','hsts','nosniff','referrer','permissions'].map((id, i) => ({ id, status: i < 2 ? 'PASS' : 'UNKNOWN' }));
  findings[2].status = 'NOT_APPLICABLE';
  findings[3].status = 'REVIEW';
  const result = categoryScores(findings, { topics: [] }, null);
  assert.equal(result.assessed, 3);
  assert.equal(result.evidenceCoverage, 38);
  assert.equal(result.score, null, 'three assessed checks do not meet the minimum evidence threshold');
  findings[4].status = 'PASS';
  const sufficient = categoryScores(findings, { topics: [] }, null);
  assert.equal(sufficient.assessed, 4);
  assert.equal(sufficient.evidenceCoverage, 50);
  assert.match(sufficient.formula, /NOT APPLICABLE are excluded/i);
});
