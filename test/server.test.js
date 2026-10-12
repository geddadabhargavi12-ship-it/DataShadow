'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { validUrl, isPublicIp, domainSimilarity, analyzePolicy, categoryScores, compareReports, consumeScanAllowance, consumeAuthAllowance, emailAddress, hashPassword, passwordMatches, readableText, normalizedUrl } = require('../server');

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
