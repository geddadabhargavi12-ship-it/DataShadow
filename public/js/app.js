const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
let savedReports = [];
let compareFirstId = null;
let showAllHistory = false;
let currentReport = null;
let currentFindings = [];

async function api(url, options = {}) {
  let response;
  try {
    response = await fetch(url, { ...options, headers: { 'content-type': 'application/json', ...(options.headers || {}) } });
  } catch {
    throw new Error('Cannot reach the DataShadow server. Make sure it is running, then try again.');
  }
  const data = await response.json().catch(() => ({ error: 'The server returned an unreadable response.' }));
  if (!response.ok) throw new Error(data?.error || `Request failed (${response.status}).`);
  if (data == null) throw new Error('The server returned an empty response. Please try again.');
  return data;
}
function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}
function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Date unavailable' : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
function toast(message) {
  const element = $('#toast');
  element.textContent = message;
  element.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { element.hidden = true; }, 2800);
}

async function checkHealth() {
  const badge = $('#dbBadge');
  try {
    const health = await api('/api/health');
    badge.className = `db-badge ${health.database === 'connected' ? 'connected' : 'offline'}`;
    badge.querySelector('span').textContent = health.database === 'connected' ? 'DB connected' : 'DB offline - sign-in paused';
  } catch {
    badge.className = 'db-badge offline';
    badge.querySelector('span').textContent = 'API unavailable';
  }
}

$('#scanForm').addEventListener('submit', async event => {
  event.preventDefault();
  const value = $('#urlInput').value.trim();
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) throw new Error();
  } catch {
    $('#notice').textContent = 'Enter a valid HTTP or HTTPS website URL.';
    $('#notice').hidden = false;
    return;
  }

  $('#notice').hidden = true;
  $('#results').hidden = true;
  $('#loading').hidden = false;
  $('#scanButton').disabled = true;
  $('#scanButton').querySelector('span').textContent = 'Inspecting…';
  $('#loading').scrollIntoView({ behavior: 'smooth', block: 'center' });
  const phases = [
    ['Preparing a safe connection', 'Resolving the public host and checking the destination.'],
    ['Validating the secure connection', 'Checking HTTPS and certificate information.'],
    ['Reading website controls', 'Inspecting response status and security headers.'],
    ['Looking for privacy statements', 'Finding a policy link and scanning its text for selected topics.']
  ];
  let phase = 0;
  const updatePhase = () => {
    $('#loadingTitle').textContent = phases[phase][0];
    $('#loadingDetail').textContent = phases[phase][1];
    $$('.scan-steps span').forEach((step, index) => step.classList.toggle('active', index <= phase));
    phase = Math.min(phase + 1, phases.length - 1);
  };
  updatePhase();
  const phaseTimer = setInterval(updatePhase, 1400);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const report = await api('/api/scan', { method: 'POST', body: JSON.stringify({ url: value, expectedDomain: $('#expectedDomain').value.trim() || null }), signal: controller.signal });
    currentReport = report;
    renderReport(report);
    $('#results').hidden = false;
    await refreshHistory();
    $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    toast(report.persistence?.saved ? 'Inspection complete. Report saved.' : 'Inspection complete. Database unavailable; report was not saved.');
  } catch (error) {
    $('#notice').textContent = error.name === 'AbortError' ? 'This inspection took too long. Check the connection and try again.' : error.message;
    $('#notice').hidden = false;
  } finally {
    clearInterval(phaseTimer);
    clearTimeout(timeout);
    $('#loading').hidden = true;
    $('#scanButton').disabled = false;
    $('#scanButton').querySelector('span').textContent = 'Start inspection';
  }
});

function renderReport(report) {
  currentReport = report;
  $('#resultTitle').textContent = report.hostname || report.url;
  $('#resultMeta').textContent = `Scanned ${formatDate(report.scannedAt)}${report.finalStatus ? ` · HTTP ${report.finalStatus}` : ''}`;
  const rating = report.rating || { score: null, label: 'Older report', assessed: 0, total: 8, formula: 'Run a new scan to calculate the configuration indicator.' };
  const score = rating.score;
  const ringStyle = score === null ? '' : `--score:${score}%`;
  $('#ratingCard').innerHTML = `
    <div class="rating-main">
      <div class="rating-eyebrow">LIMITED CONFIGURATION INDICATOR</div>
      <div class="rating-ring" style="${ringStyle}"><div><strong>${score === null ? '—' : score}</strong><small>${score === null ? 'NO SCORE' : 'OUT OF 100'}</small></div></div>
      <strong class="rating-label">${escapeHtml(rating.label)}</strong>
    </div>
    <div class="rating-details">
      <div class="rating-eyebrow">VISIBLE SECURITY SIGNALS</div>
      <div class="rating-track"><i style="width:${score === null ? 0 : score}%"></i></div>
      <p>Evidence coverage: ${rating.evidenceCoverage ?? report.evidenceCoverage ?? 0}% (${rating.assessed} of ${rating.total} checks). ${escapeHtml(rating.formula || 'Run a new scan for the current scoring method.')}</p>
      <p class="rating-caveat">This is not a verdict that the whole website is secure or unsafe.</p>
    </div>`;
  const summary = report.summary || {};
  $('#summaryGrid').innerHTML = ['PASS', 'REVIEW', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE'].map(status => `
    <div class="summary-card ${status.toLowerCase()}" title="${status.replaceAll('_', ' ')} checks"><span>${status.replaceAll('_', ' ')}</span><strong>${summary[status] || 0}</strong></div>`).join('');
  renderPriorities(report.findings || []);
  renderCategories(report);
  renderPrivacy(report.privacy || {});
  const shortScope = 'Limited configuration and policy-text inspection, not a vulnerability assessment. Missing headers alone do not prove a vulnerability; policy wording does not verify actual data practices.';
  $('#limitations').innerHTML = `<b>Scope &amp; context</b> ${escapeHtml(shortScope)}${report.errorDetails ? `<br><b>Connection note</b> ${escapeHtml(report.errorDetails)}` : ''}`;
  currentFindings = report.findings || [];
  renderFindings();
}

function renderCategories(report) {
  const categories = report.categories || report.rating?.categories || {};
  const names = { connection: 'Connection security', configuration: 'Security configuration', privacy: 'Privacy transparency', behavior: 'Observable behavior' };
  $('#coverageLabel').textContent = `${report.evidenceCoverage ?? report.rating?.evidenceCoverage ?? 0}% technical evidence coverage`;
  $('#categoryGrid').innerHTML = Object.entries(names).map(([key, name]) => {
    const item = categories[key] || {};
    return `<article class="category-card"><span>${escapeHtml(name)}</span><strong>${key === 'privacy' ? `${item.coveragePercent ?? 0}%` : item.score == null ? 'N/A' : `${item.score}/100`}</strong><small>${item.assessed || 0} of ${item.total || 0} signals assessed</small><i><b style="width:${key === 'privacy' ? item.coveragePercent ?? 0 : item.score ?? 0}%"></b></i>${key === 'privacy' ? '<em>Policy topic coverage only; not a measure of privacy quality or actual practices.</em>' : ''}</article>`;
  }).join('');
}

function renderFindings() {
  const status = $('#statusFilter').value;
  const category = $('#categoryFilter').value;
  const query = $('#findingSearch').value.trim().toLowerCase();
  const items = currentFindings.filter(item => (status === 'all' || item.status === status) && (category === 'all' || item.category === category) && `${item.name} ${item.explanation} ${item.evidence} ${item.technicalExplanation || ''}`.toLowerCase().includes(query));
  const rank = { FAIL: 0, REVIEW: 1, UNKNOWN: 2, NOT_APPLICABLE: 3, PASS: 4 };
  items.sort((a, b) => rank[a.status] - rank[b.status]);
  $('#findingCount').textContent = `${items.length} of ${currentFindings.length} observations`;
  $('#findings').innerHTML = items.map(item => {
    const remediation = item.remediation || {};
    const fixes = remediation.nginx || remediation.node ? `<details class="fix-details"><summary>Implementation guidance</summary><p>${escapeHtml(remediation.summary || item.action)}</p>${remediation.caution ? `<p class="fix-caution">${escapeHtml(remediation.caution)}</p>` : ''}<div class="fix-columns">${remediation.nginx ? `<div><b>Nginx example</b><pre>${escapeHtml(remediation.nginx)}</pre></div>` : ''}${remediation.node ? `<div><b>Node.js example</b><pre>${escapeHtml(remediation.node)}</pre></div>` : ''}</div></details>` : '';
    return `<article class="finding"><div class="finding-status st-${escapeHtml(item.status)}">${escapeHtml(item.status)}<small>${escapeHtml(item.severity || 'info')}</small></div><div class="finding-content"><div class="finding-title-row"><h4>${escapeHtml(item.name)}</h4><span class="confidence">${escapeHtml(item.confidence || 'confidence unknown')} confidence</span></div><p>${escapeHtml(item.beginnerExplanation || item.explanation)}</p><details class="evidence-details"><summary>Evidence and technical context</summary><p class="evidence">Observed: ${escapeHtml(item.evidence || 'No evidence recorded')}</p><p>${escapeHtml(item.technicalExplanation || item.explanation)}</p><p>Impact context: ${escapeHtml(item.impact || 'Interpret this observation in the context of the website.')}</p></details><p class="action"><b>Suggested next step</b> ${escapeHtml(item.action)}</p>${fixes}</div></article>`;
  }).join('') || '<div class="empty-state">No observations match these filters.</div>';
}

function renderPriorities(findings) {
  const ordered = findings.filter(item => ['FAIL', 'REVIEW'].includes(item.status))
    .sort((a, b) => (a.status === 'FAIL' ? 0 : 1) - (b.status === 'FAIL' ? 0 : 1))
    .slice(0, 3);
  $('#priorityList').innerHTML = ordered.length ? ordered.map((item, index) => `
    <article class="priority-item ${item.status.toLowerCase()}"><span class="priority-index">0${index + 1}</span><div><h4>${escapeHtml(item.name)} <span class="priority-status">${escapeHtml(item.status)}</span></h4><p>${escapeHtml(item.action)}</p></div></article>`).join('')
    : '<div class="priority-empty">No completed checks need immediate follow-up. Review UNKNOWN results for gaps in coverage.</div>';
}

function renderPrivacy(privacy) {
  const indicators = privacy.indicators || [];
  const state = privacy.status || 'UNKNOWN';
  const topics = (privacy.topics || []).map(item => `<div class="policy-topic ${escapeHtml(item.status.toLowerCase())}"><b>${escapeHtml(item.status)}</b><span>${escapeHtml(item.label)}</span>${item.excerpt ? `<details><summary>View matching excerpt</summary><blockquote>${escapeHtml(item.excerpt)}</blockquote></details>` : ''}</div>`).join('');
  const link = privacy.policyUrl ? `<a class="privacy-link" href="${escapeHtml(privacy.policyUrl)}" target="_blank" rel="noopener noreferrer">Open detected policy <span>↗</span></a>` : '';
  $('#privacyCard').innerHTML = `<div class="privacy-top"><div class="eyebrow"><span class="eyebrow-line"></span> POLICY TEXT SIGNALS</div><span class="privacy-state ${state.toLowerCase()}">${escapeHtml(state)}</span></div><h3>${indicators.length ? `${indicators.length} topic${indicators.length === 1 ? '' : 's'} matched` : 'Policy topic review'}</h3><p class="privacy-message">${escapeHtml(privacy.message || 'No accessible policy text was analyzed.')}</p><div class="policy-topic-list">${topics || '<p>No topic evidence is available.</p>'}</div><p class="policy-fingerprint">Policy fingerprint: ${escapeHtml(privacy.fingerprint || 'Not available')}</p>${link}`;
}

async function refreshHistory() {
  const list = $('#historyList');
  try {
    savedReports = await api('/api/scans');
    renderHistory();
  } catch (error) {
    list.innerHTML = `<div class="notice">${escapeHtml(error.message)}</div>`;
  }
}
function renderHistory() {
  const list = $('#historyList');
  const query = $('#historySearch').value.trim().toLowerCase();
  const filtered = savedReports.filter(report => `${report.hostname || ''} ${report.url || ''}`.toLowerCase().includes(query));
  const limit = query || showAllHistory ? filtered.length : 8;
  const visible = filtered.slice(0, limit);
  $('#historyCount').textContent = query ? `${filtered.length} MATCHING REPORT${filtered.length === 1 ? '' : 'S'}` : `${savedReports.length} SAVED · SHOWING ${visible.length}`;
  if (!filtered.length) {
    list.innerHTML = `<div class="empty-state"><span class="empty-orbit">${query ? '⌕' : '◷'}</span><strong>${query ? 'No reports match that website.' : 'Your next inspection starts here.'}</strong><p>${query ? 'Try another hostname or clear the search.' : 'Saved reports appear here automatically.'}</p>${query ? '' : '<a href="#scan">Start your first scan <span>→</span></a>'}</div>`;
    return;
  }
  const cards = visible.map(report => {
    const summary = report.summary || {};
    return `<article class="history-item" data-id="${escapeHtml(report.id)}">
      <div class="history-top"><div class="history-site"><span class="history-favicon">${escapeHtml((report.hostname || 'W').charAt(0).toUpperCase())}</span><div class="history-title"><strong>${escapeHtml(report.hostname || report.url)}</strong><small>${report.finalStatus ? `HTTP ${report.finalStatus}` : 'Response unavailable'}${report.rating?.score != null ? ` · ${report.rating.score}/100` : ''}</small></div></div><span class="history-date">${escapeHtml(formatDate(report.scannedAt))}</span></div>
      <span class="history-url" title="${escapeHtml(report.url)}">${escapeHtml(report.url)}</span>
      <div class="history-bottom"><div class="history-summary"><span class="p">${summary.PASS || 0} PASS</span><span class="r">${summary.REVIEW || 0} REVIEW</span><span class="f">${summary.FAIL || 0} FAIL</span><span class="u">${summary.UNKNOWN || 0} UNKNOWN</span>${summary.NOT_APPLICABLE ? `<span class="na">${summary.NOT_APPLICABLE} N/A</span>` : ''}</div>
        <div class="history-actions"><button class="small-btn open-report" data-id="${escapeHtml(report.id)}">View report</button><button class="small-btn select-compare ${compareFirstId === report.id ? 'selected' : ''}" data-id="${escapeHtml(report.id)}">${compareFirstId === report.id ? 'Selected' : 'Compare'}</button><button class="small-btn danger delete-report" data-id="${escapeHtml(report.id)}">Delete</button></div>
      </div></article>`;
  }).join('');
  const more = !query && !showAllHistory && filtered.length > visible.length ? `<button class="show-more" data-action="more">Show ${filtered.length - visible.length} older reports <span>↓</span></button>` : '';
  list.innerHTML = cards + more;
}

function clearCompareSelection() {
  compareFirstId = null;
  $('#comparePanel').hidden = true;
  $('#comparePanel').innerHTML = '';
  renderHistory();
}
function showComparePrompt(first) {
  $('#comparePanel').innerHTML = `<button class="compare-close" data-action="cancel" aria-label="Cancel comparison">×</button><h3>Choose a second report</h3><p>Selected <b>${escapeHtml(first.hostname)}</b>. Choose another report for this same website to see what changed.</p><p class="compare-note">Select a report card's Compare button. <button class="small-btn" data-action="cancel">Cancel</button></p>`;
  $('#comparePanel').hidden = false;
}
function renderComparison(result) {
  const changes = result.changes || [];
  const detail = changes.length ? changes.map(change => `<div class="change-row"><span>${escapeHtml(change.id)}</span><span>${escapeHtml(change.before?.status || 'Not present')} → ${escapeHtml(change.after?.status || 'Not present')} (${escapeHtml(change.kind)})</span></div>`).join('') : '<p>No check or evidence changes were recorded between these reports.</p>';
  const beforePrivacy = result.privacy?.topics ? Object.keys(result.privacy.topics).length : 0;
  const beforeCategories = result.categoryScores?.before || {};
  const afterCategories = result.categoryScores?.after || {};
  const categoryRows = Object.keys({ ...beforeCategories, ...afterCategories }).map(key => `<div class="change-row"><span>${escapeHtml(afterCategories[key]?.name || beforeCategories[key]?.name || key)}</span><span>${beforeCategories[key]?.score ?? 'N/A'} → ${afterCategories[key]?.score ?? 'N/A'}</span></div>`).join('');
  const privacyText = result.privacy?.textChanged ? 'Policy text fingerprint changed.' : result.privacy?.beforeFingerprint ? 'Policy text fingerprint unchanged.' : 'A fingerprint was unavailable for one or both reports.';
  $('#comparePanel').innerHTML = `<button class="compare-close" data-action="cancel" aria-label="Close comparison">×</button><div class="eyebrow"><span class="eyebrow-line"></span> REPORT COMPARISON</div><h3>${escapeHtml(result.hostname)}</h3><p>${escapeHtml(formatDate(result.older.scannedAt))} <b>→</b> ${escapeHtml(formatDate(result.newer.scannedAt))}</p><p><b>Overall indicator:</b> ${result.overallScore?.before ?? 'N/A'} → ${result.overallScore?.after ?? 'N/A'}</p><h4>Category score changes</h4>${categoryRows}${detail}<p>${beforePrivacy} privacy topic status changes. ${escapeHtml(privacyText)}</p><p class="compare-note">${escapeHtml(result.note)}</p>`;
  $('#comparePanel').hidden = false;
}

$('#historyList').addEventListener('click', async event => {
  const button = event.target.closest('button');
  if (!button) return;
  if (button.dataset.action === 'more') { showAllHistory = true; renderHistory(); return; }
  if (button.dataset.action === 'cancel') { clearCompareSelection(); return; }
  const id = button.dataset.id;
  try {
    if (button.classList.contains('open-report')) {
      const report = await api(`/api/scans/${id}`);
      renderReport(report);
      $('#results').hidden = false;
      $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else if (button.classList.contains('delete-report')) {
      await api(`/api/scans/${id}`, { method: 'DELETE' });
      if (compareFirstId === id) clearCompareSelection();
      await refreshHistory();
      toast('Report deleted.');
    } else if (button.classList.contains('select-compare')) {
      const selected = savedReports.find(report => report.id === id);
      if (!compareFirstId) {
        compareFirstId = id;
        renderHistory();
        showComparePrompt(selected);
      } else if (compareFirstId === id) {
        clearCompareSelection();
      } else {
        const first = savedReports.find(report => report.id === compareFirstId);
        if (first?.hostname !== selected?.hostname) { toast('Choose a report for the same website.'); return; }
        const result = await api(`/api/scans/${compareFirstId}/compare/${id}`);
        compareFirstId = null;
        renderHistory();
        renderComparison(result);
      }
    }
  } catch (error) { toast(error.message); }
});

$('#historySearch').addEventListener('input', () => renderHistory());
$('#comparePanel').addEventListener('click', event => {
  if (event.target.closest('[data-action="cancel"]')) clearCompareSelection();
});
$('#refreshHistory').addEventListener('click', async () => { await refreshHistory(); toast('Reports refreshed.'); });
$('#printButton').addEventListener('click', () => window.print());
$('#downloadButton').addEventListener('click', () => {
  if (!currentReport) { toast('Run or open a report first.'); return; }
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  const host = (currentReport.hostname || 'website').replace(/[^a-z0-9.-]/gi, '-');
  link.download = `datashadow-${host}-${new Date(currentReport.scannedAt).toISOString().slice(0, 10)}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  toast('Report downloaded as JSON.');
});

$('#htmlReportButton').addEventListener('click', () => {
  if (!currentReport) { toast('Run or open a report first.'); return; }
  const r = currentReport;
  const rows = (r.findings || []).map(f => `<article><h2>${escapeHtml(f.status)} · ${escapeHtml(f.name)}</h2><p>${escapeHtml(f.beginnerExplanation || f.explanation)}</p><p><b>Evidence:</b> ${escapeHtml(f.evidence)}</p><p><b>Next step:</b> ${escapeHtml(f.action)}</p></article>`).join('');
  const categories = Object.values(r.categories || {}).map(c => `<li>${escapeHtml(c.name)}: ${c.score == null ? `${c.coveragePercent ?? 0}% topic coverage` : `${c.score}/100`} (${c.assessed} of ${c.total} assessed)</li>`).join('');
  const topics = (r.privacy?.topics || []).map(t => `<li>${escapeHtml(t.status)} · ${escapeHtml(t.label)}${t.excerpt ? `<blockquote>${escapeHtml(t.excerpt)}</blockquote>` : ''}</li>`).join('');
  const html = `<!doctype html><html><meta charset="utf-8"><title>DataShadow report - ${escapeHtml(r.hostname)}</title><style>body{font:16px/1.6 system-ui;max-width:900px;margin:40px auto;padding:0 20px;color:#17202a}header,article,section{border-bottom:1px solid #ccd3da;padding:14px 0}small{color:#566}blockquote{margin:5px 0;padding-left:12px;border-left:2px solid #9ab}</style><header><h1>DataShadow inspection report</h1><p>${escapeHtml(r.hostname)} · ${escapeHtml(formatDate(r.scannedAt))} · HTTP ${escapeHtml(r.finalStatus ?? 'unavailable')}</p><h2>Limited configuration indicator: ${r.rating?.score ?? 'Not available'} / 100</h2><p>Evidence coverage: ${r.evidenceCoverage ?? 0}%</p><p>${escapeHtml(r.rating?.formula || '')}</p><p>This is a limited configuration and policy-text inspection, not a vulnerability assessment or a verdict that a site is safe.</p></header><section><h2>Category evidence</h2><ul>${categories}</ul></section><section><h2>Policy text topics</h2><ul>${topics}</ul><p>${escapeHtml(r.privacy?.message || 'No policy text was analyzed.')}</p></section><section><h2>Findings</h2>${rows}</section><footer>Generated by DataShadow. Policy wording does not verify actual data practices.</footer></html>`;
  const objectUrl = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
  const link = document.createElement('a'); link.href = objectUrl; link.download = `datashadow-${(r.hostname || 'website').replace(/[^a-z0-9.-]/gi, '-')}.html`; link.click(); setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
});

let printDetailsState = [];
window.addEventListener('beforeprint', () => { printDetailsState = [...document.querySelectorAll('#results details')].map(node => node.open); document.querySelectorAll('#results details').forEach(node => { node.open = true; }); });
window.addEventListener('afterprint', () => { document.querySelectorAll('#results details').forEach((node, index) => { node.open = printDetailsState[index] ?? false; }); printDetailsState = []; });

for (const selector of ['#findingSearch', '#statusFilter', '#categoryFilter']) $(selector).addEventListener('input', renderFindings);
$('#compareForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true; button.textContent = 'Inspecting two sites...';
  try {
    const result = await api('/api/compare', { method: 'POST', body: JSON.stringify({ urls: [$('#compareLeft').value.trim(), $('#compareRight').value.trim()] }) });
    const reports = [result.left, result.right];
    $('#liveCompareResult').innerHTML = reports.map(report => `<article class="compare-site"><span>${escapeHtml(report.hostname)}</span><strong>${report.rating?.score ?? 'N/A'}<small>/100</small></strong><p>${escapeHtml(report.rating?.label || 'Not enough data')}</p><div>${Object.entries(report.categories || {}).map(([key, value]) => `<p>${escapeHtml(value.name || key)} <b>${key === 'privacy' ? `${value.coveragePercent ?? 0}% topics` : value.score == null ? 'N/A' : value.score}</b></p>`).join('')}</div><small>${report.persistence?.saved ? 'Saved to history' : 'Not saved (database unavailable)'}</small></article>`).join('') + `<p class="compare-note">These independent scans describe observed signals. Differences do not establish which site is safer.</p>`;
    $('#liveCompareResult').hidden = false; await refreshHistory(); $('#liveCompareResult').scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.innerHTML = 'Inspect both sites <span>→</span>'; }
});
$('#quizChoices').addEventListener('click', event => {
  const choice = event.target.closest('button[data-answer]'); if (!choice) return;
  const correct = choice.dataset.answer === 'right';
  $('#quizFeedback').textContent = correct ? 'Correct. A text match shows wording was found; it does not verify real-world handling.' : 'Not quite. The inspection only detects matching policy wording; it cannot verify actual practices.';
  $('#quizFeedback').className = correct ? 'quiz-correct' : 'quiz-try-again';
});
checkHealth();
setInterval(checkHealth, 15000);

function showAuth(message = '') {
  document.body.classList.remove('authenticated');
  $('#authGate').hidden = false;
  $('#authControls').hidden = true;
  $('#authNotice').textContent = message;
  $('#authNotice').className = 'auth-notice';
  $('#results').hidden = true;
  currentReport = null;
  currentFindings = [];
  savedReports = [];
  $('#historyList').innerHTML = '';
}
function showWorkspace(user) {
  document.body.classList.add('authenticated');
  $('#authGate').hidden = true;
  $('#authControls').hidden = false;
  $('#currentUser').textContent = user.email;
  $('#authNotice').textContent = '';
  checkHealth();
  refreshHistory();
}
function setAuthMode(mode) {
  const registering = mode === 'register';
  $('#loginForm').hidden = registering;
  $('#registerForm').hidden = !registering;
  $('#loginTab').classList.toggle('active', !registering);
  $('#registerTab').classList.toggle('active', registering);
  $('#authTitle').textContent = registering ? 'Create your workspace.' : 'Sign in to DataShadow.';
  $('#authNotice').textContent = '';
}
$('#loginTab').addEventListener('click', () => setAuthMode('login'));
$('#registerTab').addEventListener('click', () => setAuthMode('register'));
for (const [formId, endpoint] of [['loginForm', '/api/auth/login'], ['registerForm', '/api/auth/register']]) {
  $(`#${formId}`).addEventListener('submit', async event => {
    event.preventDefault();
    const register = formId === 'registerForm';
    const data = register
      ? { email: $('#registerEmail').value.trim(), password: $('#registerPassword').value }
      : { email: $('#loginEmail').value.trim(), password: $('#loginPassword').value };
    const button = event.currentTarget.querySelector('button[type="submit"]');
    button.disabled = true;
    $('#authNotice').textContent = register ? 'Creating your account...' : 'Signing in...';
    try {
      const result = await api(endpoint, { method: 'POST', body: JSON.stringify(data) });
      event.currentTarget.reset();
      showWorkspace(result.user);
      toast(register ? 'Account created. You are signed in.' : 'Welcome back.');
    } catch (error) {
      $('#authNotice').textContent = error.message;
    } finally { button.disabled = false; }
  });
}
$('#logoutButton').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST', body: '{}' });showAuth('You have signed out.'); }
  catch (error) { showAuth(`Sign-out could not be confirmed by the server: ${error.message}`); }
});

const sidebarLinks = $$('.side-link');
for (const link of sidebarLinks) {
  link.addEventListener('click', () => {
    sidebarLinks.forEach(item => item.classList.toggle('active', item === link));
  });
}
if ('IntersectionObserver' in window) {
  const sectionObserver = new IntersectionObserver(entries => {
    const current = entries.filter(entry => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!current) return;
    sidebarLinks.forEach(link => link.classList.toggle('active', link.hash === `#${current.target.id}`));
  }, { rootMargin: '-18% 0px -68% 0px', threshold: [0, 0.15, 0.35] });
  for (const section of $$('main > section[id]')) sectionObserver.observe(section);
}

(async () => {
  try { const result = await api('/api/auth/me'); showWorkspace(result.user); }
  catch (error) {
    const message = error.message.includes('MongoDB') || error.message.includes('Authentication is unavailable')
      ? 'The database is offline. Account sign-in will be available when it reconnects.'
      : '';
    showAuth(message);
  }
})();
