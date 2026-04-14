/* CloudShield Dashboard — Chart.js Visualizations & Data Loading */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';

const SEVERITY_COLORS = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#22c55e',
};

const SOURCE_COLORS = {
    trivy: '#3b82f6',
    opa: '#8b5cf6',
    correlation: '#06b6d4',
};

let severityBarChart = null;
let sourceDoughnutChart = null;
let streamBarChart = null;
let trendChart = null;

// ── Initialize ──
document.addEventListener('DOMContentLoaded', () => {
    loadCachedResults();
});

// ── API Calls ──
async function runScan() {
    setButtonsDisabled(true);
    showPipelineRunning();
    clearLog();
    addLog('Starting scan...', 'info');

    try {
        const res = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const json = await res.json();
        if (json.data) {
            renderResults(json.data);
            showPipelineDone();
        }
    } catch (e) {
        addLog('Scan failed: ' + e.message, 'error');
        showPipelineError();
    }
    setButtonsDisabled(false);
}

async function runDemo() {
    setButtonsDisabled(true);
    showPipelineRunning();
    clearLog();
    addLog('Running demo mode — BEFORE + AFTER scans...', 'info');

    try {
        const res = await fetch(`${API_BASE}/api/demo`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const json = await res.json();
        if (json.data) {
            renderResults(json.data.before);
            renderComparison(json.data.before, json.data.after);
            showPipelineDone();
        }
    } catch (e) {
        addLog('Demo failed: ' + e.message, 'error');
        showPipelineError();
    }
    setButtonsDisabled(false);
}

async function loadCachedResults() {
    try {
        const res = await fetch(`${API_BASE}/api/results`);
        const json = await res.json();
        if (json.status === 'cached' && json.data) {
            renderResults(json.data);
            addLog('Loaded cached results', 'info');
        }
    } catch (e) { /* no cache, ok */ }
}

// ── NEW: Paste & Scan Raw Config ──
function toggleConfigPanel() {
    const panel = document.getElementById('config-panel');
    const s3Panel = document.getElementById('s3-check-panel');
    panel.classList.toggle('hidden');
    if (s3Panel) s3Panel.classList.toggle('hidden');
    if (!panel.classList.contains('hidden')) {
        document.getElementById('config-editor').focus();
    }
}

function clearConfigEditor() {
    document.getElementById('config-editor').value = '';
    document.getElementById('config-status').textContent = '';
}

function loadSampleBadConfig() {
    const sample = JSON.stringify({
        "s3_buckets": [
            {
                "name": "public-data-bucket",
                "acl": "public-read",
                "public_access_block": {
                    "block_public_acls": false,
                    "block_public_policy": false
                },
                "encryption": { "enabled": false },
                "logging": { "enabled": false }
            },
            {
                "name": "logs-bucket",
                "acl": "private",
                "public_access_block": {
                    "block_public_acls": true,
                    "block_public_policy": true
                },
                "encryption": { "enabled": true, "algorithm": "AES256" },
                "logging": { "enabled": false }
            }
        ],
        "iam_roles": [
            {
                "name": "admin-role",
                "mfa_required": false,
                "policies": [
                    { "name": "full-access", "action": "*", "resource": "*" },
                    { "name": "s3-all", "action": "s3:*", "resource": "*" }
                ]
            }
        ],
        "cloudtrail": {
            "enabled": false,
            "multi_region": false,
            "log_file_validation": false
        },
        "container_config": {
            "privileged": true,
            "run_as_root": true,
            "read_only_rootfs": false
        }
    }, null, 2);

    document.getElementById('config-editor').value = sample;
    document.querySelector('input[name="config-type"][value="json"]').checked = true;
    document.getElementById('config-status').textContent = '✅ Sample bad config loaded';
}

async function scanRawConfig() {
    const configText = document.getElementById('config-editor').value.trim();
    const configType = document.querySelector('input[name="config-type"]:checked').value;
    const statusEl = document.getElementById('config-status');

    if (!configText) {
        statusEl.textContent = '❌ Please paste a configuration first';
        statusEl.className = 'config-status error';
        return;
    }

    statusEl.textContent = '⏳ Analyzing configuration...';
    statusEl.className = 'config-status loading';
    setButtonsDisabled(true);
    showPipelineRunning();
    clearLog();
    addLog(`Scanning raw ${configType.toUpperCase()} configuration...`, 'info');

    try {
        const res = await fetch(`${API_BASE}/api/scan-config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config_text: configText, config_type: configType })
        });
        const json = await res.json();

        if (json.status === 'error') {
            statusEl.textContent = `❌ ${json.message}`;
            statusEl.className = 'config-status error';
            addLog(`Error: ${json.message}`, 'error');
            if (json.alerts) {
                renderAlerts(json.alerts, { total: json.alerts.length, critical: 0, high: 1, medium: 0, low: 0 });
            }
            showPipelineError();
        } else if (json.data) {
            const alertCount = json.data.alert_summary?.total || 0;
            statusEl.textContent = `✅ Analysis complete — ${alertCount} issues found`;
            statusEl.className = 'config-status success';
            renderResults(json.data);
            if (json.data.alerts) {
                renderAlerts(json.data.alerts, json.data.alert_summary);
            }
            if (json.data.remediations) {
                renderRemediations(json.data.remediations);
            }
            showPipelineDone();
        }
    } catch (e) {
        statusEl.textContent = `❌ Connection failed: ${e.message}`;
        statusEl.className = 'config-status error';
        addLog('Config scan failed: ' + e.message, 'error');
        showPipelineError();
    }
    setButtonsDisabled(false);
}

// ── NEW: Single S3 Bucket Check ──
async function checkS3Bucket() {
    const bucketName = document.getElementById('s3-bucket-name').value.trim();
    const resultDiv = document.getElementById('s3-check-result');
    const btn = document.getElementById('btn-check-s3');

    if (!bucketName) {
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = '<span style="color:var(--color-critical)">❌ Please enter a bucket name</span>';
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Checking...';
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = '<span style="color:var(--color-info)">⏳ Checking AWS S3 configuration...</span>';

    try {
        const res = await fetch(`${API_BASE}/api/check-bucket`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bucket: bucketName })
        });
        
        const json = await res.json();
        
        if (json.status === 'error') {
            resultDiv.innerHTML = `<span style="color:var(--color-critical)">❌ Error: ${escapeHtml(json.message)}</span>`;
        } else {
            const isPublic = json.isPublic;
            const statusColor = isPublic ? 'var(--color-critical)' : 'var(--color-low)';
            const statusIcon = isPublic ? '🚨' : '✅';
            const statusText = isPublic ? 'PUBLICLY ACCESSIBLE' : 'SECURE (Private)';
            
            resultDiv.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <strong>Bucket:</strong> <code>${escapeHtml(json.bucket)}</code>
                </div>
                <div style="margin-top:0.5rem; font-size:1.1rem; color:${statusColor}; font-weight:bold;">
                    ${statusIcon} ${statusText}
                </div>
                <div style="margin-top:0.5rem; font-size:0.85rem; color:var(--text-secondary);">
                    Status: ${json.status}
                </div>
            `;
        }
    } catch (e) {
        resultDiv.innerHTML = `<span style="color:var(--color-critical)">❌ Connection failed: ${e.message}</span>`;
    }

    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">☁️</span> Check Bucket';
}

// ── NEW: Render Alerts ──
function renderAlerts(alerts, summary) {
    const section = document.getElementById('alerts-section');
    section.classList.remove('hidden');

    // Summary bar
    const summaryEl = document.getElementById('alert-summary');
    summaryEl.innerHTML = `
        <div class="alert-stat critical"><span class="alert-count">${summary.critical || 0}</span> Critical</div>
        <div class="alert-stat high"><span class="alert-count">${summary.high || 0}</span> High</div>
        <div class="alert-stat medium"><span class="alert-count">${summary.medium || 0}</span> Medium</div>
        <div class="alert-stat low"><span class="alert-count">${summary.low || 0}</span> Low</div>
        <div class="alert-stat total"><span class="alert-count">${summary.total || 0}</span> Total</div>
    `;

    // Alert cards
    const container = document.getElementById('alerts-container');
    container.innerHTML = '';

    alerts.forEach(alert => {
        const card = document.createElement('div');
        card.className = `alert-card alert-${(alert.severity || 'low').toLowerCase()}`;
        card.innerHTML = `
            <div class="alert-header">
                <span class="alert-level">${alert.alert_level || 'ℹ️ INFO'}</span>
                <span class="badge badge-${(alert.severity || 'low').toLowerCase()}">${alert.severity}</span>
            </div>
            <div class="alert-title">${escapeHtml(alert.title || 'Unknown')}</div>
            <div class="alert-message">${escapeHtml(alert.message || '')}</div>
            <div class="alert-meta">
                <span>ID: <code>${alert.id || 'N/A'}</code></span>
                <span>Type: ${alert.type || 'N/A'}</span>
            </div>
        `;
        container.appendChild(card);
    });
}

// ── NEW: Render Remediations ──
function renderRemediations(remediations) {
    const section = document.getElementById('remediation-section');
    section.classList.remove('hidden');

    const container = document.getElementById('remediation-container');
    container.innerHTML = '';

    remediations.forEach(rem => {
        const card = document.createElement('div');
        card.className = `remediation-card confidence-${rem.confidence || 'low'}`;
        card.innerHTML = `
            <div class="rem-header">
                <span class="rem-title">🔧 ${escapeHtml(rem.title || 'Unknown Fix')}</span>
                <span class="badge badge-confidence-${rem.confidence || 'low'}">${(rem.confidence || 'low').toUpperCase()} confidence</span>
            </div>
            <div class="rem-description">${escapeHtml(rem.description || '')}</div>
            <div class="rem-command">
                <div class="rem-command-header">
                    <span>Fix Command:</span>
                    <button class="btn btn-xs" onclick="copyCommand(this)">📋 Copy</button>
                </div>
                <pre><code>${escapeHtml(rem.command || '# No command available')}</code></pre>
            </div>
            <div class="rem-meta">
                <span>Finding: <code>${rem.finding_id || 'N/A'}</code></span>
                <span>Strategy: ${rem.strategy || 'N/A'}</span>
            </div>
        `;
        container.appendChild(card);
    });
}

function copyCommand(btn) {
    const code = btn.closest('.rem-command').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.textContent = '✅ Copied!';
        setTimeout(() => { btn.textContent = '📋 Copy'; }, 2000);
    });
}

// ── Render Results ──
function renderResults(data) {
    if (!data) return;

    // Summary cards
    const findings = data.findings || [];
    const risk = data.risk || {};
    const vulns = findings.filter(f => f.source === 'trivy').length;
    const misconfigs = findings.filter(f => f.source === 'opa').length;
    const correlated = findings.filter(f => f.source === 'correlation').length;

    animateCounter('total-vulns', vulns);
    animateCounter('total-misconfig', misconfigs);
    animateCounter('total-correlated', correlated);
    document.getElementById('risk-score').textContent = risk.final_score || 0;

    const cat = risk.category || 'LOW';
    const catBadge = document.getElementById('risk-category');
    catBadge.textContent = cat;
    catBadge.className = 'card-badge badge-' + cat.toLowerCase();

    // Execution log
    const logs = data.execution_log || [];
    clearLog();
    logs.forEach(l => addLog(l, l.includes('✓') ? 'success' : 'info'));

    // Charts
    renderSeverityChart(findings);
    renderSourceChart(findings);
    renderStreamChart(risk);

    // Top 5 issues
    renderTopIssues(findings, data.remediations || []);

    // Full findings table
    renderFindingsTable(findings, data.remediations || []);
}

// ── Charts ──
function renderSeverityChart(findings) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    findings.forEach(f => { if (counts.hasOwnProperty(f.severity)) counts[f.severity]++; });

    const ctx = document.getElementById('severity-bar-chart').getContext('2d');
    if (severityBarChart) severityBarChart.destroy();

    severityBarChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(counts),
            datasets: [{
                label: 'Findings',
                data: Object.values(counts),
                backgroundColor: Object.keys(counts).map(k => SEVERITY_COLORS[k]),
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, ticks: { color: '#94a3b8', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { ticks: { color: '#94a3b8' }, grid: { display: false } }
            }
        }
    });
}

function renderSourceChart(findings) {
    const counts = { trivy: 0, opa: 0, correlation: 0 };
    findings.forEach(f => { if (counts.hasOwnProperty(f.source)) counts[f.source]++; });

    const ctx = document.getElementById('source-doughnut-chart').getContext('2d');
    if (sourceDoughnutChart) sourceDoughnutChart.destroy();

    sourceDoughnutChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['CVE (Trivy)', 'Policy (OPA)', 'Correlated'],
            datasets: [{
                data: Object.values(counts),
                backgroundColor: Object.values(SOURCE_COLORS),
                borderWidth: 0,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', padding: 12, usePointStyle: true, pointStyleWidth: 10 }
                }
            }
        }
    });
}

function renderStreamChart(risk) {
    const ctx = document.getElementById('stream-bar-chart').getContext('2d');
    if (streamBarChart) streamBarChart.destroy();

    streamBarChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['CVE Stream', 'Policy Stream', 'Correlated Stream'],
            datasets: [{
                label: 'Score',
                data: [risk.cve_score || 0, risk.policy_score || 0, risk.correlated_score || 0],
                backgroundColor: [SOURCE_COLORS.trivy, SOURCE_COLORS.opa, SOURCE_COLORS.correlation],
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { beginAtZero: true, max: 4.5, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#94a3b8' }, grid: { display: false } }
            }
        }
    });
}

// ── Comparison (Demo) ──
function renderComparison(before, after) {
    const section = document.getElementById('comparison-section');
    section.classList.remove('hidden');

    const bf = before.findings || [];
    const af = after.findings || [];
    const br = before.risk || {};
    const ar = after.risk || {};

    document.getElementById('comp-before-issues').textContent = bf.length;
    document.getElementById('comp-after-issues').textContent = af.length;
    document.getElementById('comp-before-crit').textContent = bf.filter(f => f.severity === 'CRITICAL').length;
    document.getElementById('comp-after-crit').textContent = af.filter(f => f.severity === 'CRITICAL').length;
    document.getElementById('comp-before-score').textContent = br.final_score || 0;
    document.getElementById('comp-after-score').textContent = ar.final_score || 0;
    document.getElementById('comp-before-cat').textContent = br.category || 'N/A';
    document.getElementById('comp-after-cat').textContent = ar.category || 'N/A';

    const reduction = br.final_score > 0
        ? Math.round(((br.final_score - (ar.final_score || 0)) / br.final_score) * 100)
        : 0;
    document.getElementById('reduction-badge').textContent = `↓ ${reduction}% Risk Reduction`;

    // Trend chart
    const ctx = document.getElementById('trend-chart').getContext('2d');
    if (trendChart) trendChart.destroy();

    trendChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['CVE Score', 'Policy Score', 'Correlated Score', 'Final Score'],
            datasets: [
                {
                    label: 'BEFORE',
                    data: [br.cve_score || 0, br.policy_score || 0, br.correlated_score || 0, br.final_score || 0],
                    backgroundColor: 'rgba(239, 68, 68, 0.7)',
                    borderRadius: 4,
                },
                {
                    label: 'AFTER',
                    data: [ar.cve_score || 0, ar.policy_score || 0, ar.correlated_score || 0, ar.final_score || 0],
                    backgroundColor: 'rgba(34, 197, 94, 0.7)',
                    borderRadius: 4,
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#94a3b8' } }
            },
            scales: {
                y: { beginAtZero: true, max: 4.5, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { ticks: { color: '#94a3b8' }, grid: { display: false } }
            }
        }
    });
}

// ── Top 5 Issues ──
function renderTopIssues(findings, remediations) {
    const remMap = {};
    remediations.forEach(r => { remMap[r.finding_id] = r; });

    const sorted = [...findings].sort((a, b) => {
        const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        return (order[b.severity] || 0) - (order[a.severity] || 0);
    });

    const top5 = sorted.slice(0, 5);
    const tbody = document.getElementById('top-issues-body');
    tbody.innerHTML = '';

    top5.forEach((f, i) => {
        const rem = remMap[f.id] || {};
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${i + 1}</td>
            <td><code>${f.id || 'N/A'}</code></td>
            <td>${f.source || 'N/A'}</td>
            <td><span class="badge badge-${(f.severity || 'low').toLowerCase()}">${f.severity || 'N/A'}</span></td>
            <td>${severityScore(f.severity)}</td>
            <td title="${escapeHtml(rem.command || '')}">${escapeHtml((rem.title || 'N/A').substring(0, 50))}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ── Full Findings Table ──
function renderFindingsTable(findings, remediations) {
    const remMap = {};
    remediations.forEach(r => { remMap[r.finding_id] = r; });

    const tbody = document.getElementById('findings-body');
    tbody.innerHTML = '';

    findings.forEach(f => {
        const rem = remMap[f.id] || {};
        const comp = f.compliance || {};
        const frameworks = [];
        if (comp.nist && comp.nist.length) frameworks.push('NIST');
        if (comp.iso27001 && comp.iso27001.length) frameworks.push('ISO');
        if (comp.hipaa && comp.hipaa.length) frameworks.push('HIPAA');

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${(f.id || 'N/A').substring(0, 20)}</code></td>
            <td>${f.type || 'N/A'}</td>
            <td><span class="badge badge-${(f.severity || 'low').toLowerCase()}">${f.severity || 'N/A'}</span></td>
            <td>${escapeHtml((f.title || f.message || 'N/A').substring(0, 60))}</td>
            <td>${escapeHtml((rem.title || 'N/A').substring(0, 40))}</td>
            <td>${frameworks.join(', ') || '—'}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ── UI Helpers ──
function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    let current = 0;
    const step = Math.max(1, Math.ceil(target / 20));
    const interval = setInterval(() => {
        current += step;
        if (current >= target) { current = target; clearInterval(interval); }
        el.textContent = current;
    }, 40);
}

function severityScore(severity) {
    return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[severity] || 0;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}

function setButtonsDisabled(disabled) {
    document.getElementById('btn-scan').disabled = disabled;
    document.getElementById('btn-demo').disabled = disabled;
    document.getElementById('btn-paste').disabled = disabled;
    const analyzeBtn = document.getElementById('btn-analyze');
    if (analyzeBtn) analyzeBtn.disabled = disabled;
}

function showPipelineRunning() {
    document.querySelectorAll('.pipeline-step').forEach(el => {
        el.classList.remove('done', 'error');
        el.classList.add('active');
        el.querySelector('.step-status').innerHTML = '<span class="spinner"></span>';
    });
}

function showPipelineDone() {
    document.querySelectorAll('.pipeline-step').forEach(el => {
        el.classList.remove('active', 'error');
        el.classList.add('done');
        el.querySelector('.step-status').textContent = '✓ Done';
    });
}

function showPipelineError() {
    document.querySelectorAll('.pipeline-step').forEach(el => {
        el.classList.remove('active', 'done');
        el.classList.add('error');
        el.querySelector('.step-status').textContent = '✗ Error';
    });
}

// ── Expose to global scope for inline onclick handlers ──
window.runScan = runScan;
window.runDemo = runDemo;
window.toggleConfigPanel = toggleConfigPanel;
window.clearConfigEditor = clearConfigEditor;
window.loadSampleBadConfig = loadSampleBadConfig;
window.scanRawConfig = scanRawConfig;
window.copyCommand = copyCommand;
window.checkS3Bucket = checkS3Bucket;

// ── Log ──
function clearLog() {
    document.getElementById('execution-log').innerHTML = '';
}

function addLog(message, type) {
    const log = document.getElementById('execution-log');
    const placeholder = log.querySelector('.log-placeholder');
    if (placeholder) placeholder.remove();

    const div = document.createElement('div');
    div.className = 'log-entry ' + (type || 'info');
    div.textContent = message;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
}
