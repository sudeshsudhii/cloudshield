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
}

function showPipelineRunning() {
    document.querySelectorAll('.pipeline-step').forEach(el => {
        el.classList.remove('done');
        el.classList.add('active');
        el.querySelector('.step-status').innerHTML = '<span class="spinner"></span>';
    });
}

function showPipelineDone() {
    document.querySelectorAll('.pipeline-step').forEach(el => {
        el.classList.remove('active');
        el.classList.add('done');
        el.querySelector('.step-status').textContent = '✓ Done';
    });
}

// ── Expose to global scope for inline onclick handlers ──
window.runScan = runScan;
window.runDemo = runDemo;

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
