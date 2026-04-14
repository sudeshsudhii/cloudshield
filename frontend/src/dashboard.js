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
    
    // Panel navigation
    const pastePanel = document.getElementById('config-panel');
    const telemetryPanel = document.getElementById('telemetry-panel');
    const s3Panel = document.getElementById('s3-check-panel');
    
    document.getElementById('btn-paste-panel')?.addEventListener('click', () => {
        pastePanel.classList.remove('hidden');
        telemetryPanel.classList.add('hidden');
        s3Panel.classList.add('hidden');
    });
    
    document.getElementById('btn-telemetry-panel')?.addEventListener('click', () => {
        telemetryPanel.classList.remove('hidden');
        pastePanel.classList.add('hidden');
        s3Panel.classList.add('hidden');
    });

    // Start Telemetry Polling
    fetchAgentTelemetry();
    setInterval(fetchAgentTelemetry, 10000); // 10 seconds
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

// ── NEW: Elite CSPM History Functions ──
function getScanHistory() {
    try {
        return JSON.parse(localStorage.getItem('cloudshield_s3_history') || '[]');
    } catch {
        return [];
    }
}

function saveToHistory(scanData) {
    let history = getScanHistory();
    // Prepend to start of array
    history.unshift(scanData);
    // Cap at 10 items
    if (history.length > 10) {
        history = history.slice(0, 10);
    }
    localStorage.setItem('cloudshield_s3_history', JSON.stringify(history));
    renderHistory();
}

function renderHistory() {
    const list = document.getElementById('storage-history-list');
    if (!list) return;
    const history = getScanHistory();
    
    if (history.length === 0) {
        list.innerHTML = '<div style="color:var(--text-secondary)">No scan history available.</div>';
        const exportBtn = document.getElementById('btn-export-storage');
        if(exportBtn) exportBtn.style.display = 'none';
        return;
    }

    const exportBtn = document.getElementById('btn-export-storage');
    if(exportBtn) exportBtn.style.display = 'inline-flex';

    list.innerHTML = history.map((item, idx) => {
        const isSafe = item.status === 'PASS';
        const icon = isSafe ? '✅' : '🚨';
        const color = isSafe ? 'var(--color-low)' : 'var(--color-critical)';
        const dateStr = new Date(item.scannedAt).toLocaleString();
        return `
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(255,255,255,0.05); padding-bottom:0.5rem;">
                <div>
                    <span style="margin-right:0.5rem">${icon}</span>
                    <strong style="color:${color}">${escapeHtml(item.resource)}</strong>
                    <span style="color:var(--text-secondary); margin-left:0.5rem; font-size:0.75rem;">(${item.provider.toUpperCase()})</span>
                </div>
                <div style="color:var(--text-secondary); font-size:0.75rem;">${dateStr} | ${item.scanDurationMs}ms</div>
            </div>
        `;
    }).join('');
}

function toggleHistory() {
    const drawer = document.getElementById('storage-history-drawer');
    if (drawer) {
        if (drawer.style.display === 'none') {
            renderHistory();
            drawer.style.display = 'block';
        } else {
            drawer.style.display = 'none';
        }
    }
}

function exportStorageReport() {
    const history = getScanHistory();
    if (history.length === 0) return;
    const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cloudshield-scans-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

// Ensure history is rendered on load if drawer is ever open
document.addEventListener('DOMContentLoaded', () => {
    // Initial prep
});

// ── NEW: Agent Telemetry Polling ──
async function fetchAgentTelemetry() {
    try {
        const res = await fetch(`${API_BASE}/api/agent-status`);
        if(!res.ok) return;
        const json = await res.json();
        
        const badge = document.getElementById('agent-status-badge');
        const container = document.getElementById('telemetry-container');
        const loading = document.getElementById('telemetry-loading');
        if(!badge || !container || !loading) return;

        if(!json.agents || json.agents.length === 0) {
            badge.textContent = 'Offline';
            badge.style.background = 'var(--bg-primary)';
            badge.style.color = 'var(--text-secondary)';
            container.innerHTML = '';
            loading.style.display = 'block';
            
            // Clear any fleet banners
            const existingBanner = document.getElementById('fleet-critical-banner');
            if (existingBanner) existingBanner.remove();
            return;
        }

        const agents = json.agents;
        loading.style.display = 'none';

        const onlineCount = agents.filter(a => a.connection_status === 'online').length;
        badge.textContent = `${onlineCount}/${agents.length} Online`;
        badge.style.background = onlineCount > 0 ? 'rgba(34,197,94,0.15)' : 'rgba(234,179,8,0.15)';
        badge.style.color = onlineCount > 0 ? 'var(--color-low)' : 'var(--color-medium)';

        let fleetHasCritical = false;

        container.innerHTML = agents.map(agent => {
            if (agent.risk_level === 'Critical') fleetHasCritical = true;

            const riskColor = 
                agent.risk_level === 'Critical' ? 'var(--color-critical)' : 
                agent.risk_level === 'High' ? 'var(--color-high)' : 
                agent.risk_level === 'Medium' ? 'var(--color-medium)' : 'var(--color-low)';

            const cpu = agent.cpu_percent || 0;
            const ram = agent.ram_percent || 0;
            const cves = agent.cves || {critical:0, high:0};
            
            let portsHtml = '<li>No open ports detected.</li>';
            if (agent.open_ports && agent.open_ports.length > 0) {
                portsHtml = agent.open_ports.map(p => 
                    `<li style="margin-bottom:0.2rem;"><code style="background:var(--bg-primary); padding:0.1rem 0.3rem;">${p.port}</code> <span style="color:var(--text-secondary)">${p.ip}</span></li>`
                ).join('');
            }

            return `
            <div style="border: 1px solid var(--border-glass); border-radius: 6px; overflow: hidden; background: rgba(255,255,255,0.02); margin-bottom: 1rem;">
                <!-- Card Header -->
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-glass); background: rgba(0,0,0,0.2);">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="font-size:1.2rem;">🖥️</span>
                        <div>
                            <div style="font-weight:bold; font-size:1rem;">${escapeHtml(agent.hostname || 'Unknown')}</div>
                            <div style="font-size:0.75rem; color:var(--text-secondary);">${escapeHtml(agent.agentId)} | v${escapeHtml(agent.agentVersion || '1.0')}</div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 1rem; align-items: center;">
                        <span class="badge ${agent.connection_status === 'online' ? 'badge-low' : 'badge-medium'}">${agent.connection_status.toUpperCase()}</span>
                        <div style="text-align: right;">
                            <div style="font-size: 1.1rem; font-weight: bold; color: ${riskColor};">${agent.risk_level} RISK</div>
                            <div style="font-size: 0.75rem; color: var(--text-secondary);">Score: ${agent.risk_score} | Health: ${agent.healthScore}%</div>
                        </div>
                    </div>
                </div>
                
                <!-- Card Body -->
                <div style="padding: 1rem;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                        <div>
                            <div style="display: flex; justify-content: space-between; margin-bottom: 0.25rem; font-size: 0.85rem;">
                                <span>CPU Usage</span>
                                <span>${cpu}%</span>
                            </div>
                            <div class="progress-bar-bg" style="width: 100%; height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden;">
                                <div style="width: ${cpu}%; height: 100%; background: var(--color-info); transition: width 0.3s ease;"></div>
                            </div>
                        </div>
                        <div>
                            <div style="display: flex; justify-content: space-between; margin-bottom: 0.25rem; font-size: 0.85rem;">
                                <span>RAM Usage</span>
                                <span>${ram}%</span>
                            </div>
                            <div class="progress-bar-bg" style="width: 100%; height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden;">
                                <div style="width: ${ram}%; height: 100%; background: var(--color-medium); transition: width 0.3s ease;"></div>
                            </div>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                        <div style="background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 4px; max-height: 150px; overflow-y: auto;">
                            <h3 style="margin-top: 0; font-size: 0.9rem; color: var(--text-secondary);">Open Ports</h3>
                            <ul style="list-style-type: none; padding: 0; margin: 0; font-size: 0.85rem;">
                                ${portsHtml}
                            </ul>
                        </div>
                        <div style="background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 4px;">
                            <h3 style="margin-top: 0; font-size: 0.9rem; color: var(--text-secondary);">Trivy CVE Density</h3>
                            <div style="display: flex; gap: 1rem; margin-top: 0.5rem; justify-content: space-around;">
                                <div style="text-align: center;"><div style="font-size: 1.2rem; font-weight: bold; color: var(--color-critical);">${cves.critical || 0}</div><div style="font-size: 0.7rem;">CRIT</div></div>
                                <div style="text-align: center;"><div style="font-size: 1.2rem; font-weight: bold; color: var(--color-high);">${cves.high || 0}</div><div style="font-size: 0.7rem;">HIGH</div></div>
                            </div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 1rem; text-align: right; font-size: 0.75rem; color: var(--text-secondary);">
                        Last updated: ${agent.last_seen_seconds_ago}s ago
                    </div>
                </div>
            </div>
            `;
        }).join('');

        // Critical Banner Logic
        const telemetrySection = document.getElementById('telemetry-panel');
        let existingBanner = document.getElementById('fleet-critical-banner');
        
        if (fleetHasCritical) {
            if (!existingBanner) {
                const banner = document.createElement('div');
                banner.id = 'fleet-critical-banner';
                banner.style.padding = '0.75rem 1rem';
                banner.style.background = 'rgba(239,68,68,0.2)';
                banner.style.border = '1px solid var(--color-critical)';
                banner.style.borderRadius = '6px';
                banner.style.margin = '1rem 0';
                banner.style.color = 'var(--color-critical)';
                banner.style.display = 'flex';
                banner.style.alignItems = 'center';
                banner.style.gap = '0.5rem';
                banner.innerHTML = `<strong>🚨 CRITICAL ALERT:</strong> One or more agents in your fleet are flagged as critical risk. Please execute immediate remediation.`;
                telemetrySection.insertBefore(banner, container);
            }
        } else if (existingBanner) {
            existingBanner.remove();
        }

    } catch(err) {
        // silent
    }
}

async function checkS3Bucket() {
    const bucketName = document.getElementById('s3-bucket-name').value.trim();
    const providerEle = document.querySelector('input[name="cloud-provider"]:checked');
    const provider = providerEle ? providerEle.value : 'aws';
    const resultDiv = document.getElementById('s3-check-result');
    const btn = document.getElementById('btn-check-s3');

    if (!bucketName) {
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = '<span style="color:var(--color-critical)">❌ Please enter a resource name</span>';
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing...';
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = `<span style="color:var(--color-info)">⏳ Analyzing ${provider.toUpperCase()} security posture...</span>`;

    try {
        const res = await fetch(`${API_BASE}/api/check-storage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ provider: provider, resource: bucketName })
        });
        
        const json = await res.json();
        
        if (json.status === 'error') {
            resultDiv.innerHTML = `<span style="color:var(--color-critical)">❌ Error: ${escapeHtml(json.message)}</span>`;
        } else {
            const isPublic = json.isPublic;
            const statusColor = isPublic ? 'var(--color-critical)' : 'var(--color-low)';
            const statusIcon = isPublic ? '🚨' : '✅';
            const statusText = isPublic ? 'PUBLICLY ACCESSIBLE' : 'SECURE (Private)';
            const providerTag = `<span class="badge ${json.provider === 'aws' ? 'badge-medium' : json.provider === 'azure' ? 'badge-info' : 'badge-high'}" style="margin-right:0.5rem">${json.provider.toUpperCase()}</span>`;
            
            let extraDetails = '';
            if (isPublic && json.remediation && json.remediation !== 'No action required.') {
                extraDetails = `
                    <div style="margin-top:0.75rem; padding-top:0.75rem; border-top:1px solid var(--border-glass);">
                        <div style="color:var(--text-secondary); font-size:0.85rem; margin-bottom:0.25rem;">Exposure Type</div>
                        <div style="margin-bottom:0.75rem;"><strong>${escapeHtml(json.exposureType)}</strong></div>
                        
                        <div style="color:var(--text-secondary); font-size:0.85rem; margin-bottom:0.25rem;">Details</div>
                        <div style="margin-bottom:0.75rem;">${escapeHtml(json.details)}</div>
                        
                        <div style="color:var(--text-secondary); font-size:0.85rem; margin-bottom:0.25rem;">Remediation Command</div>
                        <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(0,0,0,0.3); padding:0.5rem; border-radius:4px; font-family:monospace; font-size:0.85rem;">
                            <code>${escapeHtml(json.remediation)}</code>
                            <button class="btn btn-sm" onclick="copyCommand(this)" style="padding:0.25rem 0.5rem; font-size:0.75rem;">Copy</button>
                        </div>
                    </div>
                `;
            }

            resultDiv.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>${providerTag}<strong>Resource:</strong> <code>${escapeHtml(json.resource)}</code></div>
                    <div style="display:flex; gap:0.5rem; align-items:center;">
                        <span style="font-size:0.75rem; color:var(--text-secondary);">${json.scanDurationMs}ms</span>
                        <span class="badge ${json.risk === 'Critical' ? 'badge-critical' : json.risk === 'Medium' ? 'badge-medium' : 'badge-low'}">Risk: ${json.risk} (Conf: ${json.confidence}%)</span>
                    </div>
                </div>
                <div style="margin-top:0.5rem; font-size:1.1rem; color:${statusColor}; font-weight:bold; display:flex; justify-content:space-between; align-items:center;">
                    <span>${statusIcon} ${statusText}</span>
                    <button class="btn btn-sm btn-outline" onclick="alert('Insight AI logic triggering...')"><span class="btn-icon">💡</span> Explain Risk</button>
                </div>
                ${extraDetails}
            `;
            
            // Save to localStorage history
            saveToHistory(json);
        }
    } catch (e) {
        resultDiv.innerHTML = `<span style="color:var(--color-critical)">❌ Connection failed: ${e.message}</span>`;
    }

    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">☁️</span> Check Storage';
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
window.toggleHistory = toggleHistory;
window.exportStorageReport = exportStorageReport;

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
