// GuardNet Dashboard — auto-refreshes every 2 seconds

const POLL_INTERVAL = 2000;
const RECONNECT_INTERVAL = 5000;
let authHeader = '';
let pollTimer = null;
let failCount = 0;
let connectionLost = false;

const badgeClass = {
    'DoS': 'badge-dos', 'DDoS': 'badge-ddos', 'PortScan': 'badge-scan',
    'BruteForce': 'badge-brute', 'WebAttack': 'badge-web',
    'Infiltration': 'badge-infil', 'Botnet': 'badge-bot'
};

// ─── Auth ───────────────────────────────────────────────────

function setAuth(pass) {
    authHeader = 'Basic ' + btoa('admin:' + pass);
    sessionStorage.setItem('guardnet_pass', pass);
}

function clearAuth() {
    authHeader = '';
    sessionStorage.removeItem('guardnet_pass');
}

function showLogin() {
    document.getElementById('login-overlay').style.display = 'flex';
    document.getElementById('login-pass').value = '';
    document.getElementById('login-error').textContent = '';
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

function hideLogin() {
    document.getElementById('login-overlay').style.display = 'none';
    refreshAll();
    if (!pollTimer) pollTimer = setInterval(refreshAll, POLL_INTERVAL);
}

async function doLogin() {
    const pass = document.getElementById('login-pass').value;
    if (!pass) return;
    const header = 'Basic ' + btoa('admin:' + pass);
    try {
        const res = await fetch('/api/auth/check', { headers: { 'Authorization': header } });
        if (res.ok) {
            setAuth(pass);
            hideLogin();
        } else {
            document.getElementById('login-error').textContent = 'Wrong password';
        }
    } catch (e) {
        document.getElementById('login-error').textContent = 'Connection error';
    }
}

function doLogout() {
    clearAuth();
    showLogin();
}

// Try saved credentials on load — retry if ESP32 is still booting
(async function tryAutoLogin() {
    const saved = sessionStorage.getItem('guardnet_pass');
    if (saved) {
        for (let attempt = 0; attempt < 5; attempt++) {
            try {
                const header = 'Basic ' + btoa('admin:' + saved);
                const res = await fetch('/api/auth/check', { headers: { 'Authorization': header } });
                if (res.ok) {
                    setAuth(saved);
                    hideLogin();
                    return;
                }
                break; // 401 = wrong password, stop retrying
            } catch (e) {
                // ESP32 not ready yet — wait and retry
                if (attempt < 4) await new Promise(r => setTimeout(r, 2000));
            }
        }
    }
    showLogin();
})();

// ─── Fetch helpers ──────────────────────────────────────────

async function authFetch(url, options) {
    if (!options) options = {};
    if (!options.headers) options.headers = {};
    options.headers['Authorization'] = authHeader;
    try {
        const res = await fetch(url, options);
        if (res.status === 401) { showLogin(); return null; }
        // Connection recovered
        if (connectionLost) {
            connectionLost = false;
            failCount = 0;
            document.getElementById('reconnect-banner').style.display = 'none';
            if (pollTimer) clearInterval(pollTimer);
            pollTimer = setInterval(refreshAll, POLL_INTERVAL);
        }
        failCount = 0;
        return res;
    } catch (e) {
        failCount++;
        if (failCount >= 3 && !connectionLost) {
            connectionLost = true;
            document.getElementById('reconnect-banner').style.display = 'block';
            // Slow down polling while disconnected
            if (pollTimer) clearInterval(pollTimer);
            pollTimer = setInterval(refreshAll, RECONNECT_INTERVAL);
        }
        return null;
    }
}

async function fetchJSON(url) {
    const res = await authFetch(url);
    if (!res) return null;
    try { return await res.json(); } catch (e) { return null; }
}

// ─── Formatters ─────────────────────────────────────────────

function formatUptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
}

// ─── Dashboard updates ─────────────────────────────────────

async function updateStatus() {
    const data = await fetchJSON('/api/status');
    if (!data) return;

    document.getElementById('stat-clients').textContent = data.clients;
    document.getElementById('stat-attacks').textContent = data.total_attacks;
    updateTitleBadge(data.total_attacks);
    document.getElementById('stat-blocked').textContent = data.blocked;
    document.getElementById('uptime').textContent = 'Uptime: ' + formatUptime(data.uptime);
    if (data.avg_inference_us !== undefined) {
        const us = data.avg_inference_us;
        document.getElementById('stat-inference').textContent =
            us < 1000 ? us.toFixed(0) + ' µs' : (us / 1000).toFixed(1) + ' ms';
    }
    if (data.conf_threshold !== undefined) {
        document.getElementById('threshold-badge').textContent =
            'Threshold: ' + data.conf_threshold.toFixed(2);
    }
    document.getElementById('sta-status').textContent =
        'Upstream: ' + (data.sta_connected ? 'Connected' : 'Disconnected');

    const led = document.getElementById('status-led');
    led.className = 'led ' + (data.total_attacks > 0 ?
        (data.blocked > 0 ? 'red' : 'yellow') : 'green');

    if (data.ids_enabled !== undefined) updateIDSButton(data.ids_enabled);
    if (data.block_enabled !== undefined) updateBlockButton(data.block_enabled);
    if (data.conf_threshold !== undefined) updateParanoiaSlider(data.conf_threshold);
    if (data.block_timeout !== undefined) {
        const inp = document.getElementById('block-timeout-input');
        if (inp && !inp.matches(':focus')) inp.value = Math.round(data.block_timeout / 60);
    }
}

async function updateAlerts() {
    const alerts = await fetchJSON('/api/alerts');
    if (!alerts) return;

    const tbody = document.getElementById('attack-body');
    if (alerts.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No attacks detected</td></tr>';
        return;
    }

    const rows = [...alerts].reverse().map(a => {
        const cls = badgeClass[a.cat] || 'badge-dos';
        const confPct = Math.round(a.conf * 100);
        const confClass = confPct >= 90 ? 'conf-high' : confPct >= 75 ? 'conf-med' : '';
        const dst = (!a.dst || a.dst === '0.0.0.0') ? '&mdash;' : `<code>${a.dst}</code>`;
        const timeLabel = formatUptime(a.time);
        return `<tr class="attack-row">
            <td title="Boot +${timeLabel}">T+${timeLabel}</td>
            <td><code>${a.src}</code></td>
            <td>${dst}</td>
            <td><span class="badge ${cls}">${a.cat}</span></td>
            <td><div class="${confClass}"><div class="conf-bar"><div class="conf-fill" style="width:${confPct}%"></div></div> ${confPct}%</div></td>
            <td><span class="badge ${a.internal ? 'badge-internal' : 'badge-external'}">${a.internal ? 'Internal' : 'External'}</span></td>
        </tr>`;
    });
    tbody.innerHTML = rows.join('');
}

async function updateClients() {
    if (document.querySelector('.assign-ip-row[style*="flex"]')) return;

    const clients = await fetchJSON('/api/clients');
    if (!clients) return;

    const container = document.getElementById('clients-list');
    if (clients.length === 0) {
        container.innerHTML = '<div class="empty-msg">No clients connected</div>';
        return;
    }

    container.innerHTML = clients.map(c => {
        const macSafe = c.mac.replace(/:/g, '');
        const isBridged = c.bridged || c.mac === '--:--:--:--:--:--';
        return `<div class="list-item client-card">
            <div class="client-info">
                <code>${c.mac}</code>
                <span class="client-ip" id="cip-${macSafe}">${c.ip}</span>
            </div>
            <div class="client-actions">
                ${isBridged
                    ? '<span class="badge badge-scan">Bridged/VM</span>'
                    : `<span class="rssi-badge">RSSI: ${c.rssi} dBm</span>`}
                <button class="btn btn-assign" onclick="toggleAssignIP('${c.mac}','${macSafe}')">Assign IP</button>
                <button class="btn btn-danger" onclick="disconnectClient('${c.mac}')">Disconnect</button>
            </div>
            <div class="assign-ip-row" id="aip-${macSafe}" style="display:none">
                <input type="text" id="aip-input-${macSafe}" placeholder="192.168.4.x" style="width:130px">
                <button class="btn btn-connect" onclick="submitAssignIP('${c.mac}','${macSafe}')">Set</button>
                <span class="wifi-msg" id="aip-msg-${macSafe}"></span>
            </div>
        </div>`;
    }).join('');
}

function toggleAssignIP(mac, macSafe) {
    const row = document.getElementById('aip-' + macSafe);
    const input = document.getElementById('aip-input-' + macSafe);
    if (row.style.display === 'none') {
        const currentIP = document.getElementById('cip-' + macSafe).textContent;
        if (currentIP && currentIP !== 'pending') input.value = currentIP;
        row.style.display = 'flex';
        input.focus();
    } else {
        row.style.display = 'none';
    }
}

async function submitAssignIP(mac, macSafe) {
    const input = document.getElementById('aip-input-' + macSafe);
    const msgEl = document.getElementById('aip-msg-' + macSafe);
    const ip = input.value.trim();

    if (!ip.match(/^192\.168\.4\.([2-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])$/)) {
        msgEl.textContent = 'Need 192.168.4.2–254';
        msgEl.className = 'wifi-msg wifi-error';
        return;
    }

    msgEl.textContent = 'Sending...';
    msgEl.className = 'wifi-msg';

    const res = await authFetch('/api/clients/setip', {
        method: 'POST',
        body: JSON.stringify({ mac: mac, ip: ip })
    });

    if (!res) return;
    const data = await res.json();
    if (data.ok) {
        msgEl.textContent = 'Sent — client reconnecting';
        setTimeout(() => updateClients(), 3000);
    } else {
        msgEl.textContent = data.error || 'Failed';
        msgEl.className = 'wifi-msg wifi-error';
    }
}

function formatRemaining(seconds) {
    if (seconds < 0) return 'permanent';
    if (seconds === 0) return 'expiring...';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

async function updateBlocked() {
    const blocked = await fetchJSON('/api/blocked');
    if (!blocked) return;

    const container = document.getElementById('blocked-list');
    if (blocked.length === 0) {
        container.innerHTML = '<div class="empty-msg">No IPs blocked</div>';
        return;
    }

    container.innerHTML = blocked.map(b => {
        const cls = badgeClass[b.reason] || 'badge-dos';
        const rem = b.remaining >= 0
            ? `<span class="countdown">${formatRemaining(b.remaining)}</span>`
            : '<span class="countdown perm">∞</span>';
        return `<div class="list-item">
            <code>${b.ip}</code>
            <span class="badge ${cls}">${b.reason}</span>
            ${rem}
            <button class="btn btn-unblock" onclick="unblockIP('${b.ip}')">Unblock</button>
        </div>`;
    }).join('');
}

// ─── Actions ────────────────────────────────────────────────

async function manualBlock() {
    const input = document.getElementById('block-ip-input');
    const ip = input.value.trim();
    if (!ip.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
        alert('Invalid IP address');
        return;
    }
    await authFetch('/api/block', {
        method: 'POST',
        body: JSON.stringify({ ip: ip })
    });
    input.value = '';
    updateBlocked();
}

async function unblockIP(ip) {
    await authFetch('/api/unblock', {
        method: 'POST',
        body: JSON.stringify({ ip: ip })
    });
    updateBlocked();
}

async function disconnectClient(mac) {
    if (!confirm('Disconnect client ' + mac + '?')) return;
    await authFetch('/api/disconnect', {
        method: 'POST',
        body: JSON.stringify({ mac: mac })
    });
    setTimeout(updateClients, 1000);
}

// ─── WiFi config ────────────────────────────────────────────

async function updateWifiStatus() {
    const data = await fetchJSON('/api/wifi/status');
    if (!data) return;

    const ssidEl = document.getElementById('wifi-ssid');
    const badgeEl = document.getElementById('wifi-conn-badge');
    const retryBtn = document.getElementById('wifi-retry-btn');

    if (data.configured) {
        ssidEl.textContent = data.ssid;
        if (data.connected) {
            badgeEl.textContent = 'Connected';
            badgeEl.className = 'badge badge-connected';
            if (retryBtn) retryBtn.style.display = 'none';
        } else {
            badgeEl.textContent = 'Connecting...';
            badgeEl.className = 'badge badge-scan';
            if (retryBtn) retryBtn.style.display = 'inline-block';
        }
    } else {
        ssidEl.textContent = 'Not configured';
        badgeEl.textContent = 'No upstream';
        badgeEl.className = 'badge badge-external';
        if (retryBtn) retryBtn.style.display = 'none';
    }
}

async function wifiRetry() {
    showWifiMsg('Retrying connection...');
    const res = await authFetch('/api/wifi/retry', { method: 'POST' });
    if (res && res.ok) {
        showWifiMsg('Retry triggered — connecting...');
        setTimeout(updateWifiStatus, 4000);
    } else {
        showWifiMsg('Retry failed', true);
    }
}

async function wifiConnect() {
    const ssid = document.getElementById('wifi-ssid-input').value.trim();
    const pass = document.getElementById('wifi-pass-input').value;

    if (!ssid) {
        showWifiMsg('Enter SSID', true);
        return;
    }

    showWifiMsg('Connecting to ' + ssid + '...');
    const res = await authFetch('/api/wifi/connect', {
        method: 'POST',
        body: JSON.stringify({ ssid: ssid, pass: pass })
    });

    if (res && res.ok) {
        showWifiMsg('Credentials saved. Connecting...');
        document.getElementById('wifi-pass-input').value = '';
        setTimeout(updateWifiStatus, 5000);
    } else {
        showWifiMsg('Failed to save credentials', true);
    }
}

async function wifiForget() {
    if (!confirm('Forget saved WiFi credentials?')) return;
    await authFetch('/api/wifi/forget', { method: 'POST' });
    showWifiMsg('Credentials forgotten. AP-only mode.');
    setTimeout(updateWifiStatus, 1000);
}

async function wifiScan() {
    const container = document.getElementById('scan-results');
    container.style.display = 'block';
    container.innerHTML = '<div class="empty-msg">Scanning...</div>';

    const results = await fetchJSON('/api/wifi/scan');
    if (!results || results.length === 0) {
        container.innerHTML = '<div class="empty-msg">No networks found</div>';
        return;
    }

    container.innerHTML = results.map(r =>
        `<div class="scan-item" onclick="pickSSID('${r.ssid.replace(/'/g, "\\'")}')">
            <span>${r.ssid}</span>
            <span class="scan-meta">${r.rssi} dBm ${r.secure ? '&#128274;' : ''}</span>
        </div>`
    ).join('');
}

function pickSSID(ssid) {
    document.getElementById('wifi-ssid-input').value = ssid;
    document.getElementById('scan-results').style.display = 'none';
    document.getElementById('wifi-pass-input').focus();
}

function showWifiMsg(msg, isError) {
    const el = document.getElementById('wifi-msg');
    el.textContent = msg;
    el.className = 'wifi-msg' + (isError ? ' wifi-error' : '');
    if (!isError) setTimeout(() => { el.textContent = ''; }, 8000);
}

// ─── Password change ────────────────────────────────────────

async function changePassword() {
    const oldPass = document.getElementById('old-pass').value;
    const newPass = document.getElementById('new-pass').value;
    const msgEl = document.getElementById('pass-msg');

    if (!oldPass || !newPass) {
        msgEl.textContent = 'Fill in both fields';
        msgEl.className = 'wifi-msg wifi-error';
        return;
    }
    if (newPass.length < 4 || newPass.length > 32) {
        msgEl.textContent = 'Password must be 4-32 characters';
        msgEl.className = 'wifi-msg wifi-error';
        return;
    }

    const res = await authFetch('/api/auth/change', {
        method: 'POST',
        body: JSON.stringify({ old: oldPass, new: newPass })
    });
    if (!res) return;

    const data = await res.json();
    if (data.ok) {
        setAuth(newPass);
        document.getElementById('old-pass').value = '';
        document.getElementById('new-pass').value = '';
        msgEl.textContent = 'Password changed';
        msgEl.className = 'wifi-msg';
        setTimeout(() => { msgEl.textContent = ''; }, 5000);
    } else {
        msgEl.textContent = data.error || 'Failed';
        msgEl.className = 'wifi-msg wifi-error';
    }
}

// ─── IDS toggle ────────────────────────────────────────────

async function toggleIDS() {
    const btn = document.getElementById('ids-toggle');
    const current = btn.textContent.includes('ON');
    const newState = !current;
    await authFetch('/api/ids/toggle', {
        method: 'POST',
        body: JSON.stringify({ enabled: newState })
    });
    updateIDSButton(newState);
}

function updateIDSButton(enabled) {
    const btn = document.getElementById('ids-toggle');
    btn.textContent = 'IDS: ' + (enabled ? 'ON' : 'OFF');
    btn.className = 'btn btn-ids' + (enabled ? '' : ' ids-off');
}

// ─── Block toggle ──────────────────────────────────────────

async function toggleBlock() {
    const btn = document.getElementById('block-toggle');
    const current = btn.textContent.includes('ON');
    const newState = !current;
    await authFetch('/api/block/toggle', {
        method: 'POST',
        body: JSON.stringify({ enabled: newState })
    });
    updateBlockButton(newState);
}

function updateBlockButton(enabled) {
    const btn = document.getElementById('block-toggle');
    btn.textContent = 'Block: ' + (enabled ? 'ON' : 'OFF');
    btn.className = 'btn btn-block' + (enabled ? '' : ' block-off');
}

// ─── Clear alerts ──────────────────────────────────────────

async function clearAlerts() {
    if (!confirm('Clear all alerts and reset attack counter?')) return;
    await authFetch('/api/alerts/clear', { method: 'POST' });
    updateAlerts();
    updateStatus();
}

// ─── Paranoia slider ───────────────────────────────────────
// Slider value is threshold*100 (50..95). Lower = more paranoid (blocks more).

let paranoiaUserEditing = false;

function paranoiaMood(pct) {
    if (pct <= 55) return 'Tinfoil hat';
    if (pct <= 65) return 'Paranoid';
    if (pct <= 75) return 'Edgy';
    if (pct <= 85) return 'Normal';
    if (pct <= 90) return 'Relaxed';
    return 'Chill';
}

function updateParanoiaSlider(threshold) {
    if (paranoiaUserEditing) return;  // don't stomp while user drags
    const slider = document.getElementById('paranoia-slider');
    if (!slider) return;
    const pct = Math.round(threshold * 100);
    slider.value = pct;
    document.getElementById('paranoia-value').textContent = (pct / 100).toFixed(2);
    document.getElementById('paranoia-mood').textContent = paranoiaMood(pct);
}

function onParanoiaInput() {
    paranoiaUserEditing = true;
    const pct = parseInt(document.getElementById('paranoia-slider').value);
    document.getElementById('paranoia-value').textContent = (pct / 100).toFixed(2);
    document.getElementById('paranoia-mood').textContent = paranoiaMood(pct);
}

async function saveParanoia() {
    const pct = parseInt(document.getElementById('paranoia-slider').value);
    const threshold = pct / 100;
    const msgEl = document.getElementById('paranoia-msg');
    const res = await authFetch('/api/confidence', {
        method: 'POST',
        body: JSON.stringify({ threshold: threshold })
    });
    paranoiaUserEditing = false;
    if (res && res.ok) {
        msgEl.textContent = 'Saved';
        msgEl.className = 'wifi-msg';
        setTimeout(() => { msgEl.textContent = ''; }, 2000);
    } else {
        msgEl.textContent = 'Failed to save';
        msgEl.className = 'wifi-msg wifi-error';
    }
}

// ─── Timeline chart ────────────────────────────────────────

async function updateTimeline() {
    const counts = await fetchJSON('/api/timeline');
    if (!counts) return;
    const canvas = document.getElementById('timeline-canvas');
    if (!canvas) return;

    // Match canvas resolution to actual rendered size (prevents blur)
    const dpr = window.devicePixelRatio || 1;
    const displayW = canvas.offsetWidth;
    const displayH = canvas.offsetHeight;
    if (canvas.width !== displayW * dpr || canvas.height !== displayH * dpr) {
        canvas.width  = displayW * dpr;
        canvas.height = displayH * dpr;
    }

    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    const W = displayW, H = displayH;
    const pad = { top: 8, right: 8, bottom: 20, left: 32 };
    const chartW = W - pad.left - pad.right;
    const chartH = H - pad.top - pad.bottom;
    const max = Math.max(...counts, 1);
    const barW = chartW / counts.length;

    ctx.clearRect(0, 0, W, H);

    // Grid lines
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = pad.top + chartH - (i / 4) * chartH;
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + chartW, y); ctx.stroke();
    }

    // Bars
    counts.forEach((n, i) => {
        const x = pad.left + i * barW + 1;
        const barH = (n / max) * chartH;
        const y = pad.top + chartH - barH;
        const age = counts.length - 1 - i;  // 0 = newest
        const alpha = 0.4 + 0.6 * (1 - age / counts.length);
        ctx.fillStyle = n > 0
            ? `rgba(239,68,68,${alpha})`
            : `rgba(30,41,59,0.6)`;
        ctx.fillRect(x, y, barW - 2, barH || 1);
    });

    // Y axis label (max)
    ctx.fillStyle = '#94a3b8';
    ctx.font = '10px ui-monospace, monospace';
    ctx.textAlign = 'right';
    ctx.fillText(max, pad.left - 3, pad.top + 10);

    // Count labels on non-zero bars
    ctx.fillStyle = '#e2e8f0';
    ctx.textAlign = 'center';
    counts.forEach((n, i) => {
        if (n === 0) return;
        const x = pad.left + i * barW + barW / 2;
        const barH = (n / max) * chartH;
        const y = pad.top + chartH - barH - 3;
        ctx.fillText(n, x, y);
    });

    // X axis labels: "-9m" ... "now"
    ctx.fillStyle = '#94a3b8';
    ctx.textAlign = 'center';
    [9, 4, 0].forEach(age => {
        const i = counts.length - 1 - age;
        const x = pad.left + i * barW + barW / 2;
        ctx.fillText(age === 0 ? 'now' : `-${age}m`, x, H - 4);
    });
    ctx.setTransform(1, 0, 0, 1, 0, 0);  // reset scale for next call
}

// ─── Block timeout setting ─────────────────────────────────

async function saveBlockTimeout() {
    const val = parseInt(document.getElementById('block-timeout-input').value);
    if (isNaN(val) || val < 0) return;
    const msgEl = document.getElementById('timeout-msg');
    const res = await authFetch('/api/block/timeout', {
        method: 'POST',
        body: JSON.stringify({ minutes: val })
    });
    if (res && res.ok) {
        msgEl.textContent = val === 0 ? 'Saved — blocks are permanent' : `Saved — blocks expire after ${val} min`;
        msgEl.className = 'wifi-msg';
        setTimeout(() => { msgEl.textContent = ''; }, 4000);
    } else {
        msgEl.textContent = 'Failed'; msgEl.className = 'wifi-msg wifi-error';
    }
}

// ─── Refresh loop ───────────────────────────────────────────

function refreshAll() {
    updateStatus();
    updateAlerts();
    updateClients();
    updateBlocked();
    updateWifiStatus();
    updateTimeline();
}

function updateTitleBadge(attacks) {
    document.title = attacks > 0 ? `(${attacks}) GuardNet` : 'GuardNet';
}
