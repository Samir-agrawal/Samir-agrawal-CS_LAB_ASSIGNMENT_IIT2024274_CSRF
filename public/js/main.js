// main.js - Dynamic UI, State Polling & Control Center
let currentSecurityMode = 'VULNERABLE';
let currentCsrfToken = '';

async function fetchState() {
  try {
    const res = await fetch('/api/state');
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        window.location.href = '/login';
        return;
      }
      return;
    }
    const data = await res.json();
    renderDashboard(data);
  } catch (err) {
    console.error('Error fetching state:', err);
  }
}

function renderDashboard(data) {
  const { user, csrfToken, securityMode, transactions, auditLogs } = data;
  currentSecurityMode = securityMode;
  currentCsrfToken = csrfToken;

  // Render User Header
  document.getElementById('userNameDisplay').textContent = user.fullName;
  document.getElementById('userAccountDisplay').textContent = `Account: ${user.accountNumber}`;
  document.getElementById('avatarInitial').textContent = user.username.charAt(0).toUpperCase();

  // Render Balance
  document.getElementById('balanceDisplay').textContent = `$${user.balance.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  })}`;
  document.getElementById('lastUpdated').textContent = `Updated ${new Date().toLocaleTimeString()}`;

  // Update Hidden CSRF Input
  const formCsrf = document.getElementById('formCsrfToken');
  if (formCsrf) formCsrf.value = csrfToken;
  const tokenSnippet = document.getElementById('tokenSnippet');
  if (tokenSnippet) {
    tokenSnippet.textContent = csrfToken ? `${csrfToken.substring(0, 16)}...` : 'None';
  }

  // Update Security Mode UI
  updateSecurityModeUI(securityMode);

  // Render Transactions
  renderTransactions(transactions, user.username);

  // Render Audit Logs
  renderAuditLogs(auditLogs);
}

function updateSecurityModeUI(mode) {
  const badge = document.getElementById('modeIndicatorBadge');
  const modeText = document.getElementById('modeText');
  const toggleBtn = document.getElementById('toggleModeBtn');
  const banner = document.getElementById('modeExplanationBanner');
  const tokenEnforcementText = document.getElementById('tokenEnforcementText');

  if (mode === 'VULNERABLE') {
    badge.className = 'mode-indicator mode-vulnerable';
    modeText.textContent = '🔴 VULNERABLE (CSRF ACTIVE)';
    toggleBtn.textContent = '🛡️ Activate Synchronizer Token (Mitigate)';
    toggleBtn.className = 'btn btn-warning';

    banner.className = 'mode-info-alert alert-vulnerable';
    banner.innerHTML = `
      <strong>🔴 VULNERABLE MODE ACTIVE:</strong> The bank processes <code>POST /transfer</code> without validating any CSRF token.
      A cross-origin auto-submitting form on port 4000 will succeed silently using ambient credentials!
    `;
    tokenEnforcementText.textContent = '⚠️ Token is ignored by the server in this mode.';
  } else {
    badge.className = 'mode-indicator mode-mitigated';
    modeText.textContent = '🟢 MITIGATED (TOKEN ENFORCED)';
    toggleBtn.textContent = '⚠️ Deactivate Defense (Make Vulnerable)';
    toggleBtn.className = 'btn btn-outline';

    banner.className = 'mode-info-alert alert-mitigated';
    banner.innerHTML = `
      <strong>🟢 MITIGATED MODE ACTIVE:</strong> The bank enforces the <strong>Synchronizer Token Pattern</strong>.
      Incoming <code>POST /transfer</code> requests without a matching <code>_csrf</code> token are rejected with <strong>403 Forbidden</strong>!
    `;
    tokenEnforcementText.textContent = '🛡️ Server strictly validates this token for all state-changing POST requests.';
  }
}

function renderTransactions(transactions, currentUsername) {
  const tbody = document.getElementById('transactionTableBody');
  const countBadge = document.getElementById('txCountBadge');
  countBadge.textContent = `${transactions.length} records`;

  if (!transactions || transactions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No transactions recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = transactions.map(tx => {
    const isSender = tx.fromUser === currentUsername;
    const direction = isSender ? `Sent to <strong>${tx.toUser}</strong>` : `Received from <strong>${tx.fromUser}</strong>`;
    const formattedAmount = `$${tx.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })}`;

    let rowClass = '';
    let statusBadge = '';

    if (tx.status === 'BLOCKED_CSRF') {
      rowClass = 'tx-blocked';
      statusBadge = `<span class="tx-blocked-tag">🛡️ BLOCKED (Anti-CSRF Defense)</span><small class="text-muted">${tx.note}</small>`;
    } else {
      statusBadge = `<span class="status-chip success-chip">✓ Completed</span> <small class="text-muted">${tx.note || 'Online Wire Transfer'}</small>`;
    }

    return `
      <tr class="${rowClass}">
        <td><small class="text-muted">${tx.timestamp}</small></td>
        <td>${direction}</td>
        <td><strong style="color: ${isSender ? '#ef4444' : '#10b981'}">${isSender ? '-' : '+'}${formattedAmount}</strong></td>
        <td>${statusBadge}</td>
      </tr>
    `;
  }).join('');
}

function renderAuditLogs(logs) {
  const consoleEl = document.getElementById('auditLogConsole');
  if (!logs || logs.length === 0) {
    consoleEl.innerHTML = '<div class="terminal-line text-muted">No security events logged yet.</div>';
    return;
  }

  consoleEl.innerHTML = logs.map(l => {
    let color = '#38bdf8';
    if (l.action.includes('CSRF_BLOCKED')) color = '#10b981';
    if (l.action.includes('FORGED') || l.action.includes('VULNERABLE')) color = '#ef4444';
    if (l.action.includes('MODE_CHANGE')) color = '#facc15';

    return `
      <div class="terminal-line">
        <span class="terminal-time">[${l.timestamp}]</span>
        <span class="terminal-action" style="color: ${color}">[${l.action}]</span>
        <span class="terminal-actor">&lt;${l.actor}&gt;</span>
        <span>${l.details}</span>
      </div>
    `;
  }).join('');
}

async function toggleSecurityMode() {
  const targetMode = currentSecurityMode === 'VULNERABLE' ? 'MITIGATED' : 'VULNERABLE';
  try {
    const res = await fetch('/api/toggle-mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: targetMode })
    });
    const data = await res.json();
    if (data.success) {
      await fetchState();
    }
  } catch (err) {
    alert('Failed to switch security mode.');
  }
}

async function resetDatabase() {
  if (!confirm('Reset all balances, transaction logs, and tokens to initial demo state?')) return;
  try {
    const res = await fetch('/api/reset', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      await fetchState();
    }
  } catch (err) {
    alert('Failed to reset demo state.');
  }
}

function openPayloadModal() {
  document.getElementById('payloadModal').classList.remove('hidden');
}

function closePayloadModal() {
  document.getElementById('payloadModal').classList.add('hidden');
}

// Initial Fetch and 3-second live polling
fetchState();
setInterval(fetchState, 3000);
