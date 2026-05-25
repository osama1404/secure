/**
 * CyberShield - Dashboards Interactive Logic
 */

let currentUser = null;

document.addEventListener('DOMContentLoaded', () => {
  // Validate active session
  validateSessionAndInit();
});

/**
 * Validate active user session and route initialization
 */
function validateSessionAndInit() {
  fetch('/api/session')
    .then(res => res.json())
    .then(data => {
      if (!data.loggedIn || !data.user) {
        showToast('Authentication required. Redirecting...', 'error');
        setTimeout(() => { window.location.href = '/login'; }, 1000);
        return;
      }
      
      currentUser = data.user;
      
      // Update UI Header and Profile Names
      const profileName = document.getElementById('user-profile-name');
      if (profileName) profileName.textContent = currentUser.username;
      
      const navbarRole = document.getElementById('user-navbar-role');
      if (navbarRole) navbarRole.textContent = currentUser.role;
      
      // Initialize Dashboard components depending on page loaded
      const isUserPage = window.location.pathname.includes('user-dashboard.html');
      const isAdminPage = window.location.pathname.includes('admin-dashboard.html');
      
      if (isUserPage) {
        initUserDashboard();
      } else if (isAdminPage) {
        if (currentUser.role !== 'Admin') {
          window.location.href = '/unauthorized';
          return;
        }
        initAdminDashboard();
      }
    })
    .catch(err => {
      console.error('Session validation error:', err);
      window.location.href = '/login';
    });
}


/* ==========================================================================
   USER DASHBOARD LOGIC
   ========================================================================== */

function initUserDashboard() {
  // Initial loading
  loadUserDashboardData();

  // Save Encrypted Note Button
  const saveNoteBtn = document.getElementById('btn-save-note');
  if (saveNoteBtn) {
    saveNoteBtn.addEventListener('click', saveSensitiveNote);
  }

  // Setup MFA Button
  const setupMfaBtn = document.getElementById('btn-setup-mfa');
  if (setupMfaBtn) {
    setupMfaBtn.addEventListener('click', initiateMfaSetup);
  }

  // Confirm MFA Activation Button
  const confirmMfaBtn = document.getElementById('btn-confirm-mfa-setup');
  if (confirmMfaBtn) {
    confirmMfaBtn.addEventListener('click', confirmMfaSetup);
  }

  // Cancel MFA Setup Button
  const cancelMfaBtn = document.getElementById('btn-cancel-mfa-setup');
  if (cancelMfaBtn) {
    cancelMfaBtn.addEventListener('click', cancelMfaSetup);
  }

  // Disable MFA Button
  const disableMfaBtn = document.getElementById('btn-disable-mfa');
  if (disableMfaBtn) {
    disableMfaBtn.addEventListener('click', deactivateMfaProtection);
  }
}

/**
 * Fetch personal sensitive note and current MFA status
 */
function loadUserDashboardData() {
  const cipherDisplay = document.getElementById('note-cipher-display');
  const plainDisplay = document.getElementById('note-plain-display');
  const noteInput = document.getElementById('personal-note-input');
  
  if (!cipherDisplay) return;

  fetch('/api/user/note')
    .then(res => {
      if (!res.ok) throw new Error();
      return res.json();
    })
    .then(data => {
      cipherDisplay.textContent = data.encryptedNote;
      plainDisplay.textContent = data.decryptedNote || '(Empty - Save a note to decrypt)';
      noteInput.value = data.decryptedNote;
      
      // Update MFA Status Panels
      toggleMfaPanels(data.twoFactorEnabled);
    })
    .catch(() => {
      showToast('Failed to retrieve sensitive account data', 'error');
    });
}

/**
 * Save and encrypt sensitive note at rest
 */
function saveSensitiveNote() {
  const noteInput = document.getElementById('personal-note-input');
  if (!noteInput) return;

  const note = noteInput.value;

  fetch('/api/user/note', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note })
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      showToast(data.message, 'success');
      loadUserDashboardData(); // Refresh UI Displays
    } else {
      showToast(data.error || 'Failed to save note', 'error');
    }
  })
  .catch(() => {
    showToast('Failed to connect to the database to encrypt data', 'error');
  });
}

/**
 * Toggle MFA display containers based on status
 */
function toggleMfaPanels(isEnabled) {
  const activeContainer = document.getElementById('mfa-status-active-container');
  const inactiveContainer = document.getElementById('mfa-status-inactive-container');
  const setupBindingContainer = document.getElementById('mfa-setup-binding-container');
  
  if (!activeContainer || !inactiveContainer) return;

  setupBindingContainer.style.display = 'none';

  if (isEnabled) {
    activeContainer.style.display = 'block';
    inactiveContainer.style.display = 'none';
  } else {
    activeContainer.style.display = 'none';
    inactiveContainer.style.display = 'block';
  }
}

/**
 * Fetch MFA secrets and QR setup configuration
 */
function initiateMfaSetup() {
  const setupBindingContainer = document.getElementById('mfa-setup-binding-container');
  const mfaInactiveContainer = document.getElementById('mfa-status-inactive-container');
  const qrImg = document.getElementById('mfa-qr-code');
  const secretKeyText = document.getElementById('mfa-secret-key');

  fetch('/api/mfa/setup')
    .then(res => res.json())
    .then(data => {
      qrImg.src = data.qrCode;
      secretKeyText.textContent = data.secret;
      
      // Hide status button and display binding fields
      mfaInactiveContainer.style.display = 'none';
      setupBindingContainer.style.display = 'block';
    })
    .catch(() => {
      showToast('Failed to setup MFA cryptographic keys', 'error');
    });
}

/**
 * Submit 6-digit TOTP token to activate MFA
 */
function confirmMfaSetup() {
  const tokenInput = document.getElementById('mfa-verify-code');
  const token = tokenInput.value.trim();

  if (token.length !== 6 || isNaN(token)) {
    showToast('Verification code must be exactly 6 digits', 'error');
    return;
  }

  fetch('/api/mfa/verify-setup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      showToast(data.message, 'success');
      tokenInput.value = '';
      loadUserDashboardData(); // Refresh UI profile status
    } else {
      showToast(data.error || 'Activation failed', 'error');
    }
  })
  .catch(() => {
    showToast('MFA Activation network error', 'error');
  });
}

/**
 * Revert MFA Setup View
 */
function cancelMfaSetup() {
  loadUserDashboardData();
}

/**
 * Disable TOTP MFA security
 */
function deactivateMfaProtection() {
  const tokenInput = document.getElementById('disable-mfa-token');
  const token = tokenInput.value.trim();

  if (token.length !== 6 || isNaN(token)) {
    showToast('You must enter your current 6-digit OTP code to confirm deactivation', 'error');
    return;
  }

  fetch('/api/mfa/disable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      showToast(data.message, 'warning');
      tokenInput.value = '';
      loadUserDashboardData(); // Refresh UI Profile
    } else {
      showToast(data.error || 'Failed to disable MFA', 'error');
    }
  })
  .catch(() => {
    showToast('Failed to connect to MFA servers', 'error');
  });
}


/* ==========================================================================
   ADMIN OPERATIONS DASHBOARD LOGIC
   ========================================================================== */

function initAdminDashboard() {
  // Load administrative dataset
  loadAdminDashboardData();

  // Bind audit logs manual refresh button
  const refreshLogsBtn = document.getElementById('btn-refresh-logs');
  if (refreshLogsBtn) {
    refreshLogsBtn.addEventListener('click', () => {
      loadAdminLogsAndStats();
      showToast('Security audit logs stream refreshed!', 'success');
    });
  }
}

/**
 * Load complete dataset (User registry, logs, and statistics)
 */
function loadAdminDashboardData() {
  loadAdminUsersList();
  loadAdminLogsAndStats();
}

/**
 * Retrieve user directory and populate Admin table
 */
function loadAdminUsersList() {
  const tableBody = document.getElementById('admin-users-table-body');
  if (!tableBody) return;

  fetch('/api/admin/users')
    .then(res => res.json())
    .then(users => {
      if (users.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--text-muted)">No registered users found.</td></tr>`;
        return;
      }

      // Populate counts
      document.getElementById('stat-total-users').textContent = users.length;
      document.getElementById('stat-mfa-users').textContent = users.filter(u => u.twoFactorEnabled).length;

      tableBody.innerHTML = '';
      users.forEach(u => {
        const row = document.createElement('tr');
        
        // Highlight active user row
        const isSelf = u._id === currentUser.id;
        const selfTextSuffix = isSelf ? ' <span style="font-size: 0.75rem; color: var(--accent-cyan)">(You)</span>' : '';
        const roleBadgeClass = u.role === 'Admin' ? 'role-badge admin' : 'role-badge user';
        
        // Clean display of database AES note ciphertext
        let cipherSnippet = u.personalNote;
        let cipherDisplay = '';
        if (!cipherSnippet) {
          cipherDisplay = '<span style="color: #444; font-size: 0.8rem;">(No Encrypted Data Stored)</span>';
        } else {
          // Truncate ciphertext for nice display, adding hover title
          const cleanSnippet = cipherSnippet.length > 32 ? `${cipherSnippet.substring(0, 30)}...` : cipherSnippet;
          cipherDisplay = `<span class="crypto-display cipher" style="font-size: 0.75rem; padding: 4px 8px; max-height: 40px; display: inline-block; cursor: pointer; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 250px;" title="${cipherSnippet}">${cleanSnippet}</span>`;
        }

        // Two-factor badge
        const mfaColor = u.twoFactorEnabled ? 'var(--color-success)' : 'var(--text-muted)';
        const mfaLabel = u.twoFactorEnabled ? '🛡️ Enabled' : 'Disabled';
        const mfaDisplay = `<span style="font-weight: 600; color: ${mfaColor};">${mfaLabel}</span>`;

        // Action controls
        let actionButtons = '';
        if (isSelf) {
          actionButtons = `<span style="color: var(--text-muted); font-size: 0.8rem; font-style: italic;">Active Session Protection</span>`;
        } else {
          const promotionBtnText = u.role === 'Admin' ? 'Demote to User' : 'Promote to Admin';
          const promotionRoleTarget = u.role === 'Admin' ? 'User' : 'Admin';
          const promotionClass = u.role === 'Admin' ? 'btn-secondary' : 'btn-primary';

          actionButtons = `
            <div class="actions-cell">
              <button class="btn ${promotionClass} btn-sm btn-sm-action" onclick="changeUserRole('${u._id}', '${promotionRoleTarget}')">
                ${promotionBtnText}
              </button>
              <button class="btn btn-danger btn-sm" onclick="deleteUserAccount('${u._id}', '${u.username}')">
                Delete Account
              </button>
            </div>
          `;
        }

        const cleanDate = new Date(u.createdAt).toLocaleDateString(undefined, { 
          year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' 
        });

        row.innerHTML = `
          <td><span style="font-weight: 700; color: #fff;">${u.username}</span>${selfTextSuffix}</td>
          <td><span class="${roleBadgeClass}" style="padding: 3px 10px; font-size: 0.7rem;">${u.role}</span></td>
          <td>${mfaDisplay}</td>
          <td>${cipherDisplay}</td>
          <td style="color: var(--text-muted); font-size: 0.8rem;">${cleanDate}</td>
          <td>${actionButtons}</td>
        `;

        tableBody.appendChild(row);
      });
    })
    .catch(() => {
      tableBody.innerHTML = `<tr><td colspan="6" class="text-center" style="color: var(--color-danger)">Critical: Failed to access user directory.</td></tr>`;
    });
}

/**
 * Retrieve Audit Event logs and calculate failure metrics
 */
function loadAdminLogsAndStats() {
  const logsConsole = document.getElementById('admin-logs-console');
  if (!logsConsole) return;

  fetch('/api/admin/logs')
    .then(res => res.json())
    .then(logs => {
      // Calculate Stats
      const failedLogins = logs.filter(l => l.eventType === 'LOGIN_FAILURE' || l.eventType === 'MFA_FAILED').length;
      const securityAlerts = logs.filter(l => 
        ['UNAUTHORIZED_ACCESS', 'RATE_LIMIT_EXCEEDED', 'USER_DELETED', 'ROLE_CHANGE'].includes(l.eventType)
      ).length;

      document.getElementById('stat-failed-logins').textContent = failedLogins;
      document.getElementById('stat-security-alerts').textContent = securityAlerts;

      logsConsole.innerHTML = '';
      if (logs.length === 0) {
        logsConsole.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding-top: 100px;">No events recorded in system audit.</div>';
        return;
      }

      logs.forEach(l => {
        const logDiv = document.createElement('div');
        
        // Define criticality style
        let logClass = 'log-entry success'; // Standard events
        if (['LOGIN_FAILURE', 'MFA_FAILED'].includes(l.eventType)) {
          logClass = 'log-entry failure';
        } else if (['UNAUTHORIZED_ACCESS', 'RATE_LIMIT_EXCEEDED'].includes(l.eventType)) {
          logClass = 'log-entry failure';
        } else if (['MFA_SETUP', 'MFA_DISABLED', 'USER_DELETED', 'ROLE_CHANGE'].includes(l.eventType)) {
          logClass = 'log-entry warning';
        }

        const dateStr = new Date(l.timestamp).toLocaleTimeString([], { 
          hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false 
        });
        const dateFull = new Date(l.timestamp).toISOString().split('T')[0];

        logDiv.className = logClass;
        logDiv.innerHTML = `
          <span class="log-time" title="${l.timestamp}">[${dateFull} ${dateStr}]</span>
          <span class="log-type">[${l.eventType}]</span>
          <span class="log-user" title="IP: ${l.ipAddress} | UA: ${l.userAgent}">@${l.username}</span>
          <span class="log-details">${l.details}</span>
        `;
        
        logsConsole.appendChild(logDiv);
      });

      // Tail logs automatically
      logsConsole.scrollTop = logsConsole.scrollHeight;
    })
    .catch(() => {
      logsConsole.innerHTML = '<div style="color: var(--color-danger)">System Error: Audit logs stream offline.</div>';
    });
}

/**
 * Handle Promoted/Demoted role requests
 */
window.changeUserRole = function(userId, newRole) {
  fetch(`/api/admin/user/${userId}/role`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: newRole })
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      showToast(data.message, 'success');
      loadAdminDashboardData(); // Refresh directory registry and logs
    } else {
      showToast(data.error || 'Failed to update user authorization', 'error');
    }
  })
  .catch(() => {
    showToast('Failed to send role assignment data to database', 'error');
  });
};

/**
 * Handle User deletion profile requests
 */
window.deleteUserAccount = function(userId, username) {
  if (!confirm(`⚠️ WARNING: Are you absolutely sure you want to permanently delete user account: "${username}"?\nThis operation is audited and cannot be undone.`)) {
    return;
  }

  fetch(`/api/admin/user/${userId}`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' }
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      showToast(data.message, 'warning');
      loadAdminDashboardData(); // Refresh directory registry and logs
    } else {
      showToast(data.error || 'Failed to delete user profile', 'error');
    }
  })
  .catch(() => {
    showToast('Failed to connect to the database to remove profile', 'error');
  });
};
