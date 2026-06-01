/**
 * CyberShield - Dashboards Interactive Logic
 */

let currentUser = null;
let loadedNotes = [];

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

  // Step-Up Decryption Unlock Button
  const unlockNoteBtn = document.getElementById('btn-unlock-note');
  if (unlockNoteBtn) {
    unlockNoteBtn.addEventListener('click', decryptSensitiveNote);
  }

  // Step-Up Decryption Re-Lock Button
  const lockNoteBtn = document.getElementById('btn-lock-note');
  if (lockNoteBtn) {
    lockNoteBtn.addEventListener('click', lockSensitiveNote);
  }
}

/**
 * Fetch personal sensitive notes and current MFA status
 */
function loadUserDashboardData() {
  const gridContainer = document.getElementById('notes-grid-container');
  const decryptStatusText = document.getElementById('note-decrypt-status-text');
  const decryptOtpForm = document.getElementById('note-decrypt-otp-form');
  const unlockBtn = document.getElementById('btn-unlock-note');
  const otpInput = document.getElementById('decrypt-otp-input');
  
  if (!gridContainer) return;

  // Reset to locked UI state on initial load / refresh
  document.getElementById('note-decrypt-locked-container').style.display = 'block';
  document.getElementById('note-decrypt-unlocked-container').style.display = 'none';
  const archiveWrapper = document.getElementById('notes-archive-wrapper');
  if (archiveWrapper) archiveWrapper.style.display = 'none';
  if (otpInput) otpInput.value = '';

  fetch('/api/user/note')
    .then(res => {
      if (!res.ok) throw new Error();
      return res.json();
    })
    .then(data => {
      // 1. Populate the note cards grid
      gridContainer.innerHTML = '';
      if (!data.notes || data.notes.length === 0) {
        loadedNotes = [];
        gridContainer.innerHTML = `
          <div style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 40px;">
            📭 Your cryptographic notes archive is empty. Create a note above to secure it at rest!
          </div>
        `;
      } else {
        // Cache note list globally to support local ciphertext/plaintext toggling
        loadedNotes = data.notes.map(n => ({
          id: n.id,
          ciphertext: n.encryptedContent,
          plaintext: '',
          isDecrypted: false,
          currentView: 'cipher',
          createdAt: n.createdAt
        }));

        loadedNotes.forEach(note => {
          const card = document.createElement('div');
          card.className = 'glass-card stat-card note-card';
          card.id = `note-card-${note.id}`;
          card.style.cssText = 'flex-direction: column; align-items: stretch; gap: 12px; padding: 20px;';

          const cleanDate = new Date(note.createdAt).toLocaleDateString(undefined, { 
            year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' 
          });

          // Truncate long ciphertexts beautifully
          const cipherTextSnippet = note.ciphertext.length > 55 ? `${note.ciphertext.substring(0, 52)}...` : note.ciphertext;

          card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.03); padding-bottom: 8px;">
              <span class="note-status-header" style="font-weight: 700; color: var(--accent-pink); font-size: 0.75rem; letter-spacing: 0.05em;">🔒 ENCRYPTED CIPHER</span>
              <span style="color: var(--text-muted); font-size: 0.75rem;">${cleanDate}</span>
            </div>
            <div class="crypto-display cipher note-content-display" style="max-height: 80px; font-size: 0.75rem; cursor: help;" title="${note.ciphertext}">
              ${cipherTextSnippet}
            </div>
            <div class="actions-cell-note" style="display: flex; gap: 8px; margin-top: 4px;">
              <button class="btn btn-danger btn-sm btn-delete-note" data-id="${note.id}" style="padding: 6px 12px; font-size: 0.7rem; justify-content: center; width: 100%; border-radius: 6px;">
                🗑️ Delete Record
              </button>
            </div>
          `;
          gridContainer.appendChild(card);
        });

        // Bind delete listeners dynamically (avoids inline CSP blocks)
        gridContainer.querySelectorAll('.btn-delete-note').forEach(btn => {
          btn.addEventListener('click', (e) => {
            const noteId = e.currentTarget.getAttribute('data-id');
            deleteNote(noteId);
          });
        });
      }
      
      // 2. Enforce Step-Up MFA status check
      if (data.twoFactorEnabled) {
        decryptStatusText.textContent = "Your notes are secured under secondary Multi-Factor Authentication. Please enter your 6-digit Authenticator OTP below to unlock and decrypt your vault.";
        decryptOtpForm.style.display = 'block';
        unlockBtn.removeAttribute('disabled');
      } else {
        decryptStatusText.textContent = "⚠️ Multi-Factor Authentication (2FA) must be enabled on your account to activate this secure decryption vault. Please configure MFA on the right panel first!";
        decryptOtpForm.style.display = 'none';
        unlockBtn.setAttribute('disabled', 'true');
      }
      
      // 3. Update MFA Status Panels
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

  const note = noteInput.value.trim();
  if (!note) {
    showToast('Note content cannot be empty!', 'error');
    return;
  }

  fetch('/api/user/note', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note })
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      showToast(data.message, 'success');
      noteInput.value = ''; // Clear textarea
      loadUserDashboardData(); // Refresh UI Displays and re-lock note
    } else {
      showToast(data.error || 'Failed to save note', 'error');
    }
  })
  .catch(() => {
    showToast('Failed to connect to the database to encrypt data', 'error');
  });
}

/**
 * Request server-side note decryption via Step-Up OTP code
 */
function decryptSensitiveNote() {
  const otpInput = document.getElementById('decrypt-otp-input');
  const otpToken = otpInput ? otpInput.value.trim() : '';

  if (!otpToken || otpToken.length !== 6 || isNaN(otpToken)) {
    showToast('You must enter your current 6-digit Authenticator code to unlock this note', 'error');
    return;
  }

  fetch('/api/user/note/decrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ otpToken })
  })
  .then(res => res.json().then(data => ({ status: res.status, data })))
  .then(({ status, data }) => {
    if (status === 200 && data.success) {
      showToast('Step-up verification successful! Notes decrypted.', 'success');
      
      // Update each note card in the grid with its decrypted plaintext
      data.decryptedNotes.forEach(decrypted => {
        const note = loadedNotes.find(n => n.id === decrypted.id);
        if (note) {
          note.plaintext = decrypted.decryptedContent;
          note.isDecrypted = true;
          note.currentView = 'plain'; // default view to decrypted plaintext initially

          const card = document.getElementById(`note-card-${note.id}`);
          if (card) {
            const header = card.querySelector('.note-status-header');
            const contentBox = card.querySelector('.note-content-display');
            const actionsDiv = card.querySelector('.actions-cell-note');

            if (header) {
              header.textContent = '🔓 DECRYPTED VAULT NOTE';
              header.style.color = 'var(--accent-cyan)';
            }

            if (contentBox) {
              contentBox.className = 'crypto-display plain note-content-display';
              contentBox.style.color = 'var(--accent-cyan)';
              contentBox.style.borderLeftColor = 'var(--accent-cyan)';
              contentBox.textContent = note.plaintext || '(Empty Note)';
              contentBox.removeAttribute('title');
              contentBox.style.cursor = 'default';
            }

            // Append both dynamic view toggler button and delete button
            if (actionsDiv) {
              actionsDiv.innerHTML = `
                <button class="btn btn-secondary btn-sm btn-toggle-view" data-id="${note.id}" style="padding: 6px 12px; font-size: 0.7rem; justify-content: center; width: 100%; border-radius: 6px;">
                  🔒 View Ciphertext
                </button>
                <button class="btn btn-danger btn-sm btn-delete-note" data-id="${note.id}" style="padding: 6px 12px; font-size: 0.7rem; justify-content: center; width: 100%; border-radius: 6px;">
                  🗑️ Delete Record
                </button>
              `;
            }
          }
        }
      });

      // Bind dynamic toggle and delete event listeners for the unlocked grid state
      const unlockedGrid = document.getElementById('notes-grid-container');
      
      unlockedGrid.querySelectorAll('.btn-toggle-view').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const noteId = e.currentTarget.getAttribute('data-id');
          toggleNoteView(noteId);
        });
      });

      unlockedGrid.querySelectorAll('.btn-delete-note').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const noteId = e.currentTarget.getAttribute('data-id');
          deleteNote(noteId);
        });
      });

      // Transition UI to Unlocked Container
      document.getElementById('note-decrypt-locked-container').style.display = 'none';
      document.getElementById('note-decrypt-unlocked-container').style.display = 'block';
      const archiveWrapper = document.getElementById('notes-archive-wrapper');
      if (archiveWrapper) archiveWrapper.style.display = 'block';
      
      if (otpInput) otpInput.value = ''; // clear input
    } else {
      showToast(data.error || 'Failed to decrypt notes', 'error');
    }
  })
  .catch(() => {
    showToast('Failed to connect to decryption vault server', 'error');
  });
}

/**
 * Toggle visual note display between decrypted plaintext and encrypted GCM ciphertext
 */
function toggleNoteView(noteId) {
  const note = loadedNotes.find(n => n.id === noteId);
  if (!note || !note.isDecrypted) return;

  const card = document.getElementById(`note-card-${noteId}`);
  if (!card) return;

  const header = card.querySelector('.note-status-header');
  const contentBox = card.querySelector('.note-content-display');
  const toggleBtn = card.querySelector('.btn-toggle-view');

  if (note.currentView === 'plain') {
    // Toggle to Ciphertext View
    note.currentView = 'cipher';
    if (header) {
      header.textContent = '🔒 ENCRYPTED CIPHER';
      header.style.color = 'var(--accent-pink)';
    }
    if (contentBox) {
      contentBox.className = 'crypto-display cipher note-content-display';
      contentBox.style.color = 'var(--accent-pink)';
      contentBox.style.borderLeftColor = 'var(--accent-pink)';
      const cipherTextSnippet = note.ciphertext.length > 55 ? `${note.ciphertext.substring(0, 52)}...` : note.ciphertext;
      contentBox.textContent = cipherTextSnippet;
      contentBox.setAttribute('title', note.ciphertext);
      contentBox.style.cursor = 'help';
    }
    if (toggleBtn) {
      toggleBtn.textContent = '🔓 View Plaintext';
      toggleBtn.className = 'btn btn-primary btn-sm btn-toggle-view';
      toggleBtn.style.color = '#000'; // Make active cyan look good
    }
  } else {
    // Toggle to Plaintext View
    note.currentView = 'plain';
    if (header) {
      header.textContent = '🔓 DECRYPTED VAULT NOTE';
      header.style.color = 'var(--accent-cyan)';
    }
    if (contentBox) {
      contentBox.className = 'crypto-display plain note-content-display';
      contentBox.style.color = 'var(--accent-cyan)';
      contentBox.style.borderLeftColor = 'var(--accent-cyan)';
      contentBox.textContent = note.plaintext || '(Empty Note)';
      contentBox.removeAttribute('title');
      contentBox.style.cursor = 'default';
    }
    if (toggleBtn) {
      toggleBtn.textContent = '🔒 View Ciphertext';
      toggleBtn.className = 'btn btn-secondary btn-sm btn-toggle-view';
      toggleBtn.style.color = 'var(--text-main)'; // Restore secondary text color
    }
  }
}

/**
 * Re-lock the plaintext note container to protect privacy
 */
function lockSensitiveNote() {
  loadUserDashboardData(); // Simply re-load user dashboard data to secure and re-lock
  showToast('Personal note vault re-locked.', 'warning');
}

/**
 * Delete a specific note card permanently
 */
function deleteNote(noteId) {
  if (!confirm('⚠️ WARNING: Are you absolutely sure you want to permanently delete this secure note?\nThis operation will delete the record from MongoDB.')) {
    return;
  }

  fetch(`/api/user/note/${noteId}`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' }
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      showToast(data.message, 'warning');
      loadUserDashboardData(); // Refresh UI Displays
    } else {
      showToast(data.error || 'Failed to delete note', 'error');
    }
  })
  .catch(() => {
    showToast('Failed to connect to notes database to delete record', 'error');
  });
}

/**
brew services start mongodb-community
# OR run mongod directly:
mongod --dbpath /usr/local/var/mongodb */
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
        const selfTextSuffix = isSelf ? ' <span class="self-badge">You</span>' : '';
        const roleBadgeClass = u.role === 'Admin' ? 'role-badge admin' : 'role-badge user';
        
        // Clean display of database AES note ciphertext
        let cipherDisplay = '';
        if (u.personalNotes && u.personalNotes.length > 0) {
          const count = u.personalNotes.length;
          const lastNote = u.personalNotes[count - 1].encryptedContent;
          const cleanSnippet = lastNote.length > 25 ? `${lastNote.substring(0, 22)}...` : lastNote;
          cipherDisplay = `
            <div style="display: flex; flex-direction: column; gap: 4px;">
              <span style="font-weight: 700; color: var(--accent-cyan); font-size: 0.75rem;">🗂️ ${count} Secure Record(s)</span>
              <span class="crypto-display cipher" style="font-size: 0.7rem; padding: 2px 6px; max-height: 24px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 250px; display: inline-block;" title="Last Saved Ciphertext: ${lastNote}">${cleanSnippet}</span>
            </div>
          `;
        } else if (u.personalNote) {
          // Backward compatibility for users created prior to the array update
          let cipherSnippet = u.personalNote;
          const cleanSnippet = cipherSnippet.length > 25 ? `${cipherSnippet.substring(0, 22)}...` : cipherSnippet;
          cipherDisplay = `<span class="crypto-display cipher" style="font-size: 0.75rem; padding: 4px 8px; max-height: 40px; display: inline-block; cursor: pointer; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 250px;" title="${cipherSnippet}">${cleanSnippet}</span>`;
        } else {
          cipherDisplay = '<span style="color: #444; font-size: 0.8rem;">(No Encrypted Data Stored)</span>';
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
              <button class="btn ${promotionClass} btn-sm btn-sm-action btn-promote" data-id="${u._id}" data-role="${promotionRoleTarget}">
                ${promotionBtnText}
              </button>
              <button class="btn btn-danger btn-sm btn-delete" data-id="${u._id}" data-username="${u.username}">
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

      // Bind dynamic event listeners to bypass inline handler CSP blocks
      tableBody.querySelectorAll('.btn-promote').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const userId = e.currentTarget.getAttribute('data-id');
          const newRole = e.currentTarget.getAttribute('data-role');
          window.changeUserRole(userId, newRole);
        });
      });

      tableBody.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const userId = e.currentTarget.getAttribute('data-id');
          const username = e.currentTarget.getAttribute('data-username');
          window.deleteUserAccount(userId, username);
        });
      });
    })
    .catch((err) => {
      console.error(err);
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
