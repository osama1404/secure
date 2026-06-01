/**
 * CyberShield - Shared Frontend JavaScript
 */

document.addEventListener('DOMContentLoaded', () => {
  // Check active session and update navigation
  checkSessionStatus();

  // Load CAPTCHA if form elements exist
  const captchaBox = document.getElementById('captcha-box');
  if (captchaBox) {
    loadCaptcha();
  }

  // Setup CAPTCHA refresh listener
  const refreshBtn = document.getElementById('btn-refresh-captcha');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', loadCaptcha);
  }

  // Signup Form Submission Handler
  const signupForm = document.getElementById('signup-form');
  if (signupForm) {
    signupForm.addEventListener('submit', handleSignupSubmit);
  }

  // Login Form Submission Handler
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', handleLoginSubmit);
  }

  // MFA 2nd-Factor Login Form Submission Handler
  const mfaLoginForm = document.getElementById('mfa-login-form');
  if (mfaLoginForm) {
    mfaLoginForm.addEventListener('submit', handleMfaLoginSubmit);
  }

  // Global Logout Button Handler
  const logoutBtn = document.getElementById('btn-logout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', handleLogout);
  }
});

/**
 * Custom Toast Notification System
 */
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  if (type === 'error') icon = '❌';
  if (type === 'warning') icon = '⚠️';

  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  container.appendChild(toast);

  // Auto remove toast
  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => {
      toast.remove();
    }, 500);
  }, 4000);
}

/**
 * Fetch and Render Math CAPTCHA
 */
function loadCaptcha() {
  const captchaBox = document.getElementById('captcha-box');
  if (!captchaBox) return;

  captchaBox.innerHTML = '<span style="color: var(--text-muted)">Generating...</span>';
  
  fetch('/api/captcha')
    .then(response => {
      if (!response.ok) throw new Error();
      return response.text();
    })
    .then(svg => {
      captchaBox.innerHTML = svg;
      // Clear CAPTCHA input
      const captchaInput = document.getElementById('captchaAnswer');
      if (captchaInput) captchaInput.value = '';
    })
    .catch(() => {
      captchaBox.innerHTML = '<span style="color: var(--color-danger)">CAPTCHA Error</span>';
    });
}

/**
 * Sign Up Submission Handler
 */
function handleSignupSubmit(e) {
  e.preventDefault();
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const captchaAnswer = document.getElementById('captchaAnswer').value;

  fetch('/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, captchaAnswer })
  })
  .then(res => res.json().then(data => ({ status: res.status, data })))
  .then(({ status, data }) => {
    if (status === 200 && data.success) {
      showToast(data.message, 'success');
      setTimeout(() => {
        window.location.href = '/login';
      }, 2000);
    } else {
      showToast(data.error || 'Registration failed', 'error');
      loadCaptcha(); // Reload captcha on failure
    }
  })
  .catch(err => {
    showToast('Failed to connect to the authentication server', 'error');
    loadCaptcha();
  });
}

/**
 * First Factor Login Submission Handler
 */
let storedUsername = ''; // Cache username temporarily for MFA second-step form submission
let storedPassword = ''; // Cache password temporarily for MFA second-step form submission

function handleLoginSubmit(e) {
  e.preventDefault();
  
  storedUsername = document.getElementById('username').value;
  storedPassword = document.getElementById('password').value;
  const captchaAnswer = document.getElementById('captchaAnswer').value;

  fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: storedUsername, password: storedPassword, captchaAnswer })
  })
  .then(res => res.json().then(data => ({ status: res.status, data })))
  .then(({ status, data }) => {
    if (status === 200) {
      if (data.mfaRequired) {
        // MFA 2FA token required - slide in 2FA screen
        showToast('First factor authenticated! Authenticator token required.', 'warning');
        document.getElementById('login-step-container').style.display = 'none';
        document.getElementById('mfa-step-container').style.display = 'block';
      } else if (data.success) {
        showToast('Login successful! Welcome back.', 'success');
        setTimeout(() => {
          if (data.role === 'Admin') {
            window.location.href = '/admin-dashboard.html';
          } else {
            window.location.href = '/user-dashboard.html';
          }
        }, 1200);
      }
    } else {
      showToast(data.error || 'Authentication failed', 'error');
      loadCaptcha(); // Reload captcha on failure
    }
  })
  .catch(err => {
    showToast('Failed to connect to the authentication server', 'error');
    loadCaptcha();
  });
}

/**
 * Second Factor MFA Login Submission Handler
 */
function handleMfaLoginSubmit(e) {
  e.preventDefault();
  
  const mfaToken = document.getElementById('mfaToken').value;

  fetch('/api/mfa/verify-login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfaToken })
  })
  .then(res => res.json().then(data => ({ status: res.status, data })))
  .then(({ status, data }) => {
    if (status === 200 && data.success) {
      showToast('Second-factor verified! Establishing secure session.', 'success');
      setTimeout(() => {
        if (data.role === 'Admin') {
          window.location.href = '/admin-dashboard.html';
        } else {
          window.location.href = '/user-dashboard.html';
        }
      }, 1200);
    } else {
      showToast(data.error || 'Verification code invalid. Please try again.', 'error');
      document.getElementById('mfaToken').value = '';
    }
  })
  .catch(err => {
    showToast('Network error during second-factor verification', 'error');
  });
}

/**
 * Account Logout Handler
 */
function handleLogout() {
  fetch('/api/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  })
  .then(res => res.json())
  .then(data => {
    showToast('Session destroyed. Logging out...', 'warning');
    setTimeout(() => {
      window.location.href = '/';
    }, 1200);
  })
  .catch(() => {
    // If API call fails, force redirect to landing page
    window.location.href = '/';
  });
}

/**
 * Check active session on initial page load and adapt UI options
 */
function checkSessionStatus() {
  const navbarLinks = document.getElementById('navbar-links');
  const heroActionButtons = document.getElementById('hero-action-buttons');
  
  fetch('/api/session')
    .then(res => res.json())
    .then(data => {
      if (data.loggedIn && data.user) {
        const u = data.user;
        
        // Adapt Navbar Links
        if (navbarLinks) {
          let roleBadgeClass = u.role === 'Admin' ? 'role-badge admin' : 'role-badge user';
          
          let navHtml = `<a href="/" class="nav-link">Home</a>`;
          if (u.role === 'Admin') {
            navHtml += `
              <a href="/admin-dashboard.html" class="nav-link">Admin Panel</a>
              <a href="/user-dashboard.html" class="nav-link">User Dashboard</a>
            `;
          } else {
            navHtml += `
              <a href="/user-dashboard.html" class="nav-link">Dashboard</a>
            `;
          }
          navHtml += `
            <span class="${roleBadgeClass}">${u.role}</span>
            <button id="btn-logout" class="btn btn-secondary btn-sm">Logout</button>
          `;
          
          navbarLinks.innerHTML = navHtml;
          
          // Re-bind the logout button
          document.getElementById('btn-logout').addEventListener('click', handleLogout);
        }

        // Adapt Landing Hero Buttons if they exist
        if (heroActionButtons) {
          let dashboardLink = u.role === 'Admin' ? '/admin-dashboard.html' : '/user-dashboard.html';
          heroActionButtons.innerHTML = `
            <a href="${dashboardLink}" class="btn btn-primary">Go to Dashboard Portal</a>
            <button id="btn-logout-hero" class="btn btn-secondary">Logout Session</button>
          `;
          document.getElementById('btn-logout-hero').addEventListener('click', handleLogout);
        }
      }
    })
    .catch(err => console.log('Session check bypassed/offline'));
}
