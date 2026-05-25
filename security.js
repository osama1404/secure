const crypto = require('crypto');
const { SecurityLogModel } = require('./database');

// AES-256-GCM Configuration
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY 
  ? Buffer.from(process.env.ENCRYPTION_KEY, 'hex') 
  : crypto.randomBytes(32); // Fallback for safety (though .env has a fixed key)

const IV_LENGTH = 12; // GCM standard IV length
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypt sensitive text using AES-256-GCM
 */
function encryptData(text) {
  if (!text) return '';
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag().toString('hex');
    
    // Format: iv_hex:auth_tag_hex:ciphertext_hex
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
  } catch (err) {
    console.error('Encryption failed:', err.message);
    throw new Error('Encryption error');
  }
}

/**
 * Decrypt text encrypted with AES-256-GCM
 */
function decryptData(encryptedData) {
  if (!encryptedData) return '';
  try {
    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }
    
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encryptedText = parts[2];
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (err) {
    console.error('Decryption failed:', err.message);
    return '[Decryption Error: Sensitive Data Compromised or Invalid Key]';
  }
}

/**
 * Helper to record audit logs for security events
 */
async function logSecurityEvent(eventType, username, req, details = '') {
  try {
    let ipAddress = 'Unknown';
    let userAgent = 'Unknown';
    
    if (req) {
      ipAddress = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
      userAgent = req.headers['user-agent'] || 'Unknown';
    }
    
    const log = new SecurityLogModel({
      eventType,
      username: username || 'Anonymous',
      ipAddress,
      userAgent,
      details
    });
    
    await log.save();
    console.log(`[SECURITY EVENT] [${eventType}] User: ${username || 'Anonymous'} - ${details}`);
  } catch (err) {
    console.error('Failed to save security event log:', err.message);
  }
}

/**
 * Prevent Session Hijacking by binding session to User-Agent and IP Address
 */
function preventSessionHijacking(req, res, next) {
  if (req.session && req.session.user) {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const userAgent = req.headers['user-agent'] || '';
    
    const currentFingerprint = crypto.createHash('sha256')
      .update(userAgent + ip)
      .digest('hex');
      
    if (!req.session.fingerprint) {
      req.session.fingerprint = currentFingerprint;
    } else if (req.session.fingerprint !== currentFingerprint) {
      // Possible hijacking attempt
      logSecurityEvent(
        'UNAUTHORIZED_ACCESS', 
        req.session.user.username, 
        req, 
        'Session hijacking attempt blocked! IP or User-Agent fingerprint mismatch.'
      );
      
      // Destroy session
      req.session.destroy((err) => {
        if (err) console.error('Session destroy error during hijacking block:', err);
        return res.status(401).json({ error: 'Session compromised! Please re-authenticate.' });
      });
      return;
    }
  }
  next();
}

/**
 * Role-Based Access Control (RBAC) middleware
 */
function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.session || !req.session.user) {
      logSecurityEvent('UNAUTHORIZED_ACCESS', 'Anonymous', req, `Access denied for path: ${req.originalUrl} - Not Logged In`);
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      return res.redirect('/login');
    }
    
    const userRole = req.session.user.role;
    const hasAccess = Array.isArray(allowedRoles) 
      ? allowedRoles.includes(userRole) 
      : allowedRoles === userRole;
      
    if (!hasAccess) {
      logSecurityEvent(
        'UNAUTHORIZED_ACCESS', 
        req.session.user.username, 
        req, 
        `Access denied for path: ${req.originalUrl} - Required: ${allowedRoles}, Current: ${userRole}`
      );
      
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(403).json({ error: 'Access denied: Insufficient permissions' });
      }
      return res.redirect('/unauthorized');
    }
    
    next();
  };
}

/**
 * Generates an SVG Math CAPTCHA
 */
function generateCaptcha(req) {
  const num1 = Math.floor(Math.random() * 15) + 1; // 1 to 15
  const num2 = Math.floor(Math.random() * 10) + 1; // 1 to 10
  const operators = ['+', '-'];
  const operator = operators[Math.floor(Math.random() * operators.length)];
  
  let answer = 0;
  if (operator === '+') {
    answer = num1 + num2;
  } else {
    answer = num1 - num2;
  }
  
  // Store cryptographically in session
  req.session.captchaAnswer = answer;
  
  // Return SVG captcha
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="130" height="40" viewBox="0 0 130 40">
    <rect width="100%" height="100%" fill="#1a1c23" rx="6" stroke="#2a2f42" stroke-width="1.5" />
    <line x1="5" y1="12" x2="125" y2="28" stroke="rgba(0, 242, 254, 0.15)" stroke-width="2"/>
    <line x1="15" y1="32" x2="115" y2="8" stroke="rgba(224, 86, 253, 0.2)" stroke-width="1.5"/>
    <circle cx="20" cy="15" r="1.5" fill="rgba(0, 242, 254, 0.3)"/>
    <circle cx="95" cy="30" r="2" fill="rgba(224, 86, 253, 0.3)"/>
    <text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="18" font-weight="bold" fill="#00f2fe" letter-spacing="2">${num1} ${operator} ${num2} = ?</text>
  </svg>`;
  
  return svg;
}

module.exports = {
  encryptData,
  decryptData,
  logSecurityEvent,
  preventSessionHijacking,
  requireRole,
  generateCaptcha
};
