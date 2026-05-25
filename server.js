const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const xss = require('xss');
const { body, validationResult } = require('express-validator');

require('dotenv').config();

const { UserModel, SecurityLogModel } = require('./database');
const { 
  encryptData, 
  decryptData, 
  logSecurityEvent, 
  preventSessionHijacking, 
  requireRole, 
  generateCaptcha 
} = require('./security');

const app = express();
const PORT = process.env.PORT || 5000;

// 1. Helmet for Security Headers (with strict Content Security Policy)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Allow self and page-specific logic
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"], // data: is required for our local SVG CAPTCHA and MFA QR codes
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [], // Enforce HTTPS if available
    }
  },
  referrerPolicy: { policy: 'same-origin' },
  crossOriginEmbedderPolicy: false
}));

// 2. Strict CORS Configuration
app.use(cors({
  origin: ['http://localhost:5000', 'http://127.0.0.1:5000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 3. Body parsers & Cookie parser
app.use(express.json({ limit: '10kb' })); // Mitigate DOS by limiting payload sizes
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// 4. Session Configuration with MongoDB Store
app.use(session({
  name: 'SECURE_SESS_ID', // Mask standard connect.sid cookie name
  secret: process.env.SESSION_SECRET || 'fallback-super-secret-key-12345',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.DB_URI || 'mongodb://127.0.0.1:27017/University',
    collectionName: 'sessions',
    ttl: 15 * 60 // 15 mins session TTL
  }),
  cookie: {
    httpOnly: true, // Prevent cross-site scripting (XSS) from reading session cookies
    secure: false, // In production, must be true (requires HTTPS)
    sameSite: 'strict', // Mitigate Cross-Site Request Forgery (CSRF)
    maxAge: 15 * 60 * 1000 // 15 minutes
  }
}));

// 5. Session Hijacking Verification
app.use(preventSessionHijacking);

// 6. Rate Limiting to prevent DOS & Brute Force
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100, // Limit each IP to 100 requests per window
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests from this IP, please try again later.' },
  handler: (req, res, next, options) => {
    logSecurityEvent('RATE_LIMIT_EXCEEDED', 'Anonymous', req, 'Global rate limit breached');
    res.status(options.statusCode).json(options.message);
  }
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  limit: 5, // Limit to 5 attempts per minute
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again in 1 minute.' },
  handler: (req, res, next, options) => {
    const username = req.body.username || 'Anonymous';
    logSecurityEvent('RATE_LIMIT_EXCEEDED', username, req, `Auth rate limit breached for username: ${username}`);
    res.status(options.statusCode).json(options.message);
  }
});

// --- API ROUTES ---

// Math CAPTCHA Generator
app.get('/api/captcha', (req, res) => {
  const svg = generateCaptcha(req);
  res.type('image/svg+xml').send(svg);
});

// Register Account API
app.post('/api/signup', authLimiter, [
  body('username')
    .isAlphanumeric()
    .withMessage('Username must be alphanumeric')
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be between 3 and 20 characters')
    .trim()
    .escape(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }

  const { username, password, captchaAnswer } = req.body;

  // CAPTCHA Validation
  if (!captchaAnswer || parseInt(captchaAnswer) !== req.session.captchaAnswer) {
    logSecurityEvent('LOGIN_FAILURE', username, req, 'Signup blocked: Invalid CAPTCHA answer');
    return res.status(400).json({ error: 'Incorrect CAPTCHA answer. Please try again.' });
  }

  // Clear CAPTCHA after verification
  req.session.captchaAnswer = null;

  try {
    const existingUser = await UserModel.findOne({ username: username.toLowerCase() });
    if (existingUser) {
      logSecurityEvent('LOGIN_FAILURE', username, req, 'Signup failed: Username already exists');
      return res.status(400).json({ error: 'Username is already taken' });
    }

    // Secure Hashing (Bcrypt with 12 rounds)
    const hashedPassword = await bcrypt.hash(password, 12);

    // Bootstrap first registered user as Admin, subsequent as regular User
    const userCount = await UserModel.countDocuments();
    const role = userCount === 0 ? 'Admin' : 'User';

    const newUser = new UserModel({
      username: username.toLowerCase(),
      password: hashedPassword,
      role
    });

    await newUser.save();
    logSecurityEvent('LOGIN_SUCCESS', username, req, `New account registered as role: ${role}`);
    
    return res.json({ success: true, message: `Account created successfully as ${role}! You can now login.` });
  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'An unexpected database error occurred' });
  }
});

// Login API
app.post('/api/login', authLimiter, [
  body('username').trim().escape(),
  body('password').trim()
], async (req, res) => {
  const { username, password, captchaAnswer, mfaToken } = req.body;

  // CAPTCHA Validation
  if (!captchaAnswer || parseInt(captchaAnswer) !== req.session.captchaAnswer) {
    logSecurityEvent('LOGIN_FAILURE', username, req, 'Login blocked: Invalid CAPTCHA answer');
    return res.status(400).json({ error: 'Incorrect CAPTCHA answer. Please try again.' });
  }

  try {
    const user = await UserModel.findOne({ username: username.toLowerCase() });
    if (!user) {
      // Prevent User Enumeration by using generic error message
      logSecurityEvent('LOGIN_FAILURE', username, req, 'Failed login: Username not found');
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      logSecurityEvent('LOGIN_FAILURE', username, req, 'Failed login: Incorrect password');
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Check if 2FA (MFA) is enabled
    if (user.twoFactorEnabled) {
      // If MFA token is missing, request MFA verification
      if (!mfaToken) {
        req.session.preAuth = {
          id: user._id,
          username: user.username,
          role: user.role
        };
        logSecurityEvent('MFA_FAILED', user.username, req, 'MFA challenge requested');
        return res.json({ mfaRequired: true });
      }

      // Verify MFA Token
      const decryptedSecret = decryptData(user.twoFactorSecret);
      const verified = speakeasy.totp.verify({
        secret: decryptedSecret,
        encoding: 'base32',
        token: mfaToken,
        window: 1 // Allow 30 seconds clock drift
      });

      if (!verified) {
        logSecurityEvent('MFA_FAILED', user.username, req, 'MFA login challenge failed: Invalid token');
        return res.status(401).json({ error: 'Invalid verification token' });
      }
    }

    // Clear CAPTCHA after verification
    req.session.captchaAnswer = null;

    // Successful login: Implement Session Fixation Prevention
    const userSessionData = {
      id: user._id,
      username: user.username,
      role: user.role
    };

    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).json({ error: 'Failed to establish secure session' });
      }

      req.session.user = userSessionData;

      // Fingerprint session binding
      const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
      const userAgent = req.headers['user-agent'] || '';
      req.session.fingerprint = crypto.createHash('sha256')
        .update(userAgent + ip)
        .digest('hex');

      logSecurityEvent('LOGIN_SUCCESS', user.username, req, `User logged in. Session initialized as role: ${user.role}`);
      return res.json({ success: true, role: user.role });
    });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error during login' });
  }
});

// Verify login for MFA 2nd-Step
app.post('/api/mfa/verify-login', authLimiter, async (req, res) => {
  const { mfaToken } = req.body;
  if (!req.session.preAuth) {
    return res.status(400).json({ error: 'No authentication flow in progress' });
  }

  const { id, username, role } = req.session.preAuth;

  try {
    const user = await UserModel.findById(id);
    if (!user || !user.twoFactorEnabled) {
      req.session.preAuth = null;
      return res.status(400).json({ error: 'MFA not enabled' });
    }

    const decryptedSecret = decryptData(user.twoFactorSecret);
    const verified = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: 'base32',
      token: mfaToken,
      window: 1
    });

    if (!verified) {
      logSecurityEvent('MFA_FAILED', username, req, 'MFA verification failed');
      return res.status(401).json({ error: 'Invalid verification token' });
    }

    // Success: Login user
    const userSessionData = { id, username, role };
    req.session.preAuth = null;

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to establish secure session' });
      }
      
      req.session.user = userSessionData;
      
      const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
      const userAgent = req.headers['user-agent'] || '';
      req.session.fingerprint = crypto.createHash('sha256')
        .update(userAgent + ip)
        .digest('hex');

      logSecurityEvent('LOGIN_SUCCESS', username, req, 'Successful MFA verification');
      return res.json({ success: true, role });
    });

  } catch (err) {
    console.error('MFA Login Verification error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout API
app.post('/api/logout', (req, res) => {
  if (req.session && req.session.user) {
    const username = req.session.user.username;
    logSecurityEvent('LOGOUT', username, req, 'User logged out');
    
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Could not log out' });
      }
      res.clearCookie('SECURE_SESS_ID');
      return res.json({ success: true });
    });
  } else {
    return res.status(400).json({ error: 'No active session' });
  }
});

// Check Session Status API
app.get('/api/session', (req, res) => {
  if (req.session && req.session.user) {
    return res.json({ loggedIn: true, user: req.session.user });
  }
  return res.json({ loggedIn: false });
});


// --- SECURE USER APIs (Authenticated) ---

// Get & Update Sensitive Encrypted Note at Rest
app.get('/api/user/note', requireRole(['User', 'Admin']), async (req, res) => {
  try {
    const user = await UserModel.findById(req.session.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    let decryptedNote = '';
    if (user.personalNote) {
      decryptedNote = decryptData(user.personalNote);
    }

    return res.json({ 
      encryptedNote: user.personalNote || '(Empty - No Note Saved)', 
      decryptedNote,
      twoFactorEnabled: user.twoFactorEnabled
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve sensitive note' });
  }
});

app.post('/api/user/note', requireRole(['User', 'Admin']), [
  body('note').trim().customSanitizer(value => xss(value)) // Output sanitization / anti-XSS
], async (req, res) => {
  const { note } = req.body;
  
  try {
    const user = await UserModel.findById(req.session.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Encrypt at rest using AES-256-GCM
    user.personalNote = encryptData(note);
    await user.save();

    await logSecurityEvent('NOTE_UPDATE', user.username, req, 'Sensitive personal note updated & encrypted at rest');
    return res.json({ success: true, message: 'Note encrypted and saved at rest successfully!' });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to save encrypted note' });
  }
});

// MFA Setup Endpoint
app.get('/api/mfa/setup', requireRole(['User', 'Admin']), async (req, res) => {
  try {
    const user = await UserModel.findById(req.session.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Generate TOTP Secret
    const secret = speakeasy.generateSecret({
      name: `SecureWebApp:${user.username}`,
      issuer: 'SecureUniversity'
    });

    // Encrypt secret at rest before saving temporarily
    user.twoFactorSecret = encryptData(secret.base32);
    user.twoFactorEnabled = false; // Do not enable until verified
    await user.save();

    // Generate QR Code URL
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    await logSecurityEvent('MFA_SETUP', user.username, req, 'MFA registration initiated');
    return res.json({ 
      secret: secret.base32, 
      qrCode: qrCodeUrl 
    });
  } catch (err) {
    console.error('MFA Setup error:', err);
    return res.status(500).json({ error: 'Failed to setup MFA' });
  }
});

// Verify and enable MFA Setup
app.post('/api/mfa/verify-setup', requireRole(['User', 'Admin']), async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token is required' });

  try {
    const user = await UserModel.findById(req.session.user.id);
    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ error: 'MFA setup not initialized' });
    }

    const decryptedSecret = decryptData(user.twoFactorSecret);
    const verified = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      await logSecurityEvent('MFA_FAILED', user.username, req, 'MFA setup validation failed');
      return res.status(400).json({ error: 'Invalid verification token. MFA not enabled.' });
    }

    user.twoFactorEnabled = true;
    await user.save();

    await logSecurityEvent('MFA_VERIFIED', user.username, req, 'MFA activated successfully');
    return res.json({ success: true, message: 'Multi-Factor Authentication enabled successfully!' });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to verify MFA setup' });
  }
});

// Disable MFA
app.post('/api/mfa/disable', requireRole(['User', 'Admin']), async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Verification token is required to disable MFA' });

  try {
    const user = await UserModel.findById(req.session.user.id);
    if (!user || !user.twoFactorEnabled) {
      return res.status(400).json({ error: 'MFA is not enabled' });
    }

    const decryptedSecret = decryptData(user.twoFactorSecret);
    const verified = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      await logSecurityEvent('MFA_FAILED', user.username, req, 'Failed to disable MFA: Incorrect token');
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    user.twoFactorEnabled = false;
    user.twoFactorSecret = null;
    await user.save();

    await logSecurityEvent('MFA_DISABLED', user.username, req, 'MFA deactivated');
    return res.json({ success: true, message: 'Multi-Factor Authentication disabled successfully.' });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to disable MFA' });
  }
});


// --- ADMIN APIs (Authenticated + Admin Role) ---

// Get all users
app.get('/api/admin/users', requireRole('Admin'), async (req, res) => {
  try {
    const users = await UserModel.find({}, 'username role twoFactorEnabled createdAt personalNote');
    return res.json(users);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve users' });
  }
});

// Edit user role
app.post('/api/admin/user/:id/role', requireRole('Admin'), async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  if (!['Admin', 'User'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role specified' });
  }

  // Prevent self-demotion
  if (id === req.session.user.id) {
    return res.status(400).json({ error: 'Access Denied: You cannot change your own role!' });
  }

  try {
    const user = await UserModel.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const oldRole = user.role;
    user.role = role;
    await user.save();

    await logSecurityEvent(
      'ROLE_CHANGE', 
      req.session.user.username, 
      req, 
      `Changed role of user ${user.username} from ${oldRole} to ${role}`
    );
    return res.json({ success: true, message: `Role of ${user.username} updated to ${role}!` });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to change role' });
  }
});

// Delete user
app.delete('/api/admin/user/:id', requireRole('Admin'), async (req, res) => {
  const { id } = req.params;

  // Prevent self-deletion
  if (id === req.session.user.id) {
    return res.status(400).json({ error: 'Access Denied: You cannot delete your own admin account!' });
  }

  try {
    const user = await UserModel.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    await UserModel.findByIdAndDelete(id);
    
    await logSecurityEvent(
      'USER_DELETED', 
      req.session.user.username, 
      req, 
      `Deleted user account: ${user.username}`
    );
    return res.json({ success: true, message: `User ${user.username} deleted successfully!` });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Get security logs
app.get('/api/admin/logs', requireRole('Admin'), async (req, res) => {
  try {
    const logs = await SecurityLogModel.find()
      .sort({ timestamp: -1 })
      .limit(100);
    return res.json(logs);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve audit logs' });
  }
});


// --- PROTECTED STATIC FRONTEND ROUTES ---
// Serve dashboards and pages securely only if authorized

app.get('/user-dashboard.html', requireRole(['User', 'Admin']), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
});

app.get('/admin-dashboard.html', requireRole('Admin'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/unauthorized', (req, res) => {
  res.status(403).send(`
    <html>
      <head>
        <title>403 Access Denied</title>
        <style>
          body { background: #0b0c10; color: #66fcf1; font-family: sans-serif; text-align: center; padding-top: 100px; }
          h1 { font-size: 50px; color: #ff007f; text-shadow: 0 0 10px #ff007f; }
          a { color: #00f2fe; text-decoration: none; border: 1px solid #00f2fe; padding: 10px 20px; border-radius: 4px; display: inline-block; margin-top: 20px; transition: 0.3s; }
          a:hover { background: #00f2fe; color: #000; box-shadow: 0 0 15px #00f2fe; }
        </style>
      </head>
      <body>
        <h1>ACCESS DENIED</h1>
        <p>You do not have the required permissions to view this resource.</p>
        <a href="/">Go Back Home</a>
      </body>
    </html>
  `);
});

// Serve regular public files
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Fallback index.html mapping
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`============================================================`);
  console.log(` SECURE EXPRESS APP SERVER RUNNING NOW ON PORT ${PORT} `);
  console.log(` Access locally via: http://localhost:${PORT} `);
  console.log(`============================================================`);
});