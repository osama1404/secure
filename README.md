# Secure Web Application – CyberShield

## Description
A secure web application developed as part of the Application Security and Secure Code course. This app
demonstrates secure coding practices including authentication, input validation, encryption, role-based
access control, and threat modeling.

---

## Tech Stack
- **Frontend:** Vanilla HTML5, CSS3 (Glassmorphism Dark Theme, neon glow transitions), and Javascript (AJAX, dynamic navigation adaptors, math CAPTCHA, single-page MFA challenge panels).
- **Backend:** Node.js with Express.js (Helmet, CORS policy, rate limiters, session managers).
- **Database:** MongoDB with Mongoose ODM (Object Document Mapper, secure session store).
- **Authentication:** Session-based (Secure, Masked SESS_ID cookies) + Speakeasy TOTP Multi-Factor Authentication.
- **Deployment:** Local environment / Hostable on Render or Heroku.

---

## Features
- User Registration/Login with Math CAPTCHA
- Role-based access: Admin/User
- Session management (Anti-Hijacking IP/UA fingerprinting, session fixation regeneration)
- Password hashing using bcryptjs (12 salt rounds)
- Encryption of sensitive data at rest using AES-256-GCM
- Input validation and sanitization (NoSQL injection and XSS defenses)
- STRIDE & DREAD security modeling
- Code scanning using ESLint (eslint-plugin-security), npm audit, Snyk

---

## Security Implementations
- **Input Validation:** `express-validator` (length, alphanumeric type assertions, validation chains)
- **Output Sanitization:** `xss` (anti-XSS sanitizing filters on user-controlled inputs)
- **Password Hashing:** `bcryptjs` (12 rounds of standard cryptographically salted hashes)
- **Encryption:** `AES-256-GCM` with randomized 12-byte IVs and 16-byte authenticity tags for sensitive fields (user personal notes, TOTP secret keys)
- **Session Management:** `connect-mongo` session database store, custom ID cookie masking (`SECURE_SESS_ID`), `httpOnly` flag active, `sameSite: 'strict'` active, 15-minute maximum session expiry, and session regeneration on authentication.
- **Headers:** Helmet for Content Security Policy (CSP), XSS protection, HSTS, and X-Frame-Options
- **CORS and rate limiting setup:** Restricted CORS origins, global rate limiter (100 reqs/15 mins), and authentication rate limiter (5 reqs/min)
- **Role-based Authorization:** Session-verified Role-Based Access Control (RBAC) middleware protecting APIs and dashboard HTML routes.

---

## Threat Modeling
- See `docs/STRIDE_Threat_Model.md`
- See `docs/DREAD_Risk_Assessment.md`

---

## Code Scanning Tools Used
- [ ] GitHub CodeQL
- [ ] SonarQube
- [ ] Checkmarx
- [x] Snyk (dependency scan configurations)
- [ ] Bandit (if Python)
- [x] ESLint `eslint-plugin-security` (static code scan)

Reports/screenshots are included in the `scans/` directory.

---

## Deployment
Link: Local Application (http://localhost:5000)

Instructions:
```bash
# clone project
git clone https://github.com/username/project.git
cd project

# install dependencies
npm install

# run app
node server.js
```
