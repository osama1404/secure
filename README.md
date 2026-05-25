# CyberShield: Secure Web Application & Audit Platform

A secure 3-tier web application built to demonstrate **Secure Software Development Lifecycle (SSDLC)** principles, complete with threat modeling (STRIDE), risk assessments (DREAD), multi-factor token authentication, and data encryption at rest.

---

## 🚀 Technology Stack

*   **Frontend UI:** Modern HTML5, custom responsive CSS (Glassmorphism Dark Theme, micro-animations, glowing dashboard templates).
*   **Frontend Logic:** Vanilla Javascript (AJAX session adaptors, mathematical CAPTCHA loaders, single-page MFA challenge panels).
*   **Backend Application:** Node.js, Express.js (Security header middleware, strict request rate limiters, session managers).
*   **Database Persistent Layer:** MongoDB, Mongoose ODM (Object Document Mapper, secure session store).
*   **Cryptographic & Security Modules:**
    *   `bcryptjs` (Password hashing via salted 12-round algorithms).
    *   `crypto` (AES-256-GCM symmetric block cipher encryption at rest).
    *   `speakeasy` (RFC 6238 Time-Based One-Time Password / TOTP MFA engine).
    *   `qrcode` (Dynamic server-side QR Code data URL generator).
    *   `helmet` (Dynamic security headers CSP, HSTS, X-Frame-Options policies).
    *   `express-rate-limit` (Brute-force and socket flooding mitigations).
    *   `express-validator` & `xss` (Structured input sanitizers and Cross-Site Scripting filters).

---

## 🔒 Implemented Security Features

### 1. Authentication & Authorization (RBAC)
*   **Role-Based Access Control (RBAC):** Users are assigned to `User` or `Admin` roles. Express middleware intercepts restricted routes (`requireRole(['User', 'Admin'])`), returning `403 Forbidden` on unauthorized access attempts.
*   **Dashboard Security:** Administrative pages (`/admin-dashboard.html`) and User dashboards (`/user-dashboard.html`) are served strictly via authorized Express routing endpoints to prevent unauthorized layout viewing.

### 2. Advanced Session Management
*   **Session Store Persistence:** Sessions are kept in MongoDB (`connect-mongo`) with a 15-minute TTL.
*   **Fingerprint Bindings (Anti-Hijacking):** The server generates a `sha256(User-Agent + Client-IP)` fingerprint during authentication. Any subsequent request with a mismatched fingerprint destroys the session immediately.
*   **Session Fixation Protection:** Session IDs are completely regenerated (`req.session.regenerate`) upon successful password or MFA login.
*   **Cookie Security:** Session cookies are masked (`SECURE_SESS_ID`) and configured with `httpOnly: true` (blocks XSS reading) and `sameSite: 'strict'` (blocks Cross-Site Request Forgeries).

### 3. Data Protection (Hashing & Encryption at Rest)
*   **Password Hashing:** Passwords are salted and hashed using Bcrypt with 12 rounds.
*   **AES-256-GCM Encryption:** User sensitive notes and TOTP secret keys are encrypted at rest using symmetric AES block ciphers with randomized 12-byte IVs and 16-byte authenticity integrity tags.

### 4. Brute-Force & Automated Threat Mitigations
*   **Math CAPTCHA:** Forms require validating a randomized algebraic equation (`X +/- Y = ?`) evaluated server-side, blocking login bots.
*   **Dual-Factor MFA:** Optional TOTP bindings display a QR code to register Google Authenticator. Users are dynamically challenged for 6-digit codes on login if active.
*   **Rate Limiting:** IPs are restricted to 100 requests per 15 minutes globally, and strictly capped at 5 attempts per minute on auth routes.

---

## 📄 Academic Security Audits & Reports

Comprehensive threat assessment documentations are available in the `docs` folder:
*   **STRIDE Threat Model:** [docs/STRIDE_Threat_Model.md](file:///Users/suadsayed/Desktop/ProjectSecure/docs/STRIDE_Threat_Model.md) (Data flow diagrams, STRIDE mappings, security mitigation controls).
*   **DREAD Risk Assessment:** [docs/DREAD_Risk_Assessment.md](file:///Users/suadsayed/Desktop/ProjectSecure/docs/DREAD_Risk_Assessment.md) (DREAD risk rating metrics, severity scores, and quantitative risk assessment matrices).

---

## 🛡️ Static Security Code Scanning & ESLint

The application's source code is audited using automated static analysis engines to ensure zero security vulnerabilities:
*   **ESLint (`eslint-plugin-security`):** Detects vulnerabilities such as unsafe regular expressions, non-literal cryptos, command injections, and unsafe string manipulation.
*   **Snyk Security Scanning:** Standard dependency scans run through Snyk engines to analyze package integrity.

---

## 🛠️ Installation & Setup Instructions

### Prerequisites
*   **Node.js:** Ensure Node.js is installed (`v20.x` or above).
*   **MongoDB:** A local MongoDB server running on `mongodb://127.0.0.1:27017` is required.

### 1. Extract Project Files & Install Dependencies
Navigate to the root directory and install dependencies:
```bash
npm install
```

### 2. Configure Environment Variables
Create a secure `.env` file at the root of the project with the following configuration:
```env
PORT=5000
DB_URI=mongodb://127.0.0.1:27017/University
SESSION_SECRET=d5f7823b1234a56789cd90ef1234567890abcdef1234567890abcdef12345678
ENCRYPTION_KEY=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```
*(Note: Change keys in a production environment. `ENCRYPTION_KEY` must be a valid 64-character hex string representing a 32-byte key).*

### 3. Launch the Application
Run the application server locally in development mode:
```bash
node server.js
```
*(Server will start running on `http://localhost:5000`)*

### 4. Admin Role Bootstrapping
*   The **very first registered user** in the application is automatically bootstrapped and authorized as the **System Admin**.
*   Subsequent signups will register standard **User** accounts.
*   Admin can log in and access the **Administrative Operations Panel** to promote standard users or review real-time security event logs!
