# DREAD Risk Assessment Report

## Application Name: CyberShield Secure Web Application

---

### Risk Matrix

| Threat | Damage Potential (D) | Reproducibility (R) | Exploitability (E) | Affected Users (A) | Discoverability (D) | Total (Max 50) | Risk Level |
|--------|----------------------|---------------------|--------------------|--------------------|---------------------|----------------|------------|
| NoSQL Injection | 8 | 7 | 8 | 9 | 8 | **40** | High |
| Session Hijack | 7 | 7 | 6 | 8 | 7 | **35** | High |
| XSS | 6 | 5 | 5 | 7 | 6 | **29** | Medium |
| Brute Force | 4 | 3 | 2 | 4 | 3 | **16** | Low |

*Scoring: Each category is rated on a scale from 1 (lowest) to 10 (highest).*
> D = Damage Potential  
> R = Reproducibility  
> E = Exploitability  
> A = Affected Users  
> D = Discoverability  

---

### Mitigation Summary
- **NoSQL Injection:** Use schema typing via Mongoose ORM, parameter filtering using `express-validator` sanitizer rules, and escape inputs.
- **XSS:** Escape client-controlled inputs using `xss`, restrict DOM injections using secure textContent rendering, and configure strict Helmet Content Security Policies (CSP).
- **Session Hijack:** Bind session IDs to hashed client fingerprints `sha256(User-Agent + Client-IP)`, regenerate session IDs (`req.session.regenerate`) after login, and use masked `httpOnly` SameSite=Strict cookies.
- **Brute Force:** Restrict input attempts using `express-rate-limit` (5 requests/minute on auth routes), enforce visual mathematical CAPTCHAs, and use Bcrypt password hashing.

---

## Risk Handling Strategy

*   **High Risks:** Fix before release. Must have active production mitigations implemented, unit-tested, and audited.
*   **Medium Risks:** Monitor and patch. Configure security scanning alerts, implement strict boundary controls, and monitor system event logs.
*   **Low Risks:** Accept or monitor. Keep logs of events and maintain rate-limiting checks.

---

## Risk Mitigation

- **High Risks**:
  *   **NoSQL Injection Mitigation:** Avoid raw concatenations; inputs are strictly sanitised and parsed using Mongoose ODM schemas.
  *   **Session Hijacking Mitigation:** Strict cookie flags (HttpOnly blocks JS read, SameSite=Strict blocks CSRF cross-origin sends). Session bound to User-Agent/IP hash fingerprinting. If fingerprint changes during session lifetime, server instantly clears cookies, destroys active session in Mongo session store, and logs a `UNAUTHORIZED_ACCESS` alert.
- **Medium Risks**:
  *   **XSS Mitigation:** Input values are cleaned using `xss` to eliminate script injections. Helmet headers block any attempts to run inline scripts or styles not allowed by strict Content Security Policy rules.
- **Low Risks**:
  *   **Brute Force Mitigation:** Set authentication rate limiter to 5 requests per minute, blocking fast loops. Render server-side generated algebraic Math CAPTCHA SVG challenges to block registration bots. Slow down brute force guesses via 12 salt rounds of salted Bcrypt hashing.
