# DREAD Risk Assessment Report

**Project Name:** CyberShield Secure Web Application  
**Module:** Secure Software Development  
**Academic Target:** 15 Marks (Week 14)  
**Status:** Approved & Implemented  

---

## 1. Introduction to DREAD Risk Assessment

The **DREAD** model is a quantitative risk analysis framework used to assess the severity of security vulnerabilities. We evaluate threats using five criteria scored from 1 to 10 (with 10 being the most severe):

*   **Damage Potential (D):** How severe is the damage if the vulnerability is exploited?
*   **Reproducibility (R):** How easy is it for an attacker to reproduce the exploit?
*   **Exploitability (E):** How much technical skill or effort is required to exploit it?
*   **Affected Users (A):** How many users would be affected by a successful exploit?
*   **Discoverability (D):** How easy is it for an attacker to locate the vulnerability?

**Overall Risk Score Formula:**  
$$\text{Risk Score} = \frac{D + R + E + A + D}{5}$$

### Risk Rating Thresholds:
*   **Low Risk:** $1.0 - 3.9$
*   **Medium Risk:** $4.0 - 6.9$
*   **High Risk:** $7.0 - 10.0$

---

## 2. DREAD Risk Assessment Matrix

Below is the risk matrix mapping threats identified in the CyberShield application, their quantitative DREAD evaluations, and the direct remediation actions implemented:

| Threat ID | Threat Description | D | R | E | A | D | Avg Score | Risk Rating | Applied Remediation / Action |
| :--- | :--- | :-: | :-: | :-: | :-: | :-: | :---: | :---: | :--- |
| **TR-01** | **Brute-force / Password Spraying Attacks**<br>Attacker guesses password credentials of multiple users. | 7 | 8 | 9 | 4 | 9 | **7.4** | <span style="color:#ff3838; font-weight:bold;">HIGH</span> | 1. Rate-limiting limiting to 5 login requests/min per IP.<br>2. Dynamic Mathematical CAPTCHA blocks automated brute-force scripts.<br>3. Bcrypt (12 rounds) slows offline dictionary cracking. |
| **TR-02** | **Session Hijacking via Session ID Theft**<br>Attacker steals a session cookie via local sniffing or MITM. | 9 | 5 | 5 | 8 | 5 | **6.4** | <span style="color:#ffb300; font-weight:bold;">MEDIUM</span> | 1. IP & User-Agent hashed fingerprinting bound to sessions.<br>2. Session destroyed instantly if request fingerprint changes.<br>3. Cookies configured with HttpOnly and SameSite=Strict. |
| **TR-03** | **SQL / NoSQL Injection Attacks**<br>Attacker injects query parameters to bypass auth check. | 10 | 8 | 5 | 10 | 6 | **7.8** | <span style="color:#ff3838; font-weight:bold;">HIGH</span> | 1. Full ODM Mongoose schemas block direct NoSQL command injection.<br>2. Automatic parameter escaping using express-validator.<br>3. Unsafe raw Mongo DB queries completely avoided. |
| **TR-04** | **Cross-Site Scripting (XSS) Attacks**<br>Attacker inputs javascript to execute inside user dashboards. | 8 | 8 | 7 | 8 | 7 | **7.6** | <span style="color:#ff3838; font-weight:bold;">HIGH</span> | 1. Helmet headers enforce strict Content Security Policy (CSP).<br>2. Output sanitization using `xss` filters out script constructs.<br>3. Cookies hidden from JS via `HttpOnly`. |
| **TR-05** | **Privilege Escalation**<br>Standard user promoted to admin by injecting role parameters. | 9 | 7 | 4 | 2 | 5 | **5.4** | <span style="color:#ffb300; font-weight:bold;">MEDIUM</span> | 1. Server-side middleware check restricts role update endpoints.<br>2. User promotion completely barred from regular registration forms.<br>3. Strict RBAC checking session state roles. |
| **TR-06** | **Sensitive Data Leakage at Rest**<br>Attacker gains database backup files and reads user records. | 8 | 10 | 3 | 10 | 4 | **7.0** | <span style="color:#ff3838; font-weight:bold;">HIGH</span> | 1. Sensitive data fields (personal notes, MFA secrets) encrypted.<br>2. AES-256-GCM symmetric encryption with authentications.<br>3. Master key kept in server-side system .env variable files. |
| **TR-07** | **Denial of Service (DoS)**<br>Attacker floods request routers, overloading Mongoose DB. | 5 | 9 | 8 | 10 | 8 | **8.0** | <span style="color:#ff3838; font-weight:bold;">HIGH</span> | 1. Global API rate limits (100 queries / 15 mins).<br>2. JSON payload limited to 10kb to avoid memory exhaustions.<br>3. Session database stored session cleaning active. |

---

## 3. High-Risk Threat Analysis & Remediation Details

### TR-07: Denial of Service (Avg Score: 8.0)
*   **Threat Scenario:** An attacker launches a script that opens thousands of simultaneous connections to the landing page or login endpoints, depleting the server's TCP socket pool or overwhelming Mongoose database thread limits.
*   **DREAD Rationale:**
    *   **Damage Potential (5):** Temporary denial of service, but no direct data loss or data theft occurs.
    *   **Reproducibility (9):** Extremely high; script frameworks like `LOIC` or custom curl loops are trivial to run.
    *   **Exploitability (8):** Requires minimal knowledge to download a flood tool or write a loop script.
    *   **Affected Users (10):** All registered users are blocked from accessing the web application.
    *   **Discoverability (8):** Readily visible as the application has open endpoints on Port 5000.
*   **Mitigation Effectiveness:** Enforcing `express-rate-limit` dynamically logs the threat and returns a standard `429 Too Many Requests` response. Database memory is safeguarded by strict Express body parser limitations, which terminate requests exceeding a `10kb` buffer size.

### TR-03: SQL/NoSQL Injection (Avg Score: 7.8)
*   **Threat Scenario:** An attacker injects MongoDB operators like `{"username": {"$gt": ""}, "password": {"$gt": ""}}` inside a raw JSON login request to bypass credential comparison checks.
*   **DREAD Rationale:**
    *   **Damage Potential (10):** Total compromise of all user data and administrative takeover.
    *   **Reproducibility (8):** Readily reproducible once the API request format is inspected.
    *   **Exploitability (5):** Requires an understanding of NoSQL syntax and server frameworks.
    *   **Affected Users (10):** All registered user accounts and their associated files are exposed.
    *   **Discoverability (6):** Commonly probed on login/signup input variables.
*   **Mitigation Effectiveness:** Utilizing Mongoose ODM completely mitigates direct string-concatenation based NoSQL query injection because input fields are cast strictly to Schema types (e.g. `String`). Furthermore, `express-validator` sanitizes and filters input parameters before queries are processed.
