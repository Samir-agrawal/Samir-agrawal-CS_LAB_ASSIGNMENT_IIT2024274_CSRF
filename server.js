// server.js - Apex Vault Bank (Port 3000) & Malicious Attacker Site (Port 4000)
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const BANK_PORT = process.env.PORT || 3000;
const ATTACKER_PORT = 4000;

/* ============================================================
   1. TARGET WEB APPLICATION: APEX VAULT BANK (Port 3000)
============================================================ */
const bankApp = express();

// Body & Cookie Parsers
bankApp.use(express.urlencoded({ extended: true }));
bankApp.use(express.json());
bankApp.use(cookieParser());

// Static Files
bankApp.use('/static', express.static(path.join(__dirname, 'public')));

// Session Configuration
bankApp.use(
  session({
    name: 'apex_vault_sid',
    secret: 'apex-vault-cybersecurity-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevents XSS theft of cookie, but does NOT protect against CSRF!
      sameSite: 'lax', // Demonstrates ambient credential submission
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

// Middleware: Attach User & CSRF Token to Request
bankApp.use((req, res, next) => {
  if (req.session && req.session.username) {
    req.user = db.getUser(req.session.username);
    // Ensure session has an Anti-CSRF token generated
    if (!req.session.csrfToken) {
      req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    }
  } else {
    req.user = null;
  }
  next();
});

// Auth Guard Middleware
function requireAuth(req, res, next) {
  if (!req.session || !req.session.username) {
    return res.redirect('/login?msg=Please+log+in+to+access+your+account');
  }
  next();
}

/* ------------------- BANK ROUTES ------------------- */

// Login Page
bankApp.get('/login', (req, res) => {
  if (req.session && req.session.username) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Login Handler
bankApp.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.getUser(username);

  if (user && user.password === password) {
    req.session.username = user.username;
    // Generate fresh CSRF token upon login
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    db.addAuditLog('LOGIN', `User ${username} logged in successfully.`, username);
    return res.redirect('/dashboard');
  }

  return res.redirect('/login?error=Invalid+credentials.+Try+alice+/+password123');
});

// Logout Handler
bankApp.get('/logout', (req, res) => {
  const user = req.session ? req.session.username : 'Unknown';
  db.addAuditLog('LOGOUT', `User ${user} logged out.`, user);
  req.session.destroy(() => {
    res.redirect('/login?msg=You+have+been+logged+out');
  });
});

// Dashboard Page
bankApp.get(['/', '/dashboard'], requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// API: Current User Data & App State (used by dynamic UI)
bankApp.get('/api/state', requireAuth, (req, res) => {
  const user = db.getUser(req.session.username);
  res.json({
    user: {
      username: user.username,
      fullName: user.fullName,
      accountNumber: user.accountNumber,
      balance: user.balance,
      role: user.role
    },
    csrfToken: req.session.csrfToken,
    securityMode: db.getSecurityMode(),
    allUsers: db.getAllUsers(),
    transactions: db.getTransactions(user.username),
    auditLogs: db.getAuditLogs().slice(0, 15)
  });
});

// API: Toggle Security Mode (VULNERABLE vs MITIGATED)
bankApp.post('/api/toggle-mode', requireAuth, (req, res) => {
  const { mode } = req.body;
  if (db.setSecurityMode(mode)) {
    return res.json({ success: true, mode: db.getSecurityMode() });
  }
  return res.status(400).json({ success: false, error: 'Invalid security mode' });
});

// API: Reset Lab Database State
bankApp.post('/api/reset', requireAuth, (req, res) => {
  db.reset();
  req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  res.json({ success: true, message: 'Database reset to initial demo state.' });
});

/* ============================================================
   PRIMARY ASSIGNMENT ENDPOINT: POST-Based Transfer Action
   Variant 2: POST-based forged action
============================================================ */
bankApp.post('/transfer', requireAuth, (req, res) => {
  const sender = req.session.username;
  const { recipient, amount, _csrf } = req.body;
  const currentMode = db.getSecurityMode();
  const requestOrigin = req.headers.origin || req.headers.referer || 'Unknown';
  const isCrossOrigin =
    requestOrigin.includes(`:${ATTACKER_PORT}`) ||
    (!requestOrigin.includes(`:${BANK_PORT}`) && requestOrigin !== 'Unknown');

  /* ------------------------------------------------------------
     (d) MITIGATION CHECK (Synchronizer Token Pattern)
     If in MITIGATED mode, verify the anti-CSRF token!
  ------------------------------------------------------------ */
  if (currentMode === 'MITIGATED') {
    const sessionToken = req.session.csrfToken;
    const submittedToken = _csrf || req.headers['x-csrf-token'];

    // Verify token presence and correctness
    if (!submittedToken || submittedToken !== sessionToken) {
      db.recordBlockedAttempt(
        sender,
        recipient,
        amount,
        'Anti-CSRF Synchronizer Token was missing or invalid',
        requestOrigin
      );

      // Return informative blocked response (demonstrated at viva)
      return res.status(403).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>403 Forbidden - CSRF Attack Blocked</title>
          <link rel="stylesheet" href="/static/css/style.css">
        </head>
        <body class="error-page">
          <div class="error-card blocked-card">
            <div class="badge badge-secure">🛡️ CSRF DEFENSE ACTIVE</div>
            <h2>HTTP 403 Forbidden: Request Blocked!</h2>
            <p class="error-desc">A cross-origin unauthorized state-changing request was detected and rejected by Apex Vault Bank.</p>
            <div class="technical-details">
              <p><strong>Reason:</strong> Anti-CSRF Synchronizer Token mismatch or missing.</p>
              <p><strong>Expected Session Token:</strong> <code>${sessionToken.substring(0, 10)}...</code></p>
              <p><strong>Received Token:</strong> <code>${submittedToken ? submittedToken : '(NONE / Empty)'}</code></p>
              <p><strong>Request Origin:</strong> <code>${requestOrigin}</code></p>
              <p><strong>Intended Action:</strong> Transfer $${amount} from <strong>${sender}</strong> to <strong>${recipient}</strong></p>
            </div>
            <div class="actions">
              <a href="/dashboard" class="btn btn-primary">Return to Dashboard</a>
            </div>
          </div>
        </body>
        </html>
      `);
    }
  }

  /* ------------------------------------------------------------
     (a) VULNERABLE CODE PATH:
     In VULNERABLE mode, request is executed without any CSRF check!
     Any cross-origin page hosting an auto-submitting form can
     trigger this state-changing transfer using ambient cookies!
  ------------------------------------------------------------ */
  const result = db.transferFunds(sender, recipient, amount, {
    isForged: isCrossOrigin,
    origin: requestOrigin,
    mode: currentMode
  });

  if (!result.success) {
    return res.status(400).send(`
      <!DOCTYPE html>
      <html>
      <head><title>Transfer Failed</title><link rel="stylesheet" href="/static/css/style.css"></head>
      <body class="error-page">
        <div class="error-card">
          <h2>Transfer Error</h2>
          <p>${result.error}</p>
          <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
        </div>
      </body>
      </html>
    `);
  }

  // If request came from the attacker's domain (port 4000), show exploit outcome!
  if (isCrossOrigin) {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>CSRF Exploit Succeeded!</title>
        <link rel="stylesheet" href="/static/css/style.css">
      </head>
      <body class="error-page">
        <div class="error-card exploit-success-card">
          <div class="badge badge-vulnerable">🚨 EXPLOIT SUCCESSFUL (VULNERABLE MODE)</div>
          <h2>Cross-Site Request Forgery Succeeded!</h2>
          <p class="error-desc">The forged POST request from <strong>${requestOrigin}</strong> was executed by Apex Vault using victim <strong>${sender}</strong>'s ambient credentials!</p>
          <div class="technical-details">
            <p><strong>Transferred:</strong> <span class="highlight-amount">$${amount}</span> to <strong>${recipient}</strong></p>
            <p><strong>Victim:</strong> ${sender} (was logged in)</p>
            <p><strong>Sender New Balance:</strong> $${result.newBalance}</p>
            <p><strong>Root Cause:</strong> The bank accepted this state-changing POST without verifying proof of user intent (missing CSRF token).</p>
          </div>
          <div class="actions">
            <a href="/dashboard" class="btn btn-primary">Inspect Bank Dashboard</a>
          </div>
        </div>
      </body>
      </html>
    `);
  }

  // Normal legitimate transfer redirect
  return res.redirect(`/dashboard?success=Transfer+of+$${amount}+to+${recipient}+completed`);
});

/* ============================================================
   OPTIONAL: Variant 1 (GET-based forged action)
   Provided for comprehensive lab coverage and viva bonus!
============================================================ */
bankApp.get('/transfer-get', requireAuth, (req, res) => {
  const sender = req.session.username;
  const { recipient, amount } = req.query;
  const currentMode = db.getSecurityMode();

  if (currentMode === 'MITIGATED') {
    return res.status(403).send('<h1>403 Forbidden: State-changing actions are prohibited over GET requests.</h1>');
  }

  db.transferFunds(sender, recipient, amount, {
    isForged: true,
    origin: req.headers.referer || 'GET-link',
    mode: currentMode
  });

  return res.redirect(`/dashboard?success=GET-based+Transfer+of+$${amount}+completed`);
});

// Start Bank Server
const bankServer = bankApp.listen(BANK_PORT, () => {
  console.log(`🏦 [Apex Vault Bank] Target Web Application running at: http://localhost:${BANK_PORT}`);
});

/* ============================================================
   2. ATTACKER'S MALICIOUS SERVER (Port 4000)
   Simulates an external attacker-controlled domain
============================================================ */
const attackerApp = express();

attackerApp.use('/static', express.static(path.join(__dirname, 'public')));

// Malicious Landing Page with Auto-Submitting CSRF Form
attackerApp.get(['/', '/claim-prize', '/exploit'], (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'attacker.html'));
});

// Start Attacker Server
const attackerServer = attackerApp.listen(ATTACKER_PORT, () => {
  console.log(`🦹 [Attacker Site] Malicious Web Server running at: http://localhost:${ATTACKER_PORT}`);
  console.log(`🔗 Exploit URL: http://localhost:${ATTACKER_PORT}/claim-prize`);
});

module.exports = { bankApp, attackerApp };
