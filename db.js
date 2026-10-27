// db.js - State and persistence management for Apex Vault Bank
const INITIAL_ACCOUNTS = {
  alice: {
    username: 'alice',
    fullName: 'Alice Johnson',
    password: 'password123',
    accountNumber: 'APEX-10029',
    balance: 5000,
    role: 'customer'
  },
  attacker_bob: {
    username: 'attacker_bob',
    fullName: 'Bob Malory',
    password: 'password123',
    accountNumber: 'APEX-88392',
    balance: 150,
    role: 'customer'
  },
  charlie: {
    username: 'charlie',
    fullName: 'Charlie Davis',
    password: 'password123',
    accountNumber: 'APEX-44910',
    balance: 1200,
    role: 'customer'
  }
};

class BankDatabase {
  constructor() {
    this.reset();
  }

  reset() {
    // Deep clone initial accounts
    this.accounts = JSON.parse(JSON.stringify(INITIAL_ACCOUNTS));
    this.transactions = [
      {
        id: 1,
        timestamp: new Date(Date.now() - 3600000).toLocaleTimeString(),
        fromUser: 'Apex Employer Payroll',
        toUser: 'alice',
        amount: 5000,
        status: 'SUCCESS',
        mode: 'SYSTEM',
        note: 'Monthly Salary Credit'
      }
    ];
    this.auditLogs = [];
    // Default mode is VULNERABLE so the exploit works out-of-the-box
    this.securityMode = 'VULNERABLE'; // 'VULNERABLE' | 'MITIGATED'
  }

  getUser(username) {
    return this.accounts[username] || null;
  }

  getAllUsers() {
    return Object.values(this.accounts).map(u => ({
      username: u.username,
      fullName: u.fullName,
      accountNumber: u.accountNumber,
      balance: u.balance
    }));
  }

  getSecurityMode() {
    return this.securityMode;
  }

  setSecurityMode(mode) {
    if (mode === 'VULNERABLE' || mode === 'MITIGATED') {
      this.securityMode = mode;
      this.addAuditLog('MODE_CHANGE', `Security mode set to ${mode}`, 'System Admin');
      return true;
    }
    return false;
  }

  transferFunds(fromUsername, toUsername, amount, options = {}) {
    const sender = this.getUser(fromUsername);
    const receiver = this.getUser(toUsername);
    const parsedAmount = parseFloat(amount);

    if (!sender) {
      return { success: false, error: 'Sender account not found.' };
    }
    if (!receiver) {
      return { success: false, error: `Recipient account '${toUsername}' does not exist.` };
    }
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return { success: false, error: 'Invalid transfer amount specified.' };
    }
    if (sender.balance < parsedAmount) {
      return { success: false, error: `Insufficient funds. Available: $${sender.balance}.` };
    }

    // Execute transfer
    sender.balance -= parsedAmount;
    receiver.balance += parsedAmount;

    const txRecord = {
      id: this.transactions.length + 1,
      timestamp: new Date().toLocaleTimeString(),
      fromUser: fromUsername,
      toUser: toUsername,
      amount: parsedAmount,
      status: 'SUCCESS',
      mode: options.mode || this.securityMode,
      note: 'Online Wire Transfer'
    };
    this.transactions.unshift(txRecord);

    this.addAuditLog(
      'TRANSFER_EXECUTED',
      `$${parsedAmount} transferred from ${fromUsername} to ${toUsername} [Origin: ${options.origin || 'Unknown'}]`,
      fromUsername
    );

    return {
      success: true,
      transaction: txRecord,
      newBalance: sender.balance
    };
  }

  recordBlockedAttempt(fromUsername, toUsername, amount, reason, origin) {
    const txRecord = {
      id: this.transactions.length + 1,
      timestamp: new Date().toLocaleTimeString(),
      fromUser: fromUsername || 'Unknown',
      toUser: toUsername || 'Unknown',
      amount: parseFloat(amount) || 0,
      status: 'BLOCKED_CSRF',
      mode: 'MITIGATED',
      note: `🛡️ BLOCKED: ${reason}`
    };
    this.transactions.unshift(txRecord);

    this.addAuditLog(
      'CSRF_BLOCKED',
      `Suspicious cross-origin POST from ${origin || 'external origin'} blocked. Missing/invalid token.`,
      fromUsername || 'Anonymous'
    );

    return txRecord;
  }

  getTransactions(username) {
    return this.transactions.filter(
      tx => tx.fromUser === username || tx.toUser === username
    );
  }

  getAllTransactions() {
    return this.transactions;
  }

  addAuditLog(action, details, actor) {
    this.auditLogs.unshift({
      timestamp: new Date().toLocaleTimeString(),
      action,
      details,
      actor
    });
    if (this.auditLogs.length > 50) this.auditLogs.pop();
  }

  getAuditLogs() {
    return this.auditLogs;
  }
}

module.exports = new BankDatabase();
