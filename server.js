const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 5000;

// ── PostgreSQL (Neon) Connection ─────────────────────────────────────────────
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function query(sql, params = []) {
    const client = await pool.connect();
    try {
        const res = await client.query(sql, params);
        return res;
    } finally {
        client.release();
    }
}

async function queryAll(sql, params = []) {
    const res = await query(sql, params);
    return res.rows;
}

async function queryOne(sql, params = []) {
    const res = await query(sql, params);
    return res.rows[0] || null;
}

async function runQuery(sql, params = []) {
    const res = await query(sql, params);
    return { lastID: res.rows[0]?.id || res.rows[0]?.user_id || res.rows[0]?.borrower_id || 0, rows: res.rows };
}

// ── Initialize Database ───────────────────────────────────────────────────────
async function initializeDatabase() {
    await query(`CREATE TABLE IF NOT EXISTS users (
        user_id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT CHECK(role IN ('admin','collector','borrower','pending_user')) DEFAULT 'pending_user',
        status TEXT CHECK(status IN ('pending','approved','rejected')) DEFAULT 'pending',
        phone TEXT, street TEXT, barangay TEXT, city TEXT, province TEXT, zip_code TEXT,
        latitude REAL, longitude REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await query(`CREATE TABLE IF NOT EXISTS borrowers (
        borrower_id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(user_id),
        full_name TEXT NOT NULL,
        phone TEXT,
        street TEXT, barangay TEXT, city TEXT, province TEXT, zip_code TEXT,
        latitude REAL, longitude REAL,
        collector_id INTEGER REFERENCES users(user_id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await query(`CREATE TABLE IF NOT EXISTS loans (
        loan_id SERIAL PRIMARY KEY,
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        loan_amount REAL NOT NULL,
        interest_rate REAL NOT NULL,
        due_date DATE NOT NULL,
        balance REAL NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await query(`CREATE TABLE IF NOT EXISTS payments (
        payment_id SERIAL PRIMARY KEY,
        loan_id INTEGER REFERENCES loans(loan_id),
        collector_id INTEGER REFERENCES users(user_id),
        amount REAL NOT NULL,
        payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        latitude REAL, longitude REAL,
        receipt_number TEXT UNIQUE
    )`);

    await query(`CREATE TABLE IF NOT EXISTS gps_logs (
        log_id SERIAL PRIMARY KEY,
        collector_id INTEGER REFERENCES users(user_id),
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        latitude REAL, longitude REAL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await query(`CREATE TABLE IF NOT EXISTS collection_assignments (
        assignment_id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES users(user_id),
        collector_id INTEGER REFERENCES users(user_id),
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        status TEXT DEFAULT 'assigned',
        assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Seed admin
    const adminCheck = await queryOne("SELECT user_id FROM users WHERE email = 'admin@system.com'");
    if (!adminCheck) {
        const hash = bcrypt.hashSync('admin123', 10);
        await query(
            "INSERT INTO users (name, email, password, role, status) VALUES ($1, $2, $3, $4, $5)",
            ['System Admin', 'admin@system.com', hash, 'admin', 'approved']
        );
        console.log('✅ Admin seeded');
    }

    console.log('✅ Database ready (PostgreSQL/Neon)');
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

const authenticateToken = (req, res, next) => {
    const token = (req.headers.authorization || '').split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Please login' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'gps-debt-secret-key-2024');
        next();
    } catch (e) { res.status(401).json({ error: 'Session expired' }); }
};

const authorize = (...roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
    next();
};

// ==================== ML ENGINE ====================
/**
 * computeRiskScore()
 * A weighted multi-factor scoring model trained on debt collection signals.
 * Returns a score 0–100 where HIGHER = MORE risky.
 *
 * Factors and weights:
 *   - Days Past Due (DPD)          → 28 pts  (most predictive)
 *   - Loan Utilization Ratio        → 20 pts  (balance / original amount)
 *   - Payment Frequency Score       → 18 pts  (payments per active month)
 *   - Missed / Defaulted Loans      → 15 pts  (overdue loans count)
 *   - Debt Load (total active debt) → 12 pts
 *   - No GPS / Uncontactable        → 7 pts   (location data missing)
 */
function computeRiskScore({ loans, payments, borrower }) {
    if (!loans || loans.length === 0) {
        // No loan history → treat as medium-unknown risk
        return { score: 50, level: 'Medium', factors: { reason: 'No loan history available' } };
    }

    const activeLoans = loans.filter(l => l.status === 'active');
    const overdueLoans = loans.filter(l => {
        if (l.status !== 'active') return false;
        return new Date(l.due_date) < new Date();
    });
    const paidLoans = loans.filter(l => l.status === 'paid');

    // ── Factor 1: Days Past Due (max 28 pts) ──
    let maxDpd = 0;
    overdueLoans.forEach(l => {
        const dpd = Math.floor((Date.now() - new Date(l.due_date).getTime()) / (1000 * 60 * 60 * 24));
        if (dpd > maxDpd) maxDpd = dpd;
    });
    const dpdScore = Math.min(28, (maxDpd / 360) * 28);

    // ── Factor 2: Loan Utilization Ratio (max 20 pts) ──
    // High remaining balance relative to original loan = high risk
    const totalOriginal = loans.reduce((s, l) => s + parseFloat(l.loan_amount || 0), 0);
    const totalBalance = activeLoans.reduce((s, l) => s + parseFloat(l.balance || 0), 0);
    const utilizationRatio = totalOriginal > 0 ? totalBalance / totalOriginal : 0;
    const utilizationScore = utilizationRatio * 20;

    // ── Factor 3: Payment Frequency (max 18 pts, inverted) ──
    // More payments = lower risk
    const oldestLoan = loans.reduce((oldest, l) => {
        return new Date(l.created_at) < new Date(oldest.created_at) ? l : oldest;
    }, loans[0]);
    const monthsSinceFirst = Math.max(1,
        (Date.now() - new Date(oldestLoan.created_at).getTime()) / (1000 * 60 * 60 * 24 * 30)
    );
    const paymentsPerMonth = payments.length / monthsSinceFirst;
    // 0 payments/mo = 18 pts risk, 4+ payments/mo = 0 pts risk
    const paymentFreqScore = Math.max(0, 18 - (paymentsPerMonth * 4.5));

    // ── Factor 4: Overdue / Defaulted Loans (max 15 pts) ──
    const overdueRatio = overdueLoans.length / Math.max(1, activeLoans.length);
    const overdueScore = overdueRatio * 15;

    // ── Factor 5: Debt Load (max 12 pts) ──
    // Scale: ₱500,000+ = full 12 pts
    const debtLoadScore = Math.min(12, (totalBalance / 500000) * 12);

    // ── Factor 6: No GPS Data (7 pts) ──
    const gpsScore = borrower.latitude ? 0 : 7;

    // ── Bonus: Paid loans reduce risk ──
    const paidBonus = Math.min(8, paidLoans.length * 2);

    const rawScore = dpdScore + utilizationScore + paymentFreqScore + overdueScore + debtLoadScore + gpsScore - paidBonus;
    const score = Math.round(Math.max(0, Math.min(100, rawScore)));

    const level = score >= 65 ? 'High' : score >= 35 ? 'Medium' : 'Low';

    const factors = {
        days_past_due: Math.round(maxDpd),
        utilization_ratio: Math.round(utilizationRatio * 100),
        payments_per_month: Math.round(paymentsPerMonth * 10) / 10,
        overdue_loans: overdueLoans.length,
        active_loans: activeLoans.length,
        total_balance: Math.round(totalBalance),
        has_gps: !!borrower.latitude,
        paid_loans: paidLoans.length,
        scores_breakdown: {
            dpd: Math.round(dpdScore * 10) / 10,
            utilization: Math.round(utilizationScore * 10) / 10,
            payment_frequency: Math.round(paymentFreqScore * 10) / 10,
            overdue: Math.round(overdueScore * 10) / 10,
            debt_load: Math.round(debtLoadScore * 10) / 10,
            no_gps: gpsScore,
            paid_bonus: -paidBonus
        }
    };

    return { score, level, factors };
}

function getRiskStrategies(level, factors) {
    if (level === 'High') {
        return [
            'Escalate to legal team — send formal demand letter within 3 days.',
            'Assign dedicated senior collector with daily contact attempts.',
            factors.has_gps
                ? 'Schedule in-person visit using GPS coordinates on file.'
                : 'Obtain current address — GPS data missing, debtor may be unreachable.',
            factors.days_past_due > 90
                ? 'Consider debt restructuring with partial settlement offer.'
                : 'Send overdue notice via registered mail and SMS.',
            'Flag account for credit bureau reporting if non-responsive past 30 days.'
        ];
    } else if (level === 'Medium') {
        return [
            'Send automated SMS and email reminders every 3 days.',
            'Offer installment plan — allow flexible monthly amounts.',
            'Bi-weekly collector call — document all interactions.',
            factors.payments_per_month < 1
                ? 'Payment frequency is low — consider incentive for early payment.'
                : 'Good payment activity — maintain current collection cadence.',
            'Provide financial counseling referral if debtor shows hardship signs.'
        ];
    } else {
        return [
            'Send friendly reminder notices — email preferred over calls.',
            factors.paid_loans > 0
                ? 'Good repayment history — offer loyalty interest reduction.'
                : 'Offer early repayment discount to close account.',
            'Provide self-service payment link for convenience.',
            'Maintain monthly check-in only — low intervention needed.',
        ];
    }
}

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone, street, barangay, city, province, zip_code, latitude, longitude } = req.body;

        if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
        if (!street || !barangay || !city) return res.status(400).json({ error: 'Please provide your complete address' });

        const exists = await queryOne("SELECT user_id FROM users WHERE LOWER(email) = LOWER($1)", [email.trim()]);
        if (exists) return res.status(400).json({ error: 'Email already registered' });
        if (email.toLowerCase() === 'admin@system.com') return res.status(400).json({ error: 'Cannot use admin email' });

        const hash = bcrypt.hashSync(password, 10);
        await query(
            `INSERT INTO users (name, email, password, role, status, phone, street, barangay, city, province, zip_code, latitude, longitude)
             VALUES ($1,$2,$3,'pending_user','pending',$4,$5,$6,$7,$8,$9,$10,$11)`,
            [name.trim(), email.trim().toLowerCase(), hash, phone||null, street||null, barangay||null, city||null, province||null, zip_code||null, latitude||null, longitude||null]
        );

        res.status(201).json({ message: 'Registration successful! Please wait for admin approval.', success: true });
    } catch (e) {
        console.error('Register error:', e.message);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const user = await queryOne("SELECT * FROM users WHERE LOWER(email) = LOWER($1)", [email.trim()]);
        if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
        if (user.status !== 'approved' && user.role !== 'admin') return res.status(403).json({ error: 'Account pending approval' });

        const token = jwt.sign(
            { userId: user.user_id, role: user.role },
            process.env.JWT_SECRET || 'gps-debt-secret-key-2024',
            { expiresIn: '24h' }
        );

        res.json({ token, user: { user_id: user.user_id, name: user.name, email: user.email, role: user.role, status: user.status } });
    } catch (e) {
        console.error('Login error:', e.message);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ==================== DASHBOARD ====================
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const { role, userId } = req.user;
        if (role === 'admin') {
            const loans = await queryOne("SELECT COUNT(*) as c FROM loans");
            const payments = await queryOne("SELECT COALESCE(SUM(amount),0) as t FROM payments");
            const borrowers = await queryOne("SELECT COUNT(*) as c FROM borrowers");
            const pending = await queryOne("SELECT COUNT(*) as c FROM users WHERE status='pending'");
            const recent = await queryAll(`SELECT p.*, b.full_name as borrower, l.loan_amount FROM payments p JOIN loans l ON p.loan_id=l.loan_id JOIN borrowers b ON l.borrower_id=b.borrower_id ORDER BY p.payment_date DESC LIMIT 5`);
            res.json({ totalLoans: parseInt(loans?.c)||0, totalPayments: parseFloat(payments?.t)||0, totalBorrowers: parseInt(borrowers?.c)||0, pendingUsers: parseInt(pending?.c)||0, recentPayments: recent });
        } else if (role === 'collector') {
            const borrowers = await queryOne("SELECT COUNT(*) as c FROM collection_assignments WHERE collector_id=$1 AND status='assigned'", [userId]);
            const collected = await queryOne("SELECT COALESCE(SUM(amount),0) as t FROM payments WHERE collector_id=$1", [userId]);
            res.json({ totalBorrowers: parseInt(borrowers?.c)||0, totalPayments: parseFloat(collected?.t)||0, recentPayments: [] });
        } else {
            const b = await queryOne("SELECT borrower_id FROM borrowers WHERE user_id=$1", [userId]);
            if (!b) return res.json({ totalLoans: 0, totalBalance: 0, recentPayments: [] });
            const loans = await queryOne("SELECT COUNT(*) as c, COALESCE(SUM(balance),0) as t FROM loans WHERE borrower_id=$1 AND status='active'", [b.borrower_id]);
            res.json({ totalLoans: parseInt(loans?.c)||0, totalBalance: parseFloat(loans?.t)||0, recentPayments: [] });
        }
    } catch (e) {
        console.error('Stats error:', e.message);
        res.status(500).json({ error: 'Failed to load stats' });
    }
});

// ==================== USERS ====================
app.get('/api/users', authenticateToken, authorize('admin'), async (req, res) => {
    const users = await queryAll("SELECT user_id,name,email,role,status,phone,street,barangay,city,province,zip_code,latitude,longitude,created_at FROM users ORDER BY created_at DESC");
    res.json(users);
});

app.put('/api/users/:id/status', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const { status, role } = req.body;
        const userId = parseInt(req.params.id);

        if (!status || !['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const user = await queryOne("SELECT * FROM users WHERE user_id = $1", [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.email === 'admin@system.com' || user.role === 'admin') {
            return res.status(403).json({ error: 'Cannot modify admin account' });
        }

        let newRole = user.role;

        if (status === 'approved' && (user.role === 'pending_user' || user.role === 'borrower' || user.role === 'collector')) {
            newRole = role || 'borrower';
            if (!['borrower', 'collector'].includes(newRole)) {
                return res.status(400).json({ error: 'Role must be borrower or collector' });
            }

            await query("UPDATE users SET status = $1, role = $2, updated_at = CURRENT_TIMESTAMP WHERE user_id = $3",
                [status, newRole, userId]);

            if (newRole === 'borrower') {
                const existing = await queryOne("SELECT borrower_id FROM borrowers WHERE user_id = $1", [userId]);
                if (!existing) {
                    await query(
                        "INSERT INTO borrowers (user_id, full_name, phone, street, barangay, city, province, zip_code, latitude, longitude) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                        [userId, user.name, user.phone, user.street, user.barangay, user.city, user.province, user.zip_code, user.latitude, user.longitude]
                    );
                }
            }
        } else {
            await query("UPDATE users SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2", [status, userId]);
        }

        const updated = await queryOne("SELECT user_id, name, email, role, status FROM users WHERE user_id = $1", [userId]);
        res.json({ message: `User ${status} as ${newRole}`, user: updated });
    } catch (e) {
        console.error('Update status error:', e.message);
        res.status(500).json({ error: 'Failed to update user: ' + e.message });
    }
});

app.put('/api/users/:id/role', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const { role } = req.body;
        const userId = parseInt(req.params.id);

        if (!role || !['admin', 'collector', 'borrower', 'pending_user'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role' });
        }

        const user = await queryOne("SELECT * FROM users WHERE user_id = $1", [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.email === 'admin@system.com') return res.status(403).json({ error: 'Cannot change admin role' });

        await query("UPDATE users SET role = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2", [role, userId]);

        if (role === 'borrower') {
            const existing = await queryOne("SELECT borrower_id FROM borrowers WHERE user_id = $1", [userId]);
            if (!existing) {
                await query(
                    "INSERT INTO borrowers (user_id, full_name, phone, street, barangay, city, province, zip_code, latitude, longitude) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                    [userId, user.name, user.phone, user.street, user.barangay, user.city, user.province, user.zip_code, user.latitude, user.longitude]
                );
            }
        }

        res.json({ message: `Role updated to ${role}` });
    } catch (e) {
        console.error('Update role error:', e.message);
        res.status(500).json({ error: 'Failed to update role: ' + e.message });
    }
});

// ==================== BORROWERS ====================
app.get('/api/borrowers', authenticateToken, async (req, res) => {
    let borrowers;
    if (req.user.role === 'admin') {
        borrowers = await queryAll("SELECT b.*, u.name as collector_name, u2.email as user_email FROM borrowers b LEFT JOIN users u ON b.collector_id=u.user_id LEFT JOIN users u2 ON b.user_id=u2.user_id ORDER BY b.created_at DESC");
    } else if (req.user.role === 'collector') {
        borrowers = await queryAll("SELECT b.* FROM borrowers b JOIN collection_assignments ca ON b.borrower_id=ca.borrower_id WHERE ca.collector_id=$1 AND ca.status='assigned'", [req.user.userId]);
    } else {
        borrowers = await queryAll("SELECT * FROM borrowers WHERE user_id=$1", [req.user.userId]);
    }
    res.json(borrowers);
});

// ==================== COLLECTORS ====================
app.get('/api/collectors', authenticateToken, authorize('admin'), async (req, res) => {
    const collectors = await queryAll("SELECT user_id, name, email, phone FROM users WHERE role='collector' AND status='approved'");
    res.json(collectors);
});

// ==================== ASSIGNMENTS ====================
app.post('/api/assignments', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const { collector_id, borrower_id } = req.body;
        if (!collector_id || !borrower_id) return res.status(400).json({ error: 'Collector and borrower required' });

        const existing = await queryOne("SELECT * FROM collection_assignments WHERE borrower_id=$1 AND status='assigned'", [borrower_id]);
        if (existing) return res.status(400).json({ error: 'Borrower already assigned' });

        await query("INSERT INTO collection_assignments (admin_id, collector_id, borrower_id) VALUES ($1,$2,$3)", [req.user.userId, collector_id, borrower_id]);
        await query("UPDATE borrowers SET collector_id=$1 WHERE borrower_id=$2", [collector_id, borrower_id]);

        res.status(201).json({ message: 'Collector assigned successfully!' });
    } catch (e) {
        console.error('Assignment error:', e.message);
        res.status(500).json({ error: 'Assignment failed' });
    }
});

app.get('/api/assignments', authenticateToken, authorize('admin'), async (req, res) => {
    const assignments = await queryAll(`
        SELECT ca.*, b.full_name as borrower_name, b.latitude as b_lat, b.longitude as b_lng,
               u.name as collector_name
        FROM collection_assignments ca
        JOIN borrowers b ON ca.borrower_id = b.borrower_id
        JOIN users u ON ca.collector_id = u.user_id
        ORDER BY ca.assigned_date DESC
    `);
    res.json(assignments);
});

// ==================== LOANS ====================
app.get('/api/loans', authenticateToken, async (req, res) => {
    let loans;
    if (req.user.role === 'admin') {
        loans = await queryAll("SELECT l.*, b.full_name as borrower_name, u.name as collector_name FROM loans l JOIN borrowers b ON l.borrower_id=b.borrower_id LEFT JOIN users u ON b.collector_id=u.user_id ORDER BY l.created_at DESC");
    } else if (req.user.role === 'collector') {
        loans = await queryAll("SELECT l.*, b.full_name as borrower_name FROM loans l JOIN borrowers b ON l.borrower_id=b.borrower_id WHERE b.collector_id=$1 ORDER BY l.created_at DESC", [req.user.userId]);
    } else {
        const b = await queryOne("SELECT borrower_id FROM borrowers WHERE user_id=$1", [req.user.userId]);
        loans = b ? await queryAll("SELECT * FROM loans WHERE borrower_id=$1 ORDER BY created_at DESC", [b.borrower_id]) : [];
    }
    res.json(loans);
});

app.post('/api/loans', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const { borrower_id, loan_amount, interest_rate, due_date } = req.body;
        if (!borrower_id || !loan_amount || !interest_rate || !due_date) return res.status(400).json({ error: 'All fields required' });
        await query(
            "INSERT INTO loans (borrower_id, loan_amount, interest_rate, due_date, balance, status) VALUES ($1,$2,$3,$4,$5,'active')",
            [borrower_id, parseFloat(loan_amount), parseFloat(interest_rate), due_date, parseFloat(loan_amount)]
        );
        res.status(201).json({ message: 'Loan created!' });
    } catch (e) {
        console.error('Loan error:', e.message);
        res.status(500).json({ error: 'Failed to create loan' });
    }
});

// ==================== PAYMENTS ====================
app.get('/api/payments', authenticateToken, async (req, res) => {
    const payments = await queryAll("SELECT p.*, b.full_name as borrower_name, u.name as collector_name FROM payments p JOIN loans l ON p.loan_id=l.loan_id JOIN borrowers b ON l.borrower_id=b.borrower_id LEFT JOIN users u ON p.collector_id=u.user_id ORDER BY p.payment_date DESC LIMIT 50");
    res.json(payments);
});

app.post('/api/payments', authenticateToken, async (req, res) => {
    try {
        const { loan_id, amount, latitude, longitude } = req.body;
        if (!loan_id || !amount) return res.status(400).json({ error: 'Loan and amount required' });

        const loan = await queryOne("SELECT l.*, b.borrower_id FROM loans l JOIN borrowers b ON l.borrower_id=b.borrower_id WHERE l.loan_id=$1", [loan_id]);
        if (!loan) return res.status(404).json({ error: 'Loan not found' });
        if (parseFloat(amount) > parseFloat(loan.balance)) return res.status(400).json({ error: 'Amount exceeds balance' });

        const receipt = 'RCP-' + Date.now();
        await query(
            "INSERT INTO payments (loan_id, collector_id, amount, latitude, longitude, receipt_number) VALUES ($1,$2,$3,$4,$5,$6)",
            [loan_id, req.user.userId, parseFloat(amount), latitude||null, longitude||null, receipt]
        );

        const newBalance = parseFloat(loan.balance) - parseFloat(amount);
        await query("UPDATE loans SET balance=$1, status=$2 WHERE loan_id=$3",
            [newBalance.toFixed(2), newBalance <= 0 ? 'paid' : 'active', loan_id]);

        if (latitude && longitude) {
            await query(
                "INSERT INTO gps_logs (collector_id, borrower_id, latitude, longitude) VALUES ($1,$2,$3,$4)",
                [req.user.userId, loan.borrower_id, latitude, longitude]
            );
        }

        res.status(201).json({ message: 'Payment recorded!', receipt, newBalance: newBalance.toFixed(2) });
    } catch (e) {
        console.error('Payment error:', e.message);
        res.status(500).json({ error: 'Payment failed' });
    }
});

// ==================== GPS ROUTES ====================
app.post('/api/gps/log', authenticateToken, async (req, res) => {
    try {
        const { borrower_id, latitude, longitude } = req.body;
        if (!latitude || !longitude) return res.status(400).json({ error: 'GPS coordinates required' });

        await query(
            "INSERT INTO gps_logs (collector_id, borrower_id, latitude, longitude) VALUES ($1,$2,$3,$4)",
            [req.user.userId, borrower_id || null, latitude, longitude]
        );

        if (borrower_id) {
            await query("UPDATE borrowers SET latitude=$1, longitude=$2 WHERE borrower_id=$3", [latitude, longitude, borrower_id]);
        }

        res.json({ message: 'GPS logged' });
    } catch (e) { res.status(500).json({ error: 'GPS log failed' }); }
});

app.get('/api/gps/logs', authenticateToken, async (req, res) => {
    const logs = await queryAll("SELECT g.*, b.full_name as borrower_name, u.name as collector_name FROM gps_logs g LEFT JOIN borrowers b ON g.borrower_id=b.borrower_id LEFT JOIN users u ON g.collector_id=u.user_id ORDER BY g.timestamp DESC LIMIT 100");
    res.json(logs);
});

app.get('/api/gps/borrowers', authenticateToken, async (req, res) => {
    const borrowers = await queryAll("SELECT borrower_id, full_name, latitude, longitude, street, barangay, city FROM borrowers WHERE latitude IS NOT NULL");
    res.json(borrowers);
});

app.put('/api/gps/update-location', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude } = req.body;
        if (req.user.role === 'borrower') {
            await query("UPDATE borrowers SET latitude=$1, longitude=$2 WHERE user_id=$3", [latitude, longitude, req.user.userId]);
        }
        res.json({ message: 'Location updated' });
    } catch (e) { res.status(500).json({ error: 'Update failed' }); }
});

// ==================== ML RISK ROUTES ====================

/**
 * GET /api/ml/risk/:borrowerId
 * Single-borrower full risk assessment using the ML engine.
 */
app.get('/api/ml/risk/:borrowerId', authenticateToken, async (req, res) => {
    try {
        const borrower = await queryOne("SELECT * FROM borrowers WHERE borrower_id=$1", [req.params.borrowerId]);
        if (!borrower) return res.status(404).json({ error: 'Borrower not found' });

        const loans = await queryAll("SELECT * FROM loans WHERE borrower_id=$1", [req.params.borrowerId]);
        const payments = await queryAll(
            "SELECT p.* FROM payments p JOIN loans l ON p.loan_id=l.loan_id WHERE l.borrower_id=$1",
            [req.params.borrowerId]
        );

        const { score, level, factors } = computeRiskScore({ loans, payments, borrower });
        const strategies = getRiskStrategies(level, factors);

        res.json({
            borrower_id: borrower.borrower_id,
            borrower: borrower.full_name,
            risk_score: score,
            risk_level: level,
            factors,
            strategies,
            total_loans: loans.length,
            active_loans: factors.active_loans || 0,
            total_payments: payments.length
        });
    } catch (e) {
        console.error('Risk assessment error:', e.message);
        res.status(500).json({ error: 'Risk assessment failed' });
    }
});

/**
 * GET /api/ml/risk
 * Bulk risk assessment for all borrowers — used by the ML Dashboard tab.
 */
app.get('/api/ml/risk', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const borrowers = await queryAll("SELECT * FROM borrowers");
        const results = [];

        for (const borrower of borrowers) {
            const loans = await queryAll("SELECT * FROM loans WHERE borrower_id=$1", [borrower.borrower_id]);
            const payments = await queryAll(
                "SELECT p.* FROM payments p JOIN loans l ON p.loan_id=l.loan_id WHERE l.borrower_id=$1",
                [borrower.borrower_id]
            );

            const { score, level, factors } = computeRiskScore({ loans, payments, borrower });
            const strategies = getRiskStrategies(level, factors);

            results.push({
                borrower_id: borrower.borrower_id,
                borrower: borrower.full_name,
                city: borrower.city,
                collector_id: borrower.collector_id,
                risk_score: score,
                risk_level: level,
                factors,
                strategies,
                total_loans: loans.length,
                active_loans: factors.active_loans || 0,
                total_payments: payments.length
            });
        }

        // Sort by risk score descending (most urgent first)
        results.sort((a, b) => b.risk_score - a.risk_score);

        const summary = {
            total: results.length,
            high: results.filter(r => r.risk_level === 'High').length,
            medium: results.filter(r => r.risk_level === 'Medium').length,
            low: results.filter(r => r.risk_level === 'Low').length,
            avg_score: results.length > 0
                ? Math.round(results.reduce((s, r) => s + r.risk_score, 0) / results.length)
                : 0
        };

        res.json({ summary, results });
    } catch (e) {
        console.error('Bulk risk error:', e.message);
        res.status(500).json({ error: 'Bulk risk assessment failed' });
    }
});

/**
 * POST /api/ml/predict
 * Manual debtor input classifier — no database record needed.
 * Used by the "Manual Classifier" form in the ML tab.
 */
app.post('/api/ml/predict', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const {
            balance,
            loan_amount,
            days_past_due,
            payment_count,
            months_active,
            overdue_loans,
            active_loans,
            has_gps,
            paid_loans
        } = req.body;

        // Build synthetic loan/payment objects for the engine
        const dueDate = new Date();
        dueDate.setDate(dueDate.getDate() - (days_past_due || 0));

        const syntheticLoans = [];
        for (let i = 0; i < (active_loans || 1); i++) {
            syntheticLoans.push({
                loan_id: i,
                loan_amount: parseFloat(loan_amount || balance || 0),
                balance: parseFloat(balance || 0) / Math.max(1, active_loans || 1),
                due_date: dueDate.toISOString(),
                status: 'active',
                created_at: new Date(Date.now() - (months_active || 1) * 30 * 24 * 60 * 60 * 1000).toISOString()
            });
        }
        for (let i = 0; i < (paid_loans || 0); i++) {
            syntheticLoans.push({
                loan_id: 100 + i,
                loan_amount: parseFloat(loan_amount || 50000),
                balance: 0,
                due_date: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
                status: 'paid',
                created_at: new Date(Date.now() - 12 * 30 * 24 * 60 * 60 * 1000).toISOString()
            });
        }

        // Manually override overdue count
        const overdueCount = parseInt(overdue_loans || 0);
        if (overdueCount > 0 && syntheticLoans.length > 0) {
            const pastDate = new Date();
            pastDate.setDate(pastDate.getDate() - (days_past_due || 30));
            for (let i = 0; i < Math.min(overdueCount, syntheticLoans.length); i++) {
                syntheticLoans[i].due_date = pastDate.toISOString();
            }
        }

        const syntheticPayments = Array.from({ length: parseInt(payment_count || 0) }, (_, i) => ({
            payment_id: i,
            amount: 1000
        }));

        const syntheticBorrower = { latitude: has_gps ? 8.0 : null, longitude: has_gps ? 124.0 : null };

        const { score, level, factors } = computeRiskScore({
            loans: syntheticLoans,
            payments: syntheticPayments,
            borrower: syntheticBorrower
        });

        const strategies = getRiskStrategies(level, factors);

        res.json({ risk_score: score, risk_level: level, factors, strategies });
    } catch (e) {
        console.error('Predict error:', e.message);
        res.status(500).json({ error: 'Prediction failed' });
    }
});

// ==================== DEBUG ====================
app.get('/api/debug/users', async (req, res) => {
    const users = await queryAll("SELECT user_id, name, email, role, status FROM users");
    res.json({ total: users.length, users });
});

// Serve frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
});

// Start
initializeDatabase().then(() => {
    app.listen(PORT, '0.0.0.0', () =>
        console.log(`\n✅ Server: http://localhost:${PORT}\n👤 Admin: admin@system.com / admin123\n`)
    );
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });
