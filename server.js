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
async function queryAll(sql, params = []) { const res = await query(sql, params); return res.rows; }
async function queryOne(sql, params = []) { const res = await query(sql, params); return res.rows[0] || null; }
async function runQuery(sql, params = []) {
    const res = await query(sql, params);
    return { lastID: res.rows[0]?.id || res.rows[0]?.user_id || res.rows[0]?.borrower_id || 0, rows: res.rows };
}

// ── Validation Helpers ────────────────────────────────────────────────────────
function validateLoanAmount(amount) {
    const val = parseFloat(amount);
    if (isNaN(val) || val <= 0) return 'Loan amount must be greater than 0';
    if (val > 10000000) return 'Loan amount cannot exceed ₱10,000,000';
    return null;
}
function validateInterestRate(rate) {
    const val = parseFloat(rate);
    if (isNaN(val)) return 'Interest rate must be a valid number';
    if (val < 0) return 'Interest rate cannot be negative';
    if (val > 100) return 'Interest rate cannot exceed 100%';
    return null;
}
function validateDueDate(date) {
    if (!date) return 'Due date is required';
    const d = new Date(date);
    if (isNaN(d.getTime())) return 'Invalid due date format';
    if (d <= new Date()) return 'Due date must be in the future';
    return null;
}
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email) ? null : 'Invalid email address format';
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
        geocoded_lat REAL, geocoded_lng REAL,
        collector_id INTEGER REFERENCES users(user_id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await query(`CREATE TABLE IF NOT EXISTS loan_applications (
        application_id SERIAL PRIMARY KEY,
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        requested_amount REAL NOT NULL,
        requested_interest_rate REAL NOT NULL DEFAULT 0,
        requested_due_date DATE NOT NULL,
        purpose TEXT,
        status TEXT CHECK(status IN ('pending','approved','rejected')) DEFAULT 'pending',
        admin_notes TEXT,
        reviewed_by INTEGER REFERENCES users(user_id),
        reviewed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await query(`CREATE TABLE IF NOT EXISTS loans (
        loan_id SERIAL PRIMARY KEY,
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        application_id INTEGER REFERENCES loan_applications(application_id),
        loan_amount REAL NOT NULL,
        interest_rate REAL NOT NULL DEFAULT 0,
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
        source TEXT DEFAULT 'gps',
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

// Add health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authentication required. Please log in.' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'gps-debt-secret-key-2024');
        next();
    } catch (e) {
        if (e.name === 'TokenExpiredError') return res.status(401).json({ error: 'Session expired. Please log in again.' });
        return res.status(401).json({ error: 'Invalid session. Please log in again.' });
    }
};

const authorize = (...roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: `Access denied. This action requires: ${roles.join(' or ')} role.` });
    next();
};

// ==================== ML ENGINE ====================
function computeRiskScore({ loans, payments, borrower }) {
    if (!loans || loans.length === 0) {
        return { score: 50, level: 'Medium', factors: { reason: 'No loan history available' } };
    }
    const activeLoans = loans.filter(l => l.status === 'active');
    const overdueLoans = loans.filter(l => l.status === 'active' && new Date(l.due_date) < new Date());
    const paidLoans = loans.filter(l => l.status === 'paid');

    let maxDpd = 0;
    overdueLoans.forEach(l => {
        const dpd = Math.floor((Date.now() - new Date(l.due_date).getTime()) / (1000 * 60 * 60 * 24));
        if (dpd > maxDpd) maxDpd = dpd;
    });
    const dpdScore = Math.min(28, (maxDpd / 360) * 28);

    const totalOriginal = loans.reduce((s, l) => s + parseFloat(l.loan_amount || 0), 0);
    const totalBalance = activeLoans.reduce((s, l) => s + parseFloat(l.balance || 0), 0);
    const utilizationRatio = totalOriginal > 0 ? totalBalance / totalOriginal : 0;
    const utilizationScore = utilizationRatio * 20;

    const oldestLoan = loans.reduce((oldest, l) => new Date(l.created_at) < new Date(oldest.created_at) ? l : oldest, loans[0]);
    const monthsSinceFirst = Math.max(1, (Date.now() - new Date(oldestLoan.created_at).getTime()) / (1000 * 60 * 60 * 24 * 30));
    const paymentsPerMonth = payments.length / monthsSinceFirst;
    const paymentFreqScore = Math.max(0, 18 - (paymentsPerMonth * 4.5));

    const overdueRatio = overdueLoans.length / Math.max(1, activeLoans.length);
    const overdueScore = overdueRatio * 15;
    const debtLoadScore = Math.min(12, (totalBalance / 500000) * 12);

    // GPS: check both real GPS and geocoded fallback
    const hasLocation = borrower.latitude || borrower.geocoded_lat;
    const gpsScore = hasLocation ? 0 : 7;

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
        has_geocoded: !!borrower.geocoded_lat,
        has_any_location: !!hasLocation,
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
                : factors.has_geocoded
                    ? 'GPS not shared — use geocoded address location for in-person visit.'
                    : 'Obtain current address — no location data available, debtor may be unreachable.',
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

        if (!name || typeof name !== 'string' || name.trim().length < 2)
            return res.status(400).json({ error: 'Full name must be at least 2 characters' });
        if (!email || typeof email !== 'string')
            return res.status(400).json({ error: 'Email is required' });
        const emailErr = validateEmail(email.trim());
        if (emailErr) return res.status(400).json({ error: emailErr });
        if (!password || password.length < 6)
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        if (!street || !barangay || !city)
            return res.status(400).json({ error: 'Street, barangay, and city are required for address' });

        const normalizedEmail = email.trim().toLowerCase();
        if (normalizedEmail === 'admin@system.com')
            return res.status(400).json({ error: 'This email address is not allowed' });

        const exists = await queryOne("SELECT user_id FROM users WHERE LOWER(email) = $1", [normalizedEmail]);
        if (exists) return res.status(409).json({ error: 'An account with this email already exists' });

        const hash = bcrypt.hashSync(password, 10);
        await query(
            `INSERT INTO users (name, email, password, role, status, phone, street, barangay, city, province, zip_code, latitude, longitude)
             VALUES ($1,$2,$3,'pending_user','pending',$4,$5,$6,$7,$8,$9,$10,$11)`,
            [name.trim(), normalizedEmail, hash, phone||null, street.trim(), barangay.trim(), city.trim(), province||null, zip_code||null, latitude||null, longitude||null]
        );

        res.status(201).json({ message: 'Registration successful! Please wait for admin approval.', success: true });
    } catch (e) {
        console.error('Register error:', e.message);
        if (e.code === '23505') return res.status(409).json({ error: 'Email already registered' });
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

        const user = await queryOne("SELECT * FROM users WHERE LOWER(email) = LOWER($1)", [email.trim()]);
        if (!user) return res.status(401).json({ error: 'No account found with this email' });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Incorrect password' });
        if (user.status === 'rejected') return res.status(403).json({ error: 'Your account has been rejected. Contact admin.' });
        if (user.status !== 'approved' && user.role !== 'admin') return res.status(403).json({ error: 'Your account is pending admin approval. Please wait.' });

        const token = jwt.sign(
            { userId: user.user_id, role: user.role },
            process.env.JWT_SECRET || 'gps-debt-secret-key-2024',
            { expiresIn: '24h' }
        );

        res.json({ token, user: { user_id: user.user_id, name: user.name, email: user.email, role: user.role, status: user.status } });
    } catch (e) {
        console.error('Login error:', e.message);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// ==================== DASHBOARD ====================
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const { role, userId } = req.user;
        if (role === 'admin') {
            const [loans, payments, borrowers, pending, pendingLoans, recent] = await Promise.all([
                queryOne("SELECT COUNT(*) as c FROM loans"),
                queryOne("SELECT COALESCE(SUM(amount),0) as t FROM payments"),
                queryOne("SELECT COUNT(*) as c FROM borrowers"),
                queryOne("SELECT COUNT(*) as c FROM users WHERE status='pending'"),
                queryOne("SELECT COUNT(*) as c FROM loan_applications WHERE status='pending'"),
                queryAll(`SELECT p.*, b.full_name as borrower, l.loan_amount FROM payments p JOIN loans l ON p.loan_id=l.loan_id JOIN borrowers b ON l.borrower_id=b.borrower_id ORDER BY p.payment_date DESC LIMIT 5`)
            ]);
            res.json({
                totalLoans: parseInt(loans?.c)||0,
                totalPayments: parseFloat(payments?.t)||0,
                totalBorrowers: parseInt(borrowers?.c)||0,
                pendingUsers: parseInt(pending?.c)||0,
                pendingLoanApplications: parseInt(pendingLoans?.c)||0,
                recentPayments: recent
            });
        } else if (role === 'collector') {
            const [borrowers, collected] = await Promise.all([
                queryOne("SELECT COUNT(*) as c FROM collection_assignments WHERE collector_id=$1 AND status='assigned'", [userId]),
                queryOne("SELECT COALESCE(SUM(amount),0) as t FROM payments WHERE collector_id=$1", [userId])
            ]);
            res.json({ totalBorrowers: parseInt(borrowers?.c)||0, totalPayments: parseFloat(collected?.t)||0, recentPayments: [] });
        } else {
            const b = await queryOne("SELECT borrower_id FROM borrowers WHERE user_id=$1", [userId]);
            if (!b) return res.json({ totalLoans: 0, totalBalance: 0, pendingApplications: 0, recentPayments: [] });
            const [loanStats, pendingApps] = await Promise.all([
                queryOne("SELECT COUNT(*) as c, COALESCE(SUM(balance),0) as t FROM loans WHERE borrower_id=$1 AND status='active'", [b.borrower_id]),
                queryOne("SELECT COUNT(*) as c FROM loan_applications WHERE borrower_id=$1 AND status='pending'", [b.borrower_id])
            ]);
            res.json({
                totalLoans: parseInt(loanStats?.c)||0,
                totalBalance: parseFloat(loanStats?.t)||0,
                pendingApplications: parseInt(pendingApps?.c)||0,
                recentPayments: []
            });
        }
    } catch (e) {
        console.error('Stats error:', e.message);
        res.status(500).json({ error: 'Failed to load dashboard stats' });
    }
});

// ==================== USERS ====================
app.get('/api/users', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const users = await queryAll("SELECT user_id,name,email,role,status,phone,street,barangay,city,province,zip_code,latitude,longitude,created_at FROM users ORDER BY created_at DESC");
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.put('/api/users/:id/status', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const { status, role } = req.body;
        const userId = parseInt(req.params.id);

        if (isNaN(userId)) return res.status(400).json({ error: 'Invalid user ID' });
        if (!status || !['pending', 'approved', 'rejected'].includes(status))
            return res.status(400).json({ error: 'Status must be: pending, approved, or rejected' });

        const user = await queryOne("SELECT * FROM users WHERE user_id = $1", [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.email === 'admin@system.com' || user.role === 'admin')
            return res.status(403).json({ error: 'Cannot modify the admin account' });

        let newRole = user.role;

        if (status === 'approved' && (user.role === 'pending_user' || user.role === 'borrower' || user.role === 'collector')) {
            newRole = role || 'borrower';
            if (!['borrower', 'collector'].includes(newRole))
                return res.status(400).json({ error: 'Assigned role must be borrower or collector' });

            await query("UPDATE users SET status=$1, role=$2, updated_at=CURRENT_TIMESTAMP WHERE user_id=$3", [status, newRole, userId]);

            if (newRole === 'borrower') {
                const existing = await queryOne("SELECT borrower_id FROM borrowers WHERE user_id=$1", [userId]);
                if (!existing) {
                    await query(
                        "INSERT INTO borrowers (user_id, full_name, phone, street, barangay, city, province, zip_code, latitude, longitude) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                        [userId, user.name, user.phone, user.street, user.barangay, user.city, user.province, user.zip_code, user.latitude, user.longitude]
                    );
                }
            }
        } else {
            await query("UPDATE users SET status=$1, updated_at=CURRENT_TIMESTAMP WHERE user_id=$2", [status, userId]);
        }

        const updated = await queryOne("SELECT user_id, name, email, role, status FROM users WHERE user_id=$1", [userId]);
        res.json({ message: `User ${status} successfully as ${newRole}`, user: updated });
    } catch (e) {
        console.error('Update status error:', e.message);
        res.status(500).json({ error: 'Failed to update user status: ' + e.message });
    }
});

app.put('/api/users/:id/role', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const { role } = req.body;
        const userId = parseInt(req.params.id);

        if (isNaN(userId)) return res.status(400).json({ error: 'Invalid user ID' });
        if (!role || !['admin', 'collector', 'borrower', 'pending_user'].includes(role))
            return res.status(400).json({ error: 'Invalid role. Must be: admin, collector, borrower, or pending_user' });

        const user = await queryOne("SELECT * FROM users WHERE user_id=$1", [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.email === 'admin@system.com') return res.status(403).json({ error: 'Cannot change the system admin role' });

        await query("UPDATE users SET role=$1, updated_at=CURRENT_TIMESTAMP WHERE user_id=$2", [role, userId]);

        if (role === 'borrower') {
            const existing = await queryOne("SELECT borrower_id FROM borrowers WHERE user_id=$1", [userId]);
            if (!existing) {
                await query(
                    "INSERT INTO borrowers (user_id, full_name, phone, street, barangay, city, province, zip_code, latitude, longitude) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                    [userId, user.name, user.phone, user.street, user.barangay, user.city, user.province, user.zip_code, user.latitude, user.longitude]
                );
            }
        }

        res.json({ message: `Role updated to ${role} successfully` });
    } catch (e) {
        console.error('Update role error:', e.message);
        res.status(500).json({ error: 'Failed to update role: ' + e.message });
    }
});

// ==================== BORROWERS ====================
app.get('/api/borrowers', authenticateToken, async (req, res) => {
    try {
        let borrowers;
        if (req.user.role === 'admin') {
            borrowers = await queryAll("SELECT b.*, u.name as collector_name, u2.email as user_email FROM borrowers b LEFT JOIN users u ON b.collector_id=u.user_id LEFT JOIN users u2 ON b.user_id=u2.user_id ORDER BY b.created_at DESC");
        } else if (req.user.role === 'collector') {
            borrowers = await queryAll("SELECT b.* FROM borrowers b JOIN collection_assignments ca ON b.borrower_id=ca.borrower_id WHERE ca.collector_id=$1 AND ca.status='assigned'", [req.user.userId]);
        } else {
            borrowers = await queryAll("SELECT * FROM borrowers WHERE user_id=$1", [req.user.userId]);
        }
        res.json(borrowers);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch borrowers' });
    }
});

// ==================== COLLECTORS ====================
app.get('/api/collectors', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const collectors = await queryAll("SELECT user_id, name, email, phone FROM users WHERE role='collector' AND status='approved'");
        res.json(collectors);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch collectors' });
    }
});

// ==================== ASSIGNMENTS ====================
app.post('/api/assignments', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const { collector_id, borrower_id } = req.body;
        if (!collector_id || !borrower_id) return res.status(400).json({ error: 'Both collector and borrower are required' });

        const collector = await queryOne("SELECT user_id FROM users WHERE user_id=$1 AND role='collector' AND status='approved'", [collector_id]);
        if (!collector) return res.status(404).json({ error: 'Collector not found or not approved' });

        const borrower = await queryOne("SELECT borrower_id FROM borrowers WHERE borrower_id=$1", [borrower_id]);
        if (!borrower) return res.status(404).json({ error: 'Borrower not found' });

        const existing = await queryOne("SELECT * FROM collection_assignments WHERE borrower_id=$1 AND status='assigned'", [borrower_id]);
        if (existing) return res.status(409).json({ error: 'This borrower is already assigned to a collector' });

        await query("INSERT INTO collection_assignments (admin_id, collector_id, borrower_id) VALUES ($1,$2,$3)", [req.user.userId, collector_id, borrower_id]);
        await query("UPDATE borrowers SET collector_id=$1 WHERE borrower_id=$2", [collector_id, borrower_id]);

        res.status(201).json({ message: 'Collector assigned successfully!' });
    } catch (e) {
        console.error('Assignment error:', e.message);
        res.status(500).json({ error: 'Assignment failed: ' + e.message });
    }
});

app.get('/api/assignments', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const assignments = await queryAll(`
            SELECT ca.*, b.full_name as borrower_name, b.latitude as b_lat, b.longitude as b_lng,
                   u.name as collector_name
            FROM collection_assignments ca
            JOIN borrowers b ON ca.borrower_id=b.borrower_id
            JOIN users u ON ca.collector_id=u.user_id
            ORDER BY ca.assigned_date DESC
        `);
        res.json(assignments);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch assignments' });
    }
});

// ==================== LOAN APPLICATIONS (Borrower → Admin Approval) ====================

/**
 * POST /api/loan-applications
 * Borrower submits a loan application. Admin must approve before a real loan is created.
 */
app.post('/api/loan-applications', authenticateToken, authorize('borrower'), async (req, res) => {
    try {
        const { requested_amount, requested_interest_rate, requested_due_date, purpose } = req.body;

        // Validations
        const amtErr = validateLoanAmount(requested_amount);
        if (amtErr) return res.status(400).json({ error: amtErr });

        const rateVal = requested_interest_rate !== undefined && requested_interest_rate !== '' ? requested_interest_rate : 0;
        const rateErr = validateInterestRate(rateVal);
        if (rateErr) return res.status(400).json({ error: rateErr });

        const dateErr = validateDueDate(requested_due_date);
        if (dateErr) return res.status(400).json({ error: dateErr });

        const borrower = await queryOne("SELECT borrower_id FROM borrowers WHERE user_id=$1", [req.user.userId]);
        if (!borrower) return res.status(404).json({ error: 'Borrower profile not found. Contact admin.' });

        // Check for existing pending application
        const pendingApp = await queryOne(
            "SELECT application_id FROM loan_applications WHERE borrower_id=$1 AND status='pending'",
            [borrower.borrower_id]
        );
        if (pendingApp) return res.status(409).json({ error: 'You already have a pending loan application. Please wait for admin review.' });

        await query(
            `INSERT INTO loan_applications (borrower_id, requested_amount, requested_interest_rate, requested_due_date, purpose, status)
             VALUES ($1, $2, $3, $4, $5, 'pending')`,
            [borrower.borrower_id, parseFloat(requested_amount), parseFloat(rateVal), requested_due_date, purpose || null]
        );

        res.status(201).json({ message: 'Loan application submitted successfully! Waiting for admin approval.', success: true });
    } catch (e) {
        console.error('Loan application error:', e.message);
        res.status(500).json({ error: 'Failed to submit loan application. Please try again.' });
    }
});

/**
 * GET /api/loan-applications
 * Admin: all applications. Borrower: their own.
 */
app.get('/api/loan-applications', authenticateToken, async (req, res) => {
    try {
        let apps;
        if (req.user.role === 'admin') {
            apps = await queryAll(`
                SELECT la.*, b.full_name as borrower_name, b.city,
                       u.name as reviewed_by_name
                FROM loan_applications la
                JOIN borrowers b ON la.borrower_id=b.borrower_id
                LEFT JOIN users u ON la.reviewed_by=u.user_id
                ORDER BY la.created_at DESC
            `);
        } else if (req.user.role === 'borrower') {
            const b = await queryOne("SELECT borrower_id FROM borrowers WHERE user_id=$1", [req.user.userId]);
            if (!b) return res.json([]);
            apps = await queryAll(
                "SELECT * FROM loan_applications WHERE borrower_id=$1 ORDER BY created_at DESC",
                [b.borrower_id]
            );
        } else {
            return res.status(403).json({ error: 'Access denied' });
        }
        res.json(apps);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch loan applications' });
    }
});

/**
 * PUT /api/loan-applications/:id/review
 * Admin approves or rejects a loan application.
 * On approval: creates the actual loan record.
 */
app.put('/api/loan-applications/:id/review', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const appId = parseInt(req.params.id);
        if (isNaN(appId)) return res.status(400).json({ error: 'Invalid application ID' });

        const { status, admin_notes, final_amount, final_interest_rate, final_due_date } = req.body;

        if (!status || !['approved', 'rejected'].includes(status))
            return res.status(400).json({ error: 'Decision must be "approved" or "rejected"' });

        const app_record = await queryOne("SELECT * FROM loan_applications WHERE application_id=$1", [appId]);
        if (!app_record) return res.status(404).json({ error: 'Loan application not found' });
        if (app_record.status !== 'pending')
            return res.status(409).json({ error: `This application has already been ${app_record.status}` });

        if (status === 'approved') {
            // Use final values if admin overrides, otherwise use requested
            const loanAmount = final_amount || app_record.requested_amount;
            const interestRate = final_interest_rate !== undefined ? final_interest_rate : app_record.requested_interest_rate;
            const dueDate = final_due_date || app_record.requested_due_date;

            const amtErr = validateLoanAmount(loanAmount);
            if (amtErr) return res.status(400).json({ error: `Final amount error: ${amtErr}` });
            const rateErr = validateInterestRate(interestRate);
            if (rateErr) return res.status(400).json({ error: `Final interest rate error: ${rateErr}` });
            const dateErr = validateDueDate(dueDate);
            if (dateErr) return res.status(400).json({ error: `Final due date error: ${dateErr}` });

            await query(
                `INSERT INTO loans (borrower_id, application_id, loan_amount, interest_rate, due_date, balance, status)
                 VALUES ($1, $2, $3, $4, $5, $6, 'active')`,
                [app_record.borrower_id, appId, parseFloat(loanAmount), parseFloat(interestRate), dueDate, parseFloat(loanAmount)]
            );
        }

        await query(
            `UPDATE loan_applications SET status=$1, admin_notes=$2, reviewed_by=$3, reviewed_at=CURRENT_TIMESTAMP
             WHERE application_id=$4`,
            [status, admin_notes || null, req.user.userId, appId]
        );

        res.json({ message: `Loan application ${status} successfully!`, status });
    } catch (e) {
        console.error('Review application error:', e.message);
        res.status(500).json({ error: 'Failed to process application: ' + e.message });
    }
});

// ==================== LOANS ====================
app.get('/api/loans', authenticateToken, async (req, res) => {
    try {
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
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch loans' });
    }
});

// ==================== PAYMENTS ====================
app.get('/api/payments', authenticateToken, async (req, res) => {
    try {
        const payments = await queryAll("SELECT p.*, b.full_name as borrower_name, u.name as collector_name FROM payments p JOIN loans l ON p.loan_id=l.loan_id JOIN borrowers b ON l.borrower_id=b.borrower_id LEFT JOIN users u ON p.collector_id=u.user_id ORDER BY p.payment_date DESC LIMIT 50");
        res.json(payments);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});

app.post('/api/payments', authenticateToken, async (req, res) => {
    try {
        const { loan_id, amount, latitude, longitude } = req.body;

        if (!loan_id) return res.status(400).json({ error: 'Loan ID is required' });
        if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0)
            return res.status(400).json({ error: 'Payment amount must be greater than 0' });

        const loan = await queryOne("SELECT l.*, b.borrower_id FROM loans l JOIN borrowers b ON l.borrower_id=b.borrower_id WHERE l.loan_id=$1", [loan_id]);
        if (!loan) return res.status(404).json({ error: 'Loan not found' });
        if (loan.status === 'paid') return res.status(400).json({ error: 'This loan has already been fully paid' });
        if (loan.status !== 'active') return res.status(400).json({ error: 'This loan is not currently active' });

        const payAmt = parseFloat(amount);
        const currentBalance = parseFloat(loan.balance);

        if (payAmt > currentBalance)
            return res.status(400).json({ error: `Payment amount (₱${payAmt.toLocaleString()}) exceeds remaining balance (₱${currentBalance.toLocaleString()})` });

        const receipt = 'RCP-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5).toUpperCase();
        await query(
            "INSERT INTO payments (loan_id, collector_id, amount, latitude, longitude, receipt_number) VALUES ($1,$2,$3,$4,$5,$6)",
            [loan_id, req.user.userId, payAmt, latitude||null, longitude||null, receipt]
        );

        const newBalance = currentBalance - payAmt;
        await query("UPDATE loans SET balance=$1, status=$2 WHERE loan_id=$3",
            [newBalance.toFixed(2), newBalance <= 0 ? 'paid' : 'active', loan_id]);

        if (latitude && longitude) {
            await query("INSERT INTO gps_logs (collector_id, borrower_id, latitude, longitude, source) VALUES ($1,$2,$3,$4,'payment')",
                [req.user.userId, loan.borrower_id, latitude, longitude]);
        }

        res.status(201).json({ message: 'Payment recorded successfully!', receipt, newBalance: newBalance.toFixed(2) });
    } catch (e) {
        console.error('Payment error:', e.message);
        res.status(500).json({ error: 'Payment failed: ' + e.message });
    }
});

// ==================== GPS ROUTES ====================
app.post('/api/gps/log', authenticateToken, async (req, res) => {
    try {
        const { borrower_id, latitude, longitude } = req.body;
        if (!latitude || !longitude) return res.status(400).json({ error: 'GPS coordinates are required' });
        if (isNaN(parseFloat(latitude)) || isNaN(parseFloat(longitude)))
            return res.status(400).json({ error: 'Invalid GPS coordinate format' });

        await query("INSERT INTO gps_logs (collector_id, borrower_id, latitude, longitude, source) VALUES ($1,$2,$3,$4,'manual')",
            [req.user.userId, borrower_id||null, latitude, longitude]);

        if (borrower_id) {
            await query("UPDATE borrowers SET latitude=$1, longitude=$2 WHERE borrower_id=$3", [latitude, longitude, borrower_id]);
        }

        res.json({ message: 'GPS location logged successfully' });
    } catch (e) {
        res.status(500).json({ error: 'GPS log failed: ' + e.message });
    }
});

app.get('/api/gps/logs', authenticateToken, async (req, res) => {
    try {
        const logs = await queryAll("SELECT g.*, b.full_name as borrower_name, u.name as collector_name FROM gps_logs g LEFT JOIN borrowers b ON g.borrower_id=b.borrower_id LEFT JOIN users u ON g.collector_id=u.user_id ORDER BY g.timestamp DESC LIMIT 100");
        res.json(logs);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch GPS logs' });
    }
});

app.get('/api/gps/borrowers', authenticateToken, async (req, res) => {
    try {
        // Returns borrowers with any location: GPS or geocoded fallback
        const borrowers = await queryAll(`
            SELECT borrower_id, full_name,
                   COALESCE(latitude, geocoded_lat) as latitude,
                   COALESCE(longitude, geocoded_lng) as longitude,
                   latitude as gps_lat, longitude as gps_lng,
                   geocoded_lat, geocoded_lng,
                   street, barangay, city,
                   CASE WHEN latitude IS NOT NULL THEN 'gps'
                        WHEN geocoded_lat IS NOT NULL THEN 'geocoded'
                        ELSE 'none' END as location_source
            FROM borrowers
            WHERE latitude IS NOT NULL OR geocoded_lat IS NOT NULL
        `);
        res.json(borrowers);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch borrower locations' });
    }
});

app.put('/api/gps/update-location', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude } = req.body;
        if (!latitude || !longitude) return res.status(400).json({ error: 'Coordinates required' });
        if (isNaN(parseFloat(latitude)) || isNaN(parseFloat(longitude)))
            return res.status(400).json({ error: 'Invalid coordinate values' });

        if (req.user.role === 'borrower') {
            await query("UPDATE borrowers SET latitude=$1, longitude=$2 WHERE user_id=$3", [latitude, longitude, req.user.userId]);
        }
        res.json({ message: 'GPS location updated successfully' });
    } catch (e) {
        res.status(500).json({ error: 'Location update failed' });
    }
});

/**
 * POST /api/gps/geocode-borrower
 * Fallback: geocode a borrower's address if they haven't shared GPS.
 * Uses OpenStreetMap Nominatim (free, no API key needed).
 */
app.post('/api/gps/geocode-borrower', authenticateToken, authorize('admin', 'collector'), async (req, res) => {
    try {
        const { borrower_id } = req.body;
        if (!borrower_id) return res.status(400).json({ error: 'Borrower ID required' });

        const borrower = await queryOne("SELECT * FROM borrowers WHERE borrower_id=$1", [borrower_id]);
        if (!borrower) return res.status(404).json({ error: 'Borrower not found' });

        if (borrower.latitude) {
            return res.json({ message: 'Borrower already has GPS location', latitude: borrower.latitude, longitude: borrower.longitude, source: 'gps' });
        }

        // Build address string for geocoding
        const addressParts = [borrower.street, borrower.barangay, borrower.city, borrower.province, 'Philippines'].filter(Boolean);
        const addressStr = addressParts.join(', ');

        // Call Nominatim geocoding API
        const https = require('https');
        const encodedAddress = encodeURIComponent(addressStr);

        const geocodeResult = await new Promise((resolve, reject) => {
            const options = {
                hostname: 'nominatim.openstreetmap.org',
                path: `/search?q=${encodedAddress}&format=json&limit=1&countrycodes=ph`,
                method: 'GET',
                headers: { 'User-Agent': 'GPS-Debt-Collection-System/1.0' }
            };
            const request = https.request(options, (response) => {
                let data = '';
                response.on('data', chunk => data += chunk);
                response.on('end', () => {
                    try { resolve(JSON.parse(data)); }
                    catch (e) { reject(new Error('Invalid geocoding response')); }
                });
            });
            request.on('error', reject);
            request.setTimeout(8000, () => { request.destroy(); reject(new Error('Geocoding request timed out')); });
            request.end();
        });

        if (!geocodeResult || geocodeResult.length === 0) {
            return res.status(404).json({ error: `Could not geocode address: "${addressStr}". Try a more complete address.` });
        }

        const { lat, lon, display_name } = geocodeResult[0];
        const geocodedLat = parseFloat(lat);
        const geocodedLng = parseFloat(lon);

        // Save geocoded coordinates
        await query("UPDATE borrowers SET geocoded_lat=$1, geocoded_lng=$2 WHERE borrower_id=$3", [geocodedLat, geocodedLng, borrower_id]);
        await query("INSERT INTO gps_logs (collector_id, borrower_id, latitude, longitude, source) VALUES ($1,$2,$3,$4,'geocoded')",
            [req.user.userId, borrower_id, geocodedLat, geocodedLng]);

        res.json({
            message: 'Address successfully geocoded!',
            latitude: geocodedLat,
            longitude: geocodedLng,
            display_name,
            source: 'geocoded',
            note: 'Location estimated from address — may not be exact'
        });
    } catch (e) {
        console.error('Geocode error:', e.message);
        res.status(500).json({ error: 'Geocoding failed: ' + e.message });
    }
});

// ==================== ML RISK ROUTES ====================
app.get('/api/ml/risk/:borrowerId', authenticateToken, async (req, res) => {
    try {
        const borrowerId = parseInt(req.params.borrowerId);
        if (isNaN(borrowerId)) return res.status(400).json({ error: 'Invalid borrower ID' });

        const borrower = await queryOne("SELECT * FROM borrowers WHERE borrower_id=$1", [borrowerId]);
        if (!borrower) return res.status(404).json({ error: 'Borrower not found' });

        const [loans, payments] = await Promise.all([
            queryAll("SELECT * FROM loans WHERE borrower_id=$1", [borrowerId]),
            queryAll("SELECT p.* FROM payments p JOIN loans l ON p.loan_id=l.loan_id WHERE l.borrower_id=$1", [borrowerId])
        ]);

        const { score, level, factors } = computeRiskScore({ loans, payments, borrower });
        const strategies = getRiskStrategies(level, factors);

        res.json({
            borrower_id: borrower.borrower_id,
            borrower: borrower.full_name,
            risk_score: score, risk_level: level, factors, strategies,
            total_loans: loans.length,
            active_loans: factors.active_loans || 0,
            total_payments: payments.length
        });
    } catch (e) {
        console.error('Risk assessment error:', e.message);
        res.status(500).json({ error: 'Risk assessment failed' });
    }
});

app.get('/api/ml/risk', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const borrowers = await queryAll("SELECT * FROM borrowers");
        const results = [];

        for (const borrower of borrowers) {
            const [loans, payments] = await Promise.all([
                queryAll("SELECT * FROM loans WHERE borrower_id=$1", [borrower.borrower_id]),
                queryAll("SELECT p.* FROM payments p JOIN loans l ON p.loan_id=l.loan_id WHERE l.borrower_id=$1", [borrower.borrower_id])
            ]);
            const { score, level, factors } = computeRiskScore({ loans, payments, borrower });
            const strategies = getRiskStrategies(level, factors);
            results.push({
                borrower_id: borrower.borrower_id,
                borrower: borrower.full_name,
                city: borrower.city,
                collector_id: borrower.collector_id,
                risk_score: score, risk_level: level, factors, strategies,
                total_loans: loans.length,
                active_loans: factors.active_loans || 0,
                total_payments: payments.length
            });
        }

        results.sort((a, b) => b.risk_score - a.risk_score);
        const summary = {
            total: results.length,
            high: results.filter(r => r.risk_level === 'High').length,
            medium: results.filter(r => r.risk_level === 'Medium').length,
            low: results.filter(r => r.risk_level === 'Low').length,
            avg_score: results.length > 0 ? Math.round(results.reduce((s, r) => s + r.risk_score, 0) / results.length) : 0
        };

        res.json({ summary, results });
    } catch (e) {
        console.error('Bulk risk error:', e.message);
        res.status(500).json({ error: 'Bulk risk assessment failed' });
    }
});

app.post('/api/ml/predict', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const { balance, loan_amount, days_past_due, payment_count, months_active, overdue_loans, active_loans, has_gps, paid_loans } = req.body;

        if (!balance || isNaN(parseFloat(balance)) || parseFloat(balance) < 0)
            return res.status(400).json({ error: 'Outstanding balance must be 0 or greater' });

        const dueDate = new Date();
        dueDate.setDate(dueDate.getDate() - (parseInt(days_past_due) || 0));

        const syntheticLoans = [];
        for (let i = 0; i < (parseInt(active_loans) || 1); i++) {
            syntheticLoans.push({
                loan_id: i, loan_amount: parseFloat(loan_amount || balance || 0),
                balance: parseFloat(balance || 0) / Math.max(1, parseInt(active_loans) || 1),
                due_date: dueDate.toISOString(), status: 'active',
                created_at: new Date(Date.now() - (parseInt(months_active) || 1) * 30 * 24 * 60 * 60 * 1000).toISOString()
            });
        }
        for (let i = 0; i < (parseInt(paid_loans) || 0); i++) {
            syntheticLoans.push({
                loan_id: 100 + i, loan_amount: parseFloat(loan_amount || 50000), balance: 0,
                due_date: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(), status: 'paid',
                created_at: new Date(Date.now() - 12 * 30 * 24 * 60 * 60 * 1000).toISOString()
            });
        }

        const overdueCount = parseInt(overdue_loans || 0);
        if (overdueCount > 0 && syntheticLoans.length > 0) {
            const pastDate = new Date();
            pastDate.setDate(pastDate.getDate() - (parseInt(days_past_due) || 30));
            for (let i = 0; i < Math.min(overdueCount, syntheticLoans.length); i++) {
                syntheticLoans[i].due_date = pastDate.toISOString();
            }
        }

        const syntheticPayments = Array.from({ length: parseInt(payment_count || 0) }, (_, i) => ({ payment_id: i, amount: 1000 }));
        const syntheticBorrower = { latitude: has_gps ? 8.0 : null, longitude: has_gps ? 124.0 : null };

        const { score, level, factors } = computeRiskScore({ loans: syntheticLoans, payments: syntheticPayments, borrower: syntheticBorrower });
        const strategies = getRiskStrategies(level, factors);

        res.json({ risk_score: score, risk_level: level, factors, strategies });
    } catch (e) {
        console.error('Predict error:', e.message);
        res.status(500).json({ error: 'Prediction failed: ' + e.message });
    }
});

// ==================== DEBUG ====================
app.get('/api/debug/users', async (req, res) => {
    const users = await queryAll("SELECT user_id, name, email, role, status FROM users");
    res.json({ total: users.length, users });
});

// Serve frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Global error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'An unexpected server error occurred. Please try again.' });
});

// Start
initializeDatabase().then(() => {
    app.listen(PORT, '0.0.0.0', () =>
        console.log(`\n✅ Server: http://localhost:${PORT}\n👤 Admin: admin@system.com / admin123\n🔍 Health: http://localhost:${PORT}/api/health\n`)
    );
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });
