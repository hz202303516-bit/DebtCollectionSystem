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

// ==================== ML RISK ====================
app.get('/api/ml/risk/:borrowerId', authenticateToken, async (req, res) => {
    try {
        const borrower = await queryOne("SELECT * FROM borrowers WHERE borrower_id=$1", [req.params.borrowerId]);
        if (!borrower) return res.status(404).json({ error: 'Not found' });

        const loans = await queryAll("SELECT * FROM loans WHERE borrower_id=$1", [req.params.borrowerId]);
        const payments = await queryAll("SELECT p.* FROM payments p JOIN loans l ON p.loan_id=l.loan_id WHERE l.borrower_id=$1", [req.params.borrowerId]);

        let score = 50;
        score -= loans.filter(l => l.status === 'active').length * 5;
        score += payments.length * 2;
        score -= loans.reduce((s, l) => s + (l.loan_amount || 0), 0) * 0.002;
        score = Math.max(0, Math.min(100, score));

        res.json({
            borrower: borrower.full_name,
            risk_score: Math.round(score),
            risk_level: score >= 70 ? 'Low' : score >= 40 ? 'Medium' : 'High',
            total_loans: loans.length,
            active_loans: loans.filter(l => l.status === 'active').length
        });
    } catch (e) { res.status(500).json({ error: 'Assessment failed' }); }
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
