const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// Database setup
const dbPath = path.join(__dirname, 'debt_collection.db');
let db;

async function initializeDatabase() {
    const SQL = await initSqlJs();
    if (fs.existsSync(dbPath)) {
        db = new SQL.Database(fs.readFileSync(dbPath));
    } else {
        db = new SQL.Database();
    }

    db.run(`CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT CHECK(role IN ('admin','collector','borrower','pending_user')) DEFAULT 'pending_user',
        status TEXT CHECK(status IN ('pending','approved','rejected')) DEFAULT 'pending',
        phone TEXT, street TEXT, barangay TEXT, city TEXT, province TEXT, zip_code TEXT,
        latitude REAL, longitude REAL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS borrowers (
        borrower_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(user_id),
        full_name TEXT NOT NULL,
        phone TEXT,
        street TEXT, barangay TEXT, city TEXT, province TEXT, zip_code TEXT,
        latitude REAL, longitude REAL,
        collector_id INTEGER REFERENCES users(user_id),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS loans (
        loan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        loan_amount REAL NOT NULL,
        interest_rate REAL NOT NULL,
        due_date DATE NOT NULL,
        balance REAL NOT NULL,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS payments (
        payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        loan_id INTEGER REFERENCES loans(loan_id),
        collector_id INTEGER REFERENCES users(user_id),
        amount REAL NOT NULL,
        payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        latitude REAL, longitude REAL,
        receipt_number TEXT UNIQUE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS gps_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        collector_id INTEGER REFERENCES users(user_id),
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        latitude REAL, longitude REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS collection_assignments (
        assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER REFERENCES users(user_id),
        collector_id INTEGER REFERENCES users(user_id),
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        status TEXT DEFAULT 'assigned',
        assigned_date DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Seed admin
    const adminCheck = db.exec("SELECT COUNT(*) as c FROM users WHERE email = 'admin@system.com'");
    if (!adminCheck[0]?.values[0][0]) {
        db.run("INSERT INTO users (name,email,password,role,status) VALUES (?,?,?,?,?)",
            ['System Admin', 'admin@system.com', bcrypt.hashSync('admin123', 10), 'admin', 'approved']);
        console.log('✅ Admin seeded');
    }
    saveDb();
    console.log('✅ Database ready');
}

function saveDb() { fs.writeFileSync(dbPath, Buffer.from(db.export())); }

function queryAll(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        if (params.length) stmt.bind(params);
        const rows = [];
        while (stmt.step()) rows.push(stmt.getAsObject());
        stmt.free();
        return rows;
    } catch (e) { console.error('Query error:', e.message); return []; }
}

function queryOne(sql, params = []) { const r = queryAll(sql, params); return r[0] || null; }

function runQuery(sql, params = []) {
    try {
        db.run(sql, params);
        saveDb();
        const r = db.exec("SELECT last_insert_rowid()");
        return { lastID: r[0]?.values[0][0] || 0 };
    } catch (e) { console.error('Run error:', e.message); throw e; }
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

const authenticateToken = (req, res, next) => {
    const token = (req.headers.authorization || '').split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Please login' });
    try { req.user = jwt.verify(token, process.env.JWT_SECRET || 'gps-debt-secret-key-2024'); next(); }
    catch (e) { res.status(401).json({ error: 'Session expired' }); }
};

const authorize = (...roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
    next();
};

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', (req, res) => {
    try {
        const { name, email, password, phone, street, barangay, city, province, zip_code, latitude, longitude } = req.body;
        
        if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
        if (!street || !barangay || !city) return res.status(400).json({ error: 'Please provide your complete address' });
        
        const exists = queryOne("SELECT user_id FROM users WHERE LOWER(email) = LOWER(?)", [email.trim()]);
        if (exists) return res.status(400).json({ error: 'Email already registered' });
        if (email.toLowerCase() === 'admin@system.com') return res.status(400).json({ error: 'Cannot use admin email' });
        
        const hash = bcrypt.hashSync(password, 10);
        runQuery(
            `INSERT INTO users (name, email, password, role, status, phone, street, barangay, city, province, zip_code, latitude, longitude)
             VALUES (?,?,?,'pending_user','pending',?,?,?,?,?,?,?,?)`,
            [name.trim(), email.trim().toLowerCase(), hash, phone||null, street||null, barangay||null, city||null, province||null, zip_code||null, latitude||null, longitude||null]
        );
        
        res.status(201).json({ message: 'Registration successful! Please wait for admin approval.', success: true });
    } catch (e) {
        console.error('Register error:', e.message);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
        
        const user = queryOne("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", [email.trim()]);
        if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
        if (user.status !== 'approved' && user.role !== 'admin') return res.status(403).json({ error: 'Account pending approval' });
        
        const token = jwt.sign({ userId: user.user_id, role: user.role }, process.env.JWT_SECRET || 'gps-debt-secret-key-2024', { expiresIn: '24h' });
        
        res.json({ token, user: { user_id: user.user_id, name: user.name, email: user.email, role: user.role, status: user.status } });
    } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

// ==================== DASHBOARD ====================
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    try {
        const { role, userId } = req.user;
        if (role === 'admin') {
            const loans = queryOne("SELECT COUNT(*) as c FROM loans");
            const payments = queryOne("SELECT COALESCE(SUM(amount),0) as t FROM payments");
            const borrowers = queryOne("SELECT COUNT(*) as c FROM borrowers");
            const pending = queryOne("SELECT COUNT(*) as c FROM users WHERE status='pending'");
            const recent = queryAll(`SELECT p.*, b.full_name as borrower, l.loan_amount FROM payments p JOIN loans l ON p.loan_id=l.loan_id JOIN borrowers b ON l.borrower_id=b.borrower_id ORDER BY p.payment_date DESC LIMIT 5`);
            res.json({ totalLoans: loans?.c||0, totalPayments: payments?.t||0, totalBorrowers: borrowers?.c||0, pendingUsers: pending?.c||0, recentPayments: recent });
        } else if (role === 'collector') {
            const borrowers = queryOne("SELECT COUNT(*) as c FROM collection_assignments WHERE collector_id=? AND status='assigned'", [userId]);
            const collected = queryOne("SELECT COALESCE(SUM(amount),0) as t FROM payments WHERE collector_id=?", [userId]);
            res.json({ totalBorrowers: borrowers?.c||0, totalPayments: collected?.t||0, recentPayments: [] });
        } else {
            const b = queryOne("SELECT borrower_id FROM borrowers WHERE user_id=?", [userId]);
            if (!b) return res.json({ totalLoans: 0, totalBalance: 0, recentPayments: [] });
            const loans = queryOne("SELECT COUNT(*) as c, COALESCE(SUM(balance),0) as t FROM loans WHERE borrower_id=? AND status='active'", [b.borrower_id]);
            res.json({ totalLoans: loans?.c||0, totalBalance: loans?.t||0, recentPayments: [] });
        }
    } catch (e) { res.status(500).json({ error: 'Failed to load stats' }); }
});

// ==================== USERS ====================
app.get('/api/users', authenticateToken, authorize('admin'), (req, res) => {
    const users = queryAll("SELECT user_id,name,email,role,status,phone,street,barangay,city,province,zip_code,latitude,longitude,created_at FROM users ORDER BY created_at DESC");
    res.json(users);
});

app.put('/api/users/:id/status', authenticateToken, authorize('admin'), (req, res) => {
    try {
        const { status, role } = req.body;
        const userId = parseInt(req.params.id);
        
        if (!status || !['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        const user = queryOne("SELECT * FROM users WHERE user_id = ?", [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.email === 'admin@system.com' || user.role === 'admin') {
            return res.status(403).json({ error: 'Cannot modify admin account' });
        }
        
        let newRole = user.role;
        
        if (status === 'approved' && user.role === 'pending_user') {
            newRole = role || 'borrower';
            if (!['borrower', 'collector'].includes(newRole)) {
                return res.status(400).json({ error: 'Role must be borrower or collector' });
            }
            
            runQuery("UPDATE users SET status = ?, role = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                [status, newRole, userId]);
            
            if (newRole === 'borrower') {
                const existing = queryOne("SELECT borrower_id FROM borrowers WHERE user_id = ?", [userId]);
                if (!existing) {
                    runQuery("INSERT INTO borrowers (user_id, full_name, phone, street, barangay, city, province, zip_code, latitude, longitude) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        [userId, user.name, user.phone, user.street, user.barangay, user.city, user.province, user.zip_code, user.latitude, user.longitude]);
                }
            }
        } else {
            runQuery("UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", [status, userId]);
        }
        
        const updated = queryOne("SELECT user_id, name, email, role, status FROM users WHERE user_id = ?", [userId]);
        res.json({ message: `User ${status} as ${newRole}`, user: updated });
    } catch (e) {
        console.error('Update error:', e.message);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Add this NEW route right after the one above
app.put('/api/users/:id/role', authenticateToken, authorize('admin'), (req, res) => {
    try {
        const { role } = req.body;
        const userId = parseInt(req.params.id);
        
        if (!role || !['admin', 'collector', 'borrower', 'pending_user'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role' });
        }
        
        const user = queryOne("SELECT * FROM users WHERE user_id = ?", [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.email === 'admin@system.com') return res.status(403).json({ error: 'Cannot change admin role' });
        
        runQuery("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", [role, userId]);
        
        if (role === 'borrower') {
            const existing = queryOne("SELECT borrower_id FROM borrowers WHERE user_id = ?", [userId]);
            if (!existing) {
                runQuery("INSERT INTO borrowers (user_id, full_name, phone, street, barangay, city, province, zip_code, latitude, longitude) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [userId, user.name, user.phone, user.street, user.barangay, user.city, user.province, user.zip_code, user.latitude, user.longitude]);
            }
        }
        
        res.json({ message: `Role updated to ${role}` });
    } catch (e) {
        res.status(500).json({ error: 'Failed to update role' });
    }
});

// ==================== BORROWERS ====================
app.get('/api/borrowers', authenticateToken, (req, res) => {
    let borrowers;
    if (req.user.role === 'admin') {
        borrowers = queryAll("SELECT b.*, u.name as collector_name, u.email as user_email FROM borrowers b LEFT JOIN users u ON b.collector_id=u.user_id ORDER BY b.created_at DESC");
    } else if (req.user.role === 'collector') {
        borrowers = queryAll("SELECT b.* FROM borrowers b JOIN collection_assignments ca ON b.borrower_id=ca.borrower_id WHERE ca.collector_id=? AND ca.status='assigned'", [req.user.userId]);
    } else {
        borrowers = queryAll("SELECT * FROM borrowers WHERE user_id=?", [req.user.userId]);
    }
    res.json(borrowers);
});

// ==================== COLLECTORS ====================
app.get('/api/collectors', authenticateToken, authorize('admin'), (req, res) => {
    const collectors = queryAll("SELECT user_id, name, email, phone FROM users WHERE role='collector' AND status='approved'");
    res.json(collectors);
});

// ==================== ASSIGNMENTS ====================
app.post('/api/assignments', authenticateToken, authorize('admin'), (req, res) => {
    try {
        const { collector_id, borrower_id } = req.body;
        if (!collector_id || !borrower_id) return res.status(400).json({ error: 'Collector and borrower required' });
        
        const existing = queryOne("SELECT * FROM collection_assignments WHERE borrower_id=? AND status='assigned'", [borrower_id]);
        if (existing) return res.status(400).json({ error: 'Borrower already assigned' });
        
        runQuery("INSERT INTO collection_assignments (admin_id, collector_id, borrower_id) VALUES (?,?,?)", [req.user.userId, collector_id, borrower_id]);
        runQuery("UPDATE borrowers SET collector_id=? WHERE borrower_id=?", [collector_id, borrower_id]);
        
        res.status(201).json({ message: 'Collector assigned successfully!' });
    } catch (e) { res.status(500).json({ error: 'Assignment failed' }); }
});

app.get('/api/assignments', authenticateToken, authorize('admin'), (req, res) => {
    const assignments = queryAll(`
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
app.get('/api/loans', authenticateToken, (req, res) => {
    let loans;
    if (req.user.role === 'admin') {
        loans = queryAll("SELECT l.*, b.full_name as borrower_name, u.name as collector_name FROM loans l JOIN borrowers b ON l.borrower_id=b.borrower_id LEFT JOIN users u ON b.collector_id=u.user_id ORDER BY l.created_at DESC");
    } else if (req.user.role === 'collector') {
        loans = queryAll("SELECT l.*, b.full_name as borrower_name FROM loans l JOIN borrowers b ON l.borrower_id=b.borrower_id WHERE b.collector_id=? ORDER BY l.created_at DESC", [req.user.userId]);
    } else {
        const b = queryOne("SELECT borrower_id FROM borrowers WHERE user_id=?", [req.user.userId]);
        loans = b ? queryAll("SELECT * FROM loans WHERE borrower_id=? ORDER BY created_at DESC", [b.borrower_id]) : [];
    }
    res.json(loans);
});

app.post('/api/loans', authenticateToken, authorize('admin'), (req, res) => {
    try {
        const { borrower_id, loan_amount, interest_rate, due_date } = req.body;
        if (!borrower_id || !loan_amount || !interest_rate || !due_date) return res.status(400).json({ error: 'All fields required' });
        runQuery("INSERT INTO loans (borrower_id, loan_amount, interest_rate, due_date, balance, status) VALUES (?,?,?,?,?,'active')",
            [borrower_id, parseFloat(loan_amount), parseFloat(interest_rate), due_date, parseFloat(loan_amount)]);
        res.status(201).json({ message: 'Loan created!' });
    } catch (e) { res.status(500).json({ error: 'Failed to create loan' }); }
});

// ==================== PAYMENTS ====================
app.get('/api/payments', authenticateToken, (req, res) => {
    const payments = queryAll("SELECT p.*, b.full_name as borrower_name, u.name as collector_name FROM payments p JOIN loans l ON p.loan_id=l.loan_id JOIN borrowers b ON l.borrower_id=b.borrower_id LEFT JOIN users u ON p.collector_id=u.user_id ORDER BY p.payment_date DESC LIMIT 50");
    res.json(payments);
});

app.post('/api/payments', authenticateToken, (req, res) => {
    try {
        const { loan_id, amount, latitude, longitude } = req.body;
        if (!loan_id || !amount) return res.status(400).json({ error: 'Loan and amount required' });
        
        const loan = queryOne("SELECT l.*, b.borrower_id FROM loans l JOIN borrowers b ON l.borrower_id=b.borrower_id WHERE l.loan_id=?", [loan_id]);
        if (!loan) return res.status(404).json({ error: 'Loan not found' });
        if (parseFloat(amount) > parseFloat(loan.balance)) return res.status(400).json({ error: 'Amount exceeds balance' });
        
        const receipt = 'RCP-' + Date.now();
        runQuery("INSERT INTO payments (loan_id, collector_id, amount, latitude, longitude, receipt_number) VALUES (?,?,?,?,?,?)",
            [loan_id, req.user.userId, parseFloat(amount), latitude||null, longitude||null, receipt]);
        
        const newBalance = parseFloat(loan.balance) - parseFloat(amount);
        runQuery("UPDATE loans SET balance=?, status=? WHERE loan_id=?", [newBalance.toFixed(2), newBalance <= 0 ? 'paid' : 'active', loan_id]);
        
        if (latitude && longitude) {
            runQuery("INSERT INTO gps_logs (collector_id, borrower_id, latitude, longitude) VALUES (?,?,?,?)",
                [req.user.userId, loan.borrower_id, latitude, longitude]);
        }
        
        res.status(201).json({ message: 'Payment recorded!', receipt, newBalance: newBalance.toFixed(2) });
    } catch (e) { res.status(500).json({ error: 'Payment failed' }); }
});

// ==================== GPS ROUTES ====================
app.post('/api/gps/log', authenticateToken, (req, res) => {
    try {
        const { borrower_id, latitude, longitude } = req.body;
        if (!latitude || !longitude) return res.status(400).json({ error: 'GPS coordinates required' });
        
        runQuery("INSERT INTO gps_logs (collector_id, borrower_id, latitude, longitude) VALUES (?,?,?,?)",
            [req.user.userId, borrower_id || null, latitude, longitude]);
        
        if (borrower_id) {
            runQuery("UPDATE borrowers SET latitude=?, longitude=? WHERE borrower_id=?", [latitude, longitude, borrower_id]);
        }
        
        res.json({ message: 'GPS logged' });
    } catch (e) { res.status(500).json({ error: 'GPS log failed' }); }
});

app.get('/api/gps/logs', authenticateToken, (req, res) => {
    const logs = queryAll("SELECT g.*, b.full_name as borrower_name, u.name as collector_name FROM gps_logs g LEFT JOIN borrowers b ON g.borrower_id=b.borrower_id LEFT JOIN users u ON g.collector_id=u.user_id ORDER BY g.timestamp DESC LIMIT 100");
    res.json(logs);
});

app.get('/api/gps/borrowers', authenticateToken, (req, res) => {
    const borrowers = queryAll("SELECT borrower_id, full_name, latitude, longitude, street, barangay, city FROM borrowers WHERE latitude IS NOT NULL");
    res.json(borrowers);
});

app.put('/api/gps/update-location', authenticateToken, (req, res) => {
    try {
        const { latitude, longitude } = req.body;
        if (req.user.role === 'borrower') {
            runQuery("UPDATE borrowers SET latitude=?, longitude=? WHERE user_id=?", [latitude, longitude, req.user.userId]);
        }
        res.json({ message: 'Location updated' });
    } catch (e) { res.status(500).json({ error: 'Update failed' }); }
});

// ==================== ML RISK ====================
app.get('/api/ml/risk/:borrowerId', authenticateToken, (req, res) => {
    try {
        const borrower = queryOne("SELECT * FROM borrowers WHERE borrower_id=?", [req.params.borrowerId]);
        if (!borrower) return res.status(404).json({ error: 'Not found' });
        
        const loans = queryAll("SELECT * FROM loans WHERE borrower_id=?", [req.params.borrowerId]);
        const payments = queryAll("SELECT p.* FROM payments p JOIN loans l ON p.loan_id=l.loan_id WHERE l.borrower_id=?", [req.params.borrowerId]);
        
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

// Serve frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Error handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
});
// Debug route - check all users
app.get('/api/debug/users', (req, res) => {
    const users = queryAll("SELECT user_id, name, email, role, status FROM users");
    res.json({ total: users.length, users });
});

// Start
initializeDatabase().then(() => {
    app.listen(PORT, '0.0.0.0', () => console.log(`\n✅ Server: http://localhost:${PORT}\n👤 Admin: admin@system.com / admin123\n`));
}).catch(e => { console.error(e); process.exit(1); });
