const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// ==================== DATABASE SETUP ====================
const dbPath = path.join(__dirname, 'debt_collection.db');
let db;

async function initializeDatabase() {
    const SQL = await initSqlJs();
    
    // Load existing database or create new one
    if (fs.existsSync(dbPath)) {
        const fileBuffer = fs.readFileSync(dbPath);
        db = new SQL.Database(fileBuffer);
    } else {
        db = new SQL.Database();
    }
    
    // Create tables
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin','collector','borrower','pending_user')) NOT NULL DEFAULT 'pending_user',
            status TEXT CHECK(status IN ('pending','approved','rejected')) NOT NULL DEFAULT 'pending',
            phone TEXT,
            address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS borrowers (
            borrower_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(user_id),
            full_name TEXT NOT NULL,
            address TEXT,
            phone TEXT,
            collector_id INTEGER REFERENCES users(user_id),
            gps_latitude REAL,
            gps_longitude REAL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS loans (
            loan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            borrower_id INTEGER REFERENCES borrowers(borrower_id),
            loan_amount REAL NOT NULL,
            interest_rate REAL NOT NULL,
            due_date DATE NOT NULL,
            balance REAL NOT NULL,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS payments (
            payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            loan_id INTEGER REFERENCES loans(loan_id),
            collector_id INTEGER REFERENCES users(user_id),
            amount REAL NOT NULL,
            payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            gps_latitude REAL,
            gps_longitude REAL,
            receipt_number TEXT UNIQUE
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS risk_assessments (
            assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            borrower_id INTEGER REFERENCES borrowers(borrower_id),
            risk_score REAL,
            risk_level TEXT,
            factors TEXT,
            assessed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Seed admin user
    const adminCheck = db.exec("SELECT COUNT(*) as count FROM users WHERE email = 'admin@system.com'");
    const count = adminCheck[0]?.values[0][0] || 0;
    
    if (count === 0) {
        const hashedPassword = bcrypt.hashSync('admin123', 10);
        db.run("INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, ?, ?)",
            ['Admin', 'admin@system.com', hashedPassword, 'admin', 'approved']);
        console.log('✅ Admin user seeded (admin@system.com / admin123)');
    }
    
    // Save database
    saveDatabase();
    console.log('✅ Database initialized');
}

function saveDatabase() {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(dbPath, buffer);
}

// Helper: Run query and get all rows as array of objects
function queryAll(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        const rows = [];
        while (stmt.step()) {
            rows.push(stmt.getAsObject());
        }
        stmt.free();
        return rows;
    } catch (error) {
        console.error('Query error:', error.message);
        throw error;
    }
}

// Helper: Get single row
function queryOne(sql, params = []) {
    const rows = queryAll(sql, params);
    return rows[0] || null;
}

// Helper: Run SQL that modifies data
function runQuery(sql, params = []) {
    try {
        db.run(sql, params);
        saveDatabase();
        return { lastInsertRowid: db.exec("SELECT last_insert_rowid()")[0]?.values[0][0] };
    } catch (error) {
        console.error('Run error:', error.message);
        throw error;
    }
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied' });
    
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key-change-me');
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// ==================== ML RISK SCORING ====================
function calculateRiskScore(data) {
    let score = 50;
    score -= (data.activeLoans || 0) * 5;
    score += (data.totalPayments || 0) * 2;
    score += (data.totalPaid || 0) * 0.1;
    score -= (data.totalLoanAmount || 0) * 0.01;
    score += (data.onTimePayments || 0) * 3;
    score = Math.max(0, Math.min(100, score));
    
    return {
        risk_score: Math.round(score * 100) / 100,
        risk_level: score >= 70 ? 'low' : score >= 40 ? 'medium' : 'high',
        factors: {
            active_loans: data.activeLoans,
            payment_history: (data.totalPayments || 0) > 5 ? 'good' : 'poor'
        }
    };
}

// ==================== AUTH ROUTES ====================
app.post('/api/auth/login', (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const user = queryOne("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", [email.trim()]);
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });
        if (user.status !== 'approved') return res.status(403).json({ error: 'Account pending approval' });

        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid email or password' });

        const token = jwt.sign(
            { userId: user.user_id, role: user.role },
            process.env.JWT_SECRET || 'default-secret-key-change-me',
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                user_id: user.user_id,
                name: user.name,
                email: user.email,
                role: user.role,
                status: user.status
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/auth/register', (req, res) => {
    try {
        const { name, email, password, phone, address } = req.body;
        if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, password required' });

        const existing = queryOne("SELECT user_id FROM users WHERE LOWER(email) = LOWER(?)", [email.trim()]);
        if (existing) return res.status(400).json({ error: 'Email already registered' });

        const hashedPassword = bcrypt.hashSync(password, 10);
        runQuery(
            "INSERT INTO users (name, email, password, role, status, phone, address) VALUES (?, ?, ?, 'pending_user', 'pending', ?, ?)",
            [name, email.trim(), hashedPassword, phone || null, address || null]
        );

        res.status(201).json({ message: 'Registration successful. Please wait for admin approval.' });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// ==================== DASHBOARD ROUTES ====================
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    try {
        const { role, userId } = req.user;
        
        if (role === 'admin') {
            const totalLoans = queryOne("SELECT COUNT(*) as count FROM loans")?.count || 0;
            const totalPayments = queryOne("SELECT COALESCE(SUM(amount), 0) as total FROM payments")?.total || 0;
            const totalBorrowers = queryOne("SELECT COUNT(*) as count FROM borrowers")?.count || 0;
            const recentPayments = queryAll(`
                SELECT p.*, b.full_name as borrower_name, l.loan_amount
                FROM payments p JOIN loans l ON p.loan_id = l.loan_id
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                ORDER BY p.payment_date DESC LIMIT 5
            `);
            res.json({ totalLoans, totalPayments, totalBorrowers, recentPayments });
        } else {
            res.json({ totalLoans: 0, totalPayments: 0, recentPayments: [] });
        }
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== USER ROUTES ====================
app.get('/api/users', authenticateToken, authorizeRoles('admin'), (req, res) => {
    try {
        const users = queryAll("SELECT user_id, name, email, role, status, phone, address, created_at FROM users ORDER BY created_at DESC");
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.put('/api/users/:id/status', authenticateToken, authorizeRoles('admin'), (req, res) => {
    try {
        const { status } = req.body;
        const userId = req.params.id;
        
        if (!['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        const user = queryOne("SELECT role FROM users WHERE user_id = ?", [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        if (status === 'approved' && user.role === 'pending_user') {
            runQuery("UPDATE users SET status = ?, role = 'borrower', updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", [status, userId]);
        } else {
            runQuery("UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", [status, userId]);
        }
        
        res.json({ message: 'User updated' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// ==================== BORROWER ROUTES ====================
app.get('/api/borrowers', authenticateToken, (req, res) => {
    try {
        const borrowers = queryAll(`
            SELECT b.*, u.name as collector_name FROM borrowers b
            LEFT JOIN users u ON b.collector_id = u.user_id ORDER BY b.created_at DESC
        `);
        res.json(borrowers);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch borrowers' });
    }
});

// ==================== LOAN ROUTES ====================
app.get('/api/loans', authenticateToken, (req, res) => {
    try {
        let loans;
        if (req.user.role === 'admin') {
            loans = queryAll(`
                SELECT l.*, b.full_name as borrower_name, u.name as collector_name
                FROM loans l JOIN borrowers b ON l.borrower_id = b.borrower_id
                LEFT JOIN users u ON b.collector_id = u.user_id ORDER BY l.created_at DESC
            `);
        } else {
            const borrower = queryOne("SELECT borrower_id FROM borrowers WHERE user_id = ?", [req.user.userId]);
            loans = borrower ? queryAll("SELECT * FROM loans WHERE borrower_id = ? ORDER BY created_at DESC", [borrower.borrower_id]) : [];
        }
        res.json(loans);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch loans' });
    }
});

app.post('/api/loans', authenticateToken, authorizeRoles('admin'), (req, res) => {
    try {
        const { borrower_id, loan_amount, interest_rate, due_date } = req.body;
        if (!borrower_id || !loan_amount || !interest_rate || !due_date) {
            return res.status(400).json({ error: 'All fields required' });
        }
        
        runQuery(
            "INSERT INTO loans (borrower_id, loan_amount, interest_rate, due_date, balance, status) VALUES (?, ?, ?, ?, ?, 'active')",
            [borrower_id, loan_amount, interest_rate, due_date, loan_amount]
        );
        
        res.status(201).json({ message: 'Loan created' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create loan' });
    }
});

// ==================== PAYMENT ROUTES ====================
app.get('/api/payments', authenticateToken, (req, res) => {
    try {
        const payments = queryAll(`
            SELECT p.*, b.full_name as borrower_name, u.name as collector_name, l.loan_amount
            FROM payments p JOIN loans l ON p.loan_id = l.loan_id
            JOIN borrowers b ON l.borrower_id = b.borrower_id
            LEFT JOIN users u ON p.collector_id = u.user_id ORDER BY p.payment_date DESC
        `);
        res.json(payments);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});

// ==================== ML RISK ASSESSMENT ====================
app.get('/api/ml/risk-assessment/:borrowerId', authenticateToken, (req, res) => {
    try {
        const borrower = queryOne("SELECT * FROM borrowers WHERE borrower_id = ?", [req.params.borrowerId]);
        if (!borrower) return res.status(404).json({ error: 'Borrower not found' });
        
        const loans = queryAll("SELECT * FROM loans WHERE borrower_id = ?", [req.params.borrowerId]);
        const payments = queryAll(`
            SELECT p.* FROM payments p JOIN loans l ON p.loan_id = l.loan_id WHERE l.borrower_id = ?
        `, [req.params.borrowerId]);
        
        const riskData = calculateRiskScore({
            totalLoans: loans.length,
            activeLoans: loans.filter(l => l.status === 'active').length,
            totalPayments: payments.length,
            totalPaid: payments.reduce((sum, p) => sum + (p.amount || 0), 0),
            totalLoanAmount: loans.reduce((sum, l) => sum + (l.loan_amount || 0), 0),
            onTimePayments: 0
        });
        
        res.json({
            borrower: borrower.full_name,
            ...riskData,
            loan_summary: { total_loans: loans.length, active_loans: loans.filter(l => l.status === 'active').length }
        });
    } catch (error) {
        res.status(500).json({ error: 'Risk assessment failed' });
    }
});

// ==================== SERVE FRONTEND ====================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== ERROR HANDLER ====================
app.use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ==================== START SERVER ====================
initializeDatabase().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`✅ Server running on port ${PORT}`);
        console.log(`👤 Demo: admin@system.com / admin123`);
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});
