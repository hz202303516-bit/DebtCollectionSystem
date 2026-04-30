const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// ==================== DATABASE SETUP ====================
const dbPath = path.join(__dirname, 'debt_collection.db');
const db = new Database(dbPath);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
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
    );

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
    );

    CREATE TABLE IF NOT EXISTS loans (
        loan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        loan_amount REAL NOT NULL,
        interest_rate REAL NOT NULL,
        due_date DATE NOT NULL,
        balance REAL NOT NULL,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS payments (
        payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        loan_id INTEGER REFERENCES loans(loan_id),
        collector_id INTEGER REFERENCES users(user_id),
        amount REAL NOT NULL,
        payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        gps_latitude REAL,
        gps_longitude REAL,
        receipt_number TEXT UNIQUE
    );

    CREATE TABLE IF NOT EXISTS risk_assessments (
        assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        borrower_id INTEGER REFERENCES borrowers(borrower_id),
        risk_score REAL,
        risk_level TEXT,
        factors TEXT,
        assessed_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

// Seed admin user if not exists
const adminExists = db.prepare('SELECT COUNT(*) as count FROM users WHERE email = ?').get('admin@system.com');
if (adminExists.count === 0) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.prepare(`INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, ?, ?)`)
        .run('Admin', 'admin@system.com', hashedPassword, 'admin', 'approved');
    console.log('✅ Admin user seeded (admin@system.com / admin123)');
}

console.log('✅ Database initialized');

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== AUTH MIDDLEWARE ====================
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
function calculateRiskScore(borrowerData) {
    const { totalLoans = 0, activeLoans = 0, totalPayments = 0, totalPaid = 0, totalLoanAmount = 0, onTimePayments = 0 } = borrowerData;
    
    let score = 50;
    score -= (activeLoans * 5);
    score += (totalPayments * 2);
    score += (totalPaid * 0.1);
    score -= (totalLoanAmount * 0.01);
    score += (onTimePayments * 3);
    
    score = Math.max(0, Math.min(100, score));
    
    return {
        risk_score: Math.round(score * 100) / 100,
        risk_level: score >= 70 ? 'low' : score >= 40 ? 'medium' : 'high',
        factors: {
            active_loans: activeLoans,
            payment_history: totalPayments > 5 ? 'good' : 'poor',
            on_time_rate: totalPayments > 0 ? `${onTimePayments}/${totalPayments}` : 'N/A'
        }
    };
}

// ==================== ERROR HANDLER ====================
function errorHandler(err, req, res, next) {
    console.error('Error:', err.message);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message 
    });
}

// ==================== AUTH ROUTES ====================
app.post('/api/auth/login', (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)').get(email.trim());
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

        const existing = db.prepare('SELECT user_id FROM users WHERE LOWER(email) = LOWER(?)').get(email.trim());
        if (existing) return res.status(400).json({ error: 'Email already registered' });

        const hashedPassword = bcrypt.hashSync(password, 10);
        const result = db.prepare(
            `INSERT INTO users (name, email, password, role, status, phone, address) VALUES (?, ?, ?, 'pending_user', 'pending', ?, ?)`
        ).run(name, email.trim(), hashedPassword, phone || null, address || null);

        res.status(201).json({
            message: 'Registration successful. Please wait for admin approval.',
            user: { user_id: result.lastInsertRowid, name, email, role: 'pending_user', status: 'pending' }
        });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// ==================== DASHBOARD ROUTES ====================
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    try {
        const { role, userId } = req.user;
        
        if (role === 'admin') {
            const totalLoans = db.prepare('SELECT COUNT(*) as count FROM loans').get().count;
            const totalPayments = db.prepare('SELECT COALESCE(SUM(amount), 0) as total FROM payments').get().total;
            const totalBorrowers = db.prepare('SELECT COUNT(*) as count FROM borrowers').get().count;
            const recentPayments = db.prepare(`
                SELECT p.*, b.full_name as borrower_name, l.loan_amount
                FROM payments p JOIN loans l ON p.loan_id = l.loan_id
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                ORDER BY p.payment_date DESC LIMIT 5
            `).all();
            
            res.json({ totalLoans, totalPayments, totalBorrowers, recentPayments });
        } else if (role === 'collector') {
            const totalLoans = db.prepare(`
                SELECT COUNT(*) as count FROM loans l
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                WHERE b.collector_id = ?
            `).get(userId).count;
            const totalPayments = db.prepare('SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE collector_id = ?').get(userId).total;
            const recentPayments = db.prepare(`
                SELECT p.*, b.full_name as borrower_name, l.loan_amount
                FROM payments p JOIN loans l ON p.loan_id = l.loan_id
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                WHERE p.collector_id = ? ORDER BY p.payment_date DESC LIMIT 5
            `).all(userId);
            
            res.json({ totalLoans, totalPayments, recentPayments });
        } else {
            const borrower = db.prepare('SELECT borrower_id FROM borrowers WHERE user_id = ?').get(userId);
            if (!borrower) return res.json({ totalLoans: 0, totalPayments: 0, recentPayments: [] });
            
            const loans = db.prepare('SELECT * FROM loans WHERE borrower_id = ?').all(borrower.borrower_id);
            const totalLoans = loans.length;
            const totalPayments = db.prepare(`
                SELECT COALESCE(SUM(p.amount), 0) as total FROM payments p
                JOIN loans l ON p.loan_id = l.loan_id WHERE l.borrower_id = ?
            `).get(borrower.borrower_id).total;
            const recentPayments = db.prepare(`
                SELECT p.*, l.loan_amount FROM payments p JOIN loans l ON p.loan_id = l.loan_id
                WHERE l.borrower_id = ? ORDER BY p.payment_date DESC LIMIT 5
            `).all(borrower.borrower_id);
            
            res.json({ totalLoans, totalPayments, recentPayments });
        }
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== USER ROUTES ====================
app.get('/api/users', authenticateToken, authorizeRoles('admin'), (req, res) => {
    try {
        const users = db.prepare('SELECT user_id, name, email, role, status, phone, address, created_at FROM users ORDER BY created_at DESC').all();
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
        
        const user = db.prepare('SELECT role FROM users WHERE user_id = ?').get(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        if (status === 'approved' && user.role === 'pending_user') {
            db.prepare('UPDATE users SET status = ?, role = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?')
                .run(status, 'borrower', userId);
        } else {
            db.prepare('UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?')
                .run(status, userId);
        }
        
        res.json({ message: 'User updated' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// ==================== BORROWER ROUTES ====================
app.get('/api/borrowers', authenticateToken, (req, res) => {
    try {
        const borrowers = db.prepare(`
            SELECT b.*, u.name as collector_name FROM borrowers b
            LEFT JOIN users u ON b.collector_id = u.user_id ORDER BY b.created_at DESC
        `).all();
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
            loans = db.prepare(`
                SELECT l.*, b.full_name as borrower_name, u.name as collector_name
                FROM loans l JOIN borrowers b ON l.borrower_id = b.borrower_id
                LEFT JOIN users u ON b.collector_id = u.user_id ORDER BY l.created_at DESC
            `).all();
        } else if (req.user.role === 'collector') {
            loans = db.prepare(`
                SELECT l.*, b.full_name as borrower_name FROM loans l
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                WHERE b.collector_id = ? ORDER BY l.created_at DESC
            `).all(req.user.userId);
        } else {
            const borrower = db.prepare('SELECT borrower_id FROM borrowers WHERE user_id = ?').get(req.user.userId);
            loans = borrower ? db.prepare('SELECT * FROM loans WHERE borrower_id = ? ORDER BY created_at DESC').all(borrower.borrower_id) : [];
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
        
        const result = db.prepare(
            `INSERT INTO loans (borrower_id, loan_amount, interest_rate, due_date, balance, status) VALUES (?, ?, ?, ?, ?, 'active')`
        ).run(borrower_id, loan_amount, interest_rate, due_date, loan_amount);
        
        res.status(201).json({ message: 'Loan created', loan: { loan_id: result.lastInsertRowid } });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create loan' });
    }
});

// ==================== PAYMENT ROUTES ====================
app.get('/api/payments', authenticateToken, (req, res) => {
    try {
        let payments;
        if (req.user.role === 'admin') {
            payments = db.prepare(`
                SELECT p.*, b.full_name as borrower_name, u.name as collector_name, l.loan_amount
                FROM payments p JOIN loans l ON p.loan_id = l.loan_id
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                LEFT JOIN users u ON p.collector_id = u.user_id ORDER BY p.payment_date DESC
            `).all();
        } else if (req.user.role === 'collector') {
            payments = db.prepare(`
                SELECT p.*, b.full_name as borrower_name, l.loan_amount
                FROM payments p JOIN loans l ON p.loan_id = l.loan_id
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                WHERE p.collector_id = ? ORDER BY p.payment_date DESC
            `).all(req.user.userId);
        } else {
            const borrower = db.prepare('SELECT borrower_id FROM borrowers WHERE user_id = ?').get(req.user.userId);
            payments = borrower ? db.prepare(`
                SELECT p.*, l.loan_amount FROM payments p JOIN loans l ON p.loan_id = l.loan_id
                WHERE l.borrower_id = ? ORDER BY p.payment_date DESC
            `).all(borrower.borrower_id) : [];
        }
        res.json(payments);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});

app.post('/api/payments', authenticateToken, (req, res) => {
    try {
        const { loan_id, amount, gps_latitude, gps_longitude } = req.body;
        if (!loan_id || !amount) return res.status(400).json({ error: 'Loan ID and amount required' });
        
        const loan = db.prepare('SELECT * FROM loans WHERE loan_id = ?').get(loan_id);
        if (!loan) return res.status(404).json({ error: 'Loan not found' });
        if (parseFloat(amount) > parseFloat(loan.balance)) {
            return res.status(400).json({ error: 'Amount exceeds balance' });
        }
        
        const receiptNumber = 'RCP-' + Date.now();
        const result = db.prepare(
            `INSERT INTO payments (loan_id, collector_id, amount, gps_latitude, gps_longitude, receipt_number) VALUES (?, ?, ?, ?, ?, ?)`
        ).run(loan_id, req.user.userId, amount, gps_latitude || null, gps_longitude || null, receiptNumber);
        
        const newBalance = parseFloat(loan.balance) - parseFloat(amount);
        const newStatus = newBalance <= 0 ? 'paid' : 'active';
        db.prepare('UPDATE loans SET balance = ?, status = ? WHERE loan_id = ?').run(newBalance, newStatus, loan_id);
        
        res.status(201).json({
            message: 'Payment recorded',
            receiptNumber,
            newBalance
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to record payment' });
    }
});

// ==================== ML RISK ASSESSMENT ROUTES ====================
app.get('/api/ml/risk-assessment/:borrowerId', authenticateToken, (req, res) => {
    try {
        const borrower = db.prepare('SELECT * FROM borrowers WHERE borrower_id = ?').get(req.params.borrowerId);
        if (!borrower) return res.status(404).json({ error: 'Borrower not found' });
        
        const loans = db.prepare('SELECT * FROM loans WHERE borrower_id = ?').all(req.params.borrowerId);
        const payments = db.prepare(`
            SELECT p.* FROM payments p JOIN loans l ON p.loan_id = l.loan_id WHERE l.borrower_id = ?
        `).all(req.params.borrowerId);
        
        const riskData = calculateRiskScore({
            totalLoans: loans.length,
            activeLoans: loans.filter(l => l.status === 'active').length,
            totalPayments: payments.length,
            totalPaid: payments.reduce((sum, p) => sum + p.amount, 0),
            totalLoanAmount: loans.reduce((sum, l) => sum + l.loan_amount, 0),
            onTimePayments: payments.filter(p => {
                const paymentDate = new Date(p.payment_date);
                const loan = loans.find(l => l.loan_id === p.loan_id);
                return loan && paymentDate <= new Date(loan.due_date);
            }).length
        });
        
        db.prepare(
            `INSERT INTO risk_assessments (borrower_id, risk_score, risk_level, factors) VALUES (?, ?, ?, ?)`
        ).run(req.params.borrowerId, riskData.risk_score, riskData.risk_level, JSON.stringify(riskData.factors));
        
        res.json({
            borrower: borrower.full_name,
            ...riskData,
            loan_summary: {
                total_loans: loans.length,
                active_loans: loans.filter(l => l.status === 'active').length
            }
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
app.use(errorHandler);

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📁 Database: ${dbPath}`);
    console.log(`🔗 Open http://localhost:${PORT}`);
    console.log(`👤 Demo login: admin@system.com / admin123`);
});
