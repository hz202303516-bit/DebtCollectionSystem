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
    
    // Seed ONLY ONE admin account if not exists
    const adminCheck = db.exec("SELECT COUNT(*) as count FROM users WHERE email = 'admin@system.com'");
    const adminCount = adminCheck[0]?.values[0][0] || 0;
    
    if (adminCount === 0) {
        const hashedPassword = bcrypt.hashSync('admin123', 10);
        db.run("INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, ?, ?)",
            ['System Admin', 'admin@system.com', hashedPassword, 'admin', 'approved']);
        console.log('✅ Admin account created: admin@system.com / admin123');
    } else {
        // Ensure the existing admin is always approved
        db.run("UPDATE users SET status = 'approved', role = 'admin' WHERE email = 'admin@system.com'");
        console.log('✅ Admin account verified');
    }
    
    saveDatabase();
    console.log('✅ Database initialized');
}

function saveDatabase() {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(dbPath, buffer);
}

// Helper: Get all rows as objects
function queryAll(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        if (params.length > 0) {
            stmt.bind(params);
        }
        const rows = [];
        while (stmt.step()) {
            rows.push(stmt.getAsObject());
        }
        stmt.free();
        return rows;
    } catch (error) {
        console.error('Query error:', error.message, 'SQL:', sql);
        return [];
    }
}

// Helper: Get single row
function queryOne(sql, params = []) {
    const rows = queryAll(sql, params);
    return rows.length > 0 ? rows[0] : null;
}

// Helper: Run insert/update/delete
function runQuery(sql, params = []) {
    try {
        db.run(sql, params);
        saveDatabase();
        const result = db.exec("SELECT last_insert_rowid()");
        return { lastID: result[0]?.values[0][0] || 0, changes: db.getRowsModified() };
    } catch (error) {
        console.error('Run error:', error.message, 'SQL:', sql);
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
    if (!token) return res.status(401).json({ error: 'Access denied. Please login.' });
    
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key-change-me');
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token. Please login again.' });
    }
};

const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
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
            active_loans: data.activeLoans || 0,
            payment_history: (data.totalPayments || 0) > 5 ? 'good' : 'poor'
        }
    };
}

// ==================== AUTH ROUTES ====================

// REGISTER - Fixed and working
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone, address } = req.body;
        
        // Validate required fields
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required' });
        }
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        // Validate password length
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        // Check if email already exists
        const existingUser = queryOne("SELECT user_id FROM users WHERE LOWER(email) = LOWER(?)", [email.trim()]);
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered. Please use a different email.' });
        }
        
        // BLOCK admin registration - only one admin allowed
        if (email.toLowerCase() === 'admin@system.com') {
            return res.status(400).json({ error: 'Cannot register with admin email.' });
        }
        
        // Hash password
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        // Insert new user as pending_user
        runQuery(
            "INSERT INTO users (name, email, password, role, status, phone, address) VALUES (?, ?, ?, 'pending_user', 'pending', ?, ?)",
            [name.trim(), email.trim().toLowerCase(), hashedPassword, phone || null, address || null]
        );
        
        console.log(`✅ New user registered: ${email} - pending approval`);
        
        res.status(201).json({
            message: 'Registration successful! Please wait for admin approval before logging in.',
            success: true
        });
        
    } catch (error) {
        console.error('Registration error:', error.message);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

// LOGIN - Fixed
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        console.log(`Login attempt: ${email}`);
        
        const user = queryOne("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", [email.trim()]);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Check if user is approved (admin is always approved)
        if (user.status !== 'approved' && user.role !== 'admin') {
            return res.status(403).json({ 
                error: 'Your account is pending approval. Please wait for an admin to approve your account.',
                status: user.status
            });
        }
        
        // Verify password
        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user.user_id, role: user.role },
            process.env.JWT_SECRET || 'default-secret-key-change-me',
            { expiresIn: '24h' }
        );
        
        console.log(`✅ Login successful: ${email} (${user.role})`);
        
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
        console.error('Login error:', error.message);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
    try {
        const user = queryOne(
            "SELECT user_id, name, email, role, status, phone, address FROM users WHERE user_id = ?",
            [req.user.userId]
        );
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get user info' });
    }
});

// ==================== DASHBOARD ROUTES ====================
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    try {
        const { role, userId } = req.user;
        
        if (role === 'admin') {
            const totalLoans = queryOne("SELECT COUNT(*) as count FROM loans");
            const totalPayments = queryOne("SELECT COALESCE(SUM(amount), 0) as total FROM payments");
            const totalBorrowers = queryOne("SELECT COUNT(*) as count FROM borrowers");
            const pendingUsers = queryOne("SELECT COUNT(*) as count FROM users WHERE status = 'pending'");
            const recentPayments = queryAll(`
                SELECT p.*, b.full_name as borrower_name, l.loan_amount
                FROM payments p 
                JOIN loans l ON p.loan_id = l.loan_id
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                ORDER BY p.payment_date DESC LIMIT 5
            `);
            
            res.json({
                totalLoans: totalLoans?.count || 0,
                totalPayments: totalPayments?.total || 0,
                totalBorrowers: totalBorrowers?.count || 0,
                pendingUsers: pendingUsers?.count || 0,
                recentPayments: recentPayments || []
            });
        } else if (role === 'collector') {
            const assignedBorrowers = queryOne(
                "SELECT COUNT(*) as count FROM borrowers WHERE collector_id = ?",
                [userId]
            );
            const collectedPayments = queryOne(
                "SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE collector_id = ?",
                [userId]
            );
            const recentPayments = queryAll(`
                SELECT p.*, b.full_name as borrower_name, l.loan_amount
                FROM payments p 
                JOIN loans l ON p.loan_id = l.loan_id
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                WHERE p.collector_id = ?
                ORDER BY p.payment_date DESC LIMIT 5
            `, [userId]);
            
            res.json({
                totalBorrowers: assignedBorrowers?.count || 0,
                totalPayments: collectedPayments?.total || 0,
                recentPayments: recentPayments || []
            });
        } else if (role === 'borrower') {
            const borrower = queryOne("SELECT borrower_id FROM borrowers WHERE user_id = ?", [userId]);
            if (!borrower) {
                return res.json({ totalLoans: 0, totalPayments: 0, recentPayments: [] });
            }
            
            const totalLoans = queryOne(
                "SELECT COUNT(*) as count FROM loans WHERE borrower_id = ?",
                [borrower.borrower_id]
            );
            const totalBalance = queryOne(
                "SELECT COALESCE(SUM(balance), 0) as total FROM loans WHERE borrower_id = ? AND status = 'active'",
                [borrower.borrower_id]
            );
            const recentPayments = queryAll(`
                SELECT p.*, l.loan_amount
                FROM payments p 
                JOIN loans l ON p.loan_id = l.loan_id
                WHERE l.borrower_id = ?
                ORDER BY p.payment_date DESC LIMIT 5
            `, [borrower.borrower_id]);
            
            res.json({
                totalLoans: totalLoans?.count || 0,
                totalBalance: totalBalance?.total || 0,
                recentPayments: recentPayments || []
            });
        } else {
            res.json({ totalLoans: 0, totalPayments: 0, recentPayments: [] });
        }
    } catch (error) {
        console.error('Dashboard error:', error.message);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
});

// ==================== USER MANAGEMENT (ADMIN ONLY) ====================
app.get('/api/users', authenticateToken, authorizeRoles('admin'), (req, res) => {
    try {
        const users = queryAll(
            "SELECT user_id, name, email, role, status, phone, address, created_at FROM users ORDER BY created_at DESC"
        );
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
            return res.status(400).json({ error: 'Invalid status. Must be: pending, approved, or rejected.' });
        }
        
        const user = queryOne("SELECT * FROM users WHERE user_id = ?", [userId]);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Prevent changing admin status
        if (user.role === 'admin') {
            return res.status(403).json({ error: 'Cannot modify admin account status.' });
        }
        
        // If approving a pending_user, change role to borrower
        if (status === 'approved' && user.role === 'pending_user') {
            runQuery(
                "UPDATE users SET status = ?, role = 'borrower', updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                [status, userId]
            );
            
            // Auto-create borrower record
            const existingBorrower = queryOne("SELECT borrower_id FROM borrowers WHERE user_id = ?", [userId]);
            if (!existingBorrower) {
                runQuery(
                    "INSERT INTO borrowers (user_id, full_name, phone, address) VALUES (?, ?, ?, ?)",
                    [userId, user.name, user.phone, user.address]
                );
            }
        } else {
            runQuery(
                "UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                [status, userId]
            );
        }
        
        console.log(`✅ User ${userId} status updated to: ${status}`);
        res.json({ message: `User ${status} successfully` });
        
    } catch (error) {
        console.error('Update user error:', error.message);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// ==================== BORROWER ROUTES ====================
app.get('/api/borrowers', authenticateToken, (req, res) => {
    try {
        let borrowers;
        if (req.user.role === 'admin') {
            borrowers = queryAll(`
                SELECT b.*, u.name as collector_name, u.email as user_email
                FROM borrowers b
                LEFT JOIN users u ON b.collector_id = u.user_id
                ORDER BY b.created_at DESC
            `);
        } else if (req.user.role === 'collector') {
            borrowers = queryAll(`
                SELECT b.*, u.name as collector_name
                FROM borrowers b
                LEFT JOIN users u ON b.collector_id = u.user_id
                WHERE b.collector_id = ?
                ORDER BY b.created_at DESC
            `, [req.user.userId]);
        } else {
            borrowers = queryAll(`
                SELECT b.* FROM borrowers b WHERE b.user_id = ?
            `, [req.user.userId]);
        }
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
                FROM loans l
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                LEFT JOIN users u ON b.collector_id = u.user_id
                ORDER BY l.created_at DESC
            `);
        } else if (req.user.role === 'collector') {
            loans = queryAll(`
                SELECT l.*, b.full_name as borrower_name
                FROM loans l
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                WHERE b.collector_id = ?
                ORDER BY l.created_at DESC
            `, [req.user.userId]);
        } else {
            const borrower = queryOne("SELECT borrower_id FROM borrowers WHERE user_id = ?", [req.user.userId]);
            loans = borrower ? queryAll(
                "SELECT * FROM loans WHERE borrower_id = ? ORDER BY created_at DESC",
                [borrower.borrower_id]
            ) : [];
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
            return res.status(400).json({ error: 'All fields are required: borrower, amount, interest rate, and due date.' });
        }
        
        // Verify borrower exists
        const borrower = queryOne("SELECT * FROM borrowers WHERE borrower_id = ?", [borrower_id]);
        if (!borrower) {
            return res.status(404).json({ error: 'Borrower not found.' });
        }
        
        runQuery(
            "INSERT INTO loans (borrower_id, loan_amount, interest_rate, due_date, balance, status) VALUES (?, ?, ?, ?, ?, 'active')",
            [borrower_id, parseFloat(loan_amount), parseFloat(interest_rate), due_date, parseFloat(loan_amount)]
        );
        
        console.log(`✅ Loan created for borrower ${borrower_id}: ₱${loan_amount}`);
        res.status(201).json({ message: 'Loan created successfully!' });
        
    } catch (error) {
        console.error('Create loan error:', error.message);
        res.status(500).json({ error: 'Failed to create loan.' });
    }
});

// ==================== PAYMENT ROUTES ====================
app.get('/api/payments', authenticateToken, (req, res) => {
    try {
        let payments;
        if (req.user.role === 'admin') {
            payments = queryAll(`
                SELECT p.*, b.full_name as borrower_name, u.name as collector_name, l.loan_amount
                FROM payments p
                JOIN loans l ON p.loan_id = l.loan_id
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                LEFT JOIN users u ON p.collector_id = u.user_id
                ORDER BY p.payment_date DESC
            `);
        } else if (req.user.role === 'collector') {
            payments = queryAll(`
                SELECT p.*, b.full_name as borrower_name, l.loan_amount
                FROM payments p
                JOIN loans l ON p.loan_id = l.loan_id
                JOIN borrowers b ON l.borrower_id = b.borrower_id
                WHERE p.collector_id = ?
                ORDER BY p.payment_date DESC
            `, [req.user.userId]);
        } else {
            const borrower = queryOne("SELECT borrower_id FROM borrowers WHERE user_id = ?", [req.user.userId]);
            payments = borrower ? queryAll(`
                SELECT p.*, l.loan_amount
                FROM payments p
                JOIN loans l ON p.loan_id = l.loan_id
                WHERE l.borrower_id = ?
                ORDER BY p.payment_date DESC
            `, [borrower.borrower_id]) : [];
        }
        res.json(payments);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});

app.post('/api/payments', authenticateToken, (req, res) => {
    try {
        const { loan_id, amount, gps_latitude, gps_longitude } = req.body;
        
        if (!loan_id || !amount) {
            return res.status(400).json({ error: 'Loan ID and amount are required.' });
        }
        
        const loan = queryOne("SELECT * FROM loans WHERE loan_id = ?", [loan_id]);
        if (!loan) {
            return res.status(404).json({ error: 'Loan not found.' });
        }
        
        if (loan.status === 'paid') {
            return res.status(400).json({ error: 'This loan is already fully paid.' });
        }
        
        const paymentAmount = parseFloat(amount);
        if (paymentAmount <= 0) {
            return res.status(400).json({ error: 'Payment amount must be greater than 0.' });
        }
        
        if (paymentAmount > parseFloat(loan.balance)) {
            return res.status(400).json({ 
                error: `Payment amount exceeds remaining balance of ₱${parseFloat(loan.balance).toFixed(2)}.` 
            });
        }
        
        const receiptNumber = 'RCP-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
        
        runQuery(
            "INSERT INTO payments (loan_id, collector_id, amount, gps_latitude, gps_longitude, receipt_number) VALUES (?, ?, ?, ?, ?, ?)",
            [loan_id, req.user.userId, paymentAmount, gps_latitude || null, gps_longitude || null, receiptNumber]
        );
        
        const newBalance = parseFloat(loan.balance) - paymentAmount;
        const newStatus = newBalance <= 0 ? 'paid' : 'active';
        
        runQuery(
            "UPDATE loans SET balance = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE loan_id = ?",
            [newBalance.toFixed(2), newStatus, loan_id]
        );
        
        console.log(`✅ Payment recorded: ₱${paymentAmount} for loan ${loan_id}`);
        
        res.status(201).json({
            message: 'Payment recorded successfully!',
            receiptNumber,
            newBalance: newBalance.toFixed(2),
            loanStatus: newStatus
        });
        
    } catch (error) {
        console.error('Payment error:', error.message);
        res.status(500).json({ error: 'Failed to record payment.' });
    }
});

// ==================== ML RISK ASSESSMENT ====================
app.get('/api/ml/risk-assessment/:borrowerId', authenticateToken, (req, res) => {
    try {
        const borrower = queryOne("SELECT * FROM borrowers WHERE borrower_id = ?", [req.params.borrowerId]);
        if (!borrower) return res.status(404).json({ error: 'Borrower not found' });
        
        const loans = queryAll("SELECT * FROM loans WHERE borrower_id = ?", [req.params.borrowerId]);
        const payments = queryAll(`
            SELECT p.* FROM payments p 
            JOIN loans l ON p.loan_id = l.loan_id 
            WHERE l.borrower_id = ?
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
            loan_summary: {
                total_loans: loans.length,
                active_loans: loans.filter(l => l.status === 'active').length,
                total_paid: payments.reduce((sum, p) => sum + (p.amount || 0), 0)
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
app.use((err, req, res, next) => {
    console.error('Server error:', err.message);
    res.status(500).json({ error: 'Internal server error. Please try again.' });
});

// ==================== START SERVER ====================
initializeDatabase().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`\n✅ Server running on port ${PORT}`);
        console.log(`🌐 Open http://localhost:${PORT}`);
        console.log(`👤 Admin login: admin@system.com / admin123`);
        console.log(`\nReady to accept connections!\n`);
    });
}).catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
});
