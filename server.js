// server.js - SmartExpense Backend API (PostgreSQL Migrated Version with Static Asset Support)

const express = require('express');
const { Pool } = require('pg'); // 🔄 Swapped mysql for pg
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path'); // 🚀 Added path module for static file directory routing

const app = express();
const port = process.env.PORT || 8080;

// --- CONFIGURATION ---
const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_VERY_SECURE_SECRET_KEY';
const HASH_SALT_ROUNDS = 10;
const BASE_URL = process.env.BASE_URL || 'https://fyp-smartexpense-backend.onrender.com';
const TOKEN_EXPIRY_MINUTES = 30;
const SENSITIVE_LOG_FIELDS = new Set([
    'pass',
    'password',
    'newpassword',
    'newPassword',
    'confirmpassword',
    'confirmPassword',
    'password_hash',
    'token',
    'authorization'
]);

const redactForLog = (value) => {
    if (Array.isArray(value)) return value.map(redactForLog);
    if (!value || typeof value !== 'object') return value;

    return Object.fromEntries(
        Object.entries(value).map(([key, val]) => [
            key,
            SENSITIVE_LOG_FIELDS.has(key) || SENSITIVE_LOG_FIELDS.has(key.toLowerCase()) ? '[REDACTED]' : redactForLog(val)
        ])
    );
};

const logDebug = (label, details = {}) => {
    console.log(`[${new Date().toISOString()}] ${label}`, redactForLog(details));
};

const logError = (label, error, details = {}) => {
    console.error(`[${new Date().toISOString()}] ${label}`, {
        ...redactForLog(details),
        error: {
            message: error.message,
            code: error.code,
            detail: error.detail,
            constraint: error.constraint,
            stack: error.stack
        }
    });
};

// --- Middleware ---
app.use(express.json());

// 🚀 Serve static frontend assets dynamically from the public folder
app.use(express.static(path.join(__dirname, 'public')));

const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'https://smartexpenseai.site',
  'https://www.smartexpenseai.site',
  'https://fyp-smartexpense-backend.onrender.com' // 🚀 Ditambah supaya tak kena block dengan server sendiri!
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: 'Content-Type,Authorization'
}));

app.use('/api', (req, res, next) => {
    logDebug('API REQUEST', {
        method: req.method,
        path: req.originalUrl,
        body: req.body,
        query: req.query,
        params: req.params
    });
    next();
});

// --- Database Configuration ---
const dbConnectionString = process.env.DATABASE_URL || 'postgresql://postgres:root@127.0.0.1:5432/postgres';

const pool = new Pool({
    connectionString: dbConnectionString,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false 
});

const queryAsync = async (text, params) => {
    const res = await pool.query(text, params);
    logDebug('DB RESULT', {
        sql: text.replace(/\s+/g, ' ').trim(),
        params: params ? params.map((_, index) => `$${index + 1}`) : [],
        rowCount: res.rowCount,
        rows: res.rows
    });
    return res.rows;
};

const REQUIRED_SCHEMA = {
    users: ['id', 'name', 'email', 'password_hash'],
    budgets: ['user_id', 'income', 'rent', 'food', 'internet', 'others', 'month_year'],
    expenses: ['id', 'user_id', 'amount', 'category', 'description', 'expense_date', 'month_year'],
    savings: ['user_id', 'target', 'months', 'saved_amount', 'updated_at'],
    password_resets: ['user_id', 'token', 'created_at']
};

const verifyDatabaseSchema = async () => {
    try {
        const tableNames = Object.keys(REQUIRED_SCHEMA);
        const columns = await queryAsync(
            `SELECT table_name, column_name
             FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = ANY($1)
             ORDER BY table_name, ordinal_position`,
            [tableNames]
        );

        const available = columns.reduce((acc, row) => {
            acc[row.table_name] = acc[row.table_name] || new Set();
            acc[row.table_name].add(row.column_name);
            return acc;
        }, {});

        const missing = Object.entries(REQUIRED_SCHEMA).flatMap(([table, requiredColumns]) => {
            const existingColumns = available[table] || new Set();
            return requiredColumns
                .filter(column => !existingColumns.has(column))
                .map(column => `${table}.${column}`);
        });

        if (missing.length) {
            console.error('[DB SCHEMA CHECK] Missing required columns:', missing);
        } else {
            console.log('[DB SCHEMA CHECK] Required table columns are present.');
        }

        console.log('[DB SCHEMA CHECK] Required unique constraints/indexes for Supabase PostgreSQL: users(email), budgets(user_id, month_year), savings(user_id).');
    } catch (error) {
        logError('DB SCHEMA CHECK FAILED', error);
    }
};

// --- Frontend Default Entry Route ---

// 🚀 Redirect root domain request directly to your login interface
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- API Endpoints ---

// REGISTER
app.post('/api/register', async (req, res) => {
    const { name, email, pass } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(pass, HASH_SALT_ROUNDS);
        const sql = 'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)';
        await queryAsync(sql, [name, email, hashedPassword]);
        logDebug('REGISTER SUCCESS', { email });
        res.status(201).json({ success: true, message: 'Registration successful.' });
    } catch (error) {
        logError('REGISTER ERROR', error, { email });
        if (error.code === '23505') 
            return res.status(409).json({ success: false, message: 'Email already registered.' });
        res.status(500).json({ success: false, message: 'Server error during registration.' });
    }
});

// LOGIN
app.post('/api/login', async (req, res) => {
    const { email, pass } = req.body;
    try {
        const sql = 'SELECT id, name, password_hash FROM users WHERE email = $1';
        const results = await queryAsync(sql, [email]);
        if (!results.length) return res.status(401).json({ success: false, message: 'Invalid email or password.' });

        const user = results[0];
        const match = await bcrypt.compare(pass, user.password_hash);
        if (!match) return res.status(401).json({ success: false, message: 'Invalid email or password.' });

        const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '1h' });
        
        res.status(200).json({ 
            success: true, 
            message: 'Login successful.', 
            token, 
            userId: user.id, 
            userName: user.name 
        });
        
    } catch (error) {
        logError('LOGIN ERROR', error, { email });
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

// FORGOT PASSWORD
app.post('/api/forgot_password', async (req, res) => {
    const { email } = req.body;
    try {
        const sql = 'SELECT id, name FROM users WHERE email = $1';
        const results = await queryAsync(sql, [email]);
        if (!results.length)
            return res.status(200).json({ success: true, message: 'If this email exists, reset link sent.' });

        const user = results[0];
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: `${TOKEN_EXPIRY_MINUTES}m` });
        const resetUrl = `${BASE_URL}/reset_password_form.html?token=${token}`; 

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.MAIL_USER, 
                pass: process.env.MAIL_PASS  
            }
        });

        await transporter.sendMail({
            from: 'SmartExpense <' + process.env.MAIL_USER + '>', 
            to: email,
            subject: 'Password Reset Request',
            html: `<p>Hello ${user.name},</p>
                    <p>Click below to reset your password (valid for ${TOKEN_EXPIRY_MINUTES} minutes):</p>
                    <p><a href="${resetUrl}">Reset My Password</a></p>
                    <p>If you did not request this, ignore this email.</p>`
        });

        await queryAsync(
            'INSERT INTO password_resets (user_id, token, created_at) VALUES ($1, $2, NOW())',
            [user.id, token]
        );

        res.status(200).json({ success: true, message: 'If this email exists, reset link sent.' });
        
    } catch (error) {
        logError('FORGOT PASSWORD ERROR', error, { email }); 
        res.status(500).json({ success: false, message: 'Server error during password reset request.' });
    }
});

// RESET PASSWORD
app.post('/api/reset_password', async (req, res) => {
    const { token, newPassword, confirmPassword } = req.body; 

    if (newPassword !== confirmPassword) return res.status(400).json({ success: false, message: 'Passwords do not match.' });

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        const userId = payload.id;
        logDebug('RESET PASSWORD USER', { userId });

        const tokenSQL = "SELECT * FROM password_resets WHERE token = $1 AND created_at >= NOW() - ($2 * INTERVAL '1 minute')";
        const tokenResults = await queryAsync(tokenSQL, [token, TOKEN_EXPIRY_MINUTES]);
        if (!tokenResults.length) return res.status(401).json({ success: false, message: 'Reset link invalid or expired.' });

        const hashedPassword = await bcrypt.hash(newPassword, HASH_SALT_ROUNDS); 
        await queryAsync('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, userId]);
        await queryAsync('DELETE FROM password_resets WHERE token = $1', [token]);

        res.status(200).json({ success: true, message: 'Password updated successfully.' });
    } catch (error) {
        if (error.name === 'TokenExpiredError') return res.status(401).json({ success: false, message: 'Reset link expired.' });
        if (error.name === 'JsonWebTokenError') return res.status(401).json({ success: false, message: 'Invalid reset link.' });
        logError('RESET PASSWORD ERROR', error);
        res.status(500).json({ success: false, message: 'Server error during password update.' });
    }
});

// --- JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (token == null) return res.status(401).json({ success: false, message: 'Access Denied: No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Access Denied: Invalid or expired token.' });
        req.user = user; 
        logDebug('AUTHENTICATED USER', { userId: req.user.id });
        next();
    });
};

// GET Budget Data using query string, e.g. /api/budget/get?user_id=123
app.get('/api/budget/get', authenticateToken, async (req, res) => {
    const userId = req.query.user_id || req.query.userId;
    logDebug('BUDGET GET USER', { userId });
    if (String(req.user.id) !== String(userId)) return res.status(403).json({ success: false, message: 'Unauthorized access to user data.' });

    try {
        const sql = 'SELECT income, rent, food, internet, others, month_year FROM budgets WHERE user_id = $1 ORDER BY month_year DESC LIMIT 1';
        const results = await queryAsync(sql, [userId]);

        if (results.length > 0) {
            res.status(200).json({ success: true, budget: results[0] });
        } else {
            res.status(200).json({ success: true, budget: null, message: 'No budget setup found.' });
        }
    } catch (error) {
        logError('BUDGET GET ERROR', error, { userId });
        res.status(500).json({ success: false, message: 'Server error loading budget data.' });
    }
});

// GET Budget Data
app.get('/api/budget/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    logDebug('BUDGET LOAD USER', { userId });
    if (String(req.user.id) !== userId) return res.status(403).json({ success: false, message: 'Unauthorized access to user data.' });

    try {
        const sql = 'SELECT income, rent, food, internet, others, month_year FROM budgets WHERE user_id = $1 ORDER BY month_year DESC LIMIT 1';
        const results = await queryAsync(sql, [userId]);

        if (results.length > 0) {
            res.status(200).json({ success: true, budget: results[0] });
        } else {
            res.status(200).json({ success: true, budget: null, message: 'No budget setup found.' });
        }
    } catch (error) {
        logError('BUDGET LOAD ERROR', error, { userId });
        res.status(500).json({ success: false, message: 'Server error loading budget data.' });
    }
});

// POST/PUT Budget Data
app.post('/api/budget/save', authenticateToken, async (req, res) => {
    const { income, rent, food, internet, others } = req.body;
    const user_id = req.body.user_id || req.body.userId;
    const monthYear = new Date().toISOString().slice(0, 7);
    logDebug('BUDGET SAVE USER', { userId: user_id, month_year: monthYear });

    if (String(req.user.id) !== String(user_id)) return res.status(403).json({ success: false, message: 'Unauthorized attempt to save data.' });
    
    try {
        const sql = `
            INSERT INTO budgets (user_id, income, rent, food, internet, others, month_year)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (user_id, month_year) 
            DO UPDATE SET 
                income = EXCLUDED.income, 
                rent = EXCLUDED.rent, 
                food = EXCLUDED.food, 
                internet = EXCLUDED.internet, 
                others = EXCLUDED.others;
        `;
        const values = [user_id, income, rent, food, internet, others, monthYear];
        await queryAsync(sql, values);
        res.status(200).json({ success: true, message: 'Budget setup saved successfully!' });
    } catch (error) {
        logError('BUDGET SAVE ERROR', error, { userId: user_id, month_year: monthYear });
        res.status(500).json({ success: false, message: 'Server error saving budget data.' });
    }
});

// POST save a new expense
app.post('/api/expense/add', authenticateToken, async (req, res) => {
    const { amount, category, date } = req.body;
    const user_id = req.body.user_id || req.body.userId;
    const description = req.body.description ?? req.body.desc ?? '';
    const monthYear = date ? date.slice(0, 7) : new Date().toISOString().slice(0, 7);
    logDebug('EXPENSE ADD USER', { userId: user_id, month_year: monthYear });

    if (String(req.user.id) !== String(user_id)) return res.status(403).json({ success: false, message: 'Unauthorized attempt to save expense.' });
    
    try {
        const sql = `
            INSERT INTO expenses (user_id, amount, category, description, expense_date, month_year)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING id;
        `;
        const values = [user_id, amount, category, description, date, monthYear];
        const results = await queryAsync(sql, values);
        
        res.status(201).json({ success: true, message: 'Expense saved successfully!', expenseId: results[0].id });
    } catch (error) {
        logError('EXPENSE ADD ERROR', error, { userId: user_id, month_year: monthYear });
        res.status(500).json({ success: false, message: 'Server error saving expense data.' });
    }
});

// GET list of expenses
app.get('/api/expense/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const month = req.query.month;
    logDebug('EXPENSE LIST USER', { userId, month });

    if (String(req.user.id) !== userId) return res.status(403).json({ success: false, message: 'Unauthorized access to expense data.' });

    try {
        let sql = `
            SELECT id, amount, category, description, 
                   TO_CHAR(expense_date, 'MM/DD/YYYY') AS date 
            FROM expenses 
            WHERE user_id = $1
        `;
        const params = [userId];

        if (month) {
            sql += ' AND month_year = $2';
            params.push(month);
        }

        sql += ' ORDER BY expense_date DESC, id DESC';
        const results = await queryAsync(sql, params);
        res.status(200).json({ success: true, expenses: results });
    } catch (error) {
        logError('EXPENSE LIST ERROR', error, { userId, month });
        res.status(500).json({ success: false, message: 'Server error loading expenses data.' });
    }
});

// GET Months
app.get('/api/months', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    logDebug('MONTHS LOAD USER', { userId });
    try {
        const sql = 'SELECT DISTINCT month_year FROM expenses WHERE user_id = $1 ORDER BY month_year DESC';
        const results = await queryAsync(sql, [userId]);
        res.status(200).json(results.map(r => ({ month_year: r.month_year })));
    } catch (error) {
        logError('MONTHS LOAD ERROR', error, { userId }); 
        res.status(500).json({ success: false, message: 'Server error fetching months.' });
    }
});

// POST Delete an expense
app.post('/api/expense/delete', authenticateToken, async (req, res) => {
    const user_id = req.body.user_id || req.body.userId;
    const expense_id = req.body.expense_id || req.body.expenseId;
    logDebug('EXPENSE DELETE USER', { userId: user_id, expense_id });

    if (String(req.user.id) !== String(user_id)) return res.status(403).json({ success: false, message: 'Unauthorized attempt to delete expense.' });
    
    try {
        const sql = 'DELETE FROM expenses WHERE user_id = $1 AND id = $2';
        const resObj = await pool.query(sql, [user_id, expense_id]);
        logDebug('DB RESULT', {
            sql,
            params: ['$1', '$2'],
            rowCount: resObj.rowCount,
            rows: resObj.rows
        });

        if (resObj.rowCount === 0) { 
            return res.status(404).json({ success: false, message: 'Expense not found or unauthorized.' });
        }
        res.status(200).json({ success: true, message: 'Expense deleted successfully.' });
    } catch (error) {
        logError('EXPENSE DELETE ERROR', error, { userId: user_id, expense_id });
        res.status(500).json({ success: false, message: 'Server error deleting expense.' });
    }
});

// GET Savings Plan Data
app.get('/api/savings', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    logDebug('SAVINGS LOAD USER', { userId });
    try {
        const sql = 'SELECT target, months, saved_amount FROM savings WHERE user_id = $1';
        const results = await queryAsync(sql, [userId]);

        if (results.length > 0) {
            res.status(200).json({ success: true, ...results[0] });
        } else {
            res.status(200).json({ success: true, target: 0, months: 1, saved_amount: 0 });
        }
    } catch (error) {
        logError('SAVINGS LOAD ERROR', error, { userId });
        res.status(500).json({ success: false, message: 'Server error loading savings data.' });
    }
});

// POST Savings Target
app.post('/api/savings/target', authenticateToken, async (req, res) => {
    const { target, months } = req.body;
    const userId = req.user.id;
    logDebug('SAVINGS TARGET USER', { userId });
    
    try {
        const sql = `
            INSERT INTO savings (user_id, target, months)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id) 
            DO UPDATE SET 
                target = EXCLUDED.target, 
                months = EXCLUDED.months,
                updated_at = NOW();
        `;
        await queryAsync(sql, [userId, target, months]);
        const updatedRecord = await queryAsync('SELECT target, months, saved_amount FROM savings WHERE user_id = $1', [userId]);
        res.status(200).json({ success: true, message: 'Savings goal set successfully!', ...updatedRecord[0] });
    } catch (error) {
        logError('SAVINGS TARGET ERROR', error, { userId });
        res.status(500).json({ success: false, message: 'Server error setting savings goal.' });
    }
});

// PATCH Savings Amount
app.patch('/api/savings/current', authenticateToken, async (req, res) => {
    const { amount } = req.body; 
    const userId = req.user.id;
    logDebug('SAVINGS CURRENT USER', { userId });

    if (isNaN(Number(amount)) || Number(amount) === 0) return res.status(400).json({ success: false, message: 'Invalid amount provided.' });

    try {
        const check = await queryAsync('SELECT target FROM savings WHERE user_id = $1', [userId]);
        if (check.length === 0) return res.status(404).json({ success: false, message: 'Please set your savings target before updating.' });

        const sql = 'UPDATE savings SET saved_amount = GREATEST(0, saved_amount + $1), updated_at = NOW() WHERE user_id = $2';
        await queryAsync(sql, [amount, userId]);

        const updatedRecord = await queryAsync('SELECT target, months, saved_amount FROM savings WHERE user_id = $1', [userId]);
        res.status(200).json({ success: true, message: 'Savings amount updated!', ...updatedRecord[0] });
    } catch (error) {
        logError('SAVINGS CURRENT ERROR', error, { userId });
        res.status(500).json({ success: false, message: 'Server error updating saved amount.' });
    }
});

// GET DASHBOARD DATA
app.get('/api/dashboard/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const selectedMonth = req.query.month; 
    logDebug('DASHBOARD LOAD USER', { userId, month: selectedMonth });
    if (String(req.user.id) !== String(userId)) return res.status(403).json({ success: false, message: 'Unauthorized access to dashboard data.' });
    
    try {
        let monthYear = selectedMonth || new Date().toISOString().slice(0, 7);
        let [user] = await queryAsync('SELECT name FROM users WHERE id = $1', [userId]);
        const userName = user ? user.name : 'User';
        
        let [budget] = await queryAsync(
            `SELECT income, rent, food, internet, others, month_year 
             FROM budgets 
             WHERE user_id = $1 
             ORDER BY month_year DESC 
             LIMIT 1`, 
            [userId]
        );
        
        if (!budget) {
            return res.status(200).json({ 
                success: true, 
                name: userName, 
                month_year: monthYear, 
                budget: null, 
                expenses: [], 
            });
        }
        
        const expenses = await queryAsync(
            `SELECT id, category, amount, description, 
                    TO_CHAR(expense_date, 'YYYY-MM-DD') AS date 
             FROM expenses 
             WHERE user_id = $1 AND month_year = $2
             ORDER BY expense_date DESC, id DESC`,
            [userId, monthYear] 
        );
        
        res.status(200).json({
            success: true,
            name: userName, 
            month_year: monthYear, 
            budget,                 
            expenses,             
        });
        
    } catch (error) {
        logError('DASHBOARD LOAD ERROR', error, { userId, month: selectedMonth });
        res.status(500).json({ success: false, message: 'Server error loading dashboard data.' });
    }
});

// --- START SERVER ---
app.listen(port, () => {
    console.log(`SmartExpense backend running on port ${port}`);
    verifyDatabaseSchema();
});
