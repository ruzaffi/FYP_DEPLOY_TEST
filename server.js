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
const BASE_URL = process.env.BASE_URL || 'https://gentle-dominion-474410-t3.as.r.appspot.com';
const TOKEN_EXPIRY_MINUTES = 30;

// --- Middleware ---
app.use(express.json());

// 🚀 Serve static frontend assets dynamically from the public folder
app.use(express.static(path.join(__dirname, 'public')));

const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'https://smartexpenseai.site',
  'https://www.smartexpenseai.site',
  'https://gentle-dominion-474410-t3.as.r.appspot.com'
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

// --- Database Configuration ---
const dbConnectionString = process.env.DATABASE_URL || 'postgresql://postgres:root@127.0.0.1:5432/postgres';

const pool = new Pool({
    connectionString: dbConnectionString,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false 
});

const queryAsync = async (text, params) => {
    const res = await pool.query(text, params);
    return res.rows;
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
        res.status(201).json({ success: true, message: 'Registration successful.' });
    } catch (error) {
        if (error.code === '23505') 
            return res.status(409).json({ success: false, message: 'Email already registered.' });
        console.error('Register Error:', error);
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
        console.error('Login Error:', error);
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
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: `${TOKEN_EXPIRY_MINMinutes}m` });
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
        console.error('Forgot Password Error:', error); 
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

        const tokenSQL = "SELECT * FROM password_resets WHERE token = $1 AND created_at >= NOW() - INTERVAL '1 minute' * $2";
        const tokenResults = await queryAsync(tokenSQL, [token, TOKEN_EXPIRY_MINUTES]);
        if (!tokenResults.length) return res.status(401).json({ success: false, message: 'Reset link invalid or expired.' });

        const hashedPassword = await bcrypt.hash(newPassword, HASH_SALT_ROUNDS); 
        await queryAsync('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, userId]);
        await queryAsync('DELETE FROM password_resets WHERE token = $1', [token]);

        res.status(200).json({ success: true, message: 'Password updated successfully.' });
    } catch (error) {
        if (error.name === 'TokenExpiredError') return res.status(401).json({ success: false, message: 'Reset link expired.' });
        if (error.name === 'JsonWebTokenError') return res.status(401).json({ success: false, message: 'Invalid reset link.' });
        console.error('Reset Password Error:', error);
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
        next();
    });
};

// GET Budget Data
app.get('/api/budget/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    if (String(req.user.id) !== userId) return res.status(403).json({ success: false, message: 'Unauthorized access to user data.' });

    try {
        const sql = 'SELECT income, rent, food, internet, others FROM budgets WHERE user_id = $1';
        const results = await queryAsync(sql, [userId]);

        if (results.length > 0) {
            res.status(200).json({ success: true, budget: results[0] });
        } else {
            res.status(200).json({ success: true, budget: null, message: 'No budget setup found.' });
        }
    } catch (error) {
        console.error('Error loading budget:', error);
        res.status(500).json({ success: false, message: 'Server error loading budget data.' });
    }
});

// POST/PUT Budget Data
app.post('/api/budget/save', authenticateToken, async (req, res) => {
    const { user_id, income, rent, food, internet, others } = req.body;
    const monthYear = new Date().toISOString().slice(0, 7);

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
        console.error('Error saving budget:', error);
        res.status(500).json({ success: false, message: 'Server error saving budget data.' });
    }
});

// POST save a new expense
app.post('/api/expense/add', authenticateToken, async (req, res) => {
    const { user_id, amount, category, desc, date } = req.body;
    const monthYear = date ? date.slice(0, 7) : new Date().toISOString().slice(0, 7);

    if (String(req.user.id) !== String(user_id)) return res.status(403).json({ success: false, message: 'Unauthorized attempt to save expense.' });
    
    try {
        const sql = `
            INSERT INTO expenses (user_id, amount, category, description, expense_date, month_year)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING id;
        `;
        const values = [user_id, amount, category, desc, date, monthYear];
        const results = await queryAsync(sql, values);
        
        res.status(201).json({ success: true, message: 'Expense saved successfully!', expenseId: results[0].id });
    } catch (error) {
        console.error('Error saving expense:', error);
        res.status(500).json({ success: false, message: 'Server error saving expense data.' });
    }
});

// GET list of expenses
app.get('/api/expense/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const month = req.query.month;

    if (String(req.user.id) !== userId) return res.status(403).json({ success: false, message: 'Unauthorized access to expense data.' });

    try {
        let sql = `
            SELECT id, amount, category, description AS "desc", 
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
        console.error('Error loading expenses:', error);
        res.status(500).json({ success: false, message: 'Server error loading expenses data.' });
    }
});

// GET Months
app.get('/api/months', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const sql = 'SELECT DISTINCT month_year FROM expenses WHERE user_id = $1 ORDER BY month_year DESC';
        const results = await queryAsync(sql, [userId]);
        res.status(200).json(results.map(r => ({ month_year: r.month_year })));
    } catch (error) {
        console.error('Error fetching months:', error.message); 
        res.status(500).json({ success: false, message: 'Server error fetching months.' });
    }
});

// POST Delete an expense
app.post('/api/expense/delete', authenticateToken, async (req, res) => {
    const { user_id, expense_id } = req.body;

    if (String(req.user.id) !== String(user_id)) return res.status(403).json({ success: false, message: 'Unauthorized attempt to delete expense.' });
    
    try {
        const sql = 'DELETE FROM expenses WHERE user_id = $1 AND id = $2';
        const resObj = await pool.query(sql, [user_id, expense_id]);

        if (resObj.rowCount === 0) { 
            return res.status(404).json({ success: false, message: 'Expense not found or unauthorized.' });
        }
        res.status(200).json({ success: true, message: 'Expense deleted successfully.' });
    } catch (error) {
        console.error('Error deleting expense:', error);
        res.status(500).json({ success: false, message: 'Server error deleting expense.' });
    }
});

// GET Savings Plan Data
app.get('/api/savings', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const sql = 'SELECT target, months, saved_amount FROM savings WHERE user_id = $1';
        const results = await queryAsync(sql, [userId]);

        if (results.length > 0) {
            res.status(200).json({ success: true, ...results[0] });
        } else {
            res.status(200).json({ success: true, target: 0, months: 1, saved_amount: 0 });
        }
    } catch (error) {
        console.error('Error loading savings plan:', error);
        res.status(500).json({ success: false, message: 'Server error loading savings data.' });
    }
});

// POST Savings Target
app.post('/api/savings/target', authenticateToken, async (req, res) => {
    const { target, months } = req.body;
    const userId = req.user.id;
    
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
        console.error('Error setting savings target:', error);
        res.status(500).json({ success: false, message: 'Server error setting savings goal.' });
    }
});

// PATCH Savings Amount
app.patch('/api/savings/current', authenticateToken, async (req, res) => {
    const { amount } = req.body; 
    const userId = req.user.id;

    if (isNaN(Number(amount)) || Number(amount) === 0) return res.status(400).json({ success: false, message: 'Invalid amount provided.' });

    try {
        const check = await queryAsync('SELECT target FROM savings WHERE user_id = $1', [userId]);
        if (check.length === 0) return res.status(404).json({ success: false, message: 'Please set your savings target before updating.' });

        const sql = 'UPDATE savings SET saved_amount = GREATEST(0, saved_amount + $1), updated_at = NOW() WHERE user_id = $2';
        await queryAsync(sql, [amount, userId]);

        const updatedRecord = await queryAsync('SELECT target, months, saved_amount FROM savings WHERE user_id = $1', [userId]);
        res.status(200).json({ success: true, message: 'Savings amount updated!', ...updatedRecord[0] });
    } catch (error) {
        console.error('Error updating saved amount:', error);
        res.status(500).json({ success: false, message: 'Server error updating saved amount.' });
    }
});

// GET DASHBOARD DATA
app.get('/api/dashboard/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const selectedMonth = req.query.month; 
    if (String(req.user.id) !== String(userId)) return res.status(403).json({ success: false, message: 'Unauthorized access to dashboard data.' });
    
    try {
        let monthYear = selectedMonth || new Date().toISOString().slice(0, 7);
        let [user] = await queryAsync('SELECT name FROM users WHERE id = $1', [userId]);
        const userName = user ? user.name : 'User';
        
        let [budget] = await queryAsync(
            `SELECT income, rent, food, internet, others, month_year 
             FROM budgets 
             WHERE user_id = $1 
             ORDER BY month_year DESC, created_at DESC 
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
            `SELECT id, category, amount, description AS "desc", 
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
        console.error('CRITICAL SERVER ERROR loading dashboard data:', error.message);
        res.status(500).json({ success: false, message: 'Server error loading dashboard data.' });
    }
});

// --- START SERVER ---
app.listen(port, () => console.log(`✅ SmartExpense backend running on port ${port}`));