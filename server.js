// server.js - SmartExpense Backend API (Final Version)

const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors'); // 🟢 FIX 1: ADDED: CORS module import at the top
// Removed: const { google } = require('googleapis'); 

const app = express();
const port = process.env.PORT || 8080;

// --- CONFIGURATION ---
const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_VERY_SECURE_SECRET_KEY';
const HASH_SALT_ROUNDS = 10;
const BASE_URL = 'https://gentle-dominion-474410-t3.as.r.appspot.com';
const TOKEN_EXPIRY_MINUTES = 30;

// --- Nodemailer Setup (Using OAuth2/Refresh Token from env) ---
// NOTE: Reverting to App Password setup as per the provided code.

// --- Middleware ---
app.use(express.json());

// 🟢 FIX 2: MOVED: CORS Configuration (MUST be placed before API endpoints)
const allowedOrigins = [
  'http://127.0.0.1:5500',
  'https://smartexpenseai.site',
  'https://www.smartexpenseai.site',
  'https://gentle-dominion-474410-t3.as.r.appspot.com'
];

// Added BASE_URL for self-referencing if needed. Note: Replace 'YOUR_FRONTEND_URL' with the actual deployed URL.

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: 'Content-Type,Authorization' // CRITICAL: Allows the Authorization header for tokens
}));
// ----------------------------

// --- Database Configuration ---
// Works both locally and on App Engine
const dbConfig = process.env.INSTANCE_CONNECTION_NAME ? {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    socketPath: `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`
} : {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    host: '127.0.0.1',
    port: 3306
};

const pool = mysql.createPool(dbConfig);
const queryAsync = (sql, values) => new Promise((resolve, reject) => {
    pool.query(sql, values, (err, results) => (err ? reject(err) : resolve(results)));
});

// --- API Endpoints ---

// REGISTER (NO CHANGES)
app.post('/api/register', async (req, res) => {
    const { name, email, pass } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(pass, HASH_SALT_ROUNDS);
        const sql = 'INSERT INTO final_project_db.users (name, email, password_hash) VALUES (?, ?, ?)';
        await queryAsync(sql, [name, email, hashedPassword]);
        res.status(201).json({ success: true, message: 'Registration successful.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY')
            return res.status(409).json({ success: false, message: 'Email already registered.' });
        console.error('Register Error:', error);
        res.status(500).json({ success: false, message: 'Server error during registration.' });
    }
});

// LOGIN (🟢 FIX 3A: Corrected to include userId)
app.post('/api/login', async (req, res) => {
    const { email, pass } = req.body;
    try {
        const sql = 'SELECT id, name, password_hash FROM final_project_db.users WHERE email = ?';
        const results = await queryAsync(sql, [email]);
        if (!results.length) return res.status(401).json({ success: false, message: 'Invalid email or password.' });

        const user = results[0];
        const match = await bcrypt.compare(pass, user.password_hash);
        if (!match) return res.status(401).json({ success: false, message: 'Invalid email or password.' });

        const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '1h' });
        
        // This is the correct, final response for a successful login
        res.status(200).json({ 
            success: true, 
            message: 'Login successful.', 
            token, 
            userId: user.id, // <-- CRITICAL ADDITION for dashboard
            userName: user.name 
        });
        
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

// FORGOT PASSWORD (🟢 FIX 3B: Removed misplaced login response)
app.post('/api/forgot_password', async (req, res) => {
    const { email } = req.body;
    try {
        const sql = 'SELECT id, name FROM final_project_db.users WHERE email = ?';
        const results = await queryAsync(sql, [email]);
        if (!results.length)
            return res.status(200).json({ success: true, message: 'If this email exists, reset link sent.' });

        const user = results[0];
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: `${TOKEN_EXPIRY_MINUTES}m` });
        
        // =================================================================
        // >>>>>>>>> CRITICAL FIX: Update URL to match front-end file and query parameter <<<
        // The front-end file is reset_password_form.html and expects ?token=...
        const resetUrl = `${BASE_URL}/reset_password_form.html?token=${token}`; 
        // =================================================================

        // Transporter now uses MAIL_USER and MAIL_PASS (matching app.yaml)
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.MAIL_USER, 
                pass: process.env.MAIL_PASS  
            }
        });
        // ----------------------------------------------------

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
            'INSERT INTO final_project_db.password_resets (user_id, token, created_at) VALUES (?, ?, NOW())',
            [user.id, token]
        );

        // This is the correct response for forgot password
        res.status(200).json({ success: true, message: 'If this email exists, reset link sent.' });
        
    } catch (error) {
        console.error('Forgot Password Error (APP PASSWORD FAILURE LIKELY):', error); 
        res.status(500).json({ success: false, message: 'Server error during password reset request.' });
    }
});

// RESET PASSWORD (NO CHANGES)
app.post('/api/reset_password', async (req, res) => {
    // FIX: Change variable names to match the frontend payload keys: newPassword and confirmPassword
    const { token, newPassword, confirmPassword } = req.body; 

    // Check if passwords match using the CORRECT variables
    if (newPassword !== confirmPassword) return res.status(400).json({ success: false, message: 'Passwords do not match.' });

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        const userId = payload.id;

        const tokenSQL = 'SELECT * FROM final_project_db.password_resets WHERE token = ? AND created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)';
        const tokenResults = await queryAsync(tokenSQL, [token, TOKEN_EXPIRY_MINUTES]);
        if (!tokenResults.length) return res.status(401).json({ success: false, message: 'Reset link invalid or expired.' });

        // PASS THE CORRECT VARIABLE (newPassword) to bcrypt.hash()
        const hashedPassword = await bcrypt.hash(newPassword, HASH_SALT_ROUNDS); 
        await queryAsync('UPDATE final_project_db.users SET password_hash = ? WHERE id = ?', [hashedPassword, userId]);
        await queryAsync('DELETE FROM final_project_db.password_resets WHERE token = ?', [token]);

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
    // Format is 'Bearer TOKEN'
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (token == null) return res.status(401).json({ success: false, message: 'Access Denied: No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            // Token is invalid or expired
            return res.status(403).json({ success: false, message: 'Access Denied: Invalid or expired token.' });
        }
        // Attach the user info (id, email) to the request
        req.user = user; 
        next();
    });
};

// --- Budget Setup API Endpoints (Add these two routes) ---

// GET Budget Data: /api/budget/:userId
app.get('/api/budget/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    
    // Authorization check: Ensure the requested userId matches the token's user ID
    if (String(req.user.id) !== userId) {
        return res.status(403).json({ success: false, message: 'Unauthorized access to user data.' });
    }

    try {
        const sql = 'SELECT income, rent, food, internet, others FROM final_project_db.budgets WHERE user_id = ?';
        const results = await queryAsync(sql, [userId]);

        if (results.length > 0) {
            res.status(200).json({ success: true, budget: results[0] });
        } else {
            // Return empty data structure if no budget exists (client will show empty fields)
            res.status(200).json({ success: true, budget: null, message: 'No budget setup found.' });
        }
    } catch (error) {
        console.error('Error loading budget:', error);
        res.status(500).json({ success: false, message: 'Server error loading budget data.' });
    }
});

// POST/PUT Budget Data: /api/budget/save
app.post('/api/budget/save', authenticateToken, async (req, res) => {
    const { user_id, income, rent, food, internet, others } = req.body;
    const monthYear = new Date().toISOString().slice(0, 7); // 'YYYY-MM'

    // Authorization check: Ensure the user_id in the body matches the token's user ID
    if (String(req.user.id) !== String(user_id)) {
        return res.status(403).json({ success: false, message: 'Unauthorized attempt to save data.' });
    }
    
    try {
        // Use INSERT...ON DUPLICATE KEY UPDATE for upsert functionality
        const sql = `
    INSERT INTO final_project_db.budgets (user_id, income, rent, food, internet, others, month_year)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE 
        income=VALUES(income), 
        rent=VALUES(rent), 
        food=VALUES(food), 
        internet=VALUES(internet), 
        others=VALUES(others),
        month_year=VALUES(month_year);
`;
    const values = [user_id, income, rent, food, internet, others, monthYear];
    await queryAsync(sql, values);
        
        res.status(200).json({ success: true, message: 'Budget setup saved successfully!' });
    } catch (error) {
        console.error('Error saving budget:', error);
        res.status(500).json({ success: false, message: 'Server error saving budget data.' });
    }
});

// --- Daily Expenses API Endpoints (Matched to expenses.html) ---

// 1. POST to save a new expense: /api/expense/add
app.post('/api/expense/add', authenticateToken, async (req, res) => {
    const { user_id, amount, category, desc, date } = req.body;
    const monthYear = date ? date.slice(0, 7) : new Date().toISOString().slice(0, 7);

    if (String(req.user.id) !== String(user_id)) {
        return res.status(403).json({ success: false, message: 'Unauthorized attempt to save expense.' });
    }
    
    try {
        // In server.js, inside app.post('/api/expense/add', ...)
const sql = `
INSERT INTO final_project_db.expenses (user_id, amount, category, description, expense_date, month_year)
VALUES (?, ?, ?, ?, ?, ?)
`;
const values = [user_id, amount, category, desc, date, monthYear];

        
        const cleanedSql = sql.trim(); 

        await queryAsync(cleanedSql, values);
        
        // Return the last inserted ID to the client (for the 'delete' function reference)
        const lastIdResult = await queryAsync('SELECT LAST_INSERT_ID() as id');
        
        res.status(201).json({ success: true, message: 'Expense saved successfully!', expenseId: lastIdResult[0].id });
    } catch (error) {
        console.error('Error saving expense:', error);
        res.status(500).json({ success: false, message: 'Server error saving expense data.' });
    }
});
// 2. GET list of expenses: /api/expense/:userId (FIXED RESERVED KEYWORD)
app.get('/api/expense/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const month = req.query.month;

    if (String(req.user.id) !== userId) {
        return res.status(403).json({ success: false, message: 'Unauthorized access to expense data.' });
    }

    try {
        let sql = `
    SELECT id, amount, category, description AS \`desc\`, 
           DATE_FORMAT(expense_date, '%m/%d/%Y') AS date 
    FROM final_project_db.expenses 
    WHERE user_id = ?
`;
const params = [userId];

// Add filtering by month if query param is provided
if (month) {
    sql += ' AND month_year = ?';
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

app.get('/api/months', authenticateToken, async (req, res) => {
    const userId = req.user.id; // Use ID from token

    try {
        const sql = `
            SELECT DISTINCT month_year 
            FROM final_project_db.expenses 
            WHERE user_id = ? 
            ORDER BY month_year DESC;
        `;
        const results = await queryAsync(sql, [userId]);

        // Ensure results is an array before mapping
        if (!Array.isArray(results)) {
             console.warn('DB did not return an array for months.', results);
             return res.status(200).json([]); // Return empty array safely
        }

        // Return the clean array of objects: [{month_year: 'YYYY-MM'}, ...]
        res.status(200).json(results.map(r => ({ month_year: r.month_year })));
        
    } catch (error) {
        // This is the CRITICAL catch that reports the DB/Query error.
        console.error('CRITICAL: Error fetching months (Status 500 origin):', error.message); 
        res.status(500).json({ success: false, message: 'Server error fetching months. Check DB connection/table structure.' });
    }
}); // 🚨 CRITICAL: Make sure these two lines are present: close the route function and close the app.get call!

// ... The rest of your server.js file continues here ...

// 3. POST to delete an expense: /api/expense/delete (FIXED TO USE UNIQUE ID)
app.post('/api/expense/delete', authenticateToken, async (req, res) => {
    // We now expect the unique expense_id from the client
    const { user_id, expense_id } = req.body; // <-- Expecting expense_id, not date/amount/category

    if (String(req.user.id) !== String(user_id)) {
        return res.status(403).json({ success: false, message: 'Unauthorized attempt to delete expense.' });
    }
    
    try {
        const sql = `
            DELETE FROM final_project_db.expenses 
            WHERE user_id = ? 
              AND id = ?  
            LIMIT 1;
        `;
        
        const result = await queryAsync(sql.trim(), [user_id, expense_id]);

        if (result.affectedRows === 0) {
            // It might be 0 if the user_id/expense_id combination didn't exist
            return res.status(404).json({ success: false, message: 'Expense not found or unauthorized to delete.' });
        }
        
        res.status(200).json({ success: true, message: 'Expense deleted successfully.' });
    } catch (error) {
        console.error('Error deleting expense:', error);
        res.status(500).json({ success: false, message: 'Server error deleting expense.' });
    }
});
// --- Savings Plan API Endpoints (NEW ROUTES) ---

// 1. GET Savings Data: /api/savings (Load Savings Data)
// We'll use the user ID from the token, so we don't need it in the URL
app.get('/api/savings', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    
    try {
        const sql = 'SELECT target, months, saved_amount FROM final_project_db.savings WHERE user_id = ?';
        const results = await queryAsync(sql, [userId]);

        if (results.length > 0) {
            // Return the existing data
            res.status(200).json({ success: true, ...results[0] });
        } else {
            // Return defaults if no record exists (client will show empty fields)
            res.status(200).json({ success: true, target: 0, months: 1, saved_amount: 0 });
        }
    } catch (error) {
        console.error('Error loading savings plan:', error);
        res.status(500).json({ success: false, message: 'Server error loading savings data.' });
    }
});

// 2. POST Savings Target: /api/savings/target (Set/Update Goal)
app.post('/api/savings/target', authenticateToken, async (req, res) => {
    const { target, months } = req.body;
    const userId = req.user.id;
    
    try {
        // INSERT...ON DUPLICATE KEY UPDATE handles both creating a new record 
        // and updating an existing one (upsert).
        const sql = `
            INSERT INTO final_project_db.savings (user_id, target, months)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE 
                target = VALUES(target), 
                months = VALUES(months);
        `;
        await queryAsync(sql, [userId, target, months]);
        
        // Fetch the updated full record to send back to the client
        const updatedRecord = await queryAsync('SELECT target, months, saved_amount FROM final_project_db.savings WHERE user_id = ?', [userId]);
        
        res.status(200).json({ success: true, message: 'Savings goal set successfully!', ...updatedRecord[0] });
    } catch (error) {
        console.error('Error setting savings target:', error);
        res.status(500).json({ success: false, message: 'Server error setting savings goal.' });
    }
});

// 3. PATCH Savings Amount: /api/savings/current (Update Current Savings)
app.patch('/api/savings/current', authenticateToken, async (req, res) => {
    const { amount } = req.body; // 'amount' is the addition/deduction
    const userId = req.user.id;

    if (isNaN(Number(amount)) || Number(amount) === 0) {
        return res.status(400).json({ success: false, message: 'Invalid amount provided.' });
    }

    try {
        // Check if the savings target exists first
        const check = await queryAsync('SELECT target FROM final_project_db.savings WHERE user_id = ?', [userId]);
        if (check.length === 0) {
            return res.status(404).json({ success: false, message: 'Please set your savings target before updating the saved amount.' });
        }

        // Use a SQL expression to update the saved_amount, ensuring it never drops below zero
        const sql = `
            UPDATE final_project_db.savings
            SET saved_amount = GREATEST(0, saved_amount + ?)
            WHERE user_id = ?;
        `;
        await queryAsync(sql, [amount, userId]);

        // Fetch the updated full record to send back to the client
        const updatedRecord = await queryAsync('SELECT target, months, saved_amount FROM final_project_db.savings WHERE user_id = ?', [userId]);
        
        res.status(200).json({ success: true, message: 'Savings amount updated!', ...updatedRecord[0] });
    } catch (error) {
        console.error('Error updating saved amount:', error);
        res.status(500).json({ success: false, message: 'Server error updating saved amount.' });
    }
});

// --- DASHBOARD DATA API 
app.get('/api/dashboard/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const selectedMonth = req.query.month; // optional ?month=YYYY-MM
    if (String(req.user.id) !== String(userId)) {
        return res.status(403).json({ success: false, message: 'Unauthorized access to dashboard data.' });
    }
    try {
        let monthYear = selectedMonth || new Date().toISOString().slice(0, 7);
        let [user] = await queryAsync('SELECT name FROM final_project_db.users WHERE id = ?', [userId]);
        const userName = user ? user.name : 'User';
        let [budget] = await queryAsync(
            `SELECT income, rent, food, internet, others, month_year 
             FROM final_project_db.budgets 
             WHERE user_id = ? 
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
            `SELECT id, category, amount, description AS \`desc\`, 
                     DATE_FORMAT(expense_date, '%Y-%m-%d') AS date 
             FROM final_project_db.expenses 
             WHERE user_id = ? AND month_year = ?
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