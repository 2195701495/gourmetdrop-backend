const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'gourmetdrop_super_secret_key_produce';

// Middleware
app.use(cors());
app.use(express.json());

// Database File (Simulating a DB with a local JSON file for zero-config persistence)
const DB_FILE = path.join(__dirname, 'users.json');

function initDB() {
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, JSON.stringify({ users: [] }, null, 2));
    }
}
initDB();

function readUsers() {
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data).users;
    } catch (err) {
        return [];
    }
}

function writeUsers(users) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users }, null, 2));
}

// -------------------------
// Authentication Routes
// -------------------------

// 1. Register API
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: '请提供用户名和密码！' });
        }

        const users = readUsers();
        
        if (users.find(u => u.username === username)) {
            return res.status(400).json({ error: '用户名已存在！' });
        }

        // Hash the password securely
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = {
            id: Date.now().toString(),
            username,
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        writeUsers(users);

        res.status(201).json({ message: '注册成功，请使用新账号登录' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: '服务器内部错误' });
    }
});

// 2. Login API
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const users = readUsers();
        const user = users.find(u => u.username === username);
        
        if (!user) {
            return res.status(400).json({ error: '用户名或密码错误' });
        }

        // Compare password with hashed DB entry
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: '用户名或密码错误' });
        }

        // Generate JWT Token
        const payload = {
            id: user.id,
            username: user.username
        };

        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '7d' }); // Valid for 7 days

        res.json({
            message: '登录成功',
            token,
            user: payload
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: '服务器内部错误' });
    }
});

// 3. Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'Backend is running' });
});

app.listen(PORT, () => {
    console.log(`GourmetDrop API Server running on port ${PORT}`);
});
