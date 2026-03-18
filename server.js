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
app.use(express.json({ limit: '2mb' })); // Support handling compressed Base64 avatar uploads

// Database File (Simulating a DB with a local JSON file for zero-config persistence)
const DB_FILE = path.join(__dirname, 'users.json');
const ORDERS_FILE = path.join(__dirname, 'orders.json');

function initDB() {
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, JSON.stringify({ users: [] }, null, 2));
    }
    if (!fs.existsSync(ORDERS_FILE)) {
        fs.writeFileSync(ORDERS_FILE, JSON.stringify({ orders: [] }, null, 2));
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

function readOrders() {
    try {
        const data = fs.readFileSync(ORDERS_FILE, 'utf8');
        return JSON.parse(data).orders;
    } catch (err) {
        return [];
    }
}

function writeOrders(orders) {
    fs.writeFileSync(ORDERS_FILE, JSON.stringify({ orders }, null, 2));
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

// 4. View All Users (Demo Route)
app.get('/api/users', (req, res) => {
    try {
        const users = readUsers();
        const safeUsers = users.map(u => ({ id: u.id, username: u.username, createdAt: u.createdAt }));
        res.json({ total: safeUsers.length, users: safeUsers });
    } catch (err) {
        res.status(500).json({ error: '服务器内部错误' });
    }
});

// 4.5 Update Profile
app.put('/api/user/profile', (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: '未授权' });

        const decoded = jwt.verify(token, SECRET_KEY);
        const { nickname, avatar, birthday } = req.body;

        const users = readUsers();
        const userIndex = users.findIndex(u => u.id === decoded.id);
        
        if (userIndex === -1) return res.status(404).json({ error: '用户不存在' });

        users[userIndex].nickname = nickname || users[userIndex].nickname;
        users[userIndex].avatar = avatar || users[userIndex].avatar;
        users[userIndex].birthday = birthday || users[userIndex].birthday;

        writeUsers(users);

        res.json({ 
            message: '个人资料更新成功', 
            user: users[userIndex]
        });
    } catch (err) {
        res.status(401).json({ error: '登录失效，请重新登录' });
    }
});

// -------------------------
// Checkout & Payment Routes
// -------------------------

// 4.6 Get User Orders
app.get('/api/orders', (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: '未授权' });

        const decoded = jwt.verify(token, SECRET_KEY);
        const orders = readOrders();
        
        // Find orders belonging to user, sorted by newest first
        const userOrders = orders.filter(o => o.userId === decoded.id).reverse();
        res.json(userOrders);
    } catch (err) {
        res.status(401).json({ error: '无效令牌' });
    }
});

// 5. Create Order
app.post('/api/orders/create', (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: '微信支付前请先登录您的账号！' });

        const decoded = jwt.verify(token, SECRET_KEY);
        const { items, total } = req.body;

        if (!items || items.length === 0) {
            return res.status(400).json({ error: '购物车不能为空' });
        }

        const orders = readOrders();
        const newOrder = {
            id: 'ORD' + Date.now(),
            userId: decoded.id,
            username: decoded.username,
            items,
            total,
            status: 'PENDING_PAYMENT',
            createdAt: new Date().toISOString()
        };

        orders.push(newOrder);
        writeOrders(orders);

        res.status(201).json({ message: '订单创建成功', orderId: newOrder.id, total: newOrder.total });
    } catch (err) {
        console.error(err);
        res.status(401).json({ error: '登录状态失效，请重新登录' });
    }
});

// 6. Simulate WeChat Pay
app.post('/api/pay/wechat', (req, res) => {
    try {
        const { orderId } = req.body;
        const orders = readOrders();
        const orderIndex = orders.findIndex(o => o.id === orderId);

        if (orderIndex === -1) {
            return res.status(404).json({ error: '订单不存在或已过期' });
        }

        // Return a mock URL scheme representing the WeChat Pay portal
        const mockPayUrl = `weixin://wxpay/bizpayurl?pr=sandbox_${orderId}`;

        // Asynchronously update status to 'PAID' after 3.5 seconds to simulate user completing payment
        setTimeout(() => {
            const currentOrders = readOrders();
            const idx = currentOrders.findIndex(o => o.id === orderId);
            if (idx !== -1 && currentOrders[idx].status === 'PENDING_PAYMENT') {
                currentOrders[idx].status = 'PAID';
                writeOrders(currentOrders);
            }
        }, 3500);

        res.json({
            message: '成功调起支付参数',
            orderId,
            payUrl: mockPayUrl,
            status: orders[orderIndex].status
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: '服务器核心系统异常' });
    }
});

// 7. Check Order Status (Polling)
app.get('/api/orders/:id/status', (req, res) => {
    try {
        const orders = readOrders();
        const order = orders.find(o => o.id === req.params.id);
        if (!order) return res.status(404).json({ error: '未找到订单' });
        res.json({ status: order.status });
    } catch (err) {
        res.status(500).json({ error: '服务端状态同步异常' });
    }
});

app.listen(PORT, () => {
    console.log(`GourmetDrop API Server running on port ${PORT}`);
});
