const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// Socket.IO setup dengan CORS
const io = socketIo(server, {
    cors: {
        origin: ["https://ts-traderstation.com", "http://localhost:3000", "http://127.0.0.1:5500"],
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling']
});

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: ["https://ts-traderstation.com", "http://localhost:3000", "http://127.0.0.1:5500"],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Strict rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many authentication attempts, please try again later.'
});

// Database Models
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String },
    balance: { type: Number, default: 0 },
    accountType: { type: String, enum: ['standard', 'premium'], default: 'standard' },
    isActive: { type: Boolean, default: true },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    referralCode: { type: String, unique: true },
    stats: {
        totalTrades: { type: Number, default: 0 },
        winTrades: { type: Number, default: 0 },
        loseTrades: { type: Number, default: 0 },
        winRate: { type: Number, default: 0 }
    },
    lastLoginAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symbol: { type: String, required: true },
    direction: { type: String, enum: ['buy', 'sell'], required: true },
    amount: { type: Number, required: true },
    profitPercentage: { type: Number, required: true },
    duration: { type: Number, required: true }, // in seconds
    entryPrice: { type: Number, required: true },
    exitPrice: { type: Number },
    status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
    result: { type: String, enum: ['win', 'lose'] },
    payout: { type: Number },
    priceChangePercent: { type: Number },
    forceResult: { type: String }, // admin override
    createdAt: { type: Date, default: Date.now },
    completedAt: { type: Date }
});

const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    method: { type: String, default: 'Bank Transfer' },
    bankFrom: { type: String },
    receipt: { type: String }, // URL atau text bukti transfer
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    adminNotes: { type: String },
    transferTime: { type: Date },
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
});

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    fee: { type: Number, required: true },
    finalAmount: { type: Number, required: true },
    bankAccount: {
        bankName: { type: String, required: true },
        accountNumber: { type: String, required: true },
        accountHolder: { type: String, required: true }
    },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'processed'], default: 'pending' },
    adminNotes: { type: String },
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
});

const priceSchema = new mongoose.Schema({
    symbol: { type: String, required: true, unique: true },
    price: { type: Number, required: true },
    change: { type: Number, default: 0 }, // percentage change
    lastUpdate: { type: Date, default: Date.now }
});

const activitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    details: { type: String },
    createdAt: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', userSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Price = mongoose.model('Price', priceSchema);
const Activity = mongoose.model('Activity', activitySchema);

// Helper functions
function generateReferralCode() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
}

async function logActivity(userId, action, details = '') {
    try {
        await Activity.create({ userId, action, details });
    } catch (error) {
        console.error('Error logging activity:', error);
    }
}

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user || !user.isActive) {
            return res.status(403).json({ error: 'User not found or inactive' });
        }
        
        req.userId = decoded.userId;
        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Admin middleware
const requireAdmin = async (req, res, next) => {
    try {
        if (req.user.email !== 'admin@tradestation.com') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Admin verification failed' });
    }
};

// Initialize default prices
async function initializePrices() {
    const defaultPrices = [
        { symbol: 'BTC', price: 45000, change: 2.45 },
        { symbol: 'ETH', price: 3200, change: -1.23 },
        { symbol: 'LTC', price: 180, change: 0.87 },
        { symbol: 'XRP', price: 0.65, change: 3.21 },
        { symbol: 'DOGE', price: 0.08, change: -2.15 },
        { symbol: 'TRX', price: 0.12, change: 1.45 },
        { symbol: 'ETC', price: 25, change: -0.65 },
        { symbol: 'NEO', price: 15, change: 2.87 }
    ];

    for (const priceData of defaultPrices) {
        await Price.findOneAndUpdate(
            { symbol: priceData.symbol },
            priceData,
            { upsert: true, new: true }
        );
    }
}

// Price update simulation
function simulatePriceUpdates() {
    setInterval(async () => {
        try {
            const prices = await Price.find();
            
            for (const price of prices) {
                // Random price change between -5% to +5%
                const changePercent = (Math.random() - 0.5) * 0.1; // -5% to +5%
                const newPrice = price.price * (1 + changePercent);
                const change = ((newPrice - price.price) / price.price) * 100;
                
                price.price = parseFloat(newPrice.toFixed(price.symbol === 'BTC' ? 0 : 6));
                price.change = parseFloat(change.toFixed(2));
                price.lastUpdate = new Date();
                
                await price.save();
                
                // Broadcast price update to all connected clients
                io.emit('priceUpdate', {
                    symbol: price.symbol,
                    price: price.price,
                    change: price.change
                });
            }
        } catch (error) {
            console.error('Error updating prices:', error);
        }
    }, 3000); // Update every 3 seconds
}

// Trade completion checker
function checkTradesToComplete() {
    setInterval(async () => {
        try {
            const now = new Date();
            const activeTrades = await Trade.find({ status: 'active' }).populate('userId');
            
            for (const trade of activeTrades) {
                const createdAt = new Date(trade.createdAt);
                const elapsedSeconds = Math.floor((now - createdAt) / 1000);
                
                if (elapsedSeconds >= trade.duration) {
                    // Get current price
                    const currentPrice = await Price.findOne({ symbol: trade.symbol });
                    
                    if (currentPrice) {
                        trade.exitPrice = currentPrice.price;
                        trade.status = 'completed';
                        trade.completedAt = now;
                        
                        // Calculate price change
                        const priceChangePercent = ((currentPrice.price - trade.entryPrice) / trade.entryPrice) * 100;
                        trade.priceChangePercent = priceChangePercent;
                        
                        // Determine result based on direction or force result
                        let result;
                        if (trade.forceResult) {
                            result = trade.forceResult;
                        } else {
                            if (trade.direction === 'buy') {
                                result = currentPrice.price > trade.entryPrice ? 'win' : 'lose';
                            } else {
                                result = currentPrice.price < trade.entryPrice ? 'win' : 'lose';
                            }
                        }
                        
                        trade.result = result;
                        
                        // Calculate payout
                        if (result === 'win') {
                            trade.payout = trade.amount + (trade.amount * trade.profitPercentage / 100);
                            trade.userId.balance += trade.payout;
                            trade.userId.totalProfit += (trade.payout - trade.amount);
                        } else {
                            trade.payout = 0;
                            trade.userId.totalLoss += trade.amount;
                        }
                        
                        // Update user stats
                        trade.userId.stats.totalTrades += 1;
                        if (result === 'win') {
                            trade.userId.stats.winTrades += 1;
                        } else {
                            trade.userId.stats.loseTrades += 1;
                        }
                        trade.userId.stats.winRate = (trade.userId.stats.winTrades / trade.userId.stats.totalTrades) * 100;
                        
                        await trade.save();
                        await trade.userId.save();
                        
                        // Log activity
                        await logActivity(trade.userId._id, 'TRADE_COMPLETED', `${trade.symbol} ${trade.direction} ${result}`);
                        
                        // Notify user via socket
                        io.to(trade.userId._id.toString()).emit('tradeCompleted', {
                            trade,
                            result,
                            payout: trade.payout,
                            newBalance: trade.userId.balance
                        });
                        
                        console.log(`✅ Trade completed: ${trade._id} - ${result}`);
                    }
                }
            }
        } catch (error) {
            console.error('Error checking trades:', error);
        }
    }, 1000); // Check every second
}

// Database connection check middleware
const checkDatabaseConnection = (req, res, next) => {
    if (global.dbConnected === false) {
        return res.status(503).json({ 
            error: 'Database temporarily unavailable',
            message: 'Please try again in a few moments'
        });
    }
    next();
};

// Root route
app.get('/', (req, res) => {
    res.json({
        message: 'TradeStation Backend API',
        version: '1.0.0',
        status: 'Running',
        endpoints: {
            health: '/api/health',
            register: 'POST /api/register',
            login: 'POST /api/login',
            prices: 'GET /api/prices',
            profile: 'GET /api/profile (auth required)',
            trading: 'POST /api/trade (auth required)',
            admin: '/api/admin/* (admin required)'
        },
        documentation: 'https://github.com/tradestation/api-docs',
        timestamp: new Date().toISOString()
    });
});

// API Routes

// Health check - moved to server startup section

// Auth Routes
app.post('/api/register', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        
        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Create user
        const user = new User({
            name,
            email,
            phone,
            password: hashedPassword,
            referralCode: generateReferralCode(),
            balance: 0 // Start with 0 balance
        });
        
        await user.save();
        
        // Log activity
        await logActivity(user._id, 'USER_REGISTER', `New user registered: ${email}`);
        
        // Generate token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        // Remove password from response
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.status(201).json({
            message: 'Registration successful',
            token,
            user: userResponse
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validation
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        if (!user.isActive) {
            return res.status(400).json({ error: 'Account is deactivated' });
        }
        
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        // Update last login
        user.lastLoginAt = new Date();
        await user.save();
        
        // Log activity
        await logActivity(user._id, 'USER_LOGIN', `User logged in: ${email}`);
        
        // Generate token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        // Remove password from response
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.json({
            message: 'Login successful',
            token,
            user: userResponse
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// User Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        res.json(user);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Failed to load profile' });
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { name, phone } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.userId,
            { name, phone },
            { new: true }
        ).select('-password');
        
        res.json(user);
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Price Routes
app.get('/api/prices', async (req, res) => {
    try {
        const prices = await Price.find().sort({ symbol: 1 });
        res.json(prices);
    } catch (error) {
        console.error('Prices error:', error);
        res.status(500).json({ error: 'Failed to load prices' });
    }
});

// Trading Routes
app.post('/api/trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, direction, amount, profitPercentage, duration } = req.body;
        
        // Validation
        if (!symbol || !direction || !amount || !profitPercentage || !duration) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (amount < 500000 || amount > 100000000) {
            return res.status(400).json({ error: 'Amount must be between Rp 500,000 and Rp 100,000,000' });
        }
        
        if (amount > req.user.balance) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        // Get current price
        const currentPrice = await Price.findOne({ symbol });
        if (!currentPrice) {
            return res.status(400).json({ error: 'Invalid symbol' });
        }
        
        // Deduct amount from user balance
        req.user.balance -= amount;
        await req.user.save();
        
        // Create trade
        const trade = new Trade({
            userId: req.userId,
            symbol,
            direction,
            amount,
            profitPercentage,
            duration,
            entryPrice: currentPrice.price
        });
        
        await trade.save();
        
        // Log activity
        await logActivity(req.userId, 'TRADE_CREATED', `${symbol} ${direction} ${amount}`);
        
        // Notify via socket
        io.to(req.userId.toString()).emit('tradeCreated', {
            trade,
            newBalance: req.user.balance
        });
        
        res.status(201).json({
            message: 'Trade created successfully',
            trade,
            newBalance: req.user.balance
        });
        
    } catch (error) {
        console.error('Trade error:', error);
        res.status(500).json({ error: 'Failed to create trade' });
    }
});

app.get('/api/trades', authenticateToken, async (req, res) => {
    try {
        const { limit = 50, status } = req.query;
        
        let query = { userId: req.userId };
        if (status) {
            query.status = status;
        }
        
        const trades = await Trade.find(query)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));
        
        res.json({ trades });
    } catch (error) {
        console.error('Trades error:', error);
        res.status(500).json({ error: 'Failed to load trades' });
    }
});

// Deposit Routes
app.post('/api/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount, bankFrom, receipt, transferTime } = req.body;
        
        if (!amount || amount < 50000) {
            return res.status(400).json({ error: 'Minimum deposit is Rp 50,000' });
        }
        
        const deposit = new Deposit({
            userId: req.userId,
            amount,
            bankFrom,
            receipt,
            transferTime: transferTime || new Date()
        });
        
        await deposit.save();
        
        // Log activity
        await logActivity(req.userId, 'DEPOSIT_REQUEST', `Deposit request: ${amount}`);
        
        res.status(201).json({
            message: 'Deposit request submitted successfully',
            deposit
        });
        
    } catch (error) {
        console.error('Deposit error:', error);
        res.status(500).json({ error: 'Failed to submit deposit' });
    }
});

app.get('/api/deposits', authenticateToken, async (req, res) => {
    try {
        const deposits = await Deposit.find({ userId: req.userId })
            .sort({ createdAt: -1 });
        
        res.json(deposits);
    } catch (error) {
        console.error('Deposits error:', error);
        res.status(500).json({ error: 'Failed to load deposits' });
    }
});

// Withdrawal Routes
app.post('/api/withdrawal', authenticateToken, async (req, res) => {
    try {
        const { amount, bankAccount } = req.body;
        
        if (!amount || amount < 100000) {
            return res.status(400).json({ error: 'Minimum withdrawal is Rp 100,000' });
        }
        
        if (amount > req.user.balance) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        // Calculate fee (1% with minimum Rp 6,500)
        const fee = Math.max(6500, amount * 0.01);
        const finalAmount = amount - fee;
        
        if (finalAmount <= 0) {
            return res.status(400).json({ error: 'Amount too small after fee deduction' });
        }
        
        // Deduct amount from user balance
        req.user.balance -= amount;
        await req.user.save();
        
        const withdrawal = new Withdrawal({
            userId: req.userId,
            amount,
            fee,
            finalAmount,
            bankAccount
        });
        
        await withdrawal.save();
        
        // Log activity
        await logActivity(req.userId, 'WITHDRAWAL_REQUEST', `Withdrawal request: ${amount}`);
        
        res.status(201).json({
            message: 'Withdrawal request submitted successfully',
            withdrawal,
            newBalance: req.user.balance
        });
        
    } catch (error) {
        console.error('Withdrawal error:', error);
        res.status(500).json({ error: 'Failed to submit withdrawal' });
    }
});

app.get('/api/withdrawals', authenticateToken, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.userId })
            .sort({ createdAt: -1 });
        
        res.json(withdrawals);
    } catch (error) {
        console.error('Withdrawals error:', error);
        res.status(500).json({ error: 'Failed to load withdrawals' });
    }
});

// Admin Routes
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        // Get statistics
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isActive: true });
        const totalTrades = await Trade.countDocuments();
        const activeTrades = await Trade.countDocuments({ status: 'active' });
        const totalDeposits = await Deposit.countDocuments({ status: 'approved' });
        const pendingDeposits = await Deposit.countDocuments({ status: 'pending' });
        const totalWithdrawals = await Withdrawal.countDocuments();
        const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
        
        // Calculate volumes
        const allTrades = await Trade.find({ status: 'completed' });
        const totalVolume = allTrades.reduce((sum, trade) => sum + trade.amount, 0);
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayTrades = await Trade.find({ 
            status: 'completed', 
            createdAt: { $gte: today } 
        });
        const todayVolume = todayTrades.reduce((sum, trade) => sum + trade.amount, 0);
        
        // Get recent activities
        const recentActivities = await Activity.find()
            .populate('userId', 'name')
            .sort({ createdAt: -1 })
            .limit(20);
        
        const stats = {
            users: { total: totalUsers, active: activeUsers },
            trades: { total: totalTrades, active: activeTrades },
            deposits: { total: totalDeposits, pending: pendingDeposits },
            withdrawals: { total: totalWithdrawals, pending: pendingWithdrawals },
            volume: { total: totalVolume, today: todayVolume }
        };
        
        res.json({ stats, recentActivities });
    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        res.json({ users });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Failed to load users' });
    }
});

app.get('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).select('-password');
        const trades = await Trade.find({ userId: req.params.userId }).sort({ createdAt: -1 });
        const deposits = await Deposit.find({ userId: req.params.userId }).sort({ createdAt: -1 });
        const withdrawals = await Withdrawal.find({ userId: req.params.userId }).sort({ createdAt: -1 });
        
        res.json({ user, trades, deposits, withdrawals });
    } catch (error) {
        console.error('Admin user detail error:', error);
        res.status(500).json({ error: 'Failed to load user details' });
    }
});

app.put('/api/admin/user/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { name, email, balance, phone, accountType, isActive } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.params.userId,
            { name, email, balance, phone, accountType, isActive },
            { new: true }
        ).select('-password');
        
        await logActivity(req.params.userId, 'ADMIN_UPDATE', `Profile updated by admin`);
        
        res.json({ user });
    } catch (error) {
        console.error('Admin user update error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.delete('/api/admin/user/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.userId, { isActive: false });
        await logActivity(req.params.userId, 'ADMIN_DEACTIVATE', `User deactivated by admin`);
        
        res.json({ message: 'User deactivated successfully' });
    } catch (error) {
        console.error('Admin user delete error:', error);
        res.status(500).json({ error: 'Failed to deactivate user' });
    }
});

app.get('/api/admin/trades', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        let query = {};
        if (status) query.status = status;
        
        const trades = await Trade.find(query)
            .populate('userId', 'name email')
            .sort({ createdAt: -1 });
        
        res.json({ trades });
    } catch (error) {
        console.error('Admin trades error:', error);
        res.status(500).json({ error: 'Failed to load trades' });
    }
});

app.put('/api/admin/trade/:tradeId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { forceResult } = req.body;
        
        const trade = await Trade.findByIdAndUpdate(
            req.params.tradeId,
            { forceResult },
            { new: true }
        );
        
        res.json({ trade });
    } catch (error) {
        console.error('Admin trade control error:', error);
        res.status(500).json({ error: 'Failed to control trade' });
    }
});

app.get('/api/admin/deposits', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        let query = {};
        if (status) query.status = status;
        
        const deposits = await Deposit.find(query)
            .populate('userId', 'name email')
            .sort({ createdAt: -1 });
        
        res.json({ deposits });
    } catch (error) {
        console.error('Admin deposits error:', error);
        res.status(500).json({ error: 'Failed to load deposits' });
    }
});

app.put('/api/admin/deposit/:depositId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, adminNotes } = req.body;
        
        const deposit = await Deposit.findById(req.params.depositId).populate('userId');
        
        if (!deposit) {
            return res.status(404).json({ error: 'Deposit not found' });
        }
        
        deposit.status = status;
        deposit.adminNotes = adminNotes;
        deposit.processedAt = new Date();
        
        if (status === 'approved') {
            // Add amount to user balance
            deposit.userId.balance += deposit.amount;
            await deposit.userId.save();
            
            // Notify user via socket
            io.to(deposit.userId._id.toString()).emit('depositApproved', {
                amount: deposit.amount,
                newBalance: deposit.userId.balance
            });
        }
        
        await deposit.save();
        await logActivity(deposit.userId._id, 'DEPOSIT_' + status.toUpperCase(), `Deposit ${status} by admin`);
        
        res.json({ deposit });
    } catch (error) {
        console.error('Admin deposit update error:', error);
        res.status(500).json({ error: 'Failed to update deposit' });
    }
});

app.get('/api/admin/withdrawals', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        let query = {};
        if (status) query.status = status;
        
        const withdrawals = await Withdrawal.find(query)
            .populate('userId', 'name email')
            .sort({ createdAt: -1 });
        
        res.json({ withdrawals });
    } catch (error) {
        console.error('Admin withdrawals error:', error);
        res.status(500).json({ error: 'Failed to load withdrawals' });
    }
});

app.put('/api/admin/withdrawal/:withdrawalId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, adminNotes } = req.body;
        
        const withdrawal = await Withdrawal.findById(req.params.withdrawalId).populate('userId');
        
        if (!withdrawal) {
            return res.status(404).json({ error: 'Withdrawal not found' });
        }
        
        withdrawal.status = status;
        withdrawal.adminNotes = adminNotes;
        withdrawal.processedAt = new Date();
        
        if (status === 'rejected') {
            // Refund amount to user balance
            withdrawal.userId.balance += withdrawal.amount;
            await withdrawal.userId.save();
        }
        
        await withdrawal.save();
        await logActivity(withdrawal.userId._id, 'WITHDRAWAL_' + status.toUpperCase(), `Withdrawal ${status} by admin`);
        
        res.json({ withdrawal });
    } catch (error) {
        console.error('Admin withdrawal update error:', error);
        res.status(500).json({ error: 'Failed to update withdrawal' });
    }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
    console.log('👤 User connected:', socket.id);
    
    socket.on('join', (userId) => {
        socket.join(userId);
        console.log(`👤 User ${userId} joined room`);
    });
    
    socket.on('subscribe_prices', () => {
        console.log('📊 User subscribed to price updates');
    });
    
    socket.on('disconnect', () => {
        console.log('👤 User disconnected:', socket.id);
    });
});

// Start server first, then connect to database
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', async () => {
    console.log(`
🚀 TradeStation Backend Server Started!
📍 Port: ${PORT}
🌍 Environment: ${process.env.NODE_ENV || 'development'}
📡 Socket.IO: Enabled
🛡️  Security: Enabled
⏰ Timestamp: ${new Date().toISOString()}
`);

    // Connect to database after server starts
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000, // 10 second timeout
            socketTimeoutMS: 45000, // 45 second timeout
        });
        
        console.log('✅ Connected to MongoDB');
        
        // Initialize default admin user
        const adminExists = await User.findOne({ email: 'admin@tradestation.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 12);
            const admin = new User({
                name: 'Administrator',
                email: 'admin@tradestation.com',
                password: hashedPassword,
                balance: 0,
                accountType: 'premium',
                referralCode: 'ADMIN001'
            });
            await admin.save();
            console.log('✅ Default admin user created');
        }
        
        // Initialize prices
        await initializePrices();
        console.log('✅ Prices initialized');
        
        // Start price updates and trade checking
        simulatePriceUpdates();
        checkTradesToComplete();
        console.log('✅ Background processes started');
        
    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        console.error('❌ Server will continue running but database features will be unavailable');
        
        // Don't exit, let server run for health checks
        // Add a flag to indicate DB is not available
        global.dbConnected = false;
    }
});

// Health check that works even without DB
app.get('/api/health', (req, res) => {
    const health = {
        status: 'OK', 
        message: 'TradeStation Backend is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: global.dbConnected !== false ? 'Connected' : 'Disconnected',
        port: PORT
    };
    
    res.json(health);
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Graceful shutdown (moved after server start)

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('💤 SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('✅ Process terminated');
        mongoose.connection.close();
    });
});

process.on('SIGINT', () => {
    console.log('💤 SIGINT received, shutting down gracefully');
    server.close(() => {
        console.log('✅ Process terminated');
        mongoose.connection.close();
    });
});

module.exports = app;
