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

console.log('🚀 Starting TradeStation Backend...');

// ========================================
// 🔧 OPTIMIZED CORS CONFIGURATION
// ========================================

const allowedOrigins = [
    'https://ts-traderstation.com',
    'https://www.ts-traderstation.com',
    'https://tstradestation-frontend.vercel.app',
    'https://tstradestation-admin.vercel.app',
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:5173',
    'http://localhost:8080'
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        if (origin.startsWith('http://localhost:') || origin.includes('vercel.app')) {
            return callback(null, true);
        }
        if (process.env.NODE_ENV === 'development') return callback(null, true);
        return callback(null, true); // Allow all for compatibility
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
};

app.use(cors(corsOptions));

// Socket.IO setup
const io = socketIo(server, {
    cors: {
        origin: function(origin, callback) {
            return callback(null, true);
        },
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling']
});

// ========================================
// 🛡️ MIDDLEWARE SETUP
// ========================================

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// Simplified rate limiting
const createLimiter = (windowMs, max) => rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    skip: () => process.env.NODE_ENV === 'development'
});

const generalLimiter = createLimiter(15 * 60 * 1000, 1000);
const authLimiter = createLimiter(15 * 60 * 1000, 50);

app.use('/api/', generalLimiter);

// Simplified request logging
app.use((req, res, next) => {
    if (req.path !== '/api/health') {
        console.log(`${req.method} ${req.path}`);
    }
    next();
});

// ========================================
// 📊 DATABASE MODELS
// ========================================

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, minlength: 2, maxlength: 50 },
    email: { 
        type: String, 
        trim: true, 
        lowercase: true, 
        sparse: true,
        validate: {
            validator: function(email) {
                return !email || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
            }
        }
    },
    phone: { 
        type: String, 
        trim: true, 
        sparse: true,
        validate: {
            validator: function(phone) {
                return !phone || /^(\+?62|0)[0-9]{9,13}$/.test(phone.replace(/[\s\-\(\)]/g, ''));
            }
        }
    },
    password: { type: String, required: true, minlength: 6 },
    balance: { type: Number, default: 0, min: 0 },
    accountType: { type: String, enum: ['standard', 'premium'], default: 'standard' },
    isActive: { type: Boolean, default: true },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    referralCode: { type: String, unique: true },
    
    bankData: {
        bankName: { type: String, trim: true },
        accountNumber: { type: String, trim: true },
        accountHolder: { type: String, trim: true }
    },
    
    adminSettings: {
        forceWin: { type: Boolean, default: false },
        forceWinRate: { type: Number, default: 0, min: 0, max: 100 },
        profitCollapse: { type: String, enum: ['profit', 'collapse', 'normal'], default: 'normal' },
        profitPercentage: { type: Number, default: 80, min: 20, max: 100 }
    },
    
    stats: {
        totalTrades: { type: Number, default: 0 },
        winTrades: { type: Number, default: 0 },
        loseTrades: { type: Number, default: 0 }
    },
    
    lastLoginAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Safe indexing
userSchema.index({ email: 1 }, { unique: true, sparse: true, partialFilterExpression: { email: { $exists: true, $ne: null } }});
userSchema.index({ phone: 1 }, { unique: true, sparse: true, partialFilterExpression: { phone: { $exists: true, $ne: null } }});

// Pre-save middleware
userSchema.pre('save', function(next) {
    if (!this.adminSettings) {
        this.adminSettings = { forceWin: false, forceWinRate: 0, profitCollapse: 'normal', profitPercentage: 80 };
    }
    if (!this.stats) {
        this.stats = { totalTrades: 0, winTrades: 0, loseTrades: 0 };
    }
    next();
});

const bankAccountSchema = new mongoose.Schema({
    bankName: { type: String, required: true, trim: true },
    accountNumber: { type: String, required: true, trim: true },
    accountHolder: { type: String, required: true, trim: true },
    isActive: { type: Boolean, default: true },
    note: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now }
});

const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symbol: { type: String, required: true, uppercase: true },
    direction: { type: String, enum: ['buy', 'sell'], required: true },
    amount: { type: Number, required: true, min: 500000, max: 100000000 },
    duration: { type: Number, required: true, min: 30, max: 300 },
    entryPrice: { type: Number, required: true, min: 0 },
    exitPrice: { type: Number, min: 0 },
    status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
    result: { type: String, enum: ['win', 'lose'] },
    payout: { type: Number, min: 0 },
    priceChangePercent: { type: Number },
    forceResult: { type: String, enum: ['win', 'lose'] },
    adminForced: { type: Boolean, default: false },
    profitPercentage: { type: Number, default: 80, min: 20, max: 100 },
    createdAt: { type: Date, default: Date.now },
    completedAt: { type: Date }
});

const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 500000 },
    method: { type: String, default: 'Bank Transfer' },
    bankFrom: { type: String, trim: true },
    receipt: { type: String },
    fileName: { type: String, trim: true },
    fileType: { type: String, trim: true },
    fileSize: { type: Number, min: 0 },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    adminNotes: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
});

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 100000 },
    fee: { type: Number, required: true, min: 0 },
    finalAmount: { type: Number, required: true, min: 0 },
    bankAccount: {
        bankName: { type: String, required: true, trim: true },
        accountNumber: { type: String, required: true, trim: true },
        accountHolder: { type: String, required: true, trim: true }
    },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'processed'], default: 'pending' },
    adminNotes: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
});

const priceSchema = new mongoose.Schema({
    symbol: { type: String, required: true, unique: true, uppercase: true },
    price: { type: Number, required: true, min: 0 },
    change: { type: Number, default: 0 },
    lastUpdate: { type: Date, default: Date.now }
});

const activitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true, trim: true },
    details: { type: String, trim: true },
    ip: { type: String, trim: true },
    userAgent: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', userSchema);
const BankAccount = mongoose.model('BankAccount', bankAccountSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Price = mongoose.model('Price', priceSchema);
const Activity = mongoose.model('Activity', activitySchema);

// ========================================
// 🛠️ HELPER FUNCTIONS
// ========================================

const formatCurrency = (amount) => {
    return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        minimumFractionDigits: 0,
        maximumFractionDigits: 0
    }).format(amount || 0);
};

const generateReferralCode = () => {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
};

const isValidEmail = (email) => {
    if (!email || typeof email !== 'string') return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
};

const isValidPhone = (phone) => {
    if (!phone || typeof phone !== 'string') return false;
    const cleanPhone = phone.replace(/[\s\-\(\)]/g, '');
    return /^(\+?62|0)[0-9]{9,13}$/.test(cleanPhone);
};

const sanitizePhone = (phone) => {
    if (!phone) return null;
    return phone.replace(/[\s\-\(\)]/g, '');
};

const logActivity = async (userId, action, details = '', req = null) => {
    try {
        const activityData = { userId, action: action.trim(), details: details.trim() };
        if (req) {
            activityData.ip = req.ip || req.connection.remoteAddress;
            activityData.userAgent = req.get('User-Agent');
        }
        await Activity.create(activityData);
    } catch (error) {
        console.error('Activity log error:', error.message);
    }
};

const sendUserNotification = (userId, type, data) => {
    try {
        if (!userId || !type) return;
        const userIdString = userId.toString();
        const notificationData = { ...data, timestamp: new Date().toISOString(), type };
        io.to(userIdString).emit(type, notificationData);
    } catch (error) {
        console.error('Notification error:', error.message);
    }
};

// ========================================
// 💰 SIMPLIFIED PRICE MANAGEMENT
// ========================================

let isInitialized = false;

const initializePrices = async () => {
    try {
        const defaultPrices = [
            { symbol: 'BTC', price: 45000 + (Math.random() * 10000), change: (Math.random() - 0.5) * 5 },
            { symbol: 'ETH', price: 3200 + (Math.random() * 500), change: (Math.random() - 0.5) * 5 },
            { symbol: 'LTC', price: 180 + (Math.random() * 20), change: (Math.random() - 0.5) * 5 },
            { symbol: 'XRP', price: 0.65 + (Math.random() * 0.1), change: (Math.random() - 0.5) * 5 },
            { symbol: 'DOGE', price: 0.08 + (Math.random() * 0.02), change: (Math.random() - 0.5) * 5 },
            { symbol: 'TRX', price: 0.12 + (Math.random() * 0.02), change: (Math.random() - 0.5) * 5 }
        ];

        for (const priceData of defaultPrices) {
            await Price.findOneAndUpdate(
                { symbol: priceData.symbol },
                { ...priceData, price: Math.max(0.001, priceData.price), lastUpdate: new Date() },
                { upsert: true, new: true }
            );
        }
        console.log('✅ Prices initialized');
    } catch (error) {
        console.error('Price init error:', error.message);
    }
};

// Optimized price updates - less frequent, smaller batches
const simulatePriceUpdates = () => {
    setInterval(async () => {
        if (!isInitialized) return;
        try {
            const prices = await Price.find().limit(6);
            for (const price of prices) {
                const volatility = 0.005; // Reduced volatility
                const changePercent = (Math.random() - 0.5) * volatility;
                const newPrice = Math.max(0.001, price.price * (1 + changePercent));
                const change = ((newPrice - price.price) / price.price) * 100;
                
                price.price = parseFloat(newPrice.toFixed(price.symbol === 'BTC' ? 0 : 6));
                price.change = parseFloat(change.toFixed(2));
                price.lastUpdate = new Date();
                
                await price.save();
                io.emit('priceUpdate', { symbol: price.symbol, price: price.price, change: price.change });
            }
        } catch (error) {
            console.error('Price update error:', error.message);
        }
    }, 5000); // Increased interval to 5 seconds
};

// ========================================
// 🎯 OPTIMIZED TRADE COMPLETION
// ========================================

const checkTradesToComplete = () => {
    setInterval(async () => {
        try {
            const now = new Date();
            const activeTrades = await Trade.find({ status: 'active' }).populate('userId').limit(50);
            
            for (const trade of activeTrades) {
                const elapsedSeconds = Math.floor((now - new Date(trade.createdAt)) / 1000);
                if (elapsedSeconds >= trade.duration) {
                    const currentPrice = await Price.findOne({ symbol: trade.symbol });
                    if (currentPrice && currentPrice.price > 0) {
                        await completeTradeLogic(trade, currentPrice, now);
                    }
                }
            }
        } catch (error) {
            console.error('Trade check error:', error.message);
        }
    }, 2000); // Check every 2 seconds
};

const completeTradeLogic = async (trade, currentPrice, now) => {
    try {
        const session = await mongoose.startSession();
        session.startTransaction();
        
        try {
            trade.exitPrice = currentPrice.price;
            trade.status = 'completed';
            trade.completedAt = now;
            
            const priceChangePercent = ((currentPrice.price - trade.entryPrice) / trade.entryPrice) * 100;
            trade.priceChangePercent = priceChangePercent;
            
            let result = determineTradeResult(trade, currentPrice);
            trade.result = result;
            
            const profitPercentage = Math.max(20, Math.min(100, 
                trade.profitPercentage || trade.userId.adminSettings?.profitPercentage || 80
            ));
            
            if (result === 'win') {
                const profitAmount = trade.amount * profitPercentage / 100;
                trade.payout = trade.amount + profitAmount;
                trade.userId.balance += trade.payout;
                trade.userId.totalProfit += profitAmount;
                trade.userId.stats.winTrades += 1;
            } else {
                trade.payout = 0;
                trade.userId.totalLoss += trade.amount;
                trade.userId.stats.loseTrades += 1;
            }
            
            trade.userId.stats.totalTrades += 1;
            
            await trade.save({ session });
            await trade.userId.save({ session });
            await session.commitTransaction();
            
            sendUserNotification(trade.userId._id, 'tradeCompleted', {
                trade: { _id: trade._id, symbol: trade.symbol, direction: trade.direction, 
                        amount: trade.amount, result: trade.result, payout: trade.payout },
                result, payout: trade.payout, newBalance: trade.userId.balance
            });
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
    } catch (error) {
        console.error('Trade completion error:', error.message);
    }
};

const determineTradeResult = (trade, currentPrice) => {
    if (trade.userId.adminSettings?.profitCollapse === 'profit') {
        trade.adminForced = true;
        return 'win';
    } else if (trade.userId.adminSettings?.profitCollapse === 'collapse') {
        trade.adminForced = true;
        return 'lose';
    } else if (trade.forceResult) {
        trade.adminForced = true;
        return trade.forceResult;
    } else if (trade.userId.adminSettings?.forceWin && trade.userId.adminSettings.forceWinRate > 0) {
        const winChance = Math.random() * 100;
        trade.adminForced = true;
        return winChance <= trade.userId.adminSettings.forceWinRate ? 'win' : 'lose';
    } else {
        return trade.direction === 'buy' ? 
            (currentPrice.price > trade.entryPrice ? 'win' : 'lose') :
            (currentPrice.price < trade.entryPrice ? 'win' : 'lose');
    }
};

// ========================================
// 🔐 MIDDLEWARE
// ========================================

const checkDatabaseConnection = (req, res, next) => {
    if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({ error: 'Database temporarily unavailable' });
    }
    next();
};

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

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

const requireAdmin = async (req, res, next) => {
    try {
        if (!req.user || req.user.email !== 'admin@tradestation.com') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Admin verification failed' });
    }
};

// ========================================
// 🌐 ROUTES
// ========================================

app.get('/', (req, res) => {
    res.json({
        message: 'TradeStation Backend API',
        version: '7.0.0',
        status: 'Running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

app.get('/api/health', (req, res) => {
    const health = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        database: {
            status: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
            readyState: mongoose.connection.readyState
        }
    };
    
    const statusCode = mongoose.connection.readyState === 1 ? 200 : 503;
    res.status(statusCode).json(health);
});

// Authentication Routes
app.post('/api/login', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { email, phone, password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password diperlukan' });
        }

        if (!email && !phone) {
            return res.status(400).json({ error: 'Email atau nomor HP diperlukan' });
        }
        
        let user = null;
        
        if (email && isValidEmail(email)) {
            user = await User.findOne({ email: email.toLowerCase().trim() });
        }
        
        if (!user && phone && isValidPhone(phone)) {
            user = await User.findOne({ phone: sanitizePhone(phone) });
        }
        
        if (!user) {
            return res.status(400).json({ error: 'Email/HP atau password salah' });
        }
        
        if (!user.isActive) {
            return res.status(400).json({ error: 'Akun dinonaktifkan' });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Email/HP atau password salah' });
        }
        
        user.lastLoginAt = new Date();
        await user.save();
        
        await logActivity(user._id, 'USER_LOGIN', `Login: ${email || phone}`, req);
        
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.json({ message: 'Login berhasil', token, user: userResponse });
        
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ error: 'Login gagal. Silakan coba lagi.' });
    }
});

app.post('/api/register', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        
        if (!name?.trim() || name.trim().length < 2) {
            return res.status(400).json({ error: 'Nama harus minimal 2 karakter' });
        }

        if (!password || password.length < 6) {
            return res.status(400).json({ error: 'Password harus minimal 6 karakter' });
        }

        if (!email && !phone) {
            return res.status(400).json({ error: 'Email atau nomor HP diperlukan' });
        }
        
        if (email && !isValidEmail(email)) {
            return res.status(400).json({ error: 'Format email tidak valid' });
        }
        
        if (phone && !isValidPhone(phone)) {
            return res.status(400).json({ error: 'Format nomor HP tidak valid' });
        }
        
        const existingQuery = [];
        if (email) existingQuery.push({ email: email.toLowerCase().trim() });
        if (phone) existingQuery.push({ phone: sanitizePhone(phone) });
        
        if (existingQuery.length > 0) {
            const existingUser = await User.findOne({ $or: existingQuery });
            if (existingUser) {
                if (existingUser.email === email?.toLowerCase().trim()) {
                    return res.status(400).json({ error: 'Email sudah terdaftar' });
                }
                if (existingUser.phone === sanitizePhone(phone)) {
                    return res.status(400).json({ error: 'Nomor HP sudah terdaftar' });
                }
            }
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        const userData = {
            name: name.trim(),
            password: hashedPassword,
            referralCode: generateReferralCode()
        };

        if (email) userData.email = email.toLowerCase().trim();
        if (phone) userData.phone = sanitizePhone(phone);
        
        const user = new User(userData);
        await user.save();
        
        await logActivity(user._id, 'USER_REGISTER', `New user: ${email || phone}`, req);
        
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.status(201).json({ message: 'Pendaftaran berhasil', token, user: userResponse });
        
    } catch (error) {
        console.error('Registration error:', error.message);
        
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            return res.status(400).json({ 
                error: field === 'email' ? 'Email sudah terdaftar' : 'Nomor HP sudah terdaftar' 
            });
        }
        
        res.status(500).json({ error: 'Pendaftaran gagal. Silakan coba lagi.' });
    }
});

// User Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load profile' });
    }
});

app.get('/api/profile/bank', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('bankData');
        res.json(user.bankData || {});
    } catch (error) {
        res.status(500).json({ error: 'Failed to load bank data' });
    }
});

app.put('/api/profile/bank', authenticateToken, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder } = req.body;
        
        if (!bankName?.trim() || !accountNumber?.trim() || !accountHolder?.trim()) {
            return res.status(400).json({ error: 'All bank data fields are required' });
        }
        
        const user = await User.findByIdAndUpdate(
            req.userId,
            { bankData: { bankName: bankName.trim(), accountNumber: accountNumber.trim(), accountHolder: accountHolder.trim() }},
            { new: true }
        );
        
        await logActivity(req.userId, 'BANK_DATA_UPDATE', `Bank: ${bankName.trim()}`, req);
        res.json(user.bankData);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update bank data' });
    }
});

// Trading Routes
app.get('/api/prices', async (req, res) => {
    try {
        const prices = await Price.find().sort({ symbol: 1 }).select('-__v');
        res.json(prices);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load prices' });
    }
});

app.post('/api/trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, direction, amount, duration } = req.body;
        
        if (!symbol || !direction || !amount || !duration) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (!['buy', 'sell'].includes(direction)) {
            return res.status(400).json({ error: 'Direction must be buy or sell' });
        }
        
        if (amount < 500000 || amount > 100000000) {
            return res.status(400).json({ error: 'Amount must be between Rp 500,000 and Rp 100,000,000' });
        }
        
        if (duration < 30 || duration > 300) {
            return res.status(400).json({ error: 'Duration must be between 30 and 300 seconds' });
        }
        
        if (amount > req.user.balance) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        const currentPrice = await Price.findOne({ symbol: symbol.toUpperCase() });
        if (!currentPrice || !currentPrice.price || currentPrice.price <= 0) {
            return res.status(400).json({ error: 'Invalid symbol or price not available' });
        }
        
        const profitPercentage = Math.max(20, Math.min(100, req.user.adminSettings?.profitPercentage || 80));
        
        const session = await mongoose.startSession();
        
        try {
            session.startTransaction();
            
            req.user.balance -= amount;
            await req.user.save({ session });
            
            const trade = new Trade({
                userId: req.userId,
                symbol: symbol.toUpperCase(),
                direction,
                amount,
                profitPercentage,
                duration,
                entryPrice: currentPrice.price
            });
            
            await trade.save({ session });
            await session.commitTransaction();
            
            await logActivity(req.userId, 'TRADE_CREATED', 
                `${symbol.toUpperCase()} ${direction.toUpperCase()} ${formatCurrency(amount)}`, req);
            
            sendUserNotification(req.userId, 'tradeCreated', {
                trade: { _id: trade._id, symbol: trade.symbol, direction: trade.direction, 
                        amount: trade.amount, duration: trade.duration, entryPrice: trade.entryPrice },
                newBalance: req.user.balance
            });
            
            res.status(201).json({
                message: 'Trade created successfully',
                trade: { _id: trade._id, symbol: trade.symbol, direction: trade.direction, 
                        amount: trade.amount, duration: trade.duration, entryPrice: trade.entryPrice, 
                        status: trade.status, createdAt: trade.createdAt },
                newBalance: req.user.balance
            });
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
        
    } catch (error) {
        console.error('Trade error:', error.message);
        res.status(500).json({ error: 'Failed to create trade' });
    }
});

app.get('/api/trades', authenticateToken, async (req, res) => {
    try {
        const { limit = 50, status } = req.query;
        
        let query = { userId: req.userId };
        if (status && ['active', 'completed', 'cancelled'].includes(status)) {
            query.status = status;
        }
        
        const trades = await Trade.find(query)
            .sort({ createdAt: -1 })
            .limit(Math.min(parseInt(limit), 100))
            .select('-__v');
        
        res.json({ trades });
    } catch (error) {
        res.status(500).json({ error: 'Failed to load trades' });
    }
});

// Financial Routes
app.get('/api/bank-accounts/active', async (req, res) => {
    try {
        const accounts = await BankAccount.find({ isActive: true })
            .select('bankName accountNumber accountHolder note')
            .sort({ createdAt: -1 });
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load bank accounts' });
    }
});

app.post('/api/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount, receipt, fileName, fileType, bankFrom } = req.body;
        
        if (!amount || amount < 500000) {
            return res.status(400).json({ error: 'Minimum deposit is Rp 500,000' });
        }
        
        if (!receipt) {
            return res.status(400).json({ error: 'Payment proof is required' });
        }
        
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        if (!allowedTypes.includes(fileType)) {
            return res.status(400).json({ error: 'Invalid file type' });
        }
        
        const sizeInBytes = (receipt.length * 3) / 4;
        if (sizeInBytes > 5 * 1024 * 1024) {
            return res.status(400).json({ error: 'File size too large. Maximum 5MB allowed.' });
        }
        
        const deposit = new Deposit({
            userId: req.userId,
            amount,
            bankFrom: bankFrom?.trim() || 'Not specified',
            receipt,
            fileName: fileName?.trim() || 'payment_proof',
            fileType,
            fileSize: sizeInBytes
        });
        
        await deposit.save();
        await logActivity(req.userId, 'DEPOSIT_REQUEST', `Deposit: ${formatCurrency(amount)}`, req);
        
        res.status(201).json({
            message: 'Deposit request submitted successfully',
            deposit: { _id: deposit._id, amount: deposit.amount, status: deposit.status, createdAt: deposit.createdAt }
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to submit deposit' });
    }
});

app.get('/api/deposits', authenticateToken, async (req, res) => {
    try {
        const deposits = await Deposit.find({ userId: req.userId })
            .sort({ createdAt: -1 })
            .select('-receipt')
            .limit(50);
        res.json(deposits);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load deposits' });
    }
});

app.post('/api/withdrawal', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;
        
        if (!amount || amount < 100000) {
            return res.status(400).json({ error: 'Minimum withdrawal is Rp 100,000' });
        }
        
        const user = await User.findById(req.userId);
        
        if (amount > user.balance) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        if (!user.bankData?.bankName) {
            return res.status(400).json({ error: 'Bank data required' });
        }
        
        const feePercentage = 0.01;
        const minimumFee = 6500;
        const fee = Math.max(minimumFee, amount * feePercentage);
        const finalAmount = amount - fee;
        
        if (finalAmount <= 0) {
            return res.status(400).json({ error: 'Amount too small after fees' });
        }
        
        const session = await mongoose.startSession();
        
        try {
            session.startTransaction();
            
            user.balance -= amount;
            await user.save({ session });
            
            const withdrawal = new Withdrawal({
                userId: req.userId,
                amount,
                fee,
                finalAmount,
                bankAccount: {
                    bankName: user.bankData.bankName,
                    accountNumber: user.bankData.accountNumber,
                    accountHolder: user.bankData.accountHolder
                }
            });
            
            await withdrawal.save({ session });
            await session.commitTransaction();
            
            await logActivity(req.userId, 'WITHDRAWAL_REQUEST', 
                `Withdrawal: ${formatCurrency(amount)} (net: ${formatCurrency(finalAmount)})`, req);
            
            res.status(201).json({
                message: 'Withdrawal request submitted successfully',
                withdrawal: { _id: withdrawal._id, amount: withdrawal.amount, fee: withdrawal.fee, 
                           finalAmount: withdrawal.finalAmount, status: withdrawal.status, 
                           createdAt: withdrawal.createdAt },
                newBalance: user.balance
            });
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to submit withdrawal' });
    }
});

app.get('/api/withdrawals', authenticateToken, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.userId })
            .sort({ createdAt: -1 })
            .limit(50);
        res.json(withdrawals);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load withdrawals' });
    }
});

// Chart Data Routes
app.get('/api/chart/:symbol/:timeframe', async (req, res) => {
    try {
        const { symbol, timeframe } = req.params;
        
        const validTimeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d'];
        if (!validTimeframes.includes(timeframe)) {
            return res.status(400).json({ error: 'Invalid timeframe' });
        }
        
        const priceData = await Price.findOne({ symbol: symbol.toUpperCase() });
        if (!priceData) {
            return res.status(404).json({ error: 'Symbol not found' });
        }
        
        const generateHistoricalData = (count = 100) => {
            const data = [];
            const now = Date.now();
            let price = priceData.price;
            
            for (let i = count; i >= 0; i--) {
                const time = Math.floor((now - (i * 60000)) / 1000);
                const volatility = 0.01;
                const changePercent = (Math.random() - 0.5) * volatility;
                const newPrice = Math.max(0.001, price * (1 + changePercent));
                
                const open = price;
                const close = newPrice;
                const spread = Math.abs(close - open);
                const high = Math.max(open, close) + (spread * Math.random() * 0.5);
                const low = Math.min(open, close) - (spread * Math.random() * 0.5);
                const volume = Math.floor(Math.random() * 1000000) + 100000;
                
                data.push({
                    time,
                    open: parseFloat(Math.max(0.001, open).toFixed(8)),
                    high: parseFloat(Math.max(0.001, high).toFixed(8)),
                    low: parseFloat(Math.max(0.001, low).toFixed(8)),
                    close: parseFloat(Math.max(0.001, close).toFixed(8)),
                    volume
                });
                
                price = newPrice;
            }
            
            return data.sort((a, b) => a.time - b.time);
        };
        
        const chartData = generateHistoricalData(100);
        
        res.json({
            symbol: symbol.toUpperCase(),
            timeframe,
            candlestick: chartData,
            count: chartData.length,
            currentPrice: priceData.price,
            lastUpdate: priceData.lastUpdate
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to load chart data' });
    }
});

// Admin Routes - Optimized
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const timeout = 10000; // 10 seconds
        
        const createTimeoutQuery = (query) => {
            return Promise.race([
                query,
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('Query timeout')), timeout)
                )
            ]);
        };
        
        const basicStats = await createTimeoutQuery(
            Promise.all([
                User.countDocuments(),
                User.countDocuments({ isActive: true }),
                Trade.countDocuments(),
                Trade.countDocuments({ status: 'active' }),
                Deposit.countDocuments({ status: 'pending' }),
                Withdrawal.countDocuments({ status: 'pending' })
            ])
        );
        
        const [totalUsers, activeUsers, totalTrades, activeTrades, pendingDeposits, pendingWithdrawals] = basicStats;
        
        let recentActivities = [];
        try {
            recentActivities = await createTimeoutQuery(
                Activity.find()
                    .populate('userId', 'name email phone')
                    .sort({ createdAt: -1 })
                    .limit(10)
                    .lean()
            );
        } catch (activityError) {
            console.warn('Activity loading failed:', activityError.message);
        }
        
        res.json({ 
            stats: {
                users: { total: totalUsers, active: activeUsers },
                trades: { total: totalTrades, active: activeTrades },
                deposits: { pending: pendingDeposits },
                withdrawals: { pending: pendingWithdrawals }
            },
            recentActivities: recentActivities || [],
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Dashboard error:', error.message);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find()
            .select('-password')
            .sort({ createdAt: -1 })
            .limit(100)
            .lean();
        
        res.json({ users, count: users.length });
    } catch (error) {
        res.status(500).json({ error: 'Failed to load users' });
    }
});

app.put('/api/admin/user/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = { ...req.body };
        delete updateData.password;
        
        if (updateData.balance !== undefined) {
            const balance = parseFloat(updateData.balance);
            if (isNaN(balance) || balance < 0) {
                return res.status(400).json({ error: 'Invalid balance' });
            }
            updateData.balance = balance;
        }
        
        const user = await User.findByIdAndUpdate(id, updateData, { new: true, runValidators: true }).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_USER_UPDATE', `Updated user: ${user.name}`, req);
        res.json({ message: 'User updated successfully', user });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.get('/api/admin/deposits', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, limit = 50 } = req.query;
        
        let query = {};
        if (status && ['pending', 'approved', 'rejected'].includes(status)) {
            query.status = status;
        }
        
        const deposits = await Deposit.find(query)
            .populate('userId', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(Math.min(parseInt(limit), 100))
            .lean();
        
        res.json({ deposits, count: deposits.length });
    } catch (error) {
        res.status(500).json({ error: 'Failed to load deposits' });
    }
});

app.put('/api/admin/deposit/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, adminNotes } = req.body;
        
        if (!['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        const session = await mongoose.startSession();
        
        try {
            session.startTransaction();
            
            const deposit = await Deposit.findById(id).populate('userId').session(session);
            
            if (!deposit || deposit.status !== 'pending') {
                await session.abortTransaction();
                return res.status(400).json({ error: 'Deposit not found or already processed' });
            }
            
            deposit.status = status;
            deposit.adminNotes = adminNotes?.trim() || '';
            deposit.processedAt = new Date();
            
            if (status === 'approved') {
                deposit.userId.balance += deposit.amount;
                await deposit.userId.save({ session });
                
                setTimeout(() => {
                    sendUserNotification(deposit.userId._id, 'depositApproved', {
                        amount: deposit.amount,
                        newBalance: deposit.userId.balance
                    });
                }, 100);
            }
            
            await deposit.save({ session });
            await session.commitTransaction();
            
            await logActivity(req.userId, 'ADMIN_DEPOSIT_PROCESS', 
                `${status.toUpperCase()} deposit: ${formatCurrency(deposit.amount)}`, req);
            
            res.json({ message: `Deposit ${status} successfully` });
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to process deposit' });
    }
});

app.get('/api/admin/withdrawals', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, limit = 100 } = req.query;
        
        let query = {};
        if (status && ['pending', 'approved', 'rejected', 'processed'].includes(status)) {
            query.status = status;
        }
        
        const withdrawals = await Withdrawal.find(query)
            .populate('userId', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(Math.min(parseInt(limit), 100));
        
        res.json({ withdrawals });
    } catch (error) {
        res.status(500).json({ error: 'Failed to load withdrawals' });
    }
});

app.put('/api/admin/withdrawal/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, adminNotes } = req.body;
        
        if (!['pending', 'approved', 'rejected', 'processed'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        const withdrawal = await Withdrawal.findById(id).populate('userId');
        if (!withdrawal) {
            return res.status(404).json({ error: 'Withdrawal not found' });
        }
        
        const oldStatus = withdrawal.status;
        withdrawal.status = status;
        withdrawal.adminNotes = adminNotes?.trim() || '';
        withdrawal.processedAt = new Date();
        
        const session = await mongoose.startSession();
        
        try {
            session.startTransaction();
            
            if (status === 'rejected' && oldStatus === 'pending') {
                withdrawal.userId.balance += withdrawal.amount;
                await withdrawal.userId.save({ session });
                
                sendUserNotification(withdrawal.userId._id, 'withdrawalRejected', {
                    amount: withdrawal.amount,
                    newBalance: withdrawal.userId.balance,
                    reason: adminNotes || 'Withdrawal request rejected'
                });
            }
            
            await withdrawal.save({ session });
            await session.commitTransaction();
            
            await logActivity(req.userId, 'ADMIN_WITHDRAWAL_PROCESS', 
                `${status.toUpperCase()} withdrawal: ${formatCurrency(withdrawal.amount)}`, req);
            
            res.json({ message: `Withdrawal ${status} successfully` });
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to process withdrawal' });
    }
});

app.get('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const accounts = await BankAccount.find().sort({ createdAt: -1 });
        res.json({ accounts });
    } catch (error) {
        res.status(500).json({ error: 'Failed to load bank accounts' });
    }
});

app.post('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder, note } = req.body;
        
        if (!bankName?.trim() || !accountNumber?.trim() || !accountHolder?.trim()) {
            return res.status(400).json({ error: 'Bank name, account number, and account holder are required' });
        }
        
        const existingAccount = await BankAccount.findOne({ 
            bankName: bankName.trim(), 
            accountNumber: accountNumber.trim() 
        });
        
        if (existingAccount) {
            return res.status(400).json({ error: 'Bank account already exists' });
        }
        
        const account = new BankAccount({
            bankName: bankName.trim(),
            accountNumber: accountNumber.trim(),
            accountHolder: accountHolder.trim(),
            note: note?.trim() || ''
        });
        
        await account.save();
        await logActivity(req.userId, 'ADMIN_BANK_CREATE', `Created bank account: ${bankName.trim()}`, req);
        
        res.status(201).json({ message: 'Bank account created successfully', account });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to create bank account' });
    }
});

// ========================================
// 🔌 SOCKET.IO
// ========================================

io.on('connection', (socket) => {
    socket.on('join', (userId) => {
        if (userId && typeof userId === 'string' && userId.length === 24) {
            socket.join(userId);
            socket.userId = userId;
            socket.emit('connected', { message: 'Connected to TradeStation' });
        }
    });
    
    socket.on('subscribe_prices', () => {
        socket.join('price_updates');
        Price.find().then(prices => {
            if (prices?.length > 0) {
                socket.emit('pricesSnapshot', prices);
            }
        }).catch(err => console.error('Price snapshot error:', err.message));
    });
    
    socket.on('disconnect', (reason) => {
        // Silent disconnect logging
    });
});

// ========================================
// 🚨 ERROR HANDLING
// ========================================

app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found', path: req.originalUrl });
});

app.use((error, req, res, next) => {
    console.error('Global error:', error.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ========================================
// 🚀 SERVER STARTUP
// ========================================

const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        console.log('🚀 Starting server...');
        
        if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) {
            throw new Error('Missing required environment variables');
        }
        
        console.log('🔌 Connecting to MongoDB...');
        
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 15000,
            connectTimeoutMS: 15000,
            maxPoolSize: 10,
            family: 4
        });
        
        console.log('✅ Connected to MongoDB');
        
        // Initialize admin user
        const adminEmail = 'admin@tradestation.com';
        const adminPassword = 'admin123';
        
        const adminExists = await User.findOne({ email: adminEmail });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(adminPassword, 12);
            const admin = new User({
                name: 'Administrator',
                email: adminEmail,
                password: hashedPassword,
                referralCode: 'ADMIN001'
            });
            await admin.save();
            console.log('✅ Admin user created');
        }
        
        // Initialize sample bank accounts
        const bankExists = await BankAccount.findOne();
        if (!bankExists) {
            const sampleBanks = [
                { bankName: 'Bank BCA', accountNumber: '1234567890', accountHolder: 'TradeStation Official' },
                { bankName: 'Bank Mandiri', accountNumber: '0987654321', accountHolder: 'TradeStation Official' }
            ];
            
            for (const bank of sampleBanks) {
                await BankAccount.create(bank);
            }
            console.log('✅ Sample bank accounts created');
        }
        
        // Initialize prices and start background processes
        await initializePrices();
        isInitialized = true;
        
        // Start background processes with delay
        setTimeout(() => {
            simulatePriceUpdates();
            checkTradesToComplete();
            console.log('✅ Background processes started');
        }, 2000);
        
        // Start server
        server.listen(PORT, '0.0.0.0', () => {
            console.log(`
🎯 ====== TradeStation Backend Started ======
📍 Port: ${PORT}
🌍 Environment: ${process.env.NODE_ENV || 'development'}  
📧 Admin: ${adminEmail} / ${adminPassword}
🚀 Server Ready at: http://0.0.0.0:${PORT}
==========================================
            `);
        });
        
    } catch (error) {
        console.error('❌ Startup failed:', error.message);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('💤 Shutting down gracefully...');
    server.close(() => {
        mongoose.connection.close();
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('💤 Shutting down gracefully...');
    server.close(() => {
        mongoose.connection.close();
        process.exit(0);
    });
});

process.on('uncaughtException', (error) => {
    console.error('💥 Uncaught Exception:', error.message);
    process.exit(1);
});

process.on('unhandledRejection', (reason) => {
    console.error('💥 Unhandled Rejection:', reason);
    process.exit(1);
});

startServer();

module.exports = app;
