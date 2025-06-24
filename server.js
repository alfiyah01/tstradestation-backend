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

// ========================================
// 🔧 ENHANCED CORS CONFIGURATION - OPTIMIZED
// ========================================

const allowedOrigins = [
    // Production domains
    'https://ts-traderstation.com',
    'https://www.ts-traderstation.com', 
    'https://tstradestation-frontend.vercel.app',
    'https://tstradestation-admin.vercel.app',
    
    // Development domains
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:5173',
    'http://localhost:8080',
    'http://127.0.0.1:5500',
    'http://localhost:5500',
    
    // File protocol
    'file://',
    'null'
];

// Optimized CORS function
const isDevelopmentOrigin = (origin) => {
    if (!origin) return true; // Mobile apps, Postman
    return origin.startsWith('http://localhost:') || 
           origin.startsWith('http://127.0.0.1:') ||
           origin === 'null' ||
           allowedOrigins.includes(origin);
};

app.use(cors({
    origin: isDevelopmentOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    optionsSuccessStatus: 200
}));

// Socket.IO CORS
const io = socketIo(server, {
    cors: {
        origin: isDevelopmentOrigin,
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling'],
    allowEIO3: true
});

// ========================================
// 🛡️ ENHANCED MIDDLEWARE SETUP
// ========================================

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Enhanced rate limiting
const createLimiter = (windowMs, max, message) => rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false
});

const generalLimiter = createLimiter(15 * 60 * 1000, 100, 'Too many requests, please try again later');
const authLimiter = createLimiter(15 * 60 * 1000, 5, 'Too many authentication attempts');

app.use('/api/', generalLimiter);

// ========================================
// 📊 ENHANCED DATABASE MODELS
// ========================================

// Enhanced User Schema with better validation
const userSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: [true, 'Name is required'], 
        trim: true, 
        minlength: [2, 'Name must be at least 2 characters'],
        maxlength: [50, 'Name cannot exceed 50 characters']
    },
    email: { 
        type: String, 
        trim: true, 
        lowercase: true, 
        sparse: true,
        validate: {
            validator: function(email) {
                return !email || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
            },
            message: 'Invalid email format'
        }
    },
    phone: { 
        type: String, 
        trim: true, 
        sparse: true,
        validate: {
            validator: function(phone) {
                return !phone || /^(\+?62|0)[0-9]{9,13}$/.test(phone.replace(/[\s\-\(\)]/g, ''));
            },
            message: 'Invalid phone number format'
        }
    },
    password: { 
        type: String, 
        required: [true, 'Password is required'], 
        minlength: [6, 'Password must be at least 6 characters'] 
    },
    balance: { 
        type: Number, 
        default: 0, 
        min: [0, 'Balance cannot be negative'] 
    },
    accountType: { 
        type: String, 
        enum: ['standard', 'premium'], 
        default: 'standard' 
    },
    isActive: { 
        type: Boolean, 
        default: true 
    },
    totalProfit: { 
        type: Number, 
        default: 0 
    },
    totalLoss: { 
        type: Number, 
        default: 0 
    },
    referralCode: { 
        type: String, 
        unique: true 
    },
    
    // Bank Data
    bankData: {
        bankName: { type: String, trim: true },
        accountNumber: { type: String, trim: true },
        accountHolder: { type: String, trim: true }
    },
    
    // Enhanced Admin Settings
    adminSettings: {
        forceWin: { type: Boolean, default: false },
        forceWinRate: { 
            type: Number, 
            default: 0, 
            min: 0, 
            max: 100,
            validate: {
                validator: Number.isInteger,
                message: 'Win rate must be an integer'
            }
        },
        profitCollapse: { 
            type: String, 
            enum: ['profit', 'collapse', 'normal'], 
            default: 'normal' 
        },
        profitPercentage: { 
            type: Number, 
            default: 80, 
            min: 20, 
            max: 100,
            validate: {
                validator: function(v) {
                    return Number.isInteger(v) && v >= 20 && v <= 100;
                },
                message: 'Profit percentage must be an integer between 20 and 100'
            }
        }
    },
    
    stats: {
        totalTrades: { type: Number, default: 0, min: 0 },
        winTrades: { type: Number, default: 0, min: 0 },
        loseTrades: { type: Number, default: 0, min: 0 }
    },
    
    lastLoginAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Enhanced validation middleware
userSchema.pre('validate', function(next) {
    if (!this.email && !this.phone) {
        return next(new Error('Either email or phone number is required'));
    }
    next();
});

// Enhanced pre-save middleware
userSchema.pre('save', function(next) {
    // Ensure adminSettings defaults
    if (!this.adminSettings) {
        this.adminSettings = {
            forceWin: false,
            forceWinRate: 0,
            profitCollapse: 'normal',
            profitPercentage: 80
        };
    }
    
    // Ensure stats defaults
    if (!this.stats) {
        this.stats = {
            totalTrades: 0,
            winTrades: 0,
            loseTrades: 0
        };
    }
    
    next();
});

// Enhanced indexes
userSchema.index({ email: 1 }, { 
    unique: true, 
    sparse: true,
    partialFilterExpression: { email: { $exists: true, $ne: null } }
});
userSchema.index({ phone: 1 }, { 
    unique: true, 
    sparse: true,
    partialFilterExpression: { phone: { $exists: true, $ne: null } }
});

// Other schemas (optimized)
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
    receipt: { type: String }, // base64 file data
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
// 🛠️ ENHANCED HELPER FUNCTIONS
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

// Enhanced activity logging
const logActivity = async (userId, action, details = '', req = null) => {
    try {
        const activityData = {
            userId,
            action: action.trim(),
            details: details.trim()
        };
        
        if (req) {
            activityData.ip = req.ip || req.connection.remoteAddress;
            activityData.userAgent = req.get('User-Agent');
        }
        
        await Activity.create(activityData);
        console.log(`📝 Activity logged: ${action} - ${details}`);
    } catch (error) {
        console.error('❌ Error logging activity:', error);
    }
};

// Enhanced notification system
const sendUserNotification = (userId, type, data) => {
    try {
        if (!userId || !type) return;
        
        const userIdString = userId.toString();
        const notificationData = {
            ...data,
            timestamp: new Date().toISOString(),
            type: type
        };
        
        io.to(userIdString).emit(type, notificationData);
        console.log(`📡 Sent ${type} notification to user ${userIdString}`);
        
    } catch (error) {
        console.error('❌ Error sending notification:', error);
    }
};

// Chart data management (simplified)
let chartDataStore = new Map();
let isInitialized = false;

const generateCandleData = (symbol, currentPrice, previousCandle = null) => {
    try {
        const now = Date.now();
        const volatility = Math.random() * 0.015 + 0.005;
        
        const open = previousCandle ? previousCandle.close : currentPrice;
        const close = currentPrice;
        const maxPrice = Math.max(open, close);
        const minPrice = Math.min(open, close);
        
        const high = maxPrice * (1 + Math.random() * volatility);
        const low = minPrice * (1 - Math.random() * volatility);
        const volume = Math.floor(Math.random() * 900000) + 100000;
        
        return {
            time: Math.floor(now / 1000),
            open: parseFloat(Math.max(0.001, open).toFixed(8)),
            high: parseFloat(Math.max(0.001, high).toFixed(8)),
            low: parseFloat(Math.max(0.001, low).toFixed(8)),
            close: parseFloat(Math.max(0.001, close).toFixed(8)),
            volume
        };
    } catch (error) {
        console.error('❌ Error generating candle:', error);
        return null;
    }
};

// ========================================
// 🔐 ENHANCED MIDDLEWARE
// ========================================

const checkDatabaseConnection = (req, res, next) => {
    if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({ 
            error: 'Database temporarily unavailable',
            message: 'Please try again in a few moments'
        });
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
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (!user.isActive) {
            return res.status(403).json({ error: 'Account is deactivated' });
        }
        
        req.userId = decoded.userId;
        req.user = user;
        next();
    } catch (error) {
        const errorMessages = {
            'TokenExpiredError': 'Token expired',
            'JsonWebTokenError': 'Invalid token',
            default: 'Token verification failed'
        };
        
        return res.status(403).json({ 
            error: errorMessages[error.name] || errorMessages.default 
        });
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
// 🎯 CORE BUSINESS LOGIC
// ========================================

// Enhanced price initialization
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
                {
                    ...priceData,
                    price: Math.max(0.001, priceData.price),
                    lastUpdate: new Date()
                },
                { upsert: true, new: true }
            );
        }
        
        console.log('✅ Prices initialized successfully');
    } catch (error) {
        console.error('❌ Error initializing prices:', error);
    }
};

// Enhanced price simulation
const simulatePriceUpdates = () => {
    setInterval(async () => {
        if (!isInitialized) return;
        
        try {
            const prices = await Price.find();
            
            for (const price of prices) {
                const volatility = 0.008 + Math.random() * 0.012; // 0.8% - 2%
                const changePercent = (Math.random() - 0.5) * volatility;
                const newPrice = Math.max(0.001, price.price * (1 + changePercent));
                const change = ((newPrice - price.price) / price.price) * 100;
                
                price.price = parseFloat(newPrice.toFixed(price.symbol === 'BTC' ? 0 : 6));
                price.change = parseFloat(change.toFixed(2));
                price.lastUpdate = new Date();
                
                await price.save();
                
                // Broadcast to connected clients
                io.emit('priceUpdate', {
                    symbol: price.symbol,
                    price: price.price,
                    change: price.change,
                    lastUpdate: price.lastUpdate
                });
            }
        } catch (error) {
            console.error('❌ Error updating prices:', error);
        }
    }, 3000); // Update every 3 seconds
};

// Enhanced trade completion checker
const checkTradesToComplete = () => {
    setInterval(async () => {
        try {
            const now = new Date();
            const activeTrades = await Trade.find({ status: 'active' }).populate('userId');
            
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
            console.error('❌ Error checking trades:', error);
        }
    }, 1000);
};

// Enhanced trade completion logic
const completeTradeLogic = async (trade, currentPrice, now) => {
    try {
        trade.exitPrice = currentPrice.price;
        trade.status = 'completed';
        trade.completedAt = now;
        
        const priceChangePercent = ((currentPrice.price - trade.entryPrice) / trade.entryPrice) * 100;
        trade.priceChangePercent = priceChangePercent;
        
        // Determine result with admin settings priority
        let result = determineTradeResult(trade, currentPrice);
        trade.result = result;
        
        // Calculate payout
        const profitPercentage = Math.max(20, Math.min(100, 
            trade.profitPercentage || 
            trade.userId.adminSettings?.profitPercentage || 
            80
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
        
        // Update stats
        trade.userId.stats.totalTrades += 1;
        
        await Promise.all([trade.save(), trade.userId.save()]);
        
        // Log activity
        await logActivity(
            trade.userId._id, 
            'TRADE_COMPLETED', 
            `${trade.symbol} ${trade.direction.toUpperCase()} ${result.toUpperCase()} - ${formatCurrency(trade.payout)}`
        );
        
        // Send notification
        sendUserNotification(trade.userId._id, 'tradeCompleted', {
            trade: {
                _id: trade._id,
                symbol: trade.symbol,
                direction: trade.direction,
                amount: trade.amount,
                result: trade.result,
                payout: trade.payout,
                adminForced: trade.adminForced
            },
            result,
            payout: trade.payout,
            newBalance: trade.userId.balance
        });
        
        console.log(`✅ Trade completed: ${trade._id} - ${result.toUpperCase()} - ${formatCurrency(trade.payout)}`);
        
    } catch (error) {
        console.error('❌ Error completing trade:', error);
    }
};

const determineTradeResult = (trade, currentPrice) => {
    // Check admin settings first
    if (trade.userId.adminSettings?.profitCollapse === 'profit') {
        trade.adminForced = true;
        trade.forceResult = 'win';
        return 'win';
    } else if (trade.userId.adminSettings?.profitCollapse === 'collapse') {
        trade.adminForced = true;
        trade.forceResult = 'lose';
        return 'lose';
    } else if (trade.forceResult) {
        trade.adminForced = true;
        return trade.forceResult;
    } else if (trade.userId.adminSettings?.forceWin && trade.userId.adminSettings.forceWinRate > 0) {
        const winChance = Math.random() * 100;
        if (winChance <= trade.userId.adminSettings.forceWinRate) {
            trade.adminForced = true;
            return 'win';
        } else {
            trade.adminForced = true;
            return 'lose';
        }
    } else {
        // Natural market result
        if (trade.direction === 'buy') {
            return currentPrice.price > trade.entryPrice ? 'win' : 'lose';
        } else {
            return currentPrice.price < trade.entryPrice ? 'win' : 'lose';
        }
    }
};

// ========================================
// 🌐 PUBLIC ROUTES
// ========================================

app.get('/', (req, res) => {
    res.json({
        message: 'TradeStation Backend API - Versi Enhanced Perfect',
        version: '5.0.0',
        status: 'Running Optimally',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        features: [
            'Enhanced Email/Phone Authentication',
            'Optimized Admin Panel',
            'Robust Error Handling',
            'Advanced Security',
            'Real-time Trading System',
            'Enhanced Validation',
            'Memory Optimization',
            'Performance Monitoring'
        ]
    });
});

app.get('/api/health', (req, res) => {
    const health = {
        status: 'OK',
        message: 'TradeStation Backend running perfectly',
        timestamp: new Date().toISOString(),
        database: {
            status: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
            readyState: mongoose.connection.readyState
        },
        server: {
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            nodeVersion: process.version
        }
    };
    
    const statusCode = mongoose.connection.readyState === 1 ? 200 : 503;
    res.status(statusCode).json(health);
});

// ========================================
// 🔐 ENHANCED AUTHENTICATION ROUTES
// ========================================

// ENHANCED REGISTER ROUTE - PERFECT IMPLEMENTATION
app.post('/api/register', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        
        console.log('📝 Register request:', { 
            name: !!name, 
            email: !!email, 
            phone: !!phone, 
            password: !!password 
        });
        
        // Enhanced validation
        if (!name?.trim() || name.trim().length < 2) {
            return res.status(400).json({ error: 'Nama harus minimal 2 karakter' });
        }

        if (!password || password.length < 6) {
            return res.status(400).json({ error: 'Password harus minimal 6 karakter' });
        }

        // Must have email OR phone
        if (!email && !phone) {
            return res.status(400).json({ error: 'Email atau nomor HP diperlukan' });
        }
        
        // Validate email if provided
        if (email && !isValidEmail(email)) {
            return res.status(400).json({ error: 'Format email tidak valid' });
        }
        
        // Validate phone if provided  
        if (phone && !isValidPhone(phone)) {
            return res.status(400).json({ error: 'Format nomor HP tidak valid. Gunakan format: 08xxx atau +628xxx' });
        }
        
        // Check existing users
        const existingQuery = [];
        if (email) {
            existingQuery.push({ email: email.toLowerCase().trim() });
        }
        if (phone) {
            existingQuery.push({ phone: sanitizePhone(phone) });
        }
        
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
        
        // Create user data
        const hashedPassword = await bcrypt.hash(password, 12);
        const userData = {
            name: name.trim(),
            password: hashedPassword,
            referralCode: generateReferralCode(),
            balance: 0,
            adminSettings: {
                profitCollapse: 'normal',
                profitPercentage: 80,
                forceWin: false,
                forceWinRate: 0
            },
            stats: {
                totalTrades: 0,
                winTrades: 0,
                loseTrades: 0
            }
        };

        if (email) userData.email = email.toLowerCase().trim();
        if (phone) userData.phone = sanitizePhone(phone);
        
        const user = new User(userData);
        await user.save();
        
        // Log activity
        await logActivity(user._id, 'USER_REGISTER', `New user: ${email || phone}`, req);
        
        // Generate token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        // Response without password
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.status(201).json({
            message: 'Pendaftaran berhasil',
            token,
            user: userResponse
        });
        
        console.log(`✅ New user registered: ${email || phone}`);
        
    } catch (error) {
        console.error('❌ Registration error:', error);
        
        // Handle specific errors
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            return res.status(400).json({ 
                error: field === 'email' ? 'Email sudah terdaftar' : 'Nomor HP sudah terdaftar' 
            });
        }
        
        if (error.name === 'ValidationError') {
            const validationErrors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ 
                error: 'Data tidak valid', 
                details: validationErrors 
            });
        }
        
        res.status(500).json({ error: 'Pendaftaran gagal. Silakan coba lagi.' });
    }
});

// ENHANCED LOGIN ROUTE
app.post('/api/login', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { email, phone, password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password diperlukan' });
        }

        if (!email && !phone) {
            return res.status(400).json({ error: 'Email atau nomor HP diperlukan' });
        }
        
        // Find user
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
            return res.status(400).json({ error: 'Akun dinonaktifkan. Hubungi customer service.' });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Email/HP atau password salah' });
        }
        
        // Update last login
        user.lastLoginAt = new Date();
        await user.save();
        
        await logActivity(user._id, 'USER_LOGIN', `Login: ${email || phone}`, req);
        
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.json({
            message: 'Login berhasil',
            token,
            user: userResponse
        });
        
        console.log(`✅ User logged in: ${email || phone}`);
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Login gagal. Silakan coba lagi.' });
    }
});

// ========================================
// 👤 USER ROUTES  
// ========================================

app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        res.json(user);
    } catch (error) {
        console.error('❌ Profile error:', error);
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
            { 
                bankData: { 
                    bankName: bankName.trim(), 
                    accountNumber: accountNumber.trim(), 
                    accountHolder: accountHolder.trim() 
                }
            },
            { new: true }
        );
        
        await logActivity(req.userId, 'BANK_DATA_UPDATE', `Bank: ${bankName.trim()}`, req);
        
        res.json(user.bankData);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update bank data' });
    }
});

// ========================================
// 💰 TRADING ROUTES
// ========================================

app.get('/api/prices', async (req, res) => {
    try {
        const prices = await Price.find().sort({ symbol: 1 }).select('-__v');
        res.json(prices);
    } catch (error) {
        console.error('❌ Prices error:', error);
        res.status(500).json({ error: 'Failed to load prices' });
    }
});

app.post('/api/trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, direction, amount, duration } = req.body;
        
        // Validation
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
        
        // Get current price
        const currentPrice = await Price.findOne({ symbol: symbol.toUpperCase() });
        if (!currentPrice || !currentPrice.price || currentPrice.price <= 0) {
            return res.status(400).json({ error: 'Invalid symbol or price not available' });
        }
        
        // Get profit percentage
        const profitPercentage = Math.max(20, Math.min(100, 
            req.user.adminSettings?.profitPercentage || 80
        ));
        
        // Use session for atomic operation
        const session = await mongoose.startSession();
        
        try {
            session.startTransaction();
            
            // Deduct balance
            req.user.balance -= amount;
            await req.user.save({ session });
            
            // Create trade
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
            
            // Log activity
            await logActivity(
                req.userId, 
                'TRADE_CREATED', 
                `${symbol.toUpperCase()} ${direction.toUpperCase()} ${formatCurrency(amount)} - ${duration}s`,
                req
            );
            
            // Send notification
            sendUserNotification(req.userId, 'tradeCreated', {
                trade: {
                    _id: trade._id,
                    symbol: trade.symbol,
                    direction: trade.direction,
                    amount: trade.amount,
                    duration: trade.duration,
                    entryPrice: trade.entryPrice,
                    profitPercentage: trade.profitPercentage
                },
                newBalance: req.user.balance
            });
            
            res.status(201).json({
                message: 'Trade created successfully',
                trade: {
                    _id: trade._id,
                    symbol: trade.symbol,
                    direction: trade.direction,
                    amount: trade.amount,
                    duration: trade.duration,
                    entryPrice: trade.entryPrice,
                    profitPercentage: trade.profitPercentage,
                    status: trade.status,
                    createdAt: trade.createdAt
                },
                newBalance: req.user.balance
            });
            
            console.log(`✅ Trade created: ${trade.symbol} ${trade.direction} ${formatCurrency(trade.amount)}`);
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
        
    } catch (error) {
        console.error('❌ Trade error:', error);
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
        console.error('❌ Trades error:', error);
        res.status(500).json({ error: 'Failed to load trades' });
    }
});

// ========================================
// 💳 DEPOSIT & WITHDRAWAL ROUTES
// ========================================

app.get('/api/bank-accounts/active', async (req, res) => {
    try {
        const accounts = await BankAccount.find({ isActive: true })
            .select('bankName accountNumber accountHolder note')
            .sort({ createdAt: -1 });
        
        res.json(accounts);
    } catch (error) {
        console.error('❌ Error loading bank accounts:', error);
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
        
        // File validation
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        if (!allowedTypes.includes(fileType)) {
            return res.status(400).json({ error: 'Invalid file type. Only JPEG, PNG, and WebP are allowed.' });
        }
        
        // File size check
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
            deposit: {
                _id: deposit._id,
                amount: deposit.amount,
                method: deposit.method,
                status: deposit.status,
                createdAt: deposit.createdAt
            }
        });
        
        console.log(`✅ Deposit request: ${formatCurrency(amount)} from user ${req.user.name}`);
        
    } catch (error) {
        console.error('❌ Deposit error:', error);
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
        console.error('❌ Deposits error:', error);
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
            return res.status(400).json({ error: 'Bank data is required. Please update your bank information first.' });
        }
        
        // Calculate fee
        const feePercentage = 0.01; // 1%
        const minimumFee = 6500;
        const fee = Math.max(minimumFee, amount * feePercentage);
        const finalAmount = amount - fee;
        
        if (finalAmount <= 0) {
            return res.status(400).json({ error: 'Amount too small after fees' });
        }
        
        // Use session for atomic operation
        const session = await mongoose.startSession();
        
        try {
            session.startTransaction();
            
            // Deduct balance
            user.balance -= amount;
            await user.save({ session });
            
            // Create withdrawal
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
            
            await logActivity(req.userId, 'WITHDRAWAL_REQUEST', `Withdrawal: ${formatCurrency(amount)} (net: ${formatCurrency(finalAmount)})`, req);
            
            res.status(201).json({
                message: 'Withdrawal request submitted successfully',
                withdrawal: {
                    _id: withdrawal._id,
                    amount: withdrawal.amount,
                    fee: withdrawal.fee,
                    finalAmount: withdrawal.finalAmount,
                    bankAccount: withdrawal.bankAccount,
                    status: withdrawal.status,
                    createdAt: withdrawal.createdAt
                },
                newBalance: user.balance
            });
            
            console.log(`✅ Withdrawal request: ${formatCurrency(amount)} from user ${user.name}`);
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
        
    } catch (error) {
        console.error('❌ Withdrawal error:', error);
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
        console.error('❌ Withdrawals error:', error);
        res.status(500).json({ error: 'Failed to load withdrawals' });
    }
});

// ========================================
// 👑 ADMIN ROUTES (SIMPLIFIED & OPTIMIZED)
// ========================================

app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const timeout = 10000; // 10 second timeout
        
        const stats = await Promise.race([
            Promise.all([
                User.countDocuments(),
                User.countDocuments({ isActive: true }),
                Trade.countDocuments(),
                Trade.countDocuments({ status: 'active' }),
                Deposit.countDocuments(),
                Deposit.countDocuments({ status: 'pending' }),
                Withdrawal.countDocuments(),
                Withdrawal.countDocuments({ status: 'pending' }),
                BankAccount.countDocuments(),
                BankAccount.countDocuments({ isActive: true })
            ]),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Dashboard query timeout')), timeout)
            )
        ]);
        
        const [
            totalUsers, activeUsers, totalTrades, activeTrades,
            totalDeposits, pendingDeposits, totalWithdrawals, pendingWithdrawals,
            totalBankAccounts, activeBankAccounts
        ] = stats;
        
        // Calculate volume
        const completedTrades = await Trade.find({ status: 'completed' });
        const totalVolume = completedTrades.reduce((sum, trade) => sum + trade.amount, 0);
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayTrades = await Trade.find({ 
            status: 'completed',
            createdAt: { $gte: today }
        });
        const todayVolume = todayTrades.reduce((sum, trade) => sum + trade.amount, 0);
        
        // Recent activities
        const recentActivities = await Activity.find()
            .populate('userId', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(15);
        
        const dashboardStats = {
            users: { total: totalUsers, active: activeUsers },
            trades: { total: totalTrades, active: activeTrades },
            deposits: { total: totalDeposits, pending: pendingDeposits },
            withdrawals: { total: totalWithdrawals, pending: pendingWithdrawals },
            volume: { total: totalVolume, today: todayVolume },
            bankAccounts: { total: totalBankAccounts, active: activeBankAccounts }
        };
        
        res.json({ 
            stats: dashboardStats,
            recentActivities
        });
        
        console.log(`✅ Admin dashboard loaded by ${req.user.name}`);
        
    } catch (error) {
        console.error('❌ Admin dashboard error:', error);
        if (error.message === 'Dashboard query timeout') {
            res.status(504).json({ error: 'Dashboard query timeout - please try again' });
        } else {
            res.status(500).json({ error: 'Failed to load dashboard' });
        }
    }
});

// Enhanced User Management Routes
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find()
            .select('-password')
            .sort({ createdAt: -1 })
            .limit(200);
        
        res.json({ users });
        console.log(`✅ Admin users loaded: ${users.length} users`);
    } catch (error) {
        console.error('❌ Admin users error:', error);
        res.status(500).json({ error: 'Failed to load users' });
    }
});

app.put('/api/admin/user/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = { ...req.body };
        
        // Remove sensitive fields
        delete updateData.password;
        
        // Validate basic fields
        if (updateData.name && updateData.name.trim().length < 2) {
            return res.status(400).json({ error: 'Name must be at least 2 characters long' });
        }
        
        if (updateData.balance !== undefined) {
            const balance = parseFloat(updateData.balance);
            if (isNaN(balance) || balance < 0) {
                return res.status(400).json({ error: 'Balance must be a valid positive number' });
            }
            updateData.balance = balance;
        }
        
        // Enhanced admin settings validation
        if (updateData.adminSettings) {
            const { profitPercentage, forceWinRate, profitCollapse, forceWin } = updateData.adminSettings;
            
            if (profitPercentage !== undefined) {
                const percentage = parseInt(profitPercentage);
                if (isNaN(percentage) || percentage < 20 || percentage > 100) {
                    return res.status(400).json({ error: 'Profit percentage must be between 20 and 100' });
                }
                updateData.adminSettings.profitPercentage = percentage;
            }
            
            if (forceWinRate !== undefined) {
                const winRate = parseFloat(forceWinRate);
                if (isNaN(winRate) || winRate < 0 || winRate > 100) {
                    return res.status(400).json({ error: 'Win rate must be between 0 and 100' });
                }
                updateData.adminSettings.forceWinRate = winRate;
            }
            
            if (profitCollapse && !['normal', 'profit', 'collapse'].includes(profitCollapse)) {
                return res.status(400).json({ error: 'Invalid profit collapse setting' });
            }
            
            if (forceWin !== undefined) {
                updateData.adminSettings.forceWin = Boolean(forceWin);
            }
        }
        
        // Clean undefined values
        Object.keys(updateData).forEach(key => {
            if (updateData[key] === undefined || updateData[key] === '') {
                delete updateData[key];
            }
        });
        
        const user = await User.findByIdAndUpdate(
            id,
            updateData,
            { 
                new: true, 
                runValidators: true,
                omitUndefined: true 
            }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_USER_UPDATE', `Updated user: ${user.name}`, req);
        
        res.json({ message: 'User updated successfully', user });
        console.log(`✅ User updated by admin: ${user.name}`);
        
    } catch (error) {
        console.error('❌ Admin user update error:', error);
        
        if (error.name === 'ValidationError') {
            const validationErrors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: validationErrors 
            });
        }
        
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Enhanced User Bank Data Management
app.get('/api/admin/user/:id/bank', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const user = await User.findById(id).select('bankData name email phone');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ 
            bankData: user.bankData || {},
            user: {
                name: user.name,
                contact: user.email || user.phone
            }
        });
        
    } catch (error) {
        console.error('❌ Error loading user bank data:', error);
        res.status(500).json({ error: 'Failed to load bank data' });
    }
});

app.put('/api/admin/user/:id/bank', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { bankName, accountNumber, accountHolder } = req.body;
        
        if (!bankName?.trim() || !accountNumber?.trim() || !accountHolder?.trim()) {
            return res.status(400).json({ error: 'All bank data fields are required' });
        }
        
        const user = await User.findByIdAndUpdate(
            id,
            { 
                bankData: { 
                    bankName: bankName.trim(), 
                    accountNumber: accountNumber.trim(), 
                    accountHolder: accountHolder.trim() 
                }
            },
            { new: true }
        );
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_USER_BANK_UPDATE', `Updated bank data for user: ${user.name}`, req);
        
        res.json({ 
            message: 'User bank data updated successfully',
            bankData: user.bankData
        });
        
    } catch (error) {
        console.error('❌ Error updating user bank data:', error);
        res.status(500).json({ error: 'Failed to update bank data' });
    }
});

app.delete('/api/admin/user/:id/bank', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const user = await User.findByIdAndUpdate(
            id,
            { $unset: { bankData: 1 } },
            { new: true }
        );
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_USER_BANK_DELETE', `Deleted bank data for user: ${user.name}`, req);
        
        res.json({ message: 'User bank data deleted successfully' });
        
    } catch (error) {
        console.error('❌ Error deleting user bank data:', error);
        res.status(500).json({ error: 'Failed to delete bank data' });
    }
});

// Enhanced Password Management
app.put('/api/admin/user/:id/password', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { newPassword } = req.body;
        
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        
        const user = await User.findByIdAndUpdate(
            id,
            { password: hashedPassword },
            { new: true }
        ).select('name email phone');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_PASSWORD_CHANGE', `Changed password for user: ${user.name}`, req);
        
        res.json({ message: 'Password changed successfully' });
        
    } catch (error) {
        console.error('❌ Error changing password:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Enhanced Trade Management Routes
app.get('/api/admin/trades', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, limit = 100 } = req.query;
        
        let query = {};
        if (status && ['active', 'completed', 'cancelled'].includes(status)) {
            query.status = status;
        }
        
        const trades = await Trade.find(query)
            .populate('userId', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(Math.min(parseInt(limit), 200));
        
        res.json({ trades });
        console.log(`✅ Admin trades loaded: ${trades.length} trades`);
    } catch (error) {
        console.error('❌ Admin trades error:', error);
        res.status(500).json({ error: 'Failed to load trades' });
    }
});

app.put('/api/admin/trade/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { forceResult } = req.body;
        
        if (forceResult && !['win', 'lose'].includes(forceResult)) {
            return res.status(400).json({ error: 'Force result must be win or lose' });
        }
        
        const trade = await Trade.findById(id).populate('userId', 'name');
        if (!trade) {
            return res.status(404).json({ error: 'Trade not found' });
        }
        
        if (trade.status !== 'active') {
            return res.status(400).json({ error: 'Can only control active trades' });
        }
        
        trade.forceResult = forceResult || undefined;
        await trade.save();
        
        await logActivity(req.userId, 'ADMIN_TRADE_CONTROL', `Controlled trade: ${trade._id} - ${forceResult || 'cleared'} for user ${trade.userId.name}`, req);
        
        res.json({ message: 'Trade control updated successfully' });
        console.log(`✅ Trade controlled by admin: ${trade._id} - ${forceResult || 'cleared'}`);
        
    } catch (error) {
        console.error('❌ Admin trade control error:', error);
        res.status(500).json({ error: 'Failed to control trade' });
    }
});

// Enhanced Deposit Management Routes  
app.get('/api/admin/deposits', authenticateToken, requireAdmin, async (req, res) => {
    const startTime = Date.now();
    
    try {
        const { status, limit = 50 } = req.query;
        const queryTimeout = 15000; // 15 second timeout
        
        let query = {};
        if (status && ['pending', 'approved', 'rejected'].includes(status)) {
            query.status = status;
        }
        
        const deposits = await Promise.race([
            Deposit.find(query)
                .populate({
                    path: 'userId',
                    select: 'name email phone',
                    options: { lean: true }
                })
                .sort({ createdAt: -1 })
                .limit(Math.min(parseInt(limit), 100))
                .lean()
                .exec(),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Query timeout')), queryTimeout)
            )
        ]);
        
        const endTime = Date.now();
        const queryTime = endTime - startTime;
        
        // Filter valid deposits
        const cleanDeposits = deposits.filter(deposit => 
            deposit && deposit._id && deposit.amount
        );
        
        res.json({ 
            deposits: cleanDeposits,
            count: cleanDeposits.length,
            queryTime: queryTime,
            status: 'success'
        });
        
        console.log(`✅ Deposits loaded: ${cleanDeposits.length} records in ${queryTime}ms`);
        
    } catch (error) {
        const endTime = Date.now();
        console.error('❌ Admin deposits error:', error);
        
        res.status(500).json({ 
            error: 'Failed to load deposits',
            queryTime: endTime - startTime,
            status: 'error'
        });
    }
});

app.put('/api/admin/deposit/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, adminNotes } = req.body;
        
        if (!['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        // Use session for atomic operation
        const session = await mongoose.startSession();
        
        try {
            session.startTransaction();
            
            const deposit = await Deposit.findById(id)
                .populate('userId')
                .session(session);
                
            if (!deposit) {
                await session.abortTransaction();
                return res.status(404).json({ error: 'Deposit not found' });
            }
            
            if (deposit.status !== 'pending') {
                await session.abortTransaction();
                return res.status(400).json({ error: 'Deposit already processed' });
            }
            
            // Update deposit
            deposit.status = status;
            deposit.adminNotes = adminNotes?.trim() || '';
            deposit.processedAt = new Date();
            
            // If approved, add to user balance
            if (status === 'approved') {
                if (!deposit.userId) {
                    await session.abortTransaction();
                    return res.status(400).json({ error: 'User not found for this deposit' });
                }
                
                deposit.userId.balance += deposit.amount;
                await deposit.userId.save({ session });
                
                // Send notification
                setTimeout(() => {
                    sendUserNotification(deposit.userId._id, 'depositApproved', {
                        amount: deposit.amount,
                        newBalance: deposit.userId.balance,
                        message: 'Your deposit has been approved!'
                    });
                }, 100);
            }
            
            await deposit.save({ session });
            await session.commitTransaction();
            
            await logActivity(
                req.userId, 
                'ADMIN_DEPOSIT_PROCESS', 
                `${status.toUpperCase()} deposit: ${formatCurrency(deposit.amount)} for ${deposit.userId.name}`,
                req
            );
            
            res.json({ 
                message: `Deposit ${status} successfully`,
                deposit: {
                    _id: deposit._id,
                    status: deposit.status,
                    processedAt: deposit.processedAt
                }
            });
            
            console.log(`✅ Deposit ${status} successfully: ${formatCurrency(deposit.amount)}`);
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
        
    } catch (error) {
        console.error('❌ Admin deposit process error:', error);
        res.status(500).json({ error: 'Failed to process deposit' });
    }
});

// Enhanced Withdrawal Management Routes
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
            .limit(Math.min(parseInt(limit), 200));
        
        res.json({ withdrawals });
        console.log(`✅ Withdrawals loaded: ${withdrawals.length} withdrawals`);
    } catch (error) {
        console.error('❌ Admin withdrawals error:', error);
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
        
        // Use transaction for atomic operations
        const session = await mongoose.startSession();
        
        try {
            session.startTransaction();
            
            // If rejected, return money to user balance
            if (status === 'rejected' && oldStatus === 'pending') {
                withdrawal.userId.balance += withdrawal.amount;
                await withdrawal.userId.save({ session });
                
                // Send notification
                sendUserNotification(withdrawal.userId._id, 'withdrawalRejected', {
                    amount: withdrawal.amount,
                    newBalance: withdrawal.userId.balance,
                    reason: adminNotes || 'Withdrawal request rejected',
                    message: 'Your withdrawal request has been rejected and funds returned to your account.'
                });
            } else if (status === 'approved') {
                sendUserNotification(withdrawal.userId._id, 'withdrawalApproved', {
                    amount: withdrawal.finalAmount,
                    message: 'Your withdrawal request has been approved and will be processed soon.',
                    bankAccount: withdrawal.bankAccount
                });
            } else if (status === 'processed') {
                sendUserNotification(withdrawal.userId._id, 'withdrawalProcessed', {
                    amount: withdrawal.finalAmount,
                    message: 'Your withdrawal has been processed successfully.',
                    bankAccount: withdrawal.bankAccount
                });
            }
            
            await withdrawal.save({ session });
            await session.commitTransaction();
            
            await logActivity(
                req.userId, 
                'ADMIN_WITHDRAWAL_PROCESS', 
                `${status.toUpperCase()} withdrawal: ${formatCurrency(withdrawal.amount)} for ${withdrawal.userId.name}`, 
                req
            );
            
            res.json({ 
                message: `Withdrawal ${status} successfully`,
                withdrawal: {
                    _id: withdrawal._id,
                    status: withdrawal.status,
                    processedAt: withdrawal.processedAt
                }
            });
            
            console.log(`✅ Withdrawal ${status}: ${formatCurrency(withdrawal.amount)} for ${withdrawal.userId.name}`);
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
        
    } catch (error) {
        console.error('❌ Admin withdrawal process error:', error);
        res.status(500).json({ error: 'Failed to process withdrawal' });
    }
});

// Enhanced Bank Account Management Routes
app.get('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const accounts = await BankAccount.find().sort({ createdAt: -1 });
        res.json({ accounts });
        console.log(`✅ Bank accounts loaded: ${accounts.length} accounts`);
    } catch (error) {
        console.error('❌ Admin bank accounts error:', error);
        res.status(500).json({ error: 'Failed to load bank accounts' });
    }
});

app.post('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder, note } = req.body;
        
        if (!bankName?.trim() || !accountNumber?.trim() || !accountHolder?.trim()) {
            return res.status(400).json({ error: 'Bank name, account number, and account holder are required' });
        }
        
        // Check for duplicate account
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
        
        await logActivity(req.userId, 'ADMIN_BANK_CREATE', `Created bank account: ${bankName.trim()} - ${accountNumber.trim()}`, req);
        
        res.status(201).json({ 
            message: 'Bank account created successfully',
            account
        });
        
        console.log(`✅ Bank account created: ${bankName.trim()} - ${accountNumber.trim()}`);
        
    } catch (error) {
        console.error('❌ Admin bank account create error:', error);
        res.status(500).json({ error: 'Failed to create bank account' });
    }
});

app.put('/api/admin/bank-accounts/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { bankName, accountNumber, accountHolder, note, isActive } = req.body;
        
        if (!bankName?.trim() || !accountNumber?.trim() || !accountHolder?.trim()) {
            return res.status(400).json({ error: 'Bank name, account number, and account holder are required' });
        }
        
        const updateData = {
            bankName: bankName.trim(),
            accountNumber: accountNumber.trim(),
            accountHolder: accountHolder.trim(),
            note: note?.trim() || '',
            isActive: Boolean(isActive)
        };
        
        const account = await BankAccount.findByIdAndUpdate(
            id,
            updateData,
            { new: true, runValidators: true }
        );
        
        if (!account) {
            return res.status(404).json({ error: 'Bank account not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_BANK_UPDATE', `Updated bank account: ${account.bankName}`, req);
        
        res.json({ 
            message: 'Bank account updated successfully',
            account
        });
        
        console.log(`✅ Bank account updated: ${account.bankName}`);
        
    } catch (error) {
        console.error('❌ Admin bank account update error:', error);
        res.status(500).json({ error: 'Failed to update bank account' });
    }
});

app.patch('/api/admin/bank-accounts/:id/toggle', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const account = await BankAccount.findById(id);
        if (!account) {
            return res.status(404).json({ error: 'Bank account not found' });
        }
        
        account.isActive = !account.isActive;
        await account.save();
        
        await logActivity(req.userId, 'ADMIN_BANK_TOGGLE', `${account.isActive ? 'Activated' : 'Deactivated'} bank account: ${account.bankName}`, req);
        
        res.json({ 
            message: `Bank account ${account.isActive ? 'activated' : 'deactivated'} successfully`,
            account
        });
        
        console.log(`✅ Bank account ${account.isActive ? 'activated' : 'deactivated'}: ${account.bankName}`);
        
    } catch (error) {
        console.error('❌ Admin bank account toggle error:', error);
        res.status(500).json({ error: 'Failed to toggle bank account' });
    }
});

app.delete('/api/admin/bank-accounts/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const account = await BankAccount.findByIdAndDelete(id);
        if (!account) {
            return res.status(404).json({ error: 'Bank account not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_BANK_DELETE', `Deleted bank account: ${account.bankName}`, req);
        
        res.json({ message: 'Bank account deleted successfully' });
        
        console.log(`✅ Bank account deleted: ${account.bankName}`);
        
    } catch (error) {
        console.error('❌ Admin bank account delete error:', error);
        res.status(500).json({ error: 'Failed to delete bank account' });
    }
});

// Enhanced Health Check for Database
app.get('/api/admin/health/database', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const startTime = Date.now();
        const timeout = 8000; // 8 seconds
        
        const [userCount, depositCount, tradeCount, bankCount] = await Promise.race([
            Promise.all([
                User.countDocuments().maxTimeMS(timeout),
                Deposit.countDocuments().maxTimeMS(timeout),
                Trade.countDocuments().maxTimeMS(timeout),
                BankAccount.countDocuments().maxTimeMS(timeout)
            ]),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Database query timeout')), timeout)
            )
        ]);
        
        const endTime = Date.now();
        const queryTime = endTime - startTime;
        
        let status = 'healthy';
        let warning = null;
        
        if (queryTime > 5000) {
            status = 'slow';
            warning = 'Database response is very slow';
        } else if (queryTime > 3000) {
            status = 'degraded';
            warning = 'Database response is slower than optimal';
        }
        
        const health = {
            status: status,
            queryTime: queryTime,
            collections: {
                users: userCount,
                deposits: depositCount,
                trades: tradeCount,
                bankAccounts: bankCount
            },
            mongodb: {
                readyState: mongoose.connection.readyState,
                readyStateText: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoose.connection.readyState],
                host: mongoose.connection.host,
                name: mongoose.connection.name
            },
            server: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                nodeVersion: process.version
            }
        };
        
        if (warning) {
            health.warning = warning;
        }
        
        res.json(health);
        
    } catch (error) {
        console.error('❌ Database health check failed:', error);
        res.status(500).json({
            status: 'unhealthy',
            error: error.message,
            queryTime: null,
            mongodb: {
                readyState: mongoose.connection.readyState,
                readyStateText: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoose.connection.readyState]
            }
        });
    }
});

// Enhanced Chart Data Route
app.get('/api/chart/:symbol/:timeframe', async (req, res) => {
    try {
        const { symbol, timeframe } = req.params;
        
        // Validation
        const validTimeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d'];
        if (!validTimeframes.includes(timeframe)) {
            return res.status(400).json({ 
                error: 'Invalid timeframe',
                validTimeframes: validTimeframes
            });
        }
        
        // Check if symbol exists
        const priceData = await Price.findOne({ symbol: symbol.toUpperCase() });
        if (!priceData) {
            const availableSymbols = await Price.find().distinct('symbol');
            return res.status(404).json({ 
                error: 'Symbol not found',
                availableSymbols: availableSymbols
            });
        }
        
        // Generate historical data
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
        
        console.log(`✅ Chart data sent: ${chartData.length} candles for ${symbol}/${timeframe}`);
        
    } catch (error) {
        console.error('❌ Chart data error:', error);
        res.status(500).json({ error: 'Failed to load chart data' });
    }
});

// ========================================
// 🔌 ENHANCED SOCKET.IO
// ========================================

io.on('connection', (socket) => {
    console.log('👤 User connected:', socket.id);
    
    socket.on('join', (userId) => {
        if (userId && typeof userId === 'string' && userId.length === 24) {
            socket.join(userId);
            socket.userId = userId;
            console.log(`👤 User ${userId} joined room`);
            
            socket.emit('connected', { 
                message: 'Connected to TradeStation',
                timestamp: new Date().toISOString()
            });
        }
    });
    
    socket.on('subscribe_prices', () => {
        socket.join('price_updates');
        console.log('📊 User subscribed to price updates');
        
        Price.find().then(prices => {
            if (prices?.length > 0) {
                socket.emit('pricesSnapshot', prices);
            }
        }).catch(err => console.error('Error sending price snapshot:', err));
    });
    
    socket.on('disconnect', (reason) => {
        console.log('👤 User disconnected:', socket.id, 'Reason:', reason);
    });
    
    socket.on('error', (error) => {
        console.error('❌ Socket error:', error);
    });
});

// ========================================
// 🚨 ERROR HANDLING
// ========================================

app.use((error, req, res, next) => {
    console.error('❌ Global error:', error);
    
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    let statusCode = error.status || 500;
    let message = 'Internal server error';
    
    if (error.name === 'ValidationError') {
        statusCode = 400;
        message = 'Data validation failed';
    } else if (error.name === 'CastError') {
        statusCode = 400;
        message = 'Invalid data format';
    } else if (error.code === 11000) {
        statusCode = 400;
        message = 'Duplicate data detected';
    } else if (isDevelopment) {
        message = error.message;
    }
    
    res.status(statusCode).json({ 
        error: message,
        timestamp: new Date().toISOString(),
        ...(isDevelopment && { 
            details: error.message 
        })
    });
});

app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'Route not found',
        method: req.method,
        path: req.originalUrl,
        timestamp: new Date().toISOString()
    });
});

// ========================================
// 🚀 SERVER STARTUP
// ========================================

const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        // Connect to database
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
            maxPoolSize: 10,
            retryWrites: true,
            w: 'majority'
        });
        
        console.log('✅ Connected to MongoDB');
        
        // Initialize default admin
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
            console.log('✅ Default admin user created (admin@tradestation.com / admin123)');
        }
        
        // Initialize sample data
        const bankExists = await BankAccount.findOne();
        if (!bankExists) {
            const sampleBanks = [
                {
                    bankName: 'Bank BCA',
                    accountNumber: '1234567890',
                    accountHolder: 'TradeStation Official',
                    note: 'Primary deposit account'
                },
                {
                    bankName: 'Bank Mandiri',
                    accountNumber: '0987654321',
                    accountHolder: 'TradeStation Official',
                    note: 'Secondary deposit account'
                }
            ];
            
            for (const bank of sampleBanks) {
                await BankAccount.create(bank);
            }
            console.log('✅ Sample bank accounts created');
        }
        
        // Initialize prices
        await initializePrices();
        
        // Mark as initialized
        isInitialized = true;
        
        // Start background processes
        simulatePriceUpdates();
        checkTradesToComplete();
        console.log('✅ Background processes started');
        
        // Start server
        server.listen(PORT, '0.0.0.0', () => {
            console.log(`
🚀 TradeStation Backend - Enhanced Perfect Version 5.0.0
📍 Port: ${PORT}
🌍 Environment: ${process.env.NODE_ENV || 'development'}
📧 Enhanced Authentication: ✅ Email/Phone Registration Perfect
🛡️  CORS Protection: ✅ Optimized for All Environments  
📊 Real-time Trading: ✅ Enhanced Performance
💳 Deposit/Withdrawal: ✅ Robust File Upload Support
🎯 Admin Panel: ✅ Optimized Query Performance
🔄 Background Processes: ✅ Enhanced Error Handling
🗃️  Database: ✅ Connected with Health Monitoring
📡 Socket.IO: ✅ Enhanced Connection Management
⏰ Timestamp: ${new Date().toISOString()}

🔗 API Endpoints Ready:
   • Health: GET /api/health
   • Auth: POST /api/login, /api/register (Enhanced)
   • Trading: POST /api/trade, GET /api/trades  
   • Admin: /api/admin/* (Optimized)

📋 Admin Access:
   • Email: admin@tradestation.com
   • Password: admin123

✨ ENHANCED FEATURES:
   ✅ Optimized Registration System (Email/Phone Perfect)
   ✅ Enhanced Database Performance & Validation
   ✅ Robust Error Handling & Security
   ✅ Memory Usage Optimization
   ✅ Query Timeout Protection
   ✅ Transaction Atomic Operations
   ✅ Enhanced CORS for Production
   ✅ Real-time Notifications via WebSocket
   ✅ Improved Code Structure & Maintainability

🎯 Server ready for high-performance trading!
            `);
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('💤 SIGTERM received, shutting down gracefully');
    server.close(() => {
        mongoose.connection.close();
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('💤 SIGINT received, shutting down gracefully');
    server.close(() => {
        mongoose.connection.close();
        process.exit(0);
    });
});

// Start the server
startServer();

module.exports = app;
