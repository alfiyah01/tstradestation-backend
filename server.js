const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

// ========================================
// 🔒 SECURITY & ENVIRONMENT VALIDATION
// ========================================

// Validate required environment variables
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
    console.error('❌ Missing required environment variables:', missingEnvVars);
    console.error('Please set the following variables in your .env file:');
    missingEnvVars.forEach(envVar => {
        console.error(`  ${envVar}=your_value_here`);
    });
    process.exit(1);
}

// Validate JWT_SECRET strength
if (process.env.JWT_SECRET.length < 32) {
    console.error('❌ JWT_SECRET must be at least 32 characters long for security');
    process.exit(1);
}

// ========================================
// 🚀 EXPRESS & SERVER SETUP
// ========================================

const app = express();
const server = http.createServer(app);

// Socket.IO setup with optimized CORS
const io = socketIo(server, {
    cors: {
        origin: process.env.FRONTEND_URL || ["https://ts-traderstation.com", "http://localhost:3000"],
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling'],
    pingTimeout: 60000,
    pingInterval: 25000
});

// ========================================
// 📊 OPTIMIZED MIDDLEWARE
// ========================================

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    hsts: process.env.NODE_ENV === 'production'
}));

// Compression for better performance
app.use(compression({
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    },
    threshold: 1024
}));

// CORS with environment-based origins
const allowedOrigins = process.env.FRONTEND_URL 
    ? [process.env.FRONTEND_URL]
    : ["https://ts-traderstation.com", "http://localhost:3000", "http://127.0.0.1:5500"];

app.use(cors({
    origin: allowedOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '5mb' })); // Reduced from 10mb
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// ========================================
// 🛡️ ENHANCED RATE LIMITING
// ========================================

// General API rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: process.env.NODE_ENV === 'production' ? 100 : 1000,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Strict auth rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: { error: 'Too many authentication attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true
});

// Trading rate limiting
const tradeLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10,
    message: { error: 'Too many trades, please slow down.' }
});

app.use('/api/', apiLimiter);

// ========================================
// 🗃️ OPTIMIZED DATABASE MODELS
// ========================================

// Optimized User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, minlength: 2, maxlength: 100 },
    email: { 
        type: String, 
        trim: true, 
        lowercase: true, 
        sparse: true,
        maxlength: 255,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email format']
    },
    phone: { 
        type: String, 
        trim: true, 
        sparse: true,
        maxlength: 20,
        match: [/^(\+?628\d{8,11}|08\d{8,11})$/, 'Invalid phone format']
    },
    password: { type: String, required: true, minlength: 6 },
    balance: { type: Number, default: 0, min: 0, max: 999999999999 },
    accountType: { type: String, enum: ['standard', 'premium'], default: 'standard' },
    isActive: { type: Boolean, default: true },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    referralCode: { type: String, unique: true, sparse: true },
    bankData: {
        bankName: { type: String, trim: true, maxlength: 100 },
        accountNumber: { type: String, trim: true, maxlength: 50 },
        accountHolder: { type: String, trim: true, maxlength: 100 }
    },
    adminSettings: {
        forceWin: { type: Boolean, default: false },
        forceWinRate: { type: Number, default: 0, min: 0, max: 100 },
        profitCollapse: { 
            type: String, 
            enum: ['profit', 'collapse', 'normal'], 
            default: 'normal' 
        },
        profitPercentage: { type: Number, default: 80, min: 20, max: 100 }
    },
    stats: {
        totalTrades: { type: Number, default: 0, min: 0 },
        winTrades: { type: Number, default: 0, min: 0 },
        loseTrades: { type: Number, default: 0, min: 0 }
    },
    lastLoginAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
}, {
    timestamps: true,
    versionKey: false
});

// Optimized indexes
userSchema.index({ email: 1 }, { unique: true, sparse: true });
userSchema.index({ phone: 1 }, { unique: true, sparse: true });
userSchema.index({ referralCode: 1 }, { unique: true, sparse: true });
userSchema.index({ createdAt: -1 });
userSchema.index({ isActive: 1, createdAt: -1 });

// Validation middleware
userSchema.pre('validate', function(next) {
    if (!this.email && !this.phone) {
        this.invalidate('email', 'Either email or phone number is required');
    }
    next();
});

// Other schemas (simplified and optimized)
const bankAccountSchema = new mongoose.Schema({
    bankName: { type: String, required: true, maxlength: 100 },
    accountNumber: { type: String, required: true, maxlength: 50 },
    accountHolder: { type: String, required: true, maxlength: 100 },
    isActive: { type: Boolean, default: true },
    note: { type: String, maxlength: 500 },
    createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symbol: { type: String, required: true, maxlength: 10 },
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
}, { versionKey: false });

// Optimized indexes for trades
tradeSchema.index({ userId: 1, status: 1, createdAt: -1 });
tradeSchema.index({ status: 1, createdAt: 1 });
tradeSchema.index({ createdAt: -1 });

const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 500000, max: 1000000000 },
    method: { type: String, default: 'Bank Transfer' },
    bankFrom: { type: String, maxlength: 100 },
    receipt: { type: String }, // base64 file data
    fileName: { type: String, maxlength: 255 },
    fileType: { type: String, maxlength: 50 },
    fileSize: { type: Number, max: 5242880 }, // 5MB max
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    adminNotes: { type: String, maxlength: 1000 },
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
}, { versionKey: false });

depositSchema.index({ userId: 1, createdAt: -1 });
depositSchema.index({ status: 1, createdAt: -1 });

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 100000, max: 1000000000 },
    fee: { type: Number, required: true, min: 0 },
    finalAmount: { type: Number, required: true, min: 0 },
    bankAccount: {
        bankName: { type: String, required: true, maxlength: 100 },
        accountNumber: { type: String, required: true, maxlength: 50 },
        accountHolder: { type: String, required: true, maxlength: 100 }
    },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'processed'], default: 'pending' },
    adminNotes: { type: String, maxlength: 1000 },
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
}, { versionKey: false });

withdrawalSchema.index({ userId: 1, createdAt: -1 });
withdrawalSchema.index({ status: 1, createdAt: -1 });

const priceSchema = new mongoose.Schema({
    symbol: { type: String, required: true, unique: true, maxlength: 10 },
    price: { type: Number, required: true, min: 0 },
    change: { type: Number, default: 0 },
    lastUpdate: { type: Date, default: Date.now }
}, { versionKey: false });

const activitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true, maxlength: 100 },
    details: { type: String, maxlength: 500 },
    ip: { type: String, maxlength: 45 },
    userAgent: { type: String, maxlength: 500 },
    createdAt: { type: Date, default: Date.now, expires: 2592000 } // Auto-delete after 30 days
}, { versionKey: false });

activitySchema.index({ userId: 1, createdAt: -1 });
activitySchema.index({ createdAt: -1 });

// Create models
const User = mongoose.model('User', userSchema);
const BankAccount = mongoose.model('BankAccount', bankAccountSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Price = mongoose.model('Price', priceSchema);
const Activity = mongoose.model('Activity', activitySchema);

// ========================================
// 🧠 OPTIMIZED MEMORY MANAGEMENT
// ========================================

// Chart data with memory limits
class OptimizedChartDataStore {
    constructor() {
        this.data = new Map();
        this.maxSymbols = 20;
        this.maxCandlesPerChart = 200;
        this.lastCleanup = Date.now();
        this.cleanupInterval = 5 * 60 * 1000; // 5 minutes
    }

    set(key, value) {
        // Auto cleanup if needed
        if (Date.now() - this.lastCleanup > this.cleanupInterval) {
            this.cleanup();
        }

        // Limit candles per chart
        if (Array.isArray(value) && value.length > this.maxCandlesPerChart) {
            value = value.slice(-this.maxCandlesPerChart);
        }

        // Limit total symbols
        if (this.data.size >= this.maxSymbols && !this.data.has(key)) {
            const oldestKey = this.data.keys().next().value;
            this.data.delete(oldestKey);
            console.log(`🧹 Cleaned up old chart data: ${oldestKey}`);
        }

        this.data.set(key, value);
    }

    get(key) {
        return this.data.get(key);
    }

    has(key) {
        return this.data.has(key);
    }

    get size() {
        return this.data.size;
    }

    cleanup() {
        const memUsage = process.memoryUsage();
        const heapUsedMB = memUsage.heapUsed / 1024 / 1024;

        if (heapUsedMB > 100) { // If using more than 100MB
            const keysToDelete = Math.floor(this.data.size * 0.3); // Delete 30%
            const keys = Array.from(this.data.keys());
            
            for (let i = 0; i < keysToDelete; i++) {
                this.data.delete(keys[i]);
            }
            
            console.log(`🧹 Memory cleanup: Removed ${keysToDelete} chart datasets`);
        }

        this.lastCleanup = Date.now();
    }

    getMemoryUsage() {
        let totalSize = 0;
        for (const [key, value] of this.data) {
            if (Array.isArray(value)) {
                totalSize += value.length * 50; // Estimate 50 bytes per candle
            }
        }
        return { symbols: this.data.size, estimatedBytes: totalSize };
    }
}

const chartDataStore = new OptimizedChartDataStore();
let isInitialized = false;
let activeSockets = new Set();

// ========================================
// 🔧 UTILITY FUNCTIONS
// ========================================

function generateReferralCode() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
}

function generateSecurePassword() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// Optimized activity logging with throttling
const activityQueue = [];
let isProcessingActivities = false;

async function logActivity(userId, action, details = '', req = null) {
    const activityData = {
        userId,
        action,
        details: details.substring(0, 500), // Limit details length
        ip: req ? (req.ip || req.connection.remoteAddress || '').substring(0, 45) : null,
        userAgent: req ? (req.get('User-Agent') || '').substring(0, 500) : null
    };
    
    activityQueue.push(activityData);
    
    if (!isProcessingActivities) {
        processActivityQueue();
    }
}

async function processActivityQueue() {
    if (activityQueue.length === 0) {
        isProcessingActivities = false;
        return;
    }
    
    isProcessingActivities = true;
    
    try {
        const activities = activityQueue.splice(0, 10); // Process max 10 at once
        if (activities.length > 0) {
            await Activity.insertMany(activities, { ordered: false });
        }
    } catch (error) {
        console.error('❌ Error processing activities:', error);
    }
    
    // Continue processing if there are more activities
    if (activityQueue.length > 0) {
        setTimeout(processActivityQueue, 100);
    } else {
        isProcessingActivities = false;
    }
}

// Phone validation and normalization
function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function isValidPhone(phone) {
    if (!phone || typeof phone !== 'string') return false;
    const cleanPhone = phone.trim().replace(/[\s\-\(\)]/g, '');
    return /^(\+?628\d{8,11}|08\d{8,11})$/.test(cleanPhone);
}

function normalizePhone(phone) {
    if (!phone) return null;
    let cleaned = phone.trim().replace(/[\s\-\(\)]/g, '');
    
    if (cleaned.startsWith('08')) {
        return '+62' + cleaned.substring(1);
    }
    if (cleaned.startsWith('628')) {
        return '+' + cleaned;
    }
    if (cleaned.startsWith('+628')) {
        return cleaned;
    }
    return cleaned;
}

function formatCurrency(amount) {
    return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        minimumFractionDigits: 0,
        maximumFractionDigits: 0
    }).format(amount || 0);
}

// ========================================
// 🔐 AUTHENTICATION MIDDLEWARE
// ========================================

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).lean();
        
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
        if (error.name === 'TokenExpiredError') {
            return res.status(403).json({ error: 'Token expired' });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({ error: 'Invalid token' });
        }
        return res.status(403).json({ error: 'Token verification failed' });
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

const checkDatabaseConnection = (req, res, next) => {
    if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({ 
            error: 'Database temporarily unavailable',
            message: 'Please try again in a few moments'
        });
    }
    next();
};

// ========================================
// 📊 OPTIMIZED CHART & PRICE MANAGEMENT
// ========================================

function generateCandleFromPrice(symbol, timeframe, currentPrice, previousCandle = null) {
    try {
        if (!currentPrice || isNaN(currentPrice) || currentPrice <= 0) {
            return null;
        }

        const now = Date.now();
        const timeframeMs = getTimeframeMinutes(timeframe) * 60 * 1000;
        const roundedTime = Math.floor(now / timeframeMs) * timeframeMs;
        
        if (!previousCandle || previousCandle.time < Math.floor(roundedTime / 1000)) {
            const volatility = Math.random() * 0.01 + 0.002;
            const open = previousCandle ? previousCandle.close : currentPrice;
            const close = currentPrice;
            
            const maxPrice = Math.max(open, close);
            const minPrice = Math.min(open, close);
            
            const high = maxPrice * (1 + Math.random() * volatility);
            const low = minPrice * (1 - Math.random() * volatility);
            
            return {
                time: Math.floor(roundedTime / 1000),
                open: parseFloat(Math.max(0.001, open).toFixed(8)),
                high: parseFloat(Math.max(0.001, high).toFixed(8)),
                low: parseFloat(Math.max(0.001, low).toFixed(8)),
                close: parseFloat(Math.max(0.001, close).toFixed(8)),
                volume: Math.floor(Math.random() * 500000) + 50000
            };
        }
        
        return {
            ...previousCandle,
            close: parseFloat(Math.max(0.001, currentPrice).toFixed(8)),
            high: Math.max(previousCandle.high, currentPrice),
            low: Math.min(previousCandle.low, currentPrice),
            volume: previousCandle.volume + Math.floor(Math.random() * 25000)
        };
    } catch (error) {
        console.error('❌ Error generating candle:', error);
        return null;
    }
}

function getTimeframeMinutes(timeframe) {
    const timeframes = {
        '1m': 1, '5m': 5, '15m': 15, '30m': 30,
        '1h': 60, '4h': 240, '1d': 1440
    };
    return timeframes[timeframe] || 5;
}

async function generateHistoricalData(symbol, timeframe, count = 100) {
    try {
        const currentPrice = await Price.findOne({ symbol }).lean();
        if (!currentPrice || !currentPrice.price || currentPrice.price <= 0) {
            return [];
        }
        
        const timeframeMs = getTimeframeMinutes(timeframe) * 60 * 1000;
        const now = Date.now();
        const data = [];
        let price = currentPrice.price;
        
        for (let i = count; i >= 0; i--) {
            const time = Math.floor((now - (i * timeframeMs)) / 1000);
            const volatility = 0.005;
            const trendFactor = (Math.random() - 0.5) * volatility;
            const newPrice = Math.max(0.001, price * (1 + trendFactor));
            
            const open = price;
            const close = newPrice;
            const spread = Math.abs(close - open);
            const high = Math.max(open, close) + (spread * Math.random() * 0.3);
            const low = Math.min(open, close) - (spread * Math.random() * 0.3);
            
            data.push({
                time,
                open: parseFloat(Math.max(0.001, open).toFixed(8)),
                high: parseFloat(Math.max(0.001, high).toFixed(8)),
                low: parseFloat(Math.max(0.001, low).toFixed(8)),
                close: parseFloat(Math.max(0.001, close).toFixed(8)),
                volume: Math.floor(Math.random() * 500000) + 50000
            });
            
            price = newPrice;
        }
        
        return data.sort((a, b) => a.time - b.time);
    } catch (error) {
        console.error('❌ Error generating historical data:', error);
        return [];
    }
}

async function initializePrices() {
    try {
        const defaultPrices = [
            { symbol: 'BTC', price: 45000 + (Math.random() * 5000), change: (Math.random() - 0.5) * 3 },
            { symbol: 'ETH', price: 3200 + (Math.random() * 300), change: (Math.random() - 0.5) * 3 },
            { symbol: 'LTC', price: 180 + (Math.random() * 15), change: (Math.random() - 0.5) * 3 },
            { symbol: 'XRP', price: 0.65 + (Math.random() * 0.05), change: (Math.random() - 0.5) * 3 },
            { symbol: 'DOGE', price: 0.08 + (Math.random() * 0.01), change: (Math.random() - 0.5) * 3 },
            { symbol: 'TRX', price: 0.12 + (Math.random() * 0.01), change: (Math.random() - 0.5) * 3 }
        ];

        for (const priceData of defaultPrices) {
            await Price.findOneAndUpdate(
                { symbol: priceData.symbol },
                { ...priceData, lastUpdate: new Date() },
                { upsert: true }
            );
        }
        
        console.log('✅ Prices initialized');
    } catch (error) {
        console.error('❌ Error initializing prices:', error);
    }
}

// Optimized price updates with throttling
let lastPriceUpdate = 0;
const PRICE_UPDATE_INTERVAL = 3000; // 3 seconds

function simulatePriceUpdates() {
    setInterval(async () => {
        if (!isInitialized || activeSockets.size === 0) return;
        
        const now = Date.now();
        if (now - lastPriceUpdate < PRICE_UPDATE_INTERVAL) return;
        
        try {
            const prices = await Price.find().lean();
            const updates = [];
            
            for (const price of prices) {
                const volatility = 0.003 + (Math.random() * 0.002);
                const changePercent = (Math.random() - 0.5) * volatility;
                const newPrice = Math.max(0.001, price.price * (1 + changePercent));
                const change = ((newPrice - price.price) / price.price) * 100;
                
                const updatedPrice = {
                    price: parseFloat(newPrice.toFixed(price.symbol === 'BTC' ? 0 : 6)),
                    change: parseFloat(change.toFixed(2)),
                    lastUpdate: new Date()
                };
                
                updates.push({
                    updateOne: {
                        filter: { symbol: price.symbol },
                        update: updatedPrice
                    }
                });
                
                // Emit to active sockets only
                if (activeSockets.size > 0) {
                    io.emit('priceUpdate', {
                        symbol: price.symbol,
                        ...updatedPrice
                    });
                }
                
                // Update chart data
                const timeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d'];
                for (const timeframe of timeframes) {
                    const key = `${price.symbol}-${timeframe}`;
                    const currentCandles = chartDataStore.get(key) || [];
                    const lastCandle = currentCandles[currentCandles.length - 1];
                    
                    const newCandle = generateCandleFromPrice(price.symbol, timeframe, updatedPrice.price, lastCandle);
                    if (newCandle) {
                        if (lastCandle && lastCandle.time === newCandle.time) {
                            currentCandles[currentCandles.length - 1] = newCandle;
                        } else {
                            currentCandles.push(newCandle);
                        }
                        chartDataStore.set(key, currentCandles);
                    }
                }
            }
            
            if (updates.length > 0) {
                await Price.bulkWrite(updates, { ordered: false });
            }
            
            lastPriceUpdate = now;
        } catch (error) {
            console.error('❌ Error updating prices:', error);
        }
    }, PRICE_UPDATE_INTERVAL);
}

// Optimized trade completion checker
function checkTradesToComplete() {
    setInterval(async () => {
        try {
            const activeTrades = await Trade.find({ 
                status: 'active',
                createdAt: { $lte: new Date(Date.now() - 30000) } // At least 30 seconds old
            }).populate('userId', 'balance adminSettings stats').lean();
            
            if (activeTrades.length === 0) return;
            
            const bulkOps = [];
            const userUpdates = new Map();
            const socketNotifications = [];
            
            for (const trade of activeTrades) {
                const createdAt = new Date(trade.createdAt);
                const elapsedSeconds = Math.floor((Date.now() - createdAt) / 1000);
                
                if (elapsedSeconds >= trade.duration) {
                    const currentPrice = await Price.findOne({ symbol: trade.symbol }).lean();
                    if (!currentPrice) continue;
                    
                    const priceChangePercent = ((currentPrice.price - trade.entryPrice) / trade.entryPrice) * 100;
                    
                    // Determine result
                    let result;
                    if (trade.userId.adminSettings?.profitCollapse === 'profit') {
                        result = 'win';
                    } else if (trade.userId.adminSettings?.profitCollapse === 'collapse') {
                        result = 'lose';
                    } else if (trade.forceResult) {
                        result = trade.forceResult;
                    } else {
                        result = (trade.direction === 'buy') 
                            ? (currentPrice.price > trade.entryPrice ? 'win' : 'lose')
                            : (currentPrice.price < trade.entryPrice ? 'win' : 'lose');
                    }
                    
                    const profitPercentage = trade.profitPercentage || 80;
                    const payout = result === 'win' ? trade.amount + (trade.amount * profitPercentage / 100) : 0;
                    
                    // Update trade
                    bulkOps.push({
                        updateOne: {
                            filter: { _id: trade._id },
                            update: {
                                exitPrice: currentPrice.price,
                                status: 'completed',
                                result,
                                payout,
                                priceChangePercent,
                                completedAt: new Date()
                            }
                        }
                    });
                    
                    // Update user balance and stats
                    if (!userUpdates.has(trade.userId._id.toString())) {
                        userUpdates.set(trade.userId._id.toString(), {
                            balanceChange: 0,
                            totalTrades: 0,
                            winTrades: 0,
                            loseTrades: 0,
                            totalProfit: 0,
                            totalLoss: 0
                        });
                    }
                    
                    const userUpdate = userUpdates.get(trade.userId._id.toString());
                    userUpdate.balanceChange += payout;
                    userUpdate.totalTrades += 1;
                    
                    if (result === 'win') {
                        userUpdate.winTrades += 1;
                        userUpdate.totalProfit += (payout - trade.amount);
                    } else {
                        userUpdate.loseTrades += 1;
                        userUpdate.totalLoss += trade.amount;
                    }
                    
                    // Queue socket notification
                    socketNotifications.push({
                        userId: trade.userId._id.toString(),
                        trade: {
                            _id: trade._id,
                            symbol: trade.symbol,
                            direction: trade.direction,
                            amount: trade.amount,
                            result,
                            payout
                        },
                        newBalance: trade.userId.balance + userUpdate.balanceChange
                    });
                }
            }
            
            // Execute bulk operations
            if (bulkOps.length > 0) {
                await Trade.bulkWrite(bulkOps, { ordered: false });
                
                // Update users
                const userBulkOps = [];
                for (const [userId, update] of userUpdates) {
                    userBulkOps.push({
                        updateOne: {
                            filter: { _id: userId },
                            update: {
                                $inc: {
                                    balance: update.balanceChange,
                                    'stats.totalTrades': update.totalTrades,
                                    'stats.winTrades': update.winTrades,
                                    'stats.loseTrades': update.loseTrades,
                                    totalProfit: update.totalProfit,
                                    totalLoss: update.totalLoss
                                }
                            }
                        }
                    });
                }
                
                if (userBulkOps.length > 0) {
                    await User.bulkWrite(userBulkOps, { ordered: false });
                }
                
                // Send socket notifications
                for (const notification of socketNotifications) {
                    io.to(notification.userId).emit('tradeCompleted', notification);
                }
                
                console.log(`✅ Completed ${bulkOps.length} trades`);
            }
        } catch (error) {
            console.error('❌ Error checking trades:', error);
        }
    }, 2000);
}

// ========================================
// 🌐 PUBLIC ROUTES
// ========================================

app.get('/', (req, res) => {
    res.json({
        message: 'TradeStation Backend API - Optimized & Secure',
        version: '4.0.0',
        status: 'Running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        features: {
            security: '✅ Enhanced',
            performance: '✅ Optimized',
            memoryManagement: '✅ Improved',
            rateLimit: '✅ Active',
            monitoring: '✅ Enabled'
        }
    });
});

app.get('/api/health', (req, res) => {
    const memUsage = process.memoryUsage();
    const chartMemory = chartDataStore.getMemoryUsage();
    
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        database: {
            status: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
            readyState: mongoose.connection.readyState
        },
        server: {
            uptime: Math.floor(process.uptime()),
            memory: {
                heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
                heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
                rss: Math.round(memUsage.rss / 1024 / 1024)
            },
            activeSockets: activeSockets.size
        },
        chartData: chartMemory,
        initialized: isInitialized
    });
});

app.get('/api/chart/:symbol/:timeframe', async (req, res) => {
    try {
        const { symbol, timeframe } = req.params;
        
        const validTimeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d'];
        if (!validTimeframes.includes(timeframe)) {
            return res.status(400).json({ 
                error: 'Invalid timeframe',
                validTimeframes
            });
        }
        
        const priceData = await Price.findOne({ symbol: symbol.toUpperCase() }).lean();
        if (!priceData) {
            return res.status(404).json({ error: 'Symbol not found' });
        }
        
        const key = `${symbol.toUpperCase()}-${timeframe}`;
        let chartData = chartDataStore.get(key);
        
        if (!chartData || chartData.length === 0) {
            chartData = await generateHistoricalData(symbol.toUpperCase(), timeframe, 100);
            if (chartData && chartData.length > 0) {
                chartDataStore.set(key, chartData);
            } else {
                return res.status(500).json({ error: 'Failed to generate chart data' });
            }
        }
        
        res.json({
            symbol: symbol.toUpperCase(),
            timeframe,
            candlestick: chartData,
            count: chartData.length,
            currentPrice: priceData.price,
            lastUpdate: priceData.lastUpdate
        });
        
    } catch (error) {
        console.error('❌ Chart data error:', error);
        res.status(500).json({ error: 'Failed to load chart data' });
    }
});

// ========================================
// 🔐 AUTHENTICATION ROUTES
// ========================================

app.post('/api/register', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        
        // Validation
        if (!name || name.trim().length < 2 || name.trim().length > 100) {
            return res.status(400).json({ error: 'Name must be 2-100 characters' });
        }

        if (!password || password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        if (!email && !phone) {
            return res.status(400).json({ error: 'Email or phone number is required' });
        }
        
        if (email && !isValidEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        if (phone && !isValidPhone(phone)) {
            return res.status(400).json({ error: 'Invalid phone format' });
        }
        
        // Check duplicates
        const existingUser = await User.findOne({
            $or: [
                ...(email ? [{ email: email.toLowerCase().trim() }] : []),
                ...(phone ? [{ phone: normalizePhone(phone) }] : [])
            ]
        }).lean();
        
        if (existingUser) {
            return res.status(400).json({ 
                error: existingUser.email === email?.toLowerCase() ? 'Email already registered' : 'Phone number already registered'
            });
        }
        
        // Create user
        const hashedPassword = await bcrypt.hash(password, 12);
        const userData = {
            name: name.trim(),
            password: hashedPassword,
            referralCode: generateReferralCode(),
            balance: 0
        };

        if (email) userData.email = email.toLowerCase().trim();
        if (phone) userData.phone = normalizePhone(phone);
        
        const user = new User(userData);
        await user.save();
        
        await logActivity(user._id, 'USER_REGISTER', `New user: ${email || phone}`, req);
        
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.status(201).json({
            message: 'Registration successful',
            token,
            user: userResponse
        });
        
    } catch (error) {
        console.error('❌ Registration error:', error);
        
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            return res.status(400).json({ 
                error: `${field === 'email' ? 'Email' : 'Phone number'} already registered` 
            });
        }
        
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { email, phone, password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        if (!email && !phone) {
            return res.status(400).json({ error: 'Email or phone number is required' });
        }
        
        let user = null;
        
        if (email && isValidEmail(email)) {
            user = await User.findOne({ email: email.toLowerCase().trim() });
        }
        
        if (!user && phone && isValidPhone(phone)) {
            user = await User.findOne({ phone: normalizePhone(phone) });
        }
        
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        if (!user.isActive) {
            return res.status(400).json({ error: 'Account is deactivated' });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        user.lastLoginAt = new Date();
        await user.save();
        
        await logActivity(user._id, 'USER_LOGIN', `Login: ${email || phone}`, req);
        
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.json({
            message: 'Login successful',
            token,
            user: userResponse
        });
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ========================================
// 👤 USER ROUTES
// ========================================

app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password').lean();
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load profile' });
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { name } = req.body;
        
        const updateData = {};
        if (name && name.trim().length >= 2 && name.trim().length <= 100) {
            updateData.name = name.trim();
        }
        
        const user = await User.findByIdAndUpdate(
            req.userId,
            updateData,
            { new: true, runValidators: true }
        ).select('-password');
        
        await logActivity(req.userId, 'PROFILE_UPDATE', 'Profile updated', req);
        
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

app.get('/api/profile/bank', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('bankData').lean();
        res.json(user.bankData || {});
    } catch (error) {
        res.status(500).json({ error: 'Failed to load bank data' });
    }
});

app.put('/api/profile/bank', authenticateToken, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder } = req.body;
        
        if (!bankName || !accountNumber || !accountHolder) {
            return res.status(400).json({ error: 'All bank data fields are required' });
        }
        
        const user = await User.findByIdAndUpdate(
            req.userId,
            { 
                bankData: { 
                    bankName: bankName.trim().substring(0, 100), 
                    accountNumber: accountNumber.trim().substring(0, 50), 
                    accountHolder: accountHolder.trim().substring(0, 100)
                }
            },
            { new: true }
        );
        
        await logActivity(req.userId, 'BANK_DATA_UPDATE', `Bank: ${bankName}`, req);
        
        res.json(user.bankData);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update bank data' });
    }
});

app.get('/api/bank-accounts/active', async (req, res) => {
    try {
        const accounts = await BankAccount.find({ isActive: true }).select('-__v').lean();
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load bank accounts' });
    }
});

app.get('/api/prices', async (req, res) => {
    try {
        const prices = await Price.find().sort({ symbol: 1 }).select('-__v').lean();
        res.json(prices);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load prices' });
    }
});

// ========================================
// 💰 TRADING ROUTES
// ========================================

app.post('/api/trade', authenticateToken, tradeLimiter, async (req, res) => {
    try {
        const { symbol, direction, amount, duration } = req.body;
        
        // Validation
        if (!symbol || !direction || !amount || !duration) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (!['buy', 'sell'].includes(direction)) {
            return res.status(400).json({ error: 'Direction must be buy or sell' });
        }
        
        const numAmount = Number(amount);
        if (isNaN(numAmount) || numAmount < 500000 || numAmount > 100000000) {
            return res.status(400).json({ error: 'Amount must be between Rp 500,000 and Rp 100,000,000' });
        }
        
        const numDuration = Number(duration);
        if (isNaN(numDuration) || numDuration < 30 || numDuration > 300) {
            return res.status(400).json({ error: 'Duration must be between 30 and 300 seconds' });
        }
        
        // Check user balance
        const user = await User.findById(req.userId);
        if (numAmount > user.balance) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        // Get current price
        const currentPrice = await Price.findOne({ symbol: symbol.toUpperCase() }).lean();
        if (!currentPrice || !currentPrice.price || currentPrice.price <= 0) {
            return res.status(400).json({ error: 'Invalid symbol or price not available' });
        }
        
        // Use transaction for consistency
        const session = await mongoose.startSession();
        session.startTransaction();
        
        try {
            // Deduct amount from user balance
            await User.findByIdAndUpdate(
                req.userId,
                { $inc: { balance: -numAmount } },
                { session }
            );
            
            // Create trade
            const trade = new Trade({
                userId: req.userId,
                symbol: symbol.toUpperCase(),
                direction,
                amount: numAmount,
                duration: numDuration,
                entryPrice: currentPrice.price,
                profitPercentage: user.adminSettings?.profitPercentage || 80
            });
            
            await trade.save({ session });
            await session.commitTransaction();
            
            await logActivity(req.userId, 'TRADE_CREATED', `${symbol.toUpperCase()} ${direction.toUpperCase()} ${formatCurrency(numAmount)}`, req);
            
            io.to(req.userId.toString()).emit('tradeCreated', {
                trade: {
                    _id: trade._id,
                    symbol: trade.symbol,
                    direction: trade.direction,
                    amount: trade.amount,
                    duration: trade.duration,
                    entryPrice: trade.entryPrice
                },
                newBalance: user.balance - numAmount
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
                    status: trade.status,
                    createdAt: trade.createdAt
                },
                newBalance: user.balance - numAmount
            });
            
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
        const { limit = 20, status } = req.query;
        
        let query = { userId: req.userId };
        if (status && ['active', 'completed', 'cancelled'].includes(status)) {
            query.status = status;
        }
        
        const trades = await Trade.find(query)
            .sort({ createdAt: -1 })
            .limit(Math.min(parseInt(limit), 50))
            .select('-__v')
            .lean();
        
        res.json({ trades });
    } catch (error) {
        res.status(500).json({ error: 'Failed to load trades' });
    }
});

// ========================================
// 💳 DEPOSIT & WITHDRAWAL ROUTES
// ========================================

app.post('/api/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount, receipt, fileName, fileType, bankFrom } = req.body;
        
        const numAmount = Number(amount);
        if (isNaN(numAmount) || numAmount < 500000) {
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
        
        // Check file size (base64 estimation)
        const sizeInBytes = (receipt.length * 3) / 4;
        if (sizeInBytes > 5242880) { // 5MB
            return res.status(400).json({ error: 'File size too large. Maximum 5MB allowed.' });
        }
        
        const deposit = new Deposit({
            userId: req.userId,
            amount: numAmount,
            bankFrom: bankFrom?.substring(0, 100) || 'Not specified',
            receipt,
            fileName: fileName?.substring(0, 255) || 'payment_proof',
            fileType,
            fileSize: sizeInBytes
        });
        
        await deposit.save();
        
        await logActivity(req.userId, 'DEPOSIT_REQUEST', formatCurrency(numAmount), req);
        
        res.status(201).json({
            message: 'Deposit request submitted successfully',
            deposit: {
                _id: deposit._id,
                amount: deposit.amount,
                status: deposit.status,
                createdAt: deposit.createdAt
            }
        });
        
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
            .limit(20)
            .lean();
        
        res.json(deposits);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load deposits' });
    }
});

app.post('/api/withdrawal', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;
        
        const numAmount = Number(amount);
        if (isNaN(numAmount) || numAmount < 100000) {
            return res.status(400).json({ error: 'Minimum withdrawal is Rp 100,000' });
        }
        
        const user = await User.findById(req.userId);
        
        if (numAmount > user.balance) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        if (!user.bankData || !user.bankData.bankName) {
            return res.status(400).json({ error: 'Bank data is required. Please update your bank information first.' });
        }
        
        // Fee calculation
        const fee = Math.max(6500, numAmount * 0.01);
        const finalAmount = numAmount - fee;
        
        if (finalAmount <= 0) {
            return res.status(400).json({ error: 'Amount too small after fees' });
        }
        
        const session = await mongoose.startSession();
        session.startTransaction();
        
        try {
            // Deduct amount from user balance
            await User.findByIdAndUpdate(
                req.userId,
                { $inc: { balance: -numAmount } },
                { session }
            );
            
            const withdrawal = new Withdrawal({
                userId: req.userId,
                amount: numAmount,
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
            
            await logActivity(req.userId, 'WITHDRAWAL_REQUEST', `${formatCurrency(numAmount)} (net: ${formatCurrency(finalAmount)})`, req);
            
            res.status(201).json({
                message: 'Withdrawal request submitted successfully',
                withdrawal: {
                    _id: withdrawal._id,
                    amount: withdrawal.amount,
                    fee: withdrawal.fee,
                    finalAmount: withdrawal.finalAmount,
                    status: withdrawal.status,
                    createdAt: withdrawal.createdAt
                },
                newBalance: user.balance - numAmount
            });
            
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
            .limit(20)
            .lean();
        
        res.json(withdrawals);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load withdrawals' });
    }
});

// ========================================
// 👑 ADMIN ROUTES (Simplified)
// ========================================

app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [stats, recentActivities] = await Promise.all([
            Promise.all([
                User.countDocuments(),
                User.countDocuments({ isActive: true }),
                Trade.countDocuments(),
                Trade.countDocuments({ status: 'active' }),
                Deposit.countDocuments(),
                Deposit.countDocuments({ status: 'pending' }),
                Withdrawal.countDocuments(),
                Withdrawal.countDocuments({ status: 'pending' })
            ]).then(([totalUsers, activeUsers, totalTrades, activeTrades, totalDeposits, pendingDeposits, totalWithdrawals, pendingWithdrawals]) => ({
                users: { total: totalUsers, active: activeUsers },
                trades: { total: totalTrades, active: activeTrades },
                deposits: { total: totalDeposits, pending: pendingDeposits },
                withdrawals: { total: totalWithdrawals, pending: pendingWithdrawals }
            })),
            Activity.find()
                .populate('userId', 'name email phone')
                .sort({ createdAt: -1 })
                .limit(10)
                .lean()
        ]);
        
        res.json({ stats, recentActivities });
    } catch (error) {
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { limit = 50 } = req.query;
        const users = await User.find()
            .select('-password')
            .sort({ createdAt: -1 })
            .limit(Math.min(parseInt(limit), 100))
            .lean();
        
        res.json({ users });
    } catch (error) {
        res.status(500).json({ error: 'Failed to load users' });
    }
});

app.put('/api/admin/user/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = { ...req.body };
        
        // Remove sensitive fields
        delete updateData.password;
        delete updateData._id;
        
        // Validate fields
        if (updateData.balance !== undefined) {
            const balance = parseFloat(updateData.balance);
            if (isNaN(balance) || balance < 0) {
                return res.status(400).json({ error: 'Invalid balance' });
            }
            updateData.balance = balance;
        }
        
        const user = await User.findByIdAndUpdate(
            id,
            updateData,
            { new: true, runValidators: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_USER_UPDATE', `Updated: ${user.name}`, req);
        
        res.json({ message: 'User updated successfully', user });
    } catch (error) {
        console.error('❌ Admin user update error:', error);
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
        
        res.json({ deposits });
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
        session.startTransaction();
        
        try {
            const deposit = await Deposit.findById(id).populate('userId').session(session);
            
            if (!deposit) {
                await session.abortTransaction();
                return res.status(404).json({ error: 'Deposit not found' });
            }
            
            if (deposit.status !== 'pending') {
                await session.abortTransaction();
                return res.status(400).json({ error: 'Deposit already processed' });
            }
            
            deposit.status = status;
            deposit.adminNotes = adminNotes?.substring(0, 1000) || '';
            deposit.processedAt = new Date();
            
            if (status === 'approved') {
                await User.findByIdAndUpdate(
                    deposit.userId._id,
                    { $inc: { balance: deposit.amount } },
                    { session }
                );
                
                // Notify user
                setTimeout(() => {
                    io.to(deposit.userId._id.toString()).emit('depositApproved', {
                        amount: deposit.amount,
                        message: 'Your deposit has been approved!'
                    });
                }, 100);
            }
            
            await deposit.save({ session });
            await session.commitTransaction();
            
            await logActivity(req.userId, 'ADMIN_DEPOSIT_PROCESS', `${status.toUpperCase()}: ${formatCurrency(deposit.amount)}`, req);
            
            res.json({ message: `Deposit ${status} successfully` });
            
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

// ========================================
// 🔌 SOCKET.IO OPTIMIZATION
// ========================================

io.on('connection', (socket) => {
    activeSockets.add(socket.id);
    console.log(`👤 User connected: ${socket.id} (Total: ${activeSockets.size})`);
    
    socket.on('join', (userId) => {
        if (userId && typeof userId === 'string') {
            socket.join(userId);
            socket.userId = userId;
        }
    });
    
    socket.on('subscribe_prices', () => {
        socket.join('price_updates');
    });
    
    socket.on('subscribe_charts', (data) => {
        try {
            const { symbol, timeframe } = data;
            if (symbol && timeframe) {
                const roomName = `chart_${symbol}_${timeframe}`;
                socket.join(roomName);
                
                // Send initial data
                const key = `${symbol}-${timeframe}`;
                const chartData = chartDataStore.get(key);
                if (chartData && chartData.length > 0) {
                    const lastCandle = chartData[chartData.length - 1];
                    socket.emit('chartUpdate', {
                        symbol,
                        timeframe,
                        candle: lastCandle
                    });
                }
            }
        } catch (error) {
            console.error('❌ Chart subscription error:', error);
        }
    });
    
    socket.on('disconnect', (reason) => {
        activeSockets.delete(socket.id);
        console.log(`👤 User disconnected: ${socket.id} (Total: ${activeSockets.size})`);
    });
    
    socket.on('error', (error) => {
        console.error('❌ Socket error:', error);
    });
});

// ========================================
// 🛡️ ERROR HANDLING & MONITORING
// ========================================

// Memory monitoring
setInterval(() => {
    const memUsage = process.memoryUsage();
    const heapUsedMB = memUsage.heapUsed / 1024 / 1024;
    
    if (heapUsedMB > 150) {
        console.log(`⚠️ High memory usage: ${heapUsedMB.toFixed(2)}MB`);
        chartDataStore.cleanup();
    }
}, 30000);

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error:', error);
    
    const isDevelopment = process.env.NODE_ENV === 'development';
    res.status(error.status || 500).json({ 
        error: 'Internal server error',
        message: isDevelopment ? error.message : 'Something went wrong'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'Route not found',
        path: req.originalUrl
    });
});

// ========================================
// 🚀 SERVER STARTUP
// ========================================

async function startServer() {
    try {
        // Connect to MongoDB with optimized settings
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000,
            maxPoolSize: 5, // Reduced from default 10
            minPoolSize: 1,
            maxIdleTimeMS: 30000,
            retryWrites: true,
            w: 'majority'
        });
        
        console.log('✅ Connected to MongoDB');
        
        // Initialize default admin user
        const adminPassword = process.env.ADMIN_PASSWORD || generateSecurePassword();
        const adminExists = await User.findOne({ email: 'admin@tradestation.com' });
        
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(adminPassword, 12);
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
            console.log(`📧 Email: admin@tradestation.com`);
            console.log(`🔑 Password: ${adminPassword}`);
        }
        
        // Initialize sample bank accounts
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
            
            await BankAccount.insertMany(sampleBanks);
            console.log('✅ Sample bank accounts created');
        }
        
        // Initialize prices and chart data
        await initializePrices();
        
        console.log('📊 Initializing chart data...');
        const symbols = await Price.find().lean();
        for (const symbol of symbols) {
            const timeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d'];
            for (const timeframe of timeframes) {
                const key = `${symbol.symbol}-${timeframe}`;
                const historicalData = await generateHistoricalData(symbol.symbol, timeframe, 100);
                chartDataStore.set(key, historicalData);
            }
        }
        
        console.log(`✅ Chart data initialized: ${chartDataStore.size} datasets`);
        
        isInitialized = true;
        
        // Start background processes
        simulatePriceUpdates();
        checkTradesToComplete();
        
        // Start server
        const PORT = process.env.PORT || 3000;
        server.listen(PORT, '0.0.0.0', () => {
            console.log(`
🚀 TradeStation Backend Server Started - Optimized & Secure!
📍 Port: ${PORT}
🌍 Environment: ${process.env.NODE_ENV || 'development'}

✅ SECURITY IMPROVEMENTS:
🔒 JWT Secret Validation
🛡️ Enhanced Rate Limiting  
🔐 Secure Admin Credentials
📝 Input Validation & Sanitization

✅ PERFORMANCE OPTIMIZATIONS:
🧠 Memory Management
⚡ Database Query Optimization
🔄 Efficient Socket.io Handling
📊 Smart Chart Data Caching

✅ STABILITY ENHANCEMENTS:
💾 Transaction Support
🛠️ Better Error Handling
📈 Resource Monitoring
🧹 Automatic Cleanup

⏰ Timestamp: ${new Date().toISOString()}
            `);
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

// Graceful shutdown
const shutdown = () => {
    console.log('💤 Shutting down gracefully...');
    server.close(() => {
        mongoose.connection.close();
        process.exit(0);
    });
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Start the server
startServer();

// =====================
// ✅ REGISTER ROUTE
// =====================
app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;

        if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Nama minimal 2 karakter' });
        if (!password || password.length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
        if (!email && !phone) return res.status(400).json({ error: 'Email atau nomor HP diperlukan' });

        let finalEmail = null;
        let finalPhone = null;

        if (email) {
            if (!isValidEmail(email)) return res.status(400).json({ error: 'Format email tidak valid' });
            finalEmail = email.toLowerCase().trim();
        }

        if (phone) {
            if (!isValidPhone(phone)) return res.status(400).json({ error: 'Format nomor HP tidak valid' });
            finalPhone = normalizePhone(phone);
        }

        if (finalEmail) {
            const existingEmail = await User.findOne({ email: finalEmail });
            if (existingEmail) return res.status(400).json({ error: 'Email sudah terdaftar' });
        }
        if (finalPhone) {
            const existingPhone = await User.findOne({ phone: finalPhone });
            if (existingPhone) return res.status(400).json({ error: 'Nomor HP sudah terdaftar' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({
            name: name.trim(),
            email: finalEmail,
            phone: finalPhone,
            password: hashedPassword,
            referralCode: generateReferralCode(),
        });
        await newUser.save();

        return res.status(201).json({ message: 'Registrasi berhasil', userId: newUser._id });
    } catch (err) {
        console.error('Register Error:', err);
        return res.status(500).json({ error: 'Terjadi kesalahan saat registrasi' });
    }
});

// =====================
// ✅ LOGIN ROUTE
// =====================
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { emailOrPhone, password } = req.body;

        if (!emailOrPhone || !password) return res.status(400).json({ error: 'Email/Nomor HP dan password wajib diisi' });

        let user = null;
        if (isValidEmail(emailOrPhone)) {
            user = await User.findOne({ email: emailOrPhone.toLowerCase().trim() });
        } else if (isValidPhone(emailOrPhone)) {
            user = await User.findOne({ phone: normalizePhone(emailOrPhone) });
        } else {
            return res.status(400).json({ error: 'Format email atau nomor HP tidak valid' });
        }

        if (!user) return res.status(404).json({ error: 'Akun tidak ditemukan' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Password salah' });

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        return res.json({ message: 'Login berhasil', token });
    } catch (err) {
        console.error('Login Error:', err);
        return res.status(500).json({ error: 'Terjadi kesalahan saat login' });
    }
});

module.exports = app;
