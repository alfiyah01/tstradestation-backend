const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const socketIo = require('socket.io');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

// ========================================
// APP SETUP & CONFIGURATION
// ========================================
const app = express();
const server = http.createServer(app);

// Socket.IO Configuration
const io = socketIo(server, {
    cors: {
        origin: [
            "https://www.traderstasion.com",
            "https://traderstasion.com",
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5500",
            "http://localhost:8080"
        ],
        methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
        credentials: true,
        allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
    },
    transports: ['websocket', 'polling'],
    pingTimeout: 60000,
    pingInterval: 25000,
    maxHttpBufferSize: 1e6
});

// ========================================
// MIDDLEWARE CONFIGURATION
// ========================================

// Security middleware
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false // Disable for development - enable in production
}));

// CORS Configuration
app.use(cors({
    origin: [
        "https://www.traderstasion.com",
        "https://traderstasion.com", 
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5500",
        "http://localhost:8080"
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
    exposedHeaders: ['Content-Length', 'X-Foo', 'X-Bar']
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // Increased for development
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Increased for development
    message: { error: 'Too many login attempts, please try again after 15 minutes.' },
    skipSuccessfulRequests: true
});

app.use('/api', limiter);
app.use('/api/login', loginLimiter);

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only JPG, JPEG, and PNG files are allowed'), false);
        }
    }
});

// ========================================
// DATABASE CONNECTION
// ========================================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/tradestation';

// MongoDB connection with Railway-compatible options
const connectDB = async () => {
    try {
        const conn = await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
            connectTimeoutMS: 10000,
            heartbeatFrequencyMS: 10000,
            retryWrites: true,
            w: 'majority'
        });

        console.log('✅ Connected to MongoDB');
        console.log('📍 Database Host:', conn.connection.host);
        console.log('📍 Database Name:', conn.connection.name);
        console.log('📍 Connection State:', conn.connection.readyState);
        
        // Initialize data after successful connection
        await initializeData();
        
    } catch (err) {
        console.error('❌ MongoDB connection error:', err);
        console.error('❌ Connection String:', MONGODB_URI.replace(/:[^:@]*@/, ':****@'));
        
        // Retry connection after 5 seconds
        setTimeout(() => {
            console.log('🔄 Retrying MongoDB connection...');
            connectDB();
        }, 5000);
    }
};

// Start database connection
connectDB();

// Handle MongoDB connection events
mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('❌ MongoDB disconnected - attempting to reconnect...');
    setTimeout(() => {
        connectDB();
    }, 1000);
});

mongoose.connection.on('reconnected', () => {
    console.log('✅ MongoDB reconnected');
});

mongoose.connection.on('connected', () => {
    console.log('🔌 MongoDB connection established');
});

mongoose.connection.on('connecting', () => {
    console.log('🔄 Connecting to MongoDB...');
});

// ========================================
// DATABASE SCHEMAS & MODELS
// ========================================

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { 
        type: String, 
        unique: true, 
        sparse: true,
        lowercase: true,
        trim: true,
        validate: {
            validator: function(v) {
                return !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: 'Invalid email format'
        }
    },
    phone: { 
        type: String, 
        unique: true, 
        sparse: true,
        validate: {
            validator: function(v) {
                return !v || /^(628\d{8,11}|62\d{9,12}|08\d{8,11})$/.test(v);
            },
            message: 'Invalid phone format'
        }
    },
    password: { type: String, required: true, minlength: 6 },
    balance: { type: Number, default: 0, min: 0 },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    bankName: { type: String, trim: true },
    accountNumber: { type: String, trim: true },
    accountHolder: { type: String, trim: true },
    stats: {
        totalTrades: { type: Number, default: 0 },
        winTrades: { type: Number, default: 0 },
        loseTrades: { type: Number, default: 0 },
        winRate: { type: Number, default: 0 }
    },
    referralCode: { 
        type: String, 
        unique: true,
        uppercase: true
    },
    taxPaid: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] },
    lastLogin: { type: Date, default: Date.now },
    ipAddress: String
}, {
    timestamps: true,
    toJSON: { 
        virtuals: true,
        transform: function(doc, ret) {
            delete ret.password;
            return ret;
        }
    },
    toObject: { virtuals: true }
});

// Trade Schema
const tradeSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true,
        index: true
    },
    symbol: { 
        type: String, 
        required: true,
        enum: ['BTC', 'ETH', 'LTC', 'XRP', 'DOGE', 'TRX']
    },
    direction: { 
        type: String, 
        required: true, 
        enum: ['buy', 'sell'] 
    },
    amount: { 
        type: Number, 
        required: true, 
        min: 500000, 
        max: 100000000 
    },
    duration: { 
        type: Number, 
        required: true,
        min: 30,
        max: 600
    },
    entryPrice: { type: Number, required: true },
    exitPrice: { type: Number },
    result: { type: String, enum: ['win', 'lose'] },
    payout: { type: Number, default: 0 },
    status: { 
        type: String, 
        default: 'active', 
        enum: ['active', 'completed'],
        index: true
    },
    profitPercentage: { type: Number, default: 80 },
    completedAt: Date
}, { 
    timestamps: true,
    index: { userId: 1, status: 1, createdAt: -1 }
});

// Deposit Schema
const depositSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true,
        index: true
    },
    amount: { 
        type: Number, 
        required: true, 
        min: 500000 
    },
    method: { 
        type: String, 
        required: true, 
        enum: ['bank', 'qris'],
        default: 'bank'
    },
    receipt: { type: String, required: true }, // base64 encoded image
    fileName: String,
    fileType: String,
    status: { 
        type: String, 
        default: 'pending', 
        enum: ['pending', 'approved', 'rejected'],
        index: true
    },
    adminNotes: String,
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    processedAt: Date
}, { 
    timestamps: true,
    index: { status: 1, createdAt: -1 }
});

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true,
        index: true
    },
    amount: { 
        type: Number, 
        required: true, 
        min: 100000 
    },
    fee: { type: Number, required: true },
    finalAmount: { type: Number, required: true },
    status: { 
        type: String, 
        default: 'pending', 
        enum: ['pending', 'approved', 'processed', 'rejected'],
        index: true
    },
    adminNotes: String,
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    processedAt: Date,
    bankInfo: {
        bankName: String,
        accountNumber: String,
        accountHolder: String
    }
}, { 
    timestamps: true,
    index: { status: 1, createdAt: -1 }
});

// Bank Account Schema
const bankAccountSchema = new mongoose.Schema({
    bankName: { type: String, required: true, trim: true },
    accountNumber: { type: String, required: true, trim: true },
    accountHolder: { type: String, required: true, trim: true },
    isActive: { type: Boolean, default: true },
    note: { type: String, trim: true },
    qrCode: String // For QRIS
}, { timestamps: true });

// Crypto Price Schema
const cryptoPriceSchema = new mongoose.Schema({
    symbol: { 
        type: String, 
        required: true, 
        unique: true,
        enum: ['BTC', 'ETH', 'LTC', 'XRP', 'DOGE', 'TRX']
    },
    price: { type: Number, required: true, min: 0 },
    change: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: Date.now }
});

// Tax Schema
const taxSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true, 
        unique: true,
        index: true
    },
    totalProfit: { type: Number, required: true },
    taxAmount: { type: Number, required: true },
    taxPercentage: { type: Number, default: 10 },
    threshold: { type: Number, default: 50000000 }, // 50 million
    isPaid: { type: Boolean, default: false },
    paidAt: Date,
    notes: String,
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { 
    timestamps: true,
    index: { isPaid: 1 }
});

// Create Models
const User = mongoose.model('User', userSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const BankAccount = mongoose.model('BankAccount', bankAccountSchema);
const CryptoPrice = mongoose.model('CryptoPrice', cryptoPriceSchema);
const Tax = mongoose.model('Tax', taxSchema);

// ========================================
// AUTHENTICATION MIDDLEWARE
// ========================================
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user || !user.isActive) {
            return res.status(403).json({ error: 'User not found or inactive' });
        }
        
        req.user = user;
        next();
    } catch (error) {
        console.error('❌ Token verification error:', error);
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

const adminOnly = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ========================================
// UTILITY FUNCTIONS
// ========================================
const generateReferralCode = () => {
    return 'TS' + Math.random().toString(36).substr(2, 6).toUpperCase();
};

const calculateStats = (trades) => {
    const totalTrades = trades.length;
    const winTrades = trades.filter(t => t.result === 'win').length;
    const loseTrades = trades.filter(t => t.result === 'lose').length;
    const winRate = totalTrades > 0 ? Math.round((winTrades / totalTrades) * 100) : 0;
    
    return { totalTrades, winTrades, loseTrades, winRate };
};

const formatCurrency = (amount) => {
    return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR'
    }).format(amount || 0);
};

const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

const isValidPhone = (phone) => {
    const phoneRegex = /^(628\d{8,11}|62\d{9,12}|08\d{8,11})$/;
    return phoneRegex.test(phone.replace(/[^\d]/g, ''));
};

const normalizePhone = (phone) => {
    let cleaned = phone.replace(/[^\d]/g, '');
    if (cleaned.startsWith('08')) {
        return '628' + cleaned.substring(2);
    }
    if (cleaned.startsWith('8') && cleaned.length >= 10) {
        return '62' + cleaned;
    }
    return cleaned;
};

// ========================================
// SOCKET.IO HANDLERS
// ========================================
const connectedUsers = new Map();

io.on('connection', (socket) => {
    console.log('🔌 User connected:', socket.id);

    socket.on('join', (userId) => {
        if (userId) {
            socket.userId = userId;
            connectedUsers.set(userId, socket.id);
            socket.join(`user_${userId}`);
            console.log(`✅ User ${userId} joined room`);
        }
    });

    socket.on('subscribe_prices', () => {
        socket.join('price_updates');
        console.log('📊 User subscribed to price updates');
    });

    socket.on('subscribe_charts', (data) => {
        if (data && data.symbol && data.timeframe) {
            socket.join(`chart_${data.symbol}_${data.timeframe}`);
            console.log(`📈 User subscribed to ${data.symbol} ${data.timeframe} chart`);
        }
    });

    socket.on('pause_updates', () => {
        socket.paused = true;
    });

    socket.on('resume_updates', () => {
        socket.paused = false;
    });

    socket.on('disconnect', (reason) => {
        if (socket.userId) {
            connectedUsers.delete(socket.userId);
            console.log(`❌ User ${socket.userId} disconnected: ${reason}`);
        }
    });

    socket.on('error', (error) => {
        console.error('❌ Socket error:', error);
    });
});

// ========================================
// CRYPTO PRICE SIMULATION
// ========================================
const updateCryptoPrices = async () => {
    try {
        // Check if database is connected
        if (mongoose.connection.readyState !== 1) {
            console.log('⏸️  Skipping price update - database not connected');
            return;
        }

        const symbols = ['BTC', 'ETH', 'LTC', 'XRP', 'DOGE', 'TRX'];
        
        for (const symbol of symbols) {
            try {
                let price = await CryptoPrice.findOne({ symbol });
                
                if (!price) {
                    // Initialize with base prices
                    const basePrices = {
                        BTC: 45000,
                        ETH: 3200,
                        LTC: 180,
                        XRP: 0.65,
                        DOGE: 0.08,
                        TRX: 0.12
                    };
                    
                    price = new CryptoPrice({
                        symbol,
                        price: basePrices[symbol],
                        change: 0
                    });
                }

                // Simulate realistic price movement
                const volatility = {
                    BTC: 0.003,
                    ETH: 0.004,
                    LTC: 0.005,
                    XRP: 0.008,
                    DOGE: 0.015,
                    TRX: 0.010
                }[symbol] || 0.005;

                const randomChange = (Math.random() - 0.5) * volatility;
                const trend = Math.sin(Date.now() / 100000) * 0.001; // Long-term trend
                const oldPrice = price.price;
                const newPrice = Math.max(0.001, oldPrice * (1 + randomChange + trend));
                const changePercent = ((newPrice - oldPrice) / oldPrice) * 100;

                price.price = newPrice;
                price.change = changePercent;
                price.lastUpdated = new Date();

                await price.save();

                // Emit to connected clients (exclude paused sockets)
                const room = io.sockets.adapter.rooms.get('price_updates');
                if (room) {
                    room.forEach(socketId => {
                        const socket = io.sockets.sockets.get(socketId);
                        if (socket && !socket.paused) {
                            socket.emit('priceUpdate', {
                                symbol,
                                price: newPrice,
                                change: changePercent
                            });
                        }
                    });
                }
            } catch (symbolError) {
                console.error(`❌ Error updating ${symbol} price:`, symbolError.message);
            }
        }
    } catch (error) {
        console.error('❌ Error updating crypto prices:', error.message);
        
        // If it's a connection error, don't spam logs
        if (!error.message.includes('buffering timed out') && !error.message.includes('connection')) {
            console.error('Full error:', error);
        }
    }
};

// Note: Background processes are started after successful database initialization

// ========================================
// TRADE COMPLETION PROCESSOR
// ========================================
const processCompletedTrades = async () => {
    try {
        // Check if database is connected
        if (mongoose.connection.readyState !== 1) {
            console.log('⏸️  Skipping trade processing - database not connected');
            return;
        }

        const now = new Date();
        const activeTrades = await Trade.find({
            status: 'active'
        }).populate('userId', 'name balance totalProfit totalLoss stats');

        if (activeTrades.length === 0) {
            return; // No active trades to process
        }

        for (const trade of activeTrades) {
            try {
                const timeElapsed = (now.getTime() - trade.createdAt.getTime()) / 1000;
                
                // Check if trade duration has passed
                if (timeElapsed >= trade.duration) {
                    // Get current price
                    const currentPriceData = await CryptoPrice.findOne({ symbol: trade.symbol });
                    const currentPrice = currentPriceData ? currentPriceData.price : trade.entryPrice;

                    // Determine if trade direction is correct
                    const isDirectionCorrect = (trade.direction === 'buy' && currentPrice > trade.entryPrice) ||
                                             (trade.direction === 'sell' && currentPrice < trade.entryPrice);

                    // Apply win rate (80% for demo)
                    const randomWin = Math.random() < 0.8;
                    const finalResult = isDirectionCorrect && randomWin ? 'win' : 'lose';

                    // Calculate payout
                    let payout = 0;
                    if (finalResult === 'win') {
                        payout = Math.floor(trade.amount * (1 + (trade.profitPercentage / 100)));
                    }

                    // Update trade
                    trade.exitPrice = currentPrice;
                    trade.result = finalResult;
                    trade.payout = payout;
                    trade.status = 'completed';
                    trade.completedAt = now;
                    await trade.save();

                    // Update user balance and stats
                    const user = trade.userId;
                    if (!user) {
                        console.error('❌ User not found for trade:', trade._id);
                        continue;
                    }

                    const profit = payout - trade.amount;

                    if (finalResult === 'win') {
                        user.balance += payout;
                        user.totalProfit += profit;
                        user.stats.winTrades += 1;
                    } else {
                        user.totalLoss += trade.amount;
                        user.stats.loseTrades += 1;
                    }

                    user.stats.totalTrades += 1;
                    user.stats.winRate = user.stats.totalTrades > 0 ? 
                        Math.round((user.stats.winTrades / user.stats.totalTrades) * 100) : 0;

                    await user.save();

                    // Check and update tax status
                    await checkAndUpdateTaxStatus(user._id);

                    // Emit to user
                    const socketId = connectedUsers.get(user._id.toString());
                    if (socketId) {
                        io.to(`user_${user._id}`).emit('tradeCompleted', {
                            trade: {
                                _id: trade._id,
                                symbol: trade.symbol,
                                direction: trade.direction,
                                amount: trade.amount,
                                result: finalResult,
                                payout: payout,
                                exitPrice: currentPrice
                            },
                            newBalance: user.balance
                        });
                    }

                    console.log(`✅ Trade completed: ${trade.symbol} ${trade.direction} - ${finalResult} - User: ${user.name} - ${formatCurrency(finalResult === 'win' ? profit : -trade.amount)}`);
                }
            } catch (tradeError) {
                console.error(`❌ Error processing trade ${trade._id}:`, tradeError.message);
            }
        }
    } catch (error) {
        console.error('❌ Error processing completed trades:', error.message);
        
        // If it's a connection error, don't spam logs
        if (!error.message.includes('buffering timed out') && !error.message.includes('connection')) {
            console.error('Full error:', error);
        }
    }
};

// Note: Trade processing is started after successful database initialization

// ========================================
// TAX MANAGEMENT FUNCTIONS
// ========================================
const checkAndUpdateTaxStatus = async (userId) => {
    try {
        // Check if database is connected
        if (mongoose.connection.readyState !== 1) {
            console.log('⏸️  Skipping tax check - database not connected');
            return;
        }

        const user = await User.findById(userId);
        if (!user) {
            console.log('⚠️  User not found for tax check:', userId);
            return;
        }

        const TAX_THRESHOLD = 50000000; // 50 million IDR
        const TAX_PERCENTAGE = 10; // 10%

        if (user.totalProfit >= TAX_THRESHOLD) {
            let taxRecord = await Tax.findOne({ userId });
            
            if (!taxRecord) {
                // Create new tax record
                const taxAmount = Math.floor(user.totalProfit * (TAX_PERCENTAGE / 100));
                
                taxRecord = new Tax({
                    userId,
                    totalProfit: user.totalProfit,
                    taxAmount,
                    taxPercentage: TAX_PERCENTAGE,
                    threshold: TAX_THRESHOLD,
                    isPaid: false
                });
                
                await taxRecord.save();
                console.log(`📋 Tax record created for user ${user.name}: ${formatCurrency(taxAmount)}`);
            } else if (!taxRecord.isPaid) {
                // Update existing unpaid tax record
                const newTaxAmount = Math.floor(user.totalProfit * (TAX_PERCENTAGE / 100));
                taxRecord.totalProfit = user.totalProfit;
                taxRecord.taxAmount = newTaxAmount;
                await taxRecord.save();
            }
        }
    } catch (error) {
        console.error('❌ Error checking tax status:', error.message);
        
        // Don't spam logs for connection errors
        if (!error.message.includes('buffering timed out') && !error.message.includes('connection')) {
            console.error('Full tax error:', error);
        }
    }
};

// ========================================
// API ROUTES
// ========================================

// Health check
app.get('/api/health', async (req, res) => {
    try {
        const dbState = mongoose.connection.readyState;
        const dbStatus = {
            0: 'disconnected',
            1: 'connected', 
            2: 'connecting',
            3: 'disconnecting'
        }[dbState] || 'unknown';

        // Test database connection
        let dbTest = false;
        try {
            await mongoose.connection.db.admin().ping();
            dbTest = true;
        } catch (err) {
            console.log('Database ping failed:', err.message);
        }

        const health = {
            status: dbState === 1 ? 'OK' : 'ERROR',
            timestamp: new Date().toISOString(),
            version: '2.0.0',
            env: process.env.NODE_ENV || 'development',
            database: {
                status: dbStatus,
                connected: dbState === 1,
                ping: dbTest,
                host: mongoose.connection.host || 'unknown',
                name: mongoose.connection.name || 'unknown'
            },
            server: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                connectedUsers: connectedUsers.size
            }
        };

        res.status(dbState === 1 ? 200 : 503).json(health);
    } catch (error) {
        console.error('Health check error:', error);
        res.status(500).json({
            status: 'ERROR',
            timestamp: new Date().toISOString(),
            error: error.message
        });
    }
});

// ========================================
// AUTHENTICATION ROUTES
// ========================================

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { name, identifier, password } = req.body;

        // Validation
        if (!name || !identifier || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (name.length < 2) {
            return res.status(400).json({ error: 'Name must be at least 2 characters' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const isEmail = isValidEmail(identifier);
        let email = null;
        let phone = null;

        if (isEmail) {
            email = identifier.toLowerCase().trim();
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ error: 'Email already registered' });
            }
        } else {
            if (!isValidPhone(identifier)) {
                return res.status(400).json({ error: 'Invalid phone number format' });
            }
            phone = normalizePhone(identifier);
            const existingUser = await User.findOne({ phone });
            if (existingUser) {
                return res.status(400).json({ error: 'Phone number already registered' });
            }
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        let referralCode;
        
        // Generate unique referral code
        do {
            referralCode = generateReferralCode();
        } while (await User.findOne({ referralCode }));

        const user = new User({
            name: name.trim(),
            email,
            phone,
            password: hashedPassword,
            referralCode,
            balance: 0,
            ipAddress: req.ip || req.connection.remoteAddress
        });

        await user.save();

        const token = jwt.sign(
            { userId: user._id, email: user.email, phone: user.phone },
            process.env.JWT_SECRET || 'fallback-secret-key',
            { expiresIn: '30d' }
        );

        const userResponse = user.toObject();
        delete userResponse.password;

        res.status(201).json({
            message: 'Registration successful',
            token,
            user: userResponse
        });

        console.log(`✅ New user registered: ${user.name} (${email || phone})`);
    } catch (error) {
        console.error('❌ Registration error:', error);
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            return res.status(400).json({ error: `${field} already exists` });
        }
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, phone, password } = req.body;

        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        let user;
        if (email) {
            user = await User.findOne({ email: email.toLowerCase().trim() });
        } else if (phone) {
            const normalizedPhone = normalizePhone(phone);
            user = await User.findOne({ phone: normalizedPhone });
        } else {
            return res.status(400).json({ error: 'Email or phone number is required' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!user.isActive) {
            return res.status(403).json({ error: 'Account is deactivated' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        user.lastLogin = new Date();
        user.ipAddress = req.ip || req.connection.remoteAddress;
        await user.save();

        const token = jwt.sign(
            { userId: user._id, email: user.email, phone: user.phone },
            process.env.JWT_SECRET || 'fallback-secret-key',
            { expiresIn: '30d' }
        );

        const userResponse = user.toObject();
        delete userResponse.password;

        res.json({
            message: 'Login successful',
            token,
            user: userResponse
        });

        console.log(`✅ User logged in: ${user.name} (${user.email || user.phone})`);
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ========================================
// PROFILE ROUTES
// ========================================

// Get profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password');
        
        // Update user stats
        const trades = await Trade.find({ userId: req.user._id, status: 'completed' });
        const stats = calculateStats(trades);
        
        user.stats = stats;
        await user.save();

        res.json(user);
    } catch (error) {
        console.error('❌ Profile error:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Get bank data
app.get('/api/profile/bank', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('bankName accountNumber accountHolder');
        res.json({
            bankName: user.bankName || '',
            accountNumber: user.accountNumber || '',
            accountHolder: user.accountHolder || ''
        });
    } catch (error) {
        console.error('❌ Bank data error:', error);
        res.status(500).json({ error: 'Failed to fetch bank data' });
    }
});

// Update bank data
app.put('/api/profile/bank', authenticateToken, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder } = req.body;

        if (!bankName || !accountNumber || !accountHolder) {
            return res.status(400).json({ error: 'All bank fields are required' });
        }

        const user = await User.findById(req.user._id);
        user.bankName = bankName.trim();
        user.accountNumber = accountNumber.trim();
        user.accountHolder = accountHolder.trim();
        
        await user.save();

        res.json({
            message: 'Bank data updated successfully',
            bankData: {
                bankName: user.bankName,
                accountNumber: user.accountNumber,
                accountHolder: user.accountHolder
            }
        });

        console.log(`✅ Bank data updated: ${user.name}`);
    } catch (error) {
        console.error('❌ Bank update error:', error);
        res.status(500).json({ error: 'Failed to update bank data' });
    }
});

// ========================================
// CRYPTO PRICE ROUTES
// ========================================

// Get prices
app.get('/api/prices', authenticateToken, async (req, res) => {
    try {
        const prices = await CryptoPrice.find({}).sort({ symbol: 1 });
        res.json(prices);
    } catch (error) {
        console.error('❌ Prices error:', error);
        res.status(500).json({ error: 'Failed to fetch prices' });
    }
});

// ========================================
// TRADING ROUTES
// ========================================

// Create trade
app.post('/api/trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, direction, amount, duration } = req.body;

        // Validation
        if (!symbol || !direction || !amount || !duration) {
            return res.status(400).json({ error: 'All trade fields are required' });
        }

        if (amount < 500000 || amount > 100000000) {
            return res.status(400).json({ error: 'Trade amount must be between Rp 500,000 and Rp 100,000,000' });
        }

        if (!['buy', 'sell'].includes(direction)) {
            return res.status(400).json({ error: 'Direction must be buy or sell' });
        }

        if (!['BTC', 'ETH', 'LTC', 'XRP', 'DOGE', 'TRX'].includes(symbol)) {
            return res.status(400).json({ error: 'Invalid trading symbol' });
        }

        if (duration < 30 || duration > 600) {
            return res.status(400).json({ error: 'Duration must be between 30 and 600 seconds' });
        }

        const user = await User.findById(req.user._id);
        if (user.balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        // Get current price
        const priceData = await CryptoPrice.findOne({ symbol });
        const entryPrice = priceData ? priceData.price : 45000; // fallback price

        // Deduct amount from user balance
        user.balance -= amount;
        await user.save();

        // Create trade
        const trade = new Trade({
            userId: req.user._id,
            symbol,
            direction,
            amount,
            duration,
            entryPrice,
            profitPercentage: 80 // 80% profit rate
        });

        await trade.save();

        // Emit to user
        const socketId = connectedUsers.get(req.user._id.toString());
        if (socketId) {
            io.to(`user_${req.user._id}`).emit('tradeCreated', {
                trade,
                newBalance: user.balance
            });
        }

        res.json({
            message: 'Trade created successfully',
            trade,
            newBalance: user.balance
        });

        console.log(`📈 Trade created: ${user.name} - ${symbol} ${direction} ${formatCurrency(amount)} for ${duration}s`);
    } catch (error) {
        console.error('❌ Trade error:', error);
        res.status(500).json({ error: 'Failed to create trade' });
    }
});

// Get trades
app.get('/api/trades', authenticateToken, async (req, res) => {
    try {
        const { status, limit = 50 } = req.query;
        
        let filter = { userId: req.user._id };
        if (status) {
            filter.status = status;
        }

        const trades = await Trade.find(filter)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));

        res.json({ trades });
    } catch (error) {
        console.error('❌ Trades fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch trades' });
    }
});

// ========================================
// BANK ACCOUNT ROUTES
// ========================================

// Get active bank accounts for deposit
app.get('/api/bank-accounts/active', authenticateToken, async (req, res) => {
    try {
        const accounts = await BankAccount.find({ isActive: true }).sort({ createdAt: -1 });
        res.json(accounts);
    } catch (error) {
        console.error('❌ Bank accounts error:', error);
        res.status(500).json({ error: 'Failed to fetch bank accounts' });
    }
});

// ========================================
// DEPOSIT ROUTES
// ========================================

// Create deposit
app.post('/api/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount, receipt, fileName, fileType, method = 'bank' } = req.body;

        // Validation
        if (!amount || amount < 500000) {
            return res.status(400).json({ error: 'Minimum deposit amount is Rp 500,000' });
        }

        if (!receipt) {
            return res.status(400).json({ error: 'Receipt image is required' });
        }

        if (!['bank', 'qris'].includes(method)) {
            return res.status(400).json({ error: 'Invalid payment method' });
        }

        // Validate base64 image
        if (!receipt.startsWith('data:image/')) {
            return res.status(400).json({ error: 'Invalid receipt format' });
        }

        const deposit = new Deposit({
            userId: req.user._id,
            amount,
            method,
            receipt,
            fileName: fileName || 'receipt.jpg',
            fileType: fileType || 'image/jpeg'
        });

        await deposit.save();

        res.json({
            message: 'Deposit request submitted successfully',
            deposit: {
                _id: deposit._id,
                amount: deposit.amount,
                method: deposit.method,
                status: deposit.status,
                createdAt: deposit.createdAt
            }
        });

        console.log(`💰 Deposit request: ${req.user.name} - ${formatCurrency(amount)} via ${method}`);
    } catch (error) {
        console.error('❌ Deposit error:', error);
        res.status(500).json({ error: 'Failed to submit deposit request' });
    }
});

// Get deposits
app.get('/api/deposits', authenticateToken, async (req, res) => {
    try {
        const deposits = await Deposit.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .select('-receipt'); // Don't send receipt data to client

        res.json(deposits);
    } catch (error) {
        console.error('❌ Deposits fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch deposits' });
    }
});

// ========================================
// WITHDRAWAL ROUTES
// ========================================

// Create withdrawal
app.post('/api/withdrawal', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;

        // Validation
        if (!amount || amount < 100000) {
            return res.status(400).json({ error: 'Minimum withdrawal amount is Rp 100,000' });
        }

        const user = await User.findById(req.user._id);

        // Check if user has bank data
        if (!user.bankName || !user.accountNumber || !user.accountHolder) {
            return res.status(400).json({ 
                error: 'Bank information required',
                details: {
                    instruction: 'Please complete your bank information in Profile section before withdrawing.'
                }
            });
        }

        // Check tax status
        const taxRecord = await Tax.findOne({ userId: req.user._id });
        if (taxRecord && taxRecord.totalProfit >= taxRecord.threshold && !taxRecord.isPaid) {
            return res.status(400).json({ 
                error: 'Tax payment required before withdrawal',
                taxInfo: {
                    required: true,
                    amount: taxRecord.taxAmount,
                    totalProfit: taxRecord.totalProfit
                },
                details: {
                    instruction: 'Please pay your tax obligation through customer service before proceeding with withdrawal.'
                }
            });
        }

        if (user.balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        // Calculate fee: minimum Rp 6,500 or 1%
        const fee = Math.max(6500, Math.floor(amount * 0.01));
        const finalAmount = amount - fee;

        // Deduct from user balance
        user.balance -= amount;
        await user.save();

        // Create withdrawal request
        const withdrawal = new Withdrawal({
            userId: req.user._id,
            amount,
            fee,
            finalAmount,
            bankInfo: {
                bankName: user.bankName,
                accountNumber: user.accountNumber,
                accountHolder: user.accountHolder
            }
        });

        await withdrawal.save();

        res.json({
            message: 'Withdrawal request submitted successfully',
            withdrawal: {
                _id: withdrawal._id,
                amount: withdrawal.amount,
                fee: withdrawal.fee,
                finalAmount: withdrawal.finalAmount,
                status: withdrawal.status,
                createdAt: withdrawal.createdAt
            },
            newBalance: user.balance,
            processing: {
                estimatedTime: '1-24 hours',
                bankInfo: {
                    bankName: user.bankName,
                    accountNumber: user.accountNumber,
                    accountHolder: user.accountHolder
                }
            }
        });

        console.log(`💸 Withdrawal request: ${user.name} - ${formatCurrency(finalAmount)} (fee: ${formatCurrency(fee)}) to ${user.bankName} ${user.accountNumber}`);
    } catch (error) {
        console.error('❌ Withdrawal error:', error);
        res.status(500).json({ error: 'Failed to submit withdrawal request' });
    }
});

// Get withdrawals
app.get('/api/withdrawals', authenticateToken, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.user._id })
            .sort({ createdAt: -1 });

        res.json(withdrawals);
    } catch (error) {
        console.error('❌ Withdrawals fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

// ========================================
// TAX ROUTES
// ========================================

// Get tax status
app.get('/api/tax/status', authenticateToken, async (req, res) => {
    try {
        const taxRecord = await Tax.findOne({ userId: req.user._id });
        
        if (!taxRecord) {
            return res.status(404).json({ error: 'No tax record found' });
        }

        res.json({
            requiresTax: true,
            totalProfit: taxRecord.totalProfit,
            taxAmount: taxRecord.taxAmount,
            taxPercentage: taxRecord.taxPercentage,
            threshold: taxRecord.threshold,
            isPaid: taxRecord.isPaid,
            paidAt: taxRecord.paidAt,
            notes: taxRecord.notes,
            createdAt: taxRecord.createdAt,
            updatedAt: taxRecord.updatedAt
        });
    } catch (error) {
        console.error('❌ Tax status error:', error);
        res.status(500).json({ error: 'Failed to fetch tax status' });
    }
});

// ========================================
// ADMIN ROUTES
// ========================================

// Get admin dashboard stats
app.get('/api/admin/stats', authenticateToken, adminOnly, async (req, res) => {
    try {
        const [
            totalUsers,
            totalDeposits,
            totalWithdrawals,
            totalTrades,
            pendingDeposits,
            pendingWithdrawals,
            activeTrades
        ] = await Promise.all([
            User.countDocuments({ role: 'user' }),
            Deposit.countDocuments(),
            Withdrawal.countDocuments(),
            Trade.countDocuments(),
            Deposit.countDocuments({ status: 'pending' }),
            Withdrawal.countDocuments({ status: 'pending' }),
            Trade.countDocuments({ status: 'active' })
        ]);

        const depositSum = await Deposit.aggregate([
            { $match: { status: 'approved' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        const withdrawalSum = await Withdrawal.aggregate([
            { $match: { status: 'processed' } },
            { $group: { _id: null, total: { $sum: '$finalAmount' } } }
        ]);

        res.json({
            users: {
                total: totalUsers,
                active: await User.countDocuments({ role: 'user', isActive: true }),
                online: connectedUsers.size
            },
            deposits: {
                total: totalDeposits,
                pending: pendingDeposits,
                totalAmount: depositSum[0]?.total || 0
            },
            withdrawals: {
                total: totalWithdrawals,
                pending: pendingWithdrawals,
                totalAmount: withdrawalSum[0]?.total || 0
            },
            trades: {
                total: totalTrades,
                active: activeTrades,
                today: await Trade.countDocuments({
                    createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
                })
            }
        });
    } catch (error) {
        console.error('❌ Admin stats error:', error);
        res.status(500).json({ error: 'Failed to fetch admin stats' });
    }
});

// Get pending deposits
app.get('/api/admin/deposits', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { status = 'pending', page = 1, limit = 20 } = req.query;
        
        const deposits = await Deposit.find({ status })
            .populate('userId', 'name email phone balance')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Deposit.countDocuments({ status });

        res.json({
            deposits,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('❌ Admin deposits error:', error);
        res.status(500).json({ error: 'Failed to fetch deposits' });
    }
});

// Update deposit status
app.patch('/api/admin/deposit/:id', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, adminNotes } = req.body;

        if (!['approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const deposit = await Deposit.findById(id).populate('userId');
        if (!deposit) {
            return res.status(404).json({ error: 'Deposit not found' });
        }

        if (deposit.status !== 'pending') {
            return res.status(400).json({ error: 'Deposit already processed' });
        }

        deposit.status = status;
        deposit.adminNotes = adminNotes || '';
        deposit.processedBy = req.user._id;
        deposit.processedAt = new Date();

        if (status === 'approved') {
            // Add to user balance
            const user = deposit.userId;
            user.balance += deposit.amount;
            await user.save();

            // Emit to user
            const socketId = connectedUsers.get(user._id.toString());
            if (socketId) {
                io.to(`user_${user._id}`).emit('depositApproved', {
                    amount: deposit.amount,
                    newBalance: user.balance
                });
            }
        }

        await deposit.save();

        res.json({
            message: `Deposit ${status} successfully`,
            deposit
        });

        console.log(`✅ Deposit ${status}: ${deposit.userId.name} - ${formatCurrency(deposit.amount)} by ${req.user.name}`);
    } catch (error) {
        console.error('❌ Admin deposit update error:', error);
        res.status(500).json({ error: 'Failed to update deposit' });
    }
});

// Get pending withdrawals
app.get('/api/admin/withdrawals', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { status = 'pending', page = 1, limit = 20 } = req.query;
        
        const withdrawals = await Withdrawal.find({ status })
            .populate('userId', 'name email phone balance bankName accountNumber accountHolder')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Withdrawal.countDocuments({ status });

        res.json({
            withdrawals,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('❌ Admin withdrawals error:', error);
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

// Update withdrawal status
app.patch('/api/admin/withdrawal/:id', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, adminNotes } = req.body;

        if (!['approved', 'processed', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const withdrawal = await Withdrawal.findById(id).populate('userId');
        if (!withdrawal) {
            return res.status(404).json({ error: 'Withdrawal not found' });
        }

        if (withdrawal.status === 'processed' || withdrawal.status === 'rejected') {
            return res.status(400).json({ error: 'Withdrawal already processed' });
        }

        withdrawal.status = status;
        withdrawal.adminNotes = adminNotes || '';
        withdrawal.processedBy = req.user._id;
        withdrawal.processedAt = new Date();

        if (status === 'rejected') {
            // Return money to user balance
            const user = withdrawal.userId;
            user.balance += withdrawal.amount;
            await user.save();

            // Emit balance update to user
            const socketId = connectedUsers.get(user._id.toString());
            if (socketId) {
                io.to(`user_${user._id}`).emit('balanceUpdated', {
                    newBalance: user.balance,
                    reason: 'Withdrawal rejected'
                });
            }
        }

        await withdrawal.save();

        res.json({
            message: `Withdrawal ${status} successfully`,
            withdrawal
        });

        console.log(`✅ Withdrawal ${status}: ${withdrawal.userId.name} - ${formatCurrency(withdrawal.finalAmount)} by ${req.user.name}`);
    } catch (error) {
        console.error('❌ Admin withdrawal update error:', error);
        res.status(500).json({ error: 'Failed to update withdrawal' });
    }
});

// Update tax status
app.patch('/api/admin/tax/:userId', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { userId } = req.params;
        const { isPaid, notes } = req.body;

        const taxRecord = await Tax.findOne({ userId });
        if (!taxRecord) {
            return res.status(404).json({ error: 'Tax record not found' });
        }

        taxRecord.isPaid = isPaid;
        taxRecord.notes = notes || '';
        
        if (isPaid) {
            taxRecord.paidAt = new Date();
            taxRecord.processedBy = req.user._id;
        } else {
            taxRecord.paidAt = null;
        }

        await taxRecord.save();

        // Emit real-time update to user
        const socketId = connectedUsers.get(userId);
        if (socketId) {
            io.to(`user_${userId}`).emit('tax_status_updated', {
                userId,
                isPaid,
                paidAt: taxRecord.paidAt,
                notes: taxRecord.notes,
                taxAmount: taxRecord.taxAmount,
                totalProfit: taxRecord.totalProfit
            });
        }

        res.json({
            message: `Tax status updated successfully`,
            taxRecord
        });

        const user = await User.findById(userId);
        console.log(`📋 Tax ${isPaid ? 'marked as paid' : 'marked as unpaid'}: ${user?.name} (${formatCurrency(taxRecord.taxAmount)}) by ${req.user.name}`);
    } catch (error) {
        console.error('❌ Admin tax update error:', error);
        res.status(500).json({ error: 'Failed to update tax status' });
    }
});

// Add bank account
app.post('/api/admin/bank-accounts', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder, note } = req.body;

        if (!bankName || !accountNumber || !accountHolder) {
            return res.status(400).json({ error: 'All bank fields are required' });
        }

        const bankAccount = new BankAccount({
            bankName: bankName.trim(),
            accountNumber: accountNumber.trim(),
            accountHolder: accountHolder.trim(),
            note: note ? note.trim() : ''
        });

        await bankAccount.save();

        res.json({
            message: 'Bank account added successfully',
            bankAccount
        });

        console.log(`✅ Bank account added: ${bankName} ${accountNumber} by ${req.user.name}`);
    } catch (error) {
        console.error('❌ Admin bank account error:', error);
        res.status(500).json({ error: 'Failed to add bank account' });
    }
});

// Get all bank accounts (admin)
app.get('/api/admin/bank-accounts', authenticateToken, adminOnly, async (req, res) => {
    try {
        const accounts = await BankAccount.find({}).sort({ createdAt: -1 });
        res.json(accounts);
    } catch (error) {
        console.error('❌ Admin bank accounts error:', error);
        res.status(500).json({ error: 'Failed to fetch bank accounts' });
    }
});

// Update bank account status
app.patch('/api/admin/bank-account/:id', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { id } = req.params;
        const { isActive } = req.body;

        const account = await BankAccount.findById(id);
        if (!account) {
            return res.status(404).json({ error: 'Bank account not found' });
        }

        account.isActive = isActive;
        await account.save();

        res.json({
            message: `Bank account ${isActive ? 'activated' : 'deactivated'} successfully`,
            account
        });

        console.log(`✅ Bank account ${isActive ? 'activated' : 'deactivated'}: ${account.bankName} ${account.accountNumber} by ${req.user.name}`);
    } catch (error) {
        console.error('❌ Admin bank account update error:', error);
        res.status(500).json({ error: 'Failed to update bank account' });
    }
});

// ========================================
// STATIC FILES & ROUTES
// ========================================

// Serve static files
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: false,
    lastModified: false
}));

// Serve index.html for all non-API routes
app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) {
        return next(); // Let it go to 404 handler
    }
    
    res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
        if (err) {
            console.error('❌ Error serving index.html:', err);
            res.status(500).send('Internal Server Error');
        }
    });
});

// ========================================
// ERROR HANDLING
// ========================================

// Multer error handler
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File size too large. Maximum 5MB allowed.' });
        }
        return res.status(400).json({ error: error.message });
    }
    
    if (error.message === 'Only JPG, JPEG, and PNG files are allowed') {
        return res.status(400).json({ error: error.message });
    }
    
    next(error);
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error:', error);
    
    // Don't send error details in production
    const isDevelopment = process.env.NODE_ENV !== 'production';
    
    res.status(500).json({ 
        error: 'Internal server error',
        ...(isDevelopment && { details: error.message })
    });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
});

// ========================================
// DATABASE INITIALIZATION
// ========================================
const initializeData = async () => {
    try {
        // Wait for connection to be ready
        if (mongoose.connection.readyState !== 1) {
            console.log('⏳ Waiting for MongoDB connection...');
            await new Promise((resolve) => {
                mongoose.connection.once('connected', resolve);
            });
        }

        console.log('🔄 Initializing database data...');

        // Create admin user if not exists
        const adminExists = await User.findOne({ role: 'admin' });
        if (!adminExists) {
            const adminPassword = await bcrypt.hash('admin123456', 12);
            const admin = new User({
                name: 'TradeStation Admin',
                email: 'admin@traderstasion.com',
                password: adminPassword,
                role: 'admin',
                referralCode: 'TSADMIN',
                balance: 0,
                isActive: true
            });
            await admin.save();
            console.log('✅ Admin user created: admin@traderstasion.com / admin123456');
        } else {
            console.log('ℹ️  Admin user already exists');
        }

        // Initialize crypto prices
        const cryptoCount = await CryptoPrice.countDocuments();
        if (cryptoCount === 0) {
            const initialPrices = [
                { symbol: 'BTC', price: 45230.50, change: 2.45 },
                { symbol: 'ETH', price: 3187.25, change: -1.23 },
                { symbol: 'LTC', price: 178.90, change: 0.87 },
                { symbol: 'XRP', price: 0.6521, change: 3.21 },
                { symbol: 'DOGE', price: 0.0823, change: -2.15 },
                { symbol: 'TRX', price: 0.1145, change: 1.45 }
            ];

            await CryptoPrice.insertMany(initialPrices);
            console.log('✅ Initial crypto prices loaded');
        } else {
            console.log('ℹ️  Crypto prices already initialized');
        }

        // Initialize sample bank accounts
        const bankCount = await BankAccount.countDocuments();
        if (bankCount === 0) {
            const bankAccounts = [
                {
                    bankName: 'Bank BCA',
                    accountNumber: '1234567890',
                    accountHolder: 'TradeStation Indonesia',
                    note: 'Transfer ke rekening ini untuk deposit via Bank BCA',
                    isActive: true
                },
                {
                    bankName: 'Bank Mandiri',
                    accountNumber: '9876543210',
                    accountHolder: 'TradeStation Indonesia',
                    note: 'Transfer ke rekening ini untuk deposit via Bank Mandiri',
                    isActive: true
                },
                {
                    bankName: 'Bank BRI',
                    accountNumber: '5555666677',
                    accountHolder: 'TradeStation Indonesia',
                    note: 'Transfer ke rekening ini untuk deposit via Bank BRI',
                    isActive: true
                }
            ];

            await BankAccount.insertMany(bankAccounts);
            console.log('✅ Sample bank accounts created');
        } else {
            console.log('ℹ️  Bank accounts already initialized');
        }

        console.log('✅ Database initialization completed successfully');
        
        // Start background processes after successful initialization
        startBackgroundProcesses();
        
    } catch (error) {
        console.error('❌ Database initialization error:', error);
        console.log('🔄 Retrying initialization in 10 seconds...');
        setTimeout(() => {
            initializeData();
        }, 10000);
    }
};

// Start background processes
const startBackgroundProcesses = () => {
    console.log('🔄 Starting background processes...');
    
    // Start price updates
    setInterval(updateCryptoPrices, 3000);
    console.log('✅ Price update process started (every 3 seconds)');
    
    // Start trade processing  
    setInterval(processCompletedTrades, 5000);
    console.log('✅ Trade processing started (every 5 seconds)');
};

// ========================================
// SERVER STARTUP
// ========================================
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-jwt-secret-key-change-in-production';

// Warn if using fallback JWT secret
if (!process.env.JWT_SECRET) {
    console.log('⚠️  WARNING: Using fallback JWT secret. Set JWT_SECRET environment variable for production.');
}

server.listen(PORT, () => {
    console.log(`
🚀 TradeStation Server Starting!
📍 Port: ${PORT}
🌍 Environment: ${NODE_ENV}
💾 Database: ${MONGODB_URI.includes('localhost') ? 'Local MongoDB' : 'Cloud MongoDB'}
⚡ Socket.IO: Enabled with CORS
🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Configured' : 'Using fallback (set JWT_SECRET)'}
🛡️  Security: Helmet + CORS + Rate Limiting
📱 Static Files: Serving from /public
🔄 Background Processes: Will start after DB connection
    `);
    
    console.log('⏳ Waiting for database connection to complete initialization...');
});

// ========================================
// GRACEFUL SHUTDOWN
// ========================================
const gracefulShutdown = (signal) => {
    console.log(`🔄 ${signal} received, shutting down gracefully...`);
    
    server.close((err) => {
        if (err) {
            console.error('❌ Error during server shutdown:', err);
            process.exit(1);
        }
        
        console.log('✅ HTTP server closed');
        
        mongoose.connection.close(false, (err) => {
            if (err) {
                console.error('❌ Error during database disconnection:', err);
                process.exit(1);
            }
            
            console.log('✅ Database connection closed');
            console.log('👋 TradeStation server shutdown complete');
            process.exit(0);
        });
    });
    
    // Force close after 30 seconds
    setTimeout(() => {
        console.error('❌ Forced shutdown after timeout');
        process.exit(1);
    }, 30000);
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    gracefulShutdown('UNHANDLED_REJECTION');
});

// Export for testing
module.exports = { app, server, io };
