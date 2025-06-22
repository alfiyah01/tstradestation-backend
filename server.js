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
        origin: ["https://ts-traderstation.com", "http://localhost:3000", "http://127.0.0.1:5500", "http://localhost:5500"],
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
    origin: ["https://ts-traderstation.com", "http://localhost:3000", "http://127.0.0.1:5500", "http://localhost:5500"],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: 'Too many requests from this IP, please try again later.' }
});
app.use('/api/', limiter);

// Auth rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: { error: 'Too many authentication attempts, please try again later.' }
});

// ========================================
// DATABASE MODELS
// ========================================

// User Schema - COMPLETE
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String },
    phone: { type: String },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    accountType: { type: String, enum: ['standard', 'premium'], default: 'standard' },
    isActive: { type: Boolean, default: true },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    referralCode: { type: String, unique: true },
    // Bank Data untuk Withdrawal
    bankData: {
        bankName: { type: String },
        accountNumber: { type: String },
        accountHolder: { type: String }
    },
    // Admin Settings untuk User Trading
    adminSettings: {
        forceWin: { type: Boolean, default: false },
        forceWinRate: { type: Number, default: 0 }, // 0-100%
        profitCollapse: { type: String, enum: ['profit', 'collapse', 'normal'], default: 'normal' },
        profitPercentage: { type: Number, default: 80 } // Default 80% profit
    },
    stats: {
        totalTrades: { type: Number, default: 0 },
        winTrades: { type: Number, default: 0 },
        loseTrades: { type: Number, default: 0 }
    },
    lastLoginAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Ensure unique email or phone
userSchema.index({ email: 1 }, { unique: true, sparse: true });
userSchema.index({ phone: 1 }, { unique: true, sparse: true });

// Bank Account Schema untuk Admin Panel
const bankAccountSchema = new mongoose.Schema({
    bankName: { type: String, required: true },
    accountNumber: { type: String, required: true },
    accountHolder: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    note: { type: String },
    createdAt: { type: Date, default: Date.now }
});

// Trade Schema - COMPLETE
const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symbol: { type: String, required: true },
    direction: { type: String, enum: ['buy', 'sell'], required: true },
    amount: { type: Number, required: true },
    duration: { type: Number, required: true }, // in seconds
    entryPrice: { type: Number, required: true },
    exitPrice: { type: Number },
    status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
    result: { type: String, enum: ['win', 'lose'] },
    payout: { type: Number },
    priceChangePercent: { type: Number },
    forceResult: { type: String }, // admin override
    adminForced: { type: Boolean, default: false },
    profitPercentage: { type: Number }, // Diambil dari user settings
    createdAt: { type: Date, default: Date.now },
    completedAt: { type: Date }
});

// Deposit Schema - COMPLETE dengan File Upload
const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    method: { type: String, default: 'Bank Transfer' },
    bankFrom: { type: String },
    receipt: { type: String }, // base64 file data
    fileName: { type: String },
    fileType: { type: String },
    fileSize: { type: Number },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    adminNotes: { type: String },
    transferTime: { type: Date },
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
});

// Withdrawal Schema - COMPLETE
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

// Price Schema - COMPLETE
const priceSchema = new mongoose.Schema({
    symbol: { type: String, required: true, unique: true },
    price: { type: Number, required: true },
    change: { type: Number, default: 0 }, // percentage change
    lastUpdate: { type: Date, default: Date.now }
});

// Activity Schema - COMPLETE
const activitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    details: { type: String },
    createdAt: { type: Date, default: Date.now }
});

// Chart Data Schema - COMPLETE
const chartDataSchema = new mongoose.Schema({
    symbol: { type: String, required: true },
    timeframe: { type: String, required: true }, // 1m, 5m, 15m, 30m, 1h, 4h, 1d
    time: { type: Number, required: true }, // Unix timestamp
    open: { type: Number, required: true },
    high: { type: Number, required: true },
    low: { type: Number, required: true },
    close: { type: Number, required: true },
    volume: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

// Create compound index untuk efficient querying
chartDataSchema.index({ symbol: 1, timeframe: 1, time: 1 }, { unique: true });

// Create models
const User = mongoose.model('User', userSchema);
const BankAccount = mongoose.model('BankAccount', bankAccountSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Price = mongoose.model('Price', priceSchema);
const Activity = mongoose.model('Activity', activitySchema);
const ChartData = mongoose.model('ChartData', chartDataSchema);

// ========================================
// HELPER FUNCTIONS
// ========================================

// Chart Data Management
let chartDataStore = new Map(); // In-memory storage untuk real-time chart data

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

function getTimeframeMinutes(timeframe) {
    const timeframes = {
        '1m': 1,
        '5m': 5,
        '15m': 15,
        '30m': 30,
        '1h': 60,
        '4h': 240,
        '1d': 1440
    };
    return timeframes[timeframe] || 5;
}

function roundTimeToTimeframe(timestamp, timeframe) {
    try {
        const minutes = getTimeframeMinutes(timeframe);
        const roundedMinutes = Math.floor(timestamp / (minutes * 60 * 1000)) * minutes * 60 * 1000;
        return roundedMinutes;
    } catch (error) {
        console.error('Error rounding time:', error);
        return timestamp;
    }
}

// Enhanced candle generation
function generateCandleFromPrice(symbol, timeframe, currentPrice, previousCandle = null) {
    try {
        if (!currentPrice || isNaN(currentPrice)) {
            console.error(`Invalid price for ${symbol}:`, currentPrice);
            return null;
        }

        const now = Date.now();
        const roundedTime = roundTimeToTimeframe(now, timeframe);
        
        // Jika ini candle baru
        if (!previousCandle || previousCandle.time < roundedTime) {
            const volatility = 0.02; // 2% volatility
            
            const open = previousCandle ? previousCandle.close : currentPrice;
            const close = currentPrice;
            
            // Generate realistic high and low
            const high = Math.max(open, close) * (1 + Math.random() * volatility);
            const low = Math.min(open, close) * (1 - Math.random() * volatility);
            
            const volume = Math.floor(Math.random() * 1000000) + 100000;
            
            return {
                time: Math.floor(roundedTime / 1000), // Convert to seconds for TradingView
                open: parseFloat(open.toFixed(8)),
                high: parseFloat(high.toFixed(8)),
                low: parseFloat(low.toFixed(8)),
                close: parseFloat(close.toFixed(8)),
                volume
            };
        } else {
            // Update existing candle
            return {
                ...previousCandle,
                close: parseFloat(currentPrice.toFixed(8)),
                high: Math.max(previousCandle.high, currentPrice),
                low: Math.min(previousCandle.low, currentPrice),
                volume: previousCandle.volume + Math.floor(Math.random() * 10000)
            };
        }
    } catch (error) {
        console.error('Error generating candle:', error);
        return null;
    }
}

// Enhanced historical data generation
async function generateHistoricalData(symbol, timeframe, count = 100) {
    try {
        console.log(`📊 Generating historical data for ${symbol}/${timeframe} (${count} candles)`);
        
        const currentPrice = await Price.findOne({ symbol });
        if (!currentPrice) {
            console.error(`Price not found for symbol: ${symbol}`);
            return [];
        }
        
        const timeframeMs = getTimeframeMinutes(timeframe) * 60 * 1000;
        const now = Date.now();
        const data = [];
        
        let price = currentPrice.price;
        
        // Generate historical candles dengan trend yang realistis
        for (let i = count; i >= 0; i--) {
            const time = Math.floor((now - (i * timeframeMs)) / 1000);
            
            // Add some realistic price movement
            const volatility = 0.015; // 1.5% volatility
            const trendFactor = (Math.random() - 0.48) * volatility; // Slight upward bias
            price = price * (1 + trendFactor);
            
            const open = price;
            const close = price * (1 + (Math.random() - 0.5) * volatility);
            const high = Math.max(open, close) * (1 + Math.random() * volatility * 0.5);
            const low = Math.min(open, close) * (1 - Math.random() * volatility * 0.5);
            const volume = Math.floor(Math.random() * 1000000) + 100000;
            
            const candleData = {
                time,
                open: parseFloat(Math.max(0, open).toFixed(8)),
                high: parseFloat(Math.max(0, high).toFixed(8)),
                low: parseFloat(Math.max(0, low).toFixed(8)),
                close: parseFloat(Math.max(0, close).toFixed(8)),
                volume
            };
            
            // Pastikan OHLC logic benar
            candleData.high = Math.max(candleData.open, candleData.high, candleData.low, candleData.close);
            candleData.low = Math.min(candleData.open, candleData.high, candleData.low, candleData.close);
            
            data.push(candleData);
            price = close;
        }
        
        // Sort by time
        data.sort((a, b) => a.time - b.time);
        
        console.log(`✅ Generated ${data.length} historical candles for ${symbol}/${timeframe}`);
        return data;
        
    } catch (error) {
        console.error('Error generating historical data:', error);
        return [];
    }
}

// Chart data initialization
async function initializeChartDataForSymbol(symbol, timeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d']) {
    try {
        console.log(`📊 Initializing chart data for ${symbol}`);
        
        for (const timeframe of timeframes) {
            const key = `${symbol}-${timeframe}`;
            
            if (!chartDataStore.has(key)) {
                const historicalData = await generateHistoricalData(symbol, timeframe, 100);
                if (historicalData && historicalData.length > 0) {
                    chartDataStore.set(key, historicalData);
                    console.log(`✅ Initialized ${historicalData.length} candles for ${symbol}/${timeframe}`);
                }
            }
        }
    } catch (error) {
        console.error(`❌ Error initializing chart data for ${symbol}:`, error);
    }
}

// Price initialization
async function initializePrices() {
    const defaultPrices = [
        { symbol: 'BTC', price: 45000, change: 2.45 },
        { symbol: 'ETH', price: 3200, change: -1.23 },
        { symbol: 'LTC', price: 180, change: 0.87 },
        { symbol: 'XRP', price: 0.65, change: 3.21 },
        { symbol: 'DOGE', price: 0.08, change: -2.15 },
        { symbol: 'TRX', price: 0.12, change: 1.45 }
    ];

    for (const priceData of defaultPrices) {
        try {
            await Price.findOneAndUpdate(
                { symbol: priceData.symbol },
                priceData,
                { upsert: true, new: true }
            );
            console.log(`✅ Price initialized for ${priceData.symbol}: $${priceData.price}`);
        } catch (error) {
            console.error(`❌ Error initializing price for ${priceData.symbol}:`, error);
        }
    }
}

// Price update simulation
function simulatePriceUpdates() {
    setInterval(async () => {
        try {
            const prices = await Price.find();
            
            for (const price of prices) {
                // Random price change between -3% to +3%
                const baseVolatility = 0.03;
                const timeVolatility = 0.01;
                const totalVolatility = baseVolatility + (Math.random() * timeVolatility);
                
                const changePercent = (Math.random() - 0.5) * totalVolatility;
                const newPrice = Math.max(0.001, price.price * (1 + changePercent));
                const change = ((newPrice - price.price) / price.price) * 100;
                
                price.price = parseFloat(newPrice.toFixed(price.symbol === 'BTC' ? 0 : 6));
                price.change = parseFloat(change.toFixed(2));
                price.lastUpdate = new Date();
                
                await price.save();
                
                // Broadcast price update
                io.emit('priceUpdate', {
                    symbol: price.symbol,
                    price: price.price,
                    change: price.change,
                    lastUpdate: price.lastUpdate
                });
                
                // Update chart data
                const timeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d'];
                
                for (const timeframe of timeframes) {
                    const key = `${price.symbol}-${timeframe}`;
                    const currentCandles = chartDataStore.get(key) || [];
                    const lastCandle = currentCandles[currentCandles.length - 1];
                    
                    const newCandle = generateCandleFromPrice(price.symbol, timeframe, price.price, lastCandle);
                    
                    if (newCandle) {
                        // Update or add new candle
                        if (lastCandle && lastCandle.time === newCandle.time) {
                            currentCandles[currentCandles.length - 1] = newCandle;
                        } else {
                            currentCandles.push(newCandle);
                            if (currentCandles.length > 200) {
                                currentCandles.shift();
                            }
                        }
                        
                        chartDataStore.set(key, currentCandles);
                        
                        // Broadcast chart update
                        if (Math.random() < 0.3) {
                            io.emit('chartUpdate', {
                                symbol: price.symbol,
                                timeframe: timeframe,
                                candle: newCandle
                            });
                        }
                    }
                }
            }
        } catch (error) {
            console.error('❌ Error updating prices:', error);
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
                        
                        // Determine result berdasarkan Admin Settings
                        let result;
                        
                        // Check admin settings first
                        if (trade.userId.adminSettings.profitCollapse === 'profit') {
                            result = 'win';
                            trade.adminForced = true;
                            trade.forceResult = 'win';
                        } else if (trade.userId.adminSettings.profitCollapse === 'collapse') {
                            result = 'lose';
                            trade.adminForced = true;
                            trade.forceResult = 'lose';
                        } else if (trade.forceResult) {
                            result = trade.forceResult;
                            trade.adminForced = true;
                        } else if (trade.userId.adminSettings.forceWin && trade.userId.adminSettings.forceWinRate > 0) {
                            const winChance = Math.random() * 100;
                            if (winChance <= trade.userId.adminSettings.forceWinRate) {
                                result = 'win';
                                trade.adminForced = true;
                            } else {
                                result = 'lose';
                                trade.adminForced = true;
                            }
                        } else {
                            // Natural market result
                            if (trade.direction === 'buy') {
                                result = currentPrice.price > trade.entryPrice ? 'win' : 'lose';
                            } else {
                                result = currentPrice.price < trade.entryPrice ? 'win' : 'lose';
                            }
                        }
                        
                        trade.result = result;
                        
                        // Calculate payout
                        const profitPercentage = trade.profitPercentage || trade.userId.adminSettings.profitPercentage || 80;
                        
                        if (result === 'win') {
                            trade.payout = trade.amount + (trade.amount * profitPercentage / 100);
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
                        
                        await trade.save();
                        await trade.userId.save();
                        
                        // Log activity
                        await logActivity(trade.userId._id, 'TRADE_COMPLETED', `${trade.symbol} ${trade.direction} ${result} ${trade.adminForced ? '(Admin Controlled)' : ''}`);
                        
                        // Notify user via socket
                        io.to(trade.userId._id.toString()).emit('tradeCompleted', {
                            trade,
                            result,
                            payout: trade.payout,
                            newBalance: trade.userId.balance
                        });
                        
                        console.log(`✅ Trade completed: ${trade._id} - ${result} ${trade.adminForced ? '(Admin Controlled)' : ''}`);
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

// ========================================
// PUBLIC ROUTES
// ========================================

// Root route
app.get('/', (req, res) => {
    res.json({
        message: 'TradeStation Backend API',
        version: '3.0.0',
        status: 'Running',
        features: [
            'Email/Phone Authentication',
            'Mobile-First Trading',
            'Real-time Chart Data',
            'Bank Account Management', 
            'File Upload', 
            'Admin Trading Control', 
            'Profit Settings',
            'Enhanced Mobile UI',
            'Complete Admin Panel'
        ],
        endpoints: {
            health: '/api/health',
            register: 'POST /api/register',
            login: 'POST /api/login',
            prices: 'GET /api/prices',
            chart: 'GET /api/chart/:symbol/:timeframe',
            profile: 'GET /api/profile (auth required)',
            bank: 'GET /api/profile/bank (auth required)',
            trading: 'POST /api/trade (auth required)',
            admin: '/api/admin/* (admin required)'
        },
        timestamp: new Date().toISOString()
    });
});

// Health check
app.get('/api/health', (req, res) => {
    const health = {
        status: 'OK', 
        message: 'TradeStation Backend is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: global.dbConnected !== false ? 'Connected' : 'Disconnected',
        port: process.env.PORT || 3000,
        chartDataStatus: `${chartDataStore.size} chart datasets loaded`
    };
    
    res.json(health);
});

// Chart Data Routes
app.get('/api/chart/:symbol/:timeframe', async (req, res) => {
    try {
        const { symbol, timeframe } = req.params;
        
        console.log(`📊 Chart data requested: ${symbol}/${timeframe}`);
        
        // Validate timeframe
        const validTimeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d'];
        if (!validTimeframes.includes(timeframe)) {
            console.error(`❌ Invalid timeframe: ${timeframe}`);
            return res.status(400).json({ 
                error: 'Invalid timeframe',
                validTimeframes: validTimeframes
            });
        }
        
        // Check if symbol exists
        const priceData = await Price.findOne({ symbol: symbol.toUpperCase() });
        if (!priceData) {
            console.error(`❌ Symbol not found: ${symbol}`);
            return res.status(404).json({ 
                error: 'Symbol not found',
                availableSymbols: await Price.find().distinct('symbol')
            });
        }
        
        const key = `${symbol.toUpperCase()}-${timeframe}`;
        let chartData = chartDataStore.get(key);
        
        // Jika belum ada data, generate historical data
        if (!chartData || chartData.length === 0) {
            console.log(`📊 Generating historical data for ${symbol}/${timeframe}`);
            chartData = await generateHistoricalData(symbol.toUpperCase(), timeframe, 100);
            
            if (chartData && chartData.length > 0) {
                chartDataStore.set(key, chartData);
            } else {
                console.error(`❌ Failed to generate chart data for ${symbol}/${timeframe}`);
                return res.status(500).json({ 
                    error: 'Failed to generate chart data',
                    symbol: symbol,
                    timeframe: timeframe
                });
            }
        }
        
        // Validasi data sebelum dikirim
        const validatedData = chartData.filter(candle => 
            candle && 
            typeof candle.time === 'number' &&
            typeof candle.open === 'number' &&
            typeof candle.high === 'number' &&
            typeof candle.low === 'number' &&
            typeof candle.close === 'number' &&
            !isNaN(candle.open) &&
            !isNaN(candle.high) &&
            !isNaN(candle.low) &&
            !isNaN(candle.close)
        );
        
        const response = {
            symbol: symbol.toUpperCase(),
            timeframe,
            candlestick: validatedData,
            count: validatedData.length,
            currentPrice: priceData.price,
            lastUpdate: priceData.lastUpdate
        };
        
        res.json(response);
        
        console.log(`✅ Chart data sent: ${validatedData.length} candles for ${symbol}/${timeframe}`);
        
    } catch (error) {
        console.error('❌ Chart data error:', error);
        res.status(500).json({ 
            error: 'Failed to load chart data',
            message: error.message
        });
    }
});

// ========================================
// AUTH ROUTES
// ========================================

app.post('/api/register', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        
        // Validation
        if (!name || !password) {
            return res.status(400).json({ error: 'Name and password are required' });
        }

        if (!email && !phone) {
            return res.status(400).json({ error: 'Email or phone number is required' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        // Check if user exists
        let existingUser = null;
        if (email) {
            // Validate email format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ error: 'Invalid email format' });
            }
            existingUser = await User.findOne({ email });
        }
        
        if (phone && !existingUser) {
            existingUser = await User.findOne({ phone });
        }
        
        if (existingUser) {
            return res.status(400).json({ error: 'Email or phone already registered' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Create user dengan default profit settings
        const userData = {
            name,
            password: hashedPassword,
            referralCode: generateReferralCode(),
            balance: 0,
            adminSettings: {
                profitPercentage: 80 // Default 80%
            }
        };

        if (email) userData.email = email;
        if (phone) userData.phone = phone;
        
        const user = new User(userData);
        await user.save();
        
        // Log activity
        await logActivity(user._id, 'USER_REGISTER', `New user registered: ${email || phone}`);
        
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
        const { email, phone, password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        if (!email && !phone) {
            return res.status(400).json({ error: 'Email or phone number is required' });
        }
        
        // Find user by email or phone
        let user = null;
        if (email) {
            // Validate email format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ error: 'Invalid email format' });
            }
            user = await User.findOne({ email });
        } else if (phone) {
            user = await User.findOne({ phone });
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
        
        await logActivity(user._id, 'USER_LOGIN', `User logged in: ${email || phone}`);
        
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
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

// ========================================
// USER ROUTES
// ========================================

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

// Bank Data Routes
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
        
        const user = await User.findByIdAndUpdate(
            req.userId,
            { 
                bankData: { bankName, accountNumber, accountHolder }
            },
            { new: true }
        );
        
        await logActivity(req.userId, 'BANK_DATA_UPDATE', `Bank data updated: ${bankName}`);
        
        res.json(user.bankData);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update bank data' });
    }
});

// Active Bank Accounts untuk Deposit
app.get('/api/bank-accounts/active', async (req, res) => {
    try {
        const accounts = await BankAccount.find({ isActive: true });
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load bank accounts' });
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

// ========================================
// TRADING ROUTES
// ========================================

app.post('/api/trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, direction, amount, duration } = req.body;
        
        // Validation
        if (!symbol || !direction || !amount || !duration) {
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
        
        // Get profit percentage dari user settings
        const profitPercentage = req.user.adminSettings?.profitPercentage || 80;
        
        // Deduct amount from user balance
        req.user.balance -= amount;
        await req.user.save();
        
        // Create trade dengan profit percentage dari user settings
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

// ========================================
// DEPOSIT ROUTES
// ========================================

app.post('/api/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount, receipt, fileName, fileType, bankFrom } = req.body;
        
        if (!amount || amount < 500000) {
            return res.status(400).json({ error: 'Minimum deposit is Rp 500,000' });
        }
        
        if (!receipt) {
            return res.status(400).json({ error: 'Payment proof is required' });
        }
        
        // Validate file type
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png'];
        if (!allowedTypes.includes(fileType)) {
            return res.status(400).json({ error: 'Invalid file type' });
        }
        
        const deposit = new Deposit({
            userId: req.userId,
            amount,
            bankFrom,
            receipt,
            fileName,
            fileType,
            transferTime: new Date()
        });
        
        await deposit.save();
        
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

// ========================================
// WITHDRAWAL ROUTES
// ========================================

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
        
        if (!user.bankData || !user.bankData.bankName) {
            return res.status(400).json({ error: 'Bank data is required' });
        }
        
        // Calculate fee
        const fee = Math.max(6500, amount * 0.01);
        const finalAmount = amount - fee;
        
        // Deduct amount from user balance
        user.balance -= amount;
        await user.save();
        
        const withdrawal = new Withdrawal({
            userId: req.userId,
            amount,
            fee,
            finalAmount,
            bankAccount: user.bankData
        });
        
        await withdrawal.save();
        
        await logActivity(req.userId, 'WITHDRAWAL_REQUEST', `Withdrawal request: ${amount}`);
        
        res.status(201).json({
            message: 'Withdrawal request submitted successfully',
            withdrawal,
            newBalance: user.balance
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

// ========================================
// ADMIN ROUTES
// ========================================

// Admin Dashboard
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        // Get statistics
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isActive: true });
        const totalTrades = await Trade.countDocuments();
        const activeTrades = await Trade.countDocuments({ status: 'active' });
        const totalDeposits = await Deposit.countDocuments();
        const pendingDeposits = await Deposit.countDocuments({ status: 'pending' });
        const totalWithdrawals = await Withdrawal.countDocuments();
        const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
        
        // Get volume stats
        const completedTrades = await Trade.find({ status: 'completed' });
        const totalVolume = completedTrades.reduce((sum, trade) => sum + trade.amount, 0);
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayTrades = await Trade.find({ 
            status: 'completed',
            createdAt: { $gte: today }
        });
        const todayVolume = todayTrades.reduce((sum, trade) => sum + trade.amount, 0);
        
        // Get bank accounts stats
        const totalBankAccounts = await BankAccount.countDocuments();
        const activeBankAccounts = await BankAccount.countDocuments({ isActive: true });
        
        // Get recent activities
        const recentActivities = await Activity.find()
            .populate('userId', 'name email')
            .sort({ createdAt: -1 })
            .limit(10);
        
        const stats = {
            users: { total: totalUsers, active: activeUsers },
            trades: { total: totalTrades, active: activeTrades },
            deposits: { total: totalDeposits, pending: pendingDeposits },
            withdrawals: { total: totalWithdrawals, pending: pendingWithdrawals },
            volume: { total: totalVolume, today: todayVolume },
            bankAccounts: { total: totalBankAccounts, active: activeBankAccounts }
        };
        
        res.json({ 
            stats,
            recentActivities
        });
    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

// User Management
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find()
            .select('-password')
            .sort({ createdAt: -1 });
        
        res.json({ users });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Failed to load users' });
    }
});

app.put('/api/admin/user/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = req.body;
        
        // Don't allow updating password through this endpoint
        delete updateData.password;
        
        const user = await User.findByIdAndUpdate(
            id,
            updateData,
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_USER_UPDATE', `Updated user: ${user.name}`);
        
        res.json({ message: 'User updated successfully', user });
    } catch (error) {
        console.error('Admin user update error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.put('/api/admin/user/:id/password', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { newPassword } = req.body;
        
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        
        const user = await User.findByIdAndUpdate(
            id,
            { password: hashedPassword },
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_PASSWORD_CHANGE', `Changed password for user: ${user.name}`);
        
        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Admin password change error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// User Bank Data Management
app.get('/api/admin/user/:id/bank', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findById(id).select('bankData name email');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ bankData: user.bankData });
    } catch (error) {
        console.error('Admin user bank error:', error);
        res.status(500).json({ error: 'Failed to load user bank data' });
    }
});

app.put('/api/admin/user/:id/bank', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { bankName, accountNumber, accountHolder } = req.body;
        
        const user = await User.findByIdAndUpdate(
            id,
            { 
                bankData: { bankName, accountNumber, accountHolder }
            },
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_BANK_UPDATE', `Updated bank data for user: ${user.name}`);
        
        res.json({ message: 'Bank data updated successfully' });
    } catch (error) {
        console.error('Admin user bank update error:', error);
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
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_BANK_DELETE', `Deleted bank data for user: ${user.name}`);
        
        res.json({ message: 'Bank data deleted successfully' });
    } catch (error) {
        console.error('Admin user bank delete error:', error);
        res.status(500).json({ error: 'Failed to delete bank data' });
    }
});

// Trade Management
app.get('/api/admin/trades', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        
        let query = {};
        if (status) {
            query.status = status;
        }
        
        const trades = await Trade.find(query)
            .populate('userId', 'name email')
            .sort({ createdAt: -1 })
            .limit(100);
        
        res.json({ trades });
    } catch (error) {
        console.error('Admin trades error:', error);
        res.status(500).json({ error: 'Failed to load trades' });
    }
});

app.put('/api/admin/trade/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { forceResult } = req.body;
        
        const trade = await Trade.findById(id);
        if (!trade) {
            return res.status(404).json({ error: 'Trade not found' });
        }
        
        if (trade.status !== 'active') {
            return res.status(400).json({ error: 'Can only control active trades' });
        }
        
        trade.forceResult = forceResult;
        await trade.save();
        
        await logActivity(req.userId, 'ADMIN_TRADE_CONTROL', `Controlled trade: ${trade._id} - ${forceResult}`);
        
        res.json({ message: 'Trade control updated successfully' });
    } catch (error) {
        console.error('Admin trade control error:', error);
        res.status(500).json({ error: 'Failed to control trade' });
    }
});

// Deposit Management
app.get('/api/admin/deposits', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        
        let query = {};
        if (status) {
            query.status = status;
        }
        
        const deposits = await Deposit.find(query)
            .populate('userId', 'name email')
            .sort({ createdAt: -1 })
            .limit(100);
        
        res.json({ deposits });
    } catch (error) {
        console.error('Admin deposits error:', error);
        res.status(500).json({ error: 'Failed to load deposits' });
    }
});

app.put('/api/admin/deposit/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, adminNotes } = req.body;
        
        const deposit = await Deposit.findById(id).populate('userId');
        if (!deposit) {
            return res.status(404).json({ error: 'Deposit not found' });
        }
        
        deposit.status = status;
        deposit.adminNotes = adminNotes;
        deposit.processedAt = new Date();
        
        // If approved, add to user balance
        if (status === 'approved') {
            deposit.userId.balance += deposit.amount;
            await deposit.userId.save();
            
            // Notify user via socket
            io.to(deposit.userId._id.toString()).emit('depositApproved', {
                amount: deposit.amount,
                newBalance: deposit.userId.balance
            });
        }
        
        await deposit.save();
        
        await logActivity(req.userId, 'ADMIN_DEPOSIT_PROCESS', `${status} deposit: ${deposit.amount} for ${deposit.userId.name}`);
        
        res.json({ message: `Deposit ${status} successfully` });
    } catch (error) {
        console.error('Admin deposit process error:', error);
        res.status(500).json({ error: 'Failed to process deposit' });
    }
});

// Withdrawal Management
app.get('/api/admin/withdrawals', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        
        let query = {};
        if (status) {
            query.status = status;
        }
        
        const withdrawals = await Withdrawal.find(query)
            .populate('userId', 'name email')
            .sort({ createdAt: -1 })
            .limit(100);
        
        res.json({ withdrawals });
    } catch (error) {
        console.error('Admin withdrawals error:', error);
        res.status(500).json({ error: 'Failed to load withdrawals' });
    }
});

app.put('/api/admin/withdrawal/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, adminNotes } = req.body;
        
        const withdrawal = await Withdrawal.findById(id).populate('userId');
        if (!withdrawal) {
            return res.status(404).json({ error: 'Withdrawal not found' });
        }
        
        withdrawal.status = status;
        withdrawal.adminNotes = adminNotes;
        withdrawal.processedAt = new Date();
        
        // If rejected, return money to user balance
        if (status === 'rejected') {
            withdrawal.userId.balance += withdrawal.amount;
            await withdrawal.userId.save();
        }
        
        await withdrawal.save();
        
        await logActivity(req.userId, 'ADMIN_WITHDRAWAL_PROCESS', `${status} withdrawal: ${withdrawal.amount} for ${withdrawal.userId.name}`);
        
        res.json({ message: `Withdrawal ${status} successfully` });
    } catch (error) {
        console.error('Admin withdrawal process error:', error);
        res.status(500).json({ error: 'Failed to process withdrawal' });
    }
});

// Bank Account Management
app.get('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const accounts = await BankAccount.find().sort({ createdAt: -1 });
        res.json({ accounts });
    } catch (error) {
        console.error('Admin bank accounts error:', error);
        res.status(500).json({ error: 'Failed to load bank accounts' });
    }
});

app.post('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder, note } = req.body;
        
        const account = new BankAccount({
            bankName,
            accountNumber,
            accountHolder,
            note
        });
        
        await account.save();
        
        await logActivity(req.userId, 'ADMIN_BANK_CREATE', `Created bank account: ${bankName} - ${accountNumber}`);
        
        res.status(201).json({ 
            message: 'Bank account created successfully',
            account
        });
    } catch (error) {
        console.error('Admin bank account create error:', error);
        res.status(500).json({ error: 'Failed to create bank account' });
    }
});

app.put('/api/admin/bank-accounts/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = req.body;
        
        const account = await BankAccount.findByIdAndUpdate(
            id,
            updateData,
            { new: true }
        );
        
        if (!account) {
            return res.status(404).json({ error: 'Bank account not found' });
        }
        
        await logActivity(req.userId, 'ADMIN_BANK_UPDATE', `Updated bank account: ${account.bankName}`);
        
        res.json({ 
            message: 'Bank account updated successfully',
            account
        });
    } catch (error) {
        console.error('Admin bank account update error:', error);
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
        
        await logActivity(req.userId, 'ADMIN_BANK_TOGGLE', `${account.isActive ? 'Activated' : 'Deactivated'} bank account: ${account.bankName}`);
        
        res.json({ 
            message: `Bank account ${account.isActive ? 'activated' : 'deactivated'} successfully`,
            account
        });
    } catch (error) {
        console.error('Admin bank account toggle error:', error);
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
        
        await logActivity(req.userId, 'ADMIN_BANK_DELETE', `Deleted bank account: ${account.bankName}`);
        
        res.json({ message: 'Bank account deleted successfully' });
    } catch (error) {
        console.error('Admin bank account delete error:', error);
        res.status(500).json({ error: 'Failed to delete bank account' });
    }
});

// ========================================
// SOCKET.IO HANDLING
// ========================================

io.on('connection', (socket) => {
    console.log('👤 User connected:', socket.id);
    
    socket.on('join', (userId) => {
        socket.join(userId);
        console.log(`👤 User ${userId} joined room`);
    });
    
    socket.on('subscribe_prices', () => {
        console.log('📊 User subscribed to price updates');
    });
    
    socket.on('subscribe_charts', (data) => {
        try {
            const { symbol, timeframe } = data;
            console.log(`📊 User subscribed to chart: ${symbol}/${timeframe}`);
            
            // Join specific chart room
            socket.join(`chart_${symbol}_${timeframe}`);
            
            // Send current chart data if available
            const key = `${symbol}-${timeframe}`;
            const chartData = chartDataStore.get(key);
            if (chartData && chartData.length > 0) {
                const lastCandle = chartData[chartData.length - 1];
                socket.emit('chartUpdate', {
                    symbol,
                    timeframe,
                    candle: lastCandle
                });
                console.log(`📊 Sent initial chart data to user: ${symbol}/${timeframe}`);
            }
        } catch (error) {
            console.error('❌ Error in chart subscription:', error);
        }
    });
    
    socket.on('pause_updates', () => {
        console.log('⏸️ User paused updates');
    });
    
    socket.on('resume_updates', () => {
        console.log('▶️ User resumed updates');
    });
    
    socket.on('disconnect', () => {
        console.log('👤 User disconnected:', socket.id);
    });
});

// ========================================
// ERROR HANDLING
// ========================================

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// ========================================
// SERVER START
// ========================================

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', async () => {
    console.log(`
🚀 TradeStation Backend Server Started!
📍 Port: ${PORT}
🌍 Environment: ${process.env.NODE_ENV || 'development'}
📧 Email/Phone Authentication: Enabled
📱 Mobile-First Design: Supported
📊 Real-time Chart Data: Enhanced
🛡️  Security: Enabled
💳 Bank Management: Enabled
🎯 Trading Control: Enabled
💰 Profit Settings: Enabled
⚙️  Admin Panel: Complete
⏰ Timestamp: ${new Date().toISOString()}
`);

    // Connect to database after server starts
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
        });
        
        console.log('✅ Connected to MongoDB');
        global.dbConnected = true;
        
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
                referralCode: 'ADMIN001',
                adminSettings: {
                    profitPercentage: 80
                }
            });
            await admin.save();
            console.log('✅ Default admin user created (admin@tradestation.com / admin123)');
        }
        
        // Initialize sample bank accounts
        const bankExists = await BankAccount.findOne();
        if (!bankExists) {
            const sampleBanks = [
                {
                    bankName: 'Bank BCA',
                    accountNumber: '1234567890',
                    accountHolder: 'TradeStation Official',
                    note: 'Primary deposit account',
                    isActive: true
                },
                {
                    bankName: 'Bank Mandiri',
                    accountNumber: '0987654321',
                    accountHolder: 'TradeStation Official',
                    note: 'Secondary deposit account',
                    isActive: true
                }
            ];
            
            for (const bank of sampleBanks) {
                await BankAccount.create(bank);
            }
            console.log('✅ Sample bank accounts created');
        }
        
        // Initialize prices
        await initializePrices();
        console.log('✅ Prices initialized');
        
        // Initialize chart data for all symbols
        console.log('📊 Initializing chart data for all symbols...');
        const symbols = await Price.find();
        
        for (const symbol of symbols) {
            await initializeChartDataForSymbol(symbol.symbol);
        }
        
        console.log(`✅ Chart data initialized for ${symbols.length} symbols, total datasets: ${chartDataStore.size}`);
        
        // Start background processes
        simulatePriceUpdates();
        checkTradesToComplete();
        console.log('✅ Background processes started');
        
    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        global.dbConnected = false;
    }
});

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
