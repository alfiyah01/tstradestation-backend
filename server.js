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

// User Schema - ENHANCED dengan validasi terbaik dari Dokumen 1
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, minlength: 2 },
    email: { 
        type: String, 
        trim: true, 
        lowercase: true, 
        sparse: true,  // Ini penting: index sparse
        default: null  // Default null bukan undefined
    },
    phone: { 
        type: String, 
        trim: true, 
        sparse: true,  // Ini penting: index sparse
        default: null  // Default null bukan undefined
    },
    password: { type: String, required: true, minlength: 6 },
    balance: { type: Number, default: 0, min: 0 },
    accountType: { type: String, enum: ['standard', 'premium'], default: 'standard' },
    isActive: { type: Boolean, default: true },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    referralCode: { type: String, unique: true },
    // Bank Data untuk Withdrawal
    bankData: {
        bankName: { type: String, trim: true },
        accountNumber: { type: String, trim: true },
        accountHolder: { type: String, trim: true }
    },
    // Admin Settings untuk User Trading - ENHANCED
    adminSettings: {
        forceWin: { type: Boolean, default: false },
        forceWinRate: { type: Number, default: 0, min: 0, max: 100 },
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

// PERBAIKAN INDEX dari Dokumen 1: Pastikan unique tapi sparse untuk email dan phone
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

// Custom validation dari Dokumen 1: user harus punya email ATAU phone
userSchema.pre('validate', function(next) {
    if (!this.email && !this.phone) {
        this.invalidate('email', 'Either email or phone number is required');
        this.invalidate('phone', 'Either email or phone number is required');
    }
    next();
});

// Pre-save middleware to ensure adminSettings defaults
userSchema.pre('save', function(next) {
    if (!this.adminSettings) {
        this.adminSettings = {
            forceWin: false,
            forceWinRate: 0,
            profitCollapse: 'normal',
            profitPercentage: 80
        };
    } else {
        // Ensure all adminSettings have default values
        if (this.adminSettings.profitPercentage === undefined || this.adminSettings.profitPercentage === null) {
            this.adminSettings.profitPercentage = 80;
        }
        if (this.adminSettings.profitCollapse === undefined || this.adminSettings.profitCollapse === null) {
            this.adminSettings.profitCollapse = 'normal';
        }
        if (this.adminSettings.forceWin === undefined || this.adminSettings.forceWin === null) {
            this.adminSettings.forceWin = false;
        }
        if (this.adminSettings.forceWinRate === undefined || this.adminSettings.forceWinRate === null) {
            this.adminSettings.forceWinRate = 0;
        }
    }
    
    if (!this.stats) {
        this.stats = {
            totalTrades: 0,
            winTrades: 0,
            loseTrades: 0
        };
    }
    
    next();
});

// Bank Account Schema untuk Admin Panel
const bankAccountSchema = new mongoose.Schema({
    bankName: { type: String, required: true },
    accountNumber: { type: String, required: true },
    accountHolder: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    note: { type: String },
    createdAt: { type: Date, default: Date.now }
});

// Trade Schema - ENHANCED
const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symbol: { type: String, required: true },
    direction: { type: String, enum: ['buy', 'sell'], required: true },
    amount: { type: Number, required: true, min: 500000 },
    duration: { type: Number, required: true, min: 30, max: 300 },
    entryPrice: { type: Number, required: true },
    exitPrice: { type: Number },
    status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
    result: { type: String, enum: ['win', 'lose'] },
    payout: { type: Number },
    priceChangePercent: { type: Number },
    forceResult: { type: String, enum: ['win', 'lose'] },
    adminForced: { type: Boolean, default: false },
    profitPercentage: { type: Number, default: 80 },
    createdAt: { type: Date, default: Date.now },
    completedAt: { type: Date }
});

// Deposit Schema - ENHANCED
const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 500000 },
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

// Withdrawal Schema - ENHANCED
const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 100000 },
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

// Price Schema - ENHANCED
const priceSchema = new mongoose.Schema({
    symbol: { type: String, required: true, unique: true },
    price: { type: Number, required: true, min: 0 },
    change: { type: Number, default: 0 },
    lastUpdate: { type: Date, default: Date.now }
});

// Activity Schema - ENHANCED
const activitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    details: { type: String },
    ip: { type: String },
    userAgent: { type: String },
    createdAt: { type: Date, default: Date.now }
});

// Chart Data Schema - ENHANCED
const chartDataSchema = new mongoose.Schema({
    symbol: { type: String, required: true },
    timeframe: { type: String, required: true },
    time: { type: Number, required: true },
    open: { type: Number, required: true },
    high: { type: Number, required: true },
    low: { type: Number, required: true },
    close: { type: Number, required: true },
    volume: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

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
let chartDataStore = new Map();
let isInitialized = false;

function generateReferralCode() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
}

// Enhanced activity logging with IP and User Agent
async function logActivity(userId, action, details = '', req = null) {
    try {
        const activityData = {
            userId,
            action,
            details
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
        console.error('❌ Error rounding time:', error);
        return timestamp;
    }
}

// Enhanced candle generation with better validation
function generateCandleFromPrice(symbol, timeframe, currentPrice, previousCandle = null) {
    try {
        if (!currentPrice || isNaN(currentPrice) || currentPrice <= 0) {
            console.error(`❌ Invalid price for ${symbol}:`, currentPrice);
            return null;
        }

        const now = Date.now();
        const roundedTime = roundTimeToTimeframe(now, timeframe);
        
        // Jika ini candle baru
        if (!previousCandle || previousCandle.time < roundedTime) {
            const volatility = Math.random() * 0.015 + 0.005; // 0.5% to 2% volatility
            
            const open = previousCandle ? previousCandle.close : currentPrice;
            const close = currentPrice;
            
            // Generate realistic high and low dengan proper validation
            const maxPrice = Math.max(open, close);
            const minPrice = Math.min(open, close);
            
            const high = maxPrice * (1 + Math.random() * volatility);
            const low = minPrice * (1 - Math.random() * volatility);
            
            const volume = Math.floor(Math.random() * 900000) + 100000;
            
            const candle = {
                time: Math.floor(roundedTime / 1000),
                open: parseFloat(Math.max(0.001, open).toFixed(8)),
                high: parseFloat(Math.max(0.001, high).toFixed(8)),
                low: parseFloat(Math.max(0.001, low).toFixed(8)),
                close: parseFloat(Math.max(0.001, close).toFixed(8)),
                volume
            };
            
            // Ensure OHLC logic is correct
            candle.high = Math.max(candle.open, candle.high, candle.low, candle.close);
            candle.low = Math.min(candle.open, candle.high, candle.low, candle.close);
            
            return candle;
        } else {
            // Update existing candle
            const updatedCandle = {
                ...previousCandle,
                close: parseFloat(Math.max(0.001, currentPrice).toFixed(8)),
                high: Math.max(previousCandle.high, currentPrice),
                low: Math.min(previousCandle.low, currentPrice),
                volume: previousCandle.volume + Math.floor(Math.random() * 50000)
            };
            
            return updatedCandle;
        }
    } catch (error) {
        console.error('❌ Error generating candle:', error);
        return null;
    }
}

// Enhanced historical data generation
async function generateHistoricalData(symbol, timeframe, count = 100) {
    try {
        console.log(`📊 Generating historical data for ${symbol}/${timeframe} (${count} candles)`);
        
        const currentPrice = await Price.findOne({ symbol });
        if (!currentPrice || !currentPrice.price || currentPrice.price <= 0) {
            console.error(`❌ Invalid price data for symbol: ${symbol}`);
            return [];
        }
        
        const timeframeMs = getTimeframeMinutes(timeframe) * 60 * 1000;
        const now = Date.now();
        const data = [];
        
        let price = currentPrice.price;
        
        // Generate historical candles dengan trend yang lebih realistis
        for (let i = count; i >= 0; i--) {
            const time = Math.floor((now - (i * timeframeMs)) / 1000);
            
            // Add realistic price movement dengan trend detection
            const baseVolatility = 0.01;
            const timeVolatility = 0.005;
            const trendFactor = (Math.random() - 0.49) * (baseVolatility + timeVolatility);
            
            const newPrice = Math.max(0.001, price * (1 + trendFactor));
            
            const open = price;
            const close = newPrice;
            const spread = Math.abs(close - open);
            const high = Math.max(open, close) + (spread * Math.random() * 0.5);
            const low = Math.min(open, close) - (spread * Math.random() * 0.5);
            const volume = Math.floor(Math.random() * 1000000) + 100000;
            
            const candleData = {
                time,
                open: parseFloat(Math.max(0.001, open).toFixed(8)),
                high: parseFloat(Math.max(0.001, high).toFixed(8)),
                low: parseFloat(Math.max(0.001, low).toFixed(8)),
                close: parseFloat(Math.max(0.001, close).toFixed(8)),
                volume
            };
            
            // Ensure OHLC validation
            candleData.high = Math.max(candleData.open, candleData.high, candleData.low, candleData.close);
            candleData.low = Math.min(candleData.open, candleData.high, candleData.low, candleData.close);
            
            data.push(candleData);
            price = newPrice;
        }
        
        // Sort by time
        data.sort((a, b) => a.time - b.time);
        
        console.log(`✅ Generated ${data.length} historical candles for ${symbol}/${timeframe}`);
        return data;
        
    } catch (error) {
        console.error('❌ Error generating historical data:', error);
        return [];
    }
}

// Enhanced chart data initialization
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
                } else {
                    console.error(`❌ Failed to generate data for ${symbol}/${timeframe}`);
                }
            }
        }
    } catch (error) {
        console.error(`❌ Error initializing chart data for ${symbol}:`, error);
    }
}

// Enhanced price initialization
async function initializePrices() {
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
            try {
                await Price.findOneAndUpdate(
                    { symbol: priceData.symbol },
                    {
                        ...priceData,
                        price: Math.max(0.001, priceData.price),
                        lastUpdate: new Date()
                    },
                    { upsert: true, new: true }
                );
                console.log(`✅ Price initialized for ${priceData.symbol}: $${priceData.price.toFixed(4)}`);
            } catch (error) {
                console.error(`❌ Error initializing price for ${priceData.symbol}:`, error);
            }
        }
    } catch (error) {
        console.error('❌ Error in price initialization:', error);
    }
}

// Enhanced price update simulation
function simulatePriceUpdates() {
    setInterval(async () => {
        if (!isInitialized) return;
        
        try {
            const prices = await Price.find();
            
            for (const price of prices) {
                // More realistic price movements
                const baseVolatility = 0.01; // 1%
                const timeVolatility = Math.random() * 0.02; // 0-2%
                const marketTrend = Math.sin(Date.now() / 3600000) * 0.005; // Hourly trend
                
                const changePercent = (Math.random() - 0.5) * (baseVolatility + timeVolatility) + marketTrend;
                const newPrice = Math.max(0.001, price.price * (1 + changePercent));
                const change = ((newPrice - price.price) / price.price) * 100;
                
                // Update dengan validation
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
                
                // Update chart data for all timeframes
                const timeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d'];
                
                for (const timeframe of timeframes) {
                    const key = `${price.symbol}-${timeframe}`;
                    const currentCandles = chartDataStore.get(key) || [];
                    const lastCandle = currentCandles[currentCandles.length - 1];
                    
                    const newCandle = generateCandleFromPrice(price.symbol, timeframe, price.price, lastCandle);
                    
                    if (newCandle && newCandle.time && !isNaN(newCandle.time)) {
                        // Update or add new candle
                        if (lastCandle && lastCandle.time === newCandle.time) {
                            currentCandles[currentCandles.length - 1] = newCandle;
                        } else {
                            currentCandles.push(newCandle);
                            // Keep only last 200 candles
                            if (currentCandles.length > 200) {
                                currentCandles.shift();
                            }
                        }
                        
                        chartDataStore.set(key, currentCandles);
                        
                        // Broadcast chart update (reduced frequency)
                        if (Math.random() < 0.1) { // 10% chance to broadcast
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
    }, 2000); // Update every 2 seconds
}

// Enhanced trade completion checker
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
                    
                    if (currentPrice && currentPrice.price > 0) {
                        trade.exitPrice = currentPrice.price;
                        trade.status = 'completed';
                        trade.completedAt = now;
                        
                        // Calculate price change
                        const priceChangePercent = ((currentPrice.price - trade.entryPrice) / trade.entryPrice) * 100;
                        trade.priceChangePercent = priceChangePercent;
                        
                        // Enhanced result determination dengan validasi admin settings
                        let result;
                        
                        // Check admin settings first dengan prioritas
                        if (trade.userId.adminSettings?.profitCollapse === 'profit') {
                            result = 'win';
                            trade.adminForced = true;
                            trade.forceResult = 'win';
                        } else if (trade.userId.adminSettings?.profitCollapse === 'collapse') {
                            result = 'lose';
                            trade.adminForced = true;
                            trade.forceResult = 'lose';
                        } else if (trade.forceResult) {
                            result = trade.forceResult;
                            trade.adminForced = true;
                        } else if (trade.userId.adminSettings?.forceWin && trade.userId.adminSettings.forceWinRate > 0) {
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
                        
                        // Enhanced payout calculation dengan validation
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
                        } else {
                            trade.payout = 0;
                            trade.userId.totalLoss += trade.amount;
                        }
                        
                        // Update user stats dengan validation
                        trade.userId.stats.totalTrades = (trade.userId.stats.totalTrades || 0) + 1;
                        if (result === 'win') {
                            trade.userId.stats.winTrades = (trade.userId.stats.winTrades || 0) + 1;
                        } else {
                            trade.userId.stats.loseTrades = (trade.userId.stats.loseTrades || 0) + 1;
                        }
                        
                        await trade.save();
                        await trade.userId.save();
                        
                        // Enhanced activity logging
                        await logActivity(
                            trade.userId._id, 
                            'TRADE_COMPLETED', 
                            `${trade.symbol} ${trade.direction.toUpperCase()} ${result.toUpperCase()} - ${formatCurrency(trade.payout)} ${trade.adminForced ? '(Admin Controlled)' : ''}`
                        );
                        
                        // Notify user via socket
                        io.to(trade.userId._id.toString()).emit('tradeCompleted', {
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
                        
                        console.log(`✅ Trade completed: ${trade._id} - ${result.toUpperCase()} - ${formatCurrency(trade.payout)} ${trade.adminForced ? '(Admin Controlled)' : ''}`);
                    }
                }
            }
        } catch (error) {
            console.error('❌ Error checking trades:', error);
        }
    }, 1000); // Check every second
}

// Enhanced database connection check middleware
const checkDatabaseConnection = (req, res, next) => {
    if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({ 
            error: 'Database temporarily unavailable',
            message: 'Please try again in a few moments'
        });
    }
    next();
};

// Enhanced authentication middleware
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
        if (error.name === 'TokenExpiredError') {
            return res.status(403).json({ error: 'Token expired' });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({ error: 'Invalid token' });
        }
        return res.status(403).json({ error: 'Token verification failed' });
    }
};

// Enhanced admin middleware
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

// Utility function untuk format currency
function formatCurrency(amount) {
    return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        minimumFractionDigits: 0,
        maximumFractionDigits: 0
    }).format(amount || 0);
}

// FUNGSI VALIDASI TERBAIK dari Dokumen 1
function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email.trim());
}

function isValidPhone(phone) {
    if (!phone || typeof phone !== 'string') return false;
    // Mendukung format Indonesia: 08xxx, +628xxx, 628xxx, atau international
    const phoneRegex = /^(\+?62|0)[0-9]{9,13}$/;
    const cleanPhone = phone.replace(/[\s\-\(\)]/g, ''); // Remove spaces, dashes, parentheses
    return phoneRegex.test(cleanPhone);
}

// ========================================
// DATABASE OPTIMIZATION MIDDLEWARE dari Dokumen 2
// ========================================

// Add connection monitoring
mongoose.connection.on('connected', () => {
    console.log('✅ MongoDB connected successfully');
});

mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('⚠️ MongoDB disconnected');
});

// Add memory monitoring
setInterval(() => {
    const used = process.memoryUsage();
    const memoryUsage = {
        rss: Math.round(used.rss / 1024 / 1024 * 100) / 100,
        heapTotal: Math.round(used.heapTotal / 1024 / 1024 * 100) / 100,
        heapUsed: Math.round(used.heapUsed / 1024 / 1024 * 100) / 100,
        external: Math.round(used.external / 1024 / 1024 * 100) / 100
    };
    
    if (memoryUsage.heapUsed > 200) { // Alert if heap > 200MB
        console.log('⚠️ High memory usage:', memoryUsage);
    }
}, 30000); // Check every 30 seconds

// ========================================
// IMPROVED ERROR HANDLING dari Dokumen 2
// ========================================

// Global error handler untuk unhandled promises
process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    // Log to file in production
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    // Graceful shutdown
    process.exit(1);
});

// ========================================
// DATABASE INDEX OPTIMIZATION dari Dokumen 2
// ========================================

// Ensure proper indexes for performance
async function ensureIndexes() {
    try {
        // Deposit indexes
        await Deposit.collection.createIndex({ status: 1, createdAt: -1 });
        await Deposit.collection.createIndex({ userId: 1, createdAt: -1 });
        await Deposit.collection.createIndex({ createdAt: -1 });
        
        // User indexes
        await User.collection.createIndex({ email: 1 }, { sparse: true });
        await User.collection.createIndex({ phone: 1 }, { sparse: true });
        
        // Trade indexes
        await Trade.collection.createIndex({ userId: 1, status: 1, createdAt: -1 });
        await Trade.collection.createIndex({ status: 1, createdAt: -1 });
        
        console.log('✅ Database indexes ensured');
    } catch (error) {
        console.error('❌ Error creating indexes:', error);
    }
}

// ========================================
// PUBLIC ROUTES
// ========================================

// Enhanced root route
app.get('/', (req, res) => {
    res.json({
        message: 'TradeStation Backend API - Best Combined Version',
        version: '3.2.0',
        status: 'Running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        features: [
            'Enhanced Email/Phone Authentication (Best from Doc 1)',
            'Robust Admin Panel with Timeouts (Best from Doc 2)',
            'Performance Optimization for Many Users',
            'Advanced Monitoring & Debugging',
            'Mobile-First Trading',
            'Real-time Chart Data',
            'Bank Account Management', 
            'File Upload Support', 
            'Advanced Admin Trading Control', 
            'Dynamic Profit Settings',
            'Enhanced Mobile UI',
            'Complete Admin Panel',
            'Enhanced Security & Validation'
        ],
        improvements: [
            'Combined best registration system from Dokumen 1',
            'Enhanced admin deposit management from Dokumen 2',
            'Database optimization and monitoring',
            'Memory usage tracking',
            'Query timeout handling',
            'Better error handling for production'
        ],
        endpoints: {
            health: 'GET /api/health',
            register: 'POST /api/register',
            login: 'POST /api/login',
            prices: 'GET /api/prices',
            chart: 'GET /api/chart/:symbol/:timeframe',
            profile: 'GET /api/profile (auth required)',
            bank: 'GET /api/profile/bank (auth required)',
            trading: 'POST /api/trade (auth required)',
            admin: '/api/admin/* (admin required)'
        }
    });
});

// Enhanced health check
app.get('/api/health', (req, res) => {
    const health = {
        status: 'OK', 
        message: 'TradeStation Backend is running smoothly - Combined Best Version',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: {
            status: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
            readyState: mongoose.connection.readyState
        },
        server: {
            port: process.env.PORT || 3000,
            uptime: process.uptime(),
            memory: process.memoryUsage()
        },
        features: {
            chartDataSets: chartDataStore.size,
            initialized: isInitialized
        }
    };
    
    const statusCode = mongoose.connection.readyState === 1 ? 200 : 503;
    res.status(statusCode).json(health);
});

// Enhanced chart data route
app.get('/api/chart/:symbol/:timeframe', async (req, res) => {
    try {
        const { symbol, timeframe } = req.params;
        
        console.log(`📊 Chart data requested: ${symbol}/${timeframe}`);
        
        // Enhanced validation
        const validTimeframes = ['1m', '5m', '15m', '30m', '1h', '4h', '1d'];
        if (!validTimeframes.includes(timeframe)) {
            return res.status(400).json({ 
                error: 'Invalid timeframe',
                validTimeframes: validTimeframes,
                provided: timeframe
            });
        }
        
        // Check if symbol exists
        const priceData = await Price.findOne({ symbol: symbol.toUpperCase() });
        if (!priceData) {
            const availableSymbols = await Price.find().distinct('symbol');
            return res.status(404).json({ 
                error: 'Symbol not found',
                availableSymbols: availableSymbols,
                provided: symbol
            });
        }
        
        const key = `${symbol.toUpperCase()}-${timeframe}`;
        let chartData = chartDataStore.get(key);
        
        // Enhanced data generation jika belum ada
        if (!chartData || chartData.length === 0) {
            console.log(`📊 Generating fresh data for ${symbol}/${timeframe}`);
            chartData = await generateHistoricalData(symbol.toUpperCase(), timeframe, 100);
            
            if (chartData && chartData.length > 0) {
                chartDataStore.set(key, chartData);
                console.log(`✅ Fresh data generated: ${chartData.length} candles`);
            } else {
                return res.status(500).json({ 
                    error: 'Failed to generate chart data',
                    symbol: symbol,
                    timeframe: timeframe
                });
            }
        }
        
        // Enhanced data validation
        const validatedData = chartData.filter(candle => 
            candle && 
            typeof candle.time === 'number' &&
            typeof candle.open === 'number' &&
            typeof candle.high === 'number' &&
            typeof candle.low === 'number' &&
            typeof candle.close === 'number' &&
            candle.time > 0 &&
            candle.open > 0 &&
            candle.high > 0 &&
            candle.low > 0 &&
            candle.close > 0 &&
            candle.high >= Math.max(candle.open, candle.close) &&
            candle.low <= Math.min(candle.open, candle.close)
        );
        
        const response = {
            symbol: symbol.toUpperCase(),
            timeframe,
            candlestick: validatedData,
            count: validatedData.length,
            currentPrice: priceData.price,
            lastUpdate: priceData.lastUpdate,
            metadata: {
                generated: new Date().toISOString(),
                source: 'TradeStation API v3.2.0 - Combined Best Version'
            }
        };
        
        res.json(response);
        
        console.log(`✅ Chart data sent: ${validatedData.length} candles for ${symbol}/${timeframe}`);
        
    } catch (error) {
        console.error('❌ Chart data error:', error);
        res.status(500).json({ 
            error: 'Failed to load chart data',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// ========================================
// AUTH ROUTES - TERBAIK dari Dokumen 1
// ========================================

// REGISTER ROUTE dengan validasi terbaik dari Dokumen 1
app.post('/api/register', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        
        console.log('📝 Register request:', { name, email: !!email, phone: !!phone, password: !!password });
        
        // Enhanced validation
        if (!name || name.trim().length < 2) {
            return res.status(400).json({ error: 'Nama harus minimal 2 karakter' });
        }

        if (!password || password.length < 6) {
            return res.status(400).json({ error: 'Password harus minimal 6 karakter' });
        }

        // PERBAIKAN: User harus punya email ATAU phone (tidak keduanya)
        if (!email && !phone) {
            return res.status(400).json({ error: 'Email atau nomor HP diperlukan' });
        }
        
        // Validasi email jika ada
        if (email && !isValidEmail(email)) {
            return res.status(400).json({ error: 'Format email tidak valid' });
        }
        
        // Validasi phone jika ada
        if (phone && !isValidPhone(phone)) {
            return res.status(400).json({ error: 'Format nomor HP tidak valid. Gunakan format: 08xxx atau +628xxx' });
        }
        
        // PERBAIKAN: Check existing user dengan logic yang lebih baik
        let existingUser = null;
        
        if (email) {
            existingUser = await User.findOne({ email: email.toLowerCase().trim() });
            if (existingUser) {
                return res.status(400).json({ error: 'Email sudah terdaftar' });
            }
        }
        
        if (phone) {
            const cleanPhone = phone.replace(/[\s\-\(\)]/g, ''); // Clean phone number
            existingUser = await User.findOne({ phone: cleanPhone });
            if (existingUser) {
                return res.status(400).json({ error: 'Nomor HP sudah terdaftar' });
            }
        }
        
        // Enhanced password hashing
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // PERBAIKAN: Create user dengan data yang bersih
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

        // PERBAIKAN: Hanya set field yang ada datanya
        if (email) {
            userData.email = email.toLowerCase().trim();
        }
        if (phone) {
            userData.phone = phone.replace(/[\s\-\(\)]/g, ''); // Clean phone
        }
        
        console.log('📝 Creating user with data:', { 
            name: userData.name, 
            email: userData.email, 
            phone: userData.phone,
            hasPassword: !!userData.password 
        });
        
        const user = new User(userData);
        await user.save();
        
        // Enhanced activity logging
        await logActivity(user._id, 'USER_REGISTER', `New user registered: ${email || phone}`, req);
        
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
            message: 'Pendaftaran berhasil',
            token,
            user: userResponse
        });
        
        console.log(`✅ New user registered: ${email || phone}`);
        
    } catch (error) {
        console.error('❌ Registration error:', error);
        
        // Handle MongoDB errors
        if (error.code === 11000) {
            if (error.keyPattern.email) {
                return res.status(400).json({ error: 'Email sudah terdaftar' });
            }
            if (error.keyPattern.phone) {
                return res.status(400).json({ error: 'Nomor HP sudah terdaftar' });
            }
            return res.status(400).json({ error: 'Data sudah terdaftar' });
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

// LOGIN ROUTE dengan validasi terbaik dari Dokumen 1
app.post('/api/login', authLimiter, checkDatabaseConnection, async (req, res) => {
    try {
        const { email, phone, password } = req.body;
        
        console.log('📝 Login request:', { email: !!email, phone: !!phone, password: !!password });
        
        if (!password) {
            return res.status(400).json({ error: 'Password diperlukan' });
        }

        if (!email && !phone) {
            return res.status(400).json({ error: 'Email atau nomor HP diperlukan' });
        }
        
        // PERBAIKAN: Find user dengan logic yang lebih baik
        let user = null;
        
        if (email) {
            // Coba cari dengan email
            if (isValidEmail(email)) {
                user = await User.findOne({ email: email.toLowerCase().trim() });
            }
        }
        
        if (!user && phone) {
            // Jika tidak ketemu dengan email, coba dengan phone
            const cleanPhone = phone.replace(/[\s\-\(\)]/g, '');
            if (isValidPhone(cleanPhone)) {
                user = await User.findOne({ phone: cleanPhone });
            }
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
        
        await logActivity(user._id, 'USER_LOGIN', `User logged in: ${email || phone}`, req);
        
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
// USER ROUTES (tetap sama)
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

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { name, phone } = req.body;
        
        const updateData = {};
        if (name && name.trim().length >= 2) {
            updateData.name = name.trim();
        }
        if (phone) {
            updateData.phone = phone;
        }
        
        const user = await User.findByIdAndUpdate(
            req.userId,
            updateData,
            { new: true }
        ).select('-password');
        
        await logActivity(req.userId, 'PROFILE_UPDATE', 'Profile updated', req);
        
        res.json(user);
    } catch (error) {
        console.error('❌ Profile update error:', error);
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
        
        if (!bankName || !accountNumber || !accountHolder) {
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
        
        await logActivity(req.userId, 'BANK_DATA_UPDATE', `Bank data updated: ${bankName}`, req);
        
        res.json(user.bankData);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update bank data' });
    }
});

// Active Bank Accounts untuk Deposit
app.get('/api/bank-accounts/active', async (req, res) => {
    try {
        const accounts = await BankAccount.find({ isActive: true }).select('-__v');
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load bank accounts' });
    }
});

// Price Routes
app.get('/api/prices', async (req, res) => {
    try {
        const prices = await Price.find().sort({ symbol: 1 }).select('-__v');
        res.json(prices);
    } catch (error) {
        console.error('❌ Prices error:', error);
        res.status(500).json({ error: 'Failed to load prices' });
    }
});

// ========================================
// TRADING ROUTES (tetap sama)
// ========================================

// Enhanced trading route
app.post('/api/trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, direction, amount, duration } = req.body;
        
        // Enhanced validation
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
        
        // Get profit percentage dari user settings dengan validation
        const profitPercentage = Math.max(20, Math.min(100, 
            req.user.adminSettings?.profitPercentage || 80
        ));
        
        // Deduct amount from user balance
        req.user.balance -= amount;
        await req.user.save();
        
        // Create trade dengan enhanced settings
        const trade = new Trade({
            userId: req.userId,
            symbol: symbol.toUpperCase(),
            direction,
            amount,
            profitPercentage,
            duration,
            entryPrice: currentPrice.price
        });
        
        await trade.save();
        
        // Enhanced activity logging
        await logActivity(
            req.userId, 
            'TRADE_CREATED', 
            `${symbol.toUpperCase()} ${direction.toUpperCase()} ${formatCurrency(amount)} - ${duration}s`,
            req
        );
        
        // Notify via socket
        io.to(req.userId.toString()).emit('tradeCreated', {
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
// DEPOSIT ROUTES (tetap sama)
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
        
        // Enhanced file validation
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        if (!allowedTypes.includes(fileType)) {
            return res.status(400).json({ error: 'Invalid file type. Only JPEG, PNG, and WebP are allowed.' });
        }
        
        // Check file size (base64 length estimation)
        const sizeInBytes = (receipt.length * 3) / 4;
        if (sizeInBytes > 5 * 1024 * 1024) { // 5MB limit
            return res.status(400).json({ error: 'File size too large. Maximum 5MB allowed.' });
        }
        
        const deposit = new Deposit({
            userId: req.userId,
            amount,
            bankFrom: bankFrom || 'Not specified',
            receipt,
            fileName: fileName || 'payment_proof',
            fileType,
            fileSize: sizeInBytes,
            transferTime: new Date()
        });
        
        await deposit.save();
        
        await logActivity(req.userId, 'DEPOSIT_REQUEST', `Deposit request: ${formatCurrency(amount)}`, req);
        
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
            .select('-receipt') // Don't send receipt data in list
            .limit(50);
        
        res.json(deposits);
    } catch (error) {
        console.error('❌ Deposits error:', error);
        res.status(500).json({ error: 'Failed to load deposits' });
    }
});

// ========================================
// WITHDRAWAL ROUTES (tetap sama)
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
            return res.status(400).json({ error: 'Bank data is required. Please update your bank information first.' });
        }
        
        // Enhanced fee calculation
        const feePercentage = 0.01; // 1%
        const minimumFee = 6500;
        const fee = Math.max(minimumFee, amount * feePercentage);
        const finalAmount = amount - fee;
        
        if (finalAmount <= 0) {
            return res.status(400).json({ error: 'Amount too small after fees' });
        }
        
        // Deduct amount from user balance
        user.balance -= amount;
        await user.save();
        
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
        
        await withdrawal.save();
        
        await logActivity(req.userId, 'WITHDRAWAL_REQUEST', `Withdrawal request: ${formatCurrency(amount)} (net: ${formatCurrency(finalAmount)})`, req);
        
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
// ADMIN ROUTES - TERBAIK dari Dokumen 2
// ========================================

// Enhanced Admin Dashboard
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        // Enhanced statistics calculation
        const [
            totalUsers,
            activeUsers,
            totalTrades,
            activeTrades,
            totalDeposits,
            pendingDeposits,
            totalWithdrawals,
            pendingWithdrawals,
            totalBankAccounts,
            activeBankAccounts
        ] = await Promise.all([
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
        ]);
        
        // Enhanced volume stats
        const completedTrades = await Trade.find({ status: 'completed' });
        const totalVolume = completedTrades.reduce((sum, trade) => sum + trade.amount, 0);
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayTrades = await Trade.find({ 
            status: 'completed',
            createdAt: { $gte: today }
        });
        const todayVolume = todayTrades.reduce((sum, trade) => sum + trade.amount, 0);
        
        // Enhanced recent activities with better population
        const recentActivities = await Activity.find()
            .populate('userId', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(15);
        
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
        
        console.log(`✅ Admin dashboard loaded by ${req.user.name}`);
        
    } catch (error) {
        console.error('❌ Admin dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

// Enhanced User Management
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find()
            .select('-password')
            .sort({ createdAt: -1 })
            .limit(200); // Limit untuk performance
        
        res.json({ users });
    } catch (error) {
        console.error('❌ Admin users error:', error);
        res.status(500).json({ error: 'Failed to load users' });
    }
});

app.put('/api/admin/user/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = req.body;
        
        console.log('Received update data:', updateData);
        
        // Enhanced validation
        delete updateData.password; // Don't allow password updates through this endpoint
        
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
        
        // Validate admin settings with enhanced checks
        if (updateData.adminSettings) {
            const { profitPercentage, forceWinRate, profitCollapse, forceWin } = updateData.adminSettings;
            
            // Validate profit percentage
            if (profitPercentage !== undefined) {
                const percentage = parseInt(profitPercentage);
                if (isNaN(percentage) || percentage < 20 || percentage > 100) {
                    return res.status(400).json({ error: 'Profit percentage must be between 20 and 100' });
                }
                updateData.adminSettings.profitPercentage = percentage;
            }
            
            // Validate win rate
            if (forceWinRate !== undefined) {
                const winRate = parseFloat(forceWinRate);
                if (isNaN(winRate) || winRate < 0 || winRate > 100) {
                    return res.status(400).json({ error: 'Win rate must be between 0 and 100' });
                }
                updateData.adminSettings.forceWinRate = winRate;
            }
            
            // Validate profit collapse setting
            if (profitCollapse && !['normal', 'profit', 'collapse'].includes(profitCollapse)) {
                return res.status(400).json({ error: 'Invalid profit collapse setting' });
            }
            
            // Ensure forceWin is boolean
            if (forceWin !== undefined) {
                updateData.adminSettings.forceWin = Boolean(forceWin);
            }
        }
        
        // Clean up undefined/empty values
        Object.keys(updateData).forEach(key => {
            if (updateData[key] === undefined || updateData[key] === '') {
                delete updateData[key];
            }
        });
        
        console.log('Processed update data:', updateData);
        
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
        
        await logActivity(req.userId, 'ADMIN_USER_UPDATE', `Updated user: ${user.name} (${user.email || user.phone})`, req);
        
        res.json({ message: 'User updated successfully', user });
        
        console.log(`✅ User updated by admin: ${user.name}`);
        
    } catch (error) {
        console.error('❌ Admin user update error:', error);
        
        // Send more specific error messages
        if (error.name === 'ValidationError') {
            const validationErrors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: validationErrors 
            });
        }
        
        if (error.name === 'CastError') {
            return res.status(400).json({ error: 'Invalid data format' });
        }
        
        res.status(500).json({ 
            error: 'Failed to update user',
            message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
});

// Enhanced Trade Management
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

// ========================================
// ENHANCED DEPOSIT MANAGEMENT ROUTES dari Dokumen 2
// ========================================

// Enhanced Deposit Management dengan timeout dan error handling yang lebih baik
app.get('/api/admin/deposits', authenticateToken, requireAdmin, async (req, res) => {
    const startTime = Date.now();
    
    try {
        console.log('📊 Loading admin deposits...');
        
        const { status, limit = 50 } = req.query; // Kurangi default limit
        
        // Tambahkan timeout untuk query
        const queryTimeout = 15000; // 15 detik timeout
        
        let query = {};
        if (status && ['pending', 'approved', 'rejected'].includes(status)) {
            query.status = status;
        }
        
        console.log('🔍 Deposit query:', query);
        
        // Query dengan timeout dan pagination yang lebih efisien
        const deposits = await Promise.race([
            Deposit.find(query)
                .populate({
                    path: 'userId',
                    select: 'name email phone',
                    options: { 
                        timeout: queryTimeout / 2,
                        lean: true // Optimasi memory
                    }
                })
                .sort({ createdAt: -1 })
                .limit(Math.min(parseInt(limit), 100))
                .lean() // Optimasi memory
                .exec(),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Query timeout')), queryTimeout)
            )
        ]);
        
        const endTime = Date.now();
        console.log(`✅ Deposits loaded: ${deposits.length} records in ${endTime - startTime}ms`);
        
        // Filter data yang bermasalah
        const cleanDeposits = deposits.filter(deposit => {
            return deposit && deposit._id && deposit.amount;
        });
        
        res.json({ 
            deposits: cleanDeposits,
            count: cleanDeposits.length,
            queryTime: endTime - startTime,
            status: 'success'
        });
        
    } catch (error) {
        const endTime = Date.now();
        console.error('❌ Admin deposits error:', error);
        console.error('⏱️ Query time before error:', endTime - startTime + 'ms');
        
        // Log detail error untuk debugging
        if (error.message === 'Query timeout') {
            console.error('🕐 Database query timeout - consider optimizing or increasing timeout');
        } else if (error.name === 'MongoError') {
            console.error('🗃️ MongoDB error:', error.message);
        }
        
        // Return error dengan detail untuk debugging (production harus dihapus)
        res.status(500).json({ 
            error: 'Failed to load deposits',
            message: process.env.NODE_ENV === 'development' ? error.message : 'Database error',
            queryTime: endTime - startTime,
            status: 'error'
        });
    }
});

// Tambahkan endpoint untuk check deposit count (untuk debugging)
app.get('/api/admin/deposits/count', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalCount = await Deposit.countDocuments();
        const pendingCount = await Deposit.countDocuments({ status: 'pending' });
        const approvedCount = await Deposit.countDocuments({ status: 'approved' });
        const rejectedCount = await Deposit.countDocuments({ status: 'rejected' });
        
        res.json({
            total: totalCount,
            pending: pendingCount,
            approved: approvedCount,
            rejected: rejectedCount,
            status: 'success'
        });
    } catch (error) {
        console.error('❌ Deposit count error:', error);
        res.status(500).json({ error: 'Failed to get deposit count' });
    }
});

// Enhanced deposit processing dengan better error handling
app.put('/api/admin/deposit/:id', authenticateToken, requireAdmin, async (req, res) => {
    const startTime = Date.now();
    
    try {
        const { id } = req.params;
        const { status, adminNotes } = req.body;
        
        console.log(`📝 Processing deposit ${id}:`, { status, adminNotes });
        
        if (!['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        // Gunakan session untuk atomic operation
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
            deposit.adminNotes = adminNotes || '';
            deposit.processedAt = new Date();
            
            // If approved, add to user balance
            if (status === 'approved') {
                if (!deposit.userId) {
                    await session.abortTransaction();
                    return res.status(400).json({ error: 'User not found for this deposit' });
                }
                
                deposit.userId.balance += deposit.amount;
                await deposit.userId.save({ session });
                
                console.log(`💰 Added ${deposit.amount} to user ${deposit.userId.name} balance`);
                
                // Notify via socket
                setTimeout(() => {
                    try {
                        io.to(deposit.userId._id.toString()).emit('depositApproved', {
                            amount: deposit.amount,
                            newBalance: deposit.userId.balance,
                            message: 'Your deposit has been approved!'
                        });
                    } catch (socketError) {
                        console.error('❌ Socket notification error:', socketError);
                    }
                }, 100);
            }
            
            await deposit.save({ session });
            await session.commitTransaction();
            
            // Enhanced activity logging
            await logActivity(
                req.userId, 
                'ADMIN_DEPOSIT_PROCESS', 
                `${status.toUpperCase()} deposit: ${formatCurrency(deposit.amount)} for ${deposit.userId.name}`,
                req
            );
            
            const endTime = Date.now();
            console.log(`✅ Deposit ${status} successfully in ${endTime - startTime}ms`);
            
            res.json({ 
                message: `Deposit ${status} successfully`,
                deposit: {
                    _id: deposit._id,
                    status: deposit.status,
                    processedAt: deposit.processedAt
                },
                queryTime: endTime - startTime,
                status: 'success'
            });
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        } finally {
            session.endSession();
        }
        
    } catch (error) {
        const endTime = Date.now();
        console.error('❌ Admin deposit process error:', error);
        console.error('⏱️ Process time before error:', endTime - startTime + 'ms');
        
        res.status(500).json({ 
            error: 'Failed to process deposit',
            message: process.env.NODE_ENV === 'development' ? error.message : 'Processing error',
            queryTime: endTime - startTime,
            status: 'error'
        });
    }
});

// Add database health check endpoint
app.get('/api/admin/health/database', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const startTime = Date.now();
        
        // Test basic queries
        const [userCount, depositCount, tradeCount] = await Promise.all([
            User.countDocuments().maxTimeMS(5000),
            Deposit.countDocuments().maxTimeMS(5000),
            Trade.countDocuments().maxTimeMS(5000)
        ]);
        
        const endTime = Date.now();
        const queryTime = endTime - startTime;
        
        const health = {
            status: 'healthy',
            queryTime: queryTime,
            collections: {
                users: userCount,
                deposits: depositCount,
                trades: tradeCount
            },
            mongodb: {
                readyState: mongoose.connection.readyState,
                host: mongoose.connection.host,
                name: mongoose.connection.name
            }
        };
        
        if (queryTime > 3000) {
            health.warning = 'Slow database response';
        }
        
        res.json(health);
        
    } catch (error) {
        console.error('❌ Database health check failed:', error);
        res.status(500).json({
            status: 'unhealthy',
            error: error.message,
            mongodb: {
                readyState: mongoose.connection.readyState
            }
        });
    }
});

// Enhanced Withdrawal Management
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
        
        withdrawal.status = status;
        withdrawal.adminNotes = adminNotes || '';
        withdrawal.processedAt = new Date();
        
        // If rejected, return money to user balance
        if (status === 'rejected') {
            withdrawal.userId.balance += withdrawal.amount;
            await withdrawal.userId.save();
            
            // Notify user via socket
            io.to(withdrawal.userId._id.toString()).emit('withdrawalRejected', {
                amount: withdrawal.amount,
                newBalance: withdrawal.userId.balance,
                message: 'Your withdrawal request has been rejected and funds returned to your account.'
            });
        } else if (status === 'approved') {
            // Notify user via socket
            io.to(withdrawal.userId._id.toString()).emit('withdrawalApproved', {
                amount: withdrawal.finalAmount,
                message: 'Your withdrawal request has been approved and will be processed soon.'
            });
        }
        
        await withdrawal.save();
        
        await logActivity(req.userId, 'ADMIN_WITHDRAWAL_PROCESS', `${status.toUpperCase()} withdrawal: ${formatCurrency(withdrawal.amount)} for ${withdrawal.userId.name}`, req);
        
        res.json({ message: `Withdrawal ${status} successfully` });
        
        console.log(`✅ Withdrawal ${status} by admin: ${formatCurrency(withdrawal.amount)} for ${withdrawal.userId.name}`);
        
    } catch (error) {
        console.error('❌ Admin withdrawal process error:', error);
        res.status(500).json({ error: 'Failed to process withdrawal' });
    }
});

// Enhanced Bank Account Management
app.get('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const accounts = await BankAccount.find().sort({ createdAt: -1 });
        res.json({ accounts });
    } catch (error) {
        console.error('❌ Admin bank accounts error:', error);
        res.status(500).json({ error: 'Failed to load bank accounts' });
    }
});

app.post('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder, note } = req.body;
        
        if (!bankName || !accountNumber || !accountHolder) {
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
            note: note ? note.trim() : ''
        });
        
        await account.save();
        
        await logActivity(req.userId, 'ADMIN_BANK_CREATE', `Created bank account: ${bankName} - ${accountNumber}`, req);
        
        res.status(201).json({ 
            message: 'Bank account created successfully',
            account
        });
        
        console.log(`✅ Bank account created by admin: ${bankName} - ${accountNumber}`);
        
    } catch (error) {
        console.error('❌ Admin bank account create error:', error);
        res.status(500).json({ error: 'Failed to create bank account' });
    }
});

app.put('/api/admin/bank-accounts/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { bankName, accountNumber, accountHolder, note, isActive } = req.body;
        
        if (!bankName || !accountNumber || !accountHolder) {
            return res.status(400).json({ error: 'Bank name, account number, and account holder are required' });
        }
        
        const updateData = {
            bankName: bankName.trim(),
            accountNumber: accountNumber.trim(),
            accountHolder: accountHolder.trim(),
            note: note ? note.trim() : '',
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
        
        console.log(`✅ Bank account updated by admin: ${account.bankName}`);
        
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
        
        console.log(`✅ Bank account ${account.isActive ? 'activated' : 'deactivated'} by admin: ${account.bankName}`);
        
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
        
        console.log(`✅ Bank account deleted by admin: ${account.bankName}`);
        
    } catch (error) {
        console.error('❌ Admin bank account delete error:', error);
        res.status(500).json({ error: 'Failed to delete bank account' });
    }
});

// ========================================
// SOCKET.IO HANDLING (tetap sama)
// ========================================

io.on('connection', (socket) => {
    console.log('👤 User connected:', socket.id);
    
    socket.on('join', (userId) => {
        if (userId && typeof userId === 'string') {
            socket.join(userId);
            console.log(`👤 User ${userId} joined room`);
        }
    });
    
    socket.on('subscribe_prices', () => {
        socket.join('price_updates');
        console.log('📊 User subscribed to price updates');
    });
    
    socket.on('subscribe_charts', (data) => {
        try {
            const { symbol, timeframe } = data;
            if (symbol && timeframe) {
                console.log(`📊 User subscribed to chart: ${symbol}/${timeframe}`);
                
                // Join specific chart room
                socket.join(`chart_${symbol}_${timeframe}`);
                
                // Send current chart data if available
                const key = `${symbol}-${timeframe}`;
                const chartData = chartDataStore.get(key);
                if (chartData && chartData.length > 0) {
                    const lastCandle = chartData[chartData.length - 1];
                    if (lastCandle && lastCandle.time) {
                        socket.emit('chartUpdate', {
                            symbol,
                            timeframe,
                            candle: lastCandle
                        });
                        console.log(`📊 Sent initial chart data to user: ${symbol}/${timeframe}`);
                    }
                }
            }
        } catch (error) {
            console.error('❌ Error in chart subscription:', error);
        }
    });
    
    socket.on('unsubscribe_charts', (data) => {
        try {
            const { symbol, timeframe } = data;
            if (symbol && timeframe) {
                socket.leave(`chart_${symbol}_${timeframe}`);
                console.log(`📊 User unsubscribed from chart: ${symbol}/${timeframe}`);
            }
        } catch (error) {
            console.error('❌ Error in chart unsubscription:', error);
        }
    });
    
    socket.on('ping', () => {
        socket.emit('pong');
    });
    
    socket.on('disconnect', (reason) => {
        console.log('👤 User disconnected:', socket.id, 'Reason:', reason);
    });
    
    socket.on('error', (error) => {
        console.error('❌ Socket error:', error);
    });
});

// Enhanced price broadcasting
setInterval(() => {
    if (isInitialized) {
        io.to('price_updates').emit('priceHeartbeat', {
            timestamp: Date.now(),
            message: 'Price updates active'
        });
    }
}, 30000); // Every 30 seconds

// ========================================
// ERROR HANDLING (menggunakan yang dari Dokumen 2)
// ========================================

// Enhanced global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error:', error);
    
    // Log error details
    console.error('Error details:', {
        message: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    
    // Don't leak error details in production
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    res.status(error.status || 500).json({ 
        error: 'Internal server error',
        message: isDevelopment ? error.message : 'Something went wrong',
        timestamp: new Date().toISOString()
    });
});

// Enhanced 404 handler
app.use('*', (req, res) => {
    console.log(`❌ 404 - Route not found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ 
        error: 'Route not found',
        method: req.method,
        path: req.originalUrl,
        timestamp: new Date().toISOString()
    });
});

// ========================================
// GRACEFUL SHUTDOWN (tetap sama)
// ========================================

process.on('SIGTERM', () => {
    console.log('💤 SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('✅ Process terminated');
        mongoose.connection.close();
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('💤 SIGINT received, shutting down gracefully');
    server.close(() => {
        console.log('✅ Process terminated');
        mongoose.connection.close();
        process.exit(0);
    });
});

// ========================================
// SERVER START (menggunakan yang dari Dokumen 2 dengan monitoring)
// ========================================

const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        // Connect to database first
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
        
        // Call after database connection
        if (mongoose.connection.readyState === 1) {
            ensureIndexes();
        } else {
            mongoose.connection.once('connected', ensureIndexes);
        }
        
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
            });
            await admin.save();
            console.log('✅ Default admin user created (admin@tradestation.com / admin123)');
            console.log('✅ Admin settings:', admin.adminSettings);
        } else {
            console.log('✅ Admin user already exists');
            console.log('✅ Admin settings:', adminExists.adminSettings);
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
                },
                {
                    bankName: 'Bank BRI',
                    accountNumber: '5555666677',
                    accountHolder: 'TradeStation Official',
                    note: 'Alternative deposit account',
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
        
        // Mark as initialized
        isInitialized = true;
        
        // Start background processes
        simulatePriceUpdates();
        checkTradesToComplete();
        console.log('✅ Background processes started');
        
        // Start server
        server.listen(PORT, '0.0.0.0', () => {
            console.log(`
🚀 TradeStation Backend Server Started Successfully! - BEST COMBINED VERSION
📍 Port: ${PORT}
🌍 Environment: ${process.env.NODE_ENV || 'development'}
📧 Enhanced Email/Phone Authentication: ✅ (From Dokumen 1 - Best Registration)
📱 Robust Admin Panel: ✅ (From Dokumen 2 - With Timeouts & Optimization)
🛡️  Performance for Many Users: ✅ (Database Optimization & Monitoring)
📊 Real-time Chart Data: ✅ Enhanced
💳 Bank Management: ✅ Enabled
🎯 Trading Control: ✅ Advanced
💰 Profit Settings: ✅ Dynamic
⚙️  Admin Panel: ✅ Complete with Timeouts
🔄 Background Processes: ✅ Running
🗃️  Database: ✅ Connected with Monitoring
📡 Socket.IO: ✅ Ready
⏰ Timestamp: ${new Date().toISOString()}

🔗 API Endpoints:
   • Health Check: GET /api/health
   • Database Health: GET /api/admin/health/database
   • Authentication: POST /api/login, /api/register (Enhanced)
   • Trading: POST /api/trade, GET /api/trades
   • Charts: GET /api/chart/:symbol/:timeframe
   • Admin Panel: /api/admin/* (Enhanced with Timeouts)

📋 Admin Credentials:
   • Email: admin@tradestation.com
   • Password: admin123

✨ COMBINED BEST FEATURES:
   ✅ Enhanced Registration System (Dokumen 1)
   ✅ Robust Admin Deposit Management (Dokumen 2)
   ✅ Database Optimization & Monitoring
   ✅ Memory Usage Tracking
   ✅ Query Timeout Handling
   ✅ Better Error Handling for Production
   ✅ Indonesian Phone Number Validation
   ✅ Transaction Atomic Operations
   ✅ Performance Optimization for High Load

🎯 Ready to serve trading requests with optimal performance!
            `);
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

// Start the server
startServer();

module.exports = app;
