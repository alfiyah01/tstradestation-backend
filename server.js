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
// APP SETUP
// ========================================
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: [
            "https://www.traderstasion.com",
            "http://localhost:3000",
            "http://localhost:5173"
        ],
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling']
});

// ========================================
// MIDDLEWARE
// ========================================
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.socket.io", "https://cdn.livechatinc.com"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: ["'self'", "https://tstradestation-backend-production.up.railway.app", "wss://tstradestation-backend-production.up.railway.app"]
        }
    }
}));

app.use(cors({
    origin: [
        "https://www.traderstasion.com",
        "http://localhost:3000",
        "http://localhost:5173"
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login requests per windowMs
    message: { error: 'Too many login attempts, please try again after 15 minutes.' },
    skipSuccessfulRequests: true
});

app.use('/api', limiter);
app.use('/api/login', loginLimiter);

// File upload setup
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
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('✅ Connected to MongoDB');
    initializeData();
})
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});

// ========================================
// DATABASE SCHEMAS
// ========================================
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, sparse: true },
    phone: { type: String, unique: true, sparse: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    bankName: String,
    accountNumber: String,
    accountHolder: String,
    stats: {
        totalTrades: { type: Number, default: 0 },
        winTrades: { type: Number, default: 0 },
        loseTrades: { type: Number, default: 0 },
        winRate: { type: Number, default: 0 }
    },
    referralCode: { type: String, unique: true },
    taxPaid: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symbol: { type: String, required: true },
    direction: { type: String, required: true, enum: ['buy', 'sell'] },
    amount: { type: Number, required: true },
    duration: { type: Number, required: true },
    entryPrice: { type: Number, required: true },
    exitPrice: Number,
    result: { type: String, enum: ['win', 'lose'] },
    payout: { type: Number, default: 0 },
    status: { type: String, default: 'active', enum: ['active', 'completed'] },
    profitPercentage: { type: Number, default: 80 }
}, { timestamps: true });

const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    method: { type: String, required: true, enum: ['bank', 'qris'] },
    receipt: String, // base64 encoded image
    fileName: String,
    fileType: String,
    status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected'] },
    adminNotes: String,
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    processedAt: Date
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    fee: { type: Number, required: true },
    finalAmount: { type: Number, required: true },
    status: { type: String, default: 'pending', enum: ['pending', 'approved', 'processed', 'rejected'] },
    adminNotes: String,
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    processedAt: Date
}, { timestamps: true });

const bankAccountSchema = new mongoose.Schema({
    bankName: { type: String, required: true },
    accountNumber: { type: String, required: true },
    accountHolder: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    note: String
}, { timestamps: true });

const cryptoPriceSchema = new mongoose.Schema({
    symbol: { type: String, required: true, unique: true },
    price: { type: Number, required: true },
    change: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: Date.now }
});

const taxSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    totalProfit: { type: Number, required: true },
    taxAmount: { type: Number, required: true },
    taxPercentage: { type: Number, default: 10 },
    threshold: { type: Number, default: 50000000 }, // 50 million
    isPaid: { type: Boolean, default: false },
    paidAt: Date,
    notes: String,
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

// Models
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
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user || !user.isActive) {
            return res.status(403).json({ error: 'User not found or inactive' });
        }
        
        req.user = user;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
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
    return phoneRegex.test(phone);
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
        if (data.symbol && data.timeframe) {
            socket.join(`chart_${data.symbol}_${data.timeframe}`);
            console.log(`📈 User subscribed to ${data.symbol} ${data.timeframe} chart`);
        }
    });

    socket.on('disconnect', () => {
        if (socket.userId) {
            connectedUsers.delete(socket.userId);
            console.log(`❌ User ${socket.userId} disconnected`);
        }
    });
});

// ========================================
// CRYPTO PRICE SIMULATION
// ========================================
const updateCryptoPrices = async () => {
    try {
        const symbols = ['BTC', 'ETH', 'LTC', 'XRP', 'DOGE', 'TRX'];
        
        for (const symbol of symbols) {
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

            // Simulate price movement
            const volatility = 0.002; // 0.2% max change per update
            const randomChange = (Math.random() - 0.5) * volatility;
            const oldPrice = price.price;
            const newPrice = Math.max(0.001, oldPrice * (1 + randomChange));
            const changePercent = ((newPrice - oldPrice) / oldPrice) * 100;

            price.price = newPrice;
            price.change = changePercent;
            price.lastUpdated = new Date();

            await price.save();

            // Emit to connected clients
            io.to('price_updates').emit('priceUpdate', {
                symbol,
                price: newPrice,
                change: changePercent
            });
        }
    } catch (error) {
        console.error('❌ Error updating crypto prices:', error);
    }
};

// Update prices every 5 seconds
setInterval(updateCryptoPrices, 5000);

// ========================================
// TRADE COMPLETION PROCESSOR
// ========================================
const processCompletedTrades = async () => {
    try {
        const activeTrades = await Trade.find({
            status: 'active',
            createdAt: {
                $lte: new Date(Date.now() - 30 * 1000) // 30 seconds ago
            }
        }).populate('userId');

        for (const trade of activeTrades) {
            // Get current price
            const currentPriceData = await CryptoPrice.findOne({ symbol: trade.symbol });
            const currentPrice = currentPriceData ? currentPriceData.price : trade.entryPrice;

            // Determine if trade is winning
            const isWin = (trade.direction === 'buy' && currentPrice > trade.entryPrice) ||
                         (trade.direction === 'sell' && currentPrice < trade.entryPrice);

            // Calculate random result (80% win rate for demonstration)
            const randomWin = Math.random() < 0.8;
            const finalResult = isWin && randomWin ? 'win' : 'lose';

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
            await trade.save();

            // Update user balance and stats
            const user = trade.userId;
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
                        payout: payout
                    },
                    newBalance: user.balance
                });
            }

            console.log(`✅ Trade completed: ${trade.symbol} ${trade.direction} - ${finalResult} - User: ${user.name}`);
        }
    } catch (error) {
        console.error('❌ Error processing completed trades:', error);
    }
};

// Process trades every 10 seconds
setInterval(processCompletedTrades, 10000);

// ========================================
// TAX MANAGEMENT FUNCTIONS
// ========================================
const checkAndUpdateTaxStatus = async (userId) => {
    try {
        const user = await User.findById(userId);
        if (!user) return;

        const TAX_THRESHOLD = 50000000; // 50 million IDR
        const TAX_PERCENTAGE = 10; // 10%

        if (user.totalProfit >= TAX_THRESHOLD) {
            let taxRecord = await Tax.findOne({ userId });
            
            if (!taxRecord) {
                // Create new tax record
                const taxAmount = user.totalProfit * (TAX_PERCENTAGE / 100);
                
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
                const newTaxAmount = user.totalProfit * (TAX_PERCENTAGE / 100);
                taxRecord.totalProfit = user.totalProfit;
                taxRecord.taxAmount = newTaxAmount;
                await taxRecord.save();
            }
        }
    } catch (error) {
        console.error('❌ Error checking tax status:', error);
    }
};

// ========================================
// API ROUTES
// ========================================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        env: process.env.NODE_ENV 
    });
});

// Authentication routes
app.post('/api/register', async (req, res) => {
    try {
        const { name, identifier, password } = req.body;

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
            balance: 0 // No bonus for new users
        });

        await user.save();

        const token = jwt.sign(
            { userId: user._id, email: user.email, phone: user.phone },
            process.env.JWT_SECRET,
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
        res.status(500).json({ error: 'Registration failed' });
    }
});

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

        const token = jwt.sign(
            { userId: user._id, email: user.email, phone: user.phone },
            process.env.JWT_SECRET,
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

// Profile routes
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

// Crypto prices
app.get('/api/prices', authenticateToken, async (req, res) => {
    try {
        const prices = await CryptoPrice.find({}).sort({ symbol: 1 });
        res.json(prices);
    } catch (error) {
        console.error('❌ Prices error:', error);
        res.status(500).json({ error: 'Failed to fetch prices' });
    }
});

// Trading routes
app.post('/api/trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, direction, amount, duration } = req.body;

        if (!symbol || !direction || !amount || !duration) {
            return res.status(400).json({ error: 'All trade fields are required' });
        }

        if (amount < 500000 || amount > 100000000) {
            return res.status(400).json({ error: 'Trade amount must be between Rp 500,000 and Rp 100,000,000' });
        }

        if (!['buy', 'sell'].includes(direction)) {
            return res.status(400).json({ error: 'Direction must be buy or sell' });
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
        io.to(`user_${req.user._id}`).emit('tradeCreated', {
            trade,
            newBalance: user.balance
        });

        res.json({
            message: 'Trade created successfully',
            trade,
            newBalance: user.balance
        });

        console.log(`📈 Trade created: ${user.name} - ${symbol} ${direction} ${formatCurrency(amount)}`);
    } catch (error) {
        console.error('❌ Trade error:', error);
        res.status(500).json({ error: 'Failed to create trade' });
    }
});

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

// Bank accounts for deposit
app.get('/api/bank-accounts/active', authenticateToken, async (req, res) => {
    try {
        const accounts = await BankAccount.find({ isActive: true }).sort({ createdAt: -1 });
        res.json(accounts);
    } catch (error) {
        console.error('❌ Bank accounts error:', error);
        res.status(500).json({ error: 'Failed to fetch bank accounts' });
    }
});

// Deposit routes
app.post('/api/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount, receipt, fileName, fileType, method = 'bank' } = req.body;

        if (!amount || amount < 500000) {
            return res.status(400).json({ error: 'Minimum deposit amount is Rp 500,000' });
        }

        if (!receipt) {
            return res.status(400).json({ error: 'Receipt image is required' });
        }

        if (!['bank', 'qris'].includes(method)) {
            return res.status(400).json({ error: 'Invalid payment method' });
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

// Withdrawal routes
app.post('/api/withdrawal', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;

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
        const fee = Math.max(6500, amount * 0.01);
        const finalAmount = amount - fee;

        // Deduct from user balance
        user.balance -= amount;
        await user.save();

        // Create withdrawal request
        const withdrawal = new Withdrawal({
            userId: req.user._id,
            amount,
            fee,
            finalAmount
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

        console.log(`💸 Withdrawal request: ${user.name} - ${formatCurrency(finalAmount)} (fee: ${formatCurrency(fee)})`);
    } catch (error) {
        console.error('❌ Withdrawal error:', error);
        res.status(500).json({ error: 'Failed to submit withdrawal request' });
    }
});

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

// Tax routes
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
            createdAt: taxRecord.createdAt
        });
    } catch (error) {
        console.error('❌ Tax status error:', error);
        res.status(500).json({ error: 'Failed to fetch tax status' });
    }
});

// ========================================
// ADMIN ROUTES
// ========================================
app.get('/api/admin/deposits', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { status = 'pending', page = 1, limit = 20 } = req.query;
        
        const deposits = await Deposit.find({ status })
            .populate('userId', 'name email phone')
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
            io.to(`user_${user._id}`).emit('depositApproved', {
                amount: deposit.amount,
                newBalance: user.balance
            });
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

app.get('/api/admin/withdrawals', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { status = 'pending', page = 1, limit = 20 } = req.query;
        
        const withdrawals = await Withdrawal.find({ status })
            .populate('userId', 'name email phone bankName accountNumber accountHolder')
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

        if (withdrawal.status !== 'pending' && withdrawal.status !== 'approved') {
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

// Tax management
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
        }

        await taxRecord.save();

        // Emit real-time update to user
        io.to(`user_${userId}`).emit('tax_status_updated', {
            userId,
            isPaid,
            paidAt: taxRecord.paidAt,
            notes: taxRecord.notes
        });

        res.json({
            message: `Tax status updated successfully`,
            taxRecord
        });

        const user = await User.findById(userId);
        console.log(`📋 Tax ${isPaid ? 'marked as paid' : 'marked as unpaid'}: ${user?.name} by ${req.user.name}`);
    } catch (error) {
        console.error('❌ Admin tax update error:', error);
        res.status(500).json({ error: 'Failed to update tax status' });
    }
});

// Bank account management
app.post('/api/admin/bank-accounts', authenticateToken, adminOnly, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder, note } = req.body;

        if (!bankName || !accountNumber || !accountHolder) {
            return res.status(400).json({ error: 'All bank fields are required' });
        }

        const bankAccount = new BankAccount({
            bankName,
            accountNumber,
            accountHolder,
            note: note || ''
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

app.get('/api/admin/stats', authenticateToken, adminOnly, async (req, res) => {
    try {
        const [
            totalUsers,
            totalDeposits,
            totalWithdrawals,
            totalTrades,
            pendingDeposits,
            pendingWithdrawals
        ] = await Promise.all([
            User.countDocuments({ role: 'user' }),
            Deposit.countDocuments(),
            Withdrawal.countDocuments(),
            Trade.countDocuments(),
            Deposit.countDocuments({ status: 'pending' }),
            Withdrawal.countDocuments({ status: 'pending' })
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
                active: await User.countDocuments({ role: 'user', isActive: true })
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

// ========================================
// STATIC FILES & ERROR HANDLING
// ========================================
app.use(express.static('public'));

// Serve index.html for all non-API routes
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File size too large. Maximum 5MB allowed.' });
        }
    }
    
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// ========================================
// DATABASE INITIALIZATION
// ========================================
const initializeData = async () => {
    try {
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
        }

        // Initialize crypto prices
        const cryptoExists = await CryptoPrice.findOne();
        if (!cryptoExists) {
            const initialPrices = [
                { symbol: 'BTC', price: 45000, change: 2.45 },
                { symbol: 'ETH', price: 3200, change: -1.23 },
                { symbol: 'LTC', price: 180, change: 0.87 },
                { symbol: 'XRP', price: 0.65, change: 3.21 },
                { symbol: 'DOGE', price: 0.08, change: -2.15 },
                { symbol: 'TRX', price: 0.12, change: 1.45 }
            ];

            await CryptoPrice.insertMany(initialPrices);
            console.log('✅ Initial crypto prices loaded');
        }

        // Initialize sample bank accounts
        const bankExists = await BankAccount.findOne();
        if (!bankExists) {
            const bankAccounts = [
                {
                    bankName: 'Bank BCA',
                    accountNumber: '1234567890',
                    accountHolder: 'TradeStation Indonesia',
                    note: 'Transfer ke rekening ini untuk deposit via Bank BCA'
                },
                {
                    bankName: 'Bank Mandiri',
                    accountNumber: '9876543210',
                    accountHolder: 'TradeStation Indonesia',
                    note: 'Transfer ke rekening ini untuk deposit via Bank Mandiri'
                }
            ];

            await BankAccount.insertMany(bankAccounts);
            console.log('✅ Sample bank accounts created');
        }

        console.log('✅ Database initialization completed');
    } catch (error) {
        console.error('❌ Database initialization error:', error);
    }
};

// ========================================
// SERVER START
// ========================================
const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
    console.log(`
🚀 TradeStation Server Running!
📍 Port: ${PORT}
🌍 Environment: ${process.env.NODE_ENV}
🔗 Frontend: ${process.env.FRONTEND_URL}
💾 Database: Connected to MongoDB
⚡ Socket.IO: Enabled
🔐 JWT Secret: Configured
📊 Real-time Updates: Active
    `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🔄 SIGTERM received, shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        mongoose.connection.close(false, () => {
            console.log('✅ Database connection closed');
            process.exit(0);
        });
    });
});

process.on('SIGINT', () => {
    console.log('🔄 SIGINT received, shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        mongoose.connection.close(false, () => {
            console.log('✅ Database connection closed');
            process.exit(0);
        });
    });
});

module.exports = app;
