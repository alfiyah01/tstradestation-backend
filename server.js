const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// ===========================================
// KONFIGURASI APLIKASI (Pengaturan Dasar)
// ===========================================

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: function (origin, callback) {
            const allowedOrigins = [
                'https://ts-traderstation.com',
                'http://ts-traderstation.com',
                'https://www.ts-traderstation.com', 
                'http://www.ts-traderstation.com',
                'https://ts-traderstation.netlify.app',
                'https://www.ts-traderstation.netlify.app',
                'http://localhost:3000',
                'http://localhost:5000'
            ];
            
            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                callback(null, true); // Allow all for debugging
            }
        },
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true,
        allowEIO3: true
    },
    transports: ['websocket', 'polling'],
    pingTimeout: 60000,
    pingInterval: 25000
});

// Pengaturan port
const PORT = process.env.PORT || 3000;

// Kunci rahasia untuk JWT (token keamanan)
const JWT_SECRET = process.env.JWT_SECRET || 'tradestation_secret_key_2024';

// ===========================================
// MIDDLEWARE (Penghubung Aplikasi)
// ===========================================

// Trust proxy (penting untuk Railway)
app.set('trust proxy', 1);

// Keamanan aplikasi dengan konfigurasi yang lebih permissive
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS Configuration yang lebih komprehensif
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'https://ts-traderstation.com',
            'http://ts-traderstation.com',
            'https://www.ts-traderstation.com', 
            'http://www.ts-traderstation.com',
            'https://ts-traderstation.netlify.app',
            'https://www.ts-traderstation.netlify.app',
            'http://localhost:3000',
            'http://localhost:5000',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:5000'
        ];
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            callback(null, true); // Allow all for debugging - change to false in production
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'Accept', 
        'Origin', 
        'X-Requested-With',
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Headers',
        'Access-Control-Allow-Methods'
    ],
    exposedHeaders: ['Content-Length', 'X-Foo', 'X-Bar'],
    optionsSuccessStatus: 200,
    preflightContinue: false
};

// Apply CORS
app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

// Additional CORS headers for stubborn browsers
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, Origin, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

// Membaca data JSON dari request
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${req.headers.origin || 'none'}`);
    next();
});

// Membatasi jumlah request (mencegah spam) - lebih permissive untuk testing
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 menit
    max: 200, // maksimal 200 request per 15 menit (dinaikkan untuk testing)
    message: { error: 'Terlalu banyak request, coba lagi nanti' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// ===========================================
// KONEKSI DATABASE MONGODB
// ===========================================

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://tradestation:Yusrizal1993@clustertrading.7jozj2u.mongodb.net/tradestation?retryWrites=true&w=majority&appName=Clustertrading';

// MongoDB connection with better error handling
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    family: 4
}).then(() => {
    console.log('✅ Database MongoDB berhasil terhubung');
    console.log('📊 Database name:', mongoose.connection.name);
}).catch((error) => {
    console.error('❌ Error koneksi database:', error.message);
    // Don't exit process, let it try to reconnect
});

// MongoDB connection event handlers
mongoose.connection.on('connected', () => {
    console.log('🔗 MongoDB connected successfully');
});

mongoose.connection.on('error', (error) => {
    console.error('❌ MongoDB connection error:', error.message);
});

mongoose.connection.on('disconnected', () => {
    console.log('🔌 MongoDB disconnected');
});

// Graceful shutdown
process.on('SIGINT', async () => {
    await mongoose.connection.close();
    console.log('🔌 MongoDB connection closed through app termination');
    process.exit(0);
});

// ===========================================
// SCHEMA DATABASE (Struktur Data)
// ===========================================

// Schema untuk User (Data Pengguna)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String },
    balance: { type: Number, default: 0 },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    accountType: { type: String, default: 'standard', enum: ['standard', 'premium'] },
    isActive: { type: Boolean, default: true },
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

// Schema untuk Trade (Data Trading)
const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symbol: { type: String, required: true }, // BTC, ETH, dll
    direction: { type: String, required: true, enum: ['buy', 'sell'] },
    amount: { type: Number, required: true },
    entryPrice: { type: Number, required: true },
    exitPrice: { type: Number },
    profitPercentage: { type: Number, required: true },
    duration: { type: Number, required: true }, // dalam detik
    status: { type: String, default: 'active', enum: ['active', 'completed', 'cancelled'] },
    result: { type: String, enum: ['win', 'lose'] },
    payout: { type: Number, default: 0 },
    priceChangePercent: { type: Number },
    forceResult: { type: String, enum: ['win', 'lose'] },
    completedAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Schema untuk Deposit (Data Setoran)
const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    method: { type: String, default: 'Bank Transfer' },
    bankFrom: { type: String, required: true },
    receipt: { type: String, required: true },
    status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected'] },
    adminNotes: { type: String },
    transferTime: { type: Date },
    processedAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Schema untuk Withdrawal (Data Penarikan)
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
    status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected', 'processed'] },
    adminNotes: { type: String },
    processedAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Schema untuk Activity Log (Log Aktivitas)
const activitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    details: { type: String },
    ipAddress: { type: String },
    userAgent: { type: String },
    createdAt: { type: Date, default: Date.now }
});

// Membuat Model dari Schema
const User = mongoose.model('User', userSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Activity = mongoose.model('Activity', activitySchema);

// ===========================================
// FUNGSI BANTUAN (Helper Functions)
// ===========================================

// Generate kode referral unik
function generateReferralCode() {
    return 'TS' + Math.random().toString(36).substr(2, 6).toUpperCase();
}

// Fungsi untuk log aktivitas user
async function logActivity(userId, action, details, req) {
    try {
        await new Activity({
            userId,
            action,
            details,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        }).save();
    } catch (error) {
        console.error('Error logging activity:', error);
    }
}

// Middleware untuk verifikasi token JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token tidak ditemukan' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token tidak valid' });
        }
        req.user = user;
        next();
    });
}

// Middleware khusus untuk admin
function authenticateAdmin(req, res, next) {
    authenticateToken(req, res, async (err) => {
        if (err) return;
        
        try {
            const user = await User.findById(req.user.id);
            if (!user || user.email !== 'admin@tradestation.com') {
                return res.status(403).json({ error: 'Akses admin diperlukan' });
            }
            next();
        } catch (error) {
            res.status(500).json({ error: 'Error verifikasi admin' });
        }
    });
}

// ===========================================
// SISTEM HARGA CRYPTO REAL-TIME
// ===========================================

// Data harga cryptocurrency (simulasi real-time)
let cryptoPrices = {
    BTC: { symbol: 'BTC', price: 45000, change: 2.45, lastUpdate: Date.now() },
    ETH: { symbol: 'ETH', price: 3200, change: -1.23, lastUpdate: Date.now() },
    LTC: { symbol: 'LTC', price: 180, change: 0.85, lastUpdate: Date.now() },
    XRP: { symbol: 'XRP', price: 0.75, change: 1.45, lastUpdate: Date.now() },
    DOGE: { symbol: 'DOGE', price: 0.12, change: -0.65, lastUpdate: Date.now() },
    TRX: { symbol: 'TRX', price: 0.08, change: 0.95, lastUpdate: Date.now() },
    ETC: { symbol: 'ETC', price: 25, change: 1.75, lastUpdate: Date.now() },
    NEO: { symbol: 'NEO', price: 15, change: -0.25, lastUpdate: Date.now() }
};

// Fungsi update harga secara otomatis
function updateCryptoPrices() {
    Object.keys(cryptoPrices).forEach(symbol => {
        const crypto = cryptoPrices[symbol];
        
        // Simulasi perubahan harga random (-2% sampai +2%)
        const changePercent = (Math.random() - 0.5) * 4;
        const priceChange = crypto.price * (changePercent / 100);
        
        crypto.price = Math.max(0.01, crypto.price + priceChange);
        crypto.change = changePercent;
        crypto.lastUpdate = Date.now();
    });

    // Kirim update ke semua client yang terhubung
    io.emit('priceUpdate', cryptoPrices);
}

// Update harga setiap 2 detik
setInterval(updateCryptoPrices, 2000);

// ===========================================
// TRADING ENGINE (Mesin Trading)
// ===========================================

// Fungsi untuk memproses trade yang sudah expired
async function processExpiredTrades() {
    try {
        const activeTrades = await Trade.find({ status: 'active' }).populate('userId');
        
        for (const trade of activeTrades) {
            const tradeAge = (Date.now() - new Date(trade.createdAt)) / 1000;
            
            // Cek apakah trade sudah expired
            if (tradeAge >= trade.duration) {
                const currentPrice = cryptoPrices[trade.symbol]?.price || trade.entryPrice;
                const priceChangePercent = ((currentPrice - trade.entryPrice) / trade.entryPrice) * 100;
                
                let result;
                
                // Cek apakah admin memaksa hasil
                if (trade.forceResult) {
                    result = trade.forceResult;
                } else {
                    // Logika hasil trade berdasarkan arah dan perubahan harga
                    if (trade.direction === 'buy') {
                        result = currentPrice > trade.entryPrice ? 'win' : 'lose';
                    } else { // sell
                        result = currentPrice < trade.entryPrice ? 'win' : 'lose';
                    }
                }
                
                // Hitung payout
                let payout = 0;
                if (result === 'win') {
                    payout = trade.amount + (trade.amount * trade.profitPercentage / 100);
                }
                
                // Update trade
                trade.status = 'completed';
                trade.result = result;
                trade.exitPrice = currentPrice;
                trade.payout = payout;
                trade.priceChangePercent = priceChangePercent;
                trade.completedAt = new Date();
                await trade.save();
                
                // Update user balance dan stats
                const user = trade.userId;
                if (result === 'win') {
                    user.balance += payout;
                    user.totalProfit += (payout - trade.amount);
                    user.stats.winTrades += 1;
                } else {
                    user.totalLoss += trade.amount;
                    user.stats.loseTrades += 1;
                }
                
                user.stats.totalTrades += 1;
                user.stats.winRate = (user.stats.winTrades / user.stats.totalTrades) * 100;
                await user.save();
                
                // Kirim notifikasi ke user
                io.to(user._id.toString()).emit('tradeCompleted', {
                    trade: trade,
                    result: result,
                    payout: payout,
                    newBalance: user.balance
                });
                
                console.log(`✅ Trade ${trade._id} completed: ${result.toUpperCase()}`);
            }
        }
    } catch (error) {
        console.error('❌ Error processing trades:', error);
    }
}

// Proses trade expired setiap 1 detik
setInterval(processExpiredTrades, 1000);

// ===========================================
// API ROUTES - AUTHENTICATION
// ===========================================

// Health Check - Enhanced
app.get('/api/health', (req, res) => {
    // Set CORS headers explicitly for health check
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    const healthData = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        message: 'TradeStation API is running perfectly!',
        environment: process.env.NODE_ENV || 'development',
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        version: '1.0.0',
        cors: 'Enabled',
        endpoints: {
            auth: '/api/login, /api/register',
            trading: '/api/trade, /api/prices',
            admin: '/api/admin/*'
        }
    };
    
    console.log('Health check requested from:', req.headers.origin || req.ip);
    res.status(200).json(healthData);
});

// Root endpoint
app.get('/', (req, res) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.json({ 
        message: 'TradeStation API Server', 
        status: 'Running',
        docs: '/api/health for health check'
    });
});

// API root
app.get('/api', (req, res) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.json({ 
        message: 'TradeStation API v1.0.0', 
        status: 'Active',
        endpoints: {
            health: '/api/health',
            auth: '/api/login, /api/register, /api/profile',
            prices: '/api/prices',
            trading: '/api/trade, /api/trades',
            deposits: '/api/deposit, /api/deposits',
            withdrawals: '/api/withdrawal, /api/withdrawals',
            admin: '/api/admin/*'
        }
    });
});

// Register User Baru
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        
        // Validasi input
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Nama, email, dan password harus diisi' });
        }
        
        // Cek apakah email sudah ada
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email sudah terdaftar' });
        }
        
        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Buat user baru
        const user = new User({
            name,
            email,
            phone,
            password: hashedPassword,
            referralCode: generateReferralCode(),
            balance: 0 // Saldo awal 0
        });
        
        await user.save();
        
        // Buat token JWT
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
        
        // Log aktivitas
        await logActivity(user._id, 'USER_REGISTER', 'User registered successfully', req);
        
        // Response tanpa password
        const userResponse = {
            id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            balance: user.balance,
            totalProfit: user.totalProfit,
            accountType: user.accountType,
            referralCode: user.referralCode,
            stats: user.stats
        };
        
        res.status(201).json({ 
            token, 
            user: userResponse,
            message: 'Registrasi berhasil!'
        });
        
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Server error saat registrasi' });
    }
});

// Login User
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validasi input
        if (!email || !password) {
            return res.status(400).json({ error: 'Email dan password harus diisi' });
        }
        
        // Cari user berdasarkan email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Email atau password salah' });
        }
        
        // Cek password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Email atau password salah' });
        }
        
        // Cek apakah user aktif
        if (!user.isActive) {
            return res.status(400).json({ error: 'Akun Anda tidak aktif' });
        }
        
        // Update last login
        user.lastLoginAt = new Date();
        await user.save();
        
        // Buat token JWT
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
        
        // Log aktivitas
        await logActivity(user._id, 'USER_LOGIN', 'User logged in successfully', req);
        
        // Response tanpa password
        const userResponse = {
            id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            balance: user.balance,
            totalProfit: user.totalProfit,
            totalLoss: user.totalLoss,
            accountType: user.accountType,
            referralCode: user.referralCode,
            stats: user.stats
        };
        
        res.json({ 
            token, 
            user: userResponse,
            message: 'Login berhasil!'
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error saat login' });
    }
});

// ===========================================
// API ROUTES - USER PROFILE
// ===========================================

// Get User Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        res.json(user);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update User Profile
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { name, phone } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { name, phone },
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        await logActivity(req.user.id, 'PROFILE_UPDATE', 'Profile updated successfully', req);
        
        res.json(user);
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===========================================
// API ROUTES - CRYPTOCURRENCY PRICES
// ===========================================

// Get All Crypto Prices
app.get('/api/prices', (req, res) => {
    const pricesArray = Object.values(cryptoPrices);
    res.json(pricesArray);
});

// Get Specific Crypto Price
app.get('/api/prices/:symbol', (req, res) => {
    const { symbol } = req.params;
    const price = cryptoPrices[symbol.toUpperCase()];
    
    if (!price) {
        return res.status(404).json({ error: 'Cryptocurrency tidak ditemukan' });
    }
    
    res.json(price);
});

// ===========================================
// API ROUTES - TRADING
// ===========================================

// Create New Trade
app.post('/api/trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, direction, amount, profitPercentage, duration } = req.body;
        
        // Validasi input
        if (!symbol || !direction || !amount || !profitPercentage || !duration) {
            return res.status(400).json({ error: 'Semua field harus diisi' });
        }
        
        // Validasi amount
        if (amount < 500000 || amount > 100000000) {
            return res.status(400).json({ error: 'Jumlah trading harus antara Rp 500.000 - Rp 100.000.000' });
        }
        
        // Cek saldo user
        const user = await User.findById(req.user.id);
        if (user.balance < amount) {
            return res.status(400).json({ error: 'Saldo tidak mencukupi' });
        }
        
        // Get current price
        const currentPrice = cryptoPrices[symbol.toUpperCase()]?.price;
        if (!currentPrice) {
            return res.status(400).json({ error: 'Harga cryptocurrency tidak tersedia' });
        }
        
        // Kurangi saldo user
        user.balance -= amount;
        await user.save();
        
        // Buat trade baru
        const trade = new Trade({
            userId: req.user.id,
            symbol: symbol.toUpperCase(),
            direction,
            amount,
            entryPrice: currentPrice,
            profitPercentage,
            duration
        });
        
        await trade.save();
        
        // Log aktivitas
        await logActivity(req.user.id, 'TRADE_CREATED', `Created ${direction} trade for ${symbol} with amount ${amount}`, req);
        
        // Emit ke socket
        io.to(req.user.id).emit('tradeCreated', {
            trade: trade,
            newBalance: user.balance
        });
        
        res.status(201).json({
            trade: trade,
            newBalance: user.balance,
            message: 'Trade berhasil dibuat!'
        });
        
    } catch (error) {
        console.error('Trade creation error:', error);
        res.status(500).json({ error: 'Server error saat membuat trade' });
    }
});

// Get User Trades
app.get('/api/trades', authenticateToken, async (req, res) => {
    try {
        const { limit = 20, status } = req.query;
        
        let query = { userId: req.user.id };
        if (status) {
            query.status = status;
        }
        
        const trades = await Trade.find(query)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));
        
        res.json({ trades });
    } catch (error) {
        console.error('Get trades error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===========================================
// API ROUTES - DEPOSITS
// ===========================================

// Create Deposit Request
app.post('/api/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount, bankFrom, receipt, transferTime } = req.body;
        
        // Validasi input
        if (!amount || !bankFrom || !receipt) {
            return res.status(400).json({ error: 'Semua field harus diisi' });
        }
        
        // Validasi minimum amount
        if (amount < 50000) {
            return res.status(400).json({ error: 'Minimum deposit Rp 50.000' });
        }
        
        // Buat deposit request
        const deposit = new Deposit({
            userId: req.user.id,
            amount,
            bankFrom,
            receipt,
            transferTime: transferTime || new Date()
        });
        
        await deposit.save();
        
        // Log aktivitas
        await logActivity(req.user.id, 'DEPOSIT_REQUEST', `Deposit request of ${amount}`, req);
        
        res.status(201).json({
            deposit: deposit,
            message: 'Permintaan deposit berhasil dikirim!'
        });
        
    } catch (error) {
        console.error('Deposit error:', error);
        res.status(500).json({ error: 'Server error saat deposit' });
    }
});

// Get User Deposits
app.get('/api/deposits', authenticateToken, async (req, res) => {
    try {
        const deposits = await Deposit.find({ userId: req.user.id })
            .sort({ createdAt: -1 });
        
        res.json(deposits);
    } catch (error) {
        console.error('Get deposits error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===========================================
// API ROUTES - WITHDRAWALS
// ===========================================

// Create Withdrawal Request
app.post('/api/withdrawal', authenticateToken, async (req, res) => {
    try {
        const { amount, bankAccount } = req.body;
        
        // Validasi input
        if (!amount || !bankAccount || !bankAccount.bankName || !bankAccount.accountNumber || !bankAccount.accountHolder) {
            return res.status(400).json({ error: 'Semua field harus diisi' });
        }
        
        // Validasi minimum amount
        if (amount < 100000) {
            return res.status(400).json({ error: 'Minimum withdrawal Rp 100.000' });
        }
        
        // Cek saldo user
        const user = await User.findById(req.user.id);
        if (user.balance < amount) {
            return res.status(400).json({ error: 'Saldo tidak mencukupi' });
        }
        
        // Hitung fee (1% minimum Rp 6.500)
        const fee = Math.max(6500, amount * 0.01);
        const finalAmount = amount - fee;
        
        // Kurangi saldo user
        user.balance -= amount;
        await user.save();
        
        // Buat withdrawal request
        const withdrawal = new Withdrawal({
            userId: req.user.id,
            amount,
            fee,
            finalAmount,
            bankAccount
        });
        
        await withdrawal.save();
        
        // Log aktivitas
        await logActivity(req.user.id, 'WITHDRAWAL_REQUEST', `Withdrawal request of ${amount}`, req);
        
        res.status(201).json({
            withdrawal: withdrawal,
            newBalance: user.balance,
            message: 'Permintaan withdrawal berhasil dikirim!'
        });
        
    } catch (error) {
        console.error('Withdrawal error:', error);
        res.status(500).json({ error: 'Server error saat withdrawal' });
    }
});

// Get User Withdrawals
app.get('/api/withdrawals', authenticateToken, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.user.id })
            .sort({ createdAt: -1 });
        
        res.json(withdrawals);
    } catch (error) {
        console.error('Get withdrawals error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===========================================
// API ROUTES - ADMIN PANEL
// ===========================================

// Admin Dashboard Stats
app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
    try {
        // Hitung statistik
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isActive: true });
        const totalTrades = await Trade.countDocuments();
        const activeTrades = await Trade.countDocuments({ status: 'active' });
        const pendingDeposits = await Deposit.countDocuments({ status: 'pending' });
        const totalDeposits = await Deposit.countDocuments({ status: 'approved' });
        const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
        const totalWithdrawals = await Withdrawal.countDocuments();
        
        // Hitung volume trading
        const totalVolume = await Trade.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayVolume = await Trade.aggregate([
            { $match: { createdAt: { $gte: today } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        
        // Recent activities
        const recentActivities = await Activity.find()
            .populate('userId', 'name')
            .sort({ createdAt: -1 })
            .limit(20);
        
        const stats = {
            users: { total: totalUsers, active: activeUsers },
            trades: { total: totalTrades, active: activeTrades },
            deposits: { total: totalDeposits, pending: pendingDeposits },
            withdrawals: { total: totalWithdrawals, pending: pendingWithdrawals },
            volume: {
                total: totalVolume[0]?.total || 0,
                today: todayVolume[0]?.total || 0
            }
        };
        
        res.json({ stats, recentActivities });
    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Get All Users
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        res.json({ users });
    } catch (error) {
        console.error('Admin get users error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Get User Detail
app.get('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        const trades = await Trade.find({ userId: req.params.id }).sort({ createdAt: -1 }).limit(20);
        const deposits = await Deposit.find({ userId: req.params.id }).sort({ createdAt: -1 }).limit(10);
        const withdrawals = await Withdrawal.find({ userId: req.params.id }).sort({ createdAt: -1 }).limit(10);
        
        res.json({ user, trades, deposits, withdrawals });
    } catch (error) {
        console.error('Admin get user detail error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Update User
app.put('/api/admin/user/:id', authenticateAdmin, async (req, res) => {
    try {
        const { name, email, balance, phone, accountType, isActive } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { name, email, balance, phone, accountType, isActive },
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        await logActivity(req.user.id, 'ADMIN_UPDATE_USER', `Updated user ${user.email}`, req);
        
        res.json({ user, message: 'User berhasil diupdate' });
    } catch (error) {
        console.error('Admin update user error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Delete/Deactivate User
app.delete('/api/admin/user/:id', authenticateAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { isActive: false },
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        await logActivity(req.user.id, 'ADMIN_DEACTIVATE_USER', `Deactivated user ${user.email}`, req);
        
        res.json({ user, message: 'User berhasil dinonaktifkan' });
    } catch (error) {
        console.error('Admin deactivate user error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Get All Trades
app.get('/api/admin/trades', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        let query = {};
        if (status) query.status = status;
        
        const trades = await Trade.find(query)
            .populate('userId', 'name email')
            .sort({ createdAt: -1 });
        
        res.json({ trades });
    } catch (error) {
        console.error('Admin get trades error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Control Trade Result
app.put('/api/admin/trade/:id', authenticateAdmin, async (req, res) => {
    try {
        const { forceResult } = req.body;
        
        const trade = await Trade.findByIdAndUpdate(
            req.params.id,
            { forceResult },
            { new: true }
        );
        
        if (!trade) {
            return res.status(404).json({ error: 'Trade tidak ditemukan' });
        }
        
        await logActivity(req.user.id, 'ADMIN_CONTROL_TRADE', `Forced trade ${trade._id} result to ${forceResult}`, req);
        
        res.json({ trade, message: `Trade result diset ke ${forceResult.toUpperCase()}` });
    } catch (error) {
        console.error('Admin control trade error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Get All Deposits
app.get('/api/admin/deposits', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        let query = {};
        if (status) query.status = status;
        
        const deposits = await Deposit.find(query)
            .populate('userId', 'name email')
            .sort({ createdAt: -1 });
        
        res.json({ deposits });
    } catch (error) {
        console.error('Admin get deposits error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Update Deposit Status
app.put('/api/admin/deposit/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status, adminNotes } = req.body;
        
        const deposit = await Deposit.findById(req.params.id).populate('userId');
        if (!deposit) {
            return res.status(404).json({ error: 'Deposit tidak ditemukan' });
        }
        
        deposit.status = status;
        deposit.adminNotes = adminNotes;
        deposit.processedAt = new Date();
        await deposit.save();
        
        // Jika disetujui, tambah balance user
        if (status === 'approved') {
            const user = deposit.userId;
            user.balance += deposit.amount;
            await user.save();
            
            // Emit ke user
            io.to(user._id.toString()).emit('depositApproved', {
                amount: deposit.amount,
                newBalance: user.balance
            });
        }
        
        await logActivity(req.user.id, 'ADMIN_UPDATE_DEPOSIT', `${status} deposit ${deposit._id}`, req);
        
        res.json({ deposit, message: `Deposit ${status}` });
    } catch (error) {
        console.error('Admin update deposit error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Get All Withdrawals
app.get('/api/admin/withdrawals', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        let query = {};
        if (status) query.status = status;
        
        const withdrawals = await Withdrawal.find(query)
            .populate('userId', 'name email')
            .sort({ createdAt: -1 });
        
        res.json({ withdrawals });
    } catch (error) {
        console.error('Admin get withdrawals error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin - Update Withdrawal Status
app.put('/api/admin/withdrawal/:id', authenticateAdmin, async (req, res) => {
    try {
        const { status, adminNotes } = req.body;
        
        const withdrawal = await Withdrawal.findById(req.params.id).populate('userId');
        if (!withdrawal) {
            return res.status(404).json({ error: 'Withdrawal tidak ditemukan' });
        }
        
        // Jika ditolak, kembalikan saldo ke user
        if (status === 'rejected' && withdrawal.status === 'pending') {
            const user = withdrawal.userId;
            user.balance += withdrawal.amount;
            await user.save();
        }
        
        withdrawal.status = status;
        withdrawal.adminNotes = adminNotes;
        withdrawal.processedAt = new Date();
        await withdrawal.save();
        
        await logActivity(req.user.id, 'ADMIN_UPDATE_WITHDRAWAL', `${status} withdrawal ${withdrawal._id}`, req);
        
        res.json({ withdrawal, message: `Withdrawal ${status}` });
    } catch (error) {
        console.error('Admin update withdrawal error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===========================================
// SOCKET.IO CONNECTION HANDLER
// ===========================================

io.on('connection', (socket) => {
    console.log('👤 User connected:', socket.id);
    
    // Join user room (untuk notifikasi personal)
    socket.on('join', (userId) => {
        socket.join(userId);
        console.log(`👤 User ${userId} joined room`);
    });
    
    // Subscribe to price updates
    socket.on('subscribe_prices', () => {
        socket.emit('priceUpdate', cryptoPrices);
    });
    
    // Handle disconnect
    socket.on('disconnect', () => {
        console.log('👤 User disconnected:', socket.id);
    });
});

// ===========================================
// INISIALISASI ADMIN USER
// ===========================================

async function initializeAdmin() {
    try {
        const adminEmail = 'admin@tradestation.com';
        const existingAdmin = await User.findOne({ email: adminEmail });
        
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            
            const admin = new User({
                name: 'Administrator',
                email: adminEmail,
                password: hashedPassword,
                balance: 0,
                accountType: 'premium',
                isActive: true,
                referralCode: 'ADMIN001'
            });
            
            await admin.save();
            console.log('✅ Admin user created successfully');
        } else {
            console.log('✅ Admin user already exists');
        }
    } catch (error) {
        console.error('❌ Error creating admin user:', error);
    }
}

// ===========================================
// ERROR HANDLERS & 404
// ===========================================

// CORS preflight handler untuk semua routes
app.use((req, res, next) => {
    if (req.method === 'OPTIONS') {
        res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
        res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,PATCH');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, Origin, X-Requested-With');
        res.header('Access-Control-Allow-Credentials', 'true');
        return res.sendStatus(200);
    }
    next();
});

// Debug endpoint untuk testing CORS
app.get('/api/test-cors', (req, res) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.json({
        message: 'CORS test successful!',
        origin: req.headers.origin,
        userAgent: req.headers['user-agent'],
        timestamp: new Date().toISOString(),
        ip: req.ip
    });
});

// Handle 404
app.use('*', (req, res) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    console.log(`404 - Route not found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ 
        error: 'API endpoint tidak ditemukan',
        path: req.originalUrl,
        method: req.method,
        availableEndpoints: [
            'GET /api/health',
            'POST /api/login', 
            'POST /api/register',
            'GET /api/prices',
            'POST /api/trade'
        ]
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('Global error:', error);
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
});

// ===========================================
// START SERVER
// ===========================================

server.listen(PORT, async () => {
    console.log('🚀 ========================================');
    console.log('🚀 TradeStation Server Started Successfully!');
    console.log('🚀 ========================================');
    console.log(`📡 Server running on port: ${PORT}`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Database: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting...'}`);
    console.log(`💰 Crypto prices: Auto-updating every 2 seconds`);
    console.log(`⚡ Trading engine: Processing active trades every 1 second`);
    console.log(`🛡️  CORS enabled for multiple origins including ts-traderstation.com`);
    console.log(`📊 Health check: GET /api/health`);
    console.log(`🔍 CORS test: GET /api/test-cors`);
    console.log('🚀 ========================================');
    
    // Initialize admin user
    await initializeAdmin();
    
    // Test database connection
    try {
        await mongoose.connection.db.admin().ping();
        console.log('✅ Database ping successful');
    } catch (error) {
        console.error('❌ Database ping failed:', error.message);
    }
    
    console.log('✅ All systems ready and operational!');
    console.log('🚀 ========================================');
});

// Handle server shutdown gracefully
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received. Shutting down gracefully...');
    server.close(async () => {
        console.log('💤 HTTP server closed');
        await mongoose.connection.close();
        console.log('🔌 Database connection closed');
        process.exit(0);
    });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (error) => {
    console.error('❌ Unhandled Rejection:', error);
    process.exit(1);
});

module.exports = app;
