// server.js - Backend untuk Trading Platform (Fixed Version)
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);

// Environment Variables (Fixed)
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://tradestation:Yusrizal1993@clustertrading.7jozj2u.mongodb.net/?retryWrites=true&w=majority&appName=Clustertrading';
const JWT_SECRET = process.env.JWT_SECRET || 'tradestation-production-jwt-secret-2024-change-this-to-random-string';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'admin-panel-super-secret-key-change-this';
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const MIN_TRADE_AMOUNT = parseInt(process.env.MIN_TRADE_AMOUNT) || 500000;
const MAX_TRADE_AMOUNT = parseInt(process.env.MAX_TRADE_AMOUNT) || 100000000;
const DEFAULT_WIN_RATE = parseInt(process.env.DEFAULT_WIN_RATE) || 20;
const TRADING_COMMISSION = parseInt(process.env.TRADING_COMMISSION) || 0;
const PRICE_UPDATE_INTERVAL = parseInt(process.env.PRICE_UPDATE_INTERVAL) || 2000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@tradestation.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Fixed CORS Origins (tidak dari environment variable)
const CORS_ORIGINS = [
  "https://ts-traderstation.com",
  "https://ts-traderstation.netlify.app",
  "https://www.ts-traderstation.com",
  "http://localhost:3000",
  "http://localhost:5000",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:5000"
];

const FRONTEND_URL = process.env.FRONTEND_URL || 'https://ts-traderstation.com';
const ADMIN_URL = process.env.ADMIN_URL || 'https://ts-traderstation.com/admin';

console.log('🔧 Environment Configuration:');
console.log(`- Node Environment: ${NODE_ENV}`);
console.log(`- Port: ${PORT}`);
console.log(`- Frontend URL: ${FRONTEND_URL}`);
console.log(`- Admin URL: ${ADMIN_URL}`);
console.log(`- CORS Origins: ${CORS_ORIGINS.join(', ')}`);
console.log(`- Min Trade Amount: Rp ${MIN_TRADE_AMOUNT.toLocaleString('id-ID')}`);
console.log(`- Max Trade Amount: Rp ${MAX_TRADE_AMOUNT.toLocaleString('id-ID')}`);
console.log(`- Default Win Rate: ${DEFAULT_WIN_RATE}%`);

// Socket.IO setup with fixed CORS
const io = socketIo(server, {
  cors: {
    origin: CORS_ORIGINS,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowEIO3: true
  },
  transports: ['websocket', 'polling']
});

// CORS Middleware (Fixed)
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    if (CORS_ORIGINS.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log(`❌ CORS blocked origin: ${origin}`);
      callback(null, true); // Allow all for now, but log blocked ones
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  optionsSuccessStatus: 200
}));

// Pre-flight OPTIONS requests
app.options('*', cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url} - Origin: ${req.get('Origin')} - ${req.ip}`);
  next();
});

// MongoDB Connection with fixed URI
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 10000,
  bufferCommands: false,
  maxPoolSize: 10,
  minPoolSize: 5,
  maxIdleTimeMS: 30000,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => {
  console.log('✅ Connected to MongoDB');
  console.log(`📊 Database: ${mongoose.connection.db.databaseName}`);
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Mongoose connection events
mongoose.connection.on('disconnected', () => {
  console.log('⚠️  MongoDB disconnected');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB error:', err);
});

// Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  phone: String,
  accountType: { type: String, enum: ['standard', 'premium'], default: 'standard' },
  balance: { type: Number, default: 0 },
  totalProfit: { type: Number, default: 0 },
  totalLoss: { type: Number, default: 0 },
  totalTrades: { type: Number, default: 0 },
  winTrades: { type: Number, default: 0 },
  loseTrades: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  referralCode: String,
  referredBy: String,
  bankAccount: {
    bankName: String,
    accountNumber: String,
    accountHolder: String
  },
  lastLoginAt: Date,
  ipAddress: String,
  deviceInfo: String,
  createdAt: { type: Date, default: Date.now }
});

const tradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  symbol: { type: String, required: true },
  direction: { type: String, enum: ['buy', 'sell'], required: true },
  amount: { type: Number, required: true },
  entryPrice: { type: Number, required: true },
  exitPrice: { type: Number, default: 0 },
  profitPercentage: { type: Number, required: true },
  duration: { type: Number, required: true }, // in seconds
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  result: { type: String, enum: ['win', 'lose', 'pending'], default: 'pending' },
  payout: { type: Number, default: 0 },
  adminControlled: { type: Boolean, default: false },
  forceResult: { type: String, enum: ['win', 'lose'] },
  commission: { type: Number, default: 0 },
  priceAtEnd: Number,
  priceChange: Number,
  priceChangePercent: Number,
  tradeTimeLeft: Number,
  ipAddress: String,
  deviceInfo: String,
  createdAt: { type: Date, default: Date.now },
  completedAt: Date
});

const depositSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  method: { type: String, default: 'bank_transfer' },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  receipt: String,
  receiptUrl: String,
  bankFrom: String,
  bankTo: String,
  transferTime: Date,
  adminNotes: String,
  processedBy: String,
  ipAddress: String,
  createdAt: { type: Date, default: Date.now },
  processedAt: Date
});

const withdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  finalAmount: { type: Number, required: true },
  bankAccount: {
    bankName: { type: String, required: true },
    accountNumber: { type: String, required: true },
    accountHolder: { type: String, required: true }
  },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'processed'], default: 'pending' },
  adminNotes: String,
  processedBy: String,
  transferReceipt: String,
  ipAddress: String,
  createdAt: { type: Date, default: Date.now },
  processedAt: Date
});

const priceSchema = new mongoose.Schema({
  symbol: { type: String, required: true },
  price: { type: Number, required: true },
  change: { type: Number, required: true },
  volume: { type: Number, default: 0 },
  high24h: Number,
  low24h: Number,
  timestamp: { type: Date, default: Date.now }
});

const activityLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true },
  details: String,
  metadata: mongoose.Schema.Types.Mixed,
  ipAddress: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Price = mongoose.model('Price', priceSchema);
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// Utility Functions
function logActivity(userId, action, details, metadata = {}, req = null) {
  const activityData = {
    userId,
    action,
    details,
    metadata,
    ipAddress: req?.ip || req?.connection?.remoteAddress,
    userAgent: req?.get('User-Agent')
  };
  
  ActivityLog.create(activityData).catch(err => {
    console.error('Error logging activity:', err);
  });
}

function formatCurrency(amount) {
  return new Intl.NumberFormat('id-ID', {
    style: 'currency',
    currency: 'IDR'
  }).format(amount);
}

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    try {
      const user = await User.findById(decoded.id);
      if (!user || !user.isActive) {
        return res.status(403).json({ error: 'User account inactive' });
      }
      
      req.user = decoded;
      req.userDoc = user;
      next();
    } catch (error) {
      return res.status(403).json({ error: 'Invalid token' });
    }
  });
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.user.email !== ADMIN_EMAIL) {
    logActivity(req.user.id, 'UNAUTHORIZED_ADMIN_ACCESS', 'Attempted admin access', { 
      endpoint: req.originalUrl 
    }, req);
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Rate limiting
const rateLimitMap = new Map();

const rateLimit = (maxRequests = 100, windowMs = 60000) => {
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    if (!rateLimitMap.has(ip)) {
      rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
      return next();
    }
    
    const ipData = rateLimitMap.get(ip);
    
    if (now > ipData.resetTime) {
      ipData.count = 1;
      ipData.resetTime = now + windowMs;
      return next();
    }
    
    if (ipData.count >= maxRequests) {
      return res.status(429).json({ 
        error: 'Too many requests', 
        retryAfter: Math.ceil((ipData.resetTime - now) / 1000)
      });
    }
    
    ipData.count++;
    next();
  };
};

// Routes

// Health and Status
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '2.0.0',
    environment: NODE_ENV,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memory: process.memoryUsage(),
    server: 'TradeStation Backend',
    cors: 'Configured for ts-traderstation.com',
    features: {
      trading: true,
      deposits: true,
      withdrawals: true,
      registration: true,
      admin: true
    }
  });
});

app.get('/api/status', async (req, res) => {
  try {
    const [
      userCount,
      activeTradesCount,
      pendingDepositsCount,
      pendingWithdrawalsCount,
      latestPrices,
      totalVolume
    ] = await Promise.all([
      User.countDocuments(),
      Trade.countDocuments({ status: 'active' }),
      Deposit.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      Price.find().sort({ timestamp: -1 }).limit(5),
      Trade.aggregate([
        { $match: { status: 'completed', createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
        { $group: { _id: null, totalVolume: { $sum: '$amount' } } }
      ])
    ]);

    res.json({
      status: 'operational',
      stats: {
        totalUsers: userCount,
        activeTrades: activeTradesCount,
        pendingDeposits: pendingDepositsCount,
        pendingWithdrawals: pendingWithdrawalsCount,
        totalVolume24h: totalVolume[0]?.totalVolume || 0,
        pricesLastUpdate: latestPrices[0]?.timestamp || null
      },
      services: {
        database: mongoose.connection.readyState === 1,
        priceFeeds: latestPrices.length > 0,
        webSocket: true,
        trading: true
      },
      settings: {
        minTradeAmount: MIN_TRADE_AMOUNT,
        maxTradeAmount: MAX_TRADE_AMOUNT,
        defaultWinRate: DEFAULT_WIN_RATE,
        tradingCommission: TRADING_COMMISSION
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      error: error.message
    });
  }
});

// Auth Routes
app.post('/api/register', rateLimit(10, 600000), async (req, res) => {
  try {
    const { email, password, name, phone, referralCode } = req.body;
    
    // Validation
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const userReferralCode = Math.random().toString(36).substring(2, 8).toUpperCase();

    const userData = {
      email: email.toLowerCase(),
      password: hashedPassword,
      name,
      phone,
      referralCode: userReferralCode,
      referredBy: referralCode,
      lastLoginAt: new Date(),
      ipAddress: req.ip,
      deviceInfo: req.get('User-Agent')
    };

    const user = new User(userData);
    await user.save();

    // Add referral bonus if applicable
    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) {
        referrer.balance += 50000; // Rp 50,000 referral bonus
        await referrer.save();
        
        logActivity(referrer._id, 'REFERRAL_BONUS', 'Received referral bonus', {
          referredUser: user._id,
          bonus: 50000
        }, req);
      }
    }

    const token = jwt.sign(
      { id: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );
    
    logActivity(user._id, 'USER_REGISTER', 'User registered', {
      referralCode: referralCode || null
    }, req);

    res.status(201).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        balance: user.balance,
        accountType: user.accountType,
        referralCode: user.referralCode
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', rateLimit(20, 600000), async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(400).json({ error: 'Account is suspended' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      logActivity(user._id, 'LOGIN_FAILED', 'Invalid password attempt', {}, req);
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLoginAt = new Date();
    user.ipAddress = req.ip;
    user.deviceInfo = req.get('User-Agent');
    await user.save();

    const token = jwt.sign(
      { id: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );
    
    logActivity(user._id, 'USER_LOGIN', 'User logged in', {}, req);

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        balance: user.balance,
        accountType: user.accountType,
        referralCode: user.referralCode
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// User Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    
    // Get user stats
    const stats = await Trade.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id) } },
      {
        $group: {
          _id: null,
          totalTrades: { $sum: 1 },
          activeTrades: { $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } },
          completedTrades: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
          winTrades: { $sum: { $cond: [{ $eq: ['$result', 'win'] }, 1, 0] } },
          loseTrades: { $sum: { $cond: [{ $eq: ['$result', 'lose'] }, 1, 0] } },
          totalVolume: { $sum: '$amount' },
          totalPayout: { $sum: '$payout' }
        }
      }
    ]);

    const userStats = stats[0] || {
      totalTrades: 0,
      activeTrades: 0,
      completedTrades: 0,
      winTrades: 0,
      loseTrades: 0,
      totalVolume: 0,
      totalPayout: 0
    };

    const winRate = userStats.completedTrades > 0 ? 
      ((userStats.winTrades / userStats.completedTrades) * 100).toFixed(1) : 0;

    res.json({
      ...user.toObject(),
      stats: {
        ...userStats,
        winRate: parseFloat(winRate)
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const allowedUpdates = ['name', 'phone', 'bankAccount'];
    const updates = {};
    
    Object.keys(req.body).forEach(key => {
      if (allowedUpdates.includes(key)) {
        updates[key] = req.body[key];
      }
    });

    const user = await User.findByIdAndUpdate(
      req.user.id, 
      updates, 
      { new: true }
    ).select('-password');
    
    logActivity(req.user.id, 'PROFILE_UPDATE', 'Profile updated', updates, req);
    
    res.json(user);
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Trading Routes
app.post('/api/trade', authenticateToken, rateLimit(30, 60000), async (req, res) => {
  try {
    const { symbol, direction, amount, profitPercentage, duration } = req.body;
    
    // Validation
    if (!symbol || !direction || !amount || !profitPercentage || !duration) {
      return res.status(400).json({ error: 'All trade parameters are required' });
    }
    
    if (amount < MIN_TRADE_AMOUNT || amount > MAX_TRADE_AMOUNT) {
      return res.status(400).json({ 
        error: `Trade amount must be between ${formatCurrency(MIN_TRADE_AMOUNT)} and ${formatCurrency(MAX_TRADE_AMOUNT)}` 
      });
    }
    
    if (!['buy', 'sell'].includes(direction)) {
      return res.status(400).json({ error: 'Direction must be buy or sell' });
    }
    
    if (![30, 60, 120, 300].includes(duration)) {
      return res.status(400).json({ error: 'Invalid trade duration' });
    }

    const user = await User.findById(req.user.id);
    if (user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Get current price
    const currentPrice = await Price.findOne({ symbol }).sort({ timestamp: -1 });
    if (!currentPrice) {
      return res.status(400).json({ error: 'Price not available for this symbol' });
    }

    // Calculate commission
    const commission = (amount * TRADING_COMMISSION) / 100;
    const finalAmount = amount + commission;

    if (user.balance < finalAmount) {
      return res.status(400).json({ error: 'Insufficient balance including commission' });
    }

    // Deduct amount from user balance
    user.balance -= finalAmount;
    user.totalTrades += 1;
    await user.save();

    const trade = new Trade({
      userId: req.user.id,
      symbol,
      direction,
      amount,
      entryPrice: currentPrice.price,
      profitPercentage,
      duration,
      commission,
      ipAddress: req.ip,
      deviceInfo: req.get('User-Agent')
    });

    await trade.save();
    
    logActivity(req.user.id, 'TRADE_CREATED', 'New trade created', {
      tradeId: trade._id,
      symbol,
      direction,
      amount,
      duration
    }, req);

    // Schedule trade completion
    setTimeout(() => {
      completeTrade(trade._id);
    }, duration * 1000);

    // Emit to user
    io.to(`user_${req.user.id}`).emit('tradeCreated', {
      trade: await trade.populate('userId', 'name'),
      newBalance: user.balance
    });

    res.status(201).json(trade);
  } catch (error) {
    console.error('Trade creation error:', error);
    res.status(500).json({ error: 'Failed to create trade' });
  }
});

app.get('/api/trades', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const trades = await Trade.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip);
      
    const total = await Trade.countDocuments({ userId: req.user.id });
    
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
    console.error('Get trades error:', error);
    res.status(500).json({ error: 'Failed to get trades' });
  }
});

// Deposit Routes
app.post('/api/deposit', authenticateToken, rateLimit(10, 600000), async (req, res) => {
  try {
    const { amount, method, receipt, bankFrom, transferTime } = req.body;
    
    if (!amount || amount < 50000) {
      return res.status(400).json({ error: 'Minimum deposit amount is Rp 50,000' });
    }
    
    const deposit = new Deposit({
      userId: req.user.id,
      amount,
      method: method || 'bank_transfer',
      receipt,
      bankFrom,
      transferTime: transferTime ? new Date(transferTime) : new Date(),
      ipAddress: req.ip
    });

    await deposit.save();
    
    logActivity(req.user.id, 'DEPOSIT_REQUEST', 'Deposit request created', {
      depositId: deposit._id,
      amount
    }, req);

    res.status(201).json(deposit);
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: 'Failed to create deposit request' });
  }
});

app.get('/api/deposits', authenticateToken, async (req, res) => {
  try {
    const deposits = await Deposit.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(50);
    res.json(deposits);
  } catch (error) {
    console.error('Get deposits error:', error);
    res.status(500).json({ error: 'Failed to get deposits' });
  }
});

// Withdrawal Routes
app.post('/api/withdrawal', authenticateToken, rateLimit(5, 600000), async (req, res) => {
  try {
    const { amount, bankAccount } = req.body;
    
    if (!amount || !bankAccount || !bankAccount.bankName || !bankAccount.accountNumber || !bankAccount.accountHolder) {
      return res.status(400).json({ error: 'Amount and complete bank account details are required' });
    }
    
    if (amount < 100000) {
      return res.status(400).json({ error: 'Minimum withdrawal amount is Rp 100,000' });
    }
    
    const user = await User.findById(req.user.id);
    const fee = Math.max(6500, amount * 0.01); // Minimum Rp 6,500 or 1%
    const finalAmount = amount - fee;
    
    if (user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Deduct from balance immediately
    user.balance -= amount;
    await user.save();

    const withdrawal = new Withdrawal({
      userId: req.user.id,
      amount,
      fee,
      finalAmount,
      bankAccount,
      ipAddress: req.ip
    });

    await withdrawal.save();
    
    logActivity(req.user.id, 'WITHDRAWAL_REQUEST', 'Withdrawal request created', {
      withdrawalId: withdrawal._id,
      amount,
      fee,
      finalAmount
    }, req);

    res.status(201).json(withdrawal);
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Failed to create withdrawal request' });
  }
});

app.get('/api/withdrawals', authenticateToken, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(50);
    res.json(withdrawals);
  } catch (error) {
    console.error('Get withdrawals error:', error);
    res.status(500).json({ error: 'Failed to get withdrawals' });
  }
});

// Price Routes
app.get('/api/prices', async (req, res) => {
  try {
    const latest = await Price.aggregate([
      { $sort: { symbol: 1, timestamp: -1 } },
      { $group: {
        _id: '$symbol',
        price: { $first: '$price' },
        change: { $first: '$change' },
        volume: { $first: '$volume' },
        high24h: { $first: '$high24h' },
        low24h: { $first: '$low24h' },
        timestamp: { $first: '$timestamp' }
      }},
      { $project: {
        symbol: '$_id',
        price: 1,
        change: 1,
        volume: 1,
        high24h: 1,
        low24h: 1,
        timestamp: 1,
        _id: 0
      }}
    ]);
    
    res.json(latest);
  } catch (error) {
    console.error('Get prices error:', error);
    res.status(500).json({ error: 'Failed to get prices' });
  }
});

app.get('/api/prices/:symbol', async (req, res) => {
  try {
    const { symbol } = req.params;
    const limit = parseInt(req.query.limit) || 100;
    
    const prices = await Price.find({ symbol })
      .sort({ timestamp: -1 })
      .limit(limit);
      
    res.json(prices);
  } catch (error) {
    console.error('Get symbol prices error:', error);
    res.status(500).json({ error: 'Failed to get symbol prices' });
  }
});

// Admin Routes
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    const search = req.query.search || '';
    
    const query = search ? {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ]
    } : {};
    
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password')
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(skip),
      User.countDocuments(query)
    ]);
    
    res.json({
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin get users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

app.get('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get user's trades, deposits, withdrawals
    const [trades, deposits, withdrawals] = await Promise.all([
      Trade.find({ userId: req.params.id }).sort({ createdAt: -1 }).limit(20),
      Deposit.find({ userId: req.params.id }).sort({ createdAt: -1 }).limit(20),
      Withdrawal.find({ userId: req.params.id }).sort({ createdAt: -1 }).limit(20)
    ]);
    
    res.json({
      user,
      trades,
      deposits,
      withdrawals
    });
  } catch (error) {
    console.error('Admin get user error:', error);
    res.status(500).json({ error: 'Failed to get user details' });
  }
});

app.put('/api/admin/user/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const updates = req.body;
    const allowedUpdates = ['name', 'email', 'balance', 'accountType', 'isActive', 'phone'];
    
    const filteredUpdates = {};
    Object.keys(updates).forEach(key => {
      if (allowedUpdates.includes(key)) {
        filteredUpdates[key] = updates[key];
      }
    });

    const user = await User.findByIdAndUpdate(
      req.params.id,
      filteredUpdates,
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    logActivity(req.user.id, 'ADMIN_USER_UPDATE', 'User updated by admin', {
      targetUserId: req.params.id,
      updates: filteredUpdates
    }, req);

    res.json(user);
  } catch (error) {
    console.error('Admin update user error:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/api/admin/user/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Soft delete - deactivate user
    user.isActive = false;
    await user.save();
    
    logActivity(req.user.id, 'ADMIN_USER_DELETE', 'User deactivated by admin', {
      targetUserId: req.params.id
    }, req);

    res.json({ message: 'User deactivated successfully' });
  } catch (error) {
    console.error('Admin delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/api/admin/trades', authenticateToken, isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    const status = req.query.status || '';
    
    const query = status ? { status } : {};
    
    const [trades, total] = await Promise.all([
      Trade.find(query)
        .populate('userId', 'name email')
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(skip),
      Trade.countDocuments(query)
    ]);
    
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
    console.error('Admin get trades error:', error);
    res.status(500).json({ error: 'Failed to get trades' });
  }
});

app.put('/api/admin/trade/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { forceResult } = req.body;
    
    if (!['win', 'lose'].includes(forceResult)) {
      return res.status(400).json({ error: 'Invalid force result' });
    }
    
    const trade = await Trade.findByIdAndUpdate(
      req.params.id,
      { 
        forceResult, 
        adminControlled: true 
      },
      { new: true }
    ).populate('userId', 'name email');
    
    if (!trade) {
      return res.status(404).json({ error: 'Trade not found' });
    }
    
    logActivity(req.user.id, 'ADMIN_TRADE_CONTROL', 'Trade result forced by admin', {
      tradeId: req.params.id,
      forceResult,
      targetUserId: trade.userId._id
    }, req);

    res.json(trade);
  } catch (error) {
    console.error('Admin control trade error:', error);
    res.status(500).json({ error: 'Failed to control trade' });
  }
});

app.get('/api/admin/deposits', authenticateToken, isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    const status = req.query.status || '';
    
    const query = status ? { status } : {};
    
    const [deposits, total] = await Promise.all([
      Deposit.find(query)
        .populate('userId', 'name email')
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(skip),
      Deposit.countDocuments(query)
    ]);
    
    res.json({
      deposits,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin get deposits error:', error);
    res.status(500).json({ error: 'Failed to get deposits' });
  }
});

app.put('/api/admin/deposit/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, adminNotes } = req.body;
    
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    const deposit = await Deposit.findById(req.params.id);
    if (!deposit) {
      return res.status(404).json({ error: 'Deposit not found' });
    }
    
    if (deposit.status !== 'pending') {
      return res.status(400).json({ error: 'Deposit already processed' });
    }

    deposit.status = status;
    deposit.adminNotes = adminNotes;
    deposit.processedAt = new Date();
    deposit.processedBy = req.user.email;
    await deposit.save();

    // If approved, add to user balance
    if (status === 'approved') {
      await User.findByIdAndUpdate(deposit.userId, {
        $inc: { balance: deposit.amount }
      });
      
      // Notify user
      io.to(`user_${deposit.userId}`).emit('depositApproved', {
        deposit,
        amount: deposit.amount
      });
    }
    
    logActivity(req.user.id, 'ADMIN_DEPOSIT_UPDATE', `Deposit ${status} by admin`, {
      depositId: req.params.id,
      status,
      amount: deposit.amount,
      targetUserId: deposit.userId
    }, req);

    res.json(deposit);
  } catch (error) {
    console.error('Admin update deposit error:', error);
    res.status(500).json({ error: 'Failed to update deposit' });
  }
});

app.get('/api/admin/withdrawals', authenticateToken, isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    const status = req.query.status || '';
    
    const query = status ? { status } : {};
    
    const [withdrawals, total] = await Promise.all([
      Withdrawal.find(query)
        .populate('userId', 'name email')
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(skip),
      Withdrawal.countDocuments(query)
    ]);
    
    res.json({
      withdrawals,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin get withdrawals error:', error);
    res.status(500).json({ error: 'Failed to get withdrawals' });
  }
});

app.put('/api/admin/withdrawal/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, adminNotes, transferReceipt } = req.body;
    
    if (!['approved', 'rejected', 'processed'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    const withdrawal = await Withdrawal.findById(req.params.id);
    if (!withdrawal) {
      return res.status(404).json({ error: 'Withdrawal not found' });
    }

    withdrawal.status = status;
    withdrawal.adminNotes = adminNotes;
    withdrawal.transferReceipt = transferReceipt;
    withdrawal.processedAt = new Date();
    withdrawal.processedBy = req.user.email;
    await withdrawal.save();

    // If rejected, return money to user balance
    if (status === 'rejected') {
      await User.findByIdAndUpdate(withdrawal.userId, {
        $inc: { balance: withdrawal.amount }
      });
      
      // Notify user
      io.to(`user_${withdrawal.userId}`).emit('withdrawalRejected', {
        withdrawal,
        refundAmount: withdrawal.amount
      });
    } else if (status === 'processed') {
      // Notify user withdrawal completed
      io.to(`user_${withdrawal.userId}`).emit('withdrawalCompleted', {
        withdrawal
      });
    }
    
    logActivity(req.user.id, 'ADMIN_WITHDRAWAL_UPDATE', `Withdrawal ${status} by admin`, {
      withdrawalId: req.params.id,
      status,
      amount: withdrawal.amount,
      targetUserId: withdrawal.userId
    }, req);

    res.json(withdrawal);
  } catch (error) {
    console.error('Admin update withdrawal error:', error);
    res.status(500).json({ error: 'Failed to update withdrawal' });
  }
});

app.get('/api/admin/dashboard', authenticateToken, isAdmin, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const [
      totalUsers,
      activeUsers,
      totalTrades,
      activeTrades,
      todayTrades,
      totalDeposits,
      pendingDeposits,
      totalWithdrawals,
      pendingWithdrawals,
      totalVolume,
      todayVolume,
      recentActivities
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ lastLoginAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }),
      Trade.countDocuments(),
      Trade.countDocuments({ status: 'active' }),
      Trade.countDocuments({ createdAt: { $gte: today } }),
      Deposit.countDocuments({ status: 'approved' }),
      Deposit.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments(),
      Withdrawal.countDocuments({ status: 'pending' }),
      Trade.aggregate([
        { $match: { status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Trade.aggregate([
        { $match: { status: 'completed', createdAt: { $gte: today } } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      ActivityLog.find()
        .populate('userId', 'name email')
        .sort({ createdAt: -1 })
        .limit(20)
    ]);

    res.json({
      stats: {
        users: {
          total: totalUsers,
          active: activeUsers
        },
        trades: {
          total: totalTrades,
          active: activeTrades,
          today: todayTrades
        },
        deposits: {
          total: totalDeposits,
          pending: pendingDeposits
        },
        withdrawals: {
          total: totalWithdrawals,
          pending: pendingWithdrawals
        },
        volume: {
          total: totalVolume[0]?.total || 0,
          today: todayVolume[0]?.total || 0
        }
      },
      recentActivities
    });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({ error: 'Failed to get dashboard data' });
  }
});

// Trade completion function
async function completeTrade(tradeId) {
  try {
    const trade = await Trade.findById(tradeId);
    if (!trade || trade.status !== 'active') {
      return;
    }

    const user = await User.findById(trade.userId);
    const currentPrice = await Price.findOne({ symbol: trade.symbol }).sort({ timestamp: -1 });

    if (!currentPrice) {
      console.error(`No price found for ${trade.symbol}`);
      return;
    }

    let result = 'lose';
    let payout = 0;

    // Check if admin forced result
    if (trade.adminControlled && trade.forceResult) {
      result = trade.forceResult;
      console.log(`Trade ${tradeId} result forced by admin: ${result}`);
    } else {
      // Use configured win rate
      const randomWin = Math.random() * 100;
      if (randomWin < DEFAULT_WIN_RATE) {
        result = 'win';
      }
      console.log(`Trade ${tradeId} natural result: ${result} (${randomWin.toFixed(2)}% vs ${DEFAULT_WIN_RATE}%)`);
    }

    // Calculate payout
    if (result === 'win') {
      payout = trade.amount + (trade.amount * trade.profitPercentage / 100);
      user.balance += payout;
      user.totalProfit += payout - trade.amount;
      user.winTrades += 1;
    } else {
      user.totalLoss += trade.amount;
      user.loseTrades += 1;
    }

    await user.save();

    // Calculate price change for display
    const priceChange = currentPrice.price - trade.entryPrice;
    const priceChangePercent = (priceChange / trade.entryPrice) * 100;

    trade.status = 'completed';
    trade.result = result;
    trade.payout = payout;
    trade.exitPrice = currentPrice.price;
    trade.priceAtEnd = currentPrice.price;
    trade.priceChange = priceChange;
    trade.priceChangePercent = priceChangePercent;
    trade.completedAt = new Date();
    await trade.save();

    // Log activity
    logActivity(trade.userId, 'TRADE_COMPLETED', `Trade completed with ${result}`, {
      tradeId: trade._id,
      result,
      payout,
      priceChange: priceChangePercent.toFixed(2) + '%'
    });

    // Emit to user via socket
    io.to(`user_${trade.userId}`).emit('tradeCompleted', {
      trade,
      newBalance: user.balance,
      result,
      payout,
      priceChange: priceChangePercent
    });

    console.log(`✅ Trade ${tradeId} completed: ${result}, payout: ${formatCurrency(payout)}`);

  } catch (error) {
    console.error('Error completing trade:', error);
  }
}

// Price simulation
const cryptoSymbols = ['BTC', 'ETH', 'OPPO', 'BCH', 'IOTA', 'ETC', 'SHIB', 'DOGE', 'XRP', 'LTC', 'TRX', 'DEEP', 'NAS', 'EOS', 'NEO', 'SNT'];
const basePrices = {
  BTC: 105159, ETH: 2538, OPPO: 1.388, BCH: 492, IOTA: 0.165,
  ETC: 16.73, SHIB: 0.00001, DOGE: 0.169, XRP: 2.158, LTC: 85.11,
  TRX: 0.273, DEEP: 0.064, NAS: 0.357, EOS: 0.721, NEO: 37.5, SNT: 0.043
};

// Initialize prices and start simulation
async function initializePrices() {
  console.log('🔄 Initializing cryptocurrency prices...');
  
  for (const symbol of cryptoSymbols) {
    try {
      const existingPrice = await Price.findOne({ symbol }).sort({ timestamp: -1 });
      if (!existingPrice) {
        await Price.create({
          symbol,
          price: basePrices[symbol],
          change: 0,
          volume: Math.floor(Math.random() * 1000000),
          high24h: basePrices[symbol] * 1.05,
          low24h: basePrices[symbol] * 0.95
        });
        console.log(`✅ Initialized ${symbol}: $${basePrices[symbol]}`);
      }
    } catch (error) {
      console.error(`❌ Error initializing price for ${symbol}:`, error);
    }
  }
  
  console.log('✅ Price initialization completed');
}

function updatePrices() {
  setInterval(async () => {
    for (const symbol of cryptoSymbols) {
      try {
        const lastPrice = await Price.findOne({ symbol }).sort({ timestamp: -1 });
        if (!lastPrice) continue;
        
        // More realistic price movements
        const volatility = symbol === 'BTC' ? 0.02 : symbol === 'ETH' ? 0.03 : 0.05;
        const changePercent = (Math.random() - 0.5) * volatility;
        const newPrice = lastPrice.price * (1 + changePercent / 100);
        
        // Ensure price doesn't go too extreme
        const basePrice = basePrices[symbol];
        const minPrice = basePrice * 0.5;
        const maxPrice = basePrice * 2.0;
        const finalPrice = Math.max(minPrice, Math.min(maxPrice, newPrice));
        
        await Price.create({
          symbol,
          price: finalPrice,
          change: changePercent,
          volume: Math.floor(Math.random() * 1000000),
          high24h: lastPrice.high24h || finalPrice,
          low24h: lastPrice.low24h || finalPrice
        });

        // Emit price update to all connected clients
        io.emit('priceUpdate', { 
          symbol, 
          price: finalPrice, 
          change: changePercent,
          timestamp: new Date()
        });
        
      } catch (error) {
        console.error(`❌ Error updating price for ${symbol}:`, error);
      }
    }
  }, PRICE_UPDATE_INTERVAL);
}

// Create admin user
async function createAdminUser() {
  try {
    const adminExists = await User.findOne({ email: ADMIN_EMAIL });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await User.create({
        name: 'Administrator',
        email: ADMIN_EMAIL,
        password: hashedPassword,
        accountType: 'premium',
        balance: 0,
        isActive: true,
        referralCode: 'ADMIN2024'
      });
      console.log(`✅ Admin user created: ${ADMIN_EMAIL}`);
    } else {
      console.log('✅ Admin user already exists');
    }
  } catch (error) {
    console.error('❌ Error creating admin user:', error);
  }
}

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log(`🔌 User connected: ${socket.id}`);

  socket.on('join', (userId) => {
    socket.join(`user_${userId}`);
    console.log(`👤 User ${userId} joined room`);
  });

  socket.on('subscribe_prices', () => {
    socket.join('prices');
    console.log(`📈 Socket ${socket.id} subscribed to prices`);
  });

  socket.on('unsubscribe_prices', () => {
    socket.leave('prices');
    console.log(`📉 Socket ${socket.id} unsubscribed from prices`);
  });

  socket.on('ping', () => {
    socket.emit('pong');
  });

  socket.on('disconnect', () => {
    console.log(`🔌 User disconnected: ${socket.id}`);
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? err.message : 'Something went wrong',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method,
    availableEndpoints: [
      'GET /api/health - Health check',
      'GET /api/status - System status',
      'POST /api/register - User registration',
      'POST /api/login - User login',
      'GET /api/prices - Cryptocurrency prices'
    ],
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('🛑 Server closed');
    mongoose.connection.close(false, () => {
      console.log('🛑 MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('🛑 Server closed');
    mongoose.connection.close(false, () => {
      console.log('🛑 MongoDB connection closed');
      process.exit(0);
    });
  });
});

// Cleanup old prices (keep only last 1000 per symbol)
async function cleanupOldPrices() {
  try {
    for (const symbol of cryptoSymbols) {
      const count = await Price.countDocuments({ symbol });
      if (count > 1000) {
        const oldPrices = await Price.find({ symbol })
          .sort({ timestamp: 1 })
          .limit(count - 1000);
        
        const ids = oldPrices.map(p => p._id);
        await Price.deleteMany({ _id: { $in: ids } });
        console.log(`🧹 Cleaned up ${ids.length} old prices for ${symbol}`);
      }
    }
  } catch (error) {
    console.error('❌ Error cleaning up old prices:', error);
  }
}

// Run cleanup every hour
setInterval(cleanupOldPrices, 60 * 60 * 1000);

// Initialize and start server
async function startServer() {
  try {
    console.log('🚀 Starting TradeStation Server...');
    
    // Initialize system
    await createAdminUser();
    await initializePrices();
    
    // Start price updates
    updatePrices();
    console.log(`⏱️  Price updates started (${PRICE_UPDATE_INTERVAL}ms interval)`);
    
    // Start server
    server.listen(PORT, () => {
      console.log('\n' + '='.repeat(60));
      console.log('🎯 TradeStation Server Successfully Started!');
      console.log('='.repeat(60));
      console.log(`🌍 Server URL: http://localhost:${PORT}`);
      console.log(`📊 Health Check: http://localhost:${PORT}/api/health`);
      console.log(`📈 API Status: http://localhost:${PORT}/api/status`);
      console.log(`🔗 Frontend: ${FRONTEND_URL}`);
      console.log(`👤 Admin Panel: ${ADMIN_URL}`);
      console.log(`🎯 Environment: ${NODE_ENV}`);
      console.log(`🕐 Started at: ${new Date().toISOString()}`);
      console.log('='.repeat(60) + '\n');
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = app;
