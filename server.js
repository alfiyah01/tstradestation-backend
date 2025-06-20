// server.js - Backend untuk Trading Platform
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://admin:password123@clustertrading.7jozj2u.mongodb.net/tradingplatform?retryWrites=true&w=majority&appName=Clustertrading';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  phone: String,
  accountType: { type: String, enum: ['standard', 'premium'], default: 'standard' },
  balance: { type: Number, default: 0 },
  totalProfit: { type: Number, default: 0 },
  totalLoss: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  referralCode: String,
  bankAccount: {
    bankName: String,
    accountNumber: String,
    accountHolder: String
  },
  createdAt: { type: Date, default: Date.now }
});

const tradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  symbol: { type: String, required: true },
  direction: { type: String, enum: ['buy', 'sell'], required: true },
  amount: { type: Number, required: true },
  entryPrice: { type: Number, required: true },
  profitPercentage: { type: Number, required: true },
  duration: { type: Number, required: true }, // in seconds
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  result: { type: String, enum: ['win', 'lose', 'pending'], default: 'pending' },
  payout: { type: Number, default: 0 },
  adminControlled: { type: Boolean, default: false },
  forceResult: { type: String, enum: ['win', 'lose'] },
  createdAt: { type: Date, default: Date.now },
  completedAt: Date
});

const depositSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  method: String,
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  receipt: String,
  adminNotes: String,
  createdAt: { type: Date, default: Date.now },
  processedAt: Date
});

const withdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  bankAccount: {
    bankName: String,
    accountNumber: String,
    accountHolder: String
  },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  adminNotes: String,
  createdAt: { type: Date, default: Date.now },
  processedAt: Date
});

const priceSchema = new mongoose.Schema({
  symbol: { type: String, required: true },
  price: { type: Number, required: true },
  change: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Price = mongoose.model('Price', priceSchema);

// JWT Secret
const JWT_SECRET = 'trading-platform-secret-key-2024';

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.user.email !== 'admin@tradestation.com') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Routes

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const referralCode = Math.random().toString(36).substring(2, 8).toUpperCase();

    const user = new User({
      email,
      password: hashedPassword,
      name,
      phone,
      referralCode
    });

    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET);
    
    res.status(201).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        balance: user.balance,
        accountType: user.accountType
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET);
    
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        balance: user.balance,
        accountType: user.accountType
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// User Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true }).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Trading Routes
app.post('/api/trade', authenticateToken, async (req, res) => {
  try {
    const { symbol, direction, amount, profitPercentage, duration } = req.body;
    
    const user = await User.findById(req.user.id);
    if (user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Get current price
    const currentPrice = await Price.findOne({ symbol }).sort({ timestamp: -1 });
    if (!currentPrice) {
      return res.status(400).json({ error: 'Price not available' });
    }

    // Deduct amount from user balance
    user.balance -= amount;
    await user.save();

    const trade = new Trade({
      userId: req.user.id,
      symbol,
      direction,
      amount,
      entryPrice: currentPrice.price,
      profitPercentage,
      duration
    });

    await trade.save();

    // Schedule trade completion
    setTimeout(async () => {
      await completeTrade(trade._id);
    }, duration * 1000);

    res.status(201).json(trade);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/trades', authenticateToken, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(trades);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Deposit Routes
app.post('/api/deposit', authenticateToken, async (req, res) => {
  try {
    const { amount, method, receipt } = req.body;
    
    const deposit = new Deposit({
      userId: req.user.id,
      amount,
      method,
      receipt
    });

    await deposit.save();
    res.status(201).json(deposit);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Withdrawal Routes
app.post('/api/withdrawal', authenticateToken, async (req, res) => {
  try {
    const { amount, bankAccount } = req.body;
    
    const user = await User.findById(req.user.id);
    if (user.balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const withdrawal = new Withdrawal({
      userId: req.user.id,
      amount,
      bankAccount
    });

    await withdrawal.save();
    res.status(201).json(withdrawal);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Price Routes
app.get('/api/prices', async (req, res) => {
  try {
    const prices = await Price.find().sort({ timestamp: -1 }).limit(50);
    res.json(prices);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin Routes
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/user/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/trades', authenticateToken, isAdmin, async (req, res) => {
  try {
    const trades = await Trade.find().populate('userId', 'name email').sort({ createdAt: -1 });
    res.json(trades);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/trade/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { forceResult } = req.body;
    const trade = await Trade.findByIdAndUpdate(
      req.params.id,
      { forceResult, adminControlled: true },
      { new: true }
    );
    res.json(trade);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/deposits', authenticateToken, isAdmin, async (req, res) => {
  try {
    const deposits = await Deposit.find().populate('userId', 'name email').sort({ createdAt: -1 });
    res.json(deposits);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/deposit/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, adminNotes } = req.body;
    const deposit = await Deposit.findByIdAndUpdate(
      req.params.id,
      { status, adminNotes, processedAt: new Date() },
      { new: true }
    );

    // If approved, add to user balance
    if (status === 'approved') {
      await User.findByIdAndUpdate(deposit.userId, {
        $inc: { balance: deposit.amount }
      });
    }

    res.json(deposit);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/withdrawals', authenticateToken, isAdmin, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find().populate('userId', 'name email').sort({ createdAt: -1 });
    res.json(withdrawals);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/withdrawal/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, adminNotes } = req.body;
    const withdrawal = await Withdrawal.findByIdAndUpdate(
      req.params.id,
      { status, adminNotes, processedAt: new Date() },
      { new: true }
    );

    // If rejected, return money to user balance
    if (status === 'rejected') {
      await User.findByIdAndUpdate(withdrawal.userId, {
        $inc: { balance: withdrawal.amount }
      });
    } else if (status === 'approved') {
      // Deduct from user balance if not already done
      await User.findByIdAndUpdate(withdrawal.userId, {
        $inc: { balance: -withdrawal.amount }
      });
    }

    res.json(withdrawal);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Trade completion function
async function completeTrade(tradeId) {
  try {
    const trade = await Trade.findById(tradeId);
    if (!trade || trade.status !== 'active') return;

    const user = await User.findById(trade.userId);
    const currentPrice = await Price.findOne({ symbol: trade.symbol }).sort({ timestamp: -1 });

    let result = 'lose';
    let payout = 0;

    // Check if admin forced result
    if (trade.adminControlled && trade.forceResult) {
      result = trade.forceResult;
    } else {
      // Calculate result based on price movement
      const priceChange = ((currentPrice.price - trade.entryPrice) / trade.entryPrice) * 100;
      
      if (trade.direction === 'buy' && priceChange > 0) {
        result = 'win';
      } else if (trade.direction === 'sell' && priceChange < 0) {
        result = 'win';
      }
    }

    if (result === 'win') {
      payout = trade.amount + (trade.amount * trade.profitPercentage / 100);
      user.balance += payout;
      user.totalProfit += payout - trade.amount;
    } else {
      user.totalLoss += trade.amount;
    }

    await user.save();

    trade.status = 'completed';
    trade.result = result;
    trade.payout = payout;
    trade.completedAt = new Date();
    await trade.save();

    // Emit to user via socket
    io.to(`user_${trade.userId}`).emit('tradeCompleted', {
      trade,
      newBalance: user.balance
    });

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
  for (const symbol of cryptoSymbols) {
    const existingPrice = await Price.findOne({ symbol }).sort({ timestamp: -1 });
    if (!existingPrice) {
      await Price.create({
        symbol,
        price: basePrices[symbol],
        change: 0
      });
    }
  }
}

function updatePrices() {
  setInterval(async () => {
    for (const symbol of cryptoSymbols) {
      try {
        const lastPrice = await Price.findOne({ symbol }).sort({ timestamp: -1 });
        const changePercent = (Math.random() - 0.5) * 0.1; // ±0.05%
        const newPrice = lastPrice.price * (1 + changePercent / 100);
        
        await Price.create({
          symbol,
          price: newPrice,
          change: changePercent
        });

        // Emit price update to all connected clients
        io.emit('priceUpdate', { symbol, price: newPrice, change: changePercent });
      } catch (error) {
        console.error(`Error updating price for ${symbol}:`, error);
      }
    }
  }, 2000);
}

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join', (userId) => {
    socket.join(`user_${userId}`);
    console.log(`User ${userId} joined room`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memory: process.memoryUsage()
  });
});

// API Status endpoint
app.get('/api/status', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const activeTradesCount = await Trade.countDocuments({ status: 'active' });
    const pendingDepositsCount = await Deposit.countDocuments({ status: 'pending' });
    const latestPrices = await Price.find().sort({ timestamp: -1 }).limit(5);

    res.json({
      status: 'operational',
      stats: {
        totalUsers: userCount,
        activeTrades: activeTradesCount,
        pendingDeposits: pendingDepositsCount,
        pricesLastUpdate: latestPrices[0]?.timestamp || null
      },
      services: {
        database: mongoose.connection.readyState === 1,
        priceFeeds: latestPrices.length > 0,
        webSocket: true
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      error: error.message
    });
  }
});

// API Documentation endpoint
app.get('/api/docs', (req, res) => {
  res.json({
    name: 'TradeStation API',
    version: '1.0.0',
    description: 'Real-time cryptocurrency trading platform API',
    endpoints: {
      auth: {
        'POST /api/register': 'Register new user',
        'POST /api/login': 'User login',
        'GET /api/profile': 'Get user profile'
      },
      trading: {
        'POST /api/trade': 'Create new trade',
        'GET /api/trades': 'Get user trades',
        'GET /api/prices': 'Get current prices'
      },
      financial: {
        'POST /api/deposit': 'Create deposit request',
        'POST /api/withdrawal': 'Create withdrawal request'
      },
      admin: {
        'GET /api/admin/users': 'Get all users (admin)',
        'PUT /api/admin/user/:id': 'Update user (admin)',
        'GET /api/admin/trades': 'Get all trades (admin)',
        'PUT /api/admin/trade/:id': 'Control trade result (admin)',
        'GET /api/admin/deposits': 'Get all deposits (admin)',
        'PUT /api/admin/deposit/:id': 'Update deposit status (admin)',
        'GET /api/admin/withdrawals': 'Get all withdrawals (admin)',
        'PUT /api/admin/withdrawal/:id': 'Update withdrawal status (admin)'
      }
    },
    websocket: {
      events: {
        'priceUpdate': 'Real-time price updates',
        'tradeCompleted': 'Trade completion notification',
        'balanceUpdate': 'User balance updates'
      }
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    availableEndpoints: [
      'GET /api/health - Health check',
      'GET /api/status - System status',
      'GET /api/docs - API documentation'
    ]
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});

// Initialize and start server
async function startServer() {
  try {
    await initializePrices();
    updatePrices();
    
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      console.log(`🚀 TradeStation Server running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
      console.log(`📈 API Status: http://localhost:${PORT}/api/status`);
      console.log(`📚 API Docs: http://localhost:${PORT}/api/docs`);
      console.log(`🎯 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = app;
