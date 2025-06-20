// server.js - Main Backend File
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

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
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://username:password@cluster.mongodb.net/tradestation', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  balance: { type: Number, default: 10000 }, // Demo balance $10,000
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Trading Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['buy', 'sell'], required: true },
  cryptoSymbol: { type: String, required: true },
  amount: { type: Number, required: true },
  price: { type: Number, required: true },
  total: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'completed' },
  createdAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// Portfolio Schema
const portfolioSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  cryptoSymbol: { type: String, required: true },
  amount: { type: Number, required: true },
  averagePrice: { type: Number, required: true },
  updatedAt: { type: Date, default: Date.now }
});

const Portfolio = mongoose.model('Portfolio', portfolioSchema);

// Crypto Prices (Mock Data)
let cryptoPrices = {
  'BTC': 105159.00000,
  'ETH': 2538.06000,
  'OPPO': 1.38785,
  'BCH': 492.35000,
  'IOTA': 0.16480,
  'ETC': 16.72610,
  'SHIB': 0.00001,
  'DOGE': 0.16948,
  'XRP': 2.15770,
  'LTC': 85.11000,
  'TRX': 0.27281,
  'DEEP': 0.06431,
  'NAS': 0.35680,
  'EOS': 0.72130,
  'NEO': 37.50000,
  'SNT': 0.04263
};

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Admin Middleware
const requireAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
};

// AUTH ROUTES
// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      name
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        balance: user.balance
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        balance: user.balance,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// TRADING ROUTES
// Get crypto prices
app.get('/api/crypto/prices', (req, res) => {
  res.json(cryptoPrices);
});

// Get user portfolio
app.get('/api/trading/portfolio', authenticateToken, async (req, res) => {
  try {
    const portfolio = await Portfolio.find({ userId: req.user.userId });
    const user = await User.findById(req.user.userId);
    
    res.json({
      balance: user.balance,
      portfolio: portfolio
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Execute trade
app.post('/api/trading/trade', authenticateToken, async (req, res) => {
  try {
    const { type, cryptoSymbol, amount, price } = req.body;
    const total = amount * price;

    const user = await User.findById(req.user.userId);

    if (type === 'buy') {
      // Check if user has enough balance
      if (user.balance < total) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }

      // Deduct balance
      user.balance -= total;
      await user.save();

      // Update portfolio
      let portfolioItem = await Portfolio.findOne({ 
        userId: req.user.userId, 
        cryptoSymbol 
      });

      if (portfolioItem) {
        // Update existing portfolio
        const newTotalAmount = portfolioItem.amount + amount;
        const newTotalValue = (portfolioItem.amount * portfolioItem.averagePrice) + total;
        portfolioItem.amount = newTotalAmount;
        portfolioItem.averagePrice = newTotalValue / newTotalAmount;
        await portfolioItem.save();
      } else {
        // Create new portfolio item
        portfolioItem = new Portfolio({
          userId: req.user.userId,
          cryptoSymbol,
          amount,
          averagePrice: price
        });
        await portfolioItem.save();
      }
    } else if (type === 'sell') {
      // Check if user has enough crypto
      const portfolioItem = await Portfolio.findOne({ 
        userId: req.user.userId, 
        cryptoSymbol 
      });

      if (!portfolioItem || portfolioItem.amount < amount) {
        return res.status(400).json({ error: 'Insufficient crypto amount' });
      }

      // Add balance
      user.balance += total;
      await user.save();

      // Update portfolio
      portfolioItem.amount -= amount;
      if (portfolioItem.amount <= 0) {
        await Portfolio.findByIdAndDelete(portfolioItem._id);
      } else {
        await portfolioItem.save();
      }
    }

    // Create transaction record
    const transaction = new Transaction({
      userId: req.user.userId,
      type,
      cryptoSymbol,
      amount,
      price,
      total,
      status: 'completed'
    });

    await transaction.save();

    res.json({
      message: 'Trade executed successfully',
      transaction,
      newBalance: user.balance
    });

  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Get transaction history
app.get('/api/trading/history', authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json(transactions);
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// ADMIN ROUTES
// Get all users
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({}, '-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Get platform statistics
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const totalTransactions = await Transaction.countDocuments();
    const totalVolume = await Transaction.aggregate([
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);

    res.json({
      totalUsers,
      activeUsers,
      totalTransactions,
      totalVolume: totalVolume[0]?.total || 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Update user status
app.put('/api/admin/users/:userId/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { isActive } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { isActive },
      { new: true }
    );
    
    res.json({ message: 'User status updated', user });
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// WEBSOCKET FOR REAL-TIME PRICES
io.on('connection', (socket) => {
  console.log('Client connected');

  // Send current prices on connection
  socket.emit('priceUpdate', cryptoPrices);

  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Simulate price updates every 3 seconds
setInterval(() => {
  Object.keys(cryptoPrices).forEach(symbol => {
    const change = (Math.random() - 0.5) * cryptoPrices[symbol] * 0.001;
    cryptoPrices[symbol] = Math.max(cryptoPrices[symbol] + change, 0.00001);
  });
  
  io.emit('priceUpdate', cryptoPrices);
}, 3000);

// Basic route
app.get('/', (req, res) => {
  res.json({ 
    message: 'TradeStation API is running!',
    endpoints: {
      auth: '/api/auth/register, /api/auth/login',
      trading: '/api/trading/portfolio, /api/trading/trade, /api/trading/history',
      crypto: '/api/crypto/prices',
      admin: '/api/admin/users, /api/admin/stats'
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 TradeStation Backend running on port ${PORT}`);
  console.log(`📊 MongoDB connected!`);
  console.log(`⚡ WebSocket server ready!`);
});