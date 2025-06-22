/**
 * TradeStation Database Seeder
 * This script populates the database with initial data
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Import models (you'll need to create these based on your server.js)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String },
    balance: { type: Number, default: 0 },
    accountType: { type: String, enum: ['standard', 'premium'], default: 'standard' },
    isActive: { type: Boolean, default: true },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    referralCode: { type: String, unique: true },
    bankData: {
        bankName: { type: String },
        accountNumber: { type: String },
        accountHolder: { type: String }
    },
    adminSettings: {
        forceWin: { type: Boolean, default: false },
        forceWinRate: { type: Number, default: 0 },
        profitCollapse: { type: String, enum: ['profit', 'collapse', 'normal'], default: 'normal' },
        profitPercentage: { type: Number, default: 80 }
    },
    stats: {
        totalTrades: { type: Number, default: 0 },
        winTrades: { type: Number, default: 0 },
        loseTrades: { type: Number, default: 0 }
    },
    lastLoginAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

const bankAccountSchema = new mongoose.Schema({
    bankName: { type: String, required: true },
    accountNumber: { type: String, required: true },
    accountHolder: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    note: { type: String },
    createdAt: { type: Date, default: Date.now }
});

const priceSchema = new mongoose.Schema({
    symbol: { type: String, required: true, unique: true },
    price: { type: Number, required: true },
    change: { type: Number, default: 0 },
    lastUpdate: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', userSchema);
const BankAccount = mongoose.model('BankAccount', bankAccountSchema);
const Price = mongoose.model('Price', priceSchema);

// Helper function
function generateReferralCode() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
}

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m'
};

const log = (message, color = 'reset') => {
    console.log(`${colors[color]}${message}${colors.reset}`);
};

const success = (message) => log(`✅ ${message}`, 'green');
const error = (message) => log(`❌ ${message}`, 'red');
const info = (message) => log(`ℹ️  ${message}`, 'blue');
const warning = (message) => log(`⚠️  ${message}`, 'yellow');

// Seed data
const seedData = {
    users: [
        {
            name: 'Administrator',
            email: 'admin@tradestation.com',
            password: 'admin123',
            balance: 0,
            accountType: 'premium',
            isActive: true,
            referralCode: 'ADMIN001',
            adminSettings: {
                profitPercentage: 80,
                forceWin: false,
                forceWinRate: 0,
                profitCollapse: 'normal'
            }
        },
        {
            name: 'Demo User',
            email: 'demo@tradestation.com',
            password: 'demo123',
            phone: '08123456789',
            balance: 1000000, // 1 million IDR for demo
            accountType: 'standard',
            isActive: true,
            referralCode: 'DEMO001',
            bankData: {
                bankName: 'Bank BCA',
                accountNumber: '1234567890',
                accountHolder: 'Demo User'
            },
            adminSettings: {
                profitPercentage: 80,
                forceWin: false,
                forceWinRate: 0,
                profitCollapse: 'normal'
            }
        },
        {
            name: 'Test Trader',
            email: 'trader@tradestation.com',
            password: 'trader123',
            phone: '08987654321',
            balance: 5000000, // 5 million IDR for testing
            accountType: 'premium',
            isActive: true,
            referralCode: 'TRADER01',
            bankData: {
                bankName: 'Bank Mandiri',
                accountNumber: '9876543210',
                accountHolder: 'Test Trader'
            },
            adminSettings: {
                profitPercentage: 85,
                forceWin: true,
                forceWinRate: 70,
                profitCollapse: 'normal'
            }
        }
    ],
    
    bankAccounts: [
        {
            bankName: 'Bank BCA',
            accountNumber: '1234567890',
            accountHolder: 'TradeStation Official',
            isActive: true,
            note: 'Primary deposit account for BCA users'
        },
        {
            bankName: 'Bank Mandiri',
            accountNumber: '0987654321',
            accountHolder: 'TradeStation Official',
            isActive: true,
            note: 'Primary deposit account for Mandiri users'
        },
        {
            bankName: 'Bank BNI',
            accountNumber: '1122334455',
            accountHolder: 'TradeStation Official',
            isActive: true,
            note: 'Primary deposit account for BNI users'
        },
        {
            bankName: 'Bank BRI',
            accountNumber: '5544332211',
            accountHolder: 'TradeStation Official',
            isActive: true,
            note: 'Primary deposit account for BRI users'
        },
        {
            bankName: 'Bank CIMB Niaga',
            accountNumber: '9988776655',
            accountHolder: 'TradeStation Official',
            isActive: false,
            note: 'Secondary deposit account (currently inactive)'
        }
    ],
    
    cryptoPrices: [
        {
            symbol: 'BTC',
            price: 45230.50,
            change: 2.45
        },
        {
            symbol: 'ETH',
            price: 3200.75,
            change: -1.23
        },
        {
            symbol: 'LTC',
            price: 180.25,
            change: 0.87
        },
        {
            symbol: 'XRP',
            price: 0.6534,
            change: 3.21
        },
        {
            symbol: 'DOGE',
            price: 0.0823,
            change: -2.15
        },
        {
            symbol: 'TRX',
            price: 0.1245,
            change: 1.45
        },
        {
            symbol: 'ETC',
            price: 25.67,
            change: -0.65
        },
        {
            symbol: 'NEO',
            price: 15.43,
            change: 2.87
        }
    ]
};

// Seeding functions
async function seedUsers() {
    try {
        info('Seeding users...');
        
        for (const userData of seedData.users) {
            const existingUser = await User.findOne({ email: userData.email });
            
            if (existingUser) {
                warning(`User ${userData.email} already exists, skipping...`);
                continue;
            }
            
            // Hash password
            const hashedPassword = await bcrypt.hash(userData.password, 12);
            
            const user = new User({
                ...userData,
                password: hashedPassword
            });
            
            await user.save();
            success(`Created user: ${userData.name} (${userData.email})`);
        }
        
        success('Users seeded successfully');
    } catch (err) {
        error(`Error seeding users: ${err.message}`);
        throw err;
    }
}

async function seedBankAccounts() {
    try {
        info('Seeding bank accounts...');
        
        for (const bankData of seedData.bankAccounts) {
            const existingBank = await BankAccount.findOne({ 
                bankName: bankData.bankName,
                accountNumber: bankData.accountNumber 
            });
            
            if (existingBank) {
                warning(`Bank account ${bankData.bankName} - ${bankData.accountNumber} already exists, skipping...`);
                continue;
            }
            
            const bankAccount = new BankAccount(bankData);
            await bankAccount.save();
            success(`Created bank account: ${bankData.bankName} - ${bankData.accountNumber}`);
        }
        
        success('Bank accounts seeded successfully');
    } catch (err) {
        error(`Error seeding bank accounts: ${err.message}`);
        throw err;
    }
}

async function seedCryptoPrices() {
    try {
        info('Seeding cryptocurrency prices...');
        
        for (const priceData of seedData.cryptoPrices) {
            const existingPrice = await Price.findOne({ symbol: priceData.symbol });
            
            if (existingPrice) {
                // Update existing price
                existingPrice.price = priceData.price;
                existingPrice.change = priceData.change;
                existingPrice.lastUpdate = new Date();
                await existingPrice.save();
                success(`Updated price for ${priceData.symbol}: $${priceData.price}`);
            } else {
                // Create new price
                const price = new Price({
                    ...priceData,
                    lastUpdate: new Date()
                });
                await price.save();
                success(`Created price for ${priceData.symbol}: $${priceData.price}`);
            }
        }
        
        success('Cryptocurrency prices seeded successfully');
    } catch (err) {
        error(`Error seeding prices: ${err.message}`);
        throw err;
    }
}

// Main seeding function
async function seedDatabase() {
    try {
        log('\n🌱 TradeStation Database Seeder', 'cyan');
        log('=====================================', 'cyan');
        
        // Connect to MongoDB
        const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/tradestation';
        info(`Connecting to MongoDB: ${mongoUri}`);
        
        await mongoose.connect(mongoUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        success('Connected to MongoDB');
        
        // Run seeding functions
        await seedUsers();
        await seedBankAccounts();
        await seedCryptoPrices();
        
        log('\n🎉 Database seeding completed successfully!', 'green');
        log('=====================================', 'green');
        
        // Display seeded data summary
        const userCount = await User.countDocuments();
        const bankCount = await BankAccount.countDocuments();
        const priceCount = await Price.countDocuments();
        
        log('\n📊 Seeding Summary:', 'cyan');
        log(`👤 Users: ${userCount}`, 'blue');
        log(`🏦 Bank Accounts: ${bankCount}`, 'blue');
        log(`💰 Crypto Prices: ${priceCount}`, 'blue');
        
        log('\n🔐 Default Accounts:', 'cyan');
        log('Admin: admin@tradestation.com / admin123', 'yellow');
        log('Demo: demo@tradestation.com / demo123', 'yellow');
        log('Trader: trader@tradestation.com / trader123', 'yellow');
        
    } catch (err) {
        error(`Seeding failed: ${err.message}`);
        process.exit(1);
    } finally {
        await mongoose.connection.close();
        info('MongoDB connection closed');
        process.exit(0);
    }
}

// Clear database function
async function clearDatabase() {
    try {
        log('\n🗑️  Clearing TradeStation Database', 'red');
        log('=====================================', 'red');
        warning('This will delete ALL data from the database!');
        
        const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/tradestation';
        await mongoose.connect(mongoUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        success('Connected to MongoDB');
        
        // Clear collections
        await User.deleteMany({});
        await BankAccount.deleteMany({});
        await Price.deleteMany({});
        
        success('Database cleared successfully');
        
    } catch (err) {
        error(`Clear failed: ${err.message}`);
        process.exit(1);
    } finally {
        await mongoose.connection.close();
        process.exit(0);
    }
}

// Check command line arguments
const args = process.argv.slice(2);

if (args.includes('--clear')) {
    clearDatabase();
} else if (args.includes('--help')) {
    log('\n🌱 TradeStation Database Seeder', 'cyan');
    log('=====================================', 'cyan');
    log('Usage:', 'blue');
    log('  node scripts/seed.js          # Seed database with initial data', 'reset');
    log('  node scripts/seed.js --clear  # Clear all data from database', 'reset');
    log('  node scripts/seed.js --help   # Show this help message', 'reset');
    log('');
    process.exit(0);
} else {
    seedDatabase();
}

module.exports = { seedDatabase, clearDatabase };
