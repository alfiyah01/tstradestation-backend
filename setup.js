#!/usr/bin/env node

/**
 * TradeStation Backend Setup Script
 * This script helps you set up the TradeStation backend environment
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m'
};

// Console helpers
const log = (message, color = 'reset') => {
    console.log(`${colors[color]}${message}${colors.reset}`);
};

const success = (message) => log(`✅ ${message}`, 'green');
const error = (message) => log(`❌ ${message}`, 'red');
const warning = (message) => log(`⚠️  ${message}`, 'yellow');
const info = (message) => log(`ℹ️  ${message}`, 'blue');
const header = (message) => log(`\n🚀 ${message}`, 'cyan');

// Setup functions
function generateJWTSecret() {
    return crypto.randomBytes(32).toString('hex');
}

function createEnvFile() {
    const envPath = path.join(__dirname, '.env');
    const envExamplePath = path.join(__dirname, '.env.example');
    
    if (fs.existsSync(envPath)) {
        warning('.env file already exists. Skipping...');
        return;
    }
    
    if (!fs.existsSync(envExamplePath)) {
        error('.env.example file not found! Please create it first.');
        return;
    }
    
    // Read .env.example
    let envContent = fs.readFileSync(envExamplePath, 'utf8');
    
    // Generate JWT secret
    const jwtSecret = generateJWTSecret();
    envContent = envContent.replace(
        'JWT_SECRET=your_super_secret_jwt_key_min_32_characters_long_please_change_this',
        `JWT_SECRET=${jwtSecret}`
    );
    
    // Set development environment by default
    envContent = envContent.replace('NODE_ENV=development', 'NODE_ENV=development');
    
    // Write .env file
    fs.writeFileSync(envPath, envContent);
    success('.env file created with generated JWT secret');
}

function createDirectories() {
    const directories = [
        'logs',
        'uploads',
        'backups',
        'scripts',
        'middleware',
        'routes',
        'models',
        'utils'
    ];
    
    directories.forEach(dir => {
        const dirPath = path.join(__dirname, dir);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
            success(`Created directory: ${dir}`);
        }
    });
}

function createGitignore() {
    const gitignorePath = path.join(__dirname, '.gitignore');
    
    if (fs.existsSync(gitignorePath)) {
        warning('.gitignore already exists. Skipping...');
        return;
    }
    
    const gitignoreContent = `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Logs
logs/
*.log

# Runtime data
pids/
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/

# nyc test coverage
.nyc_output

# Dependency directories
jspm_packages/

# Optional npm cache directory
.npm

# Optional eslint cache
.eslintcache

# Microbundle cache
.rpt2_cache/
.rts2_cache_cjs/
.rts2_cache_es/
.rts2_cache_umd/

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# parcel-bundler cache (https://parceljs.org/)
.cache
.parcel-cache

# next.js build output
.next

# nuxt.js build output
.nuxt

# vuepress build output
.vuepress/dist

# Serverless directories
.serverless/

# FuseBox cache
.fusebox/

# DynamoDB Local files
.dynamodb/

# TernJS port file
.tern-port

# Stores VSCode versions used for testing VSCode extensions
.vscode-test

# Uploads
uploads/
backups/

# PM2
.pm2/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# TradeStation specific
temp/
cache/
`;
    
    fs.writeFileSync(gitignorePath, gitignoreContent);
    success('.gitignore file created');
}

function createReadme() {
    const readmePath = path.join(__dirname, 'README.md');
    
    if (fs.existsSync(readmePath)) {
        warning('README.md already exists. Skipping...');
        return;
    }
    
    const readmeContent = `# TradeStation Backend

Backend API untuk TradeStation - Platform Trading Cryptocurrency dengan fitur Mobile-First.

## 🚀 Features

- ✅ Email Authentication dengan JWT
- ✅ Real-time Chart Data dengan Socket.IO
- ✅ Trading System dengan Admin Control
- ✅ Deposit/Withdrawal Management
- ✅ Mobile-First API Design
- ✅ File Upload untuk Bukti Transfer
- ✅ Bank Account Management
- ✅ Comprehensive Security

## 📋 Requirements

- Node.js >= 16.0.0
- MongoDB
- NPM >= 8.0.0

## 🛠️ Installation

1. Clone repository
2. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`

3. Setup environment:
   \`\`\`bash
   npm run setup
   \`\`\`

4. Start development server:
   \`\`\`bash
   npm run dev
   \`\`\`

## 🔧 Configuration

Copy \`.env.example\` to \`.env\` and configure your environment variables:

- \`MONGODB_URI\` - MongoDB connection string
- \`JWT_SECRET\` - JWT secret key (auto-generated)
- \`PORT\` - Server port (default: 3000)

## 📚 API Endpoints

### Authentication
- \`POST /api/register\` - User registration
- \`POST /api/login\` - User login

### Trading
- \`GET /api/prices\` - Get crypto prices
- \`GET /api/chart/:symbol/:timeframe\` - Get chart data
- \`POST /api/trade\` - Create trade
- \`GET /api/trades\` - Get user trades

### Financial
- \`POST /api/deposit\` - Submit deposit
- \`POST /api/withdrawal\` - Submit withdrawal
- \`GET /api/deposits\` - Get deposit history
- \`GET /api/withdrawals\` - Get withdrawal history

### User
- \`GET /api/profile\` - Get user profile
- \`PUT /api/profile/bank\` - Update bank data

## 🔐 Admin Access

Default admin account:
- Email: \`admin@tradestation.com\`
- Password: \`admin123\`

## 🚀 Deployment

### Development
\`\`\`bash
npm run dev
\`\`\`

### Production
\`\`\`bash
npm start
\`\`\`

### PM2 (Recommended for Production)
\`\`\`bash
npm install -g pm2
pm2 start server.js --name tradestation
pm2 startup
pm2 save
\`\`\`

## 📊 Monitoring

- Health check: \`GET /api/health\`
- PM2 monitoring: \`pm2 monit\`
- Logs: \`pm2 logs tradestation\`

## 🛡️ Security Features

- Rate limiting
- CORS protection
- Helmet security headers
- JWT authentication
- Password hashing
- Input validation

## 📝 License

MIT License - see LICENSE file for details.
`;
    
    fs.writeFileSync(readmePath, readmeContent);
    success('README.md file created');
}

function installDependencies() {
    try {
        info('Installing dependencies...');
        execSync('npm install', { stdio: 'inherit' });
        success('Dependencies installed successfully');
    } catch (error) {
        error('Failed to install dependencies');
        console.log('Please run: npm install');
    }
}

function displaySuccess() {
    header('TradeStation Backend Setup Complete! 🎉');
    console.log('\n📋 Next Steps:');
    console.log('1. Configure your MongoDB connection in .env');
    console.log('2. Start development server: npm run dev');
    console.log('3. Open http://localhost:3000/api/health to verify');
    console.log('4. Admin login: admin@tradestation.com / admin123');
    
    console.log('\n🔧 Available Commands:');
    console.log('- npm run dev      # Start development server');
    console.log('- npm start        # Start production server');
    console.log('- npm run logs     # View PM2 logs');
    console.log('- npm run status   # Check PM2 status');
    
    console.log('\n📚 Documentation:');
    console.log('- API Health: http://localhost:3000/api/health');
    console.log('- Admin Panel: Configure via API endpoints');
    console.log('- WebSocket: Real-time updates enabled');
    
    console.log('\n✨ TradeStation is ready for development!');
}

// Main setup function
async function setup() {
    try {
        header('TradeStation Backend Setup');
        
        info('Starting setup process...');
        
        // Create necessary files and directories
        createDirectories();
        createEnvFile();
        createGitignore();
        createReadme();
        
        // Install dependencies
        installDependencies();
        
        // Display completion message
        displaySuccess();
        
    } catch (error) {
        error(`Setup failed: ${error.message}`);
        process.exit(1);
    }
}

// Run setup if this script is executed directly
if (require.main === module) {
    setup();
}

module.exports = { setup };
