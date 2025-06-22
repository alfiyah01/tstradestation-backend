# 🚀 TradeStation Backend - Complete Setup Guide

## 📋 Overview

TradeStation adalah platform trading cryptocurrency dengan fitur:
- ✅ Email Authentication dengan JWT
- ✅ Real-time Chart Data dengan Socket.IO  
- ✅ Mobile-First Design
- ✅ Trading System dengan Admin Control
- ✅ Deposit/Withdrawal Management
- ✅ File Upload untuk Bukti Transfer
- ✅ Comprehensive Security

## 🎯 Quick Start (5 menit)

### 1. Clone & Install
```bash
# Clone repository
git clone <your-repo-url>
cd tradestation-backend

# Install dependencies & setup
npm install
node setup.js
```

### 2. Configure Database
```bash
# Edit .env file
nano .env

# Update MONGODB_URI dengan connection string Anda
MONGODB_URI=mongodb://localhost:27017/tradestation
# atau untuk MongoDB Atlas:
# MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/tradestation
```

### 3. Seed Database
```bash
# Populate dengan data awal
npm run seed
```

### 4. Start Server
```bash
# Development
npm run dev

# Production
npm start
```

### 5. Test Installation
```bash
# Check health
curl http://localhost:3000/api/health

# Default admin login
# Email: admin@tradestation.com
# Password: admin123
```

## 📁 File Structure

```
tradestation-backend/
├── server.js              # Main server file
├── package.json           # Dependencies
├── .env                   # Environment variables
├── .env.example          # Environment template
├── ecosystem.config.js   # PM2 configuration
├── setup.js              # Setup script
├── 
├── scripts/
│   ├── seed.js           # Database seeder
│   └── backup.js         # Backup utility
│
├── logs/                 # Application logs
├── uploads/              # File uploads
├── backups/              # Database backups
│
└── frontend/
    ├── index.html        # Frontend application
    └── logo.svg          # TradeStation logo
```

## 🔧 Detailed Setup

### Prerequisites

**System Requirements:**
- Node.js >= 16.0.0
- MongoDB >= 5.0
- NPM >= 8.0.0
- PM2 (untuk production)
- Git

**Operating System:**
- Linux (Ubuntu 20.04+ recommended)
- macOS 10.15+
- Windows 10+ (dengan WSL2)

### 1. Environment Setup

#### Development Environment
```bash
# 1. Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# 2. Install MongoDB (Ubuntu)
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org

# 3. Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# 4. Install PM2 globally
npm install -g pm2
```

#### Production Environment (Ubuntu Server)
```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install Node.js, MongoDB, PM2
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs mongodb git nginx

# 3. Install PM2
npm install -g pm2

# 4. Configure firewall
sudo ufw allow 22
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 3000
sudo ufw enable
```

### 2. Application Setup

#### Clone Repository
```bash
git clone https://github.com/your-username/tradestation-backend.git
cd tradestation-backend
```

#### Install Dependencies
```bash
# Install all dependencies
npm install

# Or install production only
npm ci --only=production
```

#### Run Setup Script
```bash
# Automatic setup
node setup.js

# Manual setup
cp .env.example .env
mkdir -p logs uploads backups scripts
```

### 3. Environment Configuration

#### MongoDB Configuration

**Local MongoDB:**
```bash
# .env
MONGODB_URI=mongodb://localhost:27017/tradestation
```

**MongoDB Atlas:**
```bash
# .env  
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/tradestation?retryWrites=true&w=majority
```

**MongoDB with Authentication:**
```bash
# .env
MONGODB_URI=mongodb://username:password@localhost:27017/tradestation?authSource=admin
```

#### JWT Configuration
```bash
# Generate strong JWT secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Add to .env
JWT_SECRET=your_generated_secret_here
```

#### Security Configuration
```bash
# .env
# CORS Origins (comma separated)
CORS_ORIGINS=http://localhost:3000,https://your-domain.com

# Rate limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_MAX=5

# File upload limits
MAX_FILE_SIZE=5242880
ALLOWED_FILE_TYPES=image/jpeg,image/jpg,image/png
```

### 4. Database Setup

#### Initialize Database
```bash
# Seed with initial data
npm run seed

# Clear database (if needed)
npm run seed -- --clear
```

#### Manual Database Setup
```javascript
// Connect to MongoDB
mongo tradestation

// Create admin user
db.users.insertOne({
  name: "Administrator",
  email: "admin@tradestation.com", 
  password: "$2b$12$...", // bcrypt hash of 'admin123'
  accountType: "premium",
  isActive: true
})
```

### 5. Development

#### Start Development Server
```bash
# With nodemon (auto-restart)
npm run dev

# With debugging
npm run dev:debug

# Check logs
tail -f logs/combined.log
```

#### Testing API Endpoints
```bash
# Health check
curl http://localhost:3000/api/health

# Register user
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"test@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

## 🚀 Production Deployment

### 1. Server Preparation

```bash
# 1. Setup production user
sudo adduser tradestation
sudo usermod -aG sudo tradestation
su - tradestation

# 2. Clone repository
git clone https://github.com/your-username/tradestation-backend.git
cd tradestation-backend

# 3. Install dependencies
npm ci --only=production
```

### 2. Environment Configuration

```bash
# Production .env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/tradestation
JWT_SECRET=your_super_secure_production_secret
CORS_ORIGINS=https://your-domain.com
```

### 3. PM2 Deployment

```bash
# Start with PM2
pm2 start ecosystem.config.js --env production

# Save PM2 configuration
pm2 save

# Setup auto-restart on reboot
pm2 startup
sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u tradestation --hp /home/tradestation

# Monitor
pm2 monit
pm2 logs tradestation-backend
```

### 4. Nginx Configuration

```nginx
# /etc/nginx/sites-available/tradestation
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    
    # Frontend
    location / {
        root /home/tradestation/tradestation-backend/frontend;
        index index.html;
        try_files $uri $uri/ /index.html;
    }
    
    # API Backend
    location /api {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
    
    # Socket.IO
    location /socket.io/ {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/tradestation /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 5. SSL Certificate (Let's Encrypt)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### 6. Monitoring & Logging

```bash
# Setup log rotation
sudo nano /etc/logrotate.d/tradestation
```

```
/home/tradestation/tradestation-backend/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    notifempty
    create 0640 tradestation tradestation
    postrotate
        pm2 reloadLogs
    endscript
}
```

## 🔧 Maintenance

### Daily Operations

```bash
# Check status
pm2 status
pm2 logs tradestation-backend --lines 50

# Restart if needed
pm2 restart tradestation-backend

# Update application
git pull origin main
npm install
pm2 reload tradestation-backend
```

### Database Backup

```bash
# Manual backup
mongodump --uri="mongodb://localhost:27017/tradestation" --out=backups/$(date +%Y%m%d)

# Automated backup (add to crontab)
0 2 * * * /home/tradestation/tradestation-backend/scripts/backup.sh
```

### Update Dependencies

```bash
# Check outdated packages
npm outdated

# Update packages
npm update

# Security audit
npm audit
npm audit fix
```

## 🛡️ Security Checklist

### Server Security
- [ ] Firewall configured (ufw)
- [ ] SSH key authentication only
- [ ] Regular security updates
- [ ] Non-root user for application
- [ ] Fail2ban for SSH protection

### Application Security
- [ ] Strong JWT secret (32+ characters)
- [ ] Rate limiting enabled
- [ ] CORS properly configured
- [ ] Helmet security headers
- [ ] Input validation
- [ ] File upload restrictions
- [ ] Environment variables secured

### Database Security
- [ ] MongoDB authentication enabled
- [ ] Database firewall rules
- [ ] Regular backups
- [ ] Encrypted connections (SSL)
- [ ] Principle of least privilege

## 🚨 Troubleshooting

### Common Issues

**1. MongoDB Connection Failed**
```bash
# Check MongoDB status
sudo systemctl status mongod

# Check connection
mongo --eval "db.stats()"

# Check logs
sudo tail -f /var/log/mongodb/mongod.log
```

**2. PM2 Process Crashed**
```bash
# Check PM2 logs
pm2 logs tradestation-backend

# Check system resources
free -h
df -h

# Restart process
pm2 restart tradestation-backend
```

**3. High Memory Usage**
```bash
# Check memory usage
pm2 monit

# Reload with zero-downtime
pm2 reload tradestation-backend

# Check for memory leaks
node --inspect server.js
```

**4. Socket.IO Connection Issues**
```bash
# Check WebSocket support
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:3000/socket.io/

# Check Nginx configuration
sudo nginx -t
```

### Performance Optimization

**1. Database Optimization**
```javascript
// Add database indices
db.users.createIndex({ email: 1 })
db.trades.createIndex({ userId: 1, createdAt: -1 })
db.prices.createIndex({ symbol: 1 })
```

**2. Node.js Optimization**
```bash
# Increase memory limit
node --max-old-space-size=2048 server.js

# Enable cluster mode
pm2 start ecosystem.config.js
```

**3. Nginx Optimization**
```nginx
# Add to nginx configuration
gzip on;
gzip_types text/plain application/json application/javascript text/css;
client_max_body_size 10M;
```

## 📞 Support

### Getting Help

1. **Documentation**: Check this guide and README.md
2. **Logs**: Always check application and system logs
3. **Health Check**: Visit `/api/health` endpoint
4. **Community**: Create GitHub issues for bugs
5. **Professional Support**: Contact development team

### Useful Commands

```bash
# Application status
npm run status

# View logs
npm run logs

# Database health
mongo tradestation --eval "db.stats()"

# System resources
htop
iotop
netstat -tulpn | grep :3000
```

---

## ✅ Setup Complete!

Setelah mengikuti panduan ini, TradeStation backend Anda sudah siap untuk:

- ✅ Development dan testing
- ✅ Production deployment  
- ✅ Monitoring dan maintenance
- ✅ Scaling dan optimization

**Default Accounts:**
- **Admin**: admin@tradestation.com / admin123
- **Demo**: demo@tradestation.com / demo123  
- **Trader**: trader@tradestation.com / trader123

**API Health Check**: http://localhost:3000/api/health

**Happy Trading! 🚀**
