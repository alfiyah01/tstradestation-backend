# 🚀 TradeStation Backend

Backend API untuk platform trading cryptocurrency TradeStation yang sudah terhubung dengan:
- **Database**: MongoDB Atlas 
- **Frontend**: ts-traderstation.com & ts-traderstation.netlify.app
- **Deployment**: Railway (tstradestation-backend-production.up.railway.app)

## 📋 Fitur Utama

### 🔐 Authentication & User Management
- ✅ User registration & login dengan JWT
- ✅ Profile management
- ✅ Admin panel dengan full control
- ✅ Activity logging untuk audit

### 💱 Trading Engine
- ✅ Real-time cryptocurrency prices (8 crypto: BTC, ETH, LTC, XRP, DOGE, TRX, ETC, NEO)
- ✅ Live trading dengan durasi 30s - 5m
- ✅ Profit percentage 20% - 100%
- ✅ Automatic trade processing
- ✅ Admin control untuk force win/lose

### 💰 Financial Operations
- ✅ Deposit system dengan approval workflow
- ✅ Withdrawal system dengan fee calculation (1% min 6.500)
- ✅ Real-time balance updates
- ✅ Transaction history

### 📊 Admin Dashboard
- ✅ Complete user management
- ✅ Trade monitoring & control
- ✅ Deposit/Withdrawal approval
- ✅ Real-time statistics
- ✅ Activity monitoring

### ⚡ Real-time Features
- ✅ Socket.IO integration
- ✅ Live price updates setiap 2 detik
- ✅ Instant notifications untuk trades, deposits, withdrawals
- ✅ Real-time admin monitoring

## 🛠️ Teknologi yang Digunakan

- **Backend**: Node.js + Express.js
- **Database**: MongoDB Atlas
- **Real-time**: Socket.IO
- **Authentication**: JWT + bcryptjs
- **Security**: Helmet, CORS, Rate Limiting
- **Deployment**: Railway

## 📦 Instalasi dan Setup

### 1. Clone atau Download Files

Pastikan Anda memiliki files berikut:
```
tradestation-backend/
├── server.js
├── package.json
├── .env
└── README.md
```

### 2. Install Dependencies

```bash
# Install Node.js dependencies
npm install

# Untuk development (optional)
npm install -g nodemon
```

### 3. Environment Variables

File `.env` sudah dikonfigurasi dengan:
```env
PORT=3000
MONGODB_URI=mongodb+srv://tradestation:Yusrizal1993@clustertrading.7jozj2u.mongodb.net/tradestation?retryWrites=true&w=majority&appName=Clustertrading
JWT_SECRET=tradestation_super_secret_key_2024_very_secure
NODE_ENV=production
```

### 4. Jalankan Server

```bash
# Production
npm start

# Development (dengan auto-restart)
npm run dev
```

Server akan berjalan di `http://localhost:3000`

## 🌐 API Endpoints

### Authentication
- `POST /api/register` - Register user baru
- `POST /api/login` - Login user
- `GET /api/profile` - Get user profile
- `PUT /api/profile` - Update profile

### Trading
- `GET /api/prices` - Get semua harga crypto
- `GET /api/prices/:symbol` - Get harga crypto spesifik
- `POST /api/trade` - Buat trade baru
- `GET /api/trades` - Get riwayat trading user

### Financial
- `POST /api/deposit` - Request deposit
- `GET /api/deposits` - Get riwayat deposit
- `POST /api/withdrawal` - Request withdrawal
- `GET /api/withdrawals` - Get riwayat withdrawal

### Admin Panel
- `GET /api/admin/dashboard` - Dashboard statistics
- `GET /api/admin/users` - Get all users
- `GET /api/admin/users/:id` - Get user detail
- `PUT /api/admin/user/:id` - Update user
- `DELETE /api/admin/user/:id` - Deactivate user
- `GET /api/admin/trades` - Get all trades
- `PUT /api/admin/trade/:id` - Control trade result
- `GET /api/admin/deposits` - Get all deposits
- `PUT /api/admin/deposit/:id` - Approve/reject deposit
- `GET /api/admin/withdrawals` - Get all withdrawals
- `PUT /api/admin/withdrawal/:id` - Approve/reject withdrawal

## 🔐 Admin Access

**Default Admin Credentials:**
- Email: `admin@tradestation.com`
- Password: `admin123`

Admin akan otomatis dibuat saat server pertama kali dijalankan.

## 📱 Frontend Integration

Server sudah dikonfigurasi untuk bekerja dengan:
- **Primary Domain**: https://ts-traderstation.com
- **Subdomain**: https://ts-traderstation.netlify.app
- **Local Development**: http://localhost:3000

## 🚀 Deployment ke Railway

### 1. Push ke GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git push origin main
```

### 2. Deploy di Railway
1. Login ke [Railway.app](https://railway.app)
2. Connect GitHub repository
3. Deploy otomatis akan berjalan
4. Set environment variables di Railway dashboard

### 3. Custom Domain
Tambahkan domain `ts-traderstation.com` di Railway settings.

## ⚙️ Konfigurasi Sistem

### Crypto Price Updates
- Update setiap 2 detik
- Simulasi real-time dengan fluctuation -2% sampai +2%
- Support 8 cryptocurrency utama

### Trading Engine
- Process trade expired setiap 1 detik
- Automatic win/lose calculation
- Admin bisa force result manual

### Security Features
- JWT authentication dengan expire 30 hari
- Password hashing dengan bcrypt
- Rate limiting: 100 requests per 15 menit
- CORS protection untuk domain tertentu
- Helmet untuk security headers

## 📊 Database Collections

### Users
- Personal information
- Balance & trading stats
- Account type & status
- Referral system

### Trades
- Trading details & results
- Real-time status tracking
- Profit/loss calculation
- Admin control features

### Deposits
- Amount & bank information
- Receipt/proof upload
- Approval workflow
- Auto balance update

### Withdrawals
- Bank account details
- Fee calculation
- Approval workflow
- Balance deduction

### Activities
- Complete audit trail
- User action logging
- Admin action logging
- IP & user agent tracking

## 🔧 Troubleshooting

### Server tidak bisa start
```bash
# Cek port yang digunakan
netstat -tulpn | grep :3000

# Kill process yang menggunakan port
sudo kill -9 $(lsof -t -i:3000)
```

### Database connection error
- Pastikan MongoDB Atlas whitelist IP server
- Cek connection string di `.env`
- Verify database credentials

### CORS Error
- Pastikan domain frontend sudah ditambah di CORS config
- Cek protocol (http vs https)

## 🆘 Support

Jika ada masalah atau pertanyaan:
1. Cek log server untuk error details
2. Verify environment variables
3. Test API endpoints dengan Postman
4. Check database connection

## 📈 Performance Monitoring

Server sudah include:
- ✅ Health check endpoint: `GET /api/health`
- ✅ Uptime monitoring
- ✅ Error logging
- ✅ Activity tracking

---

**🎯 Server sudah siap untuk production dan fully compatible dengan frontend yang ada!**
