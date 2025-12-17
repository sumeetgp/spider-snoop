# Spider-Snoop DLP ![CI Status](https://github.com/sumeetgp/spider-snoop/actions/workflows/deploy.yml/badge.svg) System

🕷️ **Spider-Snoop** is a comprehensive Data Loss Prevention (DLP) system with AI-powered scanning, ICAP protocol support, and a modern web dashboard.

## 🌟 Features

- ✅ **User Authentication & Authorization** - JWT-based auth with role-based access control
- ✅ **Multi-User Support** - Admin, Analyst, and Viewer roles
- ✅ **AI-Powered DLP Scanning** - OpenAI-enhanced content analysis
- ✅ **ICAP Protocol Support** - Standard DLP integration for proxies and gateways
- ✅ **Pattern-Based Detection** - Detects credit cards, SSNs, API keys, emails, and more
- ✅ **Real-time Dashboard** - Analytics, trends, and statistics
- ✅ **RESTful API** - Complete API for all operations
- ✅ **Database Persistence** - SQLite/PostgreSQL support

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/sumeetgp/spider-snoop.git
cd spider-snoop
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your settings (OpenAI API key, etc.)
```

5. **Initialize database**
```bash
python scripts/init_db.py
```

6. **Run the application**
```bash
python -m app.main
# Or using uvicorn directly:
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

7. **Access the application**
- Web Dashboard: http://localhost:8000
- API Documentation: http://localhost:8000/docs
- ICAP Server: icap://localhost:1344/dlp_scan

## 👥 Default Users

After running `init_db.py`, these users are created:

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| admin | admin123 | Admin | Full access |
| analyst | analyst123 | Analyst | View all, scan |
| viewer | viewer123 | Viewer | View own scans |

⚠️ **Change these passwords in production!**

## 📡 API Endpoints

### Authentication
- `POST /api/auth/login` - Login and get JWT token

### User Management
- `GET /api/users/me` - Get current user info
- `GET /api/users/` - List all users (Admin/Analyst)
- `POST /api/users/` - Create user (Admin)
- `PUT /api/users/{id}` - Update user (Admin)
- `DELETE /api/users/{id}` - Delete user (Admin)

### DLP Scanning
- `POST /api/scans/` - Create and execute scan
- `GET /api/scans/` - List scans
- `GET /api/scans/{id}` - Get scan details
- `GET /api/scans/stats` - Get scan statistics

### Dashboard
- `GET /api/dashboard/overview` - Dashboard overview with stats

## 🔌 ICAP Integration

Configure your proxy or gateway to use Spider-Snoop as ICAP server:

```
ICAP Server: icap://your-server-ip:1344/dlp_scan
Methods: REQMOD, RESPMOD
```

### Supported ICAP Clients
- Squid Proxy
- c-icap
- Any ICAP-compliant proxy/gateway

## 🔍 Detected Data Types

- 💳 **Credit Card Numbers** - Visa, MasterCard, Amex, Discover
- 🆔 **Social Security Numbers (SSN)**
- 📧 **Email Addresses**
- 📞 **Phone Numbers**
- 🌐 **IP Addresses**
- 🔑 **API Keys & Access Tokens**
- ☁️ **AWS Access Keys**

## 🏗️ Architecture

```
spider-snoop/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration
│   ├── database.py          # Database setup
│   ├── dlp_engine.py        # DLP scanning engine
│   ├── icap_server.py       # ICAP protocol server
│   ├── models/              # Database models
│   │   ├── user.py
│   │   └── scan.py
│   ├── schemas/             # Pydantic schemas
│   │   ├── user.py
│   │   └── scan.py
│   ├── routes/              # API routes
│   │   ├── auth.py
│   │   ├── users.py
│   │   ├── scans.py
│   │   └── dashboard.py
│   └── utils/
│       └── auth.py          # Authentication utilities
├── scripts/
│   └── init_db.py           # Database initialization
├── requirements.txt
├── .env.example
└── README.md
```

## 🧪 Testing

### Test DLP Scan via API

```bash
# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"

# Scan content
curl -X POST http://localhost:8000/api/scans/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content": "My credit card is 4532-1234-5678-9012", "source": "API"}'
```

### Test ICAP Server

```bash
# Using c-icap-client
c-icap-client -i localhost -p 1344 -s dlp_scan -f test_file.txt
```

## 🔒 Security Considerations

1. **Change default passwords** immediately in production
2. **Use strong SECRET_KEY** in .env file
3. **Enable HTTPS** in production
4. **Configure CORS** appropriately
5. **Use PostgreSQL** instead of SQLite for production
6. **Implement rate limiting**
7. **Enable API key rotation**

## 📊 Database Schema

### Users Table
- id, email, username, hashed_password
- full_name, role, is_active
- created_at, updated_at

### DLP Scans Table
- id, user_id, source, content
- status, risk_level, findings, verdict
- scan_duration_ms, created_at, completed_at

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

MIT License - see LICENSE file for details

## 🆘 Support

For issues and questions:
- GitHub Issues: https://github.com/sumeetgp/spider-snoop/issues

## 🎯 Roadmap

- [x] Web Dashboard UI (HTML/Jinja2)
- [ ] Email notifications for critical findings
- [ ] Custom detection rules
- [ ] Machine learning model training
- [ ] Multi-language support
- [ ] Reporting & exports
- [ ] Integration with SIEM systems
- [x] Docker containerization

## ☁️ Cloud Deployment

Spider-Snoop is cloud-ready and includes a full Docker stack with Nginx as a reverse proxy.

### 1. Requirements
- A cloud server (AWS EC2, DigitalOcean Droplet, Linode, etc.)
- OS: Ubuntu 20.04+ (Recommended)
- **Git** installed on the server (to clone the repo)

### 2. Quick Deployment Script
We provide a zero-configuration deployment script (`deploy.sh`) that automates everything: checking/installing Docker, setting up credentials, and launching the services.

1. **Clone the repository/copy files** to your server:
   ```bash
   git clone https://github.com/sumeetgp/spider-snoop.git
   cd spider-snoop
   ```

2. **Run the deployment script**:
   ```bash
   chmod +x deploy.sh
   ./deploy.sh
   ```
   > The script will prompt you for your `OPENAI_API_KEY` if it's not present in `.env`.

3. **Access the application**:
   - Open your browser and navigate to: `http://<your-server-ip>`
   - The application usually listens on **Port 80**. Ensure your firewall allows HTTP traffic.

### 3. Manual Docker Deployment
If you prefer to run `docker-compose` manually:

1. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Add your OPENAI_API_KEY to .env
   ```

2. **Start Services**:
   ```bash
   docker-compose up -d --build
   ```

3. **Verify**:
   ```bash
   docker ps
   # You should see 3 containers: spider-snoop-nginx, spider-snoop-api, spider-snoop-db
   ```

### 4. Nginx Configuration
The included `nginx/nginx.conf` handles reverse proxying to the API and serving static files. It is configured to run on Port 80 inside the Docker network.

---

---

Made with ❤️ by the Spider-Snoop team
