# PhishHawk Backend

Phishing Takedown Automation System - Backend API

## Features

- ✅ **Two-Phase Automated Process** following flowchart design:
  - **Phase 1: Intelligence Gathering** - VirusTotal, URLhaus & Google Safe Browsing API integration
  - **Automated Risk Scoring Engine** - Combines intelligence with URL analysis
  - **Phase 2: Enforcement** - Cloudflare Registrar API for domain takedown + Email notifications
  - **Immutable Audit Logging** - Complete audit trail of all actions
- ✅ Automated URL risk analysis with rule-based scoring
- ✅ Multi-API Intelligence: VirusTotal, URLhaus (free), Google Safe Browsing
- ✅ Cloudflare Registrar API for automated domain takedown
- ✅ Email takedown reports (APWG, registrars)
- ✅ Immutable audit log system
- ✅ URL scraping from RSS feeds, URLhaus, and Twitter
- ✅ MongoDB database for storing reports
- ✅ RESTful API with pagination and filtering
- ✅ Comprehensive logging system

## Flowchart Process

The system follows a strict two-phase automated process:

1. **Input**: Suspected Phishing Domain
2. **Phase 1: Intelligence Gathering**
   - VirusTotal API Multi-engine Scan
   - URLhaus Malware URL Check (Free, no API key required)
   - Google Safe Browsing API (Optional)
3. **Automated Risk Scoring Engine**
   - Combines intelligence results with URL analysis
   - Calculates final risk score (0-100)
4. **Decision Branch**:
   - **High-Risk Score (≥70)**: 
     - Phase 2: Cloudflare Registrar API Enforcement
     - Send takedown email to APWG/registrars
     - Confirmation & Immutable Audit Log
     - Output: Domain Takedown Initiated
   - **Low-Risk Score (<70)**:
     - Log & Flag for Review

## Setup

### Prerequisites

- Node.js 18+ 
- MongoDB (local or cloud instance like MongoDB Atlas)
- API keys (see below for required vs optional):
  - **VirusTotal API key** (Recommended - free tier available)
  - **URLhaus** - No API key required (free public API)
  - **Google Safe Browsing API key** (Optional - free tier available)
  - **Cloudflare API credentials** (Optional - for automated domain takedown)
  - SMTP credentials (Optional - for email takedown reports)
  - Twitter Bearer Token (Optional - for Twitter scraping)

### Installation

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the root directory:
```env
# Server Configuration
PORT=3000
NODE_ENV=development
FRONTEND_URL=http://localhost:5173

# MongoDB Configuration (MongoDB Atlas)
# Format: mongodb+srv://username:password@cluster-hostname.mongodb.net/database-name?retryWrites=true&w=majority
# Replace YOUR_CLUSTER_HOSTNAME with your actual MongoDB Atlas cluster hostname
# You can find it in MongoDB Atlas dashboard under "Connect" -> "Connect your application"
MONGO_URI=mongodb+srv://bitoscorche_db_user:6qRqREBpo8mCiZhE@YOUR_CLUSTER_HOSTNAME.mongodb.net/phishhawk?retryWrites=true&w=majority

# ============================================
# PHASE 1: INTELLIGENCE GATHERING APIs
# ============================================

# VirusTotal API (REQUIRED for Phase 1)
# Get your API key from: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# PhishTank API (REQUIRED for Phase 1)
# Get your API key from: https://www.phishtank.com/api_register.php
PHISHTANK_API_KEY=your_phishtank_api_key_here

# ============================================
# PHASE 2: ENFORCEMENT APIs
# ============================================

# Cloudflare Registrar API (REQUIRED for Phase 2)
# Get your API key from: https://dash.cloudflare.com/profile/api-tokens
# You need: API Key, Email, and Account ID
CLOUDFLARE_API_KEY=your_cloudflare_api_key_here
CLOUDFLARE_EMAIL=your_cloudflare_email@example.com
CLOUDFLARE_ACCOUNT_ID=your_cloudflare_account_id_here

# Twitter API (Optional - for URL scraping)
TWITTER_BEARER_TOKEN=your_twitter_bearer_token_here

# SMTP Configuration (Required for takedown emails)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password_here
SMTP_FROM="PhishHawk <your_email@gmail.com>"
EMAIL_TO=report@apwg.org
```

3. Start the server:
```bash
# Development mode with auto-reload
npm run dev

# Production mode
npm start
```

## API Endpoints

### Phishing Reports

- `POST /api/phishing` - Submit a new phishing report (follows flowchart process)
- `GET /api/phishing` - Get all reports (with pagination and filters)
- `GET /api/phishing/:id` - Get specific report
- `GET /api/phishing/:id/audit-logs` - Get immutable audit logs for a report
- `POST /api/phishing/:id/reanalyze` - Re-analyze a report
- `POST /api/phishing/:id/takedown` - Submit takedown request
- `GET /api/phishing/metrics` - Get system metrics
- `GET /api/phishing/api-status` - Check external API configuration status

### URL Scraping

- `POST /api/scraping/start` - Start automated URL scraping
- `POST /api/scraping/stop` - Stop automated URL scraping
- `GET /api/scraping/status` - Get current scraping status
- `POST /api/scraping/scrape-now` - Manually trigger a scrape from a source

### Health Check

- `GET /health` - Server health status

## Risk Scoring

The system uses rule-based risk scoring with the following factors:

- **Protocol**: HTTP vs HTTPS (+15 points for HTTP)
- **Suspicious TLDs**: Known risky top-level domains (+30 points)
- **Domain Length**: Very long domains (+20 points)
- **Subdomains**: Excessive subdomains (+15 points)
- **Keywords**: Phishing-related keywords (+10 per match)
- **URL Shorteners**: Shortened URLs (+25 points)
- **IP in Domain**: IP addresses in domain (+40 points)
- **Content Analysis**: Password forms, login pages, urgent language

Risk Levels:
- **High**: Score ≥ 70
- **Medium**: Score ≥ 40
- **Low**: Score < 40

## Logging

### Application Logs
Logs are stored in the `logs/` directory with daily rotation. Logs include:
- API requests and responses
- Error messages
- Scraping activities
- Takedown submissions

### Immutable Audit Logs
All actions in the flowchart process are logged to an immutable audit log system:
- Intelligence gathering (VirusTotal & PhishTank scans)
- Risk score calculations
- Takedown initiations
- Status changes
- All actions are timestamped and cannot be modified

Access audit logs via: `GET /api/phishing/:id/audit-logs`

## API Keys Setup

**See [API_KEYS_GUIDE.md](./API_KEYS_GUIDE.md) for detailed instructions on obtaining and configuring all API keys.**

Quick summary:
- **Phase 1 Intelligence APIs**:
  - VirusTotal API Key (Recommended) - Get from https://www.virustotal.com/gui/join-us
  - URLhaus (No key required) - Free public API
  - Google Safe Browsing API Key (Optional) - Get from Google Cloud Console
- **Phase 2 Enforcement APIs**:
  - Cloudflare API Token + Account ID (Optional) - For automated domain takedown
  - SMTP credentials (Optional) - For email takedown reports
- **Scraping Sources**:
  - Twitter Bearer Token (Optional) - For Twitter phishing reports

## Quick Start

```bash
# 1. Clone the repository
git clone <repo-url>
cd PhishHawk-backend

# 2. Install dependencies
npm install

# 3. Copy and configure environment variables
cp .env.example .env
# Edit .env with your API keys

# 4. Start the server
npm run dev
```

The backend will be available at `http://localhost:5000`

## License

MIT