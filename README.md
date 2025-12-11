# PhishHawk Backend

Phishing Takedown Automation System - Backend API

## Features

- ✅ **Two-Phase Automated Process** following flowchart design:
  - **Phase 1: Intelligence Gathering** - VirusTotal & PhishTank API integration
  - **Automated Risk Scoring Engine** - Combines intelligence with URL analysis
  - **Phase 2: Enforcement** - Cloudflare Registrar API for domain takedown
  - **Immutable Audit Logging** - Complete audit trail of all actions
- ✅ Automated URL risk analysis with rule-based scoring
- ✅ VirusTotal and PhishTank API integration
- ✅ Cloudflare Registrar API for automated domain takedown
- ✅ Immutable audit log system
- ✅ URL scraping from RSS feeds and PhishTank
- ✅ MongoDB database for storing reports
- ✅ RESTful API with pagination and filtering
- ✅ Comprehensive logging system

## Flowchart Process

The system follows a strict two-phase automated process:

1. **Input**: Suspected Phishing Domain
2. **Phase 1: Intelligence Gathering**
   - VirusTotal API Multi-engine Scan
   - PhishTank API Crowdsourced Check
3. **Automated Risk Scoring Engine**
   - Combines intelligence results with URL analysis
   - Calculates final risk score (0-100)
4. **Decision Branch**:
   - **High-Risk Score (≥70)**: 
     - Phase 2: Cloudflare Registrar API Enforcement
     - Confirmation & Immutable Audit Log
     - Output: Domain Takedown Initiated
   - **Low-Risk Score (<70)**:
     - Log & Flag for Review

## Setup

### Prerequisites

- Node.js 18+ 
- MongoDB (local or cloud instance)
- API keys (see below for required vs optional):
  - **VirusTotal API key** (Required for Phase 1)
  - **PhishTank API key** (Required for Phase 1)
  - **Cloudflare API credentials** (Required for Phase 2 enforcement)
  - Twitter Bearer Token (Optional - for Twitter scraping)
  - SMTP credentials (Optional - for email notifications)

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

### URL Scraping

- `POST /api/scraping/start` - Start automated URL scraping
- `POST /api/scraping/stop` - Stop automated URL scraping

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

**See [API_KEYS_GUIDE.md](./API_KEYS_GUIDE.md) for detailed instructions on obtaining and configuring all required API keys.**

Quick summary:
- **Phase 1 (Required)**: VirusTotal API Key, PhishTank API Key
- **Phase 2 (Required)**: Cloudflare API Key, Email, Account ID
- **Optional**: SMTP credentials, Twitter Bearer Token

## License

MIT