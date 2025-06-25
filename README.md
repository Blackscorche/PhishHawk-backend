# PhishHawk 🛡️ — Complete Secure Backend

## 📦 Features
- Public phishing URL reporting
- Rule-based risk scoring
- VirusTotal lookup
- Email takedown reporting via Nodemailer
- MongoDB database
- Express-validator & Rate-limiter security

## 🚀 Setup
```bash
npm install
cp .env.example .env
npm run dev
```

## 📬 API
- POST `/api/phishing` — submit a suspicious link
- GET `/api/phishing` — view all reports
