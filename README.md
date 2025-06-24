# PhishHawk 🛡️ — Phishing Takedown Automation System

**PhishHawk** is a phishing detection and takedown backend system built by a cybersecurity-focused engineer using Node.js, Express, MongoDB, and Nodemailer. It is designed to automate the collection, scoring, and takedown reporting of malicious phishing URLs — making it faster and easier to stop phishing attacks before they do harm.

---

## 🚀 Features

- 🔍 Accepts user-submitted phishing URLs
- ⚖️ Scores URLs based on:
  - Domain age
  - SSL presence
  - Phishing keyword matches
  - VirusTotal flag
- 📩 Sends takedown requests for high-risk URLs via email
- 💾 Stores all phishing reports in MongoDB
- 📊 REST API supports connection with frontend dashboard
- 🔐 Clean, modular, and ready for enterprise upgrades

---

## 🧱 Tech Stack

- **Backend:** Node.js + Express.js
- **Database:** MongoDB + Mongoose
- **Mailer:** Nodemailer + SMTP
- **Security:** dotenv config, CORS, input validation ready

---

## 📁 Project Structure

```
phishhawk-backend/
├── server.js               # Main application entry
├── config/                 # MongoDB and environment config
├── controllers/            # Handles core logic for reporting
├── models/PhishingReport   # Mongoose schema
├── routes/                 # Express route definitions
├── utils/                  # Scoring logic and mail helpers
├── .env.example            # Sample environment variables
└── README.md               # You are here
```

---

## 📬 API Endpoints

| Method | Endpoint            | Description                |
|--------|---------------------|----------------------------|
| POST   | `/api/phishing`     | Submit phishing report     |
| GET    | `/api/phishing`     | Retrieve all reports       |

---

## 🧪 Sample POST Request

```bash
POST /api/phishing
Content-Type: application/json

{
  "url": "http://scam-site.com",
  "domainAge": 1,
  "hasSSL": false,
  "containsPhishingKeywords": true,
  "virusTotalHit": true
}
```

---

## ⚙️ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/phishhawk-backend.git
cd phishhawk-backend
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment
Rename `.env.example` to `.env` and fill in:
```
MONGO_URI=your-mongodb-uri
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=yourpassword
```

### 4. Run the Server
```bash
npm run dev
```

---

## 🔐 Production Tips

- Use a hosted MongoDB (like Atlas)
- Use a transactional email provider (like Mailgun or Brevo)
- Protect endpoints with JWT auth (optional)
- Add rate limiting middleware (`express-rate-limit`)

---



This Project Was Built with one goal: **shut phishing down.**
