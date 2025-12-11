# API Keys Guide - PhishHawk Backend

This guide explains which API keys you need to paste into your `.env` file for the flowchart process to work.

## Required API Keys for Flowchart Process

The system follows a two-phase automated process that requires specific API keys:

### Phase 1: Intelligence Gathering

#### 1. VirusTotal API Key (REQUIRED)
**Purpose**: Multi-engine malware/phishing scan  
**Where to get it**: https://www.virustotal.com/gui/join-us

1. Sign up for a free account at VirusTotal
2. Go to your profile settings
3. Copy your API key
4. Paste it in `.env`:
   ```
   VIRUSTOTAL_API_KEY=paste_your_key_here
   ```

**Note**: Free tier has rate limits (4 requests/minute). For production, consider a paid plan.

---

#### 2. PhishTank API Key (REQUIRED)
**Purpose**: Crowdsourced phishing database check  
**Where to get it**: https://www.phishtank.com/api_register.php

1. Sign up for a free PhishTank account
2. Go to API registration page
3. Register your application
4. Copy your API key
5. Paste it in `.env`:
   ```
   PHISHTANK_API_KEY=paste_your_key_here
   ```

**Note**: Free tier allows 10,000 requests/day. No API key needed for read-only access, but recommended for better rate limits.

---

### Phase 2: Enforcement (Cloudflare Registrar API)

#### 3. Cloudflare API Credentials (REQUIRED for automated takedown)
**Purpose**: Domain takedown via Cloudflare Registrar API  
**Where to get it**: https://dash.cloudflare.com/profile/api-tokens

**You have TWO options:**

##### Option A: API Token (Recommended - More Secure) ⭐

1. Go to: https://dash.cloudflare.com/profile/api-tokens
2. Click **"Create Token"**
3. Configure permissions:
   - **Zone → DNS → Edit** (Required)
   - **Zone → Zone → Read** (Recommended)
   - **Account → Registrar → Edit** (If available)
4. Set Zone Resources: **All zones** (or specific zones)
5. Click **"Create Token"** and copy it immediately
6. Paste it in `.env`:
   ```
   CLOUDFLARE_API_TOKEN=paste_your_token_here
   CLOUDFLARE_ACCOUNT_ID=paste_your_account_id_here
   ```

**See [CLOUDFLARE_TOKEN_SETUP.md](./CLOUDFLARE_TOKEN_SETUP.md) for detailed step-by-step instructions with screenshots.**

##### Option B: Global API Key (Legacy - Still Works)

You need **THREE** values from Cloudflare:

1. **Cloudflare API Key**:
   - Go to: **My Profile** → **API Tokens** → **Global API Key**
   - Click "View" and enter your password
   - Copy the API key

2. **Cloudflare Email**:
   - Your Cloudflare login email

3. **Cloudflare Account ID**:
   - Select any domain in Cloudflare dashboard
   - Find "Account ID" in the right sidebar under "API"
   - Copy the Account ID

Paste all three in `.env`:
   ```
   CLOUDFLARE_API_KEY=paste_your_global_api_key_here
   CLOUDFLARE_EMAIL=your_email@example.com
   CLOUDFLARE_ACCOUNT_ID=paste_your_account_id_here
   ```

**Important Notes**:
- **API Token is recommended** (more secure, can be restricted)
- The domain must be registered/managed through Cloudflare for takedown to work
- You need appropriate permissions on the Cloudflare account
- The API will attempt to lock the domain and pause DNS resolution

---

## Optional API Keys

### SMTP Configuration (Optional - for email notifications)
If you want to send email notifications (not required for the flowchart process):

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password_here
SMTP_FROM="PhishHawk <your_email@gmail.com>"
EMAIL_TO=report@apwg.org
```

### Twitter Bearer Token (Optional - for URL scraping)
Only needed if you want to scrape URLs from Twitter:

```
TWITTER_BEARER_TOKEN=your_twitter_bearer_token_here
```

---

## Complete .env File Template

Copy this template and fill in your API keys:

```env
# Server Configuration
PORT=5000
NODE_ENV=development
FRONTEND_URL=http://localhost:5173

# MongoDB Configuration
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/phishhawk?retryWrites=true&w=majority

# ============================================
# PHASE 1: INTELLIGENCE GATHERING APIs
# ============================================

# VirusTotal API (REQUIRED)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# PhishTank API (REQUIRED)
PHISHTANK_API_KEY=your_phishtank_api_key_here

# ============================================
# PHASE 2: ENFORCEMENT APIs
# ============================================

# Cloudflare Registrar API (REQUIRED for Phase 2)
# Option A: API Token (Recommended - more secure)
# Get your token from: https://dash.cloudflare.com/profile/api-tokens
# See CLOUDFLARE_TOKEN_SETUP.md for detailed setup instructions
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token_here
CLOUDFLARE_ACCOUNT_ID=your_cloudflare_account_id_here

# Option B: Global API Key (Legacy - still works)
# CLOUDFLARE_API_KEY=your_cloudflare_api_key_here
# CLOUDFLARE_EMAIL=your_cloudflare_email@example.com
# CLOUDFLARE_ACCOUNT_ID=your_cloudflare_account_id_here

# ============================================
# OPTIONAL APIs
# ============================================

# SMTP Configuration (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password_here
SMTP_FROM="PhishHawk <your_email@gmail.com>"
EMAIL_TO=report@apwg.org

# Twitter API (Optional - for URL scraping)
TWITTER_BEARER_TOKEN=your_twitter_bearer_token_here
```

---

## Testing Your API Keys

After adding your API keys, test the system:

1. Start the server:
   ```bash
   npm run dev
   ```

2. Submit a test phishing report:
   ```bash
   curl -X POST http://localhost:5000/api/phishing \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example-suspicious-site.com"}'
   ```

3. Check the logs to see if:
   - Phase 1 (VirusTotal & PhishTank) completes successfully
   - Risk scoring works correctly
   - Phase 2 (Cloudflare) executes if risk score is high

---

## Troubleshooting

### VirusTotal API Issues
- **Error**: "VirusTotal API key not configured"
  - **Solution**: Make sure `VIRUSTOTAL_API_KEY` is set in `.env`
- **Error**: Rate limit exceeded
  - **Solution**: Wait 15 seconds between requests (free tier limit)

### PhishTank API Issues
- **Error**: "PhishTank API key not configured"
  - **Solution**: Make sure `PHISHTANK_API_KEY` is set in `.env`
- **Note**: PhishTank can work without an API key, but with stricter rate limits

### Cloudflare API Issues
- **Error**: "Cloudflare API authentication failed"
  - **Solution**: Verify all three values (API_KEY, EMAIL, ACCOUNT_ID) are correct
- **Error**: "Domain not found in Cloudflare account"
  - **Solution**: The domain must be registered/managed through Cloudflare
- **Error**: "Cloudflare API not configured"
  - **Solution**: Add all three Cloudflare credentials to `.env`

---

## Security Best Practices

1. **Never commit `.env` file to Git** - It's already in `.gitignore`
2. **Use environment-specific keys** - Different keys for dev/staging/production
3. **Rotate API keys regularly** - Especially if exposed
4. **Use API key restrictions** - When possible, restrict API keys to specific IPs/domains
5. **Monitor API usage** - Check for unexpected usage patterns

---

## Flowchart Process Summary

With all API keys configured, the system will:

1. ✅ **Phase 1**: Gather intelligence from VirusTotal & PhishTank
2. ✅ **Risk Scoring**: Calculate risk score (0-100)
3. ✅ **High-Risk (≥70)**: Execute Phase 2 Cloudflare takedown → Audit log → Takedown initiated
4. ✅ **Low-Risk (<70)**: Log & flag for review

All actions are logged in the immutable audit log system.

