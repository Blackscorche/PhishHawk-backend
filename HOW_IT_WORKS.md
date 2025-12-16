# PhishHawk: How URL Fetching & Takedown Reporting Works

## 🔍 **PART 1: How URLs Are Fetched**

### **Step 1: User Clicks "Start Collection"**
When you click "Start Collection" in the dashboard:
- Frontend calls: `POST /api/collector/start`
- Backend receives request with sources: `['urlhaus', 'rss']` (default)

### **Step 2: Immediate Scraping**
The backend immediately scrapes URLs (doesn't wait for interval):

```javascript
// routes/scrapingRoutes.js - Line 87-101
for (const source of sources) {
  const urls = await urlScraper.scrapeSource(source);
  // Process each URL...
}
```

### **Step 3: URLhaus Scraping Process**

**Method 1: CSV Recent Feed (Primary)**
```
1. HTTP GET: https://urlhaus.abuse.ch/downloads/csv_recent/
2. Parse CSV format: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
3. Extract URLs from column 2 (index 2)
4. Filter: Only URLs starting with http:// or https://
5. Limit: First 100 URLs
```

**Method 2: Text Online Feed (Fallback)**
```
1. HTTP GET: https://urlhaus.abuse.ch/downloads/text_online/
2. Parse plain text (one URL per line)
3. Filter: Only URLs starting with http:// or https://
```

**Method 3: JSON API (If Available)**
```
1. POST: https://urlhaus.abuse.ch/api/v1/downloads/recent/
2. Parse JSON response
3. Extract URLs from response array
```

### **Step 4: VirusTotal + URLhaus Analysis**
For each scraped URL:
```javascript
// routes/scrapingRoutes.js - Line 35
const scoringResult = await riskScoringEngine.processDomain(urlData.url);
```

This runs:
1. **VirusTotal API Check**: Scans URL with 70+ antivirus engines
2. **URLhaus API Check**: Verifies if URL is in URLhaus database
3. **Risk Scoring**: Calculates risk score (0-100) based on:
   - VirusTotal malicious count
   - URLhaus confirmation
   - Suspicious patterns (TLD, keywords, subdomains, etc.)

### **Step 5: Save to Database**
```javascript
// routes/scrapingRoutes.js - Line 38-56
const report = new PhishingReport({
  url: urlData.url,
  source: 'urlhaus',
  riskScore: scoringResult.riskScore,
  validationResults: {
    virusTotal: scoringResult.intelligence?.virusTotal,
    urlhaus: scoringResult.intelligence?.urlhaus
  }
});
await report.save();
```

### **Step 6: Interval Scraping**
After immediate scrape, sets up interval (default: 5 minutes):
```javascript
// Every 5 minutes, automatically scrape again
urlScraper.startScraping(sources, interval, callback);
```

---

## 📧 **PART 2: How Abuse Emails Are Sent**

### **Current Implementation (LIMITED)**

**When Takedown is Requested:**
1. User clicks "Initiate Takedown" on a report
2. Backend calls: `POST /api/phishing/:id/takedown`
3. Email is sent via SMTP

**Current Email Recipient:**
```javascript
// services/sendTakedownEmail.js - Line 25
to: process.env.EMAIL_TO || "report@apwg.org"
```

**⚠️ PROBLEM**: Currently only sends to ONE email address:
- Either `EMAIL_TO` from `.env` file
- Or default: `report@apwg.org` (APWG - Anti-Phishing Working Group)

**❌ NOT SENT TO:**
- Hosting provider abuse email
- Domain registrar abuse email
- Cloudflare abuse email (if using Cloudflare)
- Multiple recipients

---

## 🚀 **IMPROVEMENT NEEDED: Multi-Recipient Abuse Emails**

To properly report phishing sites, we need to:

1. **Extract Domain from URL**
   - Example: `https://phishing.example.com/login` → `example.com`

2. **WHOIS Lookup** (to find registrar)
   - Query domain registrar information
   - Extract registrar abuse email
   - Example: `abuse@registrar.com`

3. **Hosting Provider Detection** (to find hosting provider)
   - Check IP address of domain
   - Lookup IP in hosting provider database
   - Extract hosting provider abuse email
   - Example: `abuse@hosting-provider.com`

4. **Cloudflare Detection** (if using Cloudflare)
   - Check if domain uses Cloudflare nameservers
   - Send to: `abuse@cloudflare.com`

5. **Send to Multiple Recipients**
   - Hosting provider abuse email
   - Domain registrar abuse email
   - Cloudflare abuse email (if applicable)
   - APWG (report@apwg.org) - for tracking

---

## 📋 **Current Email Content**

The email includes:
- ✅ Malicious URL
- ✅ Risk Score (0-100)
- ✅ VirusTotal results (X/Y engines flagged)
- ✅ URLhaus confirmation status
- ✅ Risk factors detected
- ✅ Detection timestamp

**Email Format**: HTML + Plain Text

---

## 🔧 **What Needs to Be Fixed**

1. **Add WHOIS Lookup Service**
   - Use `whois` npm package or API
   - Extract registrar information
   - Find registrar abuse email

2. **Add IP/Hosting Provider Lookup**
   - Resolve domain to IP address
   - Use IP geolocation/hosting databases
   - Find hosting provider abuse email

3. **Update `sendTakedownEmail()` Function**
   - Accept multiple recipients
   - Send separate emails to each provider
   - Track which emails were sent successfully

4. **Add Provider Email Database**
   - Common hosting providers: abuse@[provider].com
   - Common registrars: abuse@[registrar].com
   - Cloudflare: abuse@cloudflare.com

---

## 📊 **Current Flow Diagram**

```
[User Clicks "Start Collection"]
         ↓
[Scrape URLhaus CSV Feed]
         ↓
[Extract URLs from CSV]
         ↓
[For Each URL:]
    ├─→ [VirusTotal Scan]
    ├─→ [URLhaus Check]
    └─→ [Calculate Risk Score]
         ↓
[Save to MongoDB]
         ↓
[Display on Dashboard]

[User Clicks "Initiate Takedown"]
         ↓
[Gather Full Intelligence]
         ↓
[Send Email to EMAIL_TO or report@apwg.org]  ← CURRENT LIMITATION
         ↓
[Cloudflare API (if configured)]
         ↓
[Update Report Status]
```

---

## ✅ **Recommended Improvements**

1. **Multi-Recipient Email System**
   - Send to hosting provider
   - Send to registrar
   - Send to Cloudflare (if applicable)
   - Send to APWG (for tracking)

2. **WHOIS Integration**
   - Lookup domain registrar
   - Extract abuse contact

3. **IP/Hosting Detection**
   - Resolve domain to IP
   - Identify hosting provider
   - Find abuse email

4. **Email Tracking**
   - Log which emails were sent
   - Track delivery status
   - Store in audit log

