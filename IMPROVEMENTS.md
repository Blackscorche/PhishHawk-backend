# PhishHawk Improvements - Latest Updates

## ✅ **1. Fixed Latency Display**

**Problem**: Latency wasn't showing in metrics

**Solution**:
- Fixed `takedownTime` being set when takedown is initiated
- Latency now calculated as: `timeTakenDown - timeDetected`
- Displayed in **minutes** (e.g., "45.2m")
- Shows "N/A" if no resolved reports exist

**Code Changes**:
- `controllers/phishingController.js`: Sets `metadata.takedownTime` when takedown is submitted
- Latency calculation: `avgLatency` in minutes (rounded to 1 decimal)

---

## ✅ **2. Fetch ALL Phishing Links from Multiple Sources**

**Problem**: Only scraping from URLhaus

**Solution**: Added support for multiple phishing feed sources:

### **New Sources Added**:

1. **OpenPhish** (`openphish`)
   - Feed: `https://openphish.com/feed.txt`
   - Plain text feed, one URL per line
   - High priority phishing URLs

2. **PhishTank** (`phishtank`)
   - Feed: `https://www.phishtank.com/rss.php`
   - RSS feed with verified phishing URLs
   - Includes phish ID and verification status

3. **RSS Feeds** (`rss`)
   - Security news feeds (Krebs, ThreatPost)
   - Extracts phishing URLs from articles

4. **All Sources** (`all`)
   - Scrapes from: URLhaus + OpenPhish + PhishTank + RSS
   - Removes duplicates automatically
   - Returns combined unique URLs

### **How to Use**:

**Backend API**:
```javascript
// Start collection with all sources
POST /api/collector/start
{
  "sources": ["all"],  // or ["urlhaus", "openphish", "phishtank", "rss"]
  "interval": 300000
}

// Manual scrape from specific source
POST /api/scraping/scrape-now
{
  "source": "all"  // or "urlhaus", "openphish", "phishtank", "rss"
}
```

**Frontend**:
- "Start Collection" button now supports multiple sources
- Can specify `sources: ['all']` to fetch from all sources

---

## ✅ **3. Report Links to Hosting Providers**

**Problem**: No way to manually report a link to hosting providers

**Solution**: Added manual report endpoint that:
1. Analyzes URL with VirusTotal + URLhaus
2. Finds hosting provider abuse emails automatically
3. Sends email to:
   - Hosting provider abuse email
   - Domain registrar abuse email
   - Cloudflare abuse email (if applicable)
   - APWG tracking email

### **New Endpoint**:

```javascript
POST /api/phishing/report-link
{
  "url": "https://phishing-site.com",
  "reason": "Optional custom reason"
}
```

**Response**:
```json
{
  "success": true,
  "message": "Report sent to hosting providers",
  "data": {
    "url": "https://phishing-site.com",
    "riskScore": 85,
    "riskLevel": "High",
    "emailResult": {
      "sent": true,
      "totalRecipients": 3,
      "successful": 3,
      "failed": 0,
      "abuseContacts": {
        "hostingProvider": "abuse@amazonaws.com",
        "cloudflare": "abuse@cloudflare.com"
      }
    },
    "virusTotal": { "malicious": 12, "total": 70 },
    "urlhaus": { "isPhish": true }
  }
}
```

### **Frontend Usage**:

```javascript
import api from '../services/api';

// Report a link
await api.reportLink('https://phishing-site.com', 'Custom reason');
```

---

## 📊 **How It Works**

### **URL Fetching Flow**:

```
[User Clicks "Start Collection"]
         ↓
[Scrape from ALL sources:]
    ├─→ URLhaus (CSV feed)
    ├─→ OpenPhish (Text feed)
    ├─→ PhishTank (RSS feed)
    └─→ RSS Feeds (Security news)
         ↓
[Remove Duplicates]
         ↓
[For Each URL:]
    ├─→ VirusTotal Scan
    ├─→ URLhaus Check
    └─→ Calculate Risk Score
         ↓
[Save to MongoDB]
         ↓
[Display on Dashboard]
```

### **Manual Report Flow**:

```
[User Reports Link]
         ↓
[Analyze URL]
    ├─→ VirusTotal Scan
    ├─→ URLhaus Check
    └─→ Calculate Risk Score
         ↓
[Find Abuse Contacts]
    ├─→ Resolve Domain → IP
    ├─→ Reverse DNS → Hosting Provider
    ├─→ Check Nameservers → Cloudflare
    └─→ Find Abuse Emails
         ↓
[Send Emails to:]
    ├─→ Hosting Provider Abuse
    ├─→ Registrar Abuse
    ├─→ Cloudflare Abuse
    └─→ APWG Tracking
         ↓
[Return Results]
```

---

## 🔧 **Configuration**

### **Environment Variables**:

```env
# Existing
VIRUSTOTAL_API_KEY=your_key
SMTP_HOST=smtp.gmail.com
SMTP_USER=your_email
SMTP_PASS=your_password
EMAIL_TO=your_monitoring_email@example.com

# Optional (for PhishTank API)
PHISHTANK_API_KEY=your_key  # Optional - RSS feed works without it
```

---

## 📈 **Metrics Display**

**Latency Calculation**:
- Only calculated for reports with status: `resolved`, `takedown_initiated`, `takedown_sent`
- Formula: `avg(timeTakenDown - timeDetected)`
- Display: Minutes (e.g., "45.2m")
- Shows "N/A" if no resolved reports

**Other Metrics**:
- **Total Reports**: All scanned URLs
- **High Risk**: `riskScore >= 80 AND status = high_risk/pending`
- **Resolved**: `status = resolved/takedown_initiated/takedown_sent`
- **Pending**: `status = pending/high_risk/medium_risk/low_risk AND takedownSubmitted = false`

---

## 🚀 **Next Steps**

1. **Test Multi-Source Scraping**:
   ```bash
   # Start collection with all sources
   curl -X POST http://localhost:5000/api/collector/start \
     -H "Content-Type: application/json" \
     -d '{"sources": ["all"], "interval": 300000}'
   ```

2. **Test Manual Report**:
   ```bash
   curl -X POST http://localhost:5000/api/phishing/report-link \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example-phishing-site.com", "reason": "Test report"}'
   ```

3. **Check Latency**:
   - Initiate takedown on a report
   - Check metrics - latency should now display
   - Latency updates when report status changes to `takedown_initiated` or `takedown_sent`

---

## 📝 **Files Modified**

1. `services/urlScraper.js` - Added OpenPhish, PhishTank scrapers, "all" source support
2. `controllers/phishingController.js` - Fixed latency calculation, added takedownTime
3. `routes/phishingRoutes.js` - Added `/report-link` endpoint
4. `routes/scrapingRoutes.js` - Support for "all" sources
5. `services/sendTakedownEmail.js` - Multi-recipient email sending
6. `services/providerEmailFinder.js` - Find hosting provider abuse emails
7. `src/services/api.js` - Added `reportLink()` method

---

## ✅ **Summary**

- ✅ **Latency Fixed**: Now displays correctly in minutes
- ✅ **Multi-Source Scraping**: Fetch from URLhaus, OpenPhish, PhishTank, RSS
- ✅ **Manual Reporting**: Report links directly to hosting providers
- ✅ **Auto Provider Detection**: Automatically finds and emails hosting provider abuse contacts
- ✅ **Better Email Coverage**: Sends to hosting provider, registrar, Cloudflare, and APWG


