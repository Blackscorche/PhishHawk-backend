# Flowchart Implementation Summary

This document summarizes the implementation of the two-phase automated phishing domain detection and takedown process as shown in the flowchart.

## ✅ Implementation Complete

The system now follows the exact flowchart process:

### 1. Input: Suspected Phishing Domain
- Endpoint: `POST /api/phishing`
- Accepts: `{ url: "https://suspicious-domain.com" }`

### 2. Phase 1: Intelligence Gathering
**Implemented in**: `services/automatedRiskScoring.js`

- ✅ **VirusTotal API Multi-engine Scan**
  - Checks URL against VirusTotal's database
  - Gets malicious/suspicious detection counts
  - Logs results to audit log

- ✅ **PhishTank API Crowdsourced Check**
  - Checks URL against PhishTank's phishing database
  - Verifies if URL is confirmed phishing
  - Logs results to audit log

Both checks run in parallel for efficiency.

### 3. Automated Risk Scoring Engine
**Implemented in**: `services/automatedRiskScoring.js`

- ✅ Combines intelligence gathering results with URL analysis
- ✅ Calculates risk score (0-100)
- ✅ Determines risk level (Low/Medium/High)
- ✅ Decision point: High-Risk (≥70) vs Low-Risk (<70)

### 4. High-Risk Path (Score ≥ 70)

#### Phase 2: Enforcement - Cloudflare Registrar API
**Implemented in**: `services/cloudflareRegistrar.js`

- ✅ Checks if domain is registered with Cloudflare
- ✅ Locks domain registration (prevents transfers)
- ✅ Pauses DNS zone (stops domain resolution)
- ✅ Logs all actions to audit log

#### Confirmation & Immutable Audit Log
**Implemented in**: `services/auditLogger.js`

- ✅ Creates immutable audit log entry
- ✅ Records takedown confirmation
- ✅ Timestamped and cannot be modified

#### Output: Domain Takedown Initiated
- ✅ Status updated to `takedown_initiated`
- ✅ Report saved with takedown details
- ✅ Response includes full flow information

### 5. Low-Risk Path (Score < 70)

#### Log & Flag for Review
- ✅ Status set to `low_risk` or `medium_risk`
- ✅ Logged to audit system
- ✅ Flagged for manual review
- ✅ No automated takedown action

## New Files Created

1. **`services/cloudflareRegistrar.js`**
   - Cloudflare Registrar API integration
   - Domain takedown functionality
   - Domain locking and DNS pausing

2. **`services/auditLogger.js`**
   - Immutable audit log system
   - Complete audit trail of all actions
   - MongoDB schema with immutability protection

3. **`services/automatedRiskScoring.js`**
   - Phase 1 intelligence gathering orchestration
   - Risk scoring engine combining all data sources
   - Decision logic for high/low risk paths

4. **`API_KEYS_GUIDE.md`**
   - Complete guide for obtaining all API keys
   - Step-by-step instructions
   - Troubleshooting tips

## Modified Files

1. **`controllers/phishingController.js`**
   - Complete rewrite of `submitPhishingReport()` to follow flowchart
   - Updated `reanalyzeReport()` to use new flow
   - Updated `submitTakedown()` to use Cloudflare API
   - Added `getAuditLogs()` endpoint

2. **`routes/phishingRoutes.js`**
   - Added audit logs endpoint: `GET /api/phishing/:id/audit-logs`

3. **`README.md`**
   - Updated with flowchart process description
   - Added API keys section
   - Added audit logging documentation

## API Keys Required

### Phase 1 (Intelligence Gathering)
1. **VirusTotal API Key** - Required
   - Get from: https://www.virustotal.com/gui/join-us
   - Environment variable: `VIRUSTOTAL_API_KEY`

2. **PhishTank API Key** - Required
   - Get from: https://www.phishtank.com/api_register.php
   - Environment variable: `PHISHTANK_API_KEY`

### Phase 2 (Enforcement)
3. **Cloudflare API Key** - Required
   - Get from: https://dash.cloudflare.com/profile/api-tokens
   - Environment variable: `CLOUDFLARE_API_KEY`

4. **Cloudflare Email** - Required
   - Your Cloudflare account email
   - Environment variable: `CLOUDFLARE_EMAIL`

5. **Cloudflare Account ID** - Required
   - Found in Cloudflare dashboard
   - Environment variable: `CLOUDFLARE_ACCOUNT_ID`

**See `API_KEYS_GUIDE.md` for detailed setup instructions.**

## Testing the Flow

1. **Start the server**:
   ```bash
   npm run dev
   ```

2. **Submit a test domain**:
   ```bash
   curl -X POST http://localhost:5000/api/phishing \
     -H "Content-Type: application/json" \
     -d '{"url": "https://test-phishing-site.com"}'
   ```

3. **Check the response** - It will show:
   - Phase 1 completion status
   - Risk score and level
   - Phase 2 execution (if high-risk)
   - Audit log creation

4. **View audit logs**:
   ```bash
   curl http://localhost:5000/api/phishing/{reportId}/audit-logs
   ```

## Flow Diagram

```
Input: Suspected Phishing Domain
    ↓
Phase 1: Intelligence Gathering
    ├─ VirusTotal API Scan
    └─ PhishTank API Check
    ↓
Automated Risk Scoring Engine
    ↓
    ├─ High-Risk (≥70) ──→ Phase 2: Cloudflare Enforcement
    │                          ↓
    │                    Confirmation & Audit Log
    │                          ↓
    │                    Domain Takedown Initiated
    │
    └─ Low-Risk (<70) ──→ Log & Flag for Review
```

## Key Features

✅ **Immutable Audit Logs** - All actions are logged and cannot be modified  
✅ **Parallel Intelligence Gathering** - VirusTotal and PhishTank checks run simultaneously  
✅ **Comprehensive Risk Scoring** - Combines multiple data sources  
✅ **Automated Enforcement** - Cloudflare API integration for domain takedown  
✅ **Complete Flow Tracking** - Every step is logged and traceable  

## Next Steps

1. Add your API keys to `.env` file (see `API_KEYS_GUIDE.md`)
2. Test with a known phishing domain
3. Monitor audit logs to verify the flow
4. Adjust risk thresholds if needed (default: 70 for high-risk)

## Support

If you encounter issues:
1. Check `API_KEYS_GUIDE.md` for API key setup
2. Verify all environment variables are set
3. Check server logs for detailed error messages
4. Review audit logs to see where the process stopped

