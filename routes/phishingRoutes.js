import express from "express";
import { phishingValidationRules, validatePhishingRequest } from "../middleware/validateRequest.js";
import { phishingRateLimiter } from "../middleware/rateLimiter.js";
import { 
  submitPhishingReport, 
  getAllReports,
  getReportById,
  reanalyzeReport,
  submitTakedown,
  getMetrics,
  getAuditLogs
} from "../controllers/phishingController.js";
import { APIValidator } from "../services/apiValidator.js";

const router = express.Router();
const apiValidator = new APIValidator();

// API Status endpoint - check which APIs are working
router.get("/api-status", async (req, res) => {
  const status = {
    virusTotal: {
      configured: !!process.env.VIRUSTOTAL_API_KEY,
      status: 'unknown'
    },
    urlhaus: {
      configured: true, // URLhaus doesn't require API key
      status: 'unknown'
    },
    googleSafeBrowsing: {
      configured: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY,
      status: 'unknown'
    },
    cloudflare: {
      configured: !!(process.env.CLOUDFLARE_API_TOKEN || process.env.CLOUDFLARE_API_KEY) && !!process.env.CLOUDFLARE_ACCOUNT_ID,
      status: 'unknown'
    },
    smtp: {
      configured: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
      status: 'unknown'
    }
  };

  // Quick test of APIs (optional - can be slow)
  if (req.query.test === 'true') {
    // Test VirusTotal
    if (status.virusTotal.configured) {
      try {
        const vtResult = await apiValidator.checkVirusTotal('https://google.com');
        status.virusTotal.status = vtResult.error ? 'error' : 'active';
      } catch (e) {
        status.virusTotal.status = 'error';
      }
    } else {
      status.virusTotal.status = 'not_configured';
    }

    // Test URLhaus
    try {
      const uhResult = await apiValidator.checkUrlhaus('https://google.com');
      status.urlhaus.status = uhResult.error ? 'error' : 'active';
    } catch (e) {
      status.urlhaus.status = 'error';
    }

    // Test Google Safe Browsing
    if (status.googleSafeBrowsing.configured) {
      try {
        const gsbResult = await apiValidator.checkGoogleSafeBrowsing('https://google.com');
        status.googleSafeBrowsing.status = gsbResult.error ? 'error' : 'active';
      } catch (e) {
        status.googleSafeBrowsing.status = 'error';
      }
    } else {
      status.googleSafeBrowsing.status = 'not_configured';
    }
  } else {
    // Just report configuration status without testing
    status.virusTotal.status = status.virusTotal.configured ? 'configured' : 'not_configured';
    status.urlhaus.status = 'configured';
    status.googleSafeBrowsing.status = status.googleSafeBrowsing.configured ? 'configured' : 'not_configured';
    status.cloudflare.status = status.cloudflare.configured ? 'configured' : 'not_configured';
    status.smtp.status = status.smtp.configured ? 'configured' : 'not_configured';
  }

  res.json({
    success: true,
    data: status,
    timestamp: new Date().toISOString()
  });
});

// Metrics endpoint
router.get("/metrics", getMetrics);

// Get audit logs for a report
router.get("/:id/audit-logs", getAuditLogs);

// Get all reports with pagination and filters
router.get("/", getAllReports);

// Get specific report
router.get("/:id", getReportById);

// Submit new phishing report
router.post("/", phishingRateLimiter, phishingValidationRules, validatePhishingRequest, submitPhishingReport);

// Re-analyze report
router.post("/:id/reanalyze", reanalyzeReport);

// Submit takedown request
router.post("/:id/takedown", submitTakedown);

export default router;