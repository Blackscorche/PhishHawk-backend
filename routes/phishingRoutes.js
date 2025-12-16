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
  getAuditLogs,
  getUrlhausUrls,
  getVirusTotalUrls,
  markFalsePositive,
  refreshStatus
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

// Health check endpoints for individual APIs
router.get("/health/virustotal", async (req, res) => {
  try {
    const result = await apiValidator.checkVirusTotal('https://google.com');
    res.json({ 
      status: result.error ? 'down' : 'active',
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.json({ status: 'down', timestamp: new Date().toISOString() });
  }
});

router.get("/health/urlhaus", async (req, res) => {
  try {
    const result = await apiValidator.checkUrlhaus('https://google.com');
    res.json({ 
      status: result.error ? 'down' : 'active',
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.json({ status: 'down', timestamp: new Date().toISOString() });
  }
});

router.get("/health/google", async (req, res) => {
  try {
    const result = await apiValidator.checkGoogleSafeBrowsing('https://google.com');
    res.json({ 
      status: result.error ? 'down' : 'active',
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.json({ status: 'down', timestamp: new Date().toISOString() });
  }
});

// Metrics endpoint
router.get("/metrics", getMetrics);

// Fetch URLs from URLhaus
router.get("/urlhaus", getUrlhausUrls);

// Fetch URLs analyzed by VirusTotal from database
router.get("/virustotal", getVirusTotalUrls);

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

// Mark as false positive
router.patch("/:id/false-positive", markFalsePositive);

// Refresh status - recheck if site is down
router.post("/:id/refresh-status", refreshStatus);

// Report to hosting provider with full report data (from dashboard)
router.post("/report-to-provider", async (req, res) => {
  try {
    const { url, reason, additionalInfo, riskScore, riskLevel, validationResults, reportId } = req.body;
    
    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    // Import here to avoid circular dependency
    const { sendTakedownEmail } = await import('../services/sendTakedownEmail.js');
    const { logger } = await import('../utils/logger.js');

    // Normalize URL
    let normalizedUrl = url.trim();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = 'https://' + normalizedUrl;
    }

    // Create report object for email
    const reportForEmail = {
      url: normalizedUrl,
      riskScore: riskScore || 50,
      riskLevel: riskLevel || 'Medium',
      riskChecks: {},
      validationResults: validationResults || {},
      status: 'high_risk',
      createdAt: new Date()
    };

    // Build custom reason with additional info
    let customReason = reason || `Phishing URL detected - Risk Score: ${riskScore || 0}/100`;
    if (additionalInfo) {
      customReason += `\n\nAdditional Information:\n${additionalInfo}`;
    }

    logger.info(`[Report to Provider] Sending report for ${normalizedUrl} to hosting provider...`);
    
    // Check SMTP configuration first
    const smtpConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
    if (!smtpConfigured) {
      logger.warn(`[Report to Provider] SMTP not configured - cannot send emails`);
      logger.warn(`[Report to Provider] SMTP_HOST: ${process.env.SMTP_HOST ? 'Set' : 'Missing'}`);
      logger.warn(`[Report to Provider] SMTP_USER: ${process.env.SMTP_USER ? 'Set' : 'Missing'}`);
      logger.warn(`[Report to Provider] SMTP_PASS: ${process.env.SMTP_PASS ? 'Set' : 'Missing'}`);
    }

    // Send email to hosting providers
    let emailResult;
    try {
      emailResult = await sendTakedownEmail(reportForEmail, customReason);
      logger.info(`[Report to Provider] Email result:`, { 
        sent: emailResult.sent, 
        successful: emailResult.successful,
        totalRecipients: emailResult.totalRecipients,
        failed: emailResult.failed
      });
      
      if (!emailResult.sent) {
        logger.error(`[Report to Provider] Email sending failed:`, emailResult.message || emailResult.error);
      }
    } catch (emailError) {
      logger.error(`[Report to Provider] Exception sending email:`, emailError);
      logger.error(`[Report to Provider] Error stack:`, emailError.stack);
      emailResult = {
        sent: false,
        error: emailError.message || 'Failed to send email',
        message: emailError.message || 'Failed to send email to hosting provider',
        verification: {
          smtpConfigured: smtpConfigured,
          smtpHost: process.env.SMTP_HOST || 'Not configured',
          fromAddress: process.env.SMTP_FROM || process.env.SMTP_USER || 'Not configured',
          errorCode: emailError.code,
          errorMessage: emailError.message
        }
      };
    }

    // Update report status if report exists in DB
    if (emailResult.sent && req.body.reportId) {
      try {
        const PhishingReport = (await import('../models/PhishingReport.js')).default;
        const mongoose = (await import('mongoose')).default;
        
        if (mongoose.connection.readyState === 1) {
          const report = await PhishingReport.findById(req.body.reportId);
          if (report) {
            report.status = 'resolved';
            report.takedownSubmitted = true;
            report.metadata = {
              ...report.metadata,
              reportedToProvider: true,
              reportedAt: new Date().toISOString(),
              takedownTime: new Date().toISOString(), // For latency calculation
              emailResult: emailResult
            };
            await report.save();
            logger.info(`[Report to Provider] Report ${req.body.reportId} marked as resolved`);
          }
        }
      } catch (dbError) {
        logger.warn('Failed to update report status:', dbError.message);
      }
    }

    if (emailResult.sent) {
      const successfulRecipients = emailResult.results
        ?.filter(r => r.sent)
        .map(r => ({
          email: r.recipient,
          messageId: r.messageId,
          response: r.response,
          sentAt: r.sentAt
        })) || [];
      
      const failedRecipients = emailResult.results
        ?.filter(r => !r.sent)
        .map(r => ({
          email: r.recipient,
          error: r.error
        })) || [];

      res.json({
        success: true,
        message: `Report sent successfully to ${emailResult.successful || 0} of ${emailResult.totalRecipients} recipient(s)`,
        recipients: successfulRecipients.map(r => r.email),
        emailResult: {
          totalRecipients: emailResult.totalRecipients,
          successful: emailResult.successful,
          failed: emailResult.failed,
          successfulRecipients: successfulRecipients,
          failedRecipients: failedRecipients,
          abuseContacts: emailResult.abuseContacts,
          verification: emailResult.verification,
          sentAt: emailResult.sentAt
        }
      });
    } else {
      // Email failed to send
      const errorMessage = emailResult.message || emailResult.error || 'Failed to send report to hosting provider';
      const verification = emailResult.verification || {
        smtpConfigured: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
        smtpHost: process.env.SMTP_HOST || 'Not configured',
        fromAddress: process.env.SMTP_FROM || process.env.SMTP_USER || 'Not configured'
      };
      
      logger.error(`[Report to Provider] Failed: ${errorMessage}`);
      
      res.status(500).json({
        success: false,
        message: errorMessage,
        error: emailResult.error || errorMessage,
        emailResult: {
          verification: verification,
          error: emailResult.error
        }
      });
    }

  } catch (error) {
    logger.error('[Report to Provider] Unexpected error:', error);
    logger.error('[Report to Provider] Error stack:', error.stack);
    
    // Check if SMTP is configured
    const smtpConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
    
    res.status(500).json({
      success: false,
      message: 'Failed to send report to hosting provider',
      error: error.message || 'An unexpected error occurred',
      emailResult: {
        verification: {
          smtpConfigured: smtpConfigured,
          smtpHost: process.env.SMTP_HOST || 'Not configured',
          fromAddress: process.env.SMTP_FROM || process.env.SMTP_USER || 'Not configured',
          error: error.message
        }
      }
    });
  }
});

// Manual report to hosting providers (without creating DB record first)
router.post("/report-link", async (req, res) => {
  try {
    const { url, reason } = req.body;
    
    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    // Import here to avoid circular dependency
    const { sendTakedownEmail } = await import('../services/sendTakedownEmail.js');
    const { AutomatedRiskScoringEngine } = await import('../services/automatedRiskScoring.js');
    const riskScoringEngine = new AutomatedRiskScoringEngine();

    // Normalize URL
    let normalizedUrl = url.trim();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = 'https://' + normalizedUrl;
    }

    // Quick analysis
    logger.info(`[Manual Report] Analyzing ${normalizedUrl}...`);
    const scoringResult = await riskScoringEngine.processDomain(normalizedUrl);

    // Create temporary report object for email
    const tempReport = {
      url: normalizedUrl,
      riskScore: scoringResult.riskScore || 50,
      riskLevel: scoringResult.riskLevel || 'Medium',
      riskChecks: scoringResult.checks || {},
      validationResults: {
        virusTotal: scoringResult.intelligence?.virusTotal || null,
        urlhaus: scoringResult.intelligence?.urlhaus || null
      },
      status: 'high_risk',
      createdAt: new Date()
    };

    // Send email to hosting providers
    const emailResult = await sendTakedownEmail(
      tempReport,
      reason || `Manual phishing report - Risk Score: ${scoringResult.riskScore || 50}/100`
    );

    res.json({
      success: true,
      message: 'Report sent to hosting providers',
      data: {
        url: normalizedUrl,
        riskScore: scoringResult.riskScore,
        riskLevel: scoringResult.riskLevel,
        emailResult: emailResult,
        virusTotal: scoringResult.intelligence?.virusTotal,
        urlhaus: scoringResult.intelligence?.urlhaus
      }
    });

  } catch (error) {
    logger.error('Error in manual report:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send report',
      error: error.message
    });
  }
});

export default router;