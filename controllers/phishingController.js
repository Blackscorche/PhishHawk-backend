import mongoose from "mongoose";
import PhishingReport from "../models/PhishingReport.js";
import { AutomatedRiskScoringEngine } from "../services/automatedRiskScoring.js";
import { CloudflareRegistrarService } from "../services/cloudflareRegistrar.js";
import { AuditLogger } from "../services/auditLogger.js";
import { sendTakedownEmail } from "../services/sendTakedownEmail.js";
import { URLScraper } from "../services/urlScraper.js";
import { logger } from "../utils/logger.js";

const riskScoringEngine = new AutomatedRiskScoringEngine();
const cloudflareService = new CloudflareRegistrarService();

/**
 * Submit Phishing Report - Follows the exact flowchart:
 * 1. Input: Suspected Phishing Domain
 * 2. Phase 1: Intelligence Gathering (VirusTotal + URLhaus)
 * 3. Automated Risk Scoring Engine
 * 4. High-Risk: Phase 2: Cloudflare Enforcement → Audit Log → Takedown Initiated
 * 5. Low-Risk: Log & Flag for Review
 */
export const submitPhishingReport = async (req, res) => {
  let report = null;
  let dbAvailable = mongoose.connection.readyState === 1;

  try {
    const { url, source = 'manual', priority = 'medium' } = req.body;

    // Normalize URL - add protocol if missing
    let normalizedUrl = url.trim();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = 'https://' + normalizedUrl;
    }

    // Validate URL format
    let domain;
    try {
      const urlObj = new URL(normalizedUrl);
      domain = urlObj.hostname.replace(/^www\./, '');
    } catch (error) {
      return res.status(400).json({
        success: false,
        error: 'Invalid URL format',
        message: 'Please provide a valid URL (e.g., https://example.com or example.com)'
      });
    }

    // Use normalized URL for processing
    const urlToProcess = normalizedUrl;

    // Check if URL already exists (only if DB is available)
    if (dbAvailable) {
      try {
        const existing = await PhishingReport.findOne({ url: urlToProcess });
        if (existing) {
          return res.json({
            success: true,
            data: existing,
            message: 'URL already in system',
            fromCache: true
          });
        }
      } catch (dbError) {
        logger.warn('Database query failed, continuing without DB:', dbError.message);
      }
    }

    // ============================================
    // PHASE 1: INTELLIGENCE GATHERING
    // ============================================
    logger.info(`[FLOWCHART] Phase 1: Intelligence Gathering for ${urlToProcess}`);

    // Create initial report (only if DB available)
    if (dbAvailable) {
      try {
        report = new PhishingReport({
          url: urlToProcess,
          source,
          priority,
          riskScore: 0,
          riskLevel: 'Low',
          status: 'pending',
          takedownSubmitted: false
        });
        await report.save();
        await AuditLogger.logIntelligenceGatheringStart(report._id, domain);
      } catch (dbError) {
        logger.warn('Failed to save initial report, continuing scan:', dbError.message);
        dbAvailable = false;
      }
    }

    // Gather intelligence (VirusTotal + URLhaus) - This works without DB
    logger.info(`[SCAN] Starting URL analysis for: ${urlToProcess}`);
    const intelligence = await riskScoringEngine.gatherIntelligence(urlToProcess);
    logger.info(`[SCAN] Intelligence gathering completed`);

    // Log results (only if DB available and report exists)
    if (dbAvailable && report) {
      try {
        if (intelligence.virusTotal) {
          await AuditLogger.logVirusTotalScan(report._id, domain, intelligence.virusTotal);
        }
        if (intelligence.urlhaus) {
          await AuditLogger.logUrlhausCheck(report._id, domain, intelligence.urlhaus);
        }
      } catch (dbError) {
        logger.warn('Failed to log intelligence results:', dbError.message);
      }
    }

    // ============================================
    // AUTOMATED RISK SCORING ENGINE
    // ============================================
    logger.info(`[FLOWCHART] Automated Risk Scoring Engine for ${urlToProcess}`);

    const scoringResult = await riskScoringEngine.calculateRiskScore(urlToProcess, intelligence);
    logger.info(`[SCAN] Risk score calculated: ${scoringResult.score}% (${scoringResult.riskLevel})`);

    // Log risk score (only if DB available)
    if (dbAvailable && report) {
      try {
        await AuditLogger.logRiskScore(
          report._id,
          domain,
          scoringResult.score,
          scoringResult.riskLevel,
          scoringResult.checks
        );
      } catch (dbError) {
        logger.warn('Failed to log risk score:', dbError.message);
      }
    }

    // Prepare response data
    const responseData = {
      url: urlToProcess,
      source,
      priority,
      riskScore: scoringResult.score,
      riskLevel: scoringResult.riskLevel,
      riskChecks: scoringResult.checks,
      validationResults: {
        virusTotal: intelligence.virusTotal,
        urlhaus: intelligence.urlhaus
      },
      status: scoringResult.score >= 70 ? 'high_risk' :
        scoringResult.score >= 40 ? 'medium_risk' : 'low_risk',
      scannedAt: new Date(),
      dbSaved: false
    };

    // Update report with scoring results (only if DB available)
    if (dbAvailable && report) {
      try {
        report.riskScore = scoringResult.score;
        report.riskLevel = scoringResult.riskLevel;
        report.riskChecks = scoringResult.checks;
        report.validationResults = {
          virusTotal: intelligence.virusTotal,
          urlhaus: intelligence.urlhaus
        };
        report.status = responseData.status;
        await report.save();
        responseData._id = report._id;
        responseData.dbSaved = true;
        logger.info(`[SCAN] Report saved to database: ${report._id}`);
      } catch (dbError) {
        logger.error('Failed to save report results:', dbError.message);
        responseData.dbError = 'Results calculated but not saved to database';
      }
    } else {
      logger.warn('[SCAN] Database not available - scan completed but not saved');
      responseData.dbWarning = 'Database unavailable - results not saved';
    }

    // ============================================
    // DECISION: High-Risk vs Low-Risk
    // ============================================
    const isHighRisk = scoringResult.score >= 70;

    if (isHighRisk) {
      // ============================================
      // HIGH-RISK PATH: Phase 2 - Enforcement
      // ============================================
      logger.info(`[FLOWCHART] High-Risk Score (${scoringResult.score}) - Initiating Phase 2: Enforcement`);

      if (dbAvailable && report) {
        try {
          report.status = 'high_risk';
          await report.save();
        } catch (dbError) {
          logger.warn('Failed to update report status:', dbError.message);
        }
      }

      let takedownResult = null;
      let takedownSuccess = false;

      // Phase 2: Cloudflare Registrar API Enforcement
      if (cloudflareService.isConfigured()) {
        try {
          logger.info(`[FLOWCHART] Phase 2: Cloudflare Registrar API - Initiating takedown for ${domain}`);

          takedownResult = await cloudflareService.initiateDomainTakedown(
            urlToProcess,
            `Automated phishing detection - Risk Score: ${scoringResult.score}/100`
          );

          takedownSuccess = takedownResult.success || false;

          // Log takedown initiation (only if DB available)
          if (dbAvailable && report) {
            try {
              await AuditLogger.logTakedownInitiated(report._id, domain, takedownResult);
            } catch (dbError) {
              logger.warn('Failed to log takedown initiation:', dbError.message);
            }
          }

          if (takedownSuccess) {
            logger.info(`[FLOWCHART] Cloudflare takedown initiated successfully for ${domain}`);
          } else {
            logger.warn(`[FLOWCHART] Cloudflare takedown failed for ${domain}: ${takedownResult.message}`);
            if (dbAvailable && report) {
              try {
                await AuditLogger.logTakedownFailed(report._id, domain, new Error(takedownResult.message));
              } catch (dbError) {
                logger.warn('Failed to log takedown failure:', dbError.message);
              }
            }
          }
        } catch (error) {
          logger.error(`[FLOWCHART] Error in Cloudflare takedown:`, error);
          if (dbAvailable && report) {
            try {
              await AuditLogger.logTakedownFailed(report._id, domain, error);
            } catch (dbError) {
              logger.warn('Failed to log takedown error:', dbError.message);
            }
          }
          takedownResult = { success: false, error: error.message };
        }
      } else {
        logger.warn('[FLOWCHART] Cloudflare API not configured - skipping Phase 2 enforcement');
        logger.info('[FLOWCHART] High-risk domain logged for manual review (Cloudflare not configured)');
        takedownResult = {
          success: false,
          message: 'Cloudflare API not configured - Domain logged for manual review',
          skipped: true,
          action: 'logged_for_review'
        };
      }

      // Send takedown email report (APWG, registrars, etc.)
      let emailResult = null;
      try {
        logger.info(`[FLOWCHART] Sending takedown email report for ${domain}`);
        const emailReport = dbAvailable && report ? report : {
          url: urlToProcess,
          riskScore: scoringResult.score,
          riskLevel: scoringResult.riskLevel,
          riskChecks: scoringResult.checks,
          validationResults: {
            virusTotal: intelligence.virusTotal,
            urlhaus: intelligence.urlhaus
          },
          status: 'high_risk',
          createdAt: new Date()
        };
        emailResult = await sendTakedownEmail(emailReport, `High-risk phishing URL detected - Risk Score: ${scoringResult.score}/100`);
        if (emailResult.sent) {
          logger.info(`[FLOWCHART] Takedown email sent successfully for ${domain}`);
        } else {
          logger.warn(`[FLOWCHART] Email not sent: ${emailResult.message || 'SMTP not configured'}`);
        }
      } catch (emailError) {
        logger.warn('Failed to send takedown email:', emailError.message);
        emailResult = { sent: false, error: emailError.message };
      }

      // Confirmation & Immutable Audit Log
      logger.info(`[FLOWCHART] Confirmation & Immutable Audit Log for ${domain}`);

      const confirmation = {
        takedownInitiated: takedownSuccess,
        cloudflareResult: takedownResult,
        emailResult: emailResult,
        riskScore: scoringResult.score,
        riskLevel: scoringResult.riskLevel,
        timestamp: new Date().toISOString()
      };

      if (dbAvailable && report) {
        try {
          await AuditLogger.logTakedownCompleted(report._id, domain, confirmation);
          report.takedownSubmitted = takedownSuccess;
          report.status = takedownSuccess ? 'takedown_initiated' : 'high_risk';
          report.metadata = {
            ...report.metadata,
            cloudflareTakedown: takedownResult,
            confirmation: confirmation
          };
          await report.save();
        } catch (dbError) {
          logger.warn('Failed to save takedown results:', dbError.message);
        }
      }

      // Add takedown info to response
      responseData.takedownResult = takedownResult;
      responseData.takedownInitiated = takedownSuccess;
      responseData.confirmation = confirmation;

      // Output: Domain Takedown Initiated (or logged for review if Cloudflare not configured)
      return res.status(201).json({
        success: true,
        data: dbAvailable && report ? report : responseData,
        message: takedownSuccess
          ? 'High risk detected - Domain takedown initiated via Cloudflare'
          : takedownResult?.skipped
            ? 'High risk detected - Domain logged for manual review (Cloudflare not configured)'
            : 'High risk detected - Takedown attempted but failed',
        flow: {
          phase1: 'Intelligence Gathering - Completed',
          riskScoring: `Risk Score: ${scoringResult.score}/100 (${scoringResult.riskLevel})`,
          phase2: takedownSuccess
            ? 'Enforcement - Takedown Initiated'
            : takedownResult?.skipped
              ? 'Enforcement - Skipped (Cloudflare not configured) - Logged for Review'
              : 'Enforcement - Failed',
          auditLog: 'Confirmation & Immutable Audit Log - Created'
        }
      });

    } else {
      // ============================================
      // LOW-RISK PATH: Log & Flag for Review
      // ============================================
      logger.info(`[FLOWCHART] Low-Risk Score (${scoringResult.score}) - Logging & Flagging for Review`);

      if (dbAvailable && report) {
        try {
          report.status = scoringResult.score >= 40 ? 'medium_risk' : 'low_risk';
          await report.save();
          await AuditLogger.logFlaggedForReview(
            report._id,
            domain,
            `Low risk score (${scoringResult.score}/100) - Manual review required`
          );
        } catch (dbError) {
          logger.warn('Failed to save low-risk report:', dbError.message);
        }
      }

      return res.status(201).json({
        success: true,
        data: dbAvailable && report ? report : responseData,
        message: 'URL analyzed - Logged and flagged for review',
        flow: {
          phase1: 'Intelligence Gathering - Completed',
          riskScoring: `Risk Score: ${scoringResult.score}/100 (${scoringResult.riskLevel})`,
          action: 'Log & Flag for Review',
          reviewRequired: true
        }
      });
    }

  } catch (err) {
    logger.error('Error submitting phishing report:', err.message || err);
    logger.error('Error stack:', err.stack);

    // Try to log the error in audit log if report exists and DB is available
    if (report && report._id && mongoose.connection.readyState === 1) {
      try {
        await AuditLogger.log('status_changed', report._id, report.url || 'unknown', {
          error: err.message,
          status: 'error'
        });
      } catch (auditError) {
        logger.error('Error logging to audit log:', auditError);
      }
    }

    res.status(500).json({
      success: false,
      error: "Internal server error",
      message: process.env.NODE_ENV === 'development' ? (err.message || String(err)) : undefined
    });
  }
};

export const getAllReports = async (req, res) => {
  // Check if MongoDB is connected
  if (mongoose.connection.readyState !== 1) {
    logger.warn('getAllReports called but MongoDB not connected');
    return res.json({
      success: false,
      data: [],
      error: 'Database not available',
      message: 'MongoDB is not connected. Please check your connection.',
      dbAvailable: false
    });
  }
  try {
    const {
      page = 1,
      limit = 50,
      status,
      priority,
      minRisk,
      source,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    const query = {};
    if (status) query.status = status;
    if (priority) query.priority = priority;
    if (minRisk) query.riskScore = { $gte: parseInt(minRisk) };
    if (source) query.source = source;

    const sort = {};
    sort[sortBy] = sortOrder === 'asc' ? 1 : -1;

    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    };

    const result = await PhishingReport.paginate(query, options);

    res.json({
      success: true,
      data: result.docs,
      dbAvailable: true,
      pagination: {
        currentPage: result.page,
        totalPages: result.totalPages,
        totalItems: result.totalDocs,
        itemsPerPage: result.limit,
        hasNextPage: result.hasNextPage,
        hasPrevPage: result.hasPrevPage
      }
    });
  } catch (err) {
    logger.error('Error fetching reports:', err.message || err);
    if (err.name === 'MongoServerError' || err.name === 'MongoNetworkError') {
      return res.status(503).json({
        success: false,
        error: "Database connection error",
        message: "MongoDB is not available. Please check your connection."
      });
    }
    res.status(500).json({
      success: false,
      error: "Failed to fetch reports",
      message: process.env.NODE_ENV === 'development' ? (err.message || String(err)) : undefined
    });
  }
};

export const getReportById = async (req, res) => {
  try {
    const { id } = req.params;
    const report = await PhishingReport.findById(id);

    if (!report) {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }

    res.json({
      success: true,
      data: report
    });
  } catch (err) {
    logger.error('Error fetching report:', err);
    res.status(500).json({
      success: false,
      error: "Failed to fetch report"
    });
  }
};

export const reanalyzeReport = async (req, res) => {
  try {
    const { id } = req.params;
    const report = await PhishingReport.findById(id);

    if (!report) {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }

    // Extract domain
    let domain;
    try {
      const urlObj = new URL(report.url);
      domain = urlObj.hostname.replace(/^www\./, '');
    } catch (error) {
      return res.status(400).json({
        success: false,
        error: 'Invalid URL format in report'
      });
    }

    // Re-run the complete flowchart process
    logger.info(`[REANALYZE] Re-running flowchart for ${report.url}`);

    // Phase 1: Intelligence Gathering
    const intelligence = await riskScoringEngine.gatherIntelligence(report.url);
    try {
      await AuditLogger.logVirusTotalScan(report._id, domain, intelligence.virusTotal);
      await AuditLogger.logUrlhausCheck(report._id, domain, intelligence.urlhaus);
    } catch (auditErr) {
      logger.warn('Failed to log intelligence results during reanalysis:', auditErr.message);
    }

    // Automated Risk Scoring
    const scoringResult = await riskScoringEngine.calculateRiskScore(report.url, intelligence);
    try {
      await AuditLogger.logRiskScore(
        report._id,
        domain,
        scoringResult.score,
        scoringResult.riskLevel,
        scoringResult.checks
      );
    } catch (auditErr) {
      logger.warn('Failed to log risk score during reanalysis:', auditErr.message);
    }

    // Update report
    report.riskScore = scoringResult.score;
    report.riskLevel = scoringResult.riskLevel;
    report.riskChecks = scoringResult.checks;
    report.validationResults = {
      virusTotal: intelligence.virusTotal,
      urlhaus: intelligence.urlhaus
    };
    report.status = scoringResult.score >= 70 ? 'high_risk' :
      scoringResult.score >= 40 ? 'medium_risk' : 'low_risk';

    await report.save();

    res.json({
      success: true,
      data: report,
      message: 'Report re-analyzed successfully using flowchart process'
    });
  } catch (err) {
    logger.error('Error re-analyzing report:', err);
    res.status(500).json({
      success: false,
      error: "Failed to re-analyze report"
    });
  }
};

export const submitTakedown = async (req, res) => {
  try {
    const { id } = req.params;
    const { reason, url } = req.body;

    const dbAvailable = mongoose.connection.readyState === 1;
    if (!dbAvailable) {
      return res.status(503).json({
        success: false,
        message: 'Database not available. Cannot process takedown.',
        suggestion: 'Please ensure MongoDB is connected and try again.'
      });
    }

    let report = null;
    let isNewReport = false;

    // Check if this is a temp report or new URL
    if (id === 'temp' || !mongoose.Types.ObjectId.isValid(id)) {
      // New URL - need to create full report with analysis
      if (!url) {
        return res.status(400).json({
          success: false,
          message: 'URL is required for takedown request'
        });
      }

      // Normalize URL
      let normalizedUrl = url.trim();
      if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://' + normalizedUrl;
      }

      // Check if URL already exists
      const existing = await PhishingReport.findOne({ url: normalizedUrl });
      if (existing) {
        report = existing;
      } else {
        // Create new report with full analysis
        isNewReport = true;
        logger.info(`[TAKEDOWN] New URL submitted for takedown: ${normalizedUrl}`);
        logger.info(`[TAKEDOWN] Running full VirusTotal + URLhaus analysis...`);

        // Full intelligence gathering and risk scoring
        const scoringResult = await riskScoringEngine.processDomain(normalizedUrl);

        // Extract domain
        let domain;
        try {
          const urlObj = new URL(normalizedUrl);
          domain = urlObj.hostname.replace(/^www\./, '');
        } catch (error) {
          return res.status(400).json({
            success: false,
            error: 'Invalid URL format'
          });
        }

        // Create and save report with full intelligence data
        report = new PhishingReport({
          url: normalizedUrl,
          source: 'manual_takedown',
          priority: scoringResult.riskScore >= 70 ? 'high' : 'medium',
          riskScore: scoringResult.riskScore || 50,
          riskLevel: scoringResult.riskLevel || 'Medium',
          riskChecks: scoringResult.checks || {},
          status: scoringResult.riskScore >= 80 ? 'high_risk' :
            scoringResult.riskScore >= 50 ? 'medium_risk' : 'low_risk',
          validationResults: {
            virusTotal: scoringResult.intelligence?.virusTotal || null,
            urlhaus: scoringResult.intelligence?.urlhaus || null
          },
          metadata: {
            takedownRequested: true,
            requestedAt: new Date().toISOString(),
            intelligenceGathered: true
          },
          takedownSubmitted: false
        });

        await report.save();
        await AuditLogger.logIntelligenceGatheringStart(report._id, domain);

        // Log intelligence results
        if (scoringResult.intelligence?.virusTotal) {
          await AuditLogger.logVirusTotalScan(report._id, domain, scoringResult.intelligence.virusTotal);
        }
        if (scoringResult.intelligence?.urlhaus) {
          await AuditLogger.logUrlhausCheck(report._id, domain, scoringResult.intelligence.urlhaus);
        }

        logger.info(`[TAKEDOWN] Report created with full analysis: ${report._id}`);
        logger.info(`[TAKEDOWN] Risk Score: ${scoringResult.riskScore}/100, VirusTotal: ${scoringResult.intelligence?.virusTotal?.malicious || 0} engines, URLhaus: ${scoringResult.intelligence?.urlhaus?.isPhish ? 'Confirmed' : 'Not found'}`);
      }
    } else {
      // Existing report - ensure it has full intelligence data
      report = await PhishingReport.findById(id);
      if (!report) {
        return res.status(404).json({
          success: false,
          message: 'Report not found'
        });
      }

      // If report doesn't have full intelligence, gather it now
      if (!report.validationResults?.virusTotal || !report.metadata?.intelligenceGathered) {
        logger.info(`[TAKEDOWN] Report missing intelligence data, gathering now...`);
        const scoringResult = await riskScoringEngine.processDomain(report.url);

        // Update report with intelligence data
        report.validationResults = {
          virusTotal: scoringResult.intelligence?.virusTotal || report.validationResults?.virusTotal || null,
          urlhaus: scoringResult.intelligence?.urlhaus || report.validationResults?.urlhaus || null
        };
        report.riskScore = scoringResult.riskScore || report.riskScore;
        report.riskLevel = scoringResult.riskLevel || report.riskLevel;
        report.riskChecks = { ...report.riskChecks, ...scoringResult.checks };
        report.metadata = {
          ...report.metadata,
          intelligenceGathered: true,
          intelligenceUpdatedAt: new Date().toISOString()
        };

        await report.save();
        logger.info(`[TAKEDOWN] Intelligence data updated for report: ${report._id}`);
      }
    }

    // Extract domain
    let domain;
    try {
      const urlObj = new URL(report.url);
      domain = urlObj.hostname.replace(/^www\./, '');
    } catch (error) {
      return res.status(400).json({
        success: false,
        error: 'Invalid URL format in report'
      });
    }

    // Phase 2: Cloudflare Registrar API Enforcement + Email Takedown
    let takedownResult = null;
    let emailResult = null;

    // Send takedown email to hosting provider/registrar
    try {
      logger.info(`[TAKEDOWN] Sending takedown email for ${domain}`);
      emailResult = await sendTakedownEmail(report, reason || `Takedown request - Risk Score: ${report.riskScore || 0}/100`);
      if (emailResult.sent) {
        logger.info(`[TAKEDOWN] Takedown email sent successfully`);
      }
    } catch (emailError) {
      logger.warn(`[TAKEDOWN] Failed to send takedown email:`, emailError.message);
      emailResult = { sent: false, error: emailError.message };
    }

    // Cloudflare API takedown (if configured)
    if (cloudflareService.isConfigured()) {
      try {
        logger.info(`[TAKEDOWN] Initiating Cloudflare takedown for ${domain}`);
        takedownResult = await cloudflareService.initiateDomainTakedown(
          report.url,
          reason || `Takedown request - Risk Score: ${report.riskScore || 0}/100 - VirusTotal: ${report.validationResults?.virusTotal?.malicious || 0} engines flagged`
        );

        // Log takedown to audit log
        try {
          await AuditLogger.logTakedownInitiated(report._id, domain, takedownResult);

          if (takedownResult.success) {
            await AuditLogger.logTakedownCompleted(report._id, domain, {
              takedownInitiated: true,
              cloudflareResult: takedownResult,
              emailResult: emailResult,
              timestamp: new Date().toISOString()
            });
          } else {
            await AuditLogger.logTakedownFailed(report._id, domain, new Error(takedownResult.message || 'Cloudflare takedown failed'));
          }
        } catch (auditError) {
          logger.warn('Failed to log takedown to audit log:', auditError.message);
        }
      } catch (error) {
        logger.error('Error in Cloudflare takedown:', error);
        try {
          await AuditLogger.logTakedownFailed(report._id, domain, error);
        } catch (auditError) {
          logger.warn('Failed to log takedown error:', auditError.message);
        }
        takedownResult = { success: false, error: error.message };
      }
    } else {
      takedownResult = {
        success: false,
        message: 'Cloudflare API not configured',
        skipped: true
      };
      logger.warn('[TAKEDOWN] Cloudflare API not configured - email takedown sent only');
    }

    // Update report in database with takedown results
    try {
      report.takedownSubmitted = takedownResult?.success || emailResult?.sent || false;
      report.status = takedownResult?.success ? 'takedown_initiated' :
        emailResult?.sent ? 'takedown_sent' :
          report.status;

      // Set takedown time for latency calculation
      const now = new Date();
      report.metadata = {
        ...report.metadata,
        cloudflareTakedown: takedownResult,
        emailTakedown: emailResult,
        takedownRequestedAt: now.toISOString(),
        takedownTime: now.toISOString(), // For latency calculation
        takedownReason: reason || 'Manual takedown request'
      };

      await report.save();
      logger.info(`[TAKEDOWN] Report saved to database with full intelligence and takedown data: ${report._id}`);
      logger.info(`[TAKEDOWN] VirusTotal: ${report.validationResults?.virusTotal?.malicious || 0}/${report.validationResults?.virusTotal?.total || 0} engines, URLhaus: ${report.validationResults?.urlhaus?.isPhish ? 'Confirmed' : 'Not found'}`);
    } catch (dbError) {
      logger.error('Failed to save report to database:', dbError.message);
      return res.status(500).json({
        success: false,
        error: 'Failed to save report to database',
        message: dbError.message
      });
    }

    // Determine success message based on what actually happened
    let successMessage = '';
    if (takedownResult?.success && emailResult?.sent) {
      successMessage = 'Takedown submitted successfully via Cloudflare and email';
    } else if (takedownResult?.success) {
      successMessage = 'Takedown submitted successfully via Cloudflare';
    } else if (emailResult?.sent) {
      successMessage = 'Takedown email sent successfully to hosting provider';
    } else if (emailResult?.error) {
      successMessage = `Takedown email failed: ${emailResult.error}`;
    } else if (takedownResult?.skipped) {
      successMessage = 'Report saved with full intelligence data. Email takedown requires SMTP configuration.';
    } else {
      successMessage = 'Report saved with full intelligence data';
    }

    res.json({
      success: emailResult?.sent || takedownResult?.success || true, // Success if anything worked or at least saved
      data: report,
      message: successMessage,
      takedownResult: {
        cloudflare: takedownResult,
        email: emailResult,
        cloudflareConfigured: cloudflareService.isConfigured(),
        emailConfigured: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS)
      },
      intelligence: {
        virusTotal: report.validationResults?.virusTotal,
        urlhaus: report.validationResults?.urlhaus,
        riskScore: report.riskScore,
        riskLevel: report.riskLevel
      }
    });
  } catch (err) {
    logger.error('Error submitting takedown:', err);
    res.status(500).json({
      success: false,
      error: "Failed to submit takedown"
    });
  }
};

export const getAuditLogs = async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 100 } = req.query;

    const report = await PhishingReport.findById(id);
    if (!report) {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }

    const logs = await AuditLogger.getLogsForReport(id, parseInt(limit));

    res.json({
      success: true,
      data: {
        reportId: id,
        domain: report.url,
        logs: logs,
        totalLogs: logs.length
      }
    });
  } catch (err) {
    logger.error('Error fetching audit logs:', err);
    res.status(500).json({
      success: false,
      error: "Failed to fetch audit logs"
    });
  }
};

export const getMetrics = async (req, res) => {
  // Check if MongoDB is connected
  if (mongoose.connection.readyState !== 1) {
    return res.json({
      success: true,
      totalReports: 0,
      highRiskCount: 0,
      resolvedCount: 0,
      pendingCount: 0,
      avgLatency: 0,
      dbAvailable: false
    });
  }

  try {
    const [
      totalReports,
      highRiskCount,
      resolvedCount,
      pendingCount
    ] = await Promise.all([
      // Total Reports - count of all scanned URLs
      PhishingReport.countDocuments(),

      // High Risk - riskScore >= 80 AND status = ACTIVE (high_risk or pending)
      PhishingReport.countDocuments({
        riskScore: { $gte: 80 },
        status: { $in: ['high_risk', 'pending'] }
      }),

      // Resolved - status = TAKEN_DOWN (resolved, takedown_initiated, takedown_sent)
      PhishingReport.countDocuments({
        status: { $in: ['resolved', 'takedown_initiated', 'takedown_sent'] }
      }),

      // Pending - takedownStatus = PENDING (status in pending/high_risk/medium_risk/low_risk AND takedownSubmitted = false)
      PhishingReport.countDocuments({
        status: { $in: ['pending', 'high_risk', 'medium_risk', 'low_risk'] },
        takedownSubmitted: false
      })
    ]);

    // Avg Latency - avg(timeDetected → timeTakenDown)
    // Calculate from metadata.takedownTime or updatedAt where status is resolved
    // Use a simpler approach: find resolved reports and calculate latency in JavaScript
    const resolvedReports = await PhishingReport.find({
      status: { $in: ['resolved', 'takedown_initiated', 'takedown_sent'] },
      createdAt: { $exists: true }
    }).select('createdAt updatedAt metadata').lean();

    let latencySum = 0;
    let latencyCount = 0;

    resolvedReports.forEach(report => {
      let takedownTime = null;

      // Try to get takedownTime from metadata
      if (report.metadata?.takedownTime) {
        try {
          takedownTime = new Date(report.metadata.takedownTime);
          if (isNaN(takedownTime.getTime())) {
            takedownTime = null;
          }
        } catch (e) {
          takedownTime = null;
        }
      }

      // Fallback to updatedAt if takedownTime not available
      if (!takedownTime && report.updatedAt) {
        takedownTime = new Date(report.updatedAt);
      }

      // Calculate latency if we have both dates
      if (takedownTime && report.createdAt) {
        const createdAt = new Date(report.createdAt);
        if (!isNaN(createdAt.getTime()) && !isNaN(takedownTime.getTime())) {
          const latencyMs = takedownTime.getTime() - createdAt.getTime();
          if (latencyMs > 0) {
            latencySum += latencyMs;
            latencyCount++;
          }
        }
      }
    });

    const latencyData = latencyCount > 0
      ? [{ avgLatency: latencySum / latencyCount }]
      : [];

    // Calculate average latency in minutes (for display)
    let avgLatency = 0;
    if (latencyData && latencyData.length > 0 && latencyData[0]?.avgLatency) {
      const latencyMs = latencyData[0].avgLatency;
      // Check if latencyMs is a valid number
      if (typeof latencyMs === 'number' && !isNaN(latencyMs) && isFinite(latencyMs) && latencyMs > 0) {
        const latencyMinutes = latencyMs / (1000 * 60); // Convert to minutes
        avgLatency = Math.round(latencyMinutes * 10) / 10; // Round to 1 decimal place
        // Ensure it's not NaN or Infinity
        if (isNaN(avgLatency) || !isFinite(avgLatency)) {
          avgLatency = 0;
        }
      }
    }

    const metrics = {
      totalReports,
      highRiskCount,
      resolvedCount,
      pendingCount,
      avgLatency,
      lastUpdated: new Date().toISOString()
    };

    res.json({
      success: true,
      data: metrics,
      dbAvailable: true
    });
  } catch (err) {
    logger.error('Error fetching metrics:', err);
    res.status(500).json({
      success: false,
      error: "Failed to fetch metrics"
    });
  }
};

// Fetch URLs directly from URLhaus
export const getUrlhausUrls = async (req, res) => {
  try {
    const urlScraper = new URLScraper();
    const urls = await urlScraper.scrapeUrlhaus();

    res.json({
      success: true,
      data: urls,
      count: urls.length,
      source: 'urlhaus',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    logger.error('Error fetching URLhaus URLs:', err);
    res.status(500).json({
      success: false,
      error: "Failed to fetch URLs from URLhaus",
      message: err.message
    });
  }
};

// Mark report as false positive
export const markFalsePositive = async (req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      success: false,
      error: "Database not available"
    });
  }

  try {
    const { id } = req.params;
    const report = await PhishingReport.findById(id);

    if (!report) {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }

    const previousStatus = report.status;
    report.status = 'false_positive';
    await report.save();

    try {
      const urlObj = new URL(report.url);
      await AuditLogger.log('status_changed', report._id, urlObj.hostname, {
        previousStatus,
        newStatus: 'false_positive',
        markedBy: 'dashboard',
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      logger.warn('Failed to log false positive to audit log:', err);
    }

    res.json({
      success: true,
      data: report,
      message: 'Report marked as false positive'
    });
  } catch (err) {
    logger.error('Error marking false positive:', err);
    res.status(500).json({
      success: false,
      error: "Failed to mark as false positive"
    });
  }
};

// Refresh status - recheck if site is down
export const refreshStatus = async (req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      success: false,
      error: "Database not available"
    });
  }

  try {
    const { id } = req.params;
    const report = await PhishingReport.findById(id);

    if (!report) {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }

    const url = report.url;
    let isDown = false;
    let dnsResolves = false;

    // HTTP check
    try {
      const axios = (await import('axios')).default;
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true // Accept any status code
      });
      isDown = response.status >= 400 || response.status === 0;
    } catch (httpError) {
      isDown = true; // Site is likely down if request fails
    }

    // DNS resolution check
    try {
      const dns = await import('dns').then(m => m.promises);
      const urlObj = new URL(url);
      await dns.resolve4(urlObj.hostname);
      dnsResolves = true;
    } catch (dnsError) {
      dnsResolves = false;
    }

    // If site is down (HTTP fails AND DNS doesn't resolve), mark as TAKEN_DOWN
    if (isDown && !dnsResolves) {
      const previousStatus = report.status;
      report.status = 'resolved';
      report.metadata = {
        ...report.metadata,
        takedownTime: new Date().toISOString(),
        lastChecked: new Date().toISOString(),
        checkResult: 'site_down'
      };
      await report.save();

      try {
        const urlObj = new URL(report.url);
        await AuditLogger.log('status_changed', report._id, urlObj.hostname, {
          previousStatus,
          newStatus: 'resolved',
          reason: 'status_refresh',
          isDown,
          dnsResolves,
          timestamp: new Date().toISOString()
        });
      } catch (err) {
        logger.warn('Failed to log status refresh to audit log:', err);
      }
    } else {
      // Update last checked time
      report.metadata = {
        ...report.metadata,
        lastChecked: new Date().toISOString(),
        checkResult: isDown ? 'http_down' : 'site_active',
        dnsResolves
      };
      await report.save();
    }

    res.json({
      success: true,
      data: {
        ...report.toObject(),
        checkResult: {
          isDown,
          dnsResolves,
          status: isDown && !dnsResolves ? 'resolved' : report.status
        }
      },
      message: isDown && !dnsResolves
        ? 'Site is down - marked as resolved'
        : 'Status refreshed'
    });
  } catch (err) {
    logger.error('Error refreshing status:', err);
    res.status(500).json({
      success: false,
      error: "Failed to refresh status"
    });
  }
};

// Fetch URLs analyzed by VirusTotal from database
export const getVirusTotalUrls = async (req, res) => {
  // Check if MongoDB is connected
  if (mongoose.connection.readyState !== 1) {
    return res.json({
      success: true,
      data: [],
      message: 'Database not available - returning empty results',
      dbAvailable: false
    });
  }

  try {
    const {
      page = 1,
      limit = 50,
      minMalicious = 0
    } = req.query;

    const query = {
      'validationResults.virusTotal': { $exists: true, $ne: null },
      'validationResults.virusTotal.error': { $exists: false }
    };

    // Filter by minimum malicious count if provided
    if (minMalicious) {
      query['validationResults.virusTotal.malicious'] = { $gte: parseInt(minMalicious) };
    }

    const sort = { createdAt: -1 };

    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    };

    const result = await PhishingReport.paginate(query, options);

    // Format the response to include VirusTotal data
    const formattedData = result.docs.map(report => ({
      _id: report._id,
      url: report.url,
      source: report.source,
      riskLevel: report.riskLevel,
      riskScore: report.riskScore,
      status: report.status,
      createdAt: report.createdAt,
      virusTotal: report.validationResults?.virusTotal || null
    }));

    res.json({
      success: true,
      data: formattedData,
      pagination: {
        currentPage: result.page,
        totalPages: result.totalPages,
        totalItems: result.totalDocs,
        itemsPerPage: result.limit,
        hasNextPage: result.hasNextPage,
        hasPrevPage: result.hasPrevPage
      },
      source: 'virustotal',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    logger.error('Error fetching VirusTotal URLs:', err);
    res.status(500).json({
      success: false,
      error: "Failed to fetch URLs analyzed by VirusTotal",
      message: err.message
    });
  }
};