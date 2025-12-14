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
  const dbAvailable = mongoose.connection.readyState === 1;
  
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
    await AuditLogger.logVirusTotalScan(report._id, domain, intelligence.virusTotal);
      await AuditLogger.logUrlhausCheck(report._id, domain, intelligence.urlhaus);

    // Automated Risk Scoring
    const scoringResult = await riskScoringEngine.calculateRiskScore(report.url, intelligence);
    await AuditLogger.logRiskScore(
      report._id, 
      domain, 
      scoringResult.score, 
      scoringResult.riskLevel,
      scoringResult.checks
    );

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
    const { reason, url } = req.body; // Allow URL to be passed for temp reports
    
    let report = null;
    let isTempReport = false;
    
    // Check if this is a temp report (not saved to DB)
    if (id === 'temp' || !mongoose.Types.ObjectId.isValid(id)) {
      isTempReport = true;
      // For temp reports, we need the URL from the request body
      if (!url) {
        return res.status(400).json({
          success: false,
          message: 'URL is required for temporary reports'
        });
      }
      report = { url, riskScore: 0, riskLevel: 'Low' }; // Create a minimal report object
    } else {
      // Try to find report in database
      if (mongoose.connection.readyState === 1) {
        report = await PhishingReport.findById(id);
        if (!report) {
          return res.status(404).json({
            success: false,
            message: 'Report not found'
          });
        }
      } else {
        // DB not available, but we have an ID - this shouldn't happen, but handle it
        return res.status(503).json({
          success: false,
          message: 'Database not available. Cannot process takedown for saved reports.',
          suggestion: 'Please resubmit the URL to create a new scan, then request takedown.'
        });
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

    // Phase 2: Cloudflare Registrar API Enforcement
    let takedownResult = null;
    if (cloudflareService.isConfigured()) {
      try {
        logger.info(`[TAKEDOWN] Initiating takedown for ${domain} (${isTempReport ? 'temp report' : 'saved report'})`);
        takedownResult = await cloudflareService.initiateDomainTakedown(
          report.url,
          reason || `Manual takedown request - Risk Score: ${report.riskScore || 0}/100`
        );
        
        // Log takedown (only if report exists in DB)
        if (!isTempReport && report._id && mongoose.connection.readyState === 1) {
          try {
            await AuditLogger.logTakedownInitiated(report._id, domain, takedownResult);
            
            if (takedownResult.success) {
              await AuditLogger.logTakedownCompleted(report._id, domain, {
                takedownInitiated: true,
                cloudflareResult: takedownResult,
                timestamp: new Date().toISOString()
              });
            } else {
              await AuditLogger.logTakedownFailed(report._id, domain, new Error(takedownResult.message));
            }
          } catch (auditError) {
            logger.warn('Failed to log takedown to audit log:', auditError.message);
          }
        }
      } catch (error) {
        logger.error('Error in Cloudflare takedown:', error);
        if (!isTempReport && report._id && mongoose.connection.readyState === 1) {
          try {
            await AuditLogger.logTakedownFailed(report._id, domain, error);
          } catch (auditError) {
            logger.warn('Failed to log takedown error:', auditError.message);
          }
        }
        takedownResult = { success: false, error: error.message };
      }
    } else {
      takedownResult = { 
        success: false, 
        message: 'Cloudflare API not configured',
        skipped: true 
      };
      logger.warn('[TAKEDOWN] Cloudflare API not configured - takedown skipped');
    }

    // Update report in database (only if it exists in DB)
    if (!isTempReport && report._id && mongoose.connection.readyState === 1) {
      try {
        report.takedownSubmitted = takedownResult?.success || false;
        report.status = takedownResult?.success ? 'takedown_initiated' : report.status;
        report.metadata = {
          ...report.metadata,
          cloudflareTakedown: takedownResult,
          manualTakedown: true
        };
        await report.save();
        logger.info(`[TAKEDOWN] Report updated in database: ${report._id}`);
      } catch (dbError) {
        logger.warn('Failed to update report in database:', dbError.message);
      }
    } else if (isTempReport) {
      logger.info('[TAKEDOWN] Takedown processed for temp report (not saved to DB)');
    }
    
    res.json({
      success: true,
      data: isTempReport ? { url: report.url, ...takedownResult } : report,
      message: takedownResult?.success 
        ? 'Takedown submitted successfully via Cloudflare' 
        : takedownResult?.skipped
        ? 'Cloudflare API not configured - Takedown skipped'
        : takedownResult?.error
        ? `Takedown request failed: ${takedownResult.error}`
        : 'Takedown attempted but failed',
      takedownResult,
      isTempReport
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
      pendingCount,
      latencyData
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
      }),
      
      // Avg Latency - avg(timeDetected → timeTakenDown)
      // Calculate from metadata.takedownTime or updatedAt where status is resolved
      PhishingReport.aggregate([
        {
          $match: {
            status: { $in: ['resolved', 'takedown_initiated', 'takedown_sent'] },
            createdAt: { $exists: true }
          }
        },
        {
          $project: {
            latency: {
              $cond: {
                if: { $and: [{ $ne: ['$metadata.takedownTime', null] }, { $ne: ['$metadata.takedownTime', undefined] }] },
                then: {
                  $subtract: [
                    { $dateFromString: { dateString: '$metadata.takedownTime' } },
                    '$createdAt'
                  ]
                },
                else: {
                  $subtract: ['$updatedAt', '$createdAt']
                }
              }
            }
          }
        },
        {
          $group: {
            _id: null,
            avgLatency: { $avg: '$latency' }
          }
        }
      ])
    ]);

    const avgLatency = latencyData[0]?.avgLatency 
      ? Math.round(latencyData[0].avgLatency / (1000 * 60)) // Convert to minutes
      : 0;

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
      data: metrics
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
          previousStatus: report.status,
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
      'intelligence.virusTotal': { $exists: true, $ne: null },
      'intelligence.virusTotal.error': { $exists: false }
    };

    // Filter by minimum malicious count if provided
    if (minMalicious) {
      query['intelligence.virusTotal.malicious'] = { $gte: parseInt(minMalicious) };
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
      virusTotal: report.intelligence?.virusTotal || null
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