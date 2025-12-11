import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';

/**
 * Immutable Audit Log Schema
 * This creates an audit trail that cannot be modified
 */
const auditLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true,
    enum: [
      'domain_submitted',
      'intelligence_gathering_started',
      'virustotal_scan',
      'urlhaus_check',
      'risk_score_calculated',
      'takedown_initiated',
      'takedown_completed',
      'takedown_failed',
      'flagged_for_review',
      'status_changed'
    ]
  },
  reportId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'PhishingReport',
    required: true
  },
  domain: {
    type: String,
    required: true
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100
  },
  riskLevel: {
    type: String,
    enum: ['Low', 'Medium', 'High']
  },
  timestamp: {
    type: Date,
    default: Date.now,
    immutable: true // Cannot be changed after creation
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, {
  timestamps: false, // We use our own timestamp field
  collection: 'audit_logs'
});

// Indexes for efficient querying
auditLogSchema.index({ reportId: 1, timestamp: -1 });
auditLogSchema.index({ domain: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ timestamp: -1 });

// Prevent any updates or deletes
auditLogSchema.pre('updateOne', function() {
  throw new Error('Audit logs are immutable and cannot be updated');
});

auditLogSchema.pre('deleteOne', function() {
  throw new Error('Audit logs are immutable and cannot be deleted');
});

auditLogSchema.pre('findOneAndUpdate', function() {
  throw new Error('Audit logs are immutable and cannot be updated');
});

auditLogSchema.pre('findOneAndDelete', function() {
  throw new Error('Audit logs are immutable and cannot be deleted');
});

const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', auditLogSchema);

/**
 * Audit Logger Service
 * Provides methods to create immutable audit log entries
 */
export class AuditLogger {
  /**
   * Log an action to the audit log
   */
  static async log(action, reportId, domain, details = {}) {
    try {
      // If MongoDB is not connected, just log to console
      if (mongoose.connection.readyState !== 1) {
        logger.warn('MongoDB not connected, audit log written to console only');
        logger.info(`[AUDIT] ${action} - Domain: ${domain} - ReportId: ${reportId}`, details);
        return null;
      }

      const auditEntry = new AuditLog({
        action,
        reportId,
        domain,
        details,
        riskScore: details.riskScore,
        riskLevel: details.riskLevel,
        metadata: {
          userAgent: details.userAgent,
          ipAddress: details.ipAddress,
          source: details.source
        }
      });

      await auditEntry.save();
      logger.info(`[AUDIT] ${action} logged for domain: ${domain}`);
      
      return auditEntry;
    } catch (error) {
      // Even if audit logging fails, we should not break the main flow
      logger.error('Error creating audit log:', error);
      return null;
    }
  }

  /**
   * Log intelligence gathering phase start
   */
  static async logIntelligenceGatheringStart(reportId, domain) {
    return await this.log('intelligence_gathering_started', reportId, domain, {
      phase: 'Phase 1',
      description: 'Intelligence gathering initiated'
    });
  }

  /**
   * Log VirusTotal scan result
   */
  static async logVirusTotalScan(reportId, domain, result) {
    return await this.log('virustotal_scan', reportId, domain, {
      phase: 'Phase 1',
      service: 'VirusTotal',
      result: result,
      malicious: result?.malicious || 0,
      suspicious: result?.suspicious || 0
    });
  }

  /**
   * Log URLhaus check result
   */
  static async logUrlhausCheck(reportId, domain, result) {
    return await this.log('urlhaus_check', reportId, domain, {
      phase: 'Phase 1',
      service: 'URLhaus',
      result: result,
      isPhish: result?.isPhish || false,
      verified: result?.verified || false
    });
  }

  /**
   * Log risk score calculation
   */
  static async logRiskScore(reportId, domain, riskScore, riskLevel, checks) {
    return await this.log('risk_score_calculated', reportId, domain, {
      phase: 'Automated Risk Scoring Engine',
      riskScore,
      riskLevel,
      checks: checks,
      decision: riskScore >= 70 ? 'High-Risk' : 'Low-Risk'
    });
  }

  /**
   * Log takedown initiation
   */
  static async logTakedownInitiated(reportId, domain, takedownResult) {
    return await this.log('takedown_initiated', reportId, domain, {
      phase: 'Phase 2: Enforcement',
      service: 'Cloudflare Registrar API',
      result: takedownResult,
      success: takedownResult?.success || false
    });
  }

  /**
   * Log takedown completion
   */
  static async logTakedownCompleted(reportId, domain, confirmation) {
    return await this.log('takedown_completed', reportId, domain, {
      phase: 'Confirmation & Immutable Audit Log',
      confirmation: confirmation,
      status: 'Domain Takedown Initiated'
    });
  }

  /**
   * Log takedown failure
   */
  static async logTakedownFailed(reportId, domain, error) {
    return await this.log('takedown_failed', reportId, domain, {
      phase: 'Phase 2: Enforcement',
      error: error.message || String(error),
      service: 'Cloudflare Registrar API'
    });
  }

  /**
   * Log flagging for review
   */
  static async logFlaggedForReview(reportId, domain, reason) {
    return await this.log('flagged_for_review', reportId, domain, {
      phase: 'Low-Risk Path',
      reason: reason || 'Low risk score - manual review required',
      action: 'Log & Flag for Review'
    });
  }

  /**
   * Get audit logs for a specific report
   */
  static async getLogsForReport(reportId, limit = 100) {
    try {
      if (mongoose.connection.readyState !== 1) {
        return [];
      }

      return await AuditLog.find({ reportId })
        .sort({ timestamp: -1 })
        .limit(limit)
        .lean();
    } catch (error) {
      logger.error('Error fetching audit logs:', error);
      return [];
    }
  }

  /**
   * Get audit logs for a domain
   */
  static async getLogsForDomain(domain, limit = 100) {
    try {
      if (mongoose.connection.readyState !== 1) {
        return [];
      }

      return await AuditLog.find({ domain })
        .sort({ timestamp: -1 })
        .limit(limit)
        .lean();
    } catch (error) {
      logger.error('Error fetching audit logs:', error);
      return [];
    }
  }
}

export default AuditLog;

