import { logger } from '../utils/logger.js';
import { APIValidator } from './apiValidator.js';
import { RiskAnalyzer } from './riskAnalyzer.js';

/**
 * Automated Risk Scoring Engine
 * Combines Phase 1 intelligence gathering results with risk analysis
 * to produce a final risk score for decision making
 */
export class AutomatedRiskScoringEngine {
  constructor() {
    this.apiValidator = new APIValidator();
    this.riskAnalyzer = new RiskAnalyzer();
    this.highRiskThreshold = 70; // Score >= 70 = High Risk
    this.lowRiskThreshold = 40;   // Score < 40 = Low Risk
  }

  /**
   * Phase 1: Intelligence Gathering
   * Runs VirusTotal and URLhaus checks in parallel
   */
  async gatherIntelligence(url) {
    logger.info(`[Phase 1] Starting intelligence gathering for: ${url}`);
    
    const intelligence = {
      virusTotal: null,
      urlhaus: null,
      gatheredAt: new Date()
    };

    try {
      // Run both checks in parallel for efficiency
      const validationResults = await this.apiValidator.validateURL(url);
      
      intelligence.virusTotal = validationResults.virusTotal;
      intelligence.urlhaus = validationResults.urlhaus;

      logger.info(`[Phase 1] Intelligence gathering completed for: ${url}`);
      logger.info(`[Phase 1] VirusTotal: ${intelligence.virusTotal ? 'Completed' : 'Failed'}`);
      logger.info(`[Phase 1] URLhaus: ${intelligence.urlhaus ? 'Completed' : 'Failed'}`);

    } catch (error) {
      logger.error('[Phase 1] Error in intelligence gathering:', error);
      intelligence.error = error.message;
    }

    return intelligence;
  }

  /**
   * Calculate risk score based on intelligence gathering and URL analysis
   */
  async calculateRiskScore(url, intelligence) {
    logger.info(`[Risk Scoring] Calculating risk score for: ${url}`);

    // Start with base risk analysis
    const baseAnalysis = await this.riskAnalyzer.analyzeURL(url);
    let riskScore = baseAnalysis.score;
    const checks = { ...baseAnalysis.checks };

    // Add VirusTotal scoring
    if (intelligence.virusTotal && !intelligence.virusTotal.error) {
      const vt = intelligence.virusTotal;
      
      if (vt.malicious > 0) {
        // Each malicious detection adds to the score
        const vtScore = Math.min(30, vt.malicious * 5); // Max 30 points from VT
        riskScore += vtScore;
        checks.virusTotalMalicious = vt.malicious;
        checks.virusTotalTotal = vt.total;
      }
      
      if (vt.suspicious > 0) {
        const suspiciousScore = Math.min(15, vt.suspicious * 3); // Max 15 points
        riskScore += suspiciousScore;
        checks.virusTotalSuspicious = vt.suspicious;
      }

      // If submitted for analysis, add moderate risk
      if (vt.submitted) {
        riskScore += 10;
        checks.virusTotalSubmitted = true;
      }
    } else if (intelligence.virusTotal?.error) {
      checks.virusTotalError = intelligence.virusTotal.error;
    }

    // Add URLhaus scoring
    if (intelligence.urlhaus && !intelligence.urlhaus.error) {
      const uh = intelligence.urlhaus;
      
      if (uh.isPhish && uh.urlStatus === 'online') {
        // URLhaus confirmation is a strong indicator
        riskScore += 40;
        checks.urlhausConfirmed = true;
        
        if (uh.verified) {
          // Verified malicious sites get additional points
          riskScore += 15;
          checks.urlhausVerified = true;
        }
        
        // Additional scoring based on threat type
        if (uh.threat) {
          if (uh.threat.includes('phishing') || uh.threat.includes('phish')) {
            riskScore += 10;
            checks.urlhausPhishing = true;
          }
          if (uh.threat.includes('malware')) {
            riskScore += 5;
            checks.urlhausMalware = true;
          }
        }
        
        // Tags can indicate severity
        if (uh.tags && Array.isArray(uh.tags)) {
          if (uh.tags.includes('phishing')) riskScore += 5;
          if (uh.tags.includes('banking')) riskScore += 5;
          if (uh.tags.includes('credential-stealer')) riskScore += 10;
        }
      } else if (uh.urlStatus === 'offline') {
        // URL was malicious but is now offline (still a risk indicator)
        riskScore += 20;
        checks.urlhausOffline = true;
      } else {
        // Not in URLhaus doesn't mean it's safe, but slightly reduces risk
        riskScore = Math.max(0, riskScore - 5);
        checks.urlhausNotInDatabase = true;
      }
    } else if (intelligence.urlhaus?.error) {
      checks.urlhausError = intelligence.urlhaus.error;
    }

    // Cap the score at 100
    riskScore = Math.min(100, Math.max(0, riskScore));

    // Determine risk level
    let riskLevel = 'Low';
    if (riskScore >= this.highRiskThreshold) {
      riskLevel = 'High';
    } else if (riskScore >= this.lowRiskThreshold) {
      riskLevel = 'Medium';
    }

    logger.info(`[Risk Scoring] Final score: ${riskScore}/100 (${riskLevel} Risk)`);

    return {
      score: riskScore,
      riskLevel,
      checks,
      intelligence,
      decision: riskScore >= this.highRiskThreshold ? 'High-Risk' : 'Low-Risk'
    };
  }

  /**
   * Complete automated risk scoring process
   * Follows the flowchart: Intelligence Gathering → Risk Scoring → Decision
   */
  async processDomain(url) {
    try {
      // Phase 1: Intelligence Gathering
      const intelligence = await this.gatherIntelligence(url);

      // Automated Risk Scoring Engine
      const scoringResult = await this.calculateRiskScore(url, intelligence);

      return {
        success: true,
        url,
        intelligence,
        riskScore: scoringResult.score,
        riskLevel: scoringResult.riskLevel,
        checks: scoringResult.checks,
        decision: scoringResult.decision,
        isHighRisk: scoringResult.score >= this.highRiskThreshold,
        isLowRisk: scoringResult.score < this.lowRiskThreshold
      };

    } catch (error) {
      logger.error('Error in automated risk scoring:', error);
      return {
        success: false,
        url,
        error: error.message,
        riskScore: 50, // Default to medium risk on error
        riskLevel: 'Medium',
        decision: 'Error'
      };
    }
  }
}

