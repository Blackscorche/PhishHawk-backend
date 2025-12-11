import axios from 'axios';
import { logger } from '../utils/logger.js';

export class RiskAnalyzer {
  constructor() {
    this.suspiciousKeywords = [
      'login', 'verify', 'suspend', 'update', 'confirm', 'secure',
      'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
      'urgent', 'immediate', 'expires', 'limited', 'offer',
      'click', 'winner', 'prize', 'congratulations', 'free',
      'account', 'suspended', 'locked', 'billing', 'invoice'
    ];
    
    this.suspiciousTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.work', '.click',
      '.download', '.stream', '.science', '.party', '.review',
      '.loan', '.racing', '.cricket', '.accountant', '.date'
    ];
    
    this.trustedDomains = [
      'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
      'paypal.com', 'ebay.com', 'facebook.com', 'twitter.com',
      'linkedin.com', 'github.com', 'stackoverflow.com',
      'youtube.com', 'wikipedia.org', 'reddit.com'
    ];
  }

  async analyzeURL(url) {
    try {
      let riskScore = 0;
      const checks = {};
      
      // Parse URL
      let parsedUrl;
      try {
        parsedUrl = new URL(url);
      } catch (error) {
        return { 
          score: 100, 
          checks: { invalidUrl: true, error: 'Invalid URL format' },
          error: 'Invalid URL format' 
        };
      }

      const domain = parsedUrl.hostname.toLowerCase();
      checks.domain = domain;
      checks.protocol = parsedUrl.protocol;
      
      // Protocol check
      if (parsedUrl.protocol !== 'https:') {
        riskScore += 15;
        checks.insecureProtocol = true;
      }
      
      // Check for suspicious TLDs
      const hasSuspiciousTLD = this.suspiciousTLDs.some(tld => domain.endsWith(tld));
      if (hasSuspiciousTLD) {
        riskScore += 30;
        checks.suspiciousTLD = true;
      }
      
      // Check for trusted domains
      const isTrustedDomain = this.trustedDomains.some(trusted => 
        domain === trusted || domain.endsWith('.' + trusted)
      );
      if (isTrustedDomain) {
        riskScore = Math.max(0, riskScore - 40);
        checks.trustedDomain = true;
      }
      
      // Check domain length
      if (domain.length > 50) {
        riskScore += 20;
        checks.longDomain = domain.length;
      }
      
      // Check for excessive subdomains
      const subdomainCount = domain.split('.').length - 2;
      if (subdomainCount > 2) {
        riskScore += 15;
        checks.excessiveSubdomains = subdomainCount;
      }
      
      // Check for suspicious keywords in URL
      const fullUrl = url.toLowerCase();
      const keywordMatches = this.suspiciousKeywords.filter(keyword => 
        fullUrl.includes(keyword)
      );
      if (keywordMatches.length > 0) {
        riskScore += keywordMatches.length * 10;
        checks.suspiciousKeywords = keywordMatches;
      }
      
      // Check for URL shorteners
      const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd'];
      const isShortener = shorteners.some(shortener => domain.includes(shortener));
      if (isShortener) {
        riskScore += 25;
        checks.urlShortener = true;
      }
      
      // Check for suspicious patterns
      if (/\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/.test(domain)) {
        riskScore += 40;
        checks.ipInDomain = true;
      }
      
      // Path analysis
      const path = parsedUrl.pathname.toLowerCase();
      if (path.includes('..') || path.includes('%2e%2e')) {
        riskScore += 35;
        checks.pathTraversal = true;
      }
      
      // Try to fetch additional info (with timeout)
      try {
        const response = await axios.get(url, {
          timeout: 10000,
          maxRedirects: 5,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PhishingBot/1.0)'
          }
        });
        
        checks.httpStatus = response.status;
        checks.contentType = response.headers['content-type'];
        checks.server = response.headers['server'];
        
        // Analyze content if HTML
        if (response.headers['content-type']?.includes('text/html')) {
          const content = response.data.toLowerCase();
          
          // Check for suspicious form actions
          if (content.includes('<form') && content.includes('password')) {
            riskScore += 25;
            checks.passwordForm = true;
          }
          
          // Check for fake login pages
          const loginIndicators = ['login', 'signin', 'log in', 'username', 'email'];
          const loginCount = loginIndicators.filter(indicator => 
            content.includes(indicator)
          ).length;
          if (loginCount >= 3) {
            riskScore += 20;
            checks.likelyLoginPage = loginCount;
          }
          
          // Check for urgency language
          const urgentWords = ['urgent', 'immediate', 'expires', 'suspended', 'locked'];
          const urgentCount = urgentWords.filter(word => content.includes(word)).length;
          if (urgentCount > 0) {
            riskScore += urgentCount * 15;
            checks.urgentLanguage = urgentCount;
          }
        }
        
      } catch (fetchError) {
        logger.warn(`Failed to fetch ${url}:`, fetchError.message);
        checks.fetchError = fetchError.message;
        riskScore += 10; // Slightly increase risk for inaccessible sites
      }
      
      // Cap the risk score at 100
      riskScore = Math.min(100, Math.max(0, riskScore));
      
      checks.finalScore = riskScore;
      checks.analyzedAt = new Date();
      
      return {
        score: riskScore,
        checks
      };
      
    } catch (error) {
      logger.error('Error in risk analysis:', error);
      return {
        score: 50, // Default medium risk on error
        checks: { 
          error: error.message,
          analyzedAt: new Date()
        },
        error: error.message
      };
    }
  }
}
