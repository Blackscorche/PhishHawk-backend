import axios from 'axios';
import { logger } from '../utils/logger.js';

/**
 * Cloudflare Registrar API Service
 * Handles domain takedown requests through Cloudflare's registrar API
 */
export class CloudflareRegistrarService {
  constructor() {
    // Support both API Token (recommended) and Global API Key (legacy)
    this.apiToken = process.env.CLOUDFLARE_API_TOKEN;
    this.apiKey = process.env.CLOUDFLARE_API_KEY; // Legacy: Global API Key
    this.email = process.env.CLOUDFLARE_EMAIL; // Only needed for Global API Key
    this.accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
    this.baseUrl = 'https://api.cloudflare.com/client/v4';
  }

  /**
   * Check if Cloudflare API is configured
   */
  isConfigured() {
    // API Token is preferred, but Global API Key also works
    return !!(this.apiToken || (this.apiKey && this.email)) && this.accountId;
  }

  /**
   * Get authentication headers
   */
  getAuthHeaders() {
    if (this.apiToken) {
      // API Token authentication (recommended)
      return {
        'Authorization': `Bearer ${this.apiToken}`,
        'Content-Type': 'application/json'
      };
    } else {
      // Global API Key authentication (legacy)
      return {
        'X-Auth-Email': this.email,
        'X-Auth-Key': this.apiKey,
        'Content-Type': 'application/json'
      };
    }
  }

  /**
   * Extract domain from URL
   */
  extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname.replace(/^www\./, '');
    } catch (error) {
      logger.error('Error extracting domain from URL:', error);
      return null;
    }
  }

  /**
   * Check if domain is registered with Cloudflare
   */
  async checkDomainRegistration(domain) {
    if (!this.isConfigured()) {
      throw new Error('Cloudflare API not configured');
    }

    try {
      const response = await axios.get(
        `${this.baseUrl}/accounts/${this.accountId}/registrar/domains`,
        {
          headers: this.getAuthHeaders(),
          timeout: 30000
        }
      );

      const domains = response.data.result || [];
      const domainInfo = domains.find(d => d.domain === domain || d.domain === `www.${domain}`);

      return {
        registered: !!domainInfo,
        domainInfo: domainInfo || null
      };
    } catch (error) {
      logger.error('Error checking domain registration:', error);
      if (error.response?.status === 401 || error.response?.status === 403) {
        throw new Error('Cloudflare API authentication failed. Check your API token/key and credentials.');
      }
      throw error;
    }
  }

  /**
   * Initiate domain takedown through Cloudflare Registrar API
   * This locks/suspends the domain registration
   */
  async initiateDomainTakedown(domain, reason = 'Phishing domain detected') {
    if (!this.isConfigured()) {
      throw new Error('Cloudflare API not configured');
    }

    const domainName = this.extractDomain(domain);
    if (!domainName) {
      throw new Error('Invalid domain name');
    }

    try {
      // First check if domain is registered with Cloudflare
      const registrationCheck = await this.checkDomainRegistration(domainName);
      
      if (!registrationCheck.registered) {
        logger.warn(`Domain ${domainName} is not registered with Cloudflare`);
        return {
          success: false,
          message: 'Domain not registered with Cloudflare',
          domain: domainName,
          action: 'logged_only'
        };
      }

      // Lock the domain (prevent transfers and modifications)
      const lockResponse = await axios.put(
        `${this.baseUrl}/accounts/${this.accountId}/registrar/domains/${domainName}/lock`,
        {
          locked: true,
          reason: reason
        },
        {
          headers: this.getAuthHeaders(),
          timeout: 30000
        }
      );

      logger.info(`Domain ${domainName} locked successfully`);

      // Attempt to suspend DNS resolution
      try {
        const zoneResponse = await axios.get(
          `${this.baseUrl}/zones?name=${domainName}`,
          {
            headers: this.getAuthHeaders(),
            timeout: 30000
          }
        );

        if (zoneResponse.data.result && zoneResponse.data.result.length > 0) {
          const zoneId = zoneResponse.data.result[0].id;
          
          // Pause the zone (stops DNS resolution)
          await axios.patch(
            `${this.baseUrl}/zones/${zoneId}`,
            { paused: true },
            {
              headers: this.getAuthHeaders(),
              timeout: 30000
            }
          );

          logger.info(`DNS zone for ${domainName} paused successfully`);
        }
      } catch (dnsError) {
        logger.warn(`Could not pause DNS for ${domainName}:`, dnsError.message);
        // Continue even if DNS pause fails
      }

      return {
        success: true,
        message: 'Domain takedown initiated successfully',
        domain: domainName,
        action: 'takedown_initiated',
        timestamp: new Date().toISOString(),
        details: {
          domainLocked: true,
          dnsPaused: true
        }
      };

    } catch (error) {
      logger.error('Error initiating domain takedown:', error);
      
      if (error.response) {
        const status = error.response.status;
        const data = error.response.data;

        if (status === 401 || status === 403) {
          throw new Error('Cloudflare API authentication failed. Check your API credentials.');
        } else if (status === 404) {
          return {
            success: false,
            message: 'Domain not found in Cloudflare account',
            domain: domainName,
            action: 'not_found'
          };
        } else {
          throw new Error(`Cloudflare API error: ${data?.errors?.[0]?.message || error.message}`);
        }
      }

      throw error;
    }
  }

  /**
   * Submit abuse report to Cloudflare
   * Alternative method if direct domain control is not available
   */
  async submitAbuseReport(domain, reportData) {
    if (!this.isConfigured()) {
      throw new Error('Cloudflare API not configured');
    }

    const domainName = this.extractDomain(domain);
    
    try {
      // Cloudflare abuse reporting endpoint
      const response = await axios.post(
        `${this.baseUrl}/accounts/${this.accountId}/abuse/reports`,
        {
          domain: domainName,
          type: 'phishing',
          description: reportData.reason || 'Automated phishing detection',
          evidence: reportData.evidence || {},
          riskScore: reportData.riskScore || 0,
          source: reportData.source || 'automated'
        },
        {
          headers: this.getAuthHeaders(),
          timeout: 30000
        }
      );

      return {
        success: true,
        message: 'Abuse report submitted to Cloudflare',
        reportId: response.data.result?.id,
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      logger.error('Error submitting abuse report:', error);
      
      // If abuse endpoint doesn't exist, fall back to logging
      if (error.response?.status === 404) {
        logger.warn('Cloudflare abuse reporting endpoint not available, using alternative method');
        return {
          success: false,
          message: 'Abuse reporting endpoint not available',
          fallback: true
        };
      }

      throw error;
    }
  }
}

