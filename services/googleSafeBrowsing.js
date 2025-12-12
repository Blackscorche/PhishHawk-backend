import axios from 'axios';
import { logger } from '../utils/logger.js';

/**
 * Google Safe Browsing API Service
 * Alternative threat intelligence source for phishing detection
 * API Documentation: https://developers.google.com/safe-browsing/v4
 */
export class GoogleSafeBrowsingService {
  constructor() {
    this.apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    this.baseUrl = 'https://safebrowsing.googleapis.com/v4';
    this.clientId = 'phishhawk';
    this.clientVersion = '1.0.0';
  }

  /**
   * Check if the API is configured
   */
  isConfigured() {
    return !!this.apiKey;
  }

  /**
   * Check URL against Google Safe Browsing database
   * @param {string} url - URL to check
   * @returns {object} - Check result with threat information
   */
  async checkUrl(url) {
    if (!this.isConfigured()) {
      logger.info('Google Safe Browsing API not configured - skipping check');
      return { 
        error: 'Google Safe Browsing API key not configured',
        configured: false 
      };
    }

    try {
      const response = await axios.post(
        `${this.baseUrl}/threatMatches:find?key=${this.apiKey}`,
        {
          client: {
            clientId: this.clientId,
            clientVersion: this.clientVersion
          },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: url }]
          }
        },
        {
          headers: {
            'Content-Type': 'application/json'
          },
          timeout: 30000
        }
      );

      const matches = response.data.matches || [];
      
      if (matches.length > 0) {
        // URL found in Safe Browsing database - it's dangerous
        const threats = matches.map(m => ({
          type: m.threatType,
          platform: m.platformType,
          url: m.threat?.url
        }));

        logger.info(`[Google Safe Browsing] URL flagged: ${url} - ${threats.length} threats found`);
        
        return {
          isMalicious: true,
          threatCount: matches.length,
          threats: threats,
          threatTypes: [...new Set(matches.map(m => m.threatType))],
          details: matches
        };
      }

      // URL not found - considered safe by Google
      return {
        isMalicious: false,
        threatCount: 0,
        message: 'URL not found in Google Safe Browsing database'
      };

    } catch (error) {
      if (error.response?.status === 400) {
        logger.error('Google Safe Browsing API: Invalid request', error.response.data);
        return { error: 'Invalid request to Safe Browsing API' };
      }
      if (error.response?.status === 403) {
        logger.error('Google Safe Browsing API: Authentication failed');
        return { error: 'API key invalid or quota exceeded' };
      }
      
      logger.error('Google Safe Browsing API error:', error.message);
      return { error: error.message };
    }
  }

  /**
   * Check multiple URLs at once (batch check)
   * @param {string[]} urls - Array of URLs to check
   * @returns {object} - Results for all URLs
   */
  async checkUrls(urls) {
    if (!this.isConfigured()) {
      return { error: 'Google Safe Browsing API key not configured' };
    }

    if (!urls || urls.length === 0) {
      return { error: 'No URLs provided' };
    }

    // Google allows up to 500 URLs per request
    const maxUrls = Math.min(urls.length, 500);
    const urlsToCheck = urls.slice(0, maxUrls);

    try {
      const response = await axios.post(
        `${this.baseUrl}/threatMatches:find?key=${this.apiKey}`,
        {
          client: {
            clientId: this.clientId,
            clientVersion: this.clientVersion
          },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: urlsToCheck.map(url => ({ url }))
          }
        },
        {
          headers: {
            'Content-Type': 'application/json'
          },
          timeout: 60000
        }
      );

      const matches = response.data.matches || [];
      const maliciousUrls = new Set(matches.map(m => m.threat?.url));

      return {
        totalChecked: urlsToCheck.length,
        maliciousCount: maliciousUrls.size,
        maliciousUrls: [...maliciousUrls],
        matches: matches
      };

    } catch (error) {
      logger.error('Google Safe Browsing batch check error:', error.message);
      return { error: error.message };
    }
  }
}

export default GoogleSafeBrowsingService;
