import axios from 'axios';
import { logger } from '../utils/logger.js';
import { GoogleSafeBrowsingService } from './googleSafeBrowsing.js';

export class APIValidator {
  constructor() {
    // Load environment variables (in case they're loaded after class definition)
    this.loadEnvVars();
    
    // Initialize Google Safe Browsing service
    this.googleSafeBrowsing = new GoogleSafeBrowsingService();
    
    // Rate limiting
    this.lastVirusTotalCall = 0;
    this.lastUrlhausCall = 0;
    
    this.virusTotalDelay = 15000; // 15 seconds between calls (free tier)
    this.urlhausDelay = 2000; // 2 seconds between calls (public API is generous)
  }

  loadEnvVars() {
    // Reload environment variables
    this.virusTotalKey = process.env.VIRUSTOTAL_API_KEY?.trim() || null;
    this.urlhausAuthKey = process.env.URLHAUS_AUTH_KEY?.trim() || null;
    
    // Don't log warnings here - env vars might not be loaded yet during module initialization
    // Warnings will be shown when the API is actually used (in checkVirusTotal)
  }

  async validateURL(url) {
    const results = {
      virusTotal: null,
      urlhaus: null,
      googleSafeBrowsing: null,
      validatedAt: new Date()
    };

    // Run validations in parallel where possible
    const validationPromises = [];

    // Always try VirusTotal, it will return error if not configured
    validationPromises.push(this.checkVirusTotal(url).catch(err => ({ error: err.message })));

    // URLhaus doesn't require API key for basic queries
    validationPromises.push(this.checkUrlhaus(url).catch(err => ({ error: err.message })));

    // Google Safe Browsing (if configured)
    validationPromises.push(this.checkGoogleSafeBrowsing(url).catch(err => ({ error: err.message })));

    try {
      const validationResults = await Promise.allSettled(validationPromises);
      
      let index = 0;
      // VirusTotal result (always present now)
      results.virusTotal = validationResults[index].status === 'fulfilled' ? 
        validationResults[index].value : { error: validationResults[index].reason?.message || 'Unknown error' };
      index++;
      
      // URLhaus result
      results.urlhaus = validationResults[index].status === 'fulfilled' ? 
        validationResults[index].value : { error: validationResults[index].reason?.message || 'Unknown error' };
      index++;

      // Google Safe Browsing result
      results.googleSafeBrowsing = validationResults[index].status === 'fulfilled' ? 
        validationResults[index].value : { error: validationResults[index].reason?.message || 'Unknown error' };
      
    } catch (error) {
      logger.error('Error in API validation:', error);
      results.error = error.message;
    }

    return results;
  }

  /**
   * Check URL using Google Safe Browsing API
   */
  async checkGoogleSafeBrowsing(url) {
    return await this.googleSafeBrowsing.checkUrl(url);
  }

  async checkVirusTotal(url) {
    // Re-check environment variable in case it was loaded after class instantiation
    this.loadEnvVars();
    
    if (!this.virusTotalKey) {
      logger.warn('VirusTotal API key not configured - skipping VirusTotal check');
      logger.warn('  To fix: Add VIRUSTOTAL_API_KEY=your_key_here to .env file in PhishHawk-backend directory');
      logger.warn('  Make sure there are no spaces around the = sign');
      logger.warn('  Make sure the .env file is in the same directory as server.js');
      return { error: 'VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env file.' };
    }

    // Rate limiting
    const now = Date.now();
    const timeSinceLastCall = now - this.lastVirusTotalCall;
    if (timeSinceLastCall < this.virusTotalDelay) {
      await new Promise(resolve => 
        setTimeout(resolve, this.virusTotalDelay - timeSinceLastCall)
      );
    }

    try {
      // Use VirusTotal v3 API
      const urlId = Buffer.from(url).toString('base64url').replace(/=+$/, '');
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/urls/${urlId}`,
        {
          headers: {
            'x-apikey': this.virusTotalKey
          },
          timeout: 30000
        }
      );

      this.lastVirusTotalCall = Date.now();

      const data = response.data;
      const stats = data.data?.attributes?.last_analysis_stats || {};
      
      return {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0),
        scanDate: data.data?.attributes?.last_analysis_date,
        permalink: data.data?.links?.self
      };

    } catch (error) {
      if (error.response?.status === 404) {
        // URL not in database, submit for analysis
        return await this.submitToVirusTotal(url);
      }
      logger.error('VirusTotal API error:', error);
      throw error;
    }
  }

  async submitToVirusTotal(url) {
    try {
      const response = await axios.post(
        'https://www.virustotal.com/api/v3/urls',
        new URLSearchParams({ url }),
        {
          headers: {
            'x-apikey': this.virusTotalKey,
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 30000
        }
      );

      return {
        submitted: true,
        message: 'URL submitted for analysis',
        analysisId: response.data.data?.id
      };
    } catch (error) {
      logger.error('Error submitting to VirusTotal:', error);
      return {
        error: error.message,
        submitted: false
      };
    }
  }

  async checkUrlhaus(url) {
    // Rate limiting
    const now = Date.now();
    const timeSinceLastCall = now - this.lastUrlhausCall;
    if (timeSinceLastCall < this.urlhausDelay) {
      await new Promise(resolve => 
        setTimeout(resolve, this.urlhausDelay - timeSinceLastCall)
      );
    }

    try {
      // URLhaus API v1 - query by URL
      // Documentation: https://urlhaus.abuse.ch/api/
      const headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
      };
      
      // Optional: Add Auth-Key header if available (for higher rate limits)
      if (this.urlhausAuthKey) {
        headers['API-KEY'] = this.urlhausAuthKey;
      }

      const response = await axios.post(
        'https://urlhaus.abuse.ch/api/v1/url/',
        new URLSearchParams({
          url: url
        }),
        {
          headers: headers,
          timeout: 30000
        }
      );

      this.lastUrlhausCall = Date.now();

      const data = response.data;
      
      // URLhaus API v1 response structure (from official docs):
      // query_status: 'ok' (found) or 'no_results' (not found)
      // url_status: 'online' (active), 'offline' (was active but now down), or 'unknown'
      // id: URLhaus database ID
      // date_added: ISO timestamp when URL was first added
      // url: The queried URL
      // urlhaus_reference: Link to URLhaus page
      // threat: Threat type (usually 'malware_download')
      // tags: Array of tags
      // payloads: Array of payload information
      // host: Hostname/IP
      // lastseen: Last time URL was seen active
      
      if (data.query_status === 'ok') {
        // URL found in URLhaus - it's a known malware URL
        const isMalicious = true; // If it's in URLhaus, it's malicious
        const isActive = data.url_status === 'online';
        
        return {
          isPhish: isMalicious,
          verified: isActive,
          verifiedTime: data.date_added || null,
          urlhausId: data.id || null,
          urlStatus: data.url_status || null,
          threat: data.threat || 'malware_download',
          tags: Array.isArray(data.tags) ? data.tags : (data.tags ? [data.tags] : []),
          payloads: Array.isArray(data.payloads) ? data.payloads : [],
          host: data.host || null,
          details: data.urlhaus_reference || `https://urlhaus.abuse.ch/url/${data.id}/`,
          firstSeen: data.date_added || null,
          lastSeen: data.lastseen || null,
          queryStatus: data.query_status,
          url: data.url || url
        };
      } else if (data.query_status === 'no_results') {
        // URL not found in URLhaus database - not a known malware URL
        return {
          isPhish: false,
          verified: false,
          urlStatus: 'not_found',
          queryStatus: 'no_results',
          message: 'URL not found in URLhaus database'
        };
      } else {
        // Unknown response format
        logger.warn('URLhaus returned unexpected query_status:', data.query_status);
        return {
          isPhish: false,
          verified: false,
          urlStatus: 'unknown',
          queryStatus: data.query_status || 'unknown',
          rawResponse: data
        };
      }

    } catch (error) {
      // Handle different error cases
      if (error.response?.status === 404 || error.response?.status === 400) {
        // URL not found or invalid request
        return {
          isPhish: false,
          verified: false,
          urlStatus: 'not_found',
          queryStatus: 'no_results',
          error: error.response?.data?.query_status || 'URL not found in URLhaus database'
        };
      }
      
      logger.error('URLhaus API error:', error.response?.data || error.message);
      return {
        error: error.response?.data?.query_status || error.message || 'URLhaus API error',
        isPhish: false
      };
    }
  }
}
