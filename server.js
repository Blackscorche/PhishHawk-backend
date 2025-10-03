// server.js - Main Express Server
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// Import modules
const RiskAnalyzer = require('./services/riskAnalyzer');
const APIValidator = require('./services/apiValidator');
const TakedownService = require('./services/takedownService');
const URLScraper = require('./services/urlScraper');
const logger = require('./utils/logger');

// Import models
const URL = require('./models/URL');
const Takedown = require('./models/Takedown');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/phishing_takedown';

// Initialize services
const riskAnalyzer = new RiskAnalyzer();
const apiValidator = new APIValidator();
const takedownService = new TakedownService();
const urlScraper = new URLScraper();

// MongoDB Connection
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => logger.info('✅ Connected to MongoDB'))
.catch(err => {
  logger.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Validation middleware
const validateURL = [
  body('url').isURL().withMessage('Invalid URL format'),
  body('source').optional().isString().trim(),
  body('priority').optional().isIn(['low', 'medium', 'high']).withMessage('Priority must be low, medium, or high')
];

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Submit URL for analysis
app.post('/api/urls', validateURL, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { url, source = 'manual', priority = 'medium' } = req.body;
    
    // Check if URL already exists
    const existingUrl = await URL.findOne({ url });
    if (existingUrl) {
      return res.json({
        success: true,
        data: existingUrl,
        message: 'URL already in system'
      });
    }

    // Initial risk analysis
    const analysisResult = await riskAnalyzer.analyzeURL(url);
    
    // Third-party validation if high risk
    let validationResults = null;
    if (analysisResult.score >= 70) {
      validationResults = await apiValidator.validateURL(url);
    }

    // Create new URL document
    const urlDoc = new URL({
      url,
      source,
      priority,
      riskScore: analysisResult.score,
      riskChecks: analysisResult.checks,
      validationResults,
      status: analysisResult.score >= 80 ? 'high_risk' : 
              analysisResult.score >= 50 ? 'medium_risk' : 'low_risk'
    });

    const savedUrl = await urlDoc.save();
    
    // Auto-initiate takedown if high risk
    if (analysisResult.score >= 80) {
      setTimeout(async () => {
        try {
          await takedownService.initiateTakedown(savedUrl);
          savedUrl.status = 'takedown_initiated';
          await savedUrl.save();
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

  // Additional method for batch analysis
  async analyzeBatch(urls) {
    const results = [];
    const batchSize = 3;
    
    for (let i = 0; i < urls.length; i += batchSize) {
      const batch = urls.slice(i, i + batchSize);
      const batchPromises = batch.map(url => this.analyzeURL(url));
      
      try {
        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults);
      } catch (error) {
        logger.error('Error in batch analysis:', error);
        // Add error results for failed batch
        batch.forEach(url => {
          results.push({
            score: 50,
            checks: { error: 'Batch analysis failed' },
            error: 'Batch analysis failed'
          });
        });
      }
      
      // Small delay between batches
      if (i + batchSize < urls.length) {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }
    
    return results;
  }
}

module.exports = RiskAnalyzer;

// =============================================================================
// services/apiValidator.js - Third-party API Validation Service
const axios = require('axios');
const logger = require('../utils/logger');

class APIValidator {
  constructor() {
    this.virusTotalKey = process.env.VIRUSTOTAL_API_KEY;
    this.phishTankKey = process.env.PHISHTANK_API_KEY;
    this.urlVoidKey = process.env.URLVOID_API_KEY;
    
    // Rate limiting
    this.lastVirusTotalCall = 0;
    this.lastPhishTankCall = 0;
    this.lastUrlVoidCall = 0;
    
    this.virusTotalDelay = 15000; // 15 seconds between calls (free tier)
    this.phishTankDelay = 30000; // 30 seconds between calls
    this.urlVoidDelay = 10000; // 10 seconds between calls
  }

  async validateURL(url) {
    const results = {
      virusTotal: null,
      phishTank: null,
      urlVoid: null,
      validatedAt: new Date()
    };

    // Run validations in parallel where possible
    const validationPromises = [];

    if (this.virusTotalKey) {
      validationPromises.push(this.checkVirusTotal(url));
    }

    if (this.phishTankKey) {
      validationPromises.push(this.checkPhishTank(url));
    }

    if (this.urlVoidKey) {
      validationPromises.push(this.checkUrlVoid(url));
    }

    try {
      const validationResults = await Promise.allSettled(validationPromises);
      
      let index = 0;
      if (this.virusTotalKey) {
        results.virusTotal = validationResults[index].status === 'fulfilled' ? 
          validationResults[index].value : { error: validationResults[index].reason.message };
        index++;
      }
      
      if (this.phishTankKey) {
        results.phishTank = validationResults[index].status === 'fulfilled' ? 
          validationResults[index].value : { error: validationResults[index].reason.message };
        index++;
      }
      
      if (this.urlVoidKey) {
        results.urlVoid = validationResults[index].status === 'fulfilled' ? 
          validationResults[index].value : { error: validationResults[index].reason.message };
      }
      
    } catch (error) {
      logger.error('Error in API validation:', error);
      results.error = error.message;
    }

    return results;
  }

  async checkVirusTotal(url) {
    if (!this.virusTotalKey) {
      throw new Error('VirusTotal API key not configured');
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
      // First, submit URL for analysis
      const submitResponse = await axios.post(
        'https://www.virustotal.com/vtapi/v2/url/scan',
        new URLSearchParams({
          apikey: this.virusTotalKey,
          url: url
        }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 30000
        }
      );

      this.lastVirusTotalCall = Date.now();

      if (submitResponse.data.response_code !== 1) {
        throw new Error('Failed to submit URL to VirusTotal');
      }

      // Wait a moment then get the report
      await new Promise(resolve => setTimeout(resolve, 5000));

      const reportResponse = await axios.post(
        'https://www.virustotal.com/vtapi/v2/url/report',
        new URLSearchParams({
          apikey: this.virusTotalKey,
          resource: url
        }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 30000
        }
      );

      const report = reportResponse.data;
      
      if (report.response_code === 1) {
        return {
          malicious: report.positives || 0,
          total: report.total || 0,
          scanDate: report.scan_date,
          permalink: report.permalink,
          scans: report.scans
        };
      } else {
        return {
          malicious: 0,
          total: 0,
          status: 'not_found'
        };
      }

    } catch (error) {
      logger.error('VirusTotal API error:', error);
      throw error;
    }
  }

  async checkPhishTank(url) {
    if (!this.phishTankKey) {
      throw new Error('PhishTank API key not configured');
    }

    // Rate limiting
    const now = Date.now();
    const timeSinceLastCall = now - this.lastPhishTankCall;
    if (timeSinceLastCall < this.phishTankDelay) {
      await new Promise(resolve => 
        setTimeout(resolve, this.phishTankDelay - timeSinceLastCall)
      );
    }

    try {
      const response = await axios.post(
        'https://checkurl.phishtank.com/checkurl/',
        new URLSearchParams({
          url: url,
          format: 'json',
          app_key: this.phishTankKey
        }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 30000
        }
      );

      this.lastPhishTankCall = Date.now();

      const data = response.data;
      
      return {
        isPhish: data.results?.in_database || false,
        verified: data.results?.verified || false,
        verifiedTime: data.results?.verified_time || null,
        phishId: data.results?.phish_id || null,
        details: data.results?.phish_detail_url || null
      };

    } catch (error) {
      logger.error('PhishTank API error:', error);
      throw error;
    }
  }

  async checkUrlVoid(url) {
    if (!this.urlVoidKey) {
      throw new Error('URLVoid API key not configured');
    }

    // Rate limiting
    const now = Date.now();
    const timeSinceLastCall = now - this.lastUrlVoidCall;
    if (timeSinceLastCall < this.urlVoidDelay) {
      await new Promise(resolve => 
        setTimeout(resolve, this.urlVoidDelay - timeSinceLastCall)
      );
    }

    try {
      // Extract domain from URL
      const domain = new URL(url).hostname;
      
      const response = await axios.get(
        `https://api.urlvoid.com/v1/pay-as-you-go/?key=${this.urlVoidKey}&host=${domain}`,
        { timeout: 30000 }
      );

      this.lastUrlVoidCall = Date.now();

      const data = response.data;
      
      return {
        detections: data.detections?.engines?.count || 0,
        totalEngines: data.detections?.engines?.total || 0,
        engines: data.detections?.engines?.detection || [],
        reputation: data.reputation || 'unknown'
      };

    } catch (error) {
      logger.error('URLVoid API error:', error);
      throw error;
    }
  }
}

module.exports = APIValidator;

// =============================================================================
// services/takedownService.js - Automated Takedown Service
const nodemailer = require('nodemailer');
const axios = require('axios');
const Takedown = require('../models/Takedown');
const logger = require('../utils/logger');

class TakedownService {
  constructor() {
    this.emailTransporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: process.env.SMTP_PORT || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    this.providers = {
      cloudflare: {
        name: 'Cloudflare',
        email: 'abuse@cloudflare.com',
        formUrl: 'https://www.cloudflare.com/abuse/form/',
        priority: 1
      },
      google: {
        name: 'Google Safe Browsing',
        formUrl: 'https://safebrowsing.google.com/safebrowsing/report_phish/',
        priority: 2
      },
      microsoft: {
        name: 'Microsoft',
        formUrl: 'https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site',
        email: 'phish@microsoft.com',
        priority: 2
      },
      namecheap: {
        name: 'Namecheap',
        email: 'abuse@namecheap.com',
        priority: 3
      },
      godaddy: {
        name: 'GoDaddy',
        email: 'abuse@godaddy.com',
        priority: 3
      }
    };
  }

  async initiateTakedown(urlDoc, customReason = null) {
    try {
      logger.info(`Initiating takedown for ${urlDoc.url}`);
      
      // Determine the hosting provider/registrar
      const providers = await this.identifyProviders(urlDoc.url);
      
      const takedownResults = [];
      
      // Send takedown requests to identified providers
      for (const provider of providers) {
        try {
          const takedownDoc = new Takedown({
            urlId: urlDoc._id,
            provider: provider.name.toLowerCase().replace(/\s+/g, '_'),
            contactMethod: provider.email ? 'email' : 'form',
            contactInfo: {
              email: provider.email,
              formUrl: provider.formUrl
            },
            reason: customReason || this.generateReason(urlDoc),
            evidence: {
              riskAnalysis: {
                score: urlDoc.riskScore,
                checks: urlDoc.riskChecks
              },
              validationResults: urlDoc.validationResults
            }
          });

          if (provider.email) {
            const emailResult = await this.sendTakedownEmail(provider, urlDoc, takedownDoc.reason);
            takedownDoc.response = emailResult;
            takedownDoc.status = 'sent';
          } else {
            // For form-based submissions, we'll mark as pending and log the form URL
            takedownDoc.status = 'pending';
            logger.info(`Manual form submission required for ${provider.name}: ${provider.formUrl}`);
          }

          await takedownDoc.save();
          takedownResults.push(takedownDoc);

        } catch (providerError) {
          logger.error(`Error processing provider ${provider.name}:`, providerError);
        }
      }

      logger.info(`Takedown initiated for ${urlDoc.url}, ${takedownResults.length} requests sent`);
      
      return {
        success: true,
        requests: takedownResults,
        message: `Takedown requests sent to ${takedownResults.length} provider(s)`
      };

    } catch (error) {
      logger.error('Error initiating takedown:', error);
      throw error;
    }
  }

  async identifyProviders(url) {
    try {
      const domain = new URL(url).hostname;
      const providers = [];

      // Use whois lookup or DNS queries to identify hosting/registrar
      // For now, we'll use some common patterns and default providers

      // Check for Cloudflare (common CDN/security service)
      try {
        const response = await axios.get(url, { 
          timeout: 5000, 
          validateStatus: () => true,
          maxRedirects: 0
        });
        
        if (response.headers['server']?.includes('cloudflare') || 
            response.headers['cf-ray']) {
          providers.push(this.providers.cloudflare);
        }
      } catch (error) {
        // Ignore errors, just checking for Cloudflare headers
      }

      // Always add Google Safe Browsing and Microsoft
      providers.push(this.providers.google);
      providers.push(this.providers.microsoft);

      // Add common registrars based on domain patterns
      if (domain.includes('godaddy') || this.isCommonTLD(domain)) {
        providers.push(this.providers.godaddy);
      }
      
      if (domain.includes('namecheap')) {
        providers.push(this.providers.namecheap);
      }

      // Sort by priority
      providers.sort((a, b) => a.priority - b.priority);

      return providers.slice(0, 3); // Limit to top 3 providers

    } catch (error) {
      logger.error('Error identifying providers:', error);
      // Return default providers
      return [this.providers.google, this.providers.microsoft];
    }
  }

  isCommonTLD(domain) {
    const commonTLDs = ['.com', '.net', '.org', '.info', '.biz'];
    return commonTLDs.some(tld => domain.endsWith(tld));
  }

  generateReason(urlDoc) {
    const reason = `
AUTOMATED PHISHING REPORT

URL: ${urlDoc.url}
Risk Score: ${urlDoc.riskScore}/100
Detection Date: ${urlDoc.createdAt}

This URL has been automatically identified as a potential phishing threat based on the following analysis:

Risk Factors Detected:
${this.formatRiskChecks(urlDoc.riskChecks)}

${urlDoc.validationResults ? this.formatValidationResults(urlDoc.validationResults) : ''}

This automated report is generated by our phishing detection system. Please investigate and take appropriate action to protect users from this potential threat.

For questions or additional information, please contact our security team.

Best regards,
Automated Security Response Team
    `.trim();

    return reason;
  }

  formatRiskChecks(checks) {
    const messages = [];
    
    if (checks.suspiciousTLD) messages.push('• Suspicious top-level domain detected');
    if (checks.suspiciousKeywords) messages.push(`• Suspicious keywords found: ${checks.suspiciousKeywords.join(', ')}`);
    if (checks.excessiveSubdomains) messages.push(`• Excessive subdomains (${checks.excessiveSubdomains})`);
    if (checks.urlShortener) messages.push('• URL shortening service detected');
    if (checks.ipInDomain) messages.push('• IP address in domain name');
    if (checks.insecureProtocol) messages.push('• Insecure HTTP protocol');
    if (checks.passwordForm) messages.push('• Password collection form detected');
    if (checks.likelyLoginPage) messages.push('• Likely fake login page');
    if (checks.urgentLanguage) messages.push('• Urgent/threatening language detected');
    
    return messages.length > 0 ? messages.join('\n') : '• Multiple risk indicators detected';
  }

  formatValidationResults(validation) {
    let result = '\nThird-party Validation Results:\n';
    
    if (validation.virusTotal && !validation.virusTotal.error) {
      result += `• VirusTotal: ${validation.virusTotal.malicious}/${validation.virusTotal.total} engines flagged as malicious\n`;
    }
    
    if (validation.phishTank && !validation.phishTank.error) {
      result += `• PhishTank: ${validation.phishTank.isPhish ? 'Confirmed phishing site' : 'Not in phishing database'}\n`;
    }
    
    if (validation.urlVoid && !validation.urlVoid.error) {
      result += `• URLVoid: ${validation.urlVoid.detections}/${validation.urlVoid.totalEngines} engines detected threats\n`;
    }
    
    return result;
  }

  async sendTakedownEmail(provider, urlDoc, reason) {
    try {
      const mailOptions = {
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: provider.email,
        subject: `Phishing Report - ${urlDoc.url}`,
        text: reason,
        html: this.generateEmailHTML(urlDoc, reason)
      };

      const result = await this.emailTransporter.sendMail(mailOptions);
      
      logger.info(`Takedown email sent to ${provider.email} for ${urlDoc.url}`);
      
      return {
        messageId: result.messageId,
        sentAt: new Date(),
        recipient: provider.email,
        success: true
      };

    } catch (error) {
      logger.error(`Failed to send takedown email to ${provider.email}:`, error);
      return {
        error: error.message,
        sentAt: new Date(),
        recipient: provider.email,
        success: false
      };
    }
  }

  generateEmailHTML(urlDoc, reason) {
    return `
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #d32f2f;">🚨 AUTOMATED PHISHING REPORT</h2>
      
      <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <strong>Malicious URL:</strong> <code>${urlDoc.url}</code><br>
        <strong>Risk Score:</strong> <span style="color: #d32f2f; font-weight: bold;">${urlDoc.riskScore}/100</span><br>
        <strong>Detection Date:</strong> ${urlDoc.createdAt}<br>
        <strong>Status:</strong> ${urlDoc.status.replace('_', ' ').toUpperCase()}
      </div>

      <h3>Risk Analysis Details:</h3>
      <div style="background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107;">
        ${this.formatRiskChecks(urlDoc.riskChecks).replace(/\n/g, '<br>').replace(/•/g, '&#8226;')}
      </div>

      ${urlDoc.validationResults ? `
      <h3>Third-party Validation:</h3>
      <div style="background-color: #d1ecf1; padding: 10px; border-left: 4px solid #bee5eb;">
        ${this.formatValidationResults(urlDoc.validationResults).replace(/\n/g, '<br>').replace(/•/g, '&#8226;')}
      </div>
      ` : ''}

      <p style="margin-top: 30px;">
        This automated report is generated by our phishing detection system. 
        Please investigate and take appropriate action to protect users from this potential threat.
      </p>

      <hr style="margin: 30px 0;">
      <p style="color: #6c757d; font-size: 12px;">
        This is an automated message from our security monitoring system.<br>
        For questions or additional information, please contact our security team.
      </p>
    </body>
    </html>
    `;
  }

  // Method to update takedown status (for manual updates or webhook responses)
  async updateTakedownStatus(takedownId, status, response = null) {
    try {
      const takedown = await Takedown.findById(takedownId);
      if (!takedown) {
        throw new Error('Takedown request not found');
      }

      takedown.status = status;
      if (response) {
        takedown.response = { ...takedown.response, ...response };
      }
      
      if (status === 'completed') {
        takedown.completedAt = new Date();
      }

      await takedown.save();
      
      logger.info(`Takedown ${takedownId} status updated to ${status}`);
      return takedown;

    } catch (error) {
      logger.error('Error updating takedown status:', error);
      throw error;
    }
  }
}

module.exports = TakedownService;

// =============================================================================
// services/urlScraper.js - Automated URL Discovery Service
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const logger = require('../utils/logger');

class URLScraper {
  constructor() {
    this.isRunning = false;
    this.intervalIds = [];
    this.scrapingCallbacks = [];
  }

  startScraping(sources, interval, callback) {
    if (this.isRunning) {
      logger.warn('URL scraping is already running');
      return;
    }

    this.isRunning = true;
    this.scrapingCallbacks.push(callback);
    
    logger.info(`Starting URL scraping with sources: ${sources.join(', ')}`);

    // Set up interval for each source
    sources.forEach(source => {
      const intervalId = setInterval(async () => {
        try {
          const urls = await this.scrapeSource(source);
          if (urls.length > 0) {
            logger.info(`Found ${urls.length} URLs from ${source}`);
            this.scrapingCallbacks.forEach(cb => cb(urls));
          }
        } catch (error) {
          logger.error(`Error scraping ${source}:`, error);
        }
      }, interval);

      this.intervalIds.push(intervalId);
    });
  }

  stopScraping() {
    if (!this.isRunning) {
      return;
    }

    this.intervalIds.forEach(id => clearInterval(id));
    this.intervalIds = [];
    this.scrapingCallbacks = [];
    this.isRunning = false;
    
    logger.info('URL scraping stopped');
  }

  async scrapeSource(source) {
    switch (source) {
      case 'twitter':
        return await this.scrapeTwitter();
      case 'rss':
        return await this.scrapeRSSFeeds();
      case 'phishtank':
        return await this.scrapePhishTank();
      case 'urlscan':
        return await this.scrapeURLScan();
      default:
        logger.warn(`Unknown scraping source: ${source}`);
        return [];
    }
  }

  async scrapeTwitter() {
    // Note: This is a placeholder implementation
    // In production, you'd use Twitter API v2 with bearer token
    try {
      if (!process.env.TWITTER_BEARER_TOKEN) {
        logger.warn('Twitter Bearer Token not configured');
        return [];
      }

      // Search for phishing-related tweets
      const response = await axios.get(
        'https://api.twitter.com/2/tweets/search/recent',
        {
          headers: {
            'Authorization': `Bearer ${process.env.TWITTER_BEARER_TOKEN}`
          },
          params: {
            query: 'phishing OR "suspicious link" OR "fake website" url: -is:retweet',
            max_results: 20,
            'tweet.fields': 'created_at,author_id,public_metrics'
          },
          timeout: 30000
        }
      );

      const urls = [];
      if (response.data.data) {
        response.data.data.forEach(tweet => {
          const extractedUrls = this.extractURLs(tweet.text);
          extractedUrls.forEach(url => {
            urls.push({
              url,
              source: 'twitter',
              priority: 'medium',
              metadata: {
                tweetId: tweet.id,
                authorId: tweet.author_id,
                createdAt: tweet.created_at,
                text: tweet.text.substring(0, 200)
              }
            });
          });
        });
      }

      return urls;

    } catch (error) {
      logger.error('Error scraping Twitter:', error);
      return [];
    }
  }

  async scrapeRSSFeeds() {
    const feeds = [
      'https://feeds.feedburner.com/eset/blog',
      'https://krebsonsecurity.com/feed/',
      'https://threatpost.com/feed/'
    ];

    const urls = [];

    for (const feedUrl of feeds) {
      try {
        const response = await axios.get(feedUrl, { timeout: 30000 });
        const $ = cheerio.load(response.data, { xmlMode: true });

        $('item').each((i, item) => {
          const $item = $(item);
          const title = $item.find('title').text();
          const description = $item.find('description').text();
          const link = $item.find('link').text();

          // Look for phishing indicators in title and description
          const phishingIndicators = ['phishing', 'malicious', 'suspicious', 'scam', 'fake'];
          const hasPhishingContent = phishingIndicators.some(indicator => 
            title.toLowerCase().includes(indicator) || 
            description.toLowerCase().includes(indicator)
          );

          if (hasPhishingContent) {
            // Extract URLs from description
            const extractedUrls = this.extractURLs(description);
            extractedUrls.forEach(url => {
              urls.push({
                url,
                source: 'rss',
                priority: 'medium',
                metadata: {
                  feedUrl,
                  articleTitle: title,
                  articleLink: link,
                  description: description.substring(0, 300)
                }
              });
            });
          }
        });

      } catch (error) {
        logger.error(`Error scraping RSS feed ${feedUrl}:`, error);
      }
    }

    return urls;
  }

  async scrapePhishTank() {
    // Note: PhishTank requires API key for automated access
    try {
      if (!process.env.PHISHTANK_API_KEY) {
        logger.warn('PhishTank API key not configured');
        return [];
      }

      // This is a placeholder - PhishTank's API structure may differ
      const response = await axios.get(
        'https://data.phishtank.com/data/online-valid.json',
        { timeout: 60000 }
      );

      const urls = [];
      const recentData = response.data.slice(0, 50); // Get latest 50

      recentData.forEach(entry => {
        urls.push({
          url: entry.url,
          source: 'phishtank',
          priority: 'high',
          metadata: {
            phishId: entry.phish_id,
            submissionTime: entry.submission_time,
            verified: entry.verified,
            target: entry.target
          }
        });
      });

      return urls;

    } catch (error) {
      logger.error('Error scraping PhishTank:', error);
      return [];
    }
  }

  async scrapeURLScan() {
    try {
      // URLScan.io public API
      const response = await axios.get(
        'https://urlscan.io/api/v1/search/',
        {
          params: {
            q: 'page.status:200 AND (task.tags:phishing OR task.tags:malicious)',
            size: 20,
            sort: '_timestamp:desc'
          },
          timeout: 30000
        }
      );

      const urls = [];
      if (response.data.results) {
        response.data.results.forEach(result => {
          urls.push({
            url: result.page.url,
            source: 'urlscan',
            priority: 'high',
            metadata: {
              scanId: result._id,
              timestamp: result.task.time,
              country: result.page.country,
              server: result.page.server,
              title: result.page.title
            }
          });
        });
      }

      return urls;

    } catch (error) {
      logger.error('Error scraping URLScan:', error);
      return [];
    }
  }

  extractURLs(text) {
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
    const matches = text.match(urlRegex) || [];
    
    return matches
      .filter(url => {
        try {
          new URL(url);
          return true;
        } catch {
          return false;
        }
      })
      .filter(url => !this.isKnownSafeUrl(url));
  }

  isKnownSafeUrl(url) {
    const safeDomains = [
      'twitter.com', 'facebook.com', 'linkedin.com', 'youtube.com',
      'google.com', 'microsoft.com', 'github.com', 'stackoverflow.com'
    ];
    
    try {
      const domain = new URL(url).hostname.toLowerCase();
      return safeDomains.some(safe => domain === safe || domain.endsWith('.' + safe));
    } catch {
      return false;
    }
  }
}

module.exports = URLScraper;

// =============================================================================
// utils/logger.js - Logging Utility
const fs = require('fs');
const path = require('path');

class Logger {
  constructor() {
    this.logsDir = path.join(__dirname, '../logs');
    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true });
    }
    
    this.logFile = path.join(this.logsDir, `app-${this.getDateString()}.log`);
  }

  getDateString() {
    return new Date().toISOString(). (error) {
          logger.error('Auto-takedown failed:', error);
        }
      }, 1000);
    }

    res.status(201).json({
      success: true,
      data: savedUrl,
      message: analysisResult.score >= 80 ? 'High risk detected - takedown initiated' : 'URL analyzed successfully'
    });

  } catch (error) {
    logger.error('Error processing URL:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get all URLs with filtering and pagination
app.get('/api/urls', async (req, res) => {
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
      sort,
      populate: 'takedowns'
    };

    const result = await URL.paginate(query, options);
    
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

  } catch (error) {
    logger.error('Error fetching URLs:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch URLs'
    });
  }
});

// Get specific URL details
app.get('/api/urls/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const url = await URL.findById(id).populate('takedowns');
    
    if (!url) {
      return res.status(404).json({
        success: false,
        message: 'URL not found'
      });
    }

    res.json({
      success: true,
      data: url
    });

  } catch (error) {
    logger.error('Error fetching URL:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch URL details'
    });
  }
});

// Manually initiate takedown
app.post('/api/urls/:id/takedown', async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    
    const url = await URL.findById(id);
    if (!url) {
      return res.status(404).json({
        success: false,
        message: 'URL not found'
      });
    }

    const result = await takedownService.initiateTakedown(url, reason);
    url.status = 'takedown_initiated';
    await url.save();
    
    res.json({
      success: true,
      data: result,
      message: 'Takedown initiated successfully'
    });

  } catch (error) {
    logger.error('Error initiating takedown:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to initiate takedown'
    });
  }
});

// Re-analyze URL
app.post('/api/urls/:id/reanalyze', async (req, res) => {
  try {
    const { id } = req.params;
    const url = await URL.findById(id);
    
    if (!url) {
      return res.status(404).json({
        success: false,
        message: 'URL not found'
      });
    }

    const analysisResult = await riskAnalyzer.analyzeURL(url.url);
    let validationResults = null;
    
    if (analysisResult.score >= 70) {
      validationResults = await apiValidator.validateURL(url.url);
    }

    url.riskScore = analysisResult.score;
    url.riskChecks = analysisResult.checks;
    url.validationResults = validationResults;
    url.status = analysisResult.score >= 80 ? 'high_risk' : 
                 analysisResult.score >= 50 ? 'medium_risk' : 'low_risk';
    url.lastChecked = new Date();
    
    const updatedUrl = await url.save();

    res.json({
      success: true,
      data: updatedUrl,
      message: 'URL re-analyzed successfully'
    });

  } catch (error) {
    logger.error('Error re-analyzing URL:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to re-analyze URL'
    });
  }
});

// Get system metrics and statistics
app.get('/api/metrics', async (req, res) => {
  try {
    const [
      totalUrls,
      urlsByStatus,
      urlsByRisk,
      recentUrls,
      avgRiskScore,
      takedownStats
    ] = await Promise.all([
      URL.countDocuments(),
      URL.aggregate([
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ]),
      URL.aggregate([
        {
          $group: {
            _id: {
              $switch: {
                branches: [
                  { case: { $gte: ['$riskScore', 80] }, then: 'high' },
                  { case: { $gte: ['$riskScore', 50] }, then: 'medium' }
                ],
                default: 'low'
              }
            },
            count: { $sum: 1 }
          }
        }
      ]),
      URL.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }),
      URL.aggregate([
        { $group: { _id: null, avgRisk: { $avg: '$riskScore' } } }
      ]),
      Takedown.aggregate([
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ])
    ]);

    const metrics = {
      totalUrls,
      urlsByStatus: urlsByStatus.map(item => ({ status: item._id, count: item.count })),
      urlsByRisk: urlsByRisk.map(item => ({ risk_level: item._id, count: item.count })),
      recentUrls,
      averageRiskScore: Math.round(avgRiskScore[0]?.avgRisk || 0),
      takedownStats: takedownStats.map(item => ({ status: item._id, count: item.count })),
      lastUpdated: new Date().toISOString()
    };
    
    res.json({
      success: true,
      data: metrics
    });

  } catch (error) {
    logger.error('Error fetching metrics:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch metrics'
    });
  }
});

// Bulk URL submission
app.post('/api/urls/bulk', async (req, res) => {
  try {
    const { urls, source = 'bulk_import' } = req.body;
    
    if (!Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'URLs array is required and cannot be empty'
      });
    }

    if (urls.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Maximum 100 URLs per bulk request'
      });
    }

    const results = [];
    const batchSize = 5;
    
    for (let i = 0; i < urls.length; i += batchSize) {
      const batch = urls.slice(i, i + batchSize);
      const batchPromises = batch.map(async (url) => {
        try {
          // Check if URL already exists
          const existing = await URL.findOne({ url });
          if (existing) {
            return { url, status: 'exists', data: existing };
          }

          const analysisResult = await riskAnalyzer.analyzeURL(url);
          let validationResults = null;
          
          if (analysisResult.score >= 70) {
            validationResults = await apiValidator.validateURL(url);
          }

          const urlDoc = new URL({
            url,
            source,
            priority: 'medium',
            riskScore: analysisResult.score,
            riskChecks: analysisResult.checks,
            validationResults,
            status: analysisResult.score >= 80 ? 'high_risk' : 
                    analysisResult.score >= 50 ? 'medium_risk' : 'low_risk'
          });

          const savedUrl = await urlDoc.save();
          return { url, status: 'processed', data: savedUrl };
          
        } catch (error) {
          logger.error(`Error processing URL ${url}:`, error);
          return { url, status: 'error', error: error.message };
        }
      });

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      // Small delay between batches to avoid overwhelming APIs
      if (i + batchSize < urls.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    const summary = {
      total: urls.length,
      processed: results.filter(r => r.status === 'processed').length,
      existing: results.filter(r => r.status === 'exists').length,
      errors: results.filter(r => r.status === 'error').length
    };

    res.json({
      success: true,
      data: {
        results,
        summary
      }
    });

  } catch (error) {
    logger.error('Error processing bulk URLs:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process bulk URLs'
    });
  }
});

// Start automated scraping
app.post('/api/scraping/start', async (req, res) => {
  try {
    const { sources = ['twitter', 'rss'], interval = 300000 } = req.body; // 5 minutes default
    
    urlScraper.startScraping(sources, interval, async (foundUrls) => {
      // Process found URLs
      for (const urlData of foundUrls) {
        try {
          const existing = await URL.findOne({ url: urlData.url });
          if (!existing) {
            const analysisResult = await riskAnalyzer.analyzeURL(urlData.url);
            
            const urlDoc = new URL({
              ...urlData,
              riskScore: analysisResult.score,
              riskChecks: analysisResult.checks,
              status: analysisResult.score >= 80 ? 'high_risk' : 
                      analysisResult.score >= 50 ? 'medium_risk' : 'low_risk'
            });

            await urlDoc.save();
            logger.info(`Auto-scraped URL saved: ${urlData.url}`);
          }
        } catch (error) {
          logger.error(`Error processing scraped URL ${urlData.url}:`, error);
        }
      }
    });

    res.json({
      success: true,
      message: 'Automated scraping started',
      config: { sources, interval }
    });

  } catch (error) {
    logger.error('Error starting scraping:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to start automated scraping'
    });
  }
});

// Stop automated scraping
app.post('/api/scraping/stop', (req, res) => {
  try {
    urlScraper.stopScraping();
    res.json({
      success: true,
      message: 'Automated scraping stopped'
    });
  } catch (error) {
    logger.error('Error stopping scraping:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to stop scraping'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  urlScraper.stopScraping();
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  urlScraper.stopScraping();
  await mongoose.connection.close();
  process.exit(0);
});

app.listen(PORT, () => {
  logger.info(`🚀 Phishing Takedown API Server running on port ${PORT}`);
  logger.info(`📊 Health check available at http://localhost:${PORT}/health`);
  logger.info(`🗄️ Database: ${MONGO_URI}`);
});

module.exports = app;

// =============================================================================
// models/URL.js - Mongoose URL Model
const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

const urlSchema = new mongoose.Schema({
  url: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  source: {
    type: String,
    required: true,
    default: 'manual',
    enum: ['manual', 'twitter', 'rss', 'email', 'bulk_import', 'api']
  },
  priority: {
    type: String,
    required: true,
    default: 'medium',
    enum: ['low', 'medium', 'high']
  },
  riskScore: {
    type: Number,
    required: true,
    min: 0,
    max: 100
  },
  riskChecks: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  validationResults: {
    virusTotal: {
      malicious: { type: Number, default: 0 },
      suspicious: { type: Number, default: 0 },
      clean: { type: Number, default: 0 },
      unrated: { type: Number, default: 0 },
      timeout: { type: Number, default: 0 },
      confirmed_timeout: { type: Number, default: 0 },
      failure: { type: Number, default: 0 },
      type_unsupported: { type: Number, default: 0 }
    },
    phishTank: {
      isPhish: { type: Boolean, default: false },
      verified: { type: Boolean, default: false },
      verifiedTime: Date,
      url: String
    },
    urlVoid: {
      detections: { type: Number, default: 0 },
      engines: { type: Number, default: 0 }
    }
  },
  status: {
    type: String,
    required: true,
    default: 'pending',
    enum: [
      'pending', 'low_risk', 'medium_risk', 'high_risk',
      'takedown_initiated', 'takedown_sent', 'resolved', 'false_positive'
    ]
  },
  metadata: {
    title: String,
    description: String,
    screenshot: String,
    httpStatus: Number,
    contentType: String,
    serverInfo: String
  },
  geolocation: {
    country: String,
    city: String,
    coords: {
      latitude: Number,
      longitude: Number
    }
  }
}, {
  timestamps: true
});

// Virtual populate for takedowns
urlSchema.virtual('takedowns', {
  ref: 'Takedown',
  localField: '_id',
  foreignField: 'urlId'
});

// Indexes for better query performance
urlSchema.index({ url: 1 });
urlSchema.index({ status: 1 });
urlSchema.index({ riskScore: -1 });
urlSchema.index({ createdAt: -1 });
urlSchema.index({ source: 1 });
urlSchema.index({ priority: 1 });

// Add pagination plugin
urlSchema.plugin(mongoosePaginate);

// Pre-save middleware
urlSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model('URL', urlSchema);

// =============================================================================
// models/Takedown.js - Mongoose Takedown Model
const mongoose = require('mongoose');

const takedownSchema = new mongoose.Schema({
  urlId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'URL',
    required: true
  },
  provider: {
    type: String,
    required: true,
    enum: ['cloudflare', 'google', 'namecheap', 'godaddy', 'hosting_provider', 'isp', 'cert_authority', 'other']
  },
  contactMethod: {
    type: String,
    required: true,
    enum: ['email', 'form', 'api', 'phone']
  },
  contactInfo: {
    email: String,
    formUrl: String,
    apiEndpoint: String,
    phone: String
  },
  status: {
    type: String,
    required: true,
    default: 'pending',
    enum: ['pending', 'sent', 'acknowledged', 'in_progress', 'completed', 'rejected', 'expired']
  },
  reason: {
    type: String,
    default: 'Phishing website detection - automated report'
  },
  evidence: {
    screenshots: [String],
    riskAnalysis: mongoose.Schema.Types.Mixed,
    validationResults: mongoose.Schema.Types.Mixed
  },
  response: {
    ticketId: String,
    responseTime: Date,
    estimatedResolution: Date,
    finalResponse: String,
    resolved: { type: Boolean, default: false }
  },
  retries: {
    type: Number,
    default: 0
  },
  lastRetry: Date,
  completedAt: Date
}, {
  timestamps: true
});

// Indexes
takedownSchema.index({ urlId: 1 });
takedownSchema.index({ provider: 1 });
takedownSchema.index({ status: 1 });
takedownSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Takedown', takedownSchema);

// =============================================================================
// services/riskAnalyzer.js - URL Risk Analysis Service
const axios = require('axios');
const { URL } = require('url');
const logger = require('../utils/logger');

class RiskAnalyzer {
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
      
      // Check for homograph attacks (basic)
      if (/[а-я]/.test(domain) || /[α-ω]/.test(domain)) {
        riskScore += 30;
        checks.possibleHomograph = true;
      }
      
      // Path analysis
      const path = parsedUrl.pathname.toLowerCase();
      if (path.includes('..') || path.includes('%2e%2e')) {
        riskScore += 35;
        checks.pathTraversal = true;
      }
      
      // Check for excessive parameters
      const params = parsedUrl.searchParams;
      if (params.toString().length > 200) {
        riskScore += 20;
        checks.excessiveParams = params.toString().length;
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
      
    } catch
