import axios from 'axios';
import * as cheerio from 'cheerio';
import { logger } from '../utils/logger.js';

export class URLScraper {
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

    logger.info(`Starting URL scraping with sources: ${sources.join(', ')} (interval: ${interval/1000}s)`);

    // Set up interval for each source
    sources.forEach(source => {
      const intervalId = setInterval(async () => {
        try {
          const urls = await this.scrapeSource(source);
          if (urls.length > 0) {
            logger.info(`[Scraping] Found ${urls.length} URLs from ${source}`);
            this.scrapingCallbacks.forEach(cb => cb(urls));
          }
        } catch (error) {
          logger.error(`[Scraping] Error scraping ${source}:`, error.message);
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
      case 'urlhaus':
        return await this.scrapeUrlhaus();
      case 'openphish':
        return await this.scrapeOpenPhish();
      case 'phishtank':
        return await this.scrapePhishTank();
      case 'all':
        // Scrape from all sources
        return await this.scrapeAllSources();
      default:
        logger.warn(`Unknown scraping source: ${source}`);
        return [];
    }
  }

  async scrapeAllSources() {
    const allUrls = [];
    const sources = ['urlhaus', 'openphish', 'phishtank', 'rss'];
    
    logger.info('[Scraping] Fetching from all sources...');
    
    for (const source of sources) {
      try {
        const urls = await this.scrapeSource(source);
        if (urls.length > 0) {
          logger.info(`[Scraping] Found ${urls.length} URLs from ${source}`);
          allUrls.push(...urls);
        }
      } catch (error) {
        logger.warn(`[Scraping] Error scraping ${source}:`, error.message);
      }
    }
    
    // Remove duplicates
    const uniqueUrls = [];
    const seenUrls = new Set();
    
    for (const urlData of allUrls) {
      if (!seenUrls.has(urlData.url)) {
        seenUrls.add(urlData.url);
        uniqueUrls.push(urlData);
      }
    }
    
    logger.info(`[Scraping] Total unique URLs from all sources: ${uniqueUrls.length}`);
    return uniqueUrls;
  }

  async scrapeTwitter() {
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

  async scrapeUrlhaus() {
    try {
      // URLhaus API - Get recent malware URLs
      // Documentation: https://urlhaus.abuse.ch/api/
      // Try multiple endpoints to get URLs
      
      const urls = [];
      
      // Method 1: Try CSV recent feed (most reliable)
      try {
        const csvResponse = await axios.get(
          'https://urlhaus.abuse.ch/downloads/csv_recent/',
          { 
            timeout: 60000,
            headers: {
              'Accept': 'text/csv,text/plain',
              'User-Agent': 'PhishHawk/1.0'
            },
            responseType: 'text'
          }
        );

        if (csvResponse.data) {
          // Parse CSV format: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
          const lines = csvResponse.data.split('\n');
          logger.debug(`[URLhaus] CSV response has ${lines.length} lines, first 3 lines:`, lines.slice(0, 3));
          
          // Skip header line (starts with # or contains column names)
          const dataLines = lines.filter(line => {
            const trimmed = line.trim();
            return trimmed && 
                   !trimmed.startsWith('#') && 
                   !trimmed.toLowerCase().startsWith('id,dateadded') &&
                   !trimmed.toLowerCase().startsWith('dateadded') &&
                   trimmed.includes(',');
          });
          
          logger.debug(`[URLhaus] Found ${dataLines.length} data lines after filtering`);
          
          dataLines.forEach((line, index) => {
            try {
              // Handle CSV with quoted fields - split by comma but respect quotes
              const columns = [];
              let current = '';
              let inQuotes = false;
              
              for (let i = 0; i < line.length; i++) {
                const char = line[i];
                if (char === '"') {
                  inQuotes = !inQuotes;
                } else if (char === ',' && !inQuotes) {
                  columns.push(current.trim());
                  current = '';
                } else {
                  current += char;
                }
              }
              columns.push(current.trim()); // Add last column
              
              if (columns.length >= 3) {
                // URL is typically in column 2 (index 2) or column 3 (index 2)
                let url = columns[2]?.trim() || columns[3]?.trim();
                
                // Remove quotes if present
                url = url.replace(/^["']|["']$/g, '');
                
                // Validate and normalize URL
                if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
                  urls.push({
                    url: url,
                    source: 'urlhaus',
                    priority: 'high',
                    metadata: {
                      scrapedAt: new Date().toISOString(),
                      source: 'urlhaus_csv_recent',
                      dateAdded: columns[1]?.trim(),
                      threat: columns[4]?.trim() || columns[5]?.trim(),
                      tags: columns[5]?.trim() || columns[6]?.trim()
                    }
                  });
                } else if (index < 3) {
                  // Log first few failed parses for debugging
                  logger.debug(`[URLhaus] Line ${index} didn't produce valid URL. Columns:`, columns.slice(0, 5));
                }
              }
            } catch (parseError) {
              // Skip malformed lines
              if (index < 3) {
                logger.debug(`[URLhaus] Error parsing line ${index}:`, parseError.message);
              }
            }
          });
        }
        
        if (urls.length > 0) {
          logger.info(`[URLhaus] Scraped ${urls.length} URLs from CSV recent feed`);
          return urls.slice(0, 100); // Limit to 100 URLs
        } else {
          logger.warn(`[URLhaus] CSV feed returned data but no valid URLs extracted`);
        }
      } catch (csvError) {
        logger.warn(`[URLhaus] CSV feed failed: ${csvError.message}`);
        if (csvError.response) {
          logger.debug(`[URLhaus] Response status: ${csvError.response.status}, data preview:`, 
            csvError.response.data?.substring(0, 200));
        }
      }

      // Method 2: Try plain text online feed (active URLs)
      try {
        const textResponse = await axios.get(
          'https://urlhaus.abuse.ch/downloads/text_online/',
          {
            timeout: 60000,
            headers: { 'Accept': 'text/plain' },
            responseType: 'text'
          }
        );
        
        if (textResponse.data) {
          const urlLines = textResponse.data.split('\n')
            .map(line => line.trim())
            .filter(line => {
              // URLs should start with http:// or https://
              return line && (line.startsWith('http://') || line.startsWith('https://'));
            });
          
          urlLines.slice(0, 100).forEach((urlLine) => {
            // Avoid duplicates
            if (!urls.some(u => u.url === urlLine)) {
              urls.push({
                url: urlLine,
                source: 'urlhaus',
                priority: 'high',
                metadata: {
                  scrapedAt: new Date().toISOString(),
                  source: 'urlhaus_text_online'
                }
              });
            }
          });
        }
        
        if (urls.length > 0) {
          logger.info(`[URLhaus] Scraped ${urls.length} URLs from text online feed`);
          return urls.slice(0, 100);
        }
      } catch (textError) {
        logger.warn(`[URLhaus] Text feed failed: ${textError.message}`);
      }

      // Method 3: Try JSON API endpoint (if available)
      try {
        const jsonResponse = await axios.post(
          'https://urlhaus.abuse.ch/api/v1/downloads/recent/',
          {
            limit: 100
          },
          {
            timeout: 60000,
            headers: { 'Content-Type': 'application/json' }
          }
        );
        
        if (jsonResponse.data && Array.isArray(jsonResponse.data)) {
          jsonResponse.data.forEach((item) => {
            if (item.url && !urls.some(u => u.url === item.url)) {
              urls.push({
                url: item.url,
                source: 'urlhaus',
                priority: 'high',
                metadata: {
                  scrapedAt: new Date().toISOString(),
                  source: 'urlhaus_json_api',
                  dateAdded: item.dateadded,
                  threat: item.threat
                }
              });
            }
          });
        }
        
        if (urls.length > 0) {
          logger.info(`[URLhaus] Scraped ${urls.length} URLs from JSON API`);
          return urls.slice(0, 100);
        }
      } catch (jsonError) {
        // JSON API might not be available, that's okay
        logger.debug(`[URLhaus] JSON API not available: ${jsonError.message}`);
      }

      // If all methods failed, log warning
      if (urls.length === 0) {
        logger.warn('[URLhaus] All scraping methods failed - no URLs retrieved');
      } else {
        logger.info(`[URLhaus] Total scraped: ${urls.length} URLs`);
      }
      
      return urls.slice(0, 100);

    } catch (error) {
      logger.error('Error scraping URLhaus:', error.message);
      return [];
    }
  }

  async scrapeOpenPhish() {
    try {
      // OpenPhish provides a plain text feed of phishing URLs
      // Feed URL: https://openphish.com/feed.txt
      const response = await axios.get(
        'https://openphish.com/feed.txt',
        {
          timeout: 60000,
          headers: {
            'Accept': 'text/plain',
            'User-Agent': 'PhishHawk/1.0'
          },
          responseType: 'text'
        }
      );

      const urls = [];
      if (response.data) {
        const urlLines = response.data.split('\n')
          .map(line => line.trim())
          .filter(line => {
            return line && 
                   (line.startsWith('http://') || line.startsWith('https://')) &&
                   !line.startsWith('#');
          });
        
        urlLines.slice(0, 100).forEach((urlLine) => {
          urls.push({
            url: urlLine,
            source: 'openphish',
            priority: 'high',
            metadata: {
              scrapedAt: new Date().toISOString(),
              source: 'openphish_feed'
            }
          });
        });
      }

      logger.info(`[OpenPhish] Scraped ${urls.length} URLs from feed`);
      return urls;

    } catch (error) {
      logger.warn(`[OpenPhish] Scraping failed: ${error.message}`);
      return [];
    }
  }

  async scrapePhishTank() {
    try {
      // PhishTank API - requires API key but also has public feed
      // Public feed: https://www.phishtank.com/phish_search.php?format=json
      // For now, we'll use a simpler approach - PhishTank RSS feed
      
      // Try JSON API first (if API key is available)
      if (process.env.PHISHTANK_API_KEY) {
        try {
          const response = await axios.get(
            'https://checkurl.phishtank.com/checkurl/',
            {
              params: {
                format: 'json',
                app_key: process.env.PHISHTANK_API_KEY
              },
              timeout: 30000
            }
          );
          
          // PhishTank API is for checking URLs, not bulk feed
          // So we'll use RSS feed instead
        } catch (apiError) {
          logger.debug('[PhishTank] API check failed, using RSS feed');
        }
      }

      // Use PhishTank RSS feed (public, no API key needed)
      const rssResponse = await axios.get(
        'https://www.phishtank.com/rss.php',
        {
          timeout: 60000,
          headers: { 'Accept': 'application/rss+xml, text/xml' },
          responseType: 'text'
        }
      );

      const urls = [];
      if (rssResponse.data) {
        const $ = cheerio.load(rssResponse.data, { xmlMode: true });
        
        $('item').each((i, item) => {
          const $item = $(item);
          const title = $item.find('title').text();
          const link = $item.find('link').text();
          const description = $item.find('description').text();
          
          // Extract URL from link or description
          let phishUrl = link;
          if (!phishUrl || !phishUrl.startsWith('http')) {
            // Try to extract from description
            const urlMatch = description.match(/https?:\/\/[^\s<>"{}|\\^`[\]]+/i);
            if (urlMatch) {
              phishUrl = urlMatch[0];
            }
          }
          
          if (phishUrl && (phishUrl.startsWith('http://') || phishUrl.startsWith('https://'))) {
            urls.push({
              url: phishUrl,
              source: 'phishtank',
              priority: 'high',
              metadata: {
                scrapedAt: new Date().toISOString(),
                source: 'phishtank_rss',
                phishId: title.match(/Phish #(\d+)/)?.[1],
                verified: description.toLowerCase().includes('verified')
              }
            });
          }
        });
      }

      logger.info(`[PhishTank] Scraped ${urls.length} URLs from RSS feed`);
      return urls.slice(0, 100); // Limit to 100

    } catch (error) {
      logger.warn(`[PhishTank] Scraping failed: ${error.message}`);
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
