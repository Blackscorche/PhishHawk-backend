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
      case 'urlhaus':
        return await this.scrapeUrlhaus();
      default:
        logger.warn(`Unknown scraping source: ${source}`);
        return [];
    }
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
      // Using the Plain-Text URL List endpoint for recent URLs (past 30 days)
      // This is more reliable than payloads endpoint
      
      const response = await axios.get(
        'https://urlhaus.abuse.ch/downloads/csv_recent/',
        { 
          timeout: 60000,
          headers: {
            'Accept': 'text/plain'
          },
          responseType: 'text'
        }
      );

      const urls = [];
      
      if (response.data) {
        // Parse plain text URL list (one URL per line)
        const urlLines = response.data.split('\n').filter(line => line.trim() && line.startsWith('http'));
        
        // Get latest 100 URLs
        const recentUrls = urlLines.slice(0, 100);
        
        recentUrls.forEach((urlLine) => {
          const url = urlLine.trim();
          if (url) {
            urls.push({
              url: url,
              source: 'urlhaus',
              priority: 'high',
              metadata: {
                scrapedAt: new Date().toISOString(),
                source: 'urlhaus_recent_feed'
              }
            });
          }
        });
      }

      logger.info(`[URLhaus] Scraped ${urls.length} URLs from recent feed`);
      return urls;

    } catch (error) {
      logger.error('Error scraping URLhaus:', error.message);
      
      // Fallback: Try to get URLs from active malware list
      try {
        const fallbackResponse = await axios.get(
          'https://urlhaus.abuse.ch/downloads/text_online/',
          {
            timeout: 60000,
            headers: { 'Accept': 'text/plain' },
            responseType: 'text'
          }
        );
        
        const fallbackUrls = [];
        if (fallbackResponse.data) {
          const urlLines = fallbackResponse.data.split('\n').filter(line => line.trim() && line.startsWith('http'));
          urlLines.slice(0, 50).forEach((urlLine) => {
            const url = urlLine.trim();
            if (url) {
              fallbackUrls.push({
                url: url,
                source: 'urlhaus',
                priority: 'high',
                metadata: {
                  scrapedAt: new Date().toISOString(),
                  source: 'urlhaus_active_feed'
                }
              });
            }
          });
        }
        
        logger.info(`[URLhaus] Fallback: Scraped ${fallbackUrls.length} URLs from active feed`);
        return fallbackUrls;
      } catch (fallbackError) {
        logger.error('Error in URLhaus fallback scraping:', fallbackError.message);
        return [];
      }
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
