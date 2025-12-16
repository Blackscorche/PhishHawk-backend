import express from "express";
import mongoose from "mongoose";
import { URLScraper } from "../services/urlScraper.js";
import { AutomatedRiskScoringEngine } from "../services/automatedRiskScoring.js";
import PhishingReport from "../models/PhishingReport.js";
import { logger } from "../utils/logger.js";

const router = express.Router();
const urlScraper = new URLScraper();
const riskScoringEngine = new AutomatedRiskScoringEngine();

// Process URLs with full VirusTotal + URLhaus analysis and save to DB
const processAndSaveUrls = async (urls) => {
  const dbAvailable = mongoose.connection.readyState === 1;
  if (!dbAvailable) {
    logger.warn('Database not available - URLs cannot be saved');
    return { processed: 0, skipped: 0, errors: 0 };
  }

  let processed = 0;
  let skipped = 0;
  let errors = 0;

  for (const urlData of urls) {
    try {
      // Check if URL already exists
      const existing = await PhishingReport.findOne({ url: urlData.url });
      if (existing) {
        skipped++;
        continue;
      }

      // Full analysis with VirusTotal + URLhaus + risk scoring
      logger.info(`[Collection] Analyzing ${urlData.url} with VirusTotal + URLhaus...`);
      const scoringResult = await riskScoringEngine.processDomain(urlData.url);
      
      // Create report with full intelligence data
      const report = new PhishingReport({
        url: urlData.url,
        source: urlData.source || 'urlhaus',
        priority: urlData.priority || 'high',
        riskScore: scoringResult.riskScore || 50,
        riskLevel: scoringResult.riskLevel || 'Medium',
        riskChecks: scoringResult.checks || {},
        status: scoringResult.riskScore >= 80 ? 'high_risk' : 
                scoringResult.riskScore >= 50 ? 'medium_risk' : 'low_risk',
        validationResults: {
          virusTotal: scoringResult.intelligence?.virusTotal || null,
          urlhaus: scoringResult.intelligence?.urlhaus || null
        },
        metadata: {
          ...urlData.metadata,
          collectedAt: new Date().toISOString(),
          intelligenceGathered: true
        }
      });

      await report.save();
      processed++;
      logger.info(`[Collection] Saved: ${urlData.url} (Risk: ${scoringResult.riskScore}/100)`);
    } catch (error) {
      errors++;
      logger.error(`[Collection] Error processing ${urlData.url}:`, error.message);
    }
  }

  return { processed, skipped, errors };
};

// Start automated scraping
router.post("/start", async (req, res) => {
  try {
    // Support 'all' source to scrape from all available sources
    let { sources = ['urlhaus'], interval = 300000 } = req.body; // 5 minutes default
    
    // If 'all' is in sources, replace with all available sources
    if (sources.includes('all')) {
      sources = ['urlhaus', 'openphish', 'phishtank', 'rss'];
      logger.info('[Collection] Using "all" sources: urlhaus, openphish, phishtank, rss');
    }
    const dbAvailable = mongoose.connection.readyState === 1;
    
    if (!dbAvailable) {
      return res.status(503).json({
        success: false,
        message: 'Database not available - cannot start collection'
      });
    }

    // Run immediate scrape on start (don't wait for interval)
    logger.info(`[Collection] Starting immediate scrape from sources: ${sources.join(', ')}`);
    const immediateResults = { processed: 0, skipped: 0, errors: 0 };
    
    for (const source of sources) {
      try {
        const urls = await urlScraper.scrapeSource(source);
        if (urls.length > 0) {
          logger.info(`[Collection] Found ${urls.length} URLs from ${source}, processing...`);
          const result = await processAndSaveUrls(urls);
          immediateResults.processed += result.processed;
          immediateResults.skipped += result.skipped;
          immediateResults.errors += result.errors;
        }
      } catch (error) {
        logger.error(`[Collection] Error in immediate scrape from ${source}:`, error);
        immediateResults.errors++;
      }
    }
    
    // Set up interval scraping for future runs
    urlScraper.startScraping(sources, interval, async (foundUrls) => {
      logger.info(`[Collection] Interval scrape found ${foundUrls.length} URLs`);
      await processAndSaveUrls(foundUrls);
    });

    res.json({
      success: true,
      message: 'Collection started - immediate scrape completed',
      immediate: immediateResults,
      config: { sources, interval }
    });

  } catch (error) {
    logger.error('Error starting scraping:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to start collection',
      error: error.message
    });
  }
});

// Stop automated scraping
router.post("/stop", (req, res) => {
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

// Get scraping status
router.get("/status", (req, res) => {
  res.json({
    success: true,
    data: {
      isRunning: urlScraper.isRunning,
      activeSources: urlScraper.intervalIds?.length || 0
    }
  });
});

// Manually trigger a scrape from a specific source
router.post("/scrape-now", async (req, res) => {
  try {
    const { source = 'urlhaus' } = req.body;
    const dbAvailable = mongoose.connection.readyState === 1;
    
    if (!dbAvailable) {
      return res.status(503).json({
        success: false,
        message: 'Database not available - cannot scrape'
      });
    }
    
    logger.info(`[Collection] Manual scrape triggered for source: ${source}`);
    const urls = await urlScraper.scrapeSource(source);
    
    // Process with full VirusTotal + URLhaus analysis
    const result = await processAndSaveUrls(urls.slice(0, 50)); // Limit to 50 for manual scrape

    res.json({
      success: true,
      message: `Scraped ${urls.length} URLs from ${source}`,
      data: {
        totalFound: urls.length,
        processed: result.processed,
        skipped: result.skipped,
        errors: result.errors,
        source,
        dbAvailable: true
      }
    });

  } catch (error) {
    logger.error('Error in manual scrape:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to scrape URLs',
      error: error.message
    });
  }
});

export default router;
