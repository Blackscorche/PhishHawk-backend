import express from "express";
import { URLScraper } from "../services/urlScraper.js";
import { RiskAnalyzer } from "../services/riskAnalyzer.js";
import PhishingReport from "../models/PhishingReport.js";
import { logger } from "../utils/logger.js";

const router = express.Router();
const urlScraper = new URLScraper();
const riskAnalyzer = new RiskAnalyzer();

// Start automated scraping
router.post("/start", async (req, res) => {
  try {
    const { sources = ['rss', 'urlhaus'], interval = 300000 } = req.body; // 5 minutes default
    
    urlScraper.startScraping(sources, interval, async (foundUrls) => {
      // Process found URLs
      for (const urlData of foundUrls) {
        try {
          const existing = await PhishingReport.findOne({ url: urlData.url });
          if (!existing) {
            const analysisResult = await riskAnalyzer.analyzeURL(urlData.url);
            
            const report = new PhishingReport({
              url: urlData.url,
              source: urlData.source || 'api',
              priority: urlData.priority || 'medium',
              riskScore: analysisResult.score,
              riskLevel: analysisResult.score >= 70 ? 'High' : 
                        analysisResult.score >= 40 ? 'Medium' : 'Low',
              riskChecks: analysisResult.checks,
              status: analysisResult.score >= 80 ? 'high_risk' : 
                      analysisResult.score >= 50 ? 'medium_risk' : 'low_risk',
              metadata: urlData.metadata || {}
            });

            await report.save();
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

export default router;
