import express from "express";
import { phishingValidationRules, validatePhishingRequest } from "../middleware/validateRequest.js";
import { phishingRateLimiter } from "../middleware/rateLimiter.js";
import { 
  submitPhishingReport, 
  getAllReports,
  getReportById,
  reanalyzeReport,
  submitTakedown,
  getMetrics,
  getAuditLogs
} from "../controllers/phishingController.js";

const router = express.Router();

// Metrics endpoint
router.get("/metrics", getMetrics);

// Get audit logs for a report
router.get("/:id/audit-logs", getAuditLogs);

// Get all reports with pagination and filters
router.get("/", getAllReports);

// Get specific report
router.get("/:id", getReportById);

// Submit new phishing report
router.post("/", phishingRateLimiter, phishingValidationRules, validatePhishingRequest, submitPhishingReport);

// Re-analyze report
router.post("/:id/reanalyze", reanalyzeReport);

// Submit takedown request
router.post("/:id/takedown", submitTakedown);

export default router;