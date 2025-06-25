import express from "express";
import { phishingValidationRules, validatePhishingRequest } from "../middleware/validateRequest.js";
import { phishingRateLimiter } from "../middleware/rateLimiter.js";
import { submitPhishingReport, getAllReports } from "../controllers/phishingController.js";

const router = express.Router();
router.post("/", phishingRateLimiter, phishingValidationRules, validatePhishingRequest, submitPhishingReport);
router.get("/", getAllReports);

export default router;
