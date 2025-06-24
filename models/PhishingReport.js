const mongoose = require("mongoose");

const PhishingReportSchema = new mongoose.Schema({
  url: { type: String, required: true },
  domainAge: Number,
  hasSSL: Boolean,
  containsPhishingKeywords: Boolean,
  virusTotalHit: Boolean,
  score: Number,
  riskLevel: String,
  reported: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model("PhishingReport", PhishingReportSchema);
