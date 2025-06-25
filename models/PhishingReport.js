import mongoose from "mongoose";

const phishingReportSchema = new mongoose.Schema({
  url: String,
  domainAge: Number,
  hasSSL: Boolean,
  containsPhishingKeywords: Boolean,
  virusTotalHit: Boolean,
  riskScore: Number,
  riskLevel: String,
  takedownSubmitted: Boolean
}, { timestamps: true });

export default mongoose.model("PhishingReport", phishingReportSchema);
