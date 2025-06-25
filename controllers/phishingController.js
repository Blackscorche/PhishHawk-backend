import PhishingReport from "../models/PhishingReport.js";
import { scorePhishingUrl } from "../services/scoring.js";
import { sendTakedownEmail } from "../services/sendTakedownEmail.js";
import { checkUrlWithVirusTotal } from "../services/virusTotalChecker.js";

export const submitPhishingReport = async (req, res) => {
  try {
    const { url, domainAge, hasSSL, containsPhishingKeywords } = req.body;
    const virusTotalHit = await checkUrlWithVirusTotal(url);
    const { score, risk } = scorePhishingUrl({ domainAge, hasSSL, containsPhishingKeywords, virusTotalHit });

    const report = new PhishingReport({
      url, domainAge, hasSSL, containsPhishingKeywords, virusTotalHit,
      riskScore: score,
      riskLevel: risk,
      takedownSubmitted: false
    });

    if (risk === "High") {
      await sendTakedownEmail(report);
      report.takedownSubmitted = true;
    }

    await report.save();
    res.status(201).json(report);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
};

export const getAllReports = async (req, res) => {
  const reports = await PhishingReport.find().sort({ createdAt: -1 });
  res.json(reports);
};
