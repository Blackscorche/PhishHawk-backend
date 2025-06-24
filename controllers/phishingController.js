const PhishingReport = require("../models/PhishingReport");
const { scoreUrl, getRiskLevel } = require("../utils/scorer");
const { sendTakedownReport } = require("../utils/mailer");

const reportPhishingUrl = async (req, res) => {
  const data = req.body;
  const score = scoreUrl(data);
  const riskLevel = getRiskLevel(score);

  const report = new PhishingReport({
    ...data,
    score,
    riskLevel,
    reported: riskLevel === "High"
  });

  await report.save();

  if (riskLevel === "High") {
    await sendTakedownReport(data.url);
  }

  res.status(201).json(report);
};

const getAllReports = async (req, res) => {
  const reports = await PhishingReport.find().sort({ createdAt: -1 });
  res.json(reports);
};

module.exports = { reportPhishingUrl, getAllReports };
