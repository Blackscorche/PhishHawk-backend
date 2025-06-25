import nodemailer from "nodemailer";

export async function sendTakedownEmail(report) {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT),
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  return transporter.sendMail({
    from: `"PhishHawk" <${process.env.SMTP_USER}>`,
    to: "report@apwg.org",
    subject: "Phishing Takedown Request",
    text: `Phishing URL Reported:\nURL: ${report.url}\nRisk Level: ${report.riskLevel}\nScore: ${report.riskScore}`
  });
}
