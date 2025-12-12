import nodemailer from "nodemailer";
import { logger } from "./logger.js";

/**
 * Send a basic takedown report email
 * @param {string} url - The phishing URL to report
 * @param {object} options - Additional options (reason, riskScore, etc.)
 */
export async function sendTakedownReport(url, options = {}) {
  try {
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
      logger.warn('SMTP not configured, skipping email send');
      return { sent: false, message: 'SMTP not configured' };
    }

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const info = await transporter.sendMail({
      from: process.env.SMTP_FROM || `"PhishHawk" <${process.env.SMTP_USER}>`,
      to: process.env.EMAIL_TO || "report@apwg.org",
      subject: `Phishing Report - ${url}`,
      text: `Phishing URL detected: ${url}\n\nRisk Score: ${options.riskScore || 'N/A'}\nReason: ${options.reason || 'Automated detection'}`,
      html: `
        <h2>🚨 Phishing URL Detected</h2>
        <p><strong>URL:</strong> <code>${url}</code></p>
        <p><strong>Risk Score:</strong> ${options.riskScore || 'N/A'}</p>
        <p><strong>Reason:</strong> ${options.reason || 'Automated detection'}</p>
        <p><strong>Reported At:</strong> ${new Date().toISOString()}</p>
      `
    });

    logger.info(`Takedown report sent: ${info.messageId}`);
    return { sent: true, messageId: info.messageId };
  } catch (error) {
    logger.error('Failed to send takedown report:', error);
    return { sent: false, error: error.message };
  }
}

export default { sendTakedownReport };
