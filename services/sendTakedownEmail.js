import nodemailer from "nodemailer";
import { logger } from "../utils/logger.js";
import { findAbuseEmails } from "./providerEmailFinder.js";

/**
 * Send takedown emails to multiple recipients:
 * 1. Hosting provider abuse email (if detected)
 * 2. Domain registrar abuse email (if detected)
 * 3. Cloudflare abuse email (if using Cloudflare)
 * 4. APWG tracking email (always)
 * 5. Custom EMAIL_TO from .env (if set)
 */
export async function sendTakedownEmail(report, customReason = null) {
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
        pass: process.env.SMTP_PASS
      }
    });

    const reason = customReason || generateReason(report);

    // Find all abuse email addresses for this domain
    logger.info(`[Email] Finding abuse contacts for ${report.url}...`);
    let abuseContacts;
    try {
      abuseContacts = await findAbuseEmails(report.url);
      logger.info(`[Email] Found ${abuseContacts.emails?.length || 0} abuse contacts`);
    } catch (abuseError) {
      logger.warn(`[Email] Error finding abuse emails:`, abuseError.message);
      // Continue with default APWG email if abuse email finding fails
      abuseContacts = {
        domain: null,
        hostingProvider: null,
        registrar: null,
        cloudflare: null,
        emails: [{
          type: 'tracking',
          email: 'report@apwg.org',
          reason: 'Fallback - APWG tracking (abuse email detection failed)'
        }]
      };
    }
    
    // Collect all unique email addresses
    const emailRecipients = new Set();
    const emailDetails = [];

    // Add provider-specific abuse emails
    abuseContacts.emails.forEach(contact => {
      if (contact.email && !emailRecipients.has(contact.email)) {
        emailRecipients.add(contact.email);
        emailDetails.push(contact);
      }
    });

    // Add custom EMAIL_TO if set (for manual monitoring)
    if (process.env.EMAIL_TO) {
      if (!emailRecipients.has(process.env.EMAIL_TO)) {
        emailRecipients.add(process.env.EMAIL_TO);
        emailDetails.push({
          type: 'custom',
          email: process.env.EMAIL_TO,
          reason: 'Custom monitoring email from .env'
        });
      }
    }

    // If no provider emails found, use APWG as default
    if (emailRecipients.size === 0) {
      emailRecipients.add('report@apwg.org');
      emailDetails.push({
        type: 'tracking',
        email: 'report@apwg.org',
        reason: 'Default - APWG tracking (no provider emails found)'
      });
    }

    const recipients = Array.from(emailRecipients);
    logger.info(`[Email] Sending takedown emails to ${recipients.length} recipients:`, recipients);

    // Send email to all recipients
    const results = [];
    for (const recipient of recipients) {
      try {
        const mailOptions = {
          from: process.env.SMTP_FROM || `"CantPhishMe" <${process.env.SMTP_USER}>`,
          to: recipient,
          subject: `Phishing Report - ${report.url}`,
          text: reason,
          html: generateEmailHTML(report, reason, recipient)
        };

        const result = await transporter.sendMail(mailOptions);
        results.push({
          recipient: recipient,
          sent: true,
          messageId: result.messageId,
          response: result.response || 'Email accepted by server',
          sentAt: new Date().toISOString()
        });
        logger.info(`[Email] ✓ Sent to ${recipient} - Message ID: ${result.messageId}`);
        logger.info(`[Email] Server response: ${result.response || 'Accepted'}`);
      } catch (emailError) {
        logger.error(`[Email] ✗ Failed to send to ${recipient}:`, emailError.message);
        results.push({
          recipient: recipient,
          sent: false,
          error: emailError.message
        });
      }
    }

    const successCount = results.filter(r => r.sent).length;
    const failCount = results.filter(r => !r.sent).length;
    
    logger.info(`[Email] Takedown emails sent: ${successCount} successful, ${failCount} failed for ${report.url}`);
    
    // Log detailed results
    logger.info(`[Email] Detailed results:`);
    results.forEach((r, idx) => {
      if (r.sent) {
        logger.info(`  [${idx + 1}] ✓ ${r.recipient} - Message ID: ${r.messageId} - Response: ${r.response || 'Accepted'}`);
      } else {
        logger.error(`  [${idx + 1}] ✗ ${r.recipient} - Error: ${r.error}`);
      }
    });
    
    return {
      sent: successCount > 0,
      totalRecipients: recipients.length,
      successful: successCount,
      failed: failCount,
      results: results,
      abuseContacts: abuseContacts,
      sentAt: new Date().toISOString(),
      // Add verification info
      verification: {
        smtpConfigured: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
        smtpHost: process.env.SMTP_HOST || 'Not configured',
        fromAddress: process.env.SMTP_FROM || process.env.SMTP_USER || 'Not configured'
      }
    };

  } catch (error) {
    logger.error(`Failed to send takedown email:`, error);
    logger.error(`Error details:`, {
      message: error.message,
      code: error.code,
      command: error.command,
      response: error.response,
      responseCode: error.responseCode
    });
    
    return {
      sent: false,
      error: error.message || 'Failed to send email',
      message: error.message || 'SMTP error occurred',
      verification: {
        smtpConfigured: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
        smtpHost: process.env.SMTP_HOST || 'Not configured',
        fromAddress: process.env.SMTP_FROM || process.env.SMTP_USER || 'Not configured',
        errorCode: error.code,
        errorMessage: error.message
      }
    };
  }
}

function generateReason(report) {
  return `
AUTOMATED PHISHING REPORT

URL: ${report.url}
Risk Score: ${report.riskScore}/100
Risk Level: ${report.riskLevel}
Detection Date: ${report.createdAt}

This URL has been automatically identified as a potential phishing threat based on the following analysis:

Risk Factors Detected:
${formatRiskChecks(report.riskChecks)}

${report.validationResults ? formatValidationResults(report.validationResults) : ''}

This automated report is generated by our phishing detection system. Please investigate and take appropriate action to protect users from this potential threat.

For questions or additional information, please contact our security team.

Best regards,
Automated Security Response Team
  `.trim();
}

function formatRiskChecks(checks) {
  if (!checks || typeof checks !== 'object') return '• Multiple risk indicators detected';
  
  const messages = [];
  
  if (checks.suspiciousTLD) messages.push('• Suspicious top-level domain detected');
  if (checks.suspiciousKeywords) messages.push(`• Suspicious keywords found: ${Array.isArray(checks.suspiciousKeywords) ? checks.suspiciousKeywords.join(', ') : checks.suspiciousKeywords}`);
  if (checks.excessiveSubdomains) messages.push(`• Excessive subdomains (${checks.excessiveSubdomains})`);
  if (checks.urlShortener) messages.push('• URL shortening service detected');
  if (checks.ipInDomain) messages.push('• IP address in domain name');
  if (checks.insecureProtocol) messages.push('• Insecure HTTP protocol');
  if (checks.passwordForm) messages.push('• Password collection form detected');
  if (checks.likelyLoginPage) messages.push('• Likely fake login page');
  if (checks.urgentLanguage) messages.push('• Urgent/threatening language detected');
  
  return messages.length > 0 ? messages.join('\n') : '• Multiple risk indicators detected';
}

function formatValidationResults(validation) {
  if (!validation) return '';
  
  let result = '\nThird-party Validation Results:\n';
  
  if (validation.virusTotal && !validation.virusTotal.error) {
    result += `• VirusTotal: ${validation.virusTotal.malicious || 0}/${validation.virusTotal.total || 0} engines flagged as malicious\n`;
  }
  
  if (validation.urlhaus && !validation.urlhaus.error) {
    result += `• URLhaus: ${validation.urlhaus.isPhish ? 'Confirmed malicious site' : 'Not in database'}\n`;
    if (validation.urlhaus.threat) {
      result += `  Threat type: ${validation.urlhaus.threat}\n`;
    }
    if (validation.urlhaus.tags && validation.urlhaus.tags.length > 0) {
      result += `  Tags: ${validation.urlhaus.tags.join(', ')}\n`;
    }
  }
  
  return result;
}

function generateEmailHTML(report, reason, recipient = null) {
  // Add recipient-specific context
  let recipientNote = '';
  if (recipient) {
    if (recipient.includes('cloudflare')) {
      recipientNote = '<p style="background-color: #e3f2fd; padding: 10px; border-left: 4px solid #2196f3;"><strong>Note:</strong> This domain appears to be using Cloudflare services. Please investigate and take appropriate action.</p>';
    } else if (recipient.includes('apwg')) {
      recipientNote = '<p style="background-color: #f3e5f5; padding: 10px; border-left: 4px solid #9c27b0;"><strong>Note:</strong> This report is being tracked by the Anti-Phishing Working Group for coordination purposes.</p>';
    } else {
      recipientNote = `<p style="background-color: #fff3e0; padding: 10px; border-left: 4px solid #ff9800;"><strong>Note:</strong> This abuse report is being sent to your organization as the hosting provider or registrar for this domain.</p>`;
    }
  }

  return `
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #d32f2f;">🚨 AUTOMATED PHISHING REPORT</h2>
      
      ${recipientNote}
      
      <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <strong>Malicious URL:</strong> <code>${report.url}</code><br>
        <strong>Risk Score:</strong> <span style="color: #d32f2f; font-weight: bold;">${report.riskScore}/100</span><br>
        <strong>Risk Level:</strong> ${report.riskLevel}<br>
        <strong>Detection Date:</strong> ${new Date(report.createdAt).toLocaleString()}<br>
        <strong>Status:</strong> ${report.status.replace('_', ' ').toUpperCase()}
      </div>

      <h3>Risk Analysis Details:</h3>
      <div style="background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107;">
        ${formatRiskChecks(report.riskChecks).replace(/\n/g, '<br>').replace(/•/g, '&#8226;')}
      </div>

      ${report.validationResults ? `
      <h3>Third-party Validation:</h3>
      <div style="background-color: #d1ecf1; padding: 10px; border-left: 4px solid #bee5eb;">
        ${formatValidationResults(report.validationResults).replace(/\n/g, '<br>').replace(/•/g, '&#8226;')}
      </div>
      ` : ''}

      <p style="margin-top: 30px;">
        This automated report is generated by our phishing detection system. 
        Please investigate and take appropriate action to protect users from this potential threat.
      </p>

      <hr style="margin: 30px 0;">
      <p style="color: #6c757d; font-size: 12px;">
        This is an automated message from our security monitoring system.<br>
        For questions or additional information, please contact our security team.
      </p>
    </body>
    </html>
  `;
}