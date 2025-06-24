const nodemailer = require("nodemailer");
require("dotenv").config();

async function sendTakedownReport(url) {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  const info = await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: process.env.EMAIL_TO,
    subject: "Phishing Report",
    text: `Phishing URL detected: ${url}`,
  });

  console.log(`Report sent: ${info.messageId}`);
}

module.exports = { sendTakedownReport };
