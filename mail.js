const nodemailer = require("nodemailer");

/** Gmail app passwords may include spaces in .env — strip for auth. */
function smtpPass() {
  const raw = process.env.SMTP_PASS || "";
  return raw.replace(/\s/g, "");
}

function isSmtpConfigured() {
  return Boolean(
    process.env.SMTP_HOST?.trim() &&
      process.env.SMTP_USER?.trim() &&
      smtpPass()
  );
}

/**
 * @param {string} to
 * @param {string} otp
 * @param {number} [ttlMinutes=10]
 */
async function sendPasswordResetOtpEmail(to, otp, ttlMinutes = 10) {
  if (!isSmtpConfigured()) {
    throw new Error("SMTP is not configured (SMTP_HOST, SMTP_USER, SMTP_PASS)");
  }

  const port = parseInt(process.env.SMTP_PORT || "587", 10);
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST.trim(),
    port: Number.isNaN(port) ? 587 : port,
    secure: port === 465,
    requireTLS: port !== 465,
    auth: {
      user: process.env.SMTP_USER.trim(),
      pass: smtpPass(),
    },
    tls: { rejectUnauthorized: false },
  });

  const from =
    process.env.EMAIL_FROM?.trim() || process.env.SMTP_USER.trim();
  const appName = process.env.APP_NAME || "Clothing Shop";

  await transporter.sendMail({
    from: `"${appName}" <${from}>`,
    to,
    subject: `${appName} — Password reset code`,
    text: `Your password reset code is: ${otp}\n\nIt expires in ${ttlMinutes} minutes.\nIf you did not request this, ignore this email.`,
    html: `
      <div style="font-family: system-ui, sans-serif; max-width: 560px; margin: 0 auto;">
        <h2 style="color: #1e1b4b;">Password reset</h2>
        <p>Use this code to set a new password:</p>
        <p style="font-size: 28px; letter-spacing: 6px; font-weight: 700; color: #4f46e5;">${otp}</p>
        <p style="color: #64748b; font-size: 14px;">This code expires in ${ttlMinutes} minutes.</p>
        <p style="color: #64748b; font-size: 14px;">If you did not request a reset, you can ignore this email.</p>
      </div>
    `,
  });
}

/**
 * Login OTP email (passwordless login).
 * @param {string} to
 * @param {string} otp
 * @param {number} [ttlMinutes=10]
 */
async function sendLoginOtpEmail(to, otp, ttlMinutes = 10) {
  if (!isSmtpConfigured()) {
    throw new Error("SMTP is not configured (SMTP_HOST, SMTP_USER, SMTP_PASS)");
  }

  const port = parseInt(process.env.SMTP_PORT || "587", 10);
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST.trim(),
    port: Number.isNaN(port) ? 587 : port,
    secure: port === 465,
    requireTLS: port !== 465,
    auth: {
      user: process.env.SMTP_USER.trim(),
      pass: smtpPass(),
    },
    tls: { rejectUnauthorized: false },
  });

  const from =
    process.env.EMAIL_FROM?.trim() || process.env.SMTP_USER.trim();
  const appName = process.env.APP_NAME || "Clothing Shop";

  await transporter.sendMail({
    from: `"${appName}" <${from}>`,
    to,
    subject: `${appName} — Login verification code`,
    text: `Your login code is: ${otp}\n\nIt expires in ${ttlMinutes} minutes.\nIf you did not try to log in, ignore this email.`,
    html: `
      <div style="font-family: system-ui, sans-serif; max-width: 560px; margin: 0 auto;">
        <h2 style="color: #1e1b4b;">Login verification</h2>
        <p>Use this code to complete your login:</p>
        <p style="font-size: 28px; letter-spacing: 6px; font-weight: 700; color: #4f46e5;">${otp}</p>
        <p style="color: #64748b; font-size: 14px;">This code expires in ${ttlMinutes} minutes.</p>
        <p style="color: #64748b; font-size: 14px;">If you did not request this, you can ignore this email.</p>
      </div>
    `,
  });
}

/**
 * Signup verification OTP email.
 * @param {string} to
 * @param {string} otp
 * @param {number} [ttlMinutes=10]
 */
async function sendVerificationEmail(to, otp, ttlMinutes = 10) {
  if (!isSmtpConfigured()) {
    throw new Error("SMTP is not configured (SMTP_HOST, SMTP_USER, SMTP_PASS)");
  }

  const port = parseInt(process.env.SMTP_PORT || "587", 10);
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST.trim(),
    port: Number.isNaN(port) ? 587 : port,
    secure: port === 465,
    requireTLS: port !== 465,
    auth: {
      user: process.env.SMTP_USER.trim(),
      pass: smtpPass(),
    },
    tls: { rejectUnauthorized: false },
  });

  const from =
    process.env.EMAIL_FROM?.trim() || process.env.SMTP_USER.trim();
  const appName = process.env.APP_NAME || "Clothing Shop";

  await transporter.sendMail({
    from: `"${appName}" <${from}>`,
    to,
    subject: `${appName} — Signup verification code`,
    text: `Your email verification code is: ${otp}\n\nIt expires in ${ttlMinutes} minutes.\nIf you did not request this, ignore this email.`,
    html: `
      <div style="font-family: system-ui, sans-serif; max-width: 560px; margin: 0 auto;">
        <h2 style="color: #1e1b4b;">Verify your email</h2>
        <p>Use this code to verify your email address and complete your signup:</p>
        <p style="font-size: 28px; letter-spacing: 6px; font-weight: 700; color: #4f46e5;">${otp}</p>
        <p style="color: #64748b; font-size: 14px;">This code expires in ${ttlMinutes} minutes.</p>
        <p style="color: #64748b; font-size: 14px;">If you did not sign up for an account, you can ignore this email.</p>
      </div>
    `,
  });
}

module.exports = {
  sendPasswordResetOtpEmail,
  sendLoginOtpEmail,
  sendVerificationEmail,
  isSmtpConfigured,
};
