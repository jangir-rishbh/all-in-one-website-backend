const nodemailer = require("nodemailer");

/** Clean SMTP password */
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

/** Create transporter (reuse) */
function createTransporter() {
  const port = parseInt(process.env.SMTP_PORT || "587", 10);

  return nodemailer.createTransport({
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
}

/** Get FROM email safely */
function getFromEmail() {
  if (!process.env.EMAIL_FROM) {
    throw new Error("EMAIL_FROM is not set in environment variables");
  }
  return process.env.EMAIL_FROM.trim();
}

/**
 * Send Email (common function)
 */
async function sendEmail(to, subject, text, html) {
  if (!isSmtpConfigured()) {
    throw new Error("SMTP is not configured");
  }

  const transporter = createTransporter();
  const from = getFromEmail();
  const appName = process.env.APP_NAME || "Clothing Shop";

  await transporter.sendMail({
    from: `"${appName}" <${from}>`,
    to,
    subject,
    text,
    html,
  });
}

/**
 * Password Reset OTP
 */
async function sendPasswordResetOtpEmail(to, otp, ttlMinutes = 10) {
  await sendEmail(
    to,
    `Clothing Shop — Password reset code`,
    `Your password reset code is: ${otp}\n\nExpires in ${ttlMinutes} minutes.`,
    `<h2>Password Reset</h2><p>Your OTP: <b>${otp}</b></p>`
  );
}

/**
 * Login OTP
 */
async function sendLoginOtpEmail(to, otp, ttlMinutes = 10) {
  await sendEmail(
    to,
    `Clothing Shop — Login code`,
    `Your login code is: ${otp}\n\nExpires in ${ttlMinutes} minutes.`,
    `<h2>Login OTP</h2><p>Your OTP: <b>${otp}</b></p>`
  );
}

/**
 * Signup OTP
 */
async function sendVerificationEmail(to, otp, ttlMinutes = 10) {
  await sendEmail(
    to,
    `Clothing Shop — Verification code`,
    `Your verification code is: ${otp}\n\nExpires in ${ttlMinutes} minutes.`,
    `<h2>Verify Email</h2><p>Your OTP: <b>${otp}</b></p>`
  );
}

module.exports = {
  sendPasswordResetOtpEmail,
  sendLoginOtpEmail,
  sendVerificationEmail,
  isSmtpConfigured,
};