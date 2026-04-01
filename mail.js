const nodemailer = require("nodemailer");

/**
 * Configure Transporter
 */
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || "587"),
  secure: process.env.SMTP_PORT === "465", // true for port 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

/** Get FROM email safely */
function getFromEmail() {
  if (!process.env.EMAIL_FROM) {
    throw new Error("EMAIL_FROM is not set in environment variables");
  }
  return process.env.EMAIL_FROM.trim();
}

/**
 * Send Email (common function using Nodemailer)
 */
async function sendEmail(to, subject, text, html) {
  const mailOptions = {
    from: getFromEmail(),
    to,
    subject,
    text,
    html,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent successfully: ", info.messageId);
    return info;
  } catch (error) {
    console.error("Error sending email: ", error);
    throw error;
  }
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
};