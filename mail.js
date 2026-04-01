const sgMail = require("@sendgrid/mail");

// ✅ Set API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

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
  const msg = {
    to,
    from: getFromEmail(),
    subject,
    text,
    html,
  };

  await sgMail.send(msg);
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