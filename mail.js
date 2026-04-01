const nodemailer = require("nodemailer");

/**
 * Configure Transporter
 */
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || "587"),
  secure: process.env.SMTP_PORT === "465",
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
 * Shared OTP Email Template
 */
function generateOtpEmailHtml({ otp, ttlMinutes, title, description }) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title}</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f6f9fc; color: #333;">
      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout: fixed;">
        <tr>
          <td align="center" style="padding: 40px 0;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05); border: 1px solid #e1e8ed;">
              <!-- Header -->
              <tr>
                <td align="center" style="padding: 40px 40px 20px 40px;">
                  <h1 style="margin: 0; font-size: 24px; font-weight: 700; color: #1a1f36; letter-spacing: -0.5px;">${title}</h1>
                </td>
              </tr>
              <!-- Content -->
              <tr>
                <td style="padding: 0 40px 20px 40px; text-align: center;">
                  <p style="margin: 0; font-size: 16px; line-height: 24px; color: #4f566b;">${description}</p>
                </td>
              </tr>
              <!-- OTP Box -->
              <tr>
                <td align="center" style="padding: 20px 40px 30px 40px;">
                  <div style="background-color: #eef2ff; border-radius: 8px; padding: 24px; display: inline-block; border: 1px solid #e0e7ff;">
                    <span style="font-family: 'Courier New', Courier, monospace; font-size: 36px; font-weight: 700; color: #4f46e5; letter-spacing: 6px; margin-left: 6px;">${otp}</span>
                  </div>
                </td>
              </tr>
              <!-- Expiry -->
              <tr>
                <td style="padding: 0 40px 30px 40px; text-align: center;">
                  <p style="margin: 0; font-size: 14px; font-weight: 500; color: #697386;">This code will expire in <span style="color: #1a1f36; font-weight: 700;">${ttlMinutes} minutes</span>.</p>
                </td>
              </tr>
              <!-- Security Note -->
              <tr>
                <td style="padding: 20px 40px; background-color: #f9fafb; border-top: 1px solid #e1e8ed; text-align: center;">
                  <p style="margin: 0 0 8px 0; font-size: 12px; font-weight: 600; color: #697386; text-transform: uppercase; letter-spacing: 1px;">Security Note</p>
                  <p style="margin: 0; font-size: 13px; line-height: 20px; color: #697386;">If you did not request this code, someone may be trying to access your account. Please ignore this email or contact support if you have concerns.</p>
                </td>
              </tr>
              <!-- Footer -->
              <tr>
                <td style="padding: 30px 40px; text-align: center;">
                  <p style="margin: 0; font-size: 12px; color: #a3acb9;">&copy; ${new Date().getFullYear()} Clothing Shop. All rights reserved.</p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
  `;
}

/**
 * Password Reset OTP
 */
async function sendPasswordResetOtpEmail(to, otp, ttlMinutes = 10) {
  const title = "Reset Your Password";
  const description = "Use the verification code below to securely reset your password. For your protection, never share this code with anyone.";

  await sendEmail(
    to,
    `Clothing Shop — Password reset code`,
    `Your password reset code is: ${otp}\n\nExpires in ${ttlMinutes} minutes.`,
    generateOtpEmailHtml({ otp, ttlMinutes, title, description })
  );
}

/**
 * Login OTP
 */
async function sendLoginOtpEmail(to, otp, ttlMinutes = 10) {
  const title = "Login Verification";
  const description = "Welcome back! Enter the 6-digit verification code below to securely sign in to your Clothing Shop account.";

  await sendEmail(
    to,
    `Clothing Shop — Login code`,
    `Your login code is: ${otp}\n\nExpires in ${ttlMinutes} minutes.`,
    generateOtpEmailHtml({ otp, ttlMinutes, title, description })
  );
}

/**
 * Signup OTP
 */
async function sendVerificationEmail(to, otp, ttlMinutes = 10) {
  const title = "Verify Your Email";
  const description = "Thank you for choosing Clothing Shop! To complete your registration and secure your account, please enter the code below.";

  await sendEmail(
    to,
    `Clothing Shop — Verification code`,
    `Your verification code is: ${otp}\n\nExpires in ${ttlMinutes} minutes.`,
    generateOtpEmailHtml({ otp, ttlMinutes, title, description })
  );
}

module.exports = {
  sendPasswordResetOtpEmail,
  sendLoginOtpEmail,
  sendVerificationEmail,
};