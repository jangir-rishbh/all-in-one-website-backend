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

const APP_NAME = process.env.APP_NAME || "Clothing Shop";

/**
 * Builds a professional OTP email HTML body.
 * Uses table-based layout and inline CSS only for maximum email client compatibility.
 */
function buildOtpEmailHtml({ title, preheader, bodyText, otp, ttlMinutes }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1.0" />
<title>${title}</title>
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:Arial,Helvetica,sans-serif;">

<!-- Hidden preheader -->
<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">${preheader}</div>

<!-- Outer wrapper -->
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f1f5f9;padding:40px 16px;">
  <tr>
    <td align="center">

      <!-- Card -->
      <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;background-color:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e2e8f0;">

        <!-- Header -->
        <tr>
          <td align="center" style="background-color:#4f46e5;padding:36px 40px 28px;">
            <p style="margin:0 0 8px;font-size:12px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:#a5b4fc;">${APP_NAME}</p>
            <h1 style="margin:0;font-size:22px;font-weight:700;color:#ffffff;line-height:1.4;">${title}</h1>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:36px 40px 28px;">

            <p style="margin:0 0 20px;font-size:15px;line-height:1.7;color:#374151;">${bodyText}</p>

            <!-- OTP Box -->
            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:20px;">
              <tr>
                <td align="center" style="background-color:#eef2ff;border:2px solid #c7d2fe;border-radius:10px;padding:24px 16px;">
                  <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#6366f1;">Your verification code</p>
                  <p style="margin:0;font-size:44px;font-weight:800;letter-spacing:12px;color:#3730a3;font-family:'Courier New',Courier,monospace;">${otp}</p>
                </td>
              </tr>
            </table>

            <!-- Expiry notice -->
            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:20px;">
              <tr>
                <td style="background-color:#fff7ed;border-left:4px solid #f97316;border-radius:0 8px 8px 0;padding:12px 16px;">
                  <p style="margin:0;font-size:13px;color:#9a3412;line-height:1.5;">
                    <strong>&#9200; Expires in ${ttlMinutes} minutes.</strong> Do not share this code with anyone.
                  </p>
                </td>
              </tr>
            </table>

            <!-- Security note -->
            <table width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td style="background-color:#f8fafc;border-radius:8px;padding:14px 16px;">
                  <p style="margin:0;font-size:13px;color:#64748b;line-height:1.6;">
                    &#128274; <strong>Security tip:</strong> ${APP_NAME} will never ask for your OTP via phone, email, or chat.
                    If you didn't request this, your account is still safe — no action is needed.
                  </p>
                </td>
              </tr>
            </table>

          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td align="center" style="padding:20px 40px 32px;border-top:1px solid #e5e7eb;">
            <p style="margin:0 0 4px;font-size:12px;color:#9ca3af;">This is an automated message — please do not reply.</p>
            <p style="margin:0;font-size:12px;color:#d1d5db;">&copy; ${new Date().getFullYear()} ${APP_NAME}. All rights reserved.</p>
          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>

</body>
</html>`;
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
    `${APP_NAME} — Password Reset Code`,
    `Your password reset code is: ${otp}\n\nExpires in ${ttlMinutes} minutes. Do not share this with anyone.`,
    buildOtpEmailHtml({
      title: "Reset Your Password",
      preheader: `Your password reset code is ${otp}. Expires in ${ttlMinutes} minutes.`,
      bodyText: `Hi there,<br/>We received a request to reset the password for your <strong>${APP_NAME}</strong> account. Use the code below to complete the process. If you didn't request this, you can safely ignore this email.`,
      otp,
      ttlMinutes,
    })
  );
}

/**
 * Login OTP
 */
async function sendLoginOtpEmail(to, otp, ttlMinutes = 10) {
  await sendEmail(
    to,
    `${APP_NAME} — Login Verification Code`,
    `Your login code is: ${otp}\n\nExpires in ${ttlMinutes} minutes. Do not share this with anyone.`,
    buildOtpEmailHtml({
      title: "Verify Your Login",
      preheader: `Your login code is ${otp}. Expires in ${ttlMinutes} minutes.`,
      bodyText: `Hi there,<br/>A sign-in attempt was made to your <strong>${APP_NAME}</strong> account. Enter the code below to complete your login. If this wasn't you, please ignore this email — your account is safe.`,
      otp,
      ttlMinutes,
    })
  );
}

/**
 * Signup OTP
 */
async function sendVerificationEmail(to, otp, ttlMinutes = 10) {
  await sendEmail(
    to,
    `${APP_NAME} — Email Verification Code`,
    `Your verification code is: ${otp}\n\nExpires in ${ttlMinutes} minutes. Do not share this with anyone.`,
    buildOtpEmailHtml({
      title: "Verify Your Email",
      preheader: `Your email verification code is ${otp}. Expires in ${ttlMinutes} minutes.`,
      bodyText: `Hi there,<br/>Welcome to <strong>${APP_NAME}</strong>! Please use the code below to verify your email address and activate your account.`,
      otp,
      ttlMinutes,
    })
  );
}

module.exports = {
  sendPasswordResetOtpEmail,
  sendLoginOtpEmail,
  sendVerificationEmail,
};