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
 * Builds a professional OTP email HTML body.
 * Uses table-based layout and inline CSS for maximum email client compatibility.
 *
 * @param {Object} opts
 * @param {string} opts.title        - Email heading, e.g. "Verify Your Login"
 * @param {string} opts.preheader    - Short preview text shown in inbox
 * @param {string} opts.bodyText     - Paragraph above the OTP box
 * @param {string} opts.otp          - The 6-digit OTP code
 * @param {number} opts.ttlMinutes   - Expiry in minutes
 * @param {string} opts.appName      - Application/brand name
 */
function buildOtpEmailHtml({ title, preheader, bodyText, otp, ttlMinutes, appName }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f2f5;font-family:Arial,Helvetica,sans-serif;">

  <!-- Preheader (hidden preview text) -->
  <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">
    ${preheader}
  </div>

  <!-- Outer wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0" border="0"
         style="background-color:#f0f2f5;padding:40px 16px;">
    <tr>
      <td align="center">

        <!-- Card -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0"
               style="max-width:560px;background-color:#ffffff;border-radius:12px;
                      box-shadow:0 4px 24px rgba(0,0,0,0.08);overflow:hidden;">

          <!-- Header bar -->
          <tr>
            <td align="center"
                style="background:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);
                       padding:32px 40px 28px;">
              <p style="margin:0;font-size:13px;font-weight:600;letter-spacing:2px;
                        text-transform:uppercase;color:#c7d2fe;">
                ${appName}
              </p>
              <h1 style="margin:10px 0 0;font-size:24px;font-weight:700;color:#ffffff;
                         line-height:1.3;">
                ${title}
              </h1>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:36px 40px 24px;">

              <p style="margin:0 0 24px;font-size:15px;line-height:1.7;color:#374151;">
                ${bodyText}
              </p>

              <!-- OTP Box -->
              <table width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="margin-bottom:24px;">
                <tr>
                  <td align="center"
                      style="background-color:#eef2ff;border:2px dashed #6366f1;
                             border-radius:10px;padding:20px 16px;">
                    <p style="margin:0 0 6px;font-size:12px;font-weight:600;
                               letter-spacing:1.5px;text-transform:uppercase;color:#6366f1;">
                      Your verification code
                    </p>
                    <p style="margin:0;font-size:40px;font-weight:800;
                               letter-spacing:10px;color:#3730a3;
                               font-family:'Courier New',Courier,monospace;">
                      ${otp}
                    </p>
                  </td>
                </tr>
              </table>

              <!-- Expiry notice -->
              <table width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="margin-bottom:28px;">
                <tr>
                  <td style="background-color:#fff7ed;border-left:4px solid #f97316;
                             border-radius:0 8px 8px 0;padding:12px 16px;">
                    <p style="margin:0;font-size:13px;color:#9a3412;line-height:1.5;">
                      <strong>&#9200; Expires in ${ttlMinutes} minutes.</strong>
                      Do not share this code with anyone.
                    </p>
                  </td>
                </tr>
              </table>

              <!-- Security note -->
              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="background-color:#f8fafc;border-radius:8px;
                             padding:14px 16px;">
                    <p style="margin:0;font-size:13px;color:#64748b;line-height:1.6;">
                      &#128274; <strong>Security notice:</strong> ${appName} will
                      never ask for your OTP via phone or chat. If you did not
                      request this code, please ignore this email — your account
                      remains secure.
                    </p>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td align="center"
                style="padding:20px 40px 32px;border-top:1px solid #e5e7eb;">
              <p style="margin:0 0 4px;font-size:12px;color:#9ca3af;">
                This is an automated message — please do not reply.
              </p>
              <p style="margin:0;font-size:12px;color:#d1d5db;">
                &copy; ${new Date().getFullYear()} ${appName}. All rights reserved.
              </p>
            </td>
          </tr>

        </table>
        <!-- /Card -->

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

const APP_NAME = process.env.APP_NAME || "Clothing Shop";

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
      bodyText: `We received a request to reset the password for your <strong>${APP_NAME}</strong> account. Use the code below to complete the process.`,
      otp,
      ttlMinutes,
      appName: APP_NAME,
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
      bodyText: `A sign-in attempt was made to your <strong>${APP_NAME}</strong> account. Enter the code below to complete your login.`,
      otp,
      ttlMinutes,
      appName: APP_NAME,
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
      bodyText: `Welcome to <strong>${APP_NAME}</strong>! Please use the code below to verify your email address and activate your account.`,
      otp,
      ttlMinutes,
      appName: APP_NAME,
    })
  );
}

module.exports = {
  sendPasswordResetOtpEmail,
  sendLoginOtpEmail,
  sendVerificationEmail,
};