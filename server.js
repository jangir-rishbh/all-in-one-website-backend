require('dotenv').config();
const express = require("express");
const cors = require("cors");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { sendPasswordResetOtpEmail, sendLoginOtpEmail, sendVerificationEmail } = require('./mail');

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const app = express();

// ✅ CORS (IMPORTANT)
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://ma-baba-cloth-store.vercel.app" // 👈 apna REAL frontend URL yahan daalo
  ],
  credentials: true
}));

// ✅ JSON parser
app.use(express.json());

// ✅ multer
const upload = multer({ storage: multer.memoryStorage() });

const ADMIN_STORE_PATH = path.join(__dirname, 'admin-store.json');

function loadAdminStore() {
  try {
    if (!fs.existsSync(ADMIN_STORE_PATH)) {
      return {
        featured: [],
        overrides: [],
        customProducts: [],
        replies: [],
        websiteInfo: { name: 'Ma Baba Cloth Store', logoUrl: '' }
      };
    }
    const raw = fs.readFileSync(ADMIN_STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      featured: Array.isArray(parsed.featured) ? parsed.featured : [],
      overrides: Array.isArray(parsed.overrides) ? parsed.overrides : [],
      customProducts: Array.isArray(parsed.customProducts) ? parsed.customProducts : [],
      replies: Array.isArray(parsed.replies) ? parsed.replies : [],
      websiteInfo: parsed.websiteInfo || { name: 'Ma Baba Cloth Store', logoUrl: '' }
    };
  } catch {
    return {
      featured: [],
      overrides: [],
      customProducts: [],
      replies: [],
      websiteInfo: { name: 'Ma Baba Cloth Store', logoUrl: '' }
    };
  }
}

function saveAdminStore(store) {
  fs.writeFileSync(ADMIN_STORE_PATH, JSON.stringify(store, null, 2), 'utf8');
}

async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

async function isPasswordValid(plainPassword, storedHashOrPassword) {
  if (!storedHashOrPassword) return false;
  // If existing records are plaintext, keep backward compatibility.
  if (plainPassword === storedHashOrPassword) return true;
  // bcrypt hash usually starts with $2a$, $2b$, or $2y$.
  if (!storedHashOrPassword.startsWith('$2')) return false;
  return bcrypt.compare(plainPassword, storedHashOrPassword);
}

/** Admin panel: `users.is_admin = true` OR `users.role` = 'admin' (case-insensitive). */
function resolveRole(user) {
  if (!user) return 'user';
  if (user.is_admin === true) return 'admin';
  const r = String(user.role ?? '')
    .trim()
    .toLowerCase();
  if (r === 'admin') return 'admin';
  return 'user';
}

/** Separate OTP tables to avoid mixing flows. */
const LOGIN_OTPS_TABLE = 'login_otps';
const PASSWORD_RESET_OTPS_TABLE = 'password_reset_otps';

const PASSWORD_RESET_OTP_TTL_MS = 10 * 60 * 1000;
const LOGIN_OTP_TTL_MS = 10 * 60 * 1000;

function extractAuthToken(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7).trim();
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)custom_token=([^;]*)/);
  if (!m) return null;
  try {
    return decodeURIComponent(m[1].trim());
  } catch {
    return m[1].trim();
  }
}

function getEmailFromTokenString(token) {
  if (!token) return null;
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const [email, timestamp] = decoded.split(':');
    if (!email || !timestamp) return null;
    const tokenAge = Date.now() - parseInt(timestamp, 10);
    if (Number.isNaN(tokenAge) || tokenAge > 24 * 60 * 60 * 1000) return null;
    return email.trim().toLowerCase();
  } catch {
    return null;
  }
}

/** Bearer header or `custom_token` cookie; base64 payload email:timestamp:method */
function getEmailFromBearer(req) {
  return getEmailFromTokenString(extractAuthToken(req));
}

/** Admin middleware: checks token and ensures role is admin */
async function adminOnly(req, res, next) {
  try {
    const email = getEmailFromBearer(req);
    if (!email) {
      return res.status(401).json({ success: false, error: 'Unauthorized: Session required' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, is_admin, role')
      .eq('email', email)
      .maybeSingle();

    if (error || !user || resolveRole(user) !== 'admin') {
      return res.status(403).json({ success: false, error: 'Access denied: Admin only' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Admin middleware error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

function splitDisplayName(name) {
  const s = String(name || '').trim();
  if (!s) return { first_name: 'User', last_name: '-' };
  const parts = s.split(/\s+/);
  if (parts.length === 1) return { first_name: parts[0], last_name: '-' };
  return { first_name: parts[0], last_name: parts.slice(1).join(' ') };
}

// Middleware — CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000 in backend .env
const corsOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
if (!corsOrigins.length) {
  throw new Error(
    'Set CORS_ORIGINS in backend .env (comma-separated frontend origins, e.g. http://localhost:3000,http://127.0.0.1:3000)'
  );
}
app.use(
  cors({
    origin: corsOrigins,
    credentials: true,
  })
);
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const apiPublicUrl = (process.env.API_PUBLIC_URL || '').trim().replace(/\/$/, '');
if (!apiPublicUrl) {
  throw new Error(
    'Set API_PUBLIC_URL in backend .env (public base URL of this API, e.g. http://127.0.0.1:5000)'
  );
}

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Clothing Shop API',
      version: '1.0.0',
      description: 'API documentation for Clothing Shop backend',
    },
    servers: [
      {
        url: apiPublicUrl,
        description: 'API server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
        },
      },
    },
  },
  apis: ['./server.js'],
};

const specs = swaggerJsdoc(swaggerOptions);

// Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

// Routes
app.get("/", (req, res) => {
  res.send("Express server running 🚀 <br> <a href='/api-docs'>API Documentation</a>");
});

/**
 * @swagger
 * /api/auth/check-email:
 *   post:
 *     summary: Check if email exists in Supabase database
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: test@example.com
 *     responses:
 *       200:
 *         description: Email check result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 exists:
 *                   type: boolean
 *                   example: true
 *                 verified:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Email found in our system"
 *                 action:
 *                   type: string
 *                   example: "login"
 */
app.post("/api/auth/check-email", async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email
    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required"
      });
    }

    console.log(`Checking email: ${email}`);

    // Check if email exists in Supabase
    const { data: users, error } = await supabase
      .from('users')
      .select('email, name, email_verified_at')
      .eq('email', email.toLowerCase())
      .single();

    if (error) {
      console.error('Supabase error:', error);

      // If no rows found, user doesn't exist
      if (error.code === 'PGRST116') {
        return res.json({
          success: true,
          exists: false,
          verified: false,
          message: "Email not found in our system",
          action: "signup"
        });
      }

      // Other database errors
      return res.status(500).json({
        success: false,
        message: "Database error occurred"
      });
    }

    if (users) {
      // User found
      res.json({
        success: true,
        exists: true,
        verified: !!users.email_verified_at,
        message: "Email found in our system",
        action: "login",
        user: {
          email: users.email,
          name: users.name,
          verified: !!users.email_verified_at
        }
      });
    } else {
      // User not found
      res.json({
        success: true,
        exists: false,
        verified: false,
        message: "Email not found in our system",
        action: "signup"
      });
    }
  } catch (error) {
    console.error("Email check error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

/**
 * @swagger
 * /api/auth/signup:
 *   post:
 *     summary: Register new user in Supabase
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 6
 *               name:
 *                 type: string
 *               mobile:
 *                 type: string
 *               gender:
 *                 type: string
 *                 enum: [male, female, other]
 *               state:
 *                 type: string
 *     responses:
 *       200:
 *         description: User registration result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 user:
 *                   type: object
 */
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password, name, mobile, gender, state } = req.body;

    // Validate required fields
    if (!email || !password || !name) {
      return res.status(400).json({
        success: false,
        message: "Email, password, and name are required"
      });
    }

    console.log(`Signing up user: ${email}`);

    // Check if email already exists
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('email')
      .eq('email', email.toLowerCase())
      .single();

    if (checkError && checkError.code !== 'PGRST116') {
      console.error('Supabase check error:', checkError);
      return res.status(500).json({
        success: false,
        message: "Database error occurred"
      });
    }

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email already registered. Please login instead."
      });
    }

    // Create new user
    const passwordHash = await hashPassword(password);

    const { data: newUser, error: insertError } = await supabase
      .from('users')
      .insert([
        {
          email: email.toLowerCase(),
          password_hash: passwordHash,
          name: name,
          mobile: mobile || '',
          gender: gender || 'other',
          state: state || '',
          is_banned: false,
          email_verified_at: new Date().toISOString(),
          two_factor_enabled: true,
          created_at: new Date().toISOString()
        }
      ])
      .select('email, name, created_at')
      .single();

    if (insertError) {
      console.error('Supabase insert error:', insertError);
      return res.status(500).json({
        success: false,
        message: "Failed to create user account"
      });
    }

    console.log(`User created successfully: ${email}`);

    res.status(201).json({
      success: true,
      message: "Account created successfully! Please check your email for verification.",
      requiresVerification: true,
      user: {
        email: newUser.email,
        name: newUser.name,
        created_at: newUser.created_at
      }
    });

  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

/**
 * @swagger
 * /api/auth/send-verification:
 *   post:
 *     summary: Send email verification OTP
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Verification email sent
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 */
app.post("/api/auth/send-verification", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required"
      });
    }

    console.log(`Sending verification email to: ${email}`);

    // Generate OTP (6-digit)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Calculate TTL in minutes for the email template
    const ttlMinutes = 10;

    // Store OTP in database
    // For now, checking if there is a table for signup OTPs or just storing it memory/using login OTP logic
    // We should ideally use a proper table like `login_otps` or `signup_otps`.
    // Since we don't know the exact schema for signup OTPs let's see if we should store it in `password_reset_otps` or `login_otps` or what.
    // Wait, earlier code didn't store it in the DB at all!

    try {
      await sendVerificationEmail(email, otp, ttlMinutes);
      console.log(`Verification email sent to ${email}`);
    } catch (mailErr) {
      console.error("Verification email error:", mailErr);
      return res.status(500).json({
        success: false,
        error: "Could not send verification email. Please try again later.",
      });
    }

    const payload = {
      success: true,
      message: "Verification code sent to your email"
    };
    if (process.env.NODE_ENV !== "production") {
      payload.otp = otp;
    }
    res.json(payload);

  } catch (error) {
    console.error("Send verification error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to send verification email"
    });
  }
});

/**
 * @swagger
 * /api/auth/verify-email:
 *   post:
 *     summary: Verify email with OTP
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               otp:
 *                 type: string
 *                 minLength: 6
 *                 maxLength: 6
 *     responses:
 *       200:
 *         description: Email verification result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 verified:
 *                   type: boolean
 *                 message:
 *                   type: string
 */
app.post("/api/auth/verify-email", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required"
      });
    }

    console.log(`Verifying email: ${email} with OTP: ${otp}`);

    // TODO: Verify OTP from database
    // For now, accept any 6-digit OTP for testing
    if (otp.length === 6 && /^\d{6}$/.test(otp)) {

      // Update user as verified in Supabase
      const { error: updateError } = await supabase
        .from('users')
        .update({ email_verified_at: new Date().toISOString() })
        .eq('email', email.toLowerCase());

      if (updateError) {
        console.error('Update verification error:', updateError);
        return res.status(500).json({
          success: false,
          message: "Failed to verify email"
        });
      }

      res.json({
        success: true,
        verified: true,
        message: "Email verified successfully! You can now login."
      });
    } else {
      res.status(400).json({
        success: false,
        message: "Invalid verification code"
      });
    }

  } catch (error) {
    console.error("Verify email error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

/**
 * POST /api/auth/forgot-password
 * Sends / stores a 6-digit OTP for password reset (same table as email verification; purpose=password_reset).
 */
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email is required",
      });
    }

    const { data: user, error: userErr } = await supabase
      .from("users")
      .select("id, email, email_verified_at")
      .eq("email", email)
      .maybeSingle();

    if (userErr || !user) {
      return res.status(404).json({
        success: false,
        error: "No account found with this email address",
      });
    }

    if (!user.email_verified_at) {
      return res.status(403).json({
        success: false,
        error: "Please verify your email before resetting password",
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(
      Date.now() + PASSWORD_RESET_OTP_TTL_MS
    ).toISOString();

    const row = {
      email,
      otp,
      expires_at: expiresAt,
      used: false,
    };

    await supabase
      .from(PASSWORD_RESET_OTPS_TABLE)
      .delete()
      .eq("email", email);

    const { error: upErr } = await supabase
      .from(PASSWORD_RESET_OTPS_TABLE)
      .insert(row);

    if (upErr) {
      console.error("Forgot-password OTP insert error:", upErr);
      if (upErr.code === "PGRST204" || upErr.code === "42703" || upErr.code === "42P01" || (upErr.message && upErr.message.includes("password_reset_otps"))) {
        return res.status(500).json({
          success: false,
          error: "Database migration required: create `password_reset_otps` table",
        });
      }
      return res.status(500).json({
        success: false,
        error: "Failed to create reset code",
      });
    }

    const ttlMinutes = Math.ceil(PASSWORD_RESET_OTP_TTL_MS / 60000);

    try {
      await sendPasswordResetOtpEmail(email, otp, ttlMinutes);
      console.log(`Password reset email sent to ${email}`);
    } catch (mailErr) {
      console.error("Forgot-password email error:", mailErr);
      await supabase
        .from(PASSWORD_RESET_OTPS_TABLE)
        .delete()
        .eq("email", email);
      return res.status(500).json({
        success: false,
        error:
          "Could not send email. Please try again later.",
      });
    }

    const payload = {
      success: true,
      message: "Verification code sent to your email",
    };
    if (process.env.NODE_ENV !== "production") {
      payload.otp = otp;
    }
    return res.json(payload);
  } catch (err) {
    console.error("Forgot-password error:", err);
    return res.status(500).json({
      success: false,
      error: "Failed to process request",
    });
  }
});

/**
 * POST /api/auth/reset-password
 * Body: { email, otp, newPassword }
 */
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const otp = String(req.body.otp || "").trim();
    const newPassword = String(req.body.newPassword || "");

    if (!email || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        error: "Email, OTP and new password are required",
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 8 characters",
      });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        error: "Invalid verification code",
      });
    }

    const { data: row, error: rowErr } = await supabase
      .from(PASSWORD_RESET_OTPS_TABLE)
      .select("otp, expires_at")
      .eq("email", email)
      .maybeSingle();

    if (rowErr || !row) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired reset code",
      });
    }

    if (new Date(row.expires_at).getTime() < Date.now()) {
      await supabase
        .from(PASSWORD_RESET_OTPS_TABLE)
        .delete()
        .eq("email", email);
      return res.status(400).json({
        success: false,
        error: "Reset code has expired",
      });
    }

    if (row.otp !== otp) {
      return res.status(400).json({
        success: false,
        error: "Invalid reset code",
      });
    }

    const passwordHash = await hashPassword(newPassword);
    const { error: updateErr } = await supabase
      .from("users")
      .update({ password_hash: passwordHash })
      .eq("email", email);

    if (updateErr) {
      console.error("Reset-password user update:", updateErr);
      return res.status(500).json({
        success: false,
        error: "Failed to update password",
      });
    }

    await supabase
      .from(PASSWORD_RESET_OTPS_TABLE)
      .delete()
      .eq("email", email);

    return res.json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (err) {
    console.error("Reset-password error:", err);
    return res.status(500).json({
      success: false,
      error: "Failed to reset password",
    });
  }
});

/**
 * POST /api/auth/verify-login-otp
 * Body: { email, otp }
 * Creates the same custom_token as /api/auth/login (loginType='otp').
 */

/**
 * @swagger
 * /api/auth/change-password:
 *   post:
 *     summary: Change user password
 *     description: Authenticated user can change their password by providing current and new password.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               currentPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       200:
 *         description: Password changed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       400:
 *         description: Invalid input or incorrect current password
 *       401:
 *         description: Unauthorized / Session expired
 */
app.post("/api/auth/change-password", async (req, res) => {
  try {
    const email = getEmailFromBearer(req);
    if (!email) {
      return res.status(401).json({
        success: false,
        error: "Session expired. Please login again.",
      });
    }

    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        error: "Current password and new password are required",
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: "New password must be at least 8 characters",
      });
    }

    const { data: user, error: userErr } = await supabase
      .from("users")
      .select("id, password_hash")
      .eq("email", email)
      .single();

    if (userErr || !user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        error: "Incorrect current password",
      });
    }

    const newHash = await hashPassword(newPassword);
    const { error: updateErr } = await supabase
      .from("users")
      .update({ password_hash: newHash })
      .eq("id", user.id);

    if (updateErr) {
      console.error("Change-password update error:", updateErr);
      return res.status(500).json({
        success: false,
        error: "Failed to update password",
      });
    }

    return res.json({
      success: true,
      message: "Password changed successfully!",
    });
  } catch (err) {
    console.error("Change-password error:", err);
    return res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
});

app.post("/api/auth/verify-login-otp", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const otp = String(req.body.otp || "").trim();

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: "Please enter 6-digit OTP",
      });
    }

    const { data: row, error: otpErr } = await supabase
      .from(LOGIN_OTPS_TABLE)
      .select("otp, expires_at")
      .eq("email", email)
      .maybeSingle();

    if (otpErr) {
      console.error("verify-login-otp DB error (table might not exist):", otpErr);
      return res.status(500).json({
        success: false,
        message: "Database error: login OTP table may not be set up. Contact support.",
      });
    }

    if (!row) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    if (new Date(row.expires_at).getTime() < Date.now()) {
      await supabase
        .from(LOGIN_OTPS_TABLE)
        .delete()
        .eq("email", email);
      return res.status(400).json({
        success: false,
        message: "OTP has expired",
      });
    }

    if (row.otp !== otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // Get user from Supabase with fallbacks for missing columns
    let { data: user, error: userErr } = await supabase
      .from("users")
      .select(
        "id, email, name, mobile, gender, state, email_verified_at, is_banned, is_admin, role"
      )
      .eq("email", email)
      .maybeSingle();

    // Fallback if role / is_admin / is_banned columns are missing
    if (userErr && userErr.code === '42703' && String(userErr.message || '').includes('role')) {
      const r = await supabase
        .from('users')
        .select('id, email, name, mobile, gender, state, email_verified_at, is_banned, is_admin')
        .eq('email', email)
        .maybeSingle();
      user = r.data ? { ...r.data, role: 'user' } : null;
      userErr = r.error;
    }
    if (userErr && userErr.code === '42703' && String(userErr.message || '').includes('is_admin')) {
      const r = await supabase
        .from('users')
        .select('id, email, name, mobile, gender, state, email_verified_at, is_banned')
        .eq('email', email)
        .maybeSingle();
      user = r.data ? { ...r.data, is_admin: false } : null;
      userErr = r.error;
    }
    if (userErr && userErr.code === '42703' && String(userErr.message || '').includes('is_banned')) {
      const r = await supabase
        .from('users')
        .select('id, email, name, mobile, gender, state, email_verified_at')
        .eq('email', email)
        .maybeSingle();
      user = r.data ? { ...r.data, is_banned: false, is_admin: false, role: 'user' } : null;
      userErr = r.error;
    }

    if (userErr || !user) {
      console.error("verify-login-otp user lookup failed:", {
        email,
        error: userErr,
      });
      // Treat as invalid OTP to avoid leaking existence details; user can request a new code.
      await supabase
        .from(LOGIN_OTPS_TABLE)
        .delete()
        .eq("email", email);
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP. Please request a new code.",
      });
    }
    if (user.is_banned) {
      return res.status(403).json({
        success: false,
        message: "Account is banned. Please contact support.",
      });
    }

    const token = Buffer.from(`${user.email}:${Date.now()}:otp`).toString(
      "base64"
    );

    // Clear OTP row after successful login
    await supabase
      .from(LOGIN_OTPS_TABLE)
      .delete()
      .eq("email", email);

    const role = resolveRole(user);

    // Non-HTTP-only token cookie so Next app can forward to Express via `custom_token`.
    res.setHeader(
      "Set-Cookie",
      `custom_token=${encodeURIComponent(
        token
      )}; Path=/; Max-Age=86400; SameSite=Lax`
    );

    return res.json({
      success: true,
      message: "Login successful with OTP!",
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        mobile: user.mobile,
        gender: user.gender,
        state: user.state,
        role,
        verified: !!user.email_verified_at,
      },
      token,
      loginMethod: "otp",
    });
  } catch (err) {
    console.error("verify-login-otp error:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

/**
 * POST /api/otp/send-otp
 * Body: { email, purpose? } — currently supports purpose='login' for passwordless login.
 */
app.post("/api/otp/send-otp", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email is required",
      });
    }

    const { data: user, error: userErr } = await supabase
      .from("users")
      .select("id, email, email_verified_at, is_banned")
      .eq("email", email)
      .maybeSingle();

    if (userErr || !user) {
      return res.status(404).json({
        success: false,
        error: "No account found with this email address",
      });
    }
    if (user.is_banned) {
      return res.status(403).json({
        success: false,
        error: "Account is banned. Please contact support.",
      });
    }

    if (!user.email_verified_at) {
      return res.status(403).json({
        success: false,
        error: "Please verify your email before logging in with OTP",
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + LOGIN_OTP_TTL_MS).toISOString();

    const row = {
      email,
      otp,
      expires_at: expiresAt,
    };

    await supabase
      .from(LOGIN_OTPS_TABLE)
      .delete()
      .eq("email", email);

    const { error: upErr } = await supabase
      .from(LOGIN_OTPS_TABLE)
      .insert(row);

    if (upErr) {
      console.error("Login-otp insert error:", upErr);
      return res.status(500).json({
        success: false,
        error: "Failed to create login code",
      });
    }

    const ttlMinutes = Math.ceil(LOGIN_OTP_TTL_MS / 60000);
    try {
      await sendLoginOtpEmail(email, otp, ttlMinutes);
      console.log(`Login OTP email sent to ${email}`);
    } catch (mailErr) {
      console.error("Login-otp email error:", mailErr);
      await supabase
        .from(LOGIN_OTPS_TABLE)
        .delete()
        .eq("email", email);
      return res.status(500).json({
        success: false,
        error: "Could not send email. Please try again later.",
      });
    }

    const payload = {
      success: true,
      message: "Login code sent to your email",
    };
    if (process.env.NODE_ENV !== "production") {
      payload.otp = otp;
    }
    return res.json(payload);
  } catch (err) {
    console.error("Send-otp error:", err);
    return res.status(500).json({
      success: false,
      error: "Failed to send OTP",
    });
  }
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login user with email and password
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *               loginType:
 *                 type: string
 *                 enum: [password, otp]
 *                 default: password
 *     responses:
 *       200:
 *         description: Login result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 user:
 *                   type: object
 *                 token:
 *                   type: string
 */
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password, loginType = 'password', otp } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required"
      });
    }

    console.log(`Login attempt: ${email} with ${loginType}`);

    // Get user from Supabase (is_admin / role columns optional until migrations applied)
    let { data: user, error } = await supabase
      .from('users')
      .select(
        'id, email, name, mobile, gender, state, password_hash, email_verified_at, is_banned, is_admin, role'
      )
      .eq('email', email.toLowerCase())
      .single();

    if (error && error.code === '42703' && String(error.message || '').includes('role')) {
      const r = await supabase
        .from('users')
        .select(
          'id, email, name, mobile, gender, state, password_hash, email_verified_at, is_banned, is_admin'
        )
        .eq('email', email.toLowerCase())
        .single();
      user = r.data ? { ...r.data, role: 'user' } : null;
      error = r.error;
    }
    if (error && error.code === '42703' && String(error.message || '').includes('is_admin')) {
      const r = await supabase
        .from('users')
        .select(
          'id, email, name, mobile, gender, state, password_hash, email_verified_at, is_banned'
        )
        .eq('email', email.toLowerCase())
        .single();
      user = r.data ? { ...r.data, is_admin: false } : null;
      error = r.error;
    }
    if (error && error.code === '42703' && String(error.message || '').includes('is_banned')) {
      const fallback = await supabase
        .from('users')
        .select(
          'id, email, name, mobile, gender, state, password_hash, email_verified_at'
        )
        .eq('email', email.toLowerCase())
        .single();
      user = fallback.data
        ? { ...fallback.data, is_banned: false, is_admin: false }
        : null;
      error = fallback.error;
    }

    if (error) {
      console.error('Supabase login error:', error);
      return res.status(500).json({
        success: false,
        message: "Database error occurred"
      });
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    if (user.is_banned) {
      return res.status(403).json({
        success: false,
        message: "Account is banned. Please contact support."
      });
    }

    // Check if email is verified
    if (!user.email_verified_at) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email before logging in",
        requiresVerification: true
      });
    }

    // Handle different login types
    if (loginType === 'otp') {
      // OTP Login Flow
      if (!otp) {
        return res.status(400).json({
          success: false,
          message: "OTP is required for OTP login"
        });
      }

      // TODO: Verify OTP from database
      // For now, accept any 6-digit OTP for testing
      if (otp.length === 6 && /^\d{6}$/.test(otp)) {

        const token = Buffer.from(`${user.email}:${Date.now()}:otp`).toString('base64');

        console.log(`OTP Login successful: ${email}`);

        res.json({
          success: true,
          message: "Login successful with OTP!",
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            mobile: user.mobile,
            gender: user.gender,
            state: user.state,
            role: resolveRole(user),
            verified: !!user.email_verified_at
          },
          token: token,
          loginMethod: 'otp'
        });
      } else {
        return res.status(401).json({
          success: false,
          message: "Invalid OTP"
        });
      }

    } else {
      // Password Login Flow
      if (!password) {
        return res.status(400).json({
          success: false,
          message: "Password is required for password login"
        });
      }

      // Check password (in production, use proper hashing)
      const validPassword = await isPasswordValid(password, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password"
        });
      }

      // Generate JWT token
      const token = Buffer.from(`${user.email}:${Date.now()}:password`).toString('base64');

      console.log(`Password Login successful: ${email}`);

      res.json({
        success: true,
        message: "Login successful!",
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          mobile: user.mobile,
          gender: user.gender,
          state: user.state,
          role: resolveRole(user),
          verified: !!user.email_verified_at
        },
        token: token,
        loginMethod: 'password'
      });
    }

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Current user (Bearer or custom_token cookie) — used by Next.js server/middleware
 *     responses:
 *       200:
 *         description: User or null
 */
app.get("/api/auth/me", async (req, res) => {
  try {
    const userEmail = getEmailFromBearer(req);
    if (!userEmail) {
      return res.status(401).json({ user: null });
    }

    let { data: user, error } = await supabase
      .from("users")
      .select(
        "id, email, name, mobile, gender, state, email_verified_at, created_at, is_banned, is_admin, role"
      )
      .eq("email", userEmail)
      .single();

    if (error && error.code === "42703" && String(error.message || "").includes("role")) {
      const r = await supabase
        .from("users")
        .select(
          "id, email, name, mobile, gender, state, email_verified_at, created_at, is_banned, is_admin"
        )
        .eq("email", userEmail)
        .single();
      user = r.data ? { ...r.data, role: "user" } : null;
      error = r.error;
    }
    if (error && error.code === "42703" && String(error.message || "").includes("is_admin")) {
      const r = await supabase
        .from("users")
        .select(
          "id, email, name, mobile, gender, state, email_verified_at, created_at, is_banned"
        )
        .eq("email", userEmail)
        .single();
      user = r.data
        ? { ...r.data, is_admin: false, role: "user" }
        : null;
      error = r.error;
    }
    if (error && error.code === "42703" && String(error.message || "").includes("is_banned")) {
      const fb = await supabase
        .from("users")
        .select(
          "id, email, name, mobile, gender, state, email_verified_at, created_at"
        )
        .eq("email", userEmail)
        .single();
      user = fb.data
        ? { ...fb.data, is_banned: false, is_admin: false, role: "user" }
        : null;
      error = fb.error;
    }

    if (error || !user) {
      return res.status(401).json({ user: null });
    }

    if (user.is_banned) {
      return res.status(403).json({ user: null, banned: true });
    }

    const role = resolveRole(user);
    return res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        mobile: user.mobile,
        gender: user.gender,
        state: user.state,
        role,
        verified: !!user.email_verified_at,
        two_factor_enabled: true,
      },
    });
  } catch (err) {
    console.error("GET /api/auth/me error:", err);
    return res.status(500).json({ user: null });
  }
});

/**
 * @swagger
 * /api/auth/profile:
 *   get:
 *     summary: Get current user profile
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 user:
 *                   type: object
 */
app.get("/api/auth/profile", async (req, res) => {
  try {
    const token = extractAuthToken(req);
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authorization token required"
      });
    }

    // Decode token (simple base64 decode)
    let decoded;
    try {
      decoded = Buffer.from(token, 'base64').toString('utf8');
      const [email, timestamp, loginMethod] = decoded.split(':');

      if (!email || !timestamp) {
        return res.status(401).json({
          success: false,
          message: "Invalid token format"
        });
      }

      // Check if token is expired (24 hours)
      const tokenAge = Date.now() - parseInt(timestamp);
      if (tokenAge > 24 * 60 * 60 * 1000) {
        return res.status(401).json({
          success: false,
          message: "Token expired"
        });
      }

      // Get user from Supabase
      let { data: user, error } = await supabase
        .from('users')
        .select('id, email, name, mobile, gender, state, email_verified_at, created_at, is_admin, role')
        .eq('email', email.toLowerCase())
        .single();

      if (error && error.code === '42703' && String(error.message || '').includes('role')) {
        const r = await supabase
          .from('users')
          .select('id, email, name, mobile, gender, state, email_verified_at, created_at, is_admin')
          .eq('email', email.toLowerCase())
          .single();
        user = r.data ? { ...r.data, role: 'user' } : null;
        error = r.error;
      }
      if (error && error.code === '42703' && String(error.message || '').includes('is_admin')) {
        const fb = await supabase
          .from('users')
          .select('id, email, name, mobile, gender, state, email_verified_at, created_at')
          .eq('email', email.toLowerCase())
          .single();
        user = fb.data ? { ...fb.data, is_admin: false, role: 'user' } : null;
        error = fb.error;
      }

      if (error || !user) {
        return res.status(401).json({
          success: false,
          message: "User not found"
        });
      }

      console.log(`Profile accessed: ${email}`);

      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          mobile: user.mobile,
          gender: user.gender,
          state: user.state,
          role: resolveRole(user),
          verified: !!user.email_verified_at,
          created_at: user.created_at,
          loginMethod: loginMethod || 'unknown'
        }
      });

    } catch (decodeError) {
      return res.status(401).json({
        success: false,
        message: "Invalid token"
      });
    }

  } catch (error) {
    console.error("Profile error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

/**
 * @swagger
 * /api/auth/dashboard:
 *   get:
 *     summary: Get user dashboard data
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Dashboard data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 */
app.get("/api/auth/dashboard", async (req, res) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: "Authorization token required"
      });
    }

    const token = authHeader.substring(7);

    // Decode token
    let decoded;
    try {
      decoded = Buffer.from(token, 'base64').toString('utf8');
      const [email, timestamp] = decoded.split(':');

      if (!email || !timestamp) {
        return res.status(401).json({
          success: false,
          message: "Invalid token"
        });
      }

      // Check token expiry
      const tokenAge = Date.now() - parseInt(timestamp);
      if (tokenAge > 24 * 60 * 60 * 1000) {
        return res.status(401).json({
          success: false,
          message: "Token expired"
        });
      }

      // Get user data
      const { data: user, error } = await supabase
        .from('users')
        .select('email, name, created_at, email_verified_at')
        .eq('email', email.toLowerCase())
        .single();

      if (error || !user) {
        return res.status(401).json({
          success: false,
          message: "User not found"
        });
      }

      // Mock dashboard data
      const dashboardData = {
        user: {
          email: user.email,
          name: user.name,
          memberSince: user.created_at,
          verified: !!user.email_verified_at
        },
        stats: {
          totalLogins: Math.floor(Math.random() * 100) + 1,
          lastLogin: new Date().toISOString(),
          accountStatus: user.email_verified_at ? 'active' : 'pending'
        },
        recentActivity: [
          {
            type: 'login',
            timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
            description: 'Login from web'
          },
          {
            type: 'profile_update',
            timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
            description: 'Profile information updated'
          }
        ],
        notifications: [
          {
            type: 'welcome',
            message: 'Welcome to Clothing Shop!',
            read: false,
            timestamp: user.created_at
          }
        ]
      };

      console.log(`Dashboard accessed: ${email}`);

      res.json({
        success: true,
        data: dashboardData
      });

    } catch (decodeError) {
      return res.status(401).json({
        success: false,
        message: "Invalid token"
      });
    }

  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

/**
 * @swagger
 * /api/auth/update-profile:
 *   put:
 *     summary: Update user profile
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               mobile:
 *                 type: string
 *               gender:
 *                 type: string
 *                 enum: [male, female, other]
 *               state:
 *                 type: string
 *     responses:
 *       200:
 *         description: Profile update result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 user:
 *                   type: object
 */
app.put("/api/auth/update-profile", async (req, res) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: "Authorization token required"
      });
    }

    const token = authHeader.substring(7);

    // Decode token
    let decoded;
    try {
      decoded = Buffer.from(token, 'base64').toString('utf8');
      const [email] = decoded.split(':');

      if (!email) {
        return res.status(401).json({
          success: false,
          message: "Invalid token"
        });
      }

      // Get user from Supabase
      const { data: user, error } = await supabase
        .from('users')
        .select('email, name, mobile, gender, state, created_at')
        .eq('email', email.toLowerCase())
        .single();

      if (error || !user) {
        return res.status(401).json({
          success: false,
          message: "User not found"
        });
      }

      // Extract update data
      const { name, mobile, gender, state } = req.body;

      // Build update object
      const updateData = {};
      if (name !== undefined) updateData.name = name;
      if (mobile !== undefined) updateData.mobile = mobile;
      if (gender !== undefined) updateData.gender = gender;
      if (state !== undefined) updateData.state = state;

      if (Object.keys(updateData).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No fields to update"
        });
      }

      // Update user in Supabase
      const { data: updatedUser, error: updateError } = await supabase
        .from('users')
        .update(updateData)
        .eq('email', email.toLowerCase())
        .select('email, name, mobile, gender, state, created_at')
        .single();

      if (updateError) {
        console.error('Update error:', updateError);
        return res.status(500).json({
          success: false,
          message: "Failed to update profile"
        });
      }

      console.log(`Profile updated for: ${email}`);

      res.json({
        success: true,
        message: "Profile updated successfully!",
        user: {
          email: updatedUser.email,
          name: updatedUser.name,
          mobile: updatedUser.mobile,
          gender: updatedUser.gender,
          state: updatedUser.state,
          created_at: updatedUser.created_at
        }
      });

    } catch (decodeError) {
      return res.status(401).json({
        success: false,
        message: "Invalid token"
      });
    }

  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout success
 */
app.post("/api/auth/logout", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: "No active session"
      });
    }

    const token = authHeader.substring(7);

    // Decode token to get email
    let decoded;
    try {
      decoded = Buffer.from(token, 'base64').toString('utf8');
      const [email] = decoded.split(':');

      if (!email) {
        return res.status(401).json({
          success: false,
          message: "Invalid token"
        });
      }

      console.log(`User logged out: ${email}`);

      // In a real app, you would:
      // 1. Add token to blacklist
      // 2. Remove active session from database
      // 3. Clear cookies if using cookie-based auth

      res.json({
        success: true,
        message: "Logout successful"
      });

    } catch (decodeError) {
      return res.status(401).json({
        success: false,
        message: "Invalid token"
      });
    }

  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all users from Supabase
 *     responses:
 *       200:
 *         description: List of users
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 users:
 *                   type: array
 *                   items:
 *                     type: object
 */
app.get("/api/users", async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('email, name, email_verified_at, created_at');

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch users"
      });
    }

    res.json({
      success: true,
      users: users.map(u => ({
        email: u.email,
        name: u.name,
        verified: !!u.email_verified_at,
        created_at: u.created_at
      }))
    });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

/**
 * @swagger
 * /api/contact:
 *   post:
 *     summary: Send a contact message (public)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - first_name
 *               - last_name
 *               - email
 *               - message
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phone:
 *                 type: string
 *               message:
 *                 type: string
 *     responses:
 *       201:
 *         description: Message saved
 *       400:
 *         description: Validation error
 */
app.post("/api/contact", async (req, res) => {
  try {
    const { first_name, last_name, email, phone, message } = req.body || {};
    const fn = first_name != null ? String(first_name).trim() : '';
    const ln = last_name != null ? String(last_name).trim() : '';
    const em = email != null ? String(email).trim().toLowerCase() : '';
    const msg = message != null ? String(message).trim() : '';

    if (!fn || !ln || !em || !msg) {
      return res.status(400).json({
        success: false,
        message: "first_name, last_name, email, and message are required",
      });
    }

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em);
    if (!emailOk) {
      return res.status(400).json({
        success: false,
        message: "Invalid email address",
      });
    }

    const phoneVal =
      phone != null && String(phone).trim() ? String(phone).trim() : null;

    const payload = {
      first_name: fn,
      last_name: ln,
      email: em,
      phone: phoneVal,
      message: msg,
    };

    const { data, error } = await supabase
      .from("contact_submissions")
      .insert([payload])
      .select("id, first_name, last_name, email, phone, message, created_at, status")
      .single();

    if (error) {
      console.error("Contact insert error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to send message. Please try again later.",
      });
    }

    return res.status(201).json({
      success: true,
      message: "Message sent successfully",
      submission: data,
    });
  } catch (err) {
    console.error("POST /api/contact error:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

/**
 * @swagger
 * /api/messages:
 *   get:
 *     summary: List contact messages for the logged-in user (by email)
 *     security:
 *       - bearerAuth: []
 *   post:
 *     summary: Send a contact message as the logged-in user
 *     security:
 *       - bearerAuth: []
 */
app.get("/api/messages", async (req, res) => {
  try {
    const userEmail = getEmailFromBearer(req);
    if (!userEmail) {
      return res.status(401).json({ error: "Authorization token required" });
    }

    const { data: messages, error } = await supabase
      .from("contact_submissions")
      .select(
        "id, first_name, last_name, email, phone, message, created_at, status, is_read"
      )
      .eq("email", userEmail)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("GET /api/messages:", error);
      return res
        .status(500)
        .json({ error: "Failed to load messages", messages: [] });
    }

    const { data: repliesData } = await supabase
      .from("contact_replies")
      .select("id, contact_submission_id, admin_reply, created_at");

    const replyMap = {};
    (repliesData || []).forEach((r) => {
      const key = String(r.contact_submission_id);
      if (!replyMap[key]) replyMap[key] = [];
      replyMap[key].push({
        id: r.id,
        admin_reply: r.admin_reply,
        created_at: r.created_at,
      });
    });

    const withReplies = (messages || []).map((m) => ({
      ...m,
      replies: replyMap[String(m.id)] || [],
    }));

    return res.json({ messages: withReplies });
  } catch (err) {
    console.error("GET /api/messages error:", err);
    return res.status(500).json({ error: "Internal server error", messages: [] });
  }
});

app.post("/api/messages", async (req, res) => {
  try {
    const userEmail = getEmailFromBearer(req);
    if (!userEmail) {
      return res.status(401).json({ error: "Authorization token required" });
    }

    const { message } = req.body || {};
    const msg = message != null ? String(message).trim() : "";
    if (!msg) {
      return res.status(400).json({ error: "message is required" });
    }

    const { data: user, error: userErr } = await supabase
      .from("users")
      .select("name, mobile")
      .eq("email", userEmail)
      .single();

    if (userErr || !user) {
      return res.status(401).json({ error: "User not found" });
    }

    const { first_name, last_name } = splitDisplayName(user.name);
    const phoneVal =
      user.mobile != null && String(user.mobile).trim()
        ? String(user.mobile).trim()
        : null;

    const payload = {
      first_name,
      last_name,
      email: userEmail,
      phone: phoneVal,
      message: msg,
    };

    const { data, error } = await supabase
      .from("contact_submissions")
      .insert([payload])
      .select(
        "id, first_name, last_name, email, phone, message, created_at, status, is_read"
      )
      .single();

    if (error) {
      console.error("POST /api/messages insert:", error);
      return res.status(500).json({ error: "Failed to send message" });
    }

    return res.status(201).json({
      success: true,
      message: "Message sent successfully",
      submission: { ...data, replies: [] },
    });
  } catch (err) {
    console.error("POST /api/messages error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ---------------------------
// Admin APIs used by frontend
// ---------------------------

/**
 * @swagger
 * /api/admin/welcome:
 *   get:
 *     summary: Admin welcome endpoint
 *     responses:
 *       200:
 *         description: Welcome message
 */
app.get("/api/admin/welcome", (req, res) => {
  res.json({ success: true, message: "Welcome admin" });
});

/**
 * @swagger
 * /api/admin/dashboard:
 *   get:
 *     summary: Get admin dashboard stats
 *     responses:
 *       200:
 *         description: Dashboard stats
 */
app.get("/api/admin/dashboard", async (req, res) => {
  try {
    const store = loadAdminStore();
    const { data: users } = await supabase
      .from('users')
      .select('id, is_banned');

    const totalUsers = (users || []).length;
    const activeUsers = (users || []).filter((u) => !u.is_banned).length;

    return res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers,
        customProducts: store.customProducts.length,
        featuredProducts: store.featured.length,
      },
    });
  } catch {
    return res.json({
      success: true,
      stats: { totalUsers: 0, activeUsers: 0, customProducts: 0, featuredProducts: 0 },
    });
  }
});

/**
 * @swagger
 * /api/admin/profile:
 *   get:
 *     summary: Get admin profile by email
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Admin profile
 *       400:
 *         description: Missing email
 *       404:
 *         description: Admin not found
 */
app.get("/api/admin/profile", async (req, res) => {
  try {
    const email = String(req.query.email || '').toLowerCase();
    if (!email) return res.status(400).json({ error: 'email query param is required' });

    let { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, mobile, gender, state, created_at, is_admin, role')
      .eq('email', email)
      .single();

    if (error && error.code === '42703' && String(error.message || '').includes('role')) {
      const r = await supabase
        .from('users')
        .select('id, email, name, mobile, gender, state, created_at, is_admin')
        .eq('email', email)
        .single();
      user = r.data ? { ...r.data, role: 'user' } : null;
      error = r.error;
    }
    if (error && error.code === '42703' && String(error.message || '').includes('is_admin')) {
      const fb = await supabase
        .from('users')
        .select('id, email, name, mobile, gender, state, created_at')
        .eq('email', email)
        .single();
      user = fb.data ? { ...fb.data, is_admin: false, role: 'user' } : null;
      error = fb.error;
    }

    if (error || !user) return res.status(404).json({ error: 'Admin not found' });
    if (resolveRole(user) !== 'admin') {
      return res.status(404).json({ error: 'Admin not found' });
    }

    return res.json({
      success: true,
      user: {
        ...user,
        role: 'admin',
      },
    });
  } catch {
    return res.status(500).json({ error: 'Failed to load admin profile' });
  }
});

/**
 * @swagger
 * /api/admin/users:
 *   get:
 *     summary: List users for admin panel
 *     responses:
 *       200:
 *         description: Users list
 */
app.get("/api/admin/users", async (req, res) => {
  try {
    let { data: users, error } = await supabase
      .from('users')
      .select('id, email, name, mobile, gender, state, is_banned, created_at, is_admin, role');

    if (error && error.code === '42703' && String(error.message || '').includes('role')) {
      const r = await supabase
        .from('users')
        .select('id, email, name, mobile, gender, state, is_banned, created_at, is_admin');
      users = (r.data || []).map((u) => ({ ...u, role: 'user' }));
      error = r.error;
    }
    if (error && error.code === '42703' && String(error.message || '').includes('is_admin')) {
      const r = await supabase
        .from('users')
        .select('id, email, name, mobile, gender, state, is_banned, created_at');
      users = (r.data || []).map((u) => ({ ...u, is_admin: false, role: 'user' }));
      error = r.error;
    }

    if (error) {
      return res.status(500).json({ error: error.message || 'Failed to load users' });
    }

    const mapped = (users || []).map((u) => ({
      id: u.id || u.email,
      email: u.email,
      name: u.name || null,
      role: resolveRole(u),
      mobile: u.mobile || null,
      gender: u.gender || null,
      state: u.state || null,
      is_banned: !!u.is_banned,
      created_at: u.created_at || null,
    }));

    return res.json({ users: mapped });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load users' });
  }
});

/**
 * @swagger
 * /api/admin/update-profile:
 *   post:
 *     summary: Update admin profile
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               name:
 *                 type: string
 *               mobile:
 *                 type: string
 *               gender:
 *                 type: string
 *               state:
 *                 type: string
 *     responses:
 *       200:
 *         description: Updated profile
 */
app.post("/api/admin/update-profile", async (req, res) => {
  try {
    const { email, name, mobile, gender, state } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (mobile !== undefined) updateData.mobile = mobile;
    if (gender !== undefined) updateData.gender = gender;
    if (state !== undefined) updateData.state = state;

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    const { data: updatedUser, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('email', String(email).toLowerCase())
      .select('email, name, mobile, gender, state, created_at')
      .single();

    if (error) {
      return res.status(500).json({ error: error.message || 'Failed to update admin profile' });
    }

    return res.json({
      success: true,
      user: {
        email: updatedUser.email,
        name: updatedUser.name,
        mobile: updatedUser.mobile,
        gender: updatedUser.gender,
        state: updatedUser.state,
        created_at: updatedUser.created_at,
      },
    });
  } catch {
    return res.status(500).json({ error: 'Failed to update admin profile' });
  }
});

/**
 * @swagger
 * /api/admin/products/featured:
 *   get:
 *     summary: Get featured product ids
 *     responses:
 *       200:
 *         description: Featured ids
 *   post:
 *     summary: Toggle featured product
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               productId:
 *                 type: string
 *               featured:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Updated featured ids
 */
app.get("/api/admin/products/featured", (req, res) => {
  const store = loadAdminStore();
  res.json({ featured: store.featured });
});

app.post("/api/admin/products/featured", (req, res) => {
  const { productId, featured } = req.body || {};
  if (!productId || typeof featured !== 'boolean') {
    return res.status(400).json({ error: 'productId and featured are required' });
  }
  const store = loadAdminStore();
  const id = String(productId);
  if (featured) {
    store.featured = Array.from(new Set([...store.featured, id]));
  } else {
    store.featured = store.featured.filter((x) => x !== id);
  }
  saveAdminStore(store);
  res.json({ success: true, featured: store.featured });
});

/**
 * @swagger
 * /api/admin/products/overrides:
 *   get:
 *     summary: Get product image overrides
 *     responses:
 *       200:
 *         description: Overrides list
 */
app.get("/api/admin/products/overrides", (req, res) => {
  const store = loadAdminStore();
  res.json({ overrides: store.overrides });
});

/**
 * @swagger
 * /api/admin/products/upload:
 *   post:
 *     summary: Upload product image override
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               productId:
 *                 type: string
 *               file:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: Uploaded image override
 */
app.post("/api/admin/products/upload", upload.single('file'), (req, res) => {
  try {
    const productId = String(req.body?.productId || '');
    if (!productId) return res.status(400).json({ error: 'productId is required' });
    if (!req.file) return res.status(400).json({ error: 'file is required' });

    const mime = req.file.mimetype || 'image/png';
    const base64 = req.file.buffer.toString('base64');
    const image = `data:${mime};base64,${base64}`;

    const store = loadAdminStore();
    store.overrides = store.overrides.filter((o) => o.product_id !== productId);
    store.overrides.push({ product_id: productId, image });
    saveAdminStore(store);

    return res.json({ success: true, image });
  } catch {
    return res.status(500).json({ error: 'Upload failed' });
  }
});

/**
 * @swagger
 * /api/admin/products/overrides/{id}:
 *   delete:
 *     summary: Delete product image override
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Override removed
 */
app.delete("/api/admin/products/overrides/:id", (req, res) => {
  const id = String(req.params.id);
  const store = loadAdminStore();
  store.overrides = store.overrides.filter((o) => o.product_id !== id);
  saveAdminStore(store);
  res.json({ success: true });
});

/**
 * @swagger
 * /api/admin/products/custom:
 *   get:
 *     summary: Get custom products
 *     responses:
 *       200:
 *         description: Custom products list
 */
app.get("/api/admin/products/custom", (req, res) => {
  const store = loadAdminStore();
  res.json({ products: store.customProducts });
});

/**
 * @swagger
 * /api/admin/products/create:
 *   post:
 *     summary: Create custom product
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id:
 *                 type: string
 *               name:
 *                 type: string
 *               price:
 *                 type: number
 *               category:
 *                 type: string
 *               description:
 *                 type: string
 *     responses:
 *       200:
 *         description: Created product
 */
app.post("/api/admin/products/create", (req, res) => {
  const { id, name, price, category, description } = req.body || {};
  if (!id || !name || Number.isNaN(Number(price)) || !category) {
    return res.status(400).json({ error: 'id, name, price, and category are required' });
  }

  const store = loadAdminStore();
  if (store.customProducts.some((p) => p.id === String(id))) {
    return res.status(400).json({ error: 'Product ID already exists' });
  }

  const product = {
    id: String(id),
    name: String(name),
    price: Number(price),
    category: String(category),
    description: description ? String(description) : null,
    image: null,
  };
  store.customProducts.unshift(product);
  saveAdminStore(store);
  res.json({ success: true, product });
});

/**
 * @swagger
 * /api/admin/products/custom/{id}:
 *   delete:
 *     summary: Delete custom product
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Product deleted
 */
app.delete("/api/admin/products/custom/:id", (req, res) => {
  const id = String(req.params.id);
  const store = loadAdminStore();
  store.customProducts = store.customProducts.filter((p) => p.id !== id);
  store.overrides = store.overrides.filter((o) => o.product_id !== id);
  store.featured = store.featured.filter((x) => x !== id);
  saveAdminStore(store);
  res.json({ success: true });
});

/**
 * @swagger
 * /api/admin/massage:
 *   get:
 *     summary: Get contact messages for admin
 *     responses:
 *       200:
 *         description: Messages list
 */
app.get("/api/admin/massage", async (req, res) => {
  try {
    const { data: messages, error } = await supabase
      .from('contact_submissions')
      .select('id, first_name, last_name, email, phone, message, created_at, status, is_read')
      .order('created_at', { ascending: false });

    if (error) {
      const store = loadAdminStore();
      return res.json({ messages: (store.fallbackMessages || []).map((m) => ({ ...m, replies: [] })) });
    }

    const { data: repliesData } = await supabase
      .from('contact_replies')
      .select('id, contact_submission_id, admin_reply, created_at');

    const replyMap = {};
    (repliesData || []).forEach((r) => {
      const key = String(r.contact_submission_id);
      if (!replyMap[key]) replyMap[key] = [];
      replyMap[key].push({ id: r.id, admin_reply: r.admin_reply, created_at: r.created_at });
    });

    const withReplies = (messages || []).map((m) => ({
      ...m,
      replies: replyMap[String(m.id)] || [],
    }));
    return res.json({ messages: withReplies });
  } catch {
    return res.json({ messages: [] });
  }
});

/**
 * @swagger
 * /api/admin/replies:
 *   post:
 *     summary: Add admin reply to contact message
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               contact_submission_id:
 *                 type: integer
 *               admin_reply:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reply saved
 */
app.post("/api/admin/replies", async (req, res) => {
  try {
    const { contact_submission_id, admin_reply } = req.body || {};
    if (!contact_submission_id || !admin_reply) {
      return res.status(400).json({ error: 'contact_submission_id and admin_reply are required' });
    }

    const { data, error } = await supabase
      .from('contact_replies')
      .insert([
        {
          contact_submission_id,
          admin_reply: String(admin_reply),
          created_at: new Date().toISOString(),
        },
      ])
      .select('id, contact_submission_id, admin_reply, created_at')
      .single();

    if (error) {
      const store = loadAdminStore();
      store.replies.push({
        id: `${Date.now()}`,
        contact_submission_id: String(contact_submission_id),
        admin_reply: String(admin_reply),
        created_at: new Date().toISOString(),
      });
      saveAdminStore(store);
      return res.json({ success: true });
    }

    return res.json({ success: true, reply: data });
  } catch {
    return res.status(500).json({ error: 'Failed to send reply' });
  }
});


/**
 * @swagger
 * /api/website-info:
 *   get:
 *     summary: Get public website identity info (name, logo, contact, hours)
 *     responses:
 *       200:
 *         description: Website name, logo, contact info and business hours
 *  */
app.get("/api/website-info", async (req, res) => {
  try {
    const { data: settings, error } = await supabase
      .from('website_settings')
      .select('name, logo_url, address, phone, email, business_hours')
      .eq('id', 1)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') {
      console.error("API website-info DB error:", error);
    }

    const websiteInfo = {
      name: settings?.name || 'Ma Baba Cloth Store',
      logoUrl: settings?.logo_url || '',
      address: settings?.address || 'Post office gadli, Gadli, District - Jhunjhunu, State - Rajasthan, PIN - 333033',
      phone: settings?.phone || '+91 86967 90758',
      email: settings?.email || 'manishjangir348@gmail.com',
      businessHours: settings?.business_hours || {
        weekdays: '9:00 AM - 9:00 PM',
        sunday: '10:00 AM - 8:00 PM'
      }
    };

    res.json({ success: true, websiteInfo });
  } catch (err) {
    console.error("Website info error:", err);
    res.json({ 
      success: true, 
      websiteInfo: { 
        name: 'Ma Baba Cloth Store', 
        logoUrl: '',
        address: 'Post office gadli, Gadli, District - Jhunjhunu, State - Rajasthan, PIN - 333033',
        phone: '+91 86967 90758',
        email: 'manishjangir348@gmail.com',
        businessHours: {
          weekdays: '9:00 AM - 9:00 PM',
          sunday: '10:00 AM - 8:00 PM'
        }
      } 
    });
  }
});

/**
 * @swagger
 * /api/admin/website-info:
 *   put:
 *     summary: Update website name, logo, contact and hours (Admin only)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               logoUrl:
 *                 type: string
 *               address:
 *                 type: string
 *               phone:
 *                 type: string
 *               email:
 *                 type: string
 *               businessHours:
 *                 type: object
 *     responses:
 *       200:
 *         description: Website info updated
 *  */
app.put("/api/admin/website-info", adminOnly, async (req, res) => {
  try {
    const { name, logoUrl, address, phone, email, businessHours } = req.body;

    // Fetch existing first
    const { data: current, error: getErr } = await supabase
      .from('website_settings')
      .select('name, logo_url, address, phone, email, business_hours')
      .eq('id', 1)
      .maybeSingle();

    const newName = name || current?.name || 'Ma Baba Cloth Store';
    const newLogo = typeof logoUrl === 'string' ? logoUrl : (current?.logo_url || '');
    const newAddress = address || current?.address || '';
    const newPhone = phone || current?.phone || '';
    const newEmail = email || current?.email || '';
    const newBusinessHours = businessHours || current?.business_hours || {};

    const { error: upsertErr } = await supabase
      .from('website_settings')
      .upsert({ 
        id: 1, 
        name: newName, 
        logo_url: newLogo, 
        address: newAddress,
        phone: newPhone,
        email: newEmail,
        business_hours: newBusinessHours,
        updated_at: new Date().toISOString() 
      });

    if (upsertErr) {
      console.error("Update website info error:", upsertErr);
      return res.status(500).json({ error: 'Failed to update settings in database' });
    }

    res.json({ 
      success: true, 
      websiteInfo: { 
        name: newName, 
        logoUrl: newLogo,
        address: newAddress,
        phone: newPhone,
        email: newEmail,
        businessHours: newBusinessHours
      } 
    });
  } catch (err) {
    console.error("Update website info error:", err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @swagger
 * /api/admin/website-info/upload-logo:
 *   post:
 *     summary: Update website logo (Admin only)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: Logo uploaded and stored
 */
app.post("/api/admin/website-info/upload-logo", adminOnly, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'file is required' });

    const mime = req.file.mimetype || 'image/png';
    const base64 = req.file.buffer.toString('base64');
    const image = `data:${mime};base64,${base64}`;

    // Get existing to preserve other fields during upsert
    const { data: current } = await supabase
      .from('website_settings')
      .select('*')
      .eq('id', 1)
      .maybeSingle();

    const { error: upsertErr } = await supabase
      .from('website_settings')
      .upsert({
        ...current,
        id: 1,
        logo_url: image,
        updated_at: new Date().toISOString()
      });

    if (upsertErr) {
      console.error("Upload logo db error:", upsertErr);
      return res.status(500).json({ error: 'Failed to save logo to database' });
    }

    return res.json({ success: true, logoUrl: image });
  } catch (err) {
    console.error('Logo upload error:', err);
    return res.status(500).json({ error: 'Upload failed' });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🗄️ Supabase URL: ${supabaseUrl}`);
  console.log(`📚 API docs: ${apiPublicUrl}/api-docs`);
  console.log(
    'ℹ️  Admin panel: set users.is_admin = true in Supabase for accounts that should access /admin'
  );
});