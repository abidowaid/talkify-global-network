const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || "development";

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_IN_PRODUCTION";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "";

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is not configured.");
  process.exit(1);
}

if (
  NODE_ENV === "production" &&
  (!process.env.JWT_SECRET ||
    process.env.JWT_SECRET === "CHANGE_THIS_IN_PRODUCTION")
) {
  console.error("ERROR: A strong JWT_SECRET is required in production.");
  process.exit(1);
}

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

/* =========================================================
   SECURITY / CORS
========================================================= */

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

const allowedOrigins = FRONTEND_ORIGIN
  .split(",")
  .map((x) => x.trim())
  .filter(Boolean);

const corsOptions = {
  credentials: true,
  origin: function (origin, callback) {
    // Development: allow SPCK preview and local testing.
    if (NODE_ENV !== "production") {
      if (
        !origin ||
        origin === "null" ||
        origin.startsWith("http://localhost") ||
        origin.startsWith("http://127.0.0.1") ||
        origin.startsWith("https://localhost") ||
        origin.startsWith("https://127.0.0.1")
      ) {
        return callback(null, true);
      }

      return callback(null, true);
    }

    // Production: only explicitly configured origins.
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("CORS origin not allowed"));
  }
};

app.use(cors(corsOptions));

/* =========================================================
   REQUEST ID
========================================================= */

app.use((req, res, next) => {
  const requestId = crypto.randomUUID();

  req.requestId = requestId;
  res.setHeader("X-Request-ID", requestId);

  next();
});

/* =========================================================
   RATE LIMITERS
========================================================= */

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: "Too many authentication attempts. Please try again later."
  }
});

app.use(generalLimiter);

/* =========================================================
   HELPERS
========================================================= */

function sendError(res, status, message, extra = {}) {
  return res.status(status).json({
    ok: false,
    error: message,
    requestId: res.getHeader("X-Request-ID"),
    ...extra
  });
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "7d"
  });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function setAuthCookie(res, token) {
  res.cookie("talkify_session", token, {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: NODE_ENV === "production" ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/"
  });
}

function clearAuthCookie(res) {
  res.clearCookie("talkify_session", {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: NODE_ENV === "production" ? "none" : "lax",
    path: "/"
  });
}

function getTokenFromRequest(req) {
  if (req.cookies && req.cookies.talkify_session) {
    return req.cookies.talkify_session;
  }

  const auth = req.headers.authorization || "";

  if (auth.startsWith("Bearer ")) {
    return auth.substring(7);
  }

  return null;
}

function requireAuth(req, res, next) {
  try {
    const token = getTokenFromRequest(req);

    if (!token) {
      return sendError(res, 401, "Authentication required.");
    }

    const payload = verifyToken(token);

    req.auth = payload;

    next();
  } catch (error) {
    return sendError(res, 401, "Invalid or expired session.");
  }
}

function requireMasterAdmin(req, res, next) {
  if (!req.auth || req.auth.type !== "master_admin") {
    return sendError(res, 403, "Master Admin access required.");
  }

  next();
}

function normalizePhone(phone) {
  return String(phone || "")
    .trim()
    .replace(/[^\d+]/g, "");
}

function generateRegistrationId() {
  return (
    "REG-" +
    Date.now().toString(36).toUpperCase() +
    "-" +
    crypto.randomBytes(3).toString("hex").toUpperCase()
  );
}

/* =========================================================
   AUDIT LOG
========================================================= */

async function writeAudit({
  adminId = null,
  action,
  targetType = null,
  targetId = null,
  details = {}
}) {
  try {
    await pool.query(
      `
      INSERT INTO audit_logs
      (
        admin_id,
        action,
        target_type,
        target_id,
        details,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, NOW())
      `,
      [
        adminId,
        action,
        targetType,
        targetId,
        JSON.stringify(details)
      ]
    );
  } catch (error) {
    console.error("Audit log error:", error.message);
  }
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS db_time");

    return res.json({
      ok: true,
      service: "Talkify Global Network Backend",
      time: new Date().toISOString(),
      environment: NODE_ENV,
      database: "connected",
      dbTime: result.rows[0].db_time,
      requestId: req.requestId
    });
  } catch (error) {
    return res.status(503).json({
      ok: false,
      service: "Talkify Global Network Backend",
      time: new Date().toISOString(),
      environment: NODE_ENV,
      database: "error",
      error: "Database connection failed.",
      requestId: req.requestId
    });
  }
});

/* =========================================================
   AUTH SESSION
========================================================= */

app.get("/api/auth/session", async (req, res) => {
  try {
    const token = getTokenFromRequest(req);

    if (!token) {
      return res.json({
        ok: true,
        authenticated: false
      });
    }

    const payload = verifyToken(token);

    if (payload.type === "master_admin") {
      const result = await pool.query(
        `
        SELECT id, username, display_name, is_active
        FROM master_admins
        WHERE id = $1
        LIMIT 1
        `,
        [payload.id]
      );

      if (!result.rows.length || !result.rows[0].is_active) {
        clearAuthCookie(res);

        return res.json({
          ok: true,
          authenticated: false
        });
      }

      return res.json({
        ok: true,
        authenticated: true,
        type: "master_admin",
        user: result.rows[0]
      });
    }

    if (payload.type === "user") {
      const result = await pool.query(
        `
        SELECT
          id,
          phone,
          network_number,
          full_name,
          kyc_status,
          is_active,
          created_at
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [payload.id]
      );

      if (!result.rows.length || !result.rows[0].is_active) {
        clearAuthCookie();

        return res.json({
          ok: true,
          authenticated: false
        });
      }

      return res.json({
        ok: true,
        authenticated: true,
        type: "user",
        user: result.rows[0]
      });
    }

    clearAuthCookie();

    return res.json({
      ok: true,
      authenticated: false
    });
  } catch (error) {
    clearAuthCookie();

    return res.json({
      ok: true,
      authenticated: false
    });
  }
});

/* =========================================================
   MASTER ADMIN SETUP
========================================================= */

app.post(
  "/api/admin/setup",
  authLimiter,
  async (req, res) => {
    try {
      const { username, password, displayName } = req.body;

      if (!username || !password) {
        return sendError(
          res,
          400,
          "Username and password are required."
        );
      }

      if (String(password).length < 8) {
        return sendError(
          res,
          400,
          "Password must contain at least 8 characters."
        );
      }

      const countResult = await pool.query(
        `SELECT COUNT(*)::int AS count FROM master_admins`
      );

      if (countResult.rows[0].count > 0) {
        return sendError(
          res,
          409,
          "Master Admin setup has already been completed."
        );
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await pool.query(
        `
        INSERT INTO master_admins
        (
          username,
          password_hash,
          display_name,
          is_active,
          created_at,
          updated_at
        )
        VALUES ($1, $2, $3, true, NOW(), NOW())
        RETURNING id, username, display_name, is_active, created_at
        `,
        [
          String(username).trim(),
          passwordHash,
          displayName || "Master Admin"
        ]
      );

      await writeAudit({
        adminId: result.rows[0].id,
        action: "master_admin_setup",
        targetType: "master_admin",
        targetId: result.rows[0].id,
        details: {
          username: result.rows[0].username
        }
      });

      return res.status(201).json({
        ok: true,
        message: "Master Admin setup completed.",
        admin: result.rows[0]
      });
    } catch (error) {
      console.error("Admin setup:", error);

      if (error.code === "23505") {
        return sendError(res, 409, "Username already exists.");
      }

      return sendError(
        res,
        500,
        "Master Admin setup failed."
      );
    }
  }
);

/* =========================================================
   MASTER ADMIN LOGIN
========================================================= */

app.post(
  "/api/admin/login",
  authLimiter,
  async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return sendError(
          res,
          400,
          "Username and password are required."
        );
      }

      const result = await pool.query(
        `
        SELECT *
        FROM master_admins
        WHERE username = $1
        LIMIT 1
        `,
        [String(username).trim()]
      );

      if (!result.rows.length) {
        return sendError(res, 401, "Invalid username or password.");
      }

      const admin = result.rows[0];

      if (!admin.is_active) {
        return sendError(res, 403, "This admin account is disabled.");
      }

      const valid = await bcrypt.compare(
        String(password),
        admin.password_hash
      );

      if (!valid) {
        return sendError(res, 401, "Invalid username or password.");
      }

      const token = signToken({
        id: admin.id,
        type: "master_admin",
        username: admin.username
      });

      setAuthCookie(res, token);

      await pool.query(
        `
        UPDATE master_admins
        SET last_login_at = NOW(), updated_at = NOW()
        WHERE id = $1
        `,
        [admin.id]
      );

      await writeAudit({
        adminId: admin.id,
        action: "master_admin_login",
        targetType: "master_admin",
        targetId: admin.id,
        details: {}
      });

      return res.json({
        ok: true,
        authenticated: true,
        type: "master_admin",
        admin: {
          id: admin.id,
          username: admin.username,
          display_name: admin.display_name
        }
      });
    } catch (error) {
      console.error("Admin login:", error);

      return sendError(
        res,
        500,
        "Login failed."
      );
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/auth/logout", requireAuth, async (req, res) => {
  try {
    if (req.auth && req.auth.type === "master_admin") {
      await writeAudit({
        adminId: req.auth.id,
        action: "logout",
        targetType: "master_admin",
        targetId: req.auth.id
      });
    }

    clearAuthCookie(res);

    return res.json({
      ok: true,
      message: "Logged out successfully."
    });
  } catch (error) {
    clearAuthCookie(res);

    return res.json({
      ok: true,
      message: "Logged out successfully."
    });
  }
});

/* =========================================================
   CHANGE MASTER ADMIN PASSWORD
========================================================= */

app.post(
  "/api/admin/change-password",
  requireAuth,
  requireMasterAdmin,
  authLimiter,
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
        return sendError(
          res,
          400,
          "Current password and new password are required."
        );
      }

      if (String(newPassword).length < 8) {
        return sendError(
          res,
          400,
          "New password must contain at least 8 characters."
        );
      }

      const result = await pool.query(
        `
        SELECT id, password_hash
        FROM master_admins
        WHERE id = $1
        LIMIT 1
        `,
        [req.auth.id]
      );

      if (!result.rows.length) {
        return sendError(res, 404, "Admin account not found.");
      }

      const valid = await bcrypt.compare(
        currentPassword,
        result.rows[0].password_hash
      );

      if (!valid) {
        return sendError(
          res,
          401,
          "Current password is incorrect."
        );
      }

      const passwordHash = await bcrypt.hash(newPassword, 12);

      await pool.query(
        `
        UPDATE master_admins
        SET password_hash = $1, updated_at = NOW()
        WHERE id = $2
        `,
        [passwordHash, req.auth.id]
      );

      await writeAudit({
        adminId: req.auth.id,
        action: "master_admin_password_changed",
        targetType: "master_admin",
        targetId: req.auth.id
      });

      return res.json({
        ok: true,
        message: "Password changed successfully."
      });
    } catch (error) {
      console.error("Password change:", error);

      return sendError(
        res,
        500,
        "Password change failed."
      );
    }
  }
);

/* =========================================================
   FORGOT PASSWORD / 2FA
   Real provider required — no fake success.
========================================================= */

app.post(
  "/api/admin/forgot-password",
  authLimiter,
  async (req, res) => {
    return res.status(501).json({
      ok: false,
      error:
        "Password recovery is not enabled yet. A verified email/SMS provider must be connected first."
    });
  }
);

app.post(
  "/api/admin/2fa/send",
  authLimiter,
  async (req, res) => {
    return res.status(501).json({
      ok: false,
      error:
        "2FA delivery is not enabled yet. A real OTP provider must be connected first."
    });
  }
);

app.post(
  "/api/admin/2fa/verify",
  authLimiter,
  async (req, res) => {
    return res.status(501).json({
      ok: false,
      error:
        "2FA verification is not enabled yet. A real OTP provider must be connected first."
    });
  }
);

/* =========================================================
   COUNTRIES
========================================================= */

app.get("/api/config/countries", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        country_code,
        country_name,
        dial_code,
        primary_language,
        enabled
      FROM countries
      WHERE enabled = true
      ORDER BY country_name ASC
      `
    );

    return res.json({
      ok: true,
      countries: result.rows
    });
  } catch (error) {
    console.error("Countries:", error);

    return sendError(
      res,
      500,
      "Unable to load countries."
    );
  }
});

app.get(
  "/api/admin/countries",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM countries
        ORDER BY country_name ASC
        `
      );

      return res.json({
        ok: true,
        countries: result.rows
      });
    } catch (error) {
      return sendError(
        res,
        500,
        "Unable to load countries."
      );
    }
  }
);

app.patch(
  "/api/admin/countries/:id",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const { enabled } = req.body;

      if (typeof enabled !== "boolean") {
        return sendError(
          res,
          400,
          "enabled must be true or false."
        );
      }

      const result = await pool.query(
        `
        UPDATE countries
        SET enabled = $1, updated_at = NOW()
        WHERE id = $2
        RETURNING *
        `,
        [enabled, req.params.id]
      );

      if (!result.rows.length) {
        return sendError(res, 404, "Country not found.");
      }

      await writeAudit({
        adminId: req.auth.id,
        action: "country_status_changed",
        targetType: "country",
        targetId: req.params.id,
        details: { enabled }
      });

      return res.json({
        ok: true,
        country: result.rows[0]
      });
    } catch (error) {
      return sendError(
        res,
        500,
        "Unable to update country."
      );
    }
  }
);

/* =========================================================
   USER REGISTRATION OTP
   Real SMS provider required.
========================================================= */

app.post(
  "/api/auth/register/send-otp",
  authLimiter,
  async (req, res) => {
    return res.status(501).json({
      ok: false,
      error:
        "Registration OTP is not enabled yet. Connect a real SMS provider before sending OTPs."
    });
  }
);

app.post(
  "/api/auth/register/verify-otp",
  authLimiter,
  async (req, res) => {
    return res.status(501).json({
      ok: false,
      error:
        "Registration OTP verification is not enabled yet. Connect a real SMS provider first."
    });
  }
);

/* =========================================================
   USER LOGIN OTP
========================================================= */

app.post(
  "/api/auth/login/send-otp",
  authLimiter,
  async (req, res) => {
    return res.status(501).json({
      ok: false,
      error:
        "Login OTP is not enabled yet. Connect a real SMS provider first."
    });
  }
);

app.post(
  "/api/auth/login/verify-otp",
  authLimiter,
  async (req, res) => {
    return res.status(501).json({
      ok: false,
      error:
        "Login OTP verification is not enabled yet. Connect a real SMS provider first."
    });
  }
);

/* =========================================================
   USER PROFILE
========================================================= */

app.get(
  "/api/profile",
  requireAuth,
  async (req, res) => {
    try {
      if (req.auth.type !== "user") {
        return sendError(res, 403, "User access required.");
      }

      const result = await pool.query(
        `
        SELECT
          id,
          phone,
          network_number,
          full_name,
          date_of_birth,
          gender,
          nid_number,
          kyc_status,
          created_at
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [req.auth.id]
      );

      if (!result.rows.length) {
        return sendError(res, 404, "User not found.");
      }

      return res.json({
        ok: true,
        profile: result.rows[0]
      });
    } catch (error) {
      return sendError(
        res,
        500,
        "Unable to load profile."
      );
    }
  }
);

/* =========================================================
   KYC FACE MATCH
   Real provider required.
========================================================= */

app.post(
  "/api/kyc/face-match",
  requireAuth,
  async (req, res) => {
    return res.status(501).json({
      ok: false,
      error:
        "Face matching is not enabled yet. A real KYC/face verification provider must be connected."
    });
  }
);

/* =========================================================
   KYC SUBMIT
========================================================= */

app.post(
  "/api/kyc/submit",
  requireAuth,
  async (req, res) => {
    try {
      if (req.auth.type !== "user") {
        return sendError(res, 403, "User access required.");
      }

      const {
        fullName,
        dateOfBirth,
        gender,
        nidNumber,
        idFrontUrl,
        idBackUrl,
        selfieUrl
      } = req.body;

      if (
        !fullName ||
        !dateOfBirth ||
        !gender ||
        !nidNumber
      ) {
        return sendError(
          res,
          400,
          "Required KYC information is missing."
        );
      }

      const userResult = await pool.query(
        `
        SELECT id
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [req.auth.id]
      );

      if (!userResult.rows.length) {
        return sendError(res, 404, "User not found.");
      }

      await pool.query(
        `
        UPDATE users
        SET
          full_name = $1,
          date_of_birth = $2,
          gender = $3,
          nid_number = $4,
          kyc_status = 'Pending',
          updated_at = NOW()
        WHERE id = $5
        `,
        [
          fullName,
          dateOfBirth,
          gender,
          nidNumber,
          req.auth.id
        ]
      );

      const result = await pool.query(
        `
        INSERT INTO kyc_records
        (
          user_id,
          id_front_url,
          id_back_url,
          selfie_url,
          status,
          created_at,
          updated_at
        )
        VALUES ($1, $2, $3, $4, 'Pending', NOW(), NOW())
        RETURNING *
        `,
        [
          req.auth.id,
          idFrontUrl || null,
          idBackUrl || null,
          selfieUrl || null
        ]
      );

      return res.status(201).json({
        ok: true,
        message: "KYC submitted for review.",
        kyc: result.rows[0]
      });
    } catch (error) {
      console.error("KYC submit:", error);

      return sendError(
        res,
        500,
        "KYC submission failed."
      );
    }
  }
);

/* =========================================================
   ADMIN DASHBOARD SUMMARY
========================================================= */

app.get(
  "/api/admin/dashboard/summary",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const users = await pool.query(
        `SELECT COUNT(*)::int AS count FROM users`
      );

      const pendingKyc = await pool.query(
        `
        SELECT COUNT(*)::int AS count
        FROM kyc_records
        WHERE status IN ('Pending', 'manual_review')
        `
      );

      const walletBalance = await pool.query(
        `
        SELECT COALESCE(SUM(balance), 0) AS total
        FROM wallets
        `
      );

      const transactions = await pool.query(
        `
        SELECT
          COUNT(*)::int AS count,
          COALESCE(SUM(amount), 0) AS amount
        FROM wallet_transactions
        WHERE created_at >= CURRENT_DATE
        `
      );

      return res.json({
        ok: true,
        metrics: {
          totalUsers: users.rows[0].count,
          onlineUsers: 0,
          todayRecharge: Number(transactions.rows[0].amount || 0),
          todaysCalls: 0,
          totalWalletBalance: Number(
            walletBalance.rows[0].total || 0
          ),
          callProviderCost: 0,
          revenue: 0,
          estimatedMargin: 0,
          pendingTasks: pendingKyc.rows[0].count
        }
      });
    } catch (error) {
      console.error("Dashboard summary:", error);

      return sendError(
        res,
        500,
        "Unable to load dashboard summary."
      );
    }
  }
);

/* =========================================================
   USERS
========================================================= */

app.get(
  "/api/admin/users",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const search = String(req.query.search || "").trim();
      const status = String(req.query.status || "").trim();

      const params = [];
      const conditions = [];

      if (search) {
        params.push(`%${search}%`);

        conditions.push(`
          (
            full_name ILIKE $${params.length}
            OR phone ILIKE $${params.length}
            OR network_number ILIKE $${params.length}
            OR registration_id ILIKE $${params.length}
          )
        `);
      }

      if (status) {
        params.push(status);

        conditions.push(
          `kyc_status = $${params.length}`
        );
      }

      const where = conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

      const result = await pool.query(
        `
        SELECT
          id,
          registration_id,
          phone,
          network_number,
          full_name,
          date_of_birth,
          gender,
          kyc_status,
          is_active,
          created_at
        FROM users
        ${where}
        ORDER BY created_at DESC
        LIMIT 200
        `,
        params
      );

      return res.json({
        ok: true,
        users: result.rows
      });
    } catch (error) {
      console.error("Users:", error);

      return sendError(
        res,
        500,
        "Unable to load users."
      );
    }
  }
);

/* =========================================================
   USER DETAIL
========================================================= */

app.get(
  "/api/admin/users/:id",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          u.*,
          k.id AS kyc_record_id,
          k.id_front_url,
          k.id_back_url,
          k.selfie_url,
          k.face_match_status,
          k.status AS kyc_record_status,
          k.created_at AS kyc_created_at
        FROM users u
        LEFT JOIN LATERAL (
          SELECT *
          FROM kyc_records
          WHERE user_id = u.id
          ORDER BY created_at DESC
          LIMIT 1
        ) k ON true
        WHERE u.id = $1
        LIMIT 1
        `,
        [req.params.id]
      );

      if (!result.rows.length) {
        return sendError(res, 404, "User not found.");
      }

      return res.json({
        ok: true,
        user: result.rows[0]
      });
    } catch (error) {
      return sendError(
        res,
        500,
        "Unable to load user."
      );
    }
  }
);

/* =========================================================
   KYC LIST
========================================================= */

app.get(
  "/api/admin/kyc",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const status = String(req.query.status || "").trim();
      const search = String(req.query.search || "").trim();

      const params = [];
      const conditions = [];

      if (status) {
        params.push(status);
        conditions.push(`k.status = $${params.length}`);
      }

      if (search) {
        params.push(`%${search}%`);

        conditions.push(`
          (
            u.full_name ILIKE $${params.length}
            OR u.phone ILIKE $${params.length}
            OR u.network_number ILIKE $${params.length}
            OR u.nid_number ILIKE $${params.length}
          )
        `);
      }

      const where = conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

      const result = await pool.query(
        `
        SELECT
          k.*,
          u.full_name,
          u.phone,
          u.network_number,
          u.date_of_birth,
          u.gender,
          u.nid_number,
          u.registration_id
        FROM kyc_records k
        JOIN users u ON u.id = k.user_id
        ${where}
        ORDER BY k.created_at DESC
        LIMIT 200
        `,
        params
      );

      return res.json({
        ok: true,
        records: result.rows
      });
    } catch (error) {
      console.error("KYC:", error);

      return sendError(
        res,
        500,
        "Unable to load KYC records."
      );
    }
  }
);

/* =========================================================
   KYC DECISION
========================================================= */

app.patch(
  "/api/admin/kyc/:id/decision",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const { status, notes } = req.body;

      const allowed = [
        "Pending",
        "Approved",
        "Rejected",
        "manual_review"
      ];

      if (!allowed.includes(status)) {
        return sendError(
          res,
          400,
          "Invalid KYC status."
        );
      }

      const kycResult = await pool.query(
        `
        UPDATE kyc_records
        SET
          status = $1,
          review_notes = $2,
          reviewed_by = $3,
          reviewed_at = NOW(),
          updated_at = NOW()
        WHERE id = $4
        RETURNING *
        `,
        [
          status,
          notes || null,
          req.auth.id,
          req.params.id
        ]
      );

      if (!kycResult.rows.length) {
        return sendError(
          res,
          404,
          "KYC record not found."
        );
      }

      const kyc = kycResult.rows[0];

      await pool.query(
        `
        UPDATE users
        SET
          kyc_status = $1,
          updated_at = NOW()
        WHERE id = $2
        `,
        [status, kyc.user_id]
      );

      await writeAudit({
        adminId: req.auth.id,
        action: "kyc_decision",
        targetType: "kyc",
        targetId: req.params.id,
        details: {
          status,
          notes: notes || null
        }
      });

      return res.json({
        ok: true,
        kyc
      });
    } catch (error) {
      console.error("KYC decision:", error);

      return sendError(
        res,
        500,
        "Unable to update KYC status."
      );
    }
  }
);

/* =========================================================
   FEATURES
========================================================= */

app.get(
  "/api/admin/features",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM features
        ORDER BY name ASC
        `
      );

      return res.json({
        ok: true,
        features: result.rows
      });
    } catch (error) {
      return sendError(
        res,
        500,
        "Unable to load features."
      );
    }
  }
);

app.patch(
  "/api/admin/features/:id",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const { enabled } = req.body;

      if (typeof enabled !== "boolean") {
        return sendError(
          res,
          400,
          "enabled must be true or false."
        );
      }

      const result = await pool.query(
        `
        UPDATE features
        SET
          enabled = $1,
          updated_at = NOW()
        WHERE id = $2
        RETURNING *
        `,
        [enabled, req.params.id]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          404,
          "Feature not found."
        );
      }

      await writeAudit({
        adminId: req.auth.id,
        action: "feature_status_changed",
        targetType: "feature",
        targetId: req.params.id,
        details: { enabled }
      });

      return res.json({
        ok: true,
        feature: result.rows[0]
      });
    } catch (error) {
      return sendError(
        res,
        500,
        "Unable to update feature."
      );
    }
  }
);

/* =========================================================
   WALLET TRANSACTIONS
========================================================= */

app.get(
  "/api/admin/wallet/transactions",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          wt.*,
          u.full_name,
          u.phone,
          u.network_number
        FROM wallet_transactions wt
        LEFT JOIN users u ON u.id = wt.user_id
        ORDER BY wt.created_at DESC
        LIMIT 200
        `
      );

      return res.json({
        ok: true,
        transactions: result.rows
      });
    } catch (error) {
      console.error("Wallet transactions:", error);

      return sendError(
        res,
        500,
        "Unable to load wallet transactions."
      );
    }
  }
);

/* =========================================================
   CALL RATES
========================================================= */

app.get(
  "/api/admin/rates",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM call_rates
        ORDER BY country_name ASC
        `
      );

      return res.json({
        ok: true,
        rates: result.rows
      });
    } catch (error) {
      return sendError(
        res,
        500,
        "Unable to load call rates."
      );
    }
  }
);

app.patch(
  "/api/admin/rates/:id",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const {
        provider_cost,
        customer_rate,
        pulse_seconds
      } = req.body;

      const result = await pool.query(
        `
        UPDATE call_rates
        SET
          provider_cost = COALESCE($1, provider_cost),
          customer_rate = COALESCE($2, customer_rate),
          pulse_seconds = COALESCE($3, pulse_seconds),
          updated_at = NOW()
        WHERE id = $4
        RETURNING *
        `,
        [
          provider_cost ?? null,
          customer_rate ?? null,
          pulse_seconds ?? null,
          req.params.id
        ]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          404,
          "Call rate not found."
        );
      }

      await writeAudit({
        adminId: req.auth.id,
        action: "call_rate_updated",
        targetType: "call_rate",
        targetId: req.params.id,
        details: req.body
      });

      return res.json({
        ok: true,
        rate: result.rows[0]
      });
    } catch (error) {
      console.error("Rate update:", error);

      return sendError(
        res,
        500,
        "Unable to update call rate."
      );
    }
  }
);

/* =========================================================
   AUDIT LOG
========================================================= */

app.get(
  "/api/admin/audit-logs",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          al.*,
          ma.username AS admin_username
        FROM audit_logs al
        LEFT JOIN master_admins ma
          ON ma.id = al.admin_id
        ORDER BY al.created_at DESC
        LIMIT 300
        `
      );

      return res.json({
        ok: true,
        logs: result.rows
      });
    } catch (error) {
      return sendError(
        res,
        500,
        "Unable to load audit logs."
      );
    }
  }
);

/* =========================================================
   SAFE PLACEHOLDER ENDPOINTS
   No fake data is returned.
========================================================= */

app.get(
  "/api/admin/gateways",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    return res.json({
      ok: true,
      gateways: []
    });
  }
);

app.get(
  "/api/admin/live-calls",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    return res.json({
      ok: true,
      calls: []
    });
  }
);

app.get(
  "/api/admin/sms",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    return res.json({
      ok: true,
      provider: null,
      todayCount: 0,
      todayCost: 0,
      messages: []
    });
  }
);

app.get(
  "/api/admin/support",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    return res.json({
      ok: true,
      tickets: []
    });
  }
);

app.get(
  "/api/admin/subadmins",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    return res.json({
      ok: true,
      subAdmins: []
    });
  }
);

app.get(
  "/api/admin/apps",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    return res.json({
      ok: true,
      apps: []
    });
  }
);

app.get(
  "/api/admin/analytics",
  requireAuth,
  requireMasterAdmin,
  async (req, res) => {
    return res.json({
      ok: true,
      data: []
    });
  }
);

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  return res.status(404).json({
    ok: false,
    error: "API route not found.",
    path: req.path,
    requestId: req.requestId
  });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);

  if (err.message === "CORS origin not allowed") {
    return sendError(res, 403, "CORS origin not allowed.");
  }

  return sendError(
    res,
    500,
    "Internal server error."
  );
});

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await pool.query("SELECT 1");

    console.log("Database connection successful.");

    app.listen(PORT, () => {
      console.log(
        `Talkify Global Network backend running on port ${PORT}`
      );

      console.log(`Environment: ${NODE_ENV}`);
    });
  } catch (error) {
    console.error(
      "Database connection failed:",
      error.message
    );

    process.exit(1);
  }
}

process.on("SIGTERM", async () => {
  console.log("SIGTERM received. Closing database...");

  await pool.end();

  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("SIGINT received. Closing database...");

  await pool.end();

  process.exit(0);
});

startServer();
