const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || "development";

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "CHANGE_THIS_SECRET_BEFORE_PRODUCTION_2026_TALKIFY";

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN || "";

const configuredOrigins = FRONTEND_ORIGIN
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

const isProduction = NODE_ENV === "production";

/* =========================================================
   BASIC APP CONFIG
========================================================= */

app.disable("x-powered-by");

if (isProduction) {
  app.set("trust proxy", 1);
}

/* =========================================================
   SECURITY HEADERS
========================================================= */

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin"
    },
    contentSecurityPolicy: false
  })
);

/* =========================================================
   BODY PARSER
========================================================= */

app.use(
  express.json({
    limit: "2mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "2mb"
  })
);

app.use(cookieParser());

/* =========================================================
   REQUEST ID
========================================================= */

app.use((req, res, next) => {
  const requestId = crypto.randomUUID();

  req.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);

  next();
});

/* =========================================================
   CORS
========================================================= */

app.use((req, res, next) => {
  const origin = req.headers.origin;

  /*
    DEVELOPMENT:
    SPCK Preview may send:
      - null
      - localhost
      - 127.0.0.1
      - local/LAN origins

    Therefore, during development we reflect the actual
    origin instead of using "*" because credentials/cookies
    cannot safely work with "*" + Access-Control-Allow-Credentials.
  */

  if (!isProduction) {
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    } else {
      res.setHeader("Access-Control-Allow-Origin", "*");
    }

    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-Requested-With, Accept"
    );
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    );
    res.setHeader(
      "Access-Control-Expose-Headers",
      "Content-Length, X-Request-Id"
    );

    res.setHeader("Vary", "Origin");

    if (req.method === "OPTIONS") {
      return res.status(204).end();
    }

    return next();
  }

  /*
    PRODUCTION:
    Only explicitly configured frontend origins are allowed.
  */

  if (origin && configuredOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-Requested-With, Accept"
    );
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    );
    res.setHeader(
      "Access-Control-Expose-Headers",
      "Content-Length, X-Request-Id"
    );
    res.setHeader("Vary", "Origin");
  }

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  next();
});

/* =========================================================
   RATE LIMITERS
========================================================= */

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    message: "Too many requests. Please try again later."
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    message: "Too many authentication attempts. Please try again later."
  }
});

app.use(generalLimiter);

/* =========================================================
   DEVELOPMENT DATABASE
   NOTE:
   This is temporary.
   Production will use PostgreSQL/Supabase.
========================================================= */

const db = {
  masterAdmin: null,

  resetTokens: new Map(),

  sessions: new Map(),

  auditLogs: [],

  twoFA: {
    enabled: false
  }
};

/* =========================================================
   HELPERS
========================================================= */

function nowISO() {
  return new Date().toISOString();
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 12
  );
}

function createToken(payload, expiresIn = "8h") {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn,
    issuer: "talkify-global-network",
    audience: "talkify-admin"
  });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET, {
    issuer: "talkify-global-network",
    audience: "talkify-admin"
  });
}

function setAuthCookie(res, token) {
  res.cookie("talkify_admin_session", token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    maxAge: 8 * 60 * 60 * 1000,
    path: "/"
  });
}

function clearAuthCookie(res) {
  res.clearCookie("talkify_admin_session", {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    path: "/"
  });
}

function getAuthToken(req) {
  if (req.cookies && req.cookies.talkify_admin_session) {
    return req.cookies.talkify_admin_session;
  }

  const header = req.headers.authorization || "";

  if (header.startsWith("Bearer ")) {
    return header.substring(7);
  }

  return null;
}

function requireMasterAdmin(req, res, next) {
  const token = getAuthToken(req);

  if (!token) {
    return res.status(401).json({
      authenticated: false,
      message: "Authentication required.",
      requestId: req.requestId
    });
  }

  try {
    const decoded = verifyToken(token);

    if (decoded.role !== "master_admin") {
      return res.status(403).json({
        authenticated: false,
        message: "Master Admin access required.",
        requestId: req.requestId
      });
    }

    req.admin = decoded;

    next();
  } catch (error) {
    clearAuthCookie(res);

    return res.status(401).json({
      authenticated: false,
      message: "Session expired or invalid.",
      requestId: req.requestId
    });
  }
}

function addAudit(action, details = {}) {
  db.auditLogs.unshift({
    id: crypto.randomUUID(),
    action,
    details,
    createdAt: nowISO()
  });

  if (db.auditLogs.length > 500) {
    db.auditLogs.length = 500;
  }
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "Talkify Global Network Backend",
    time: nowISO(),
    environment: NODE_ENV,
    requestId: req.requestId
  });
});

/* =========================================================
   MASTER ADMIN SETUP
========================================================= */

app.post(
  "/api/admin/auth/setup",
  authLimiter,
  async (req, res) => {
    try {
      if (db.masterAdmin) {
        return res.status(409).json({
          ok: false,
          message: "Master Admin account already exists.",
          requestId: req.requestId
        });
      }

      const email = normalizeEmail(req.body.email);
      const password = req.body.password;

      if (!isValidEmail(email)) {
        return res.status(400).json({
          ok: false,
          message: "Please provide a valid Admin email.",
          requestId: req.requestId
        });
      }

      if (!isStrongPassword(password)) {
        return res.status(400).json({
          ok: false,
          message: "Password must contain at least 12 characters.",
          requestId: req.requestId
        });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      db.masterAdmin = {
        id: crypto.randomUUID(),
        email,
        passwordHash,
        role: "master_admin",
        createdAt: nowISO(),
        updatedAt: nowISO(),
        lastLoginAt: null
      };

      addAudit("master_admin_created", {
        email
      });

      return res.status(201).json({
        ok: true,
        authenticated: false,
        role: "master_admin",
        message: "Master Admin account created successfully.",
        requestId: req.requestId
      });
    } catch (error) {
      console.error("SETUP ERROR:", error);

      return res.status(500).json({
        ok: false,
        message: "Master Admin setup failed.",
        requestId: req.requestId
      });
    }
  }
);

/* =========================================================
   MASTER ADMIN LOGIN
========================================================= */

app.post(
  "/api/admin/auth/login",
  authLimiter,
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);
      const password = req.body.password;

      if (!db.masterAdmin) {
        return res.status(404).json({
          ok: false,
          message: "Master Admin account has not been created yet.",
          requestId: req.requestId
        });
      }

      if (!email || !password) {
        return res.status(400).json({
          ok: false,
          message: "Email and password are required.",
          requestId: req.requestId
        });
      }

      const emailMatches =
        email === db.masterAdmin.email;

      const passwordMatches =
        await bcrypt.compare(
          password,
          db.masterAdmin.passwordHash
        );

      if (!emailMatches || !passwordMatches) {
        addAudit("master_admin_login_failed", {
          email
        });

        return res.status(401).json({
          ok: false,
          authenticated: false,
          message: "Invalid email or password.",
          requestId: req.requestId
        });
      }

      /*
        2FA is intentionally not faked.
        If later enabled through a real provider,
        this branch can return a real challenge.
      */

      if (db.twoFA.enabled) {
        const challengeId = crypto.randomUUID();

        db.sessions.set(challengeId, {
          type: "2fa_challenge",
          email,
          createdAt: nowISO(),
          expiresAt: Date.now() + 5 * 60 * 1000
        });

        return res.json({
          ok: true,
          authenticated: false,
          requires2FA: true,
          challengeId,
          message: "2FA verification required.",
          requestId: req.requestId
        });
      }

      const token = createToken({
        sub: db.masterAdmin.id,
        email: db.masterAdmin.email,
        role: "master_admin"
      });

      db.masterAdmin.lastLoginAt = nowISO();

      setAuthCookie(res, token);

      addAudit("master_admin_login_success", {
        email
      });

      return res.json({
        ok: true,
        authenticated: true,
        role: "master_admin",
        email: db.masterAdmin.email,
        message: "Login successful.",
        requestId: req.requestId
      });
    } catch (error) {
      console.error("LOGIN ERROR:", error);

      return res.status(500).json({
        ok: false,
        authenticated: false,
        message: "Authentication failed.",
        requestId: req.requestId
      });
    }
  }
);

/* =========================================================
   SESSION
========================================================= */

app.get(
  "/api/admin/auth/session",
  async (req, res) => {
    const token = getAuthToken(req);

    if (!token) {
      return res.status(401).json({
        authenticated: false,
        message: "Authentication required.",
        requestId: req.requestId
      });
    }

    try {
      const decoded = verifyToken(token);

      if (decoded.role !== "master_admin") {
        return res.status(403).json({
          authenticated: false,
          message: "Master Admin access required.",
          requestId: req.requestId
        });
      }

      return res.json({
        ok: true,
        authenticated: true,
        role: "master_admin",
        email: decoded.email,
        requestId: req.requestId
      });
    } catch (error) {
      clearAuthCookie(res);

      return res.status(401).json({
        authenticated: false,
        message: "Session expired or invalid.",
        requestId: req.requestId
      });
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/admin/auth/logout",
  requireMasterAdmin,
  (req, res) => {
    clearAuthCookie(res);

    addAudit("master_admin_logout", {
      email: req.admin.email
    });

    return res.json({
      ok: true,
      authenticated: false,
      message: "Logged out successfully.",
      requestId: req.requestId
    });
  }
);

/* =========================================================
   CHANGE PASSWORD
========================================================= */

app.post(
  "/api/admin/auth/change-password",
  requireMasterAdmin,
  authLimiter,
  async (req, res) => {
    try {
      const currentPassword = req.body.currentPassword;
      const newPassword = req.body.newPassword;

      if (!isStrongPassword(newPassword)) {
        return res.status(400).json({
          ok: false,
          message: "New password must contain at least 12 characters.",
          requestId: req.requestId
        });
      }

      const currentMatches =
        await bcrypt.compare(
          currentPassword,
          db.masterAdmin.passwordHash
        );

      if (!currentMatches) {
        return res.status(401).json({
          ok: false,
          message: "Current password is incorrect.",
          requestId: req.requestId
        });
      }

      db.masterAdmin.passwordHash =
        await bcrypt.hash(newPassword, 12);

      db.masterAdmin.updatedAt = nowISO();

      addAudit("master_admin_password_changed", {
        email: req.admin.email
      });

      return res.json({
        ok: true,
        message: "Password changed successfully.",
        requestId: req.requestId
      });
    } catch (error) {
      console.error("CHANGE PASSWORD ERROR:", error);

      return res.status(500).json({
        ok: false,
        message: "Password change failed.",
        requestId: req.requestId
      });
    }
  }
);

/* =========================================================
   FORGOT PASSWORD
========================================================= */

app.post(
  "/api/admin/auth/forgot-password",
  authLimiter,
  (req, res) => {
    const email = normalizeEmail(req.body.email);

    /*
      Always return a generic response so that the API does
      not reveal whether an account exists.
    */

    if (
      db.masterAdmin &&
      email === db.masterAdmin.email
    ) {
      const token = crypto.randomBytes(32).toString("hex");

      db.resetTokens.set(token, {
        email,
        createdAt: Date.now(),
        expiresAt: Date.now() + 15 * 60 * 1000
      });

      /*
        IMPORTANT:
        No fake email is claimed here.
        A real email provider must be connected later.
      */

      console.log(
        "PASSWORD RESET TOKEN CREATED:",
        token
      );
    }

    return res.json({
      ok: true,
      message:
        "If this email belongs to an Admin account, secure recovery instructions have been initiated.",
      requestId: req.requestId
    });
  }
);

/* =========================================================
   RESET PASSWORD
========================================================= */

app.post(
  "/api/admin/auth/reset-password",
  authLimiter,
  async (req, res) => {
    try {
      const token = String(req.body.token || "");
      const password = req.body.password;

      if (!token) {
        return res.status(400).json({
          ok: false,
          message: "Reset token is required.",
          requestId: req.requestId
        });
      }

      if (!isStrongPassword(password)) {
        return res.status(400).json({
          ok: false,
          message: "Password must contain at least 12 characters.",
          requestId: req.requestId
        });
      }

      const record = db.resetTokens.get(token);

      if (!record) {
        return res.status(400).json({
          ok: false,
          message: "Invalid or expired reset token.",
          requestId: req.requestId
        });
      }

      if (Date.now() > record.expiresAt) {
        db.resetTokens.delete(token);

        return res.status(400).json({
          ok: false,
          message: "Reset token has expired.",
          requestId: req.requestId
        });
      }

      if (
        !db.masterAdmin ||
        db.masterAdmin.email !== record.email
      ) {
        return res.status(400).json({
          ok: false,
          message: "Invalid password reset request.",
          requestId: req.requestId
        });
      }

      db.masterAdmin.passwordHash =
        await bcrypt.hash(password, 12);

      db.masterAdmin.updatedAt = nowISO();

      db.resetTokens.delete(token);

      addAudit("master_admin_password_reset", {
        email: record.email
      });

      return res.json({
        ok: true,
        message: "Password changed successfully.",
        requestId: req.requestId
      });
    } catch (error) {
      console.error("RESET PASSWORD ERROR:", error);

      return res.status(500).json({
        ok: false,
        message: "Password reset failed.",
        requestId: req.requestId
      });
    }
  }
);

/* =========================================================
   2FA ENABLE
========================================================= */

app.post(
  "/api/admin/auth/2fa/enable",
  requireMasterAdmin,
  (req, res) => {
    /*
      We do NOT pretend that 2FA is active without a real
      provider/secret setup.
    */

    return res.status(501).json({
      ok: false,
      message:
        "2FA provider is not connected yet. No fake 2FA has been enabled.",
      requestId: req.requestId
    });
  }
);

/* =========================================================
   2FA DISABLE
========================================================= */

app.post(
  "/api/admin/auth/2fa/disable",
  requireMasterAdmin,
  (req, res) => {
    db.twoFA.enabled = false;

    addAudit("master_admin_2fa_disabled", {
      email: req.admin.email
    });

    return res.json({
      ok: true,
      enabled: false,
      message: "2FA disabled.",
      requestId: req.requestId
    });
  }
);

/* =========================================================
   2FA VERIFY
========================================================= */

app.post(
  "/api/admin/auth/2fa/verify",
  authLimiter,
  (req, res) => {
    /*
      No fake OTP verification.
      A real 2FA provider will be connected later.
    */

    return res.status(501).json({
      ok: false,
      authenticated: false,
      message:
        "2FA provider is not connected yet.",
      requestId: req.requestId
    });
  }
);

/* =========================================================
   REVOKE SESSIONS
========================================================= */

app.post(
  "/api/admin/auth/revoke-sessions",
  requireMasterAdmin,
  (req, res) => {
    db.sessions.clear();

    addAudit("master_admin_sessions_revoked", {
      email: req.admin.email
    });

    return res.json({
      ok: true,
      message: "Pending authentication challenges revoked.",
      requestId: req.requestId
    });
  }
);

/* =========================================================
   AUDIT LOG
========================================================= */

app.get(
  "/api/admin/audit",
  requireMasterAdmin,
  (req, res) => {
    return res.json({
      ok: true,
      logs: db.auditLogs,
      requestId: req.requestId
    });
  }
);

/* =========================================================
   ADMIN DASHBOARD SUMMARY
========================================================= */

app.get(
  "/api/admin/dashboard/summary",
  requireMasterAdmin,
  (req, res) => {
    return res.json({
      ok: true,

      users: {
        total: 0,
        active: 0,
        pendingKyc: 0
      },

      calls: {
        today: 0,
        minutesToday: 0
      },

      messages: {
        today: 0
      },

      financial: {
        totalBalance: 0,
        todayRevenue: 0
      },

      kyc: {
        pending: 0,
        approved: 0,
        rejected: 0
      },

      services: {
        backend: "online",
        database: "not_connected",
        sms: "not_connected",
        voice: "not_connected",
        payment: "not_connected"
      },

      message:
        "Dashboard values will become live after the production database and service providers are connected.",

      requestId: req.requestId
    });
  }
);

/* =========================================================
   COUNTRIES
========================================================= */

app.get(
  "/api/admin/countries",
  requireMasterAdmin,
  (req, res) => {
    return res.json({
      ok: true,
      countries: [],
      message:
        "Country configuration will be loaded from the production database.",
      requestId: req.requestId
    });
  }
);

/* =========================================================
   FEATURES
========================================================= */

app.get(
  "/api/admin/features",
  requireMasterAdmin,
  (req, res) => {
    return res.json({
      ok: true,
      features: [],
      message:
        "Feature configuration will be loaded from the production database.",
      requestId: req.requestId
    });
  }
);

/* =========================================================
   ADMIN PROFILE
========================================================= */

app.get(
  "/api/admin/profile",
  requireMasterAdmin,
  (req, res) => {
    return res.json({
      ok: true,
      profile: {
        id: db.masterAdmin.id,
        email: db.masterAdmin.email,
        role: db.masterAdmin.role,
        createdAt: db.masterAdmin.createdAt,
        updatedAt: db.masterAdmin.updatedAt,
        lastLoginAt: db.masterAdmin.lastLoginAt
      },
      requestId: req.requestId
    });
  }
);

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  return res.status(404).json({
    ok: false,
    message: "API endpoint not found.",
    path: req.originalUrl,
    requestId: req.requestId
  });
});

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
  console.error("GLOBAL ERROR:", err);

  if (res.headersSent) {
    return next(err);
  }

  return res.status(500).json({
    ok: false,
    message: "Internal server error.",
    requestId: req.requestId
  });
});

/* =========================================================
   START SERVER
========================================================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Talkify Global Network Backend running on port ${PORT}`
  );

  console.log(
    `Environment: ${NODE_ENV}`
  );

  console.log(
    `Configured frontend origins: ${
      configuredOrigins.length
        ? configuredOrigins.join(", ")
        : "(development dynamic origin mode)"
    }`
  );
});
