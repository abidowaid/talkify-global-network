
'use strict';

/*
 * Talkify Global Network
 * Production-ready backend foundation
 *
 * Important:
 * - No localStorage/sessionStorage/IndexedDB for account data.
 * - Database is PostgreSQL/Supabase.
 * - Frontend is never trusted for balance, KYC, payment or permissions.
 * - Real OTP/payment/telephony/SMS providers must be connected before production use.
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();

/* =========================================================
   ENVIRONMENT
========================================================= */

const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';

const PORT = Number(process.env.PORT || 10000);

const DATABASE_URL = process.env.DATABASE_URL || '';
const JWT_SECRET = process.env.JWT_SECRET || '';

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '';

const COOKIE_NAME = 'talkify_session';

const REQUEST_TIMEOUT_MS = 15000;
const DB_CONNECT_TIMEOUT_MS = 8000;

/* =========================================================
   SAFE DATABASE CONFIG DIAGNOSTICS
   Never log the password or complete DATABASE_URL.
========================================================= */

try {
  if (DATABASE_URL) {
    const dbUrl = new URL(DATABASE_URL);

    console.log('[DATABASE CONFIG]', {
      protocol: dbUrl.protocol,
      username: decodeURIComponent(dbUrl.username),
      hostname: dbUrl.hostname,
      port: dbUrl.port || '(default)',
      database: dbUrl.pathname
    });
  } else {
    console.log('[DATABASE CONFIG] DATABASE_URL is missing.');
  }
} catch (error) {
  console.error('[DATABASE CONFIG] Invalid DATABASE_URL format.');
}

/* =========================================================
   BASIC VALIDATION
========================================================= */

if (!DATABASE_URL) {
  console.error('WARNING: DATABASE_URL is not configured.');
  console.error('The server will start, but database-dependent APIs will return 503.');
}

if (IS_PRODUCTION && !JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is required in production.');
  process.exit(1);
}

const EFFECTIVE_JWT_SECRET =
  JWT_SECRET ||
  crypto.randomBytes(48).toString('hex');

/* =========================================================
   DATABASE
========================================================= */

let pool = null;
let dbReady = false;
let dbConnecting = false;

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: DB_CONNECT_TIMEOUT_MS,
    ssl: {
      rejectUnauthorized: false
    }
  });

  pool.on('error', (err) => {
    dbReady = false;
    console.error('[DATABASE POOL ERROR]', err.message);
  });
}

/* =========================================================
   REQUEST ID
========================================================= */

function requestId() {
  return crypto.randomUUID();
}

app.use((req, res, next) => {
  req.requestId = requestId();
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

/* =========================================================
   SECURITY
========================================================= */

app.disable('x-powered-by');

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: 'cross-origin'
    }
  })
);

app.use(
  express.json({
    limit: '15mb'
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '15mb'
  })
);

app.use(cookieParser());

/* =========================================================
   CORS
========================================================= */

const developmentOrigins = [
  'http://localhost',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173'
];

function isAllowedOrigin(origin) {
  if (!origin) return true;

  if (!IS_PRODUCTION) {
    return true;
  }

  if (!FRONTEND_ORIGIN) {
    return false;
  }

  return origin === FRONTEND_ORIGIN;
}

app.use(
  cors({
    origin: (origin, callback) => {
      if (isAllowedOrigin(origin)) {
        callback(null, true);
      } else {
        callback(new Error('CORS origin not allowed'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Request-ID'
    ]
  })
);

/* =========================================================
   TIMEOUT
========================================================= */

app.use((req, res, next) => {
  res.setTimeout(REQUEST_TIMEOUT_MS, () => {
    if (!res.headersSent) {
      res.status(408).json({
        ok: false,
        error: 'Request timeout',
        requestId: req.requestId
      });
    }
  });

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
    error: 'Too many authentication requests. Please try again later.'
  }
});

app.use(generalLimiter);

/* =========================================================
   HELPERS
========================================================= */

function jsonError(res, status, message, extra = {}) {
  return res.status(status).json({
    ok: false,
    error: message,
    ...extra
  });
}

function requireDatabase(req, res, next) {
  if (!pool || !dbReady) {
    return jsonError(
      res,
      503,
      'Database is not ready. Please try again shortly.'
    );
  }

  next();
}

function asyncHandler(fn) {
  return function wrappedHandler(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function normalizePhone(value) {
  return String(value || '')
    .trim()
    .replace(/[^\d+]/g, '');
}

function normalizeEmail(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function makeNetworkSuffix() {
  return String(
    crypto.randomInt(0, 100000000)
  ).padStart(8, '0');
}

function createNetworkNumber(countryDigits) {
  const digits = String(countryDigits || '').replace(/\D/g, '');

  if (!digits) {
    throw new Error('Invalid country digits');
  }

  const prefix = digits + '22222';

  if (prefix.length >= 16) {
    throw new Error('Country prefix is too long');
  }

  const suffixLength = 16 - prefix.length;

  let suffix = '';

  for (let i = 0; i < suffixLength; i++) {
    suffix += String(crypto.randomInt(0, 10));
  }

  return prefix + suffix;
}

/* =========================================================
   JWT
========================================================= */

function signToken(payload) {
  return jwt.sign(payload, EFFECTIVE_JWT_SECRET, {
    expiresIn: '7d',
    issuer: 'talkify-global-network'
  });
}

function verifyToken(token) {
  return jwt.verify(token, EFFECTIVE_JWT_SECRET, {
    issuer: 'talkify-global-network'
  });
}

function getTokenFromRequest(req) {
  if (req.cookies && req.cookies[COOKIE_NAME]) {
    return req.cookies[COOKIE_NAME];
  }

  const header = req.headers.authorization || '';

  if (header.startsWith('Bearer ')) {
    return header.slice(7).trim();
  }

  return null;
}

function setSessionCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: IS_PRODUCTION ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/'
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: IS_PRODUCTION ? 'none' : 'lax',
    path: '/'
  });
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function requireAuth(req, res, next) {
  const token = getTokenFromRequest(req);

  if (!token) {
    return jsonError(res, 401, 'Authentication required.');
  }

  try {
    const decoded = verifyToken(token);

    req.auth = decoded;

    next();
  } catch (error) {
    return jsonError(res, 401, 'Invalid or expired session.');
  }
}

function requireMasterAdmin(req, res, next) {
  if (!req.auth || req.auth.role !== 'master_admin') {
    return jsonError(res, 403, 'Master Admin access required.');
  }

  next();
}

/* =========================================================
   DATABASE CONNECTION
========================================================= */

async function checkDatabase() {
  if (!pool) {
    dbReady = false;
    return false;
  }

  if (dbConnecting) {
    return dbReady;
  }

  dbConnecting = true;

  try {
    const client = await pool.connect();

    try {
      await client.query('SELECT 1');
      dbReady = true;

      console.log('[DATABASE] Connected successfully.');

      return true;
    } finally {
      client.release();
    }
  } catch (error) {
    dbReady = false;

    console.error(
      '[DATABASE] Connection failed:',
      error.message
    );

    return false;
  } finally {
    dbConnecting = false;
  }
}

/*
 * Retry database connection in the background.
 * This NEVER blocks app.listen().
 */
function startDatabaseMonitor() {
  if (!pool) {
    console.log(
      '[DATABASE] No DATABASE_URL configured. Database APIs are disabled.'
    );

    return;
  }

  checkDatabase();

  setInterval(() => {
    if (!dbReady) {
      checkDatabase();
    }
  }, 10000).unref();
}

/* =========================================================
   HEALTH
========================================================= */

app.get('/api/health', asyncHandler(async (req, res) => {
  let database = 'not_configured';

  if (pool) {
    database = dbReady ? 'connected' : 'disconnected';
  }

  res.json({
    ok: true,
    service: 'Talkify Global Network Backend',
    time: new Date().toISOString(),
    environment: NODE_ENV,
    database,
    requestId: req.requestId
  });
}));

app.get('/api/health/db', requireDatabase, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT NOW() AS now');

  res.json({
    ok: true,
    database: 'connected',
    time: result.rows[0].now,
    requestId: req.requestId
  });
}));

/* =========================================================
   AUTH - SESSION
========================================================= */

app.get('/api/auth/session', asyncHandler(async (req, res) => {
  const token = getTokenFromRequest(req);

  if (!token) {
    return res.json({
      ok: true,
      authenticated: false
    });
  }

  try {
    const decoded = verifyToken(token);

    return res.json({
      ok: true,
      authenticated: true,
      user: {
        id: decoded.sub,
        role: decoded.role,
        networkNumber: decoded.networkNumber || null
      }
    });
  } catch (error) {
    return res.json({
      ok: true,
      authenticated: false
    });
  }
}));

/* =========================================================
   MASTER ADMIN - SETUP
========================================================= */

app.post(
  '/api/admin/setup',
  authLimiter,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const {
      password,
      email = null,
      name = 'Master Admin'
    } = req.body || {};

    if (!password || String(password).length < 10) {
      return jsonError(
        res,
        400,
        'Password must contain at least 10 characters.'
      );
    }

    const existing = await pool.query(
      'SELECT id FROM master_admins LIMIT 1'
    );

    if (existing.rows.length > 0) {
      return jsonError(
        res,
        409,
        'Master Admin is already configured.'
      );
    }

    const passwordHash = await bcrypt.hash(
      String(password),
      12
    );

    const result = await pool.query(
      `
      INSERT INTO master_admins
        (name, email, password_hash, created_at)
      VALUES
        ($1, $2, $3, NOW())
      RETURNING id, name, email, created_at
      `,
      [
        String(name).trim(),
        email ? normalizeEmail(email) : null,
        passwordHash
      ]
    );

    res.status(201).json({
      ok: true,
      message: 'Master Admin created successfully.',
      admin: result.rows[0]
    });
  })
);

/* =========================================================
   MASTER ADMIN - LOGIN
========================================================= */

app.post(
  '/api/admin/login',
  authLimiter,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const {
      password,
      email = null
    } = req.body || {};

    if (!password) {
      return jsonError(res, 400, 'Password is required.');
    }

    let result;

    if (email) {
      result = await pool.query(
        `
        SELECT *
        FROM master_admins
        WHERE LOWER(email) = LOWER($1)
        LIMIT 1
        `,
        [normalizeEmail(email)]
      );
    } else {
      result = await pool.query(
        `
        SELECT *
        FROM master_admins
        ORDER BY created_at ASC
        LIMIT 1
        `
      );
    }

    if (!result.rows.length) {
      return jsonError(
        res,
        401,
        'Master Admin account not found.'
      );
    }

    const admin = result.rows[0];

    const valid = await bcrypt.compare(
      String(password),
      admin.password_hash
    );

    if (!valid) {
      return jsonError(
        res,
        401,
        'Invalid password.'
      );
    }

    const token = signToken({
      sub: String(admin.id),
      role: 'master_admin',
      name: admin.name
    });

    setSessionCookie(res, token);

    await pool.query(
      `
      UPDATE master_admins
      SET last_login_at = NOW()
      WHERE id = $1
      `,
      [admin.id]
    );

    res.json({
      ok: true,
      message: 'Login successful.',
      admin: {
        id: admin.id,
        name: admin.name,
        email: admin.email
      }
    });
  })
);

/* =========================================================
   MASTER ADMIN - LOGOUT
========================================================= */

app.post('/api/admin/logout', (req, res) => {
  clearSessionCookie(res);

  res.json({
    ok: true,
    message: 'Logged out successfully.'
  });
});

app.post('/api/auth/logout', (req, res) => {
  clearSessionCookie(res);

  res.json({
    ok: true,
    message: 'Logged out successfully.'
  });
});

/* =========================================================
   MASTER ADMIN - SESSION
========================================================= */

app.get(
  '/api/admin/session',
  requireAuth,
  requireMasterAdmin,
  asyncHandler(async (req, res) => {
    res.json({
      ok: true,
      authenticated: true,
      admin: {
        id: req.auth.sub,
        role: req.auth.role,
        name: req.auth.name || 'Master Admin'
      }
    });
  })
);

/* =========================================================
   MASTER ADMIN - CHANGE PASSWORD
========================================================= */

app.post(
  '/api/admin/change-password',
  authLimiter,
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const {
      currentPassword,
      newPassword
    } = req.body || {};

    if (!currentPassword || !newPassword) {
      return jsonError(
        res,
        400,
        'Current and new password are required.'
      );
    }

    if (String(newPassword).length < 10) {
      return jsonError(
        res,
        400,
        'New password must contain at least 10 characters.'
      );
    }

    const result = await pool.query(
      `
      SELECT *
      FROM master_admins
      WHERE id = $1
      LIMIT 1
      `,
      [req.auth.sub]
    );

    if (!result.rows.length) {
      return jsonError(
        res,
        404,
        'Admin account not found.'
      );
    }

    const admin = result.rows[0];

    const valid = await bcrypt.compare(
      String(currentPassword),
      admin.password_hash
    );

    if (!valid) {
      return jsonError(
        res,
        401,
        'Current password is incorrect.'
      );
    }

    const newHash = await bcrypt.hash(
      String(newPassword),
      12
    );

    await pool.query(
      `
      UPDATE master_admins
      SET password_hash = $1
      WHERE id = $2
      `,
      [
        newHash,
        req.auth.sub
      ]
    );

    res.json({
      ok: true,
      message: 'Password changed successfully.'
    });
  })
);

/* =========================================================
   USER AUTH - SEND OTP
========================================================= */

app.post(
  '/api/auth/register/send-otp',
  authLimiter,
  asyncHandler(async (req, res) => {
    const phone = normalizePhone(req.body?.phone);

    if (!phone) {
      return jsonError(res, 400, 'Phone number is required.');
    }

    return res.status(501).json({
      ok: false,
      error: 'OTP provider is not configured yet.',
      code: 'OTP_PROVIDER_NOT_CONFIGURED'
    });
  })
);

app.post(
  '/api/auth/login/send-otp',
  authLimiter,
  asyncHandler(async (req, res) => {
    const phone = normalizePhone(req.body?.phone);

    if (!phone) {
      return jsonError(res, 400, 'Phone number is required.');
    }

    return res.status(501).json({
      ok: false,
      error: 'OTP provider is not configured yet.',
      code: 'OTP_PROVIDER_NOT_CONFIGURED'
    });
  })
);

app.post(
  '/api/auth/register/verify-otp',
  authLimiter,
  asyncHandler(async (req, res) => {
    return res.status(501).json({
      ok: false,
      error: 'OTP provider is not configured yet.',
      code: 'OTP_PROVIDER_NOT_CONFIGURED'
    });
  })
);

app.post(
  '/api/auth/login/verify-otp',
  authLimiter,
  asyncHandler(async (req, res) => {
    return res.status(501).json({
      ok: false,
      error: 'OTP provider is not configured yet.',
      code: 'OTP_PROVIDER_NOT_CONFIGURED'
    });
  })
);

/* =========================================================
   PROFILE
========================================================= */

app.get(
  '/api/profile',
  requireAuth,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        id,
        phone,
        network_number,
        full_name,
        date_of_birth,
        gender,
        country_code,
        status,
        created_at
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [req.auth.sub]
    );

    if (!result.rows.length) {
      return jsonError(
        res,
        404,
        'User profile not found.'
      );
    }

    res.json({
      ok: true,
      user: result.rows[0]
    });
  })
);

/* =========================================================
   CONFIG - COUNTRIES
========================================================= */

app.get(
  '/api/config/countries',
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM countries
      WHERE enabled = TRUE
      ORDER BY name ASC
      `
    );

    res.json({
      ok: true,
      countries: result.rows
    });
  })
);

/* =========================================================
   ADMIN - COUNTRIES
========================================================= */

app.get(
  '/api/admin/countries',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM countries
      ORDER BY name ASC
      `
    );

    res.json({
      ok: true,
      countries: result.rows
    });
  })
);

app.patch(
  '/api/admin/countries/:id',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const enabled = Boolean(req.body?.enabled);

    const result = await pool.query(
      `
      UPDATE countries
      SET enabled = $1
      WHERE id = $2
      RETURNING *
      `,
      [
        enabled,
        req.params.id
      ]
    );

    if (!result.rows.length) {
      return jsonError(
        res,
        404,
        'Country not found.'
      );
    }

    res.json({
      ok: true,
      country: result.rows[0]
    });
  })
);

/* =========================================================
   KYC
========================================================= */

app.post(
  '/api/kyc/face-match',
  requireAuth,
  requireDatabase,
  asyncHandler(async (req, res) => {
    return res.status(501).json({
      ok: false,
      error: 'Face verification provider is not configured yet.',
      code: 'FACE_PROVIDER_NOT_CONFIGURED'
    });
  })
);

app.post(
  '/api/kyc/submit',
  requireAuth,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const {
      fullName,
      dateOfBirth,
      gender,
      nid
    } = req.body || {};

    if (!fullName || !dateOfBirth || !gender || !nid) {
      return jsonError(
        res,
        400,
        'Required KYC information is missing.'
      );
    }

    return res.status(501).json({
      ok: false,
      error: 'KYC storage/verification provider is not configured yet.',
      code: 'KYC_PROVIDER_NOT_CONFIGURED'
    });
  })
);

/* =========================================================
   ADMIN - KYC LIST
========================================================= */

app.get(
  '/api/admin/kyc',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        k.*,
        u.phone,
        u.network_number
      FROM kyc_records k
      LEFT JOIN users u
        ON u.id = k.user_id
      ORDER BY k.created_at DESC
      LIMIT 500
      `
    );

    res.json({
      ok: true,
      kyc: result.rows
    });
  })
);

/* =========================================================
   ADMIN - KYC DETAIL
========================================================= */

app.get(
  '/api/admin/kyc/:id',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        k.*,
        u.phone,
        u.network_number
      FROM kyc_records k
      LEFT JOIN users u
        ON u.id = k.user_id
      WHERE k.id = $1
      LIMIT 1
      `,
      [req.params.id]
    );

    if (!result.rows.length) {
      return jsonError(
        res,
        404,
        'KYC record not found.'
      );
    }

    res.json({
      ok: true,
      kyc: result.rows[0]
    });
  })
);

/* =========================================================
   ADMIN - KYC DECISION
========================================================= */

app.patch(
  '/api/admin/kyc/:id/decision',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const status = String(
      req.body?.status || ''
    ).toLowerCase();

    const allowed = [
      'approved',
      'rejected',
      'manual_review',
      'pending'
    ];

    if (!allowed.includes(status)) {
      return jsonError(
        res,
        400,
        'Invalid KYC status.'
      );
    }

    const result = await pool.query(
      `
      UPDATE kyc_records
      SET
        status = $1,
        reviewed_by = $2,
        reviewed_at = NOW()
      WHERE id = $3
      RETURNING *
      `,
      [
        status,
        req.auth.sub,
        req.params.id
      ]
    );

    if (!result.rows.length) {
      return jsonError(
        res,
        404,
        'KYC record not found.'
      );
    }

    res.json({
      ok: true,
      kyc: result.rows[0]
    });
  })
);

/* =========================================================
   ADMIN - USERS
========================================================= */

app.get(
  '/api/admin/users',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const search = String(
      req.query.search || ''
    ).trim();

    const country = String(
      req.query.country || ''
    ).trim();

    const status = String(
      req.query.status || ''
    ).trim();

    const values = [];
    const conditions = [];

    if (search) {
      values.push(`%${search}%`);

      conditions.push(`
        (
          full_name ILIKE $${values.length}
          OR phone ILIKE $${values.length}
          OR network_number ILIKE $${values.length}
        )
      `);
    }

    if (country) {
      values.push(country);

      conditions.push(
        `country_code = $${values.length}`
      );
    }

    if (status) {
      values.push(status);

      conditions.push(
        `status = $${values.length}`
      );
    }

    const where = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const result = await pool.query(
      `
      SELECT
        id,
        phone,
        network_number,
        full_name,
        date_of_birth,
        gender,
        country_code,
        status,
        created_at
      FROM users
      ${where}
      ORDER BY created_at DESC
      LIMIT 500
      `,
      values
    );

    res.json({
      ok: true,
      users: result.rows
    });
  })
);

/* =========================================================
   ADMIN - USER DETAIL
========================================================= */

app.get(
  '/api/admin/users/:id',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT
        id,
        phone,
        network_number,
        full_name,
        date_of_birth,
        gender,
        country_code,
        status,
        created_at
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [req.params.id]
    );

    if (!result.rows.length) {
      return jsonError(
        res,
        404,
        'User not found.'
      );
    }

    res.json({
      ok: true,
      user: result.rows[0]
    });
  })
);

/* =========================================================
   FEATURES
========================================================= */

app.get(
  '/api/config/features',
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM features
      ORDER BY name ASC
      `
    );

    res.json({
      ok: true,
      features: result.rows
    });
  })
);

app.get(
  '/api/admin/features',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM features
      ORDER BY name ASC
      `
    );

    res.json({
      ok: true,
      features: result.rows
    });
  })
);

app.patch(
  '/api/admin/features/:id',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const enabled = Boolean(req.body?.enabled);

    const result = await pool.query(
      `
      UPDATE features
      SET enabled = $1
      WHERE id = $2
      RETURNING *
      `,
      [
        enabled,
        req.params.id
      ]
    );

    if (!result.rows.length) {
      return jsonError(
        res,
        404,
        'Feature not found.'
      );
    }

    res.json({
      ok: true,
      feature: result.rows[0]
    });
  })
);

/* =========================================================
   WALLET
========================================================= */

app.get(
  '/api/wallet',
  requireAuth,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM wallets
      WHERE user_id = $1
      LIMIT 1
      `,
      [req.auth.sub]
    );

    if (!result.rows.length) {
      return res.json({
        ok: true,
        wallet: null
      });
    }

    res.json({
      ok: true,
      wallet: result.rows[0]
    });
  })
);

/* =========================================================
   ADMIN - WALLET TRANSACTIONS
========================================================= */

app.get(
  '/api/admin/wallet/transactions',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM wallet_transactions
      ORDER BY created_at DESC
      LIMIT 500
      `
    );

    res.json({
      ok: true,
      transactions: result.rows
    });
  })
);

/* =========================================================
   CALL RATES
========================================================= */

app.get(
  '/api/config/rates',
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM call_rates
      ORDER BY country_code ASC
      `
    );

    res.json({
      ok: true,
      rates: result.rows
    });
  })
);

app.get(
  '/api/admin/rates',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM call_rates
      ORDER BY country_code ASC
      `
    );

    res.json({
      ok: true,
      rates: result.rows
    });
  })
);

app.patch(
  '/api/admin/rates/:id',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const {
      provider_cost,
      customer_rate,
      pulse_seconds
    } = req.body || {};

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
      return jsonError(
        res,
        404,
        'Rate not found.'
      );
    }

    res.json({
      ok: true,
      rate: result.rows[0]
    });
  })
);

/* =========================================================
   AUDIT LOG
========================================================= */

async function writeAuditLog({
  adminId = null,
  action,
  entityType = null,
  entityId = null,
  details = {}
}) {
  if (!pool || !dbReady) return;

  try {
    await pool.query(
      `
      INSERT INTO audit_logs
        (
          admin_id,
          action,
          entity_type,
          entity_id,
          details,
          created_at
        )
      VALUES
        ($1, $2, $3, $4, $5, NOW())
      `,
      [
        adminId,
        action,
        entityType,
        entityId,
        JSON.stringify(details)
      ]
    );
  } catch (error) {
    console.error(
      '[AUDIT LOG ERROR]',
      error.message
    );
  }
}

app.get(
  '/api/admin/audit-logs',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `
      SELECT *
      FROM audit_logs
      ORDER BY created_at DESC
      LIMIT 500
      `
    );

    res.json({
      ok: true,
      logs: result.rows
    });
  })
);

/* =========================================================
   DASHBOARD SUMMARY
========================================================= */

app.get(
  '/api/admin/dashboard/summary',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users) AS total_users,
        (SELECT COUNT(*) FROM users WHERE status = 'active') AS active_users,
        (SELECT COUNT(*) FROM kyc_records WHERE status = 'pending') AS pending_kyc,
        (SELECT COUNT(*) FROM kyc_records WHERE status = 'manual_review') AS manual_review_kyc,
        (SELECT COALESCE(SUM(balance), 0) FROM wallets) AS total_wallet_balance
    `);

    res.json({
      ok: true,
      summary: result.rows[0],
      system: {
        database: dbReady ? 'connected' : 'disconnected',
        backend: 'online'
      }
    });
  })
);

/* =========================================================
   CALLING
========================================================= */

app.get(
  '/api/admin/calls/live',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    res.json({
      ok: true,
      calls: [],
      provider: 'not_configured'
    });
  })
);

/* =========================================================
   SMS
========================================================= */

app.get(
  '/api/admin/sms/summary',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    res.json({
      ok: true,
      provider: 'not_configured',
      todayCount: 0,
      todayCost: 0
    });
  })
);

/* =========================================================
   SUPPORT
========================================================= */

app.get(
  '/api/admin/support',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    res.json({
      ok: true,
      tickets: []
    });
  })
);

/* =========================================================
   PAYMENT GATEWAYS
========================================================= */

app.get(
  '/api/admin/payment-gateways',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    res.json({
      ok: true,
      gateways: [],
      message: 'Payment provider is not configured yet.'
    });
  })
);

/* =========================================================
   SUB ADMINS
========================================================= */

app.get(
  '/api/admin/sub-admins',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    res.json({
      ok: true,
      subAdmins: []
    });
  })
);

/* =========================================================
   API / APPS
========================================================= */

app.get(
  '/api/admin/apps',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    res.json({
      ok: true,
      apps: []
    });
  })
);

/* =========================================================
   ANALYTICS
========================================================= */

app.get(
  '/api/admin/analytics',
  requireAuth,
  requireMasterAdmin,
  requireDatabase,
  asyncHandler(async (req, res) => {
    res.json({
      ok: true,
      analytics: {
        users: [],
        calls: [],
        revenue: [],
        sms: []
      }
    });
  })
);

/* =========================================================
   2FA
========================================================= */

app.post(
  '/api/admin/2fa/enable',
  requireAuth,
  requireMasterAdmin,
  asyncHandler(async (req, res) => {
    return res.status(501).json({
      ok: false,
      error: '2FA provider is not configured yet.',
      code: 'TWO_FACTOR_PROVIDER_NOT_CONFIGURED'
    });
  })
);

/* =========================================================
   FORGOT / RESET PASSWORD
========================================================= */

app.post(
  '/api/admin/forgot-password',
  authLimiter,
  requireDatabase,
  asyncHandler(async (req, res) => {
    return res.status(501).json({
      ok: false,
      error: 'Password reset email provider is not configured yet.',
      code: 'EMAIL_PROVIDER_NOT_CONFIGURED'
    });
  })
);

app.post(
  '/api/admin/reset-password',
  authLimiter,
  requireDatabase,
  asyncHandler(async (req, res) => {
    return res.status(501).json({
      ok: false,
      error: 'Password reset provider is not configured yet.',
      code: 'PASSWORD_RESET_NOT_CONFIGURED'
    });
  })
);

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: 'API route not found.',
    path: req.originalUrl,
    requestId: req.requestId
  });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error(
    `[ERROR ${req.requestId}]`,
    error
  );

  if (res.headersSent) {
    return next(error);
  }

  if (error.message === 'CORS origin not allowed') {
    return res.status(403).json({
      ok: false,
      error: 'CORS origin not allowed.',
      requestId: req.requestId
    });
  }

  return res.status(500).json({
    ok: false,
    error: IS_PRODUCTION
      ? 'Internal server error.'
      : error.message,
    requestId: req.requestId
  });
});

/* =========================================================
   START SERVER
========================================================= */

const server = app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `Talkify Global Network Backend listening on port ${PORT}`
    );

    console.log(
      `Environment: ${NODE_ENV}`
    );

    console.log(
      `Database configured: ${DATABASE_URL ? 'YES' : 'NO'}`
    );

    startDatabaseMonitor();
  }
);

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

async function shutdown(signal) {
  console.log(`${signal} received. Shutting down...`);

  server.close(async () => {
    try {
      if (pool) {
        await pool.end();
      }

      console.log('Shutdown complete.');

      process.exit(0);
    } catch (error) {
      console.error(
        'Shutdown database error:',
        error.message
      );

      process.exit(1);
    }
  });

  setTimeout(() => {
    process.exit(1);
  }, 10000).unref();
}

process.on(
  'SIGTERM',
  () => shutdown('SIGTERM')
);

process.on(
  'SIGINT',
  () => shutdown('SIGINT')
);

/* =========================================================
   UNHANDLED ERRORS
========================================================= */

process.on(
  'unhandledRejection',
  (error) => {
    console.error(
      '[UNHANDLED REJECTION]',
      error
    );
  }
);

process.on(
  'uncaughtException',
  (error) => {
    console.error(
      '[UNCAUGHT EXCEPTION]',
      error
    );
  }
);
