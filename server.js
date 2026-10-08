/*
========================================================
 TALKIFY GLOBAL NETWORK
 MASTER BACKEND - server.js
========================================================

SECURE DEVELOPMENT / PRODUCTION-READY BASE

Included:
1. First-time Master Admin setup
2. Master Admin login
3. Secure bcrypt password hashing
4. HTTP-only authentication cookie
5. Admin session check
6. Logout
7. Forgot-password request
8. Password reset token
9. Change password
10. Optional 2FA-ready API
11. Audit logging
12. Helmet security headers
13. Rate limiting
14. Production-safe CORS
15. Secure cookie configuration
16. Render/Reverse-proxy support
17. Health check
18. Dashboard base API
19. Countries base API
20. Features base API

IMPORTANT:
- No password is stored in frontend.
- No authentication data uses localStorage.
- Production secrets must be environment variables.
- This version still uses an in-memory database.
- PostgreSQL/Supabase will be connected in the next backend stage.
========================================================
*/


const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");


const app = express();


/*
========================================================
 SERVER CONFIGURATION
========================================================
*/

const PORT =
    Number(process.env.PORT || 3000);


const NODE_ENV =
    String(
        process.env.NODE_ENV || "development"
    ).trim().toLowerCase();


/*
========================================================
 PRODUCTION JWT SECRET
========================================================

IMPORTANT:
Set JWT_SECRET inside Render Environment Variables.

Do NOT put your real production secret in this file.
========================================================
*/

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "CHANGE_THIS_TALKIFY_SECRET_BEFORE_PRODUCTION";


/*
========================================================
 FRONTEND ORIGIN CONFIGURATION
========================================================

Render production should use the exact frontend origin.

Example:

https://your-frontend-domain.com

Multiple origins can be separated by commas.

Development:
- localhost
- 127.0.0.1
- null origin from local file/SPCK preview

Production:
- only configured origins are allowed
========================================================
*/

const configuredOrigins =
    String(
        process.env.FRONTEND_ORIGIN || ""
    )
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);


/*
========================================================
 BASIC APP CONFIG
========================================================
*/


app.disable("x-powered-by");


/*
Render runs behind a reverse proxy.

This is important for:
- secure cookies
- HTTPS detection
- rate limiting
*/

if (NODE_ENV === "production") {

    app.set(
        "trust proxy",
        1
    );

}


/*
========================================================
 SECURITY HEADERS
========================================================
*/

app.use(
    helmet({
        crossOriginResourcePolicy: {
            policy: "cross-origin"
        },

        contentSecurityPolicy: false
    })
);


/*
========================================================
 REQUEST BODY
========================================================
*/

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


/*
========================================================
 COOKIE PARSER
========================================================
*/

app.use(cookieParser());


/*
========================================================
 PRODUCTION-SAFE CORS
========================================================

Important:

Credential cookies cannot be used with:

Access-Control-Allow-Origin: *

Therefore we return the exact allowed origin.

Development:
- null origin is allowed for local/SPCK testing.
- localhost is allowed.

Production:
- only FRONTEND_ORIGIN values are allowed.
========================================================
*/

app.use(
    (req, res, next) => {

        const requestOrigin =
            req.headers.origin;


        /*
        ------------------------------------------------
        DEVELOPMENT
        ------------------------------------------------
        */

        if (NODE_ENV !== "production") {

            const developmentOrigins = [

                "http://localhost",
                "http://localhost:3000",
                "http://localhost:5173",
                "http://127.0.0.1",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:5173"

            ];


            /*
            SPCK/local HTML can sometimes send:
            Origin: null
            */

            if (
                requestOrigin === "null" ||
                !requestOrigin ||
                developmentOrigins.includes(
                    requestOrigin
                )
            ) {

                if (requestOrigin) {

                    res.setHeader(
                        "Access-Control-Allow-Origin",
                        requestOrigin
                    );

                }

                res.setHeader(
                    "Access-Control-Allow-Credentials",
                    "true"
                );

            }
            else if (
                configuredOrigins.includes(
                    requestOrigin
                )
            ) {

                res.setHeader(
                    "Access-Control-Allow-Origin",
                    requestOrigin
                );

                res.setHeader(
                    "Access-Control-Allow-Credentials",
                    "true"
                );

            }

        }


        /*
        ------------------------------------------------
        PRODUCTION
        ------------------------------------------------
        */

        else {

            if (
                requestOrigin &&
                configuredOrigins.includes(
                    requestOrigin
                )
            ) {

                res.setHeader(
                    "Access-Control-Allow-Origin",
                    requestOrigin
                );

                res.setHeader(
                    "Access-Control-Allow-Credentials",
                    "true"
                );

            }

        }


        /*
        ------------------------------------------------
        COMMON CORS HEADERS
        ------------------------------------------------
        */

        res.setHeader(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Requested-With"
        );


        res.setHeader(
            "Access-Control-Allow-Methods",
            "GET,POST,PUT,PATCH,DELETE,OPTIONS"
        );


        res.setHeader(
            "Access-Control-Expose-Headers",
            "Content-Length, X-Request-Id"
        );


        /*
        ------------------------------------------------
        PREFLIGHT
        ------------------------------------------------
        */

        if (req.method === "OPTIONS") {

            return res.sendStatus(204);

        }


        next();

    }
);


/*
========================================================
 REQUEST ID
========================================================
*/

app.use(
    (req, res, next) => {

        const requestId =
            crypto.randomUUID();


        res.setHeader(
            "X-Request-Id",
            requestId
        );


        req.requestId =
            requestId;


        next();

    }
);


/*
========================================================
 RATE LIMITERS
========================================================
*/

const authLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            20,

        standardHeaders:
            true,

        legacyHeaders:
            false,

        message: {

            ok: false,

            message:
                "Too many authentication attempts. Please try again later."

        }

    });


const generalLimiter =
    rateLimit({

        windowMs:
            60 * 1000,

        max:
            120,

        standardHeaders:
            true,

        legacyHeaders:
            false

    });


app.use(
    generalLimiter
);


/*
========================================================
 TEMPORARY SERVER DATABASE
========================================================

IMPORTANT:

This is still an in-memory development database.

It is NOT the final production database.

If Render restarts the server, the data disappears.

Next backend stage:
PostgreSQL / Supabase.

Permanent data will include:

- users
- wallets
- KYC
- payments
- calls
- SMS
- admins
- sub-admins
- audit logs
- support tickets
- countries
- feature controls
========================================================
*/

const db = {

    masterAdmin:
        null,

    resetTokens:
        new Map(),

    sessions:
        new Map(),

    auditLogs:
        [],

    twoFA: {

        enabled:
            false

    }

};


/*
========================================================
 HELPER FUNCTIONS
========================================================
*/


function nowISO() {

    return new Date().toISOString();

}


/*
--------------------------------------------------------
 RANDOM TOKEN
--------------------------------------------------------
*/

function randomToken(
    bytes = 32
) {

    return crypto
        .randomBytes(bytes)
        .toString("hex");

}


/*
--------------------------------------------------------
 SANITIZE EMAIL
--------------------------------------------------------
*/

function sanitizeEmail(
    email
) {

    return String(
        email || ""
    )
    .trim()
    .toLowerCase();

}


/*
--------------------------------------------------------
 VALID EMAIL
--------------------------------------------------------
*/

function validEmail(
    email
) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);

}


/*
--------------------------------------------------------
 STRONG PASSWORD
--------------------------------------------------------
*/

function passwordIsStrong(
    password
) {

    if (
        typeof password !== "string" ||
        password.length < 12
    ) {

        return false;

    }


    const upper =
        /[A-Z]/.test(password);


    const lower =
        /[a-z]/.test(password);


    const number =
        /[0-9]/.test(password);


    const symbol =
        /[^A-Za-z0-9]/.test(password);


    return (
        upper &&
        lower &&
        number &&
        symbol
    );

}


/*
--------------------------------------------------------
 AUDIT LOG
--------------------------------------------------------
*/

function audit(
    action,
    details = {}
) {

    db.auditLogs.unshift({

        id:
            crypto.randomUUID(),

        action,

        details,

        createdAt:
            nowISO()

    });


    if (
        db.auditLogs.length > 5000
    ) {

        db.auditLogs.length =
            5000;

    }

}


/*
--------------------------------------------------------
 JWT AUTH TOKEN
--------------------------------------------------------
*/

function createAuthToken(
    admin
) {

    return jwt.sign(

        {

            sub:
                admin.id,

            role:
                "master_admin",

            email:
                admin.email

        },

        JWT_SECRET,

        {

            expiresIn:
                "8h",

            issuer:
                "talkify-global-network",

            audience:
                "talkify-admin"

        }

    );

}


/*
========================================================
 SECURE AUTH COOKIE
========================================================

Production:
- HTTPS
- Secure
- SameSite=None
- HTTP-only

Development:
- Secure=false
- SameSite=Lax

This allows local/SPCK development while keeping
cross-site production authentication compatible
with HTTPS.
========================================================
*/

function setAuthCookie(
    res,
    token
) {

    const production =
        NODE_ENV === "production";


    res.cookie(
        "talkify_admin_session",
        token,
        {

            httpOnly:
                true,

            secure:
                production,

            sameSite:
                production
                    ? "none"
                    : "lax",

            maxAge:
                8 * 60 * 60 * 1000,

            path:
                "/"

        }
    );

}


/*
--------------------------------------------------------
 CLEAR AUTH COOKIE
--------------------------------------------------------
*/

function clearAuthCookie(
    res
) {

    const production =
        NODE_ENV === "production";


    res.clearCookie(
        "talkify_admin_session",
        {

            httpOnly:
                true,

            secure:
                production,

            sameSite:
                production
                    ? "none"
                    : "lax",

            path:
                "/"

        }
    );

}


/*
========================================================
 TOKEN FROM REQUEST
========================================================
*/

function getTokenFromRequest(
    req
) {

    if (
        req.cookies &&
        req.cookies.talkify_admin_session
    ) {

        return req.cookies
            .talkify_admin_session;

    }


    const auth =
        req.headers.authorization || "";


    if (
        auth.startsWith("Bearer ")
    ) {

        return auth.slice(7);

    }


    return null;

}


/*
========================================================
 MASTER ADMIN AUTHENTICATION
========================================================
*/

function authenticateAdmin(
    req,
    res,
    next
) {

    try {

        const token =
            getTokenFromRequest(
                req
            );


        if (!token) {

            return res.status(401).json({

                authenticated:
                    false,

                message:
                    "Authentication required.",

                requestId:
                    req.requestId

            });

        }


        const decoded =
            jwt.verify(
                token,
                JWT_SECRET,
                {

                    issuer:
                        "talkify-global-network",

                    audience:
                        "talkify-admin"

                }
            );


        if (
            decoded.role !==
            "master_admin"
        ) {

            return res.status(403).json({

                authenticated:
                    false,

                message:
                    "Master Admin access required.",

                requestId:
                    req.requestId

            });

        }


        if (
            !db.masterAdmin ||
            db.masterAdmin.id !==
            decoded.sub
        ) {

            return res.status(401).json({

                authenticated:
                    false,

                message:
                    "Admin account not found.",

                requestId:
                    req.requestId

            });

        }


        if (
            db.masterAdmin.status !==
            "active"
        ) {

            return res.status(403).json({

                authenticated:
                    false,

                message:
                    "Master Admin account is not active.",

                requestId:
                    req.requestId

            });

        }


        req.admin =
            db.masterAdmin;


        next();

    }
    catch (error) {

        return res.status(401).json({

            authenticated:
                false,

            message:
                "Invalid or expired session.",

            requestId:
                req.requestId

        });

    }

}


/*
========================================================
 HEALTH CHECK
========================================================
*/

app.get(
    "/api/health",
    (req, res) => {

        res.json({

            ok:
                true,

            service:
                "Talkify Global Network Backend",

            time:
                nowISO(),

            environment:
                NODE_ENV,

            requestId:
                req.requestId

        });

    }
);


/*
========================================================
 MASTER ADMIN SETUP
========================================================

POST
/api/admin/auth/setup
========================================================
*/

app.post(
    "/api/admin/auth/setup",
    authLimiter,
    async (req, res) => {

        try {

            if (
                db.masterAdmin
            ) {

                return res.status(409).json({

                    ok:
                        false,

                    message:
                        "Master Admin is already configured. Use Login."

                });

            }


            const email =
                sanitizeEmail(
                    req.body.email
                );


            const password =
                String(
                    req.body.password || ""
                );


            const confirmPassword =
                String(
                    req.body.confirmPassword || ""
                );


            if (
                !validEmail(email)
            ) {

                return res.status(400).json({

                    ok:
                        false,

                    message:
                        "Please enter a valid email address."

                });

            }


            if (
                password !==
                confirmPassword
            ) {

                return res.status(400).json({

                    ok:
                        false,

                    message:
                        "Passwords do not match."

                });

            }


            if (
                !passwordIsStrong(
                    password
                )
            ) {

                return res.status(400).json({

                    ok:
                        false,

                    message:
                        "Password must contain at least 12 characters, uppercase letters, lowercase letters, numbers and symbols."

                });

            }


            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );


            const admin = {

                id:
                    crypto.randomUUID(),

                email,

                passwordHash,

                role:
                    "master_admin",

                status:
                    "active",

                twoFAEnabled:
                    false,

                createdAt:
                    nowISO(),

                lastLoginAt:
                    null

            };


            db.masterAdmin =
                admin;


            audit(
                "MASTER_ADMIN_CREATED",
                {

                    adminId:
                        admin.id,

                    email:
                        admin.email

                }
            );


            const token =
                createAuthToken(
                    admin
                );


            setAuthCookie(
                res,
                token
            );


            return res.status(201).json({

                ok:
                    true,

                authenticated:
                    true,

                role:
                    "master_admin",

                message:
                    "Master Admin created successfully."

            });

        }
        catch (error) {

            console.error(
                "MASTER SETUP ERROR:",
                error
            );


            return res.status(500).json({

                ok:
                    false,

                message:
                    "Unable to create Master Admin.",

                requestId:
                    req.requestId

            });

        }

    }
);


/*
========================================================
 MASTER ADMIN LOGIN
========================================================
*/

app.post(
    "/api/admin/auth/login",
    authLimiter,
    async (req, res) => {

        try {

            if (
                !db.masterAdmin
            ) {

                return res.status(404).json({

                    ok:
                        false,

                    message:
                        "Master Admin has not been configured yet."

                });

            }


            const email =
                sanitizeEmail(
                    req.body.email
                );


            const password =
                String(
                    req.body.password || ""
                );


            if (
                email !==
                db.masterAdmin.email
            ) {

                audit(
                    "MASTER_LOGIN_FAILED",
                    {

                        email,

                        reason:
                            "invalid_email"

                    }
                );


                return res.status(401).json({

                    ok:
                        false,

                    message:
                        "Invalid email or password."

                });

            }


            const passwordOk =
                await bcrypt.compare(
                    password,
                    db.masterAdmin.passwordHash
                );


            if (!passwordOk) {

                audit(
                    "MASTER_LOGIN_FAILED",
                    {

                        email,

                        reason:
                            "invalid_password"

                    }
                );


                return res.status(401).json({

                    ok:
                        false,

                    message:
                        "Invalid email or password."

                });

            }


            /*
            --------------------------------------------
            OPTIONAL 2FA
            --------------------------------------------
            */

            if (
                db.masterAdmin.twoFAEnabled
            ) {

                const challengeToken =
                    randomToken(32);


                db.sessions.set(
                    challengeToken,
                    {

                        adminId:
                            db.masterAdmin.id,

                        type:
                            "2fa_challenge",

                        expiresAt:
                            Date.now()
                            +
                            5 * 60 * 1000

                    }
                );


                return res.json({

                    ok:
                        true,

                    authenticated:
                        false,

                    requires2FA:
                        true,

                    challengeToken

                });

            }


            db.masterAdmin.lastLoginAt =
                nowISO();


            const token =
                createAuthToken(
                    db.masterAdmin
                );


            setAuthCookie(
                res,
                token
            );


            audit(
                "MASTER_LOGIN_SUCCESS",
                {

                    adminId:
                        db.masterAdmin.id

                }
            );


            return res.json({

                ok:
                    true,

                authenticated:
                    true,

                role:
                    "master_admin"

            });

        }
        catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );


            return res.status(500).json({

                ok:
                    false,

                message:
                    "Login failed.",

                requestId:
                    req.requestId

            });

        }

    }
);


/*
========================================================
 ADMIN SESSION
========================================================
*/

app.get(
    "/api/admin/auth/session",
    authenticateAdmin,
    (req, res) => {

        res.json({

            ok:
                true,

            authenticated:
                true,

            role:
                "master_admin",

            admin: {

                id:
                    req.admin.id,

                email:
                    req.admin.email,

                status:
                    req.admin.status,

                twoFAEnabled:
                    req.admin.twoFAEnabled,

                createdAt:
                    req.admin.createdAt,

                lastLoginAt:
                    req.admin.lastLoginAt

            }

        });

    }
);


/*
========================================================
 LOGOUT
========================================================
*/

app.post(
    "/api/admin/auth/logout",
    authenticateAdmin,
    (req, res) => {

        audit(
            "MASTER_LOGOUT",
            {

                adminId:
                    req.admin.id

            }
        );


        clearAuthCookie(
            res
        );


        res.json({

            ok:
                true,

            authenticated:
                false

        });

    }
);


/*
========================================================
 CHANGE PASSWORD
========================================================
*/

app.post(
    "/api/admin/auth/change-password",
    authLimiter,
    authenticateAdmin,
    async (req, res) => {

        try {

            const currentPassword =
                String(
                    req.body.currentPassword || ""
                );


            const newPassword =
                String(
                    req.body.newPassword || ""
                );


            if (
                !passwordIsStrong(
                    newPassword
                )
            ) {

                return res.status(400).json({

                    ok:
                        false,

                    message:
                        "New password must contain at least 12 characters, uppercase letters, lowercase letters, numbers and symbols."

                });

            }


            const currentOk =
                await bcrypt.compare(
                    currentPassword,
                    req.admin.passwordHash
                );


            if (!currentOk) {

                return res.status(401).json({

                    ok:
                        false,

                    message:
                        "Current password is incorrect."

                });

            }


            const newHash =
                await bcrypt.hash(
                    newPassword,
                    12
                );


            req.admin.passwordHash =
                newHash;


            audit(
                "MASTER_PASSWORD_CHANGED",
                {

                    adminId:
                        req.admin.id

                }
            );


            const newToken =
                createAuthToken(
                    req.admin
                );


            setAuthCookie(
                res,
                newToken
            );


            res.json({

                ok:
                    true,

                message:
                    "Password changed successfully."

            });

        }
        catch (error) {

            console.error(
                "CHANGE PASSWORD ERROR:",
                error
            );


            res.status(500).json({

                ok:
                    false,

                message:
                    "Unable to change password."

            });

        }

    }
);


/*
========================================================
 FORGOT PASSWORD
========================================================
*/

app.post(
    "/api/admin/auth/forgot-password",
    authLimiter,
    async (req, res) => {

        try {

            const email =
                sanitizeEmail(
                    req.body.email
                );


            const genericResponse = {

                ok:
                    true,

                message:
                    "If an account exists for that email, a password reset request has been created."

            };


            if (
                !db.masterAdmin ||
                email !==
                db.masterAdmin.email
            ) {

                return res.json(
                    genericResponse
                );

            }


            const token =
                randomToken(32);


            db.resetTokens.set(
                token,
                {

                    adminId:
                        db.masterAdmin.id,

                    expiresAt:
                        Date.now()
                        +
                        15 * 60 * 1000

                }
            );


            audit(
                "MASTER_PASSWORD_RESET_REQUESTED",
                {

                    adminId:
                        db.masterAdmin.id

                }
            );


            /*
            Development only.

            In production the token must be sent by
            a real email provider.
            */

            if (
                NODE_ENV !==
                "production"
            ) {

                genericResponse.developmentResetUrl =
                    "/talkify-admin.index.html?reset_token="
                    +
                    token;

            }


            return res.json(
                genericResponse
            );

        }
        catch (error) {

            console.error(
                "FORGOT PASSWORD ERROR:",
                error
            );


            return res.status(500).json({

                ok:
                    false,

                message:
                    "Unable to process password reset."

            });

        }

    }
);


/*
========================================================
 RESET PASSWORD
========================================================
*/

app.post(
    "/api/admin/auth/reset-password",
    authLimiter,
    async (req, res) => {

        try {

            const token =
                String(
                    req.body.token || ""
                );


            const password =
                String(
                    req.body.password || ""
                );


            if (!token) {

                return res.status(400).json({

                    ok:
                        false,

                    message:
                        "Reset token is required."

                });

            }


            const reset =
                db.resetTokens.get(
                    token
                );


            if (
                !reset ||
                reset.expiresAt <
                Date.now()
            ) {

                if (reset) {

                    db.resetTokens.delete(
                        token
                    );

                }


                return res.status(400).json({

                    ok:
                        false,

                    message:
                        "Reset token is invalid or expired."

                });

            }


            if (
                !passwordIsStrong(
                    password
                )
            ) {

                return res.status(400).json({

                    ok:
                        false,

                    message:
                        "Password must contain at least 12 characters, uppercase letters, lowercase letters, numbers and symbols."

                });

            }


            if (
                !db.masterAdmin ||
                db.masterAdmin.id !==
                reset.adminId
            ) {

                return res.status(400).json({

                    ok:
                        false,

                    message:
                        "Admin account not found."

                });

            }


            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );


            db.masterAdmin.passwordHash =
                passwordHash;


            db.resetTokens.delete(
                token
            );


            audit(
                "MASTER_PASSWORD_RESET_COMPLETED",
                {

                    adminId:
                        db.masterAdmin.id

                }
            );


            res.json({

                ok:
                    true,

                message:
                    "Password reset successfully."

            });

        }
        catch (error) {

            console.error(
                "RESET PASSWORD ERROR:",
                error
            );


            res.status(500).json({

                ok:
                    false,

                message:
                    "Unable to reset password."

            });

        }

    }
);


/*
========================================================
 ENABLE 2FA
========================================================
*/

app.post(
    "/api/admin/auth/2fa/enable",
    authenticateAdmin,
    (req, res) => {

        req.admin.twoFAEnabled =
            true;


        audit(
            "MASTER_2FA_ENABLED",
            {

                adminId:
                    req.admin.id

            }
        );


        res.json({

            ok:
                true,

            enabled:
                true,

            message:
                "2FA has been enabled. A real OTP/TOTP provider must be connected before production use."

        });

    }
);


/*
========================================================
 DISABLE 2FA
========================================================
*/

app.post(
    "/api/admin/auth/2fa/disable",
    authenticateAdmin,
    (req, res) => {

        req.admin.twoFAEnabled =
            false;


        audit(
            "MASTER_2FA_DISABLED",
            {

                adminId:
                    req.admin.id

            }
        );


        res.json({

            ok:
                true,

            enabled:
                false,

            message:
                "2FA has been disabled."

        });

    }
);


/*
========================================================
 2FA VERIFY
========================================================

NO FAKE OTP.

Until a real provider is connected, this endpoint
rejects verification.
========================================================
*/

app.post(
    "/api/admin/auth/2fa/verify",
    authLimiter,
    async (req, res) => {

        try {

            const challengeToken =
                String(
                    req.body.challengeToken || ""
                );


            const code =
                String(
                    req.body.code || ""
                );


            if (
                !challengeToken ||
                !code
            ) {

                return res.status(400).json({

                    ok:
                        false,

                    message:
                        "2FA challenge and code are required."

                });

            }


            const challenge =
                db.sessions.get(
                    challengeToken
                );


            if (
                !challenge ||
                challenge.type !==
                "2fa_challenge" ||
                challenge.expiresAt <
                Date.now()
            ) {

                return res.status(401).json({

                    ok:
                        false,

                    message:
                        "2FA challenge expired."

                });

            }


            return res.status(501).json({

                ok:
                    false,

                message:
                    "Real 2FA provider is not connected yet. No fake OTP is accepted."

            });

        }
        catch (error) {

            console.error(
                "2FA ERROR:",
                error
            );


            return res.status(500).json({

                ok:
                    false,

                message:
                    "2FA verification failed."

            });

        }

    }
);


/*
========================================================
 REVOKE OTHER SESSIONS
========================================================
*/

app.post(
    "/api/admin/auth/revoke-sessions",
    authenticateAdmin,
    (req, res) => {

        audit(
            "MASTER_SESSIONS_REVOKE_REQUESTED",
            {

                adminId:
                    req.admin.id

            }
        );


        res.json({

            ok:
                true,

            message:
                "Session revocation request recorded."

        });

    }
);


/*
========================================================
 ADMIN AUDIT API
========================================================
*/

app.get(
    "/api/admin/audit",
    authenticateAdmin,
    (req, res) => {

        const requestedLimit =
            Number(
                req.query.limit || 100
            );


        const limit =
            Math.min(
                Math.max(
                    requestedLimit,
                    1
                ),
                500
            );


        res.json({

            ok:
                true,

            items:
                db.auditLogs.slice(
                    0,
                    limit
                )

        });

    }
);


/*
========================================================
 DASHBOARD SUMMARY
========================================================

These values are intentionally zero/empty.

We do NOT create fake users, money, calls or profit.

Real values will come from PostgreSQL/Supabase.
========================================================
*/

app.get(
    "/api/admin/dashboard/summary",
    authenticateAdmin,
    (req, res) => {

        res.json({

            ok:
                true,

            totalUsers:
                0,

            onlineUsers:
                0,

            todayRecharge:
                0,

            todayCalls:
                0,

            totalWalletBalance:
                0,

            callProviderCost:
                0,

            revenue:
                0,

            profit:
                0,

            currency:
                "৳",

            services: [

                {
                    name:
                        "Authentication",

                    status:
                        "active"

                },

                {
                    name:
                        "Database",

                    status:
                        "pending"

                },

                {
                    name:
                        "Calling Provider",

                    status:
                        "not_configured"

                },

                {
                    name:
                        "SMS Provider",

                    status:
                        "not_configured"

                },

                {
                    name:
                        "Payment Gateway",

                    status:
                        "not_configured"

                }

            ],

            pending:
                []

        });

    }
);


/*
========================================================
 COUNTRIES
========================================================
*/

app.get(
    "/api/admin/countries",
    authenticateAdmin,
    (req, res) => {

        res.json({

            ok:
                true,

            countries:
                []

        });

    }
);


/*
========================================================
 FEATURES
========================================================
*/

app.get(
    "/api/admin/features",
    authenticateAdmin,
    (req, res) => {

        res.json({

            ok:
                true,

            features:
                []

        });

    }
);


/*
========================================================
 FALLBACK API
========================================================
*/

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({

            ok:
                false,

            message:
                "Talkify API endpoint not found.",

            path:
                req.originalUrl,

            requestId:
                req.requestId

        });

    }
);


/*
========================================================
 GENERAL ERROR HANDLER
========================================================
*/

app.use(
    (err, req, res, next) => {

        console.error(
            "SERVER ERROR:",
            err
        );


        res.status(500).json({

            ok:
                false,

            message:
                "Internal server error.",

            requestId:
                req.requestId

        });

    }
);


/*
========================================================
 START SERVER
========================================================
*/

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "=========================================="
        );

        console.log(
            " TALKIFY GLOBAL NETWORK BACKEND"
        );

        console.log(
            "=========================================="
        );

        console.log(
            `Server running on port ${PORT}`
        );

        console.log(
            `Environment: ${NODE_ENV}`
        );

        console.log(
            "CORS configured origins:"
        );

        console.log(
            configuredOrigins.length
                ? configuredOrigins.join(", ")
                : "(development/default rules)"
        );

        console.log(
            "Health:"
        );

        console.log(
            "/api/health"
        );

        console.log(
            "=========================================="
        );

    }
);
