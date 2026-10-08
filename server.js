/*
========================================================
 TALKIFY GLOBAL NETWORK
 MASTER BACKEND - server.js
========================================================

This backend provides the first secure Master Admin system.

Included:
1. First-time Master Admin setup
2. Master Admin login
3. Secure password hashing
4. HTTP-only authentication cookie
5. Admin session check
6. Logout
7. Forgot-password request
8. Password reset token
9. Change password
10. Optional 2FA-ready API
11. Audit logging
12. Basic security headers
13. Rate limiting
14. CORS configuration
15. Health check

IMPORTANT:
- Never put passwords in frontend code.
- Never put database passwords/API secrets in HTML.
- Never use localStorage for authentication.
- Production secrets must be stored as environment variables.
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

const PORT = Number(process.env.PORT || 3000);


/*
========================================================
 ENVIRONMENT VARIABLES
========================================================
*/

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "CHANGE_THIS_TALKIFY_SECRET_BEFORE_PRODUCTION";

const FRONTEND_ORIGIN =
    process.env.FRONTEND_ORIGIN ||
    "*";

const NODE_ENV =
    process.env.NODE_ENV ||
    "development";


/*
========================================================
 BASIC APP CONFIG
========================================================
*/

app.disable("x-powered-by");

app.use(
    helmet({
        crossOriginResourcePolicy: {
            policy: "cross-origin"
        }
    })
);


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


/*
========================================================
 CORS
========================================================
*/

app.use((req, res, next) => {

    if (FRONTEND_ORIGIN !== "*") {

        res.setHeader(
            "Access-Control-Allow-Origin",
            FRONTEND_ORIGIN
        );

        res.setHeader(
            "Access-Control-Allow-Credentials",
            "true"
        );

    }

    res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization"
    );

    res.setHeader(
        "Access-Control-Allow-Methods",
        "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    );


    if (req.method === "OPTIONS") {

        return res.sendStatus(204);

    }


    next();

});


/*
========================================================
 RATE LIMITERS
========================================================
*/

const authLimiter =
    rateLimit({

        windowMs: 15 * 60 * 1000,

        max: 20,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            ok: false,
            message:
                "Too many authentication attempts. Please try again later."
        }

    });


const generalLimiter =
    rateLimit({

        windowMs: 60 * 1000,

        max: 120,

        standardHeaders: true,

        legacyHeaders: false

    });


app.use(generalLimiter);


/*
========================================================
 TEMPORARY SERVER DATABASE
========================================================

IMPORTANT:

This is an in-memory development database.

It is NOT the final production database.

If the Node.js server restarts, the data disappears.

We are using this only to make the first backend
authentication flow work.

Later we will connect PostgreSQL/Supabase so that:

- users
- wallets
- KYC
- payments
- calls
- SMS
- admins
- sub-admins
- audit logs

are permanently stored.

========================================================
*/


const db = {

    masterAdmin: null,

    resetTokens: new Map(),

    sessions: new Map(),

    auditLogs: [],

    twoFA: {

        enabled: false

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



function randomToken(bytes = 32) {

    return crypto
        .randomBytes(bytes)
        .toString("hex");

}



function sanitizeEmail(email) {

    return String(email || "")
        .trim()
        .toLowerCase();

}



function validEmail(email) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);

}



function passwordIsStrong(password) {

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



function audit(action, details = {}) {

    db.auditLogs.unshift({

        id:
            crypto.randomUUID(),

        action,

        details,

        createdAt:
            nowISO()

    });


    if (db.auditLogs.length > 5000) {

        db.auditLogs.length = 5000;

    }

}



function createAuthToken(admin) {

    return jwt.sign(

        {

            sub: admin.id,

            role: "master_admin",

            email: admin.email

        },

        JWT_SECRET,

        {

            expiresIn: "8h",

            issuer:
                "talkify-global-network",

            audience:
                "talkify-admin"

        }

    );

}



function setAuthCookie(res, token) {

    res.cookie(
        "talkify_admin_session",
        token,
        {

            httpOnly: true,

            secure:
                NODE_ENV === "production",

            sameSite:
                NODE_ENV === "production"
                    ? "none"
                    : "lax",

            maxAge:
                8 * 60 * 60 * 1000,

            path: "/"

        }
    );

}



function clearAuthCookie(res) {

    res.clearCookie(
        "talkify_admin_session",
        {

            httpOnly: true,

            secure:
                NODE_ENV === "production",

            sameSite:
                NODE_ENV === "production"
                    ? "none"
                    : "lax",

            path: "/"

        }
    );

}



function getTokenFromRequest(req) {

    if (
        req.cookies &&
        req.cookies.talkify_admin_session
    ) {

        return req.cookies.talkify_admin_session;

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



function authenticateAdmin(req, res, next) {

    try {

        const token =
            getTokenFromRequest(req);


        if (!token) {

            return res.status(401).json({

                authenticated: false,

                message:
                    "Authentication required."

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

                authenticated: false,

                message:
                    "Master Admin access required."

            });

        }


        if (
            !db.masterAdmin ||
            db.masterAdmin.id !==
            decoded.sub
        ) {

            return res.status(401).json({

                authenticated: false,

                message:
                    "Admin account not found."

            });

        }


        req.admin =
            db.masterAdmin;


        next();

    }
    catch (error) {

        return res.status(401).json({

            authenticated: false,

            message:
                "Invalid or expired session."

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

            ok: true,

            service:
                "Talkify Global Network Backend",

            time:
                nowISO(),

            environment:
                NODE_ENV

        });

    }
);


/*
========================================================
 MASTER ADMIN SETUP
========================================================

POST
/api/admin/auth/setup

Body:

{
    "email":"admin@example.com",
    "password":"StrongPassword123!",
    "confirmPassword":"StrongPassword123!"
}

========================================================
*/

app.post(
    "/api/admin/auth/setup",
    authLimiter,
    async (req, res) => {

        try {

            /*
            Prevent creating another Master Admin
            through this public endpoint.
            */

            if (db.masterAdmin) {

                return res.status(409).json({

                    ok: false,

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


            if (!validEmail(email)) {

                return res.status(400).json({

                    ok: false,

                    message:
                        "Please enter a valid email address."

                });

            }


            if (
                password !==
                confirmPassword
            ) {

                return res.status(400).json({

                    ok: false,

                    message:
                        "Passwords do not match."

                });

            }


            if (
                !passwordIsStrong(password)
            ) {

                return res.status(400).json({

                    ok: false,

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
                createAuthToken(admin);


            setAuthCookie(
                res,
                token
            );


            return res.status(201).json({

                ok: true,

                authenticated: true,

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

                ok: false,

                message:
                    "Unable to create Master Admin."

            });

        }

    }
);


/*
========================================================
 MASTER ADMIN LOGIN
========================================================

POST
/api/admin/auth/login

========================================================
*/

app.post(
    "/api/admin/auth/login",
    authLimiter,
    async (req, res) => {

        try {

            if (!db.masterAdmin) {

                return res.status(404).json({

                    ok: false,

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

                    ok: false,

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

                    ok: false,

                    message:
                        "Invalid email or password."

                });

            }


            /*
            Optional 2FA.

            If enabled, do not create the final
            authenticated session until the OTP
            is verified.
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

                    ok: true,

                    authenticated: false,

                    requires2FA: true,

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

                ok: true,

                authenticated: true,

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

                ok: false,

                message:
                    "Login failed."

            });

        }

    }
);


/*
========================================================
 SESSION CHECK
========================================================

GET
/api/admin/auth/session

========================================================
*/

app.get(
    "/api/admin/auth/session",
    authenticateAdmin,
    (req, res) => {

        res.json({

            ok: true,

            authenticated: true,

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


        clearAuthCookie(res);


        res.json({

            ok: true,

            authenticated: false

        });

    }
);


/*
========================================================
 CHANGE PASSWORD
========================================================

POST
/api/admin/auth/change-password

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

                    ok: false,

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

                    ok: false,

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


            /*
            Force the current browser session
            to receive a new authentication token.
            */

            const newToken =
                createAuthToken(
                    req.admin
                );


            setAuthCookie(
                res,
                newToken
            );


            res.json({

                ok: true,

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

                ok: false,

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

POST
/api/admin/auth/forgot-password

For real production:
- Send reset link through secure email provider.
- Never return the token to the browser.

For development this API returns a development
reset URL so the system can be tested.

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


            /*
            Always return a generic response.
            This prevents email/account enumeration.
            */

            const genericResponse = {

                ok: true,

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

            In production this token MUST be
            emailed by the backend and MUST NOT
            be returned in the API response.
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

                ok: false,

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

POST
/api/admin/auth/reset-password

Body:

{
    "token":"...",
    "password":"..."
}

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

                    ok: false,

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

                    ok: false,

                    message:
                        "Reset token is invalid or expired."

                });

            }


            if (
                !passwordIsStrong(password)
            ) {

                return res.status(400).json({

                    ok: false,

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

                    ok: false,

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

                ok: true,

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

                ok: false,

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

This first backend version provides the
2FA configuration endpoint.

The actual OTP/TOTP provider will be connected
in the next security step.

We do NOT fake an OTP.

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

            ok: true,

            enabled: true,

            message:
                "2FA has been enabled. Complete the backend OTP enrollment before using it for login."

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

            ok: true,

            enabled: false,

            message:
                "2FA has been disabled."

        });

    }
);


/*
========================================================
 2FA VERIFY
========================================================

We intentionally do not accept arbitrary codes.

A real OTP/TOTP service will be connected here.

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

                    ok: false,

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

                    ok: false,

                    message:
                        "2FA challenge expired."

                });

            }


            /*
            IMPORTANT:

            No fake OTP.

            Until a real TOTP/SMS/email OTP
            provider is connected, verification
            is rejected.
            */

            return res.status(501).json({

                ok: false,

                message:
                    "Real 2FA provider is not connected yet. No fake OTP is accepted."

            });

        }
        catch (error) {

            console.error(
                "2FA ERROR:",
                error
            );


            res.status(500).json({

                ok: false,

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

        /*
        JWT sessions are stateless in this first version.

        Full server-side session revocation will be
        implemented when the production session store
        is connected.
        */

        audit(
            "MASTER_SESSIONS_REVOKE_REQUESTED",
            {

                adminId:
                    req.admin.id

            }
        );


        res.json({

            ok: true,

            message:
                "Session revocation request recorded."

        });

    }
);


/*
========================================================
 BASIC ADMIN AUDIT API
========================================================
*/

app.get(
    "/api/admin/audit",
    authenticateAdmin,
    (req, res) => {

        const limit =
            Math.min(
                Number(
                    req.query.limit || 100
                ),
                500
            );


        res.json({

            ok: true,

            items:
                db.auditLogs
                .slice(
                    0,
                    limit
                )

        });

    }
);


/*
========================================================
 ADMIN DASHBOARD PLACEHOLDER

These endpoints allow dashboard.html to load
without fake financial/user/call data.

They intentionally return empty real-data
structures until the production database is connected.

========================================================
*/

app.get(
    "/api/admin/dashboard/summary",
    authenticateAdmin,
    (req, res) => {

        res.json({

            ok: true,

            totalUsers: 0,

            onlineUsers: 0,

            todayRecharge: 0,

            todayCalls: 0,

            totalWalletBalance: 0,

            callProviderCost: 0,

            revenue: 0,

            profit: 0,

            currency: "৳",

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

            pending: []

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

            ok: true,

            countries: []

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

            ok: true,

            features: []

        });

    }
);


/*
========================================================
 FALLBACK API HANDLER
========================================================
*/

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({

            ok: false,

            message:
                "Talkify API endpoint not found.",

            path:
                req.originalUrl

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

            ok: false,

            message:
                "Internal server error."

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
            "Health:"
        );

        console.log(
            `/api/health`
        );

        console.log(
            "=========================================="
        );

    }
);
