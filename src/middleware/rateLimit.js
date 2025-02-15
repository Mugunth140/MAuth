const rateLimit = require('express-rate-limit');

// Rate limiter for login attempts
exports.loginLimiter = rateLimit({
    windowMs: process.env.RATE_LIMIT_WINDOW || 15 * 60 * 1000, // 15 minutes
    max: process.env.RATE_LIMIT_MAX || 5, // 5 attempts per window
    message: 'Too many login attempts. Please try again later.',
    handler: (req, res) => {
        res.status(429).json({
            error: 'Too many login attempts. Please try again later.',
        });
    },
});

// Rate limiter for sign-up attempts
exports.signUpLimiter = rateLimit({
    windowMs: process.env.RATE_LIMIT_WINDOW || 60 * 60 * 1000, // 1 hour
    max: process.env.RATE_LIMIT_MAX || 10, // 10 attempts per window
    message: 'Too many sign-up attempts. Please try again later.',
    handler: (req, res) => {
        res.status(429).json({
            error: 'Too many sign-up attempts. Please try again later.',
        });
    },
});

// Rate limiter for password reset attempts
exports.passwordResetLimiter = rateLimit({
    windowMs: process.env.RATE_LIMIT_WINDOW || 60 * 60 * 1000, // 1 hour
    max: process.env.RATE_LIMIT_MAX || 5, // 5 attempts per window
    message: 'Too many password reset attempts. Please try again later.',
    handler: (req, res) => {
        res.status(429).json({
            error: 'Too many password reset attempts. Please try again later.',
        });
    },
});