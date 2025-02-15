const express = require('express');
const passport = require('passport');
const authController = require('../controllers/authController');
const { loginLimiter, signUpLimiter, passwordResetLimiter } = require('../middleware/rateLimit');

const router = express.Router();

// Apply rate limiting to authentication endpoints
router.post('/signin', loginLimiter, authController.signIn);
router.post('/signup', signUpLimiter, authController.signUp);
router.post('/forgot-password', passwordResetLimiter, authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

// Google OAuth routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get(
    '/google/callback',
    passport.authenticate('google', { session: false }),
    authController.googleOAuthCallback
);

module.exports = router;