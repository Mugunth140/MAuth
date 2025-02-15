const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const sendEmail = require('../utils/email');
const speakeasy = require('speakeasy');

// Send verification email after signup
exports.signUp = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = new User({ email, password });
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        user.emailVerificationToken = token;
        user.emailVerificationExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        // Send email using nodemailer (configured via env)
        const transporter = nodemailer.createTransport({
            service: process.env.EMAIL_SERVICE,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD,
            },
        });

        await transporter.sendMail({
            to: email,
            subject: 'Verify Your Email',
            html: `Click <a href="${process.env.BASE_URL}/verify-email?token=${token}">here</a> to verify your email.`,
        });

        res.status(201).json({ message: 'User created. Verification email sent.' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
};

// Sign In with 2FA Check
exports.signIn = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        if (user.is2FAEnabled) {
            return res.json({ requires2FA: true, userId: user._id });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Forgot Password
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) throw new Error('User not found');

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        // Send email with reset link (use Nodemailer or similar)
        res.json({ message: 'Reset password email sent' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
};

// Reset Password
exports.resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() },
        });
        if (!user) throw new Error('Invalid or expired token');

        user.password = newPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.json({ message: 'Password reset successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
};

// Verify email endpoint
exports.verifyEmail = async (req, res) => {
    const { token } = req.query;
    try {
        const user = await User.findOne({
            emailVerificationToken: token,
            emailVerificationExpires: { $gt: Date.now() },
        });
        if (!user) throw new Error('Invalid or expired token');

        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;
        await user.save();
        res.json({ message: 'Email verified successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
};

exports.enable2FA = async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const secret = speakeasy.generateSecret({ length: 20 });
        user.twoFASecret = secret.base32;
        user.is2FAEnabled = true;
        await user.save();

        res.json({ secret: secret.base32, qrCodeUrl: secret.otpauth_url });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.verify2FA = async (req, res) => {
    const { token, userId } = req.body;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const verified = speakeasy.totp.verify({
            secret: user.twoFASecret,
            encoding: 'base32',
            token,
        });

        if (!verified) {
            return res.status(400).json({ error: 'Invalid 2FA code' });
        }

        const authToken = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token: authToken });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Google OAuth callback
exports.googleOAuthCallback = (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
};
