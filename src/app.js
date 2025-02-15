const express = require('express');
const dotenv = require('dotenv');
const passport = require('passport');
const session = require('express-session');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const tenantRoutes = require('./routes/tenantRoutes');
const { loginLimiter, signUpLimiter, passwordResetLimiter } = require('./config/rateLimit');
const errorHandler = require('./middleware/errorHandler');

dotenv.config();
const app = express();

// Connect to MongoDB
connectDB();

// Middleware
app.use(express.json());

// Session configuration for Passport
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'your_session_secret',
        resave: false,
        saveUninitialized: true,
        cookie: { secure: process.env.NODE_ENV === 'production' },
    })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api', tenantRoutes);

// Apply rate limiting to authentication endpoints
app.use('/api/auth/signin', loginLimiter);
app.use('/api/auth/signup', signUpLimiter);
app.use('/api/auth/forgot-password', passwordResetLimiter);

// Error handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));