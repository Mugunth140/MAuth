const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');

// Configure Google OAuth Strategy
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_CALLBACK_URL,
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                // Check if the user already exists
                let user = await User.findOne({ googleId: profile.id });

                if (!user) {
                    // Create a new user if they don't exist
                    user = new User({
                        googleId: profile.id,
                        email: profile.emails[0].value,
                        isEmailVerified: true, // Assume Google-verified email
                    });
                    await user.save();
                }

                // Return the user
                done(null, user);
            } catch (err) {
                done(err, null);
            }
        }
    )
);

// Serialize user into session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

module.exports = passport;