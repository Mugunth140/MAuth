const winston = require('winston');
const path = require('path');

// Create a logger instance
const logger = winston.createLogger({
    level: 'info', // Log level
    format: winston.format.json(), // Log format
    transports: [
        // Log to a file
        new winston.transports.File({
            filename: path.join(__dirname, '../auth.log'), // Log file path
            level: 'info', // Log level for the file
        }),
        // Log to the console (optional)
        new winston.transports.Console({
            format: winston.format.simple(), // Simple format for console
        }),
    ],
});

/**
 * Log an authentication event
 * @param {string} event - Event name (e.g., "login", "signup")
 * @param {string} userId - User ID (if available)
 * @param {string} status - Event status (e.g., "success", "failed")
 * @param {string} message - Additional message (optional)
 */
const logAuthEvent = (event, userId, status, message = '') => {
    logger.info({
        timestamp: new Date().toISOString(),
        event,
        userId,
        status,
        message,
    });
};

module.exports = logAuthEvent;