const nodemailer = require('nodemailer');

// Create a reusable transporter object using the default SMTP transport
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'Gmail', // e.g., Gmail, SendGrid
    auth: {
        user: process.env.EMAIL_USER, // Your email address
        pass: process.env.EMAIL_PASSWORD, // Your email password or app password
    },
});

/**
 * Send an email
 * @param {string} to - Recipient email address
 * @param {string} subject - Email subject
 * @param {string} html - HTML content of the email
 */
const sendEmail = async (to, subject, html) => {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER, // Sender address
            to, // Recipient address
            subject, // Subject line
            html, // HTML body
        };

        // Send the email
        await transporter.sendMail(mailOptions);
        console.log(`Email sent to ${to}`);
    } catch (err) {
        console.error('Error sending email:', err);
        throw new Error('Failed to send email');
    }
};

module.exports = sendEmail;