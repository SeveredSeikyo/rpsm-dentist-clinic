const nodemailer = require('nodemailer');
const cron = require('node-cron');
const { getDB } = require('./db');
const { DateTime } = require('luxon');
require('dotenv').config();

const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;

// Email transporter setup
const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT == 465, // true for 465, false for other ports
    auth: {
        user: SMTP_USER,
        pass: SMTP_PASS
    }
});

// Function to verify SMTP connection
async function verifySMTP() {
    try {
        await transporter.verify();
        console.log('SMTP connection verified');
    } catch (err) {
        console.error('SMTP connection error:', err.message);
    }
}

// Function to send reminder email
async function sendReminderEmail(reminder) {
    try {
        // Convert remind_at to IST for display
        const remindAtIST = DateTime.fromISO(reminder.remind_at, { zone: 'utc' }).setZone('Asia/Kolkata').toLocaleString(DateTime.DATETIME_FULL);
        console.log(`Attempting to send email for reminder ${reminder.id} to ${reminder.email} at ${DateTime.now().setZone('Asia/Kolkata').toISO()}`);
        await transporter.sendMail({
            from: `"RPSM Dental Clinic" <${SMTP_USER}>`,
            to: reminder.email,
            subject: 'Dental Appointment Reminder',
            text: `Dear Patient,\n\nThis is a reminder for your dental appointment:\n\nMessage: ${reminder.message}\nTime: ${remindAtIST}\n\nBest regards,\nRPSM Dental Clinic`,
            html: `
                <h2>Dental Appointment Reminder</h2>
                <p>Dear Patient,</p>
                <p>This is a reminder for your dental appointment:</p>
                <ul>
                    <li><strong>Message:</strong> ${reminder.message}</li>
                    <li><strong>Time:</strong> ${remindAtIST}</li>
                </ul>
                <p>Best regards,<br>RPSM Dental Clinic</p>
            `
        });
        console.log(`Reminder email sent to ${reminder.email} for reminder ${reminder.id}`);
    } catch (err) {
        console.error(`Error sending email for reminder ${reminder.id} to ${reminder.email}:`, err.message);
        throw err;
    }
}

// Function to check and send reminders
async function startReminderCheck() {
    // Verify SMTP on startup
    await verifySMTP();

    // Run every minute
    cron.schedule('* * * * *', async () => {
        try {
            const db = getDB();
            // Get current time in IST, convert to UTC for database comparison
            const now = DateTime.now().setZone('Asia/Kolkata').toUTC().toISO();
            console.log(`Checking reminders at ${DateTime.now().setZone('Asia/Kolkata').toISO()} (UTC: ${now})`);
            const reminders = await new Promise((resolve, reject) => {
                db.all(
                    `SELECT * FROM reminders WHERE remind_at <= ? AND sent = 0`,
                    [now],
                    (err, rows) => {
                        if (err) reject(err);
                        resolve(rows);
                    }
                );
            });

            console.log(`Found ${reminders.length} reminders to process:`, JSON.stringify(reminders, null, 2));
            for (const reminder of reminders) {
                await sendReminderEmail(reminder);
                await new Promise((resolve, reject) => {
                    db.run(
                        `UPDATE reminders SET sent = 1 WHERE id = ?`,
                        [reminder.id],
                        (err) => {
                            if (err) reject(err);
                            resolve();
                        }
                    );
                });
                console.log(`Reminder ${reminder.id} marked as sent`);
            }
        } catch (err) {
            console.error('Error checking reminders:', err.message);
        }
    });
}

module.exports = { startReminderCheck, sendReminderEmail, transporter };