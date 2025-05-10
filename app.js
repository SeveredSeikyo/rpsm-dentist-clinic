const express = require('express');
const cors = require('cors');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { hash, compare } = require('bcrypt');
const dotenv = require('dotenv');
const { connectAndSetup, getDB } = require('./db');
const { startReminderCheck, transporter } = require('./notif');
const crypto = require('crypto');
const { DateTime } = require('luxon');
dotenv.config();

const app = express();
const viewsDir = path.join(__dirname, 'views');
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const SMTP_USER = process.env.SMTP_USER;

app.use(cors({
    origin: true,
    credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(viewsDir));

let db = null;

const initializeDBAndServer = async () => {
    try {
        db = await connectAndSetup();

        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
        startReminderCheck();
    } catch (e) {
        console.error("DB Error:", e.message);
    }
};

initializeDBAndServer();

// Middleware to check authentication
const requireAuth = (userType) => {
    return (req, res, next) => {
        const token = req.cookies.jwtToken;
        if (!token) return res.redirect('/login');

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;

            // Check if the user's role matches the required userType
            if (decoded.userType !== userType) {
                return res.status(403).send('Unauthorized: Insufficient role');
            }

            next();
        } catch (err) {
            res.clearCookie('jwtToken');
            return res.redirect('/login');
        }
    };
};

function restrictToAny(...roles) {
    return (req, res, next) => {
        const token = req.cookies.jwtToken;
        if (!token) return res.redirect('/login');

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;

            // Check if the user's role is one of the allowed roles
            if (!roles.includes(decoded.userType)) {
                return res.status(403).send('Unauthorized: Insufficient role');
            }

            next();
        } catch (err) {
            res.clearCookie('jwtToken');
            return res.redirect('/login');
        }
    };
}

// Root route: Redirects if logged in
app.get('/', (req, res) => {
    // const token = req.cookies.jwtToken;
    // if (token) {
    //     try {
    //         const decoded = jwt.verify(token, JWT_SECRET);
    //         let redirectURL = '/';
    //         if (decoded.userType === 'dentist') redirectURL = '/dentist';
    //         else if (decoded.userType === 'patient') redirectURL = '/patient';
    //         else if (decoded.userType === 'staff') redirectURL = '/staff';
    //         return res.redirect(redirectURL);
    //     } catch (err) {
    //         res.clearCookie('jwtToken');
    //     }
    // }
    return res.sendFile(path.join(viewsDir, 'homie.html'));
});

app.get('/logout', (req, res) => {
    res.clearCookie('jwtToken');
    res.redirect('/');
});

// Serve static pages
app.get('/login', (req, res) => {
    const token = req.cookies.jwtToken;
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            let redirectURL = '/';
            if (decoded.userType === 'dentist') redirectURL = '/dentist';
            else if (decoded.userType === 'patient') redirectURL = '/patient';
            else if (decoded.userType === 'staff') redirectURL = '/staff';
            return res.redirect(redirectURL);
        } catch (err) {
            res.clearCookie('jwtToken');
        }
    }
    res.sendFile(path.join(viewsDir, 'login.html'));
});

app.get('/register', (req, res) => {
    const token = req.cookies.jwtToken;
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            let redirectURL = '/';
            if (decoded.userType === 'dentist') redirectURL = '/dentist';
            else if (decoded.userType === 'patient') redirectURL = '/patient';
            else if (decoded.userType === 'staff') redirectURL = '/staff';
            return res.redirect(redirectURL);
        } catch (err) {
            res.clearCookie('jwtToken');
        }
    }
    res.sendFile(path.join(viewsDir, 'register.html'));
});

app.get('/billing', requireAuth('patient'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'billing.html'));
});

app.get('/terms', (req, res) => {
    res.sendFile(path.join(viewsDir, 'serviceterms.html'));
});

app.get('/about', (req, res) => {
    res.sendFile(path.join(viewsDir, 'aboutus.html'));
});

app.get('/dentist-schedule', requireAuth('dentist'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'dentist.html'));
});

app.get('/staff-schedule', requireAuth('staff'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'staff.html'));
});

app.get('/feedback', requireAuth('patient'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'feedback.html'));
});

app.get('/policy', (req, res) => {
    res.sendFile(path.join(viewsDir, 'policy.html'));
});

app.get('/records', restrictToAny('staff', 'dentist'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'records.html'));
});

app.get('/reminders', requireAuth('staff'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'automatedreminder.html'));
});

app.get('/appointment', requireAuth('patient'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'appointment.html'));
});

app.get('/staff-appointments', requireAuth('staff'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'staff-appointments.html'));
});

app.get('/dentist-appointments', requireAuth('dentist'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'dentist-appointments.html'));
});

app.get('/patient', requireAuth('patient'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'patientdash.html'));
});

app.get('/dentist', requireAuth('dentist'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'dentistdash.html'));
});

app.get('/staff', requireAuth('staff'), (req, res) => {
    res.sendFile(path.join(viewsDir, 'staffdash.html'));
});

//Get View FeedBack
app.get('/staff-feedback', restrictToAny('staff', 'dentist'), (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'staff-feedback.html'));
});

// Login route
app.post('/login', async (req, res) => {
    const { userType, email, password } = req.body;

    if (!email || !password || !userType) {
        return res.status(400).json({ error: 'Email, Password, and UserType are required' });
    }

    try {
        const db = getDB();
        const user = await new Promise((resolve, reject) => {
            db.get(`SELECT * FROM users WHERE email = ? AND userType = ?`, [email, userType], (err, row) => {
                if (err) return reject(err);
                resolve(row);
            });
        });

        if (!user || !user.password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const passwordMatch = await compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT and set cookie
        const token = jwt.sign({ id: user.id, userType: user.userType, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
        res.cookie('jwtToken', token, {
            httpOnly: false,
            secure: false, // true if using HTTPS
            sameSite: 'lax',
        });

        return res.status(200).json({ redirect: `${user.userType}` });
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'An error occurred during login' });
    }
});

// Registration route
app.post('/register', async (req, res) => {
    const { username, email, password, full_name, dob, phone, consent, userType } = req.body;

    if (!username || !email || !password || !full_name || !dob || !phone || !consent || !userType) {
        return res.status(400).json({ error: 'All fields are required, and you must agree to the terms' });
    }

    if (!['patient', 'dentist', 'staff'].includes(userType)) {
        return res.status(400).json({ error: 'Invalid User Type' });
    }

    try {
        const hashedPassword = await hash(password, 10);
        const db = getDB();
        await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO users (username, email, password, full_name, dob, phone, userType)
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [username, email, hashedPassword, full_name, dob, phone, userType],
                function (err) {
                    if (err) return reject(err);
                    resolve(this);
                }
            );
        });

        return res.status(200).json({ redirect: '/login' });
    } catch (error) {
        console.error('Registration error:', error);
        return res.status(500).json({ error: 'An error occurred during registration' });
    }
});

// Appointment routes
// Create appointment (patients only)
app.post('/api/appointments', requireAuth('patient'), async (req, res) => {
    const { date, time, procedure } = req.body;
    const user_id = req.user.id;

    if (!date || !time || !procedure) {
        return res.status(400).json({ error: 'Date, time, and procedure are required' });
    }

    // Validate date is in the future
    const appointmentDateTime = new Date(`${date}T${time}`);
    if (appointmentDateTime <= new Date()) {
        return res.status(400).json({ error: 'Appointment must be in the future' });
    }

    try {
        const db = getDB();
        const result = await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO appointments (user_id, date, time, procedure) VALUES (?, ?, ?, ?)`,
                [user_id, date, time, procedure],
                function (err) {
                    if (err) reject(err);
                    resolve({ id: this.lastID });
                }
            );
        });

        // Fetch the inserted appointment with user details
        const appointment = await new Promise((resolve, reject) => {
            db.get(
                `SELECT a.*, u.full_name, u.email 
                 FROM appointments a 
                 JOIN users u ON a.user_id = u.id 
                 WHERE a.id = ?`,
                [result.id],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        res.status(201).json(appointment);
    } catch (err) {
        console.error('Error creating appointment:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get appointments (patients see their own, staff see all)
app.get('/api/appointments', restrictToAny('patient', 'staff','dentist'), async (req, res) => {
    try {
        const db = getDB();
        const query = req.user.userType === 'staff' || req.user.userType === 'dentist'
            ? `SELECT a.*, u.full_name, u.email 
               FROM appointments a 
               JOIN users u ON a.user_id = u.id`
            : `SELECT a.*, u.full_name, u.email 
               FROM appointments a 
               JOIN users u ON a.user_id = u.id 
               WHERE a.user_id = ?`;

        const params = req.user.userType === 'staff' || req.user.userType==='dentist' ? [] : [req.user.id];

        const appointments = await new Promise((resolve, reject) => {
            db.all(query, params, (err, rows) => {
                if (err) reject(err);
                resolve(rows);
            });
        });

        res.json(appointments);
    } catch (err) {
        console.error('Error fetching appointments:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete appointment (staff or patient who owns it)
app.delete('/api/appointments/:id', requireAuth('patient'), async (req, res) => {
    const { id } = req.params;
    const user_id = req.user.id;

    try {
        const db = getDB();
        const query = `DELETE FROM appointments WHERE id = ? AND user_id = ?`;
        const params = [id, user_id];

        await new Promise((resolve, reject) => {
            db.run(query, params, function (err) {
                if (err) reject(err);
                if (this.changes === 0) reject(new Error('Appointment not found or unauthorized'));
                resolve();
            });
        });

        res.status(204).send();
    } catch (err) {
        console.error('Error deleting appointment:', err.message);
        res.status(err.message === 'Appointment not found or unauthorized' ? 404 : 500)
            .json({ error: err.message });
    }
});

// Create reminder
app.post('/api/reminders', requireAuth('staff'), async (req, res) => {
    const { email, message, remind_at } = req.body;
    const patient_id = req.user.id;

    if (!email || !message || !remind_at) {
        return res.status(400).json({ error: 'Email, message, and reminder time are required' });
    }

    // Parse remind_at as IST, convert to UTC for storage
    const reminderDateTime = DateTime.fromISO(remind_at, { zone: 'Asia/Kolkata' });
    if (!reminderDateTime.isValid) {
        console.error(`Invalid remind_at format: ${remind_at}`);
        return res.status(400).json({ error: 'Invalid reminder time format' });
    }

    if (reminderDateTime <= DateTime.now().setZone('Asia/Kolkata')) {
        return res.status(400).json({ error: 'Reminder time must be in the future' });
    }

    const remindAtUTC = reminderDateTime.toUTC().toISO();

    try {
        const result = await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO reminders (patient_id, email, message, remind_at) VALUES (?, ?, ?, ?)`,
                [patient_id, email, message, remindAtUTC],
                function (err) {
                    if (err) reject(err);
                    resolve({ id: this.lastID });
                }
            );
        });

        const reminder = await new Promise((resolve, reject) => {
            db.get(
                `SELECT * FROM reminders WHERE id = ?`,
                [result.id],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        // Convert remind_at back to IST for response
        reminder.remind_at = DateTime.fromISO(reminder.remind_at, { zone: 'utc' }).setZone('Asia/Kolkata').toISO();
        console.log(`Reminder created: ID ${reminder.id}, Email ${reminder.email}, Time ${reminder.remind_at}`);
        res.status(201).json(reminder);
    } catch (err) {
        console.error('Error creating reminder:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get reminders
app.get('/api/reminders', requireAuth('staff'), async (req, res) => {
    try {
        const reminders = await new Promise((resolve, reject) => {
            db.all(
                `SELECT * FROM reminders WHERE patient_id = ? AND sent = 0`,
                [req.user.id],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        // Convert remind_at to IST for response
        const remindersIST = reminders.map(reminder => ({
            ...reminder,
            remind_at: DateTime.fromISO(reminder.remind_at, { zone: 'utc' }).setZone('Asia/Kolkata').toISO()
        }));
        res.json(remindersIST);
    } catch (err) {
        console.error('Error fetching reminders:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete reminder
app.delete('/api/reminders/:id', requireAuth('staff'), async (req, res) => {
    const { id } = req.params;
    const patient_id = req.user.id;

    try {
        await new Promise((resolve, reject) => {
            db.run(
                `DELETE FROM reminders WHERE id = ? AND patient_id = ?`,
                [id, patient_id],
                function (err) {
                    if (err) reject(err);
                    if (this.changes === 0) reject(new Error('Reminder not found or unauthorized'));
                    resolve();
                }
            );
        });
        res.status(204).send();
    } catch (err) {
        console.error('Error deleting reminder:', err.message);
        res.status(err.message === 'Reminder not found or unauthorized' ? 404 : 500)
            .json({ error: err.message });
    }
});

// Test email
app.get('/test-email', async (req, res) => {
    try {
        await transporter.sendMail({
            from: process.env.SMTP_USER,
            to: 'ashb01012000@gmail.com',
            subject: 'Test Email',
            text: 'This is a test email from RPSM Dental Clinic.'
        });
        console.log('Test email sent to ashb01012000@gmail.com');
        res.send('Email sent');
    } catch (err) {
        console.error('Test email error:', err.message);
        res.status(500).send(err.message);
    }
});

// Forgot password
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!user) {
            return res.status(404).json({ error: 'No user found with this email' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = DateTime.now().plus({ hours: 1 }).toISO();

        await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO reset_tokens (email, token, expires_at) VALUES (?, ?, ?)',
                [email, token, expiresAt],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });

        const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${token}`;

        const mailOptions = {
            from: process.env.SMTP_USER,
            to: email,
            subject: 'Password Reset Request',
            text: `You requested a password reset. Click this link to reset your password: ${resetLink}\n\nThis link expires in 1 hour.`
        };

        await transporter.sendMail(mailOptions);
        console.log(`Password reset email sent to: ${email}`);
        res.json({ message: 'Password reset link sent to your email' });
    } catch (err) {
        console.error('Error processing forgot password:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Serve reset password page
app.get('/reset-password', async (req, res) => {
    const { token } = req.query;

    if (!token) {
        console.log('No token provided in reset-password GET request');
        return res.redirect('/login?error=' + encodeURIComponent('No reset token provided'));
    }

    try {
        const resetToken = await new Promise((resolve, reject) => {
            db.get(
                `SELECT * FROM reset_tokens WHERE token = ? AND expires_at > ?`,
                [token, new Date().toISOString()],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        if (!resetToken) {
            console.log(`Invalid or expired token: ${token}`);
            return res.redirect('/login?error=' + encodeURIComponent('Invalid or expired reset token'));
        }

        console.log(`Valid token accessed for reset-password: ${token}`);
        res.sendFile(path.join(__dirname, 'views', 'resetpassword.html'));
    } catch (err) {
        console.error('Error validating reset token:', err.message);
        res.redirect('/login?error=' + encodeURIComponent('Server error during token validation'));
    }
});

// Reset password
app.post('/reset-password', async (req, res) => {
    const { token, password, confirmPassword } = req.body;

    if (!token || !password || !confirmPassword) {
        return res.status(400).send('Token, password, and confirm password are required');
    }

    if (password !== confirmPassword) {
        return res.status(400).send('Passwords do not match');
    }

    try {
        const resetToken = await new Promise((resolve, reject) => {
            db.get(
                `SELECT * FROM reset_tokens WHERE token = ? AND expires_at > ?`,
                [token, new Date().toISOString()],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        if (!resetToken) {
            return res.status(400).send('Invalid or expired token');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await new Promise((resolve, reject) => {
            db.run(
                `UPDATE users SET password = ? WHERE email = ?`,
                [hashedPassword, resetToken.email],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });

        await new Promise((resolve, reject) => {
            db.run(
                `DELETE FROM reset_tokens WHERE token = ?`,
                [token],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });

        console.log(`Password reset for ${resetToken.email}`);
        res.status(200).send('Password reset successfully');
    } catch (err) {
        console.error('Error in reset-password:', err.message);
        res.status(500).send('Server error');
    }
});

// Submit feedback
app.post('/api/feedback', requireAuth('patient'), async (req, res) => {
    const { rating, comment } = req.body;
    const user_id = req.user.id;

    if (!rating || !comment) {
        return res.status(400).json({ error: 'Rating and comment are required' });
    }

    if (!Number.isInteger(Number(rating)) || rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Rating must be an integer between 1 and 5' });
    }

    try {
        const result = await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO feedback (user_id, rating, comment) VALUES (?, ?, ?)`,
                [user_id, rating, comment],
                function (err) {
                    if (err) reject(err);
                    resolve({ id: this.lastID });
                }
            );
        });

        const feedback = await new Promise((resolve, reject) => {
            db.get(
                `SELECT f.*, u.username, u.email FROM feedback f 
                 JOIN users u ON f.user_id = u.id 
                 WHERE f.id = ?`,
                [result.id],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        console.log(`Feedback submitted: ID ${feedback.id}, User ${feedback.email}, Rating ${feedback.rating}`);
        res.status(201).json(feedback);
    } catch (err) {
        console.error('Error submitting feedback:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get feedback
app.get('/api/feedback', restrictToAny('patient', 'staff', 'dentist'), async (req, res) => {
    try {
        const feedback = await new Promise((resolve, reject) => {
            db.all(
                `SELECT f.*, u.username, u.email FROM feedback f 
                 JOIN users u ON f.user_id = u.id 
                 ORDER BY f.created_at DESC`,
                [],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json(feedback);
    } catch (err) {
        console.error('Error fetching feedback:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Patient routes
// Get patients with appointments (for billing dropdown)
app.get('/api/patients', restrictToAny('patient','staff', 'dentist'), async (req, res) => {
    try {
        const patients = await new Promise((resolve, reject) => {
            db.all(
                `SELECT DISTINCT u.id, u.full_name, u.email, u.phone, u.dob 
                 FROM users u
                 JOIN appointments a ON u.id = a.user_id
                 WHERE u.userType = 'patient'`,
                [],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json(patients);
    } catch (err) {
        console.error('Error fetching patients:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

//GET ALL PATIENTS
app.get('/api/records/patients', restrictToAny('patient','staff', 'dentist'), async (req, res) => {
    try {
        const patients = await new Promise((resolve, reject) => {
            db.all(
                `SELECT DISTINCT u.id, u.full_name, u.email, u.phone, u.dob 
                 FROM users`,
                [],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json(patients);
    } catch (err) {
        console.error('Error fetching patients:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete patient
app.delete('/api/patients/:id', restrictToAny('patient','staff', 'dentist'), async (req, res) => {
    const { id } = req.params;

    try {
        await new Promise((resolve, reject) => {
            db.run(
                `DELETE FROM users WHERE id = ? AND userType = 'patient'`,
                [id],
                function (err) {
                    if (err) reject(err);
                    if (this.changes === 0) reject(new Error('Patient not found'));
                    resolve();
                }
            );
        });

        console.log(`Patient deleted: ID ${id}`);
        res.status(204).send();
    } catch (err) {
        console.error('Error deleting patient:', err.message);
        res.status(err.message === 'Patient not found' ? 404 : 500).json({ error: err.message });
    }
});

// Get patient appointments
app.get('/api/patients/:id/appointments', restrictToAny('patient','staff', 'dentist'), async (req, res) => {
    const { id } = req.params;

    try {
        const appointments = await new Promise((resolve, reject) => {
            db.all(
                `SELECT id, date, time, procedure, created_at 
                 FROM appointments 
                 WHERE user_id = ? 
                 ORDER BY date DESC, time DESC`,
                [id],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json(appointments);
    } catch (err) {
        console.error('Error fetching appointments:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get patient billing history
app.get('/api/patients/:id/billings', restrictToAny('patient','staff', 'dentist'), async (req, res) => {
    const { id } = req.params;

    try {
        const billings = await new Promise((resolve, reject) => {
            db.all(
                `SELECT id, amount, payment_method, date, appointment_id, 
                        (SELECT procedure FROM appointments WHERE id = billings.appointment_id) AS procedure,
                        (SELECT date FROM appointments WHERE id = billings.appointment_id) AS appointment_date,
                        (SELECT time FROM appointments WHERE id = billings.appointment_id) AS appointment_time
                 FROM billings 
                 WHERE patient_id = ? 
                 ORDER BY date DESC`,
                [id],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json(billings);
    } catch (err) {
        console.error('Error fetching billings:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Billing routes

// Get unbilled appointments for a patient
app.get('/api/patients/:id/unbilled-appointments', requireAuth('patient'), async (req, res) => {
    const { id } = req.params;

    try {
        const appointments = await new Promise((resolve, reject) => {
            db.all(
                `SELECT a.id, a.date, a.time, a.procedure
                 FROM appointments a
                 LEFT JOIN billings b ON a.id = b.appointment_id
                 WHERE a.user_id = ? AND b.id IS NULL
                 ORDER BY a.date DESC, a.time DESC`,
                [id],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json(appointments);
    } catch (err) {
        console.error('Error fetching unbilled appointments:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Add billing entry
app.post('/api/billings', requireAuth('patient'), async (req, res) => {
    const { appointment_id, amount, payment_method } = req.body;
    const staff_id = req.user.id;

    if (!appointment_id || !amount || !payment_method) {
        return res.status(400).json({ error: 'Appointment ID, amount, and payment method are required' });
    }

    if (amount <= 0) {
        return res.status(400).json({ error: 'Amount must be greater than zero' });
    }

    if (!['cash', 'gcash'].includes(payment_method)) {
        return res.status(400).json({ error: 'Payment method must be cash or gcash' });
    }

    try {
        // Verify appointment exists and is unbilled
        const appointment = await new Promise((resolve, reject) => {
            db.get(
                `SELECT a.id, a.user_id
                 FROM appointments a
                 LEFT JOIN billings b ON a.id = b.appointment_id
                 WHERE a.id = ? AND b.id IS NULL`,
                [appointment_id],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        if (!appointment) {
            return res.status(404).json({ error: 'Appointment not found or already billed' });
        }

        await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO billings (patient_id, staff_id, appointment_id, amount, payment_method) 
                 VALUES (?, ?, ?, ?, ?)`,
                [appointment.user_id, staff_id, appointment_id, amount, payment_method],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });

        console.log(`Billing added: Appointment ID ${appointment_id}, Amount ${amount}`);
        res.status(201).json({ message: 'Payment processed successfully' });
    } catch (err) {
        console.error('Error adding billing:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all billing records
app.get('/api/billings', requireAuth('patient'), async (req, res) => {
    try {
        const billings = await new Promise((resolve, reject) => {
            db.all(
                `SELECT b.id, b.patient_id, u.full_name AS patient_name, b.staff_id, u2.full_name AS staff_name, 
                        b.appointment_id, a.procedure, a.date AS appointment_date, a.time AS appointment_time,
                        b.amount, b.payment_method, b.date 
                 FROM billings b
                 JOIN users u ON b.patient_id = u.id
                 LEFT JOIN users u2 ON b.staff_id = u2.id
                 LEFT JOIN appointments a ON b.appointment_id = a.id
                 ORDER BY b.date DESC`,
                [],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json(billings);
    } catch (err) {
        console.error('Error fetching billings:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete billing entry
app.delete('/api/billings/:id', requireAuth('patient'), async (req, res) => {
    const { id } = req.params;

    try {
        await new Promise((resolve, reject) => {
            db.run(
                `DELETE FROM billings WHERE id = ?`,
                [id],
                function (err) {
                    if (err) reject(err);
                    if (this.changes === 0) reject(new Error('Billing record not found'));
                    resolve();
                }
            );
        });

        console.log(`Billing deleted: ID ${id}`);
        res.status(204).send();
    } catch (err) {
        console.error('Error deleting billing:', err.message);
        res.status(err.message === 'Billing record not found' ? 404 : 500).json({ error: err.message });
    }
});

// Dentist and Staff schedule routes

// Get user's own schedule (dentist or staff)
app.get('/api/schedules', restrictToAny('dentist', 'staff'), async (req, res) => {
    const user_id = req.user.id;

    try {
        const schedules = await new Promise((resolve, reject) => {
            db.all(
                `SELECT s.id, s.days, s.hours, u.full_name 
                 FROM schedules s 
                 JOIN users u ON s.user_id = u.id 
                 WHERE s.user_id = ?`,
                [user_id],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        res.json(schedules);
    } catch (err) {
        console.error('Error fetching schedules:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Add or update user's schedule (dentist or staff)
app.post('/api/schedules', restrictToAny('dentist', 'staff'), async (req, res) => {
    const { days, hours } = req.body;
    const user_id = req.user.id;

    if (!days || !hours) {
        return res.status(400).json({ error: 'Days and hours are required' });
    }

    try {
        const db = getDB();

        // Check if user already has a schedule
        const existingSchedule = await new Promise((resolve, reject) => {
            db.get(
                `SELECT id FROM schedules WHERE user_id = ?`,
                [user_id],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        let result;
        if (existingSchedule) {
            // Update existing schedule
            await new Promise((resolve, reject) => {
                db.run(
                    `UPDATE schedules SET days = ?, hours = ?, created_at = CURRENT_TIMESTAMP 
                     WHERE user_id = ?`,
                    [days, hours, user_id],
                    (err) => {
                        if (err) reject(err);
                        resolve();
                    }
                );
            });
            result = { id: existingSchedule.id };
        } else {
            // Create new schedule
            result = await new Promise((resolve, reject) => {
                db.run(
                    `INSERT INTO schedules (user_id, days, hours) VALUES (?, ?, ?)`,
                    [user_id, days, hours],
                    function (err) {
                        if (err) reject(err);
                        resolve({ id: this.lastID });
                    }
                );
            });
        }

        // Fetch the updated/inserted schedule
        const schedule = await new Promise((resolve, reject) => {
            db.get(
                `SELECT s.id, s.days, s.hours, u.full_name 
                 FROM schedules s 
                 JOIN users u ON s.user_id = u.id 
                 WHERE s.id = ?`,
                [result.id],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row);
                }
            );
        });

        console.log(`Schedule updated/created: ID ${schedule.id}, User ${schedule.full_name}`);
        res.status(201).json(schedule);
    } catch (err) {
        console.error('Error saving schedule:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete user's schedule (dentist or staff)
app.delete('/api/schedules/:id', restrictToAny('dentist', 'staff'), async (req, res) => {
    const { id } = req.params;
    const user_id = req.user.id;

    try {
        await new Promise((resolve, reject) => {
            db.run(
                `DELETE FROM schedules WHERE id = ? AND user_id = ?`,
                [id, user_id],
                function (err) {
                    if (err) reject(err);
                    if (this.changes === 0) reject(new Error('Schedule not found or unauthorized'));
                    resolve();
                }
            );
        });

        console.log(`Schedule deleted: ID ${id}`);
        res.status(204).send();
    } catch (err) {
        console.error('Error deleting schedule:', err.message);
        res.status(err.message === 'Schedule not found or unauthorized' ? 404 : 500)
            .json({ error: err.message });
    }
});