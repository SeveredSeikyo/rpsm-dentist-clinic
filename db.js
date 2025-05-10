const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'dental.db');
let db = null;

const connectAndSetup = async () => {
    try {
        const newDb = await new Promise((resolve, reject) => {
            const database = new sqlite3.Database(dbPath, (err) => {
                if (err) {
                    console.error('Error opening database:', err.message);
                    reject(err);
                } else {
                    console.log('Connected to the SQLite database.');
                    resolve(database);
                }
            });
        });

        await new Promise((resolve, reject) => {
            newDb.serialize(() => {
                newDb.run(`
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        full_name TEXT NOT NULL,
                        dob DATE NOT NULL,
                        phone TEXT NOT NULL,
                        userType TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        CHECK (email LIKE '%.com')
                    )`, logOrReject('users', reject));

                newDb.run(`
                    CREATE TABLE IF NOT EXISTS appointments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        date DATE NOT NULL,
                        time TEXT NOT NULL,
                        procedure TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )`, logOrReject('appointments', reject));

                newDb.run(`
                    CREATE TABLE IF NOT EXISTS billings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        patient_id INTEGER NOT NULL,
                        staff_id INTEGER,
                        appointment_id INTEGER,
                        amount REAL NOT NULL,
                        payment_method TEXT NOT NULL CHECK(payment_method IN ('cash', 'gcash')),
                        date DATE DEFAULT CURRENT_DATE,
                        FOREIGN KEY (patient_id) REFERENCES users(id),
                        FOREIGN KEY (staff_id) REFERENCES users(id),
                        FOREIGN KEY (appointment_id) REFERENCES appointments(id)
                    )`, logOrReject('billings', reject));

                newDb.run(`
                    CREATE TABLE IF NOT EXISTS reminders (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        patient_id INTEGER NOT NULL,
                        email TEXT NOT NULL,
                        message TEXT NOT NULL,
                        remind_at DATETIME NOT NULL,
                        sent INTEGER DEFAULT 0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (patient_id) REFERENCES users(id)
                    )`, logOrReject('reminders', reject));

                newDb.run(`
                    CREATE TABLE IF NOT EXISTS feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                        comment TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )`, logOrReject('feedback', reject));

                newDb.run(`
                    CREATE TABLE IF NOT EXISTS schedules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        days TEXT NOT NULL,
                        hours TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )`, logOrReject('schedules', reject));

                newDb.run(`
                  CREATE TABLE IF NOT EXISTS reset_tokens (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL,
                  token TEXT NOT NULL,
                  expires_at DATETIME NOT NULL
                )`, logOrReject('reset_tokens',reject));

                console.log('All tables created or already exist.');
                resolve();
            });
        });

        db = newDb;
        return db;
    } catch (error) {
        console.error('Failed to connect or setup database', error);
        process.exit(1);
    }
};

// Helper to log or reject
function logOrReject(name, rejectFn) {
    return (err) => {
        if (err) {
            console.error(`Error creating ${name} table:`, err.message);
            rejectFn(err);
        } else {
            console.log(`${name.charAt(0).toUpperCase() + name.slice(1)} table ready.`);
        }
    };
}

function getDB() {
    if (!db) {
        throw new Error("Database not initialized");
    }
    return db;
}

module.exports = {
    connectAndSetup,
    getDB
};
