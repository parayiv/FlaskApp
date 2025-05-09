-- schema.sql
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0 -- 0 for False, 1 for True
);

-- We'll also need a messages table later
DROP TABLE IF EXISTS messages;
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER, -- Can be NULL if it's a general message to all admins
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (sender_id) REFERENCES users (id)
    -- FOREIGN KEY (recipient_id) REFERENCES users (id) -- if direct to specific admin
);

-- Optional: For payslip/vacation requests if not using general messages
DROP TABLE IF EXISTS requests;
CREATE TABLE requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    request_type TEXT NOT NULL, -- 'payslip', 'vacation'
    details TEXT, -- e.g., month for payslip, dates for vacation
    status TEXT NOT NULL DEFAULT 'pending', -- pending, approved, rejected
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    admin_notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);