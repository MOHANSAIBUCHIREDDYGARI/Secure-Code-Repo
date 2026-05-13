-- Users table
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    public_key TEXT,
    encrypted_private_key TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    lockout_until TIMESTAMP
);

-- OTP table for 2FA
CREATE TABLE otp_codes (
    otp_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Repositories table
CREATE TABLE repositories (
    repo_id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_name VARCHAR(100) NOT NULL,
    owner_id INTEGER NOT NULL,
    description TEXT,
    qr_code TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(user_id)
);

-- Files table (encrypted files)
CREATE TABLE files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    encrypted_content TEXT NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    digital_signature TEXT,
    uploaded_by INTEGER NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (repo_id) REFERENCES repositories(repo_id),
    FOREIGN KEY (uploaded_by) REFERENCES users(user_id)
);

-- Access Control List (ACL)
CREATE TABLE access_control (
    acl_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    repo_id INTEGER NOT NULL,
    role VARCHAR(20) NOT NULL CHECK(role IN ('Owner', 'Collaborator', 'Viewer')),
    can_read BOOLEAN DEFAULT 1,
    can_write BOOLEAN DEFAULT 0,
    can_delete BOOLEAN DEFAULT 0,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (repo_id) REFERENCES repositories(repo_id),
    UNIQUE(user_id, repo_id)
);

-- Commit logs for integrity
CREATE TABLE commits (
    commit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    commit_message TEXT,
    commit_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (repo_id) REFERENCES repositories(repo_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Repository Keys (Encrypted per user)
CREATE TABLE repo_keys (
    key_id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    encrypted_key TEXT NOT NULL, -- The Repo AES Key encrypted with User Public Key
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (repo_id) REFERENCES repositories(repo_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    UNIQUE(repo_id, user_id)
);