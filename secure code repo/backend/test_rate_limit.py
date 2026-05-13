import sqlite3
import os
from auth import AuthManager
from hash_utils import HashUtils
from datetime import datetime, timedelta

def setup_test_db():
    if os.path.exists("test_secure_repo.db"):
        os.remove("test_secure_repo.db")
    
    conn = sqlite3.connect("test_secure_repo.db")
    cursor = conn.cursor()
    
    # Create minimal users table for testing
    cursor.execute("""
        CREATE TABLE users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            salt VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            failed_login_attempts INTEGER DEFAULT 0,
            lockout_until TIMESTAMP
        )
    """)
    
    # Create test user
    salt = HashUtils.generate_salt()
    password_hash = HashUtils.hash_password("Password123!", salt)
    
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, salt)
        VALUES (?, ?, ?, ?)
    """, ("testuser", "test@example.com", password_hash, salt))
    
    conn.commit()
    return conn

def test_rate_limiting():
    print("Setting up test database...")
    conn = setup_test_db()
    auth = AuthManager(conn)
    
    username = "testuser"
    
    print("\n--- Test 1: Successful Login ---")
    success, _, _ = auth.authenticate_user(username, "Password123!")
    if success:
        print("PASS: Login successful with correct password")
    else:
        print("FAIL: Login failed with correct password")

    print("\n--- Test 2: Failed Attempts Increment ---")
    for i in range(1, 6):
        success, _, msg = auth.authenticate_user(username, "WrongPass")
        print(f"Attempt {i}: {msg}")
        
        cursor = conn.cursor()
        cursor.execute("SELECT failed_login_attempts FROM users WHERE username = ?", (username,))
        attempts = cursor.fetchone()[0]
        
        if i < 5:
            if not success and attempts == i and "attempts remaining" in msg:
                print(f"PASS: Attempt {i} correctly incremented counter")
            else:
                print(f"FAIL: Attempt {i} unexpected state")
        else:
            if not success and attempts == 5 and "Account locked" in msg:
                print("PASS: 5th attempt triggered lockout")
            else:
                print("FAIL: 5th attempt did not trigger lockout")

    print("\n--- Test 3: Login During Lockout ---")
    # Even with correct password
    success, _, msg = auth.authenticate_user(username, "Password123!")
    if not success and "Account locked" in msg:
        print("PASS: Login blocked during lockout period")
    else:
        print(f"FAIL: Login allowed during lockout? Msg: {msg}")

    print("\n--- Test 4: Lockout Expiry ---")
    # Manually expire the lockout
    print("Simulating time passing (resetting lockout_until in DB to past)...")
    past_time = datetime.now() - timedelta(minutes=1)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET lockout_until = ? WHERE username = ?", (past_time, username))
    conn.commit()
    
    success, _, _ = auth.authenticate_user(username, "Password123!")
    if success:
        print("PASS: Login successful after lockout expiry")
        
        # Check counters reset
        cursor.execute("SELECT failed_login_attempts, lockout_until FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row[0] == 0 and row[1] is None:
            print("PASS: Counters reset after successful login")
        else:
            print(f"FAIL: Counters not reset. Attempts: {row[0]}, Lockout: {row[1]}")
    else:
        print("FAIL: Login failed after lockout expiry")

    conn.close()
    if os.path.exists("test_secure_repo.db"):
        os.remove("test_secure_repo.db")

if __name__ == "__main__":
    test_rate_limiting()
