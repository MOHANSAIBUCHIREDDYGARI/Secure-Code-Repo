
import sqlite3
import os
from auth import AuthManager
from hash_utils import HashUtils
from datetime import datetime

DB_PATH = 'secure_repo_v2.db'

def setup_db_mock_if_needed():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if users table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not cursor.fetchone():
        print("Initializing DB from schema...")
        schema_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'schema.sql')
        with open(schema_path, 'r') as f:
            schema = f.read()
        cursor.executescript(schema)
        # Re-connect to ensure changes are visible/committed properly if needed
        conn.commit()
    
    # Check for columns (Double check after init or if existing)
    cursor.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in cursor.fetchall()]
    
    if 'public_key' not in columns:
        print("Migrating: Adding public_key...")
        cursor.execute("ALTER TABLE users ADD COLUMN public_key TEXT")
        
    if 'encrypted_private_key' not in columns:
        print("Migrating: Adding encrypted_private_key...")
        cursor.execute("ALTER TABLE users ADD COLUMN encrypted_private_key TEXT")
    
    conn.commit()
    conn.close()

def test_pki():
    print(f"Testing PKI on {DB_PATH}")
    setup_db_mock_if_needed()
    
    conn = sqlite3.connect(DB_PATH)
    auth = AuthManager(conn)
    
    # Test User
    username = f"testpki_{int(datetime.now().timestamp())}"
    email = f"{username}@example.com"
    password = "TestPassword123!"
    
    print(f"Registering user: {username}")
    success, msg = auth.register_user(username, email, password)
    
    if not success:
        print(f"Registration Failed: {msg}")
        return
        
    print("Registration Successful.")
    
    # Verify DB content
    cursor = conn.cursor()
    cursor.execute("SELECT public_key, encrypted_private_key FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    
    if not row:
        print("User not found in DB!")
        return
        
    pub_key, enc_priv_key = row
    
    if not pub_key or not enc_priv_key:
        print("KEYS ARE MISSING!")
        print(f"Public: {pub_key is not None}")
        print(f"Private: {enc_priv_key is not None}")
        return
        
    print("Keys found in DB.")
    print("Public Key starts with:", pub_key[:30])
    
    # Verify Decryption
    print("Attempting to decrypt private key with correct password...")
    priv_key_obj = HashUtils.decrypt_private_key(enc_priv_key, password)
    
    if priv_key_obj:
        print("SUCCESS: Private key decrypted.")
    else:
        print("FAILURE: Could not decrypt private key.")
        
    conn.close()

if __name__ == "__main__":
    test_pki()
