import sqlite3
import os

def migrate_db():
    db_path = 'secure_repo_v2.db'
    if not os.path.exists(db_path):
        print(f"Database {db_path} not found.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if columns exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'failed_login_attempts' not in columns:
            print("Adding failed_login_attempts column...")
            cursor.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
            
        if 'lockout_until' not in columns:
            print("Adding lockout_until column...")
            cursor.execute("ALTER TABLE users ADD COLUMN lockout_until TIMESTAMP")

        if 'public_key' not in columns:
            print("Adding public_key column...")
            cursor.execute("ALTER TABLE users ADD COLUMN public_key TEXT")
            
        if 'encrypted_private_key' not in columns:
            print("Adding encrypted_private_key column...")
            cursor.execute("ALTER TABLE users ADD COLUMN encrypted_private_key TEXT")
            
        # Check for repo_keys table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='repo_keys'")
        if not cursor.fetchone():
            print("Creating repo_keys table...")
            cursor.execute("""
                CREATE TABLE repo_keys (
                    key_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    encrypted_key TEXT NOT NULL,
                    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (repo_id) REFERENCES repositories(repo_id),
                    FOREIGN KEY (user_id) REFERENCES users(user_id),
                    UNIQUE(repo_id, user_id)
                )
            """)
            
        conn.commit()
        print("Migration completed successfully.")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_db()
