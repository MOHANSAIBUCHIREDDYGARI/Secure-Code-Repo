import sqlite3

def inspect_keys():
    try:
        conn = sqlite3.connect('secure_repo_v2.db')
        cursor = conn.cursor()
        
        print(f"{'Repository':<20} | {'User':<15} | {'Encrypted Key Preview':<25} | {'Assigned At':<20}")
        print("-" * 85)
        
        cursor.execute("""
            SELECT r.repo_name, u.username, substr(rk.encrypted_key, 1, 20), rk.assigned_at
            FROM repo_keys rk
            JOIN repositories r ON rk.repo_id = r.repo_id
            JOIN users u ON rk.user_id = u.user_id
        """)
        
        rows = cursor.fetchall()
        if not rows:
            print("No keys found.")
            
        for row in rows:
            rname, uname, key_prev, assigned = row
            key_str = f"{key_prev}..." if key_prev else "N/A"
            print(f"{rname:<20} | {uname:<15} | {key_str:<25} | {assigned:<20}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    inspect_keys()
