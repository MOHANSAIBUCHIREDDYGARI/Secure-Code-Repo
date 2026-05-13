import sqlite3
from tabulate import tabulate

def check_database():
    conn = sqlite3.connect('secure_repo_v2.db')
    cursor = conn.cursor()
    
    print("\n" + "="*80)
    print("DATABASE INSPECTION TOOL")
    print("="*80)
    
    # 1. Check Users
    print("\n USERS TABLE:")
    try:
        cursor.execute("SELECT user_id, username, email, created_at, public_key, encrypted_private_key FROM users")
        rows = cursor.fetchall()
        
        display_data = []
        for row in rows:
            uid, uname, email, created, pub, priv = row
            has_pub = "YES" if pub else "NO"
            has_priv = "YES" if priv else "NO"
            display_data.append([uid, uname, email, created, has_pub,has_priv])
            
        if display_data:
            print(tabulate(display_data, headers=['ID', 'Username', 'Email', 'Created', 'Pub Key', 'Priv Key'], tablefmt='grid'))
        else:
            print("No users found.")
    except Exception as e:
        print(f"Error querying users: {e}")
        # Fallback for old schema
        cursor.execute("SELECT user_id, username, email, created_at FROM users")
        users = cursor.fetchall()
        if users:
            print(tabulate(users, headers=['ID', 'Username', 'Email', 'Created'], tablefmt='grid'))
    
    # 2. Check Password Hashing
    print("\n PASSWORD HASHING (First 20 chars):")
    cursor.execute("SELECT username, substr(password_hash, 1, 20) as hash_preview, substr(salt, 1, 20) as salt_preview FROM users")
    passwords = cursor.fetchall()
    if passwords:
        print(tabulate(passwords, headers=['Username', 'Hash Preview', 'Salt Preview'], tablefmt='grid'))
    
    # 3. Check Repositories
    print("\n REPOSITORIES TABLE:")
    cursor.execute("""
        SELECT r.repo_id, r.repo_name, u.username as owner, r.description 
        FROM repositories r
        JOIN users u ON r.owner_id = u.user_id
    """)
    repos = cursor.fetchall()
    if repos:
        print(tabulate(repos, headers=['Repo ID', 'Name', 'Owner', 'Description'], tablefmt='grid'))
    else:
        print("No repositories found.")
    
    # 4. Check Access Control (ACL)
    print("\n ACCESS CONTROL LIST:")
    cursor.execute("""
        SELECT u.username, r.repo_name, ac.role, ac.can_read, ac.can_write, ac.can_delete
        FROM access_control ac
        JOIN users u ON ac.user_id = u.user_id
        JOIN repositories r ON ac.repo_id = r.repo_id
    """)
    acl = cursor.fetchall()
    if acl:
        print(tabulate(acl, headers=['User', 'Repository', 'Role', 'Read', 'Write', 'Delete'], tablefmt='grid'))
    else:
        print("No access control entries found.")
    
    # 5. Check Files
    print("\n FILES TABLE:")
    cursor.execute("""
        SELECT f.file_id, f.file_name, r.repo_name, 
               substr(f.file_hash, 1, 16) as hash_preview,
               substr(f.digital_signature, 1, 20) as sig_preview,
               u.username as uploaded_by
        FROM files f
        JOIN repositories r ON f.repo_id = r.repo_id
        JOIN users u ON f.uploaded_by = u.user_id
    """)
    files = cursor.fetchall()
    if files:
        print(tabulate(files, headers=['File ID', 'Filename', 'Repository', 'Hash', 'Signature', 'Uploaded By'], tablefmt='grid'))
    else:
        print("No files found.")
    
    # 6. Check OTP Codes
    print("\n OTP CODES (Last 5):")
    cursor.execute("""
        SELECT u.username, o.otp_code, o.is_used, o.created_at, o.expires_at
        FROM otp_codes o
        JOIN users u ON o.user_id = u.user_id
        ORDER BY o.created_at DESC
        LIMIT 5
    """)
    otps = cursor.fetchall()
    if otps:
        print(tabulate(otps, headers=['User', 'OTP', 'Used', 'Created', 'Expires'], tablefmt='grid'))
    else:
        print("No OTP codes found.")
    
    # 7. Check Commits
    print("\n COMMITS (Version Control):")
    cursor.execute("""
        SELECT u.username, r.repo_name, c.commit_message, 
               substr(c.commit_hash, 1, 16) as hash_preview, c.created_at
        FROM commits c
        JOIN users u ON c.user_id = u.user_id
        JOIN repositories r ON c.repo_id = r.repo_id
        ORDER BY c.created_at DESC
        LIMIT 10
    """)
    commits = cursor.fetchall()
    if commits:
        print(tabulate(commits, headers=['User', 'Repository', 'Message', 'Hash', 'Date'], tablefmt='grid'))
    else:
        print("No commits found.")
    
    
    # 8. Check Repo Keys
    print("\n REPO A Keys (Encrypted AES Keys):")
    cursor.execute("""
        SELECT r.repo_name, u.username, substr(rk.encrypted_key, 1, 20) as key_preview, rk.assigned_at
        FROM repo_keys rk
        JOIN repositories r ON rk.repo_id = r.repo_id
        JOIN users u ON rk.user_id = u.user_id
    """)
    keys = cursor.fetchall()
    if keys:
        print(tabulate(keys, headers=['Repository', 'User', 'Encrypted Key Preview', 'Assigned At'], tablefmt='grid'))
    else:
        print("No repo keys found.")
    
    # 9. Database Statistics
    print("\n DATABASE STATISTICS:")
    stats = []
    
    cursor.execute("SELECT COUNT(*) FROM users")
    stats.append(['Total Users', cursor.fetchone()[0]])
    
    cursor.execute("SELECT COUNT(*) FROM repositories")
    stats.append(['Total Repositories', cursor.fetchone()[0]])
    
    cursor.execute("SELECT COUNT(*) FROM files")
    stats.append(['Total Files', cursor.fetchone()[0]])
    
    cursor.execute("SELECT COUNT(*) FROM access_control")
    stats.append(['Access Control Entries', cursor.fetchone()[0]])
    
    # cursor.execute("SELECT COUNT(*) FROM commits")
    # stats.append(['Total Commits', cursor.fetchone()[0]])
    
    print(tabulate(stats, headers=['Metric', 'Count'], tablefmt='grid'))
    
    conn.close()
    print("\n" + "="*80)

if __name__ == '__main__':
    # Install tabulate if needed: pip install tabulate
    try:
        check_database()
    except Exception as e:
        print(f"Error: {e}")
        print("\nIf you see 'No module named tabulate', run: pip install tabulate")