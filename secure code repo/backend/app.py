from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, make_response
import sqlite3
from datetime import datetime
import os
from cryptography.hazmat.primitives import serialization

from auth import AuthManager
from access_control import AccessControl
from crypto_utils import CryptoUtils
from hash_utils import HashUtils
from encoding_utils import EncodingUtils

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.urandom(24)

# Global cache for decrypted active user private keys
# Format: {user_id: private_key_object}
# Note: In production, use Redis or Session-based secure storage
user_keys = {}

# Database connection
def get_db_path():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, 'secure_repo_v2.db')

def get_db():
    db = sqlite3.connect(get_db_path())
    return db

# Initialize database
def init_db():
    db = get_db()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    schema_path = os.path.join(base_dir, '..', 'database', 'schema.sql')
    
    with open(schema_path, 'r') as f:
        db.executescript(f.read())
    db.commit()
    db.close()

# --- AUTHENTICATION ROUTES ---

@app.route('/')
def index():
    if 'user_id' in session:
        # Check if there's a pending repo redirect from QR code
        if 'pending_repo_id' in session:
            repo_id = session.pop('pending_repo_id')
            return redirect(url_for('view_repository', repo_id=repo_id))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        db = get_db()
        auth = AuthManager(db)
        
        success, message = auth.register_user(username, email, password)
        db.close()
        
        if success:
            flash(message, 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        auth = AuthManager(db)
        
        success, user_id, email = auth.authenticate_user(username, password)
        
        if success:
            # Generate OTP for 2FA
            otp, email_sent, message = auth.generate_otp(user_id, email)
            
            # Store temp session data
            session['temp_user_id'] = user_id
            session['temp_username'] = username
            
            # --- KEY CACHING START ---
            # Retrieve encrypted private key from DB
            cursor = db.cursor()
            cursor.execute("SELECT encrypted_private_key FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            if row and row[0]:
                enc_priv_key = row[0]
                # Decrypt using the password the user just provided
                try:
                    priv_key_obj = HashUtils.decrypt_private_key(enc_priv_key, password)
                    if priv_key_obj:
                        user_keys[user_id] = priv_key_obj
                        print(f"DEBUG: Cached private key for user {user_id}")
                except Exception as e:
                    print(f"DEBUG: Failed to decrypt private key: {e}")
            # --- KEY CACHING END ---
            
            if email_sent:
                flash(f'OTP sent to {email}', 'success')
            else:
                # Show OTP if email failed (for demo)
                flash(message, 'info')
            
            db.close()
            return redirect(url_for('verify_otp'))
        else:
            flash(email, 'error')  # email variable contains error message
            db.close()
    
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form['otp']
        user_id = session['temp_user_id']
        
        db = get_db()
        auth = AuthManager(db)
        
        success, message = auth.verify_otp(user_id, otp)
        db.close()
        
        if success:
            # Complete login
            session['user_id'] = session.pop('temp_user_id')
            session['username'] = session.pop('temp_username')
            flash('Login successful!', 'success')
            
            # Check if there's a pending repo redirect from QR code
            if 'pending_repo_id' in session:
                repo_id = session.pop('pending_repo_id')
                return redirect(url_for('view_repository', repo_id=repo_id))
            
            return redirect(url_for('dashboard'))
        else:
            flash(message, 'error')
    
    return render_template('verify_otp.html')

@app.route('/resend-otp')
def resend_otp():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['temp_user_id']
    username = session.get('temp_username')
    
    db = get_db()
    
    # Get email
    cursor = db.cursor()
    cursor.execute("SELECT email FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    
    if result:
        email = result[0]
        auth = AuthManager(db)
        otp, email_sent, message = auth.generate_otp(user_id, email)
        
        if email_sent:
            flash(f'New OTP sent to {email}', 'success')
        else:
            flash(message, 'info')
    else:
        flash('User not found', 'error')
        
    db.close()
    return redirect(url_for('verify_otp'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- REPOSITORY ROUTES ---

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    acl = AccessControl(db)
    
    repos = acl.list_user_repositories(session['user_id'])
    db.close()
    
    return render_template('dashboard.html', repositories=repos, username=session['username'])

@app.route('/create-repository', methods=['POST'])
def create_repository():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    repo_name = request.form['repo_name']
    description = request.form.get('description', '')
    
    db = get_db()
    cursor = db.cursor()
    
    # Create repository
    cursor.execute("""
        INSERT INTO repositories (repo_name, owner_id, description)
        VALUES (?, ?, ?)
    """, (repo_name, session['user_id'], description))
    
    repo_id = cursor.lastrowid
    
    # 1. Generate Repo Key (AES)
    repo_aes_key = CryptoUtils.generate_aes_key()
    
    # 2. Encrypt Repo Key with Owner's Public Key
    cursor.execute("SELECT public_key FROM users WHERE user_id = ?", (session['user_id'],))
    owner_pub_key = cursor.fetchone()[0]
    
    encrypted_repo_key = CryptoUtils.encrypt_repo_key(repo_aes_key, owner_pub_key)
    
    # 3. Store in repo_keys
    cursor.execute("""
        INSERT INTO repo_keys (repo_id, user_id, encrypted_key)
        VALUES (?, ?, ?)
    """, (repo_id, session['user_id'], encrypted_repo_key))
    
    # Generate QR code for sharing
    qr_data = f"http://localhost:5000/repo/{repo_id}"
    qr_code = EncodingUtils.generate_qr_code(qr_data)
    
    cursor.execute("UPDATE repositories SET qr_code = ? WHERE repo_id = ?", 
                   (qr_code, repo_id))
    
    # Grant owner access
    acl = AccessControl(db)
    acl.grant_access(session['user_id'], repo_id, 'Owner')
    
    db.commit()
    db.close()
    
    # CACHE THE KEY FOR IMMEDIATE USE
    # Format: repo_keys_cache[repo_id] = aes_key_bytes
    # Note: Global cache might need per-user context if we want strictness, 
    # but since it's "Repo Key", it's the SAME key for everyone.
    # However, we only cache it if the current user has unlocked it.
    
    flash(f'Repository "{repo_name}" created successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete-repository/<int:repo_id>', methods=['POST'])
def delete_repository(repo_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    acl = AccessControl(db)
    
    # Check if user is owner
    role = acl.get_user_role(session['user_id'], repo_id)
    if role != 'Owner':
        flash('Only the owner can delete this repository', 'error')
        db.close()
        return redirect(url_for('view_repository', repo_id=repo_id))
    
    cursor = db.cursor()
    
    try:
        # Cascading delete manually since SQLite might not have it enforced
        
        # 1. Delete files
        cursor.execute("DELETE FROM files WHERE repo_id = ?", (repo_id,))
        
        # 2. Delete commits
        cursor.execute("DELETE FROM commits WHERE repo_id = ?", (repo_id,))
        
        # 3. Delete access controls
        cursor.execute("DELETE FROM access_control WHERE repo_id = ?", (repo_id,))
        
        # 4. Delete repository
        cursor.execute("DELETE FROM repositories WHERE repo_id = ?", (repo_id,))
        
        db.commit()
        flash('Repository deleted successfully', 'success')
        
    except Exception as e:
        db.rollback()
        flash(f'Error deleting repository: {str(e)}', 'error')
        
    finally:
        db.close()
        
    return redirect(url_for('dashboard'))

@app.route('/repo/<int:repo_id>')
def repo_short_url(repo_id):
    """Handle QR code short URL - redirects to main repository view"""
    if 'user_id' in session:
        # User is already logged in, redirect directly to repository
        return redirect(url_for('view_repository', repo_id=repo_id))
    else:
        # Store the repo_id in session and redirect to login
        session['pending_repo_id'] = repo_id
        return redirect(url_for('login'))

@app.route('/repository/<int:repo_id>')
def view_repository(repo_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    acl = AccessControl(db)
    
    # Check read permission
    if not acl.check_permission(session['user_id'], repo_id, 'can_read'):
        flash('Access denied', 'error')
        db.close()
        return redirect(url_for('dashboard'))
    
    cursor = db.cursor()
    
    # Get repository details
    cursor.execute("""
        SELECT repo_name, description, qr_code, owner_id 
        FROM repositories WHERE repo_id = ?
    """, (repo_id,))
    repo = cursor.fetchone()
    
    # Get files
    cursor.execute("""
        SELECT file_id, file_name, file_hash, uploaded_at
        FROM files WHERE repo_id = ?
    """, (repo_id,))
    files = cursor.fetchall()
    
    # Get user role
    role = acl.get_user_role(session['user_id'], repo_id)
    
    # Check permissions
    can_write = acl.check_permission(session['user_id'], repo_id, 'can_write')
    can_delete = acl.check_permission(session['user_id'], repo_id, 'can_delete')
    

    
    # Get all users with access (only for owner)
    repo_users = []
    if role == 'Owner':
        repo_users = acl.get_repo_users(repo_id)
    
    db.close()
    
    return render_template('repository.html', 
                         repo_id=repo_id,
                         repo_name=repo[0],
                         description=repo[1],
                         qr_code=repo[2],
                         files=files,
                         role=role,
                         can_write=can_write,
                         can_delete=can_delete,
                         repo_users=repo_users)


@app.route('/upload-file/<int:repo_id>', methods=['POST'])
def upload_file(repo_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    acl = AccessControl(db)
    
    # Check write permission
    if not acl.check_permission(session['user_id'], repo_id, 'can_write'):
        flash('You do not have permission to upload files', 'error')
        db.close()
        return redirect(url_for('view_repository', repo_id=repo_id))
    
    file_name = request.form['file_name']
    file_content = request.form['file_content']
    
    # 1. GET REPO KEY
    # We must retrieve the repo key for this user
    cursor = db.cursor()
    cursor.execute("SELECT encrypted_key FROM repo_keys WHERE repo_id = ? AND user_id = ?", 
                  (repo_id, session['user_id']))
    row = cursor.fetchone()
    
    if not row:
        flash('Error: You do not have the encryption key for this repository.', 'error')
        return redirect(url_for('view_repository', repo_id=repo_id))
        
    enc_repo_key = row[0]
    
    # Unlock Repo Key using User's Private Key
    user_priv_key = user_keys.get(session['user_id'])
    if not user_priv_key:
        flash('Session expired. Please relogin.', 'error')
        return redirect(url_for('login'))
        
    repo_aes_key = CryptoUtils.decrypt_repo_key(enc_repo_key, user_priv_key)
    
    # 2. ENCRYPT FILE WITH REPO KEY
    # Format: REPO_LOCKED|IV+Ciphertext
    encrypted_data = CryptoUtils.encrypt_with_repo_key(file_content, repo_aes_key)
    # We store a marker to know it's a Repo-Key file
    final_encrypted_content = f"REPO_LOCKED|{encrypted_data}"
    
    # 3. Create digital signature (Identity)
    signature = "UNSIGNED_NO_KEY"
    if user_priv_key:
        priv_pem_str = user_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        signature = HashUtils.create_digital_signature(file_content, priv_pem_str)

    
    # Generate file hash for integrity
    file_hash = HashUtils.hash_file_content(file_content)
    
    # Store in database
    cursor.execute("""
        INSERT INTO files 
        (repo_id, file_name, encrypted_content, file_hash, digital_signature, uploaded_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (repo_id, file_name, final_encrypted_content, 
          file_hash, signature, session['user_id']))
    
    # Create commit for version control
    commit_hash = HashUtils.generate_commit_hash(
        repo_id, session['user_id'], f"Added {file_name}", datetime.now()
    )
    
    cursor.execute("""
        INSERT INTO commits (repo_id, user_id, commit_message, commit_hash)
        VALUES (?, ?, ?, ?)
    """, (repo_id, session['user_id'], f"Added {file_name}", commit_hash))
    
    db.commit()
    db.close()
    
    flash(f'File "{file_name}" uploaded successfully!', 'success')
    return redirect(url_for('view_repository', repo_id=repo_id))

@app.route('/download-file/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Get file details
    cursor.execute("""
        SELECT f.file_name, f.encrypted_content, f.file_hash, 
               f.digital_signature, f.repo_id
        FROM files f
        WHERE f.file_id = ?
    """, (file_id,))
    
    file_data = cursor.fetchone()
    if not file_data:
        flash('File not found', 'error')
        db.close()
        return redirect(url_for('dashboard'))
    
    file_name, encrypted_content, stored_hash, signature, repo_id = file_data
    
    # Check read permission
    acl = AccessControl(db)
    if not acl.check_permission(session['user_id'], repo_id, 'can_read'):
        flash('Access denied', 'error')
        db.close()
        return redirect(url_for('dashboard'))
    
    # Decrypt file
    try:
        user_priv_key = user_keys.get(session['user_id'])
        if not user_priv_key:
            flash('Session expired or key lost. Please toggle Logout/Login.', 'error')
            return redirect(url_for('dashboard'))

        if encrypted_content.startswith("REPO_LOCKED|"):
            # New Repo-Key Decryption
            # 1. Get Repo Key
            cursor = db.cursor()
            cursor.execute("SELECT encrypted_key FROM repo_keys WHERE repo_id = ? AND user_id = ?", 
                          (repo_id, session['user_id']))
            row = cursor.fetchone()
            if not row:
                raise Exception("No Repo Key found for user")
            
            enc_repo_key = row[0]
            repo_aes_key = CryptoUtils.decrypt_repo_key(enc_repo_key, user_priv_key)
            
            # 2. Decrypt Content
            # Format: REPO_LOCKED|EncData
            file_enc_data = encrypted_content.split("|")[1]
            decrypted_content = CryptoUtils.decrypt_with_repo_key(file_enc_data, repo_aes_key)
            
        else:
            # Fallback to Old Hybrid Decryption
            decrypted_content = CryptoUtils.hybrid_decrypt_wrapper(encrypted_content, user_priv_key)
        
        # Verify integrity
        computed_hash = HashUtils.hash_file_content(decrypted_content)
        integrity_check = (computed_hash == stored_hash)
        
        # Verify Signature (IDENTITY CHECK)
        # 1. Fetch Uploader's Public Key
        # We need the uploaded_by user ID from the file record
        cursor = db.cursor()
        cursor.execute("SELECT uploaded_by FROM files WHERE file_id = ?", (file_id,))
        uploader_id = cursor.fetchone()[0]
        
        cursor.execute("SELECT public_key, username FROM users WHERE user_id = ?", (uploader_id,))
        uploader_data = cursor.fetchone()
        
        signature_valid = False
        signer_name = "Unknown"
        
        if uploader_data:
            uploader_pub_key, signer_name = uploader_data
            if uploader_pub_key and signature != "UNSIGNED_NO_KEY":
                signature_valid = HashUtils.verify_digital_signature(
                    decrypted_content, signature, uploader_pub_key
                )
        
        db.close()
        
        return render_template('view_file.html',
                             file_id=file_id,
                             file_name=file_name,
                             content=decrypted_content,
                             integrity_check=integrity_check,
                             signature_valid=signature_valid,
                             signer_name=signer_name,
                             repo_id=repo_id)
                             
    except Exception as e:
        print(f"Decryption error: {e}")
        flash('Failed to decrypt file. You may need to relogin.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
def download_content(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Get file details
    cursor.execute("""
        SELECT f.file_name, f.encrypted_content, f.repo_id
        FROM files f
        WHERE f.file_id = ?
    """, (file_id,))
    
    file_data = cursor.fetchone()
    if not file_data:
        flash('File not found', 'error')
        db.close()
        return redirect(url_for('dashboard'))
    
    file_name, encrypted_content, repo_id = file_data
    
    # Check read permission
    acl = AccessControl(db)
    if not acl.check_permission(session['user_id'], repo_id, 'can_read'):
        flash('Access denied', 'error')
        db.close()
        return redirect(url_for('dashboard'))
    
    # Decrypt file
    try:
        user_priv_key = user_keys.get(session['user_id'])
        if not user_priv_key:
            return redirect(url_for('login')) # Simple redirect for download link
            
        if encrypted_content.startswith("REPO_LOCKED|"):
            # Repo-Key Decryption
            cursor.execute("SELECT encrypted_key FROM repo_keys WHERE repo_id = ? AND user_id = ?", 
                          (repo_id, session['user_id']))
            row = cursor.fetchone()
            if not row:
                raise Exception("No Repo Key found")
            enc_repo_key = row[0]
            repo_aes_key = CryptoUtils.decrypt_repo_key(enc_repo_key, user_priv_key)
            
            file_enc_data = encrypted_content.split("|")[1]
            decrypted_content = CryptoUtils.decrypt_with_repo_key(file_enc_data, repo_aes_key)
        else:
            # Fallback
            decrypted_content = CryptoUtils.hybrid_decrypt_wrapper(encrypted_content, user_priv_key)
            
    except Exception as e:
        print(f"Download Decryption error: {e}")
        flash('Failed to decrypt file. Please relogin.', 'error')
        return redirect(url_for('dashboard'))
    
    db.close()
    
    response = make_response(decrypted_content)
    response.headers['Content-Disposition'] = f'attachment; filename="{file_name}"'
    return response

@app.route('/grant-access/<int:repo_id>', methods=['POST'])
def grant_access_route(repo_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    acl = AccessControl(db)
    
    # Only owner can grant access
    role = acl.get_user_role(session['user_id'], repo_id)
    if role != 'Owner':
        flash('Only owner can grant access', 'error')
        db.close()
        return redirect(url_for('view_repository', repo_id=repo_id))
    
    target_username = request.form['username']
    target_role = request.form['role']
    
    # Get target user ID
    cursor = db.cursor()
    cursor.execute("SELECT user_id FROM users WHERE username = ?", (target_username,))
    target_user = cursor.fetchone()
    
    if not target_user:
        flash('User not found', 'error')
        db.close()
        return redirect(url_for('view_repository', repo_id=repo_id))
    
    success, message = acl.grant_access(target_user[0], repo_id, target_role)
    
    if success:
        # DISTRIBUTE REPO KEY
        # 1. Get Repo Key (Owner deciphers it)
        # We need the Owner's private key from cache
        owner_priv_key = user_keys.get(session['user_id'])
        if owner_priv_key:
            cursor.execute("SELECT encrypted_key FROM repo_keys WHERE repo_id = ? AND user_id = ?", 
                          (repo_id, session['user_id']))
            row = cursor.fetchone()
            if row:
                enc_repo_key = row[0]
                repo_aes_key = CryptoUtils.decrypt_repo_key(enc_repo_key, owner_priv_key)
                
                # 2. Encrypt for Target User
                cursor.execute("SELECT public_key FROM users WHERE user_id = ?", (target_user[0],))
                target_pub_key = cursor.fetchone()[0]
                
                if target_pub_key:
                    new_enc_repo_key = CryptoUtils.encrypt_repo_key(repo_aes_key, target_pub_key)
                    
                    # 3. Store
                    try:
                        cursor.execute("""
                            INSERT INTO repo_keys (repo_id, user_id, encrypted_key)
                            VALUES (?, ?, ?)
                        """, (repo_id, target_user[0], new_enc_repo_key))
                    except:
                        # Maybe already exists, update?
                        pass

    db.commit()
    db.close()
    
    flash(message, 'success' if success else 'error')
    return redirect(url_for('view_repository', repo_id=repo_id))

if __name__ == '__main__':
    @app.route('/edit-file/<int:file_id>', methods=['GET', 'POST'])
    def edit_file(file_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        db = get_db()
        cursor = db.cursor()
        
        # Get file details
        cursor.execute("""
            SELECT f.file_name, f.encrypted_content, f.repo_id
            FROM files f
            WHERE f.file_id = ?
        """, (file_id,))
        
        file_data = cursor.fetchone()
        if not file_data:
            flash('File not found', 'error')
            db.close()
            return redirect(url_for('dashboard'))
        
        file_name, encrypted_content, repo_id = file_data
        
        # Check write permission
        acl = AccessControl(db)
        if not acl.check_permission(session['user_id'], repo_id, 'can_write'):
            flash('You do not have permission to edit this file', 'error')
            db.close()
            return redirect(url_for('view_repository', repo_id=repo_id))
        
        if request.method == 'GET':
            # Decrypt file for editing
            try:
                user_priv_key = user_keys.get(session['user_id'])
                if not user_priv_key:
                    flash('Session expired. Please relogin.', 'error')
                    return redirect(url_for('login'))
                
                if encrypted_content.startswith("REPO_LOCKED|"):
                    # Repo Key Decryption
                    cursor.execute("SELECT encrypted_key FROM repo_keys WHERE repo_id = ? AND user_id = ?", 
                                  (repo_id, session['user_id']))
                    row = cursor.fetchone()
                    if not row:
                        raise Exception("No Repo Key found")
                    enc_repo_key = row[0]
                    repo_aes_key = CryptoUtils.decrypt_repo_key(enc_repo_key, user_priv_key)
                    
                    file_enc_data = encrypted_content.split("|")[1]
                    decrypted_content = CryptoUtils.decrypt_with_repo_key(file_enc_data, repo_aes_key)
                else:
                    # Fallback
                    decrypted_content = CryptoUtils.hybrid_decrypt_wrapper(encrypted_content, user_priv_key)
                
                db.close()
                return render_template('edit_file.html',
                                    file_id=file_id,
                                    file_name=file_name,
                                    content=decrypted_content,
                                    repo_id=repo_id)
            except Exception as e:
                print(f"Edit Decryption error: {e}")
                flash('Failed to decrypt file for editing. Please relogin.', 'error')
                return redirect(url_for('view_repository', repo_id=repo_id))
        
        elif request.method == 'POST':
            # Update file with new content
            new_content = request.form['file_content']
            
            # --- START REPO KEY ENCRYPTION ---
            # 1. Get Repo Key
            # We need the User's Private Key to unlock the Repo Key
            user_priv_key = user_keys.get(session['user_id'])
            if not user_priv_key:
                flash('Session expired. Please relogin.', 'error')
                return redirect(url_for('login'))
                
            cursor.execute("SELECT encrypted_key FROM repo_keys WHERE repo_id = ? AND user_id = ?", 
                          (repo_id, session['user_id']))
            row = cursor.fetchone()
            if not row:
                 # Should we support legacy upgrade here? 
                 # Generating a new repo key on the fly if missing is complex (need to share with everyone).
                 # For now, assume Repo Key exists (new repos) or error.
                 # Actually, old repos won't have keys. We can't easily edit old files into new format 
                 # without creating a key for the repo first.
                 # Let's fail gracefully or fallback to old method?
                 # Creating hybrid key is safer for legacy.
                 # BUT user wants Option B. 
                 # Let's Try Repo Key, if fail, Fallback to Hybrid (but warn).
                 flash('Legacy Repository: Cannot use shared encryption. Falling back to private encryption.', 'warning')
                 # FALLBACK LOGIC HERE? Or just Error?
                 # Let's error for now to enforce migration.
                 flash('Error: Repository keys not initialized. Please create a new repository for collaboration.', 'error')
                 return redirect(url_for('view_repository', repo_id=repo_id))

            enc_repo_key = row[0]
            repo_aes_key = CryptoUtils.decrypt_repo_key(enc_repo_key, user_priv_key)
            
            # 2. Encrypt Content
            encrypted_data = CryptoUtils.encrypt_with_repo_key(new_content, repo_aes_key)
            final_encrypted_content = f"REPO_LOCKED|{encrypted_data}"
            # --- END REPO KEY ENCRYPTION ---
            
            # 3. Create digital signature using CACHED Private Key
            signature = "UNSIGNED_NO_KEY"
            if user_priv_key:
                priv_pem_str = user_priv_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
                signature = HashUtils.create_digital_signature(new_content, priv_pem_str)
            
            # Generate new file hash
            file_hash = HashUtils.hash_file_content(new_content)
            
            # Update in database
            cursor.execute("""
                UPDATE files 
                SET encrypted_content = ?, file_hash = ?, digital_signature = ?, uploaded_by = ?
                WHERE file_id = ?
            """, (final_encrypted_content, 
                file_hash, signature, session['user_id'], file_id))
            
            # Create commit for version control
            commit_hash = HashUtils.generate_commit_hash(
                repo_id, session['user_id'], f"Updated {file_name}", datetime.now()
            )
            
            cursor.execute("""
                INSERT INTO commits (repo_id, user_id, commit_message, commit_hash)
                VALUES (?, ?, ?, ?)
            """, (repo_id, session['user_id'], f"Updated {file_name}", commit_hash))
            
            db.commit()
            db.close()
            
            flash(f'File "{file_name}" updated successfully!', 'success')
            return redirect(url_for('view_repository', repo_id=repo_id))
    @app.route('/delete-file/<int:file_id>', methods=['POST'])
    def delete_file(file_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        db = get_db()
        cursor = db.cursor()
        
        # Get file details
        cursor.execute("""
            SELECT file_name, repo_id FROM files WHERE file_id = ?
        """, (file_id,))
        
        file_data = cursor.fetchone()
        if not file_data:
            flash('File not found', 'error')
            db.close()
            return redirect(url_for('dashboard'))
        
        file_name, repo_id = file_data
        
        # Check delete permission
        acl = AccessControl(db)
        if not acl.check_permission(session['user_id'], repo_id, 'can_delete'):
            flash('You do not have permission to delete this file', 'error')
            db.close()
            return redirect(url_for('view_repository', repo_id=repo_id))
        
        # Delete file
        cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
        
        # Create commit for version control
        commit_hash = HashUtils.generate_commit_hash(
            repo_id, session['user_id'], f"Deleted {file_name}", datetime.now()
        )
        
        cursor.execute("""
            INSERT INTO commits (repo_id, user_id, commit_message, commit_hash)
            VALUES (?, ?, ?, ?)
        """, (repo_id, session['user_id'], f"Deleted {file_name}", commit_hash))
        
        db.commit()
        db.close()
        
        flash(f'File "{file_name}" deleted successfully!', 'success')
        return redirect(url_for('view_repository', repo_id=repo_id))
    # Check if database needs initialization
    db_path = get_db_path()
    needs_init = False
    
    if not os.path.exists(db_path):
        needs_init = True
    else:
        # Check if tables exist
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
            if not cursor.fetchone():
                needs_init = True
            conn.close()
        except:
            needs_init = True
            
    if needs_init:
        print("Initializing database...")
        try:
            init_db()
            print("Database initialized.")
        except Exception as e:
            print(f"Error initializing database: {e}")

    app.run(debug=True, port=5000)