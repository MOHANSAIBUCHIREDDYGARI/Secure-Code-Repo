from flask import session
import random
import string
from datetime import datetime, timedelta
from hash_utils import HashUtils
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AuthManager:
    """Authentication Manager - Single Factor + Multi-Factor"""
    
    def __init__(self, db):
        self.db = db
        
        # Email configuration
        self.EMAIL_HOST = "smtp.gmail.com"
        self.EMAIL_PORT = 587
        self.EMAIL_ADDRESS = "mohansai1810@gmail.com"
        self.EMAIL_PASSWORD = "bbbzxjmusjipxvis"
    
    def send_email_otp(self, to_email, otp):
        """Send OTP via email"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.EMAIL_ADDRESS
            msg['To'] = to_email
            msg['Subject'] = "Your OTP Code - Secure Code Repository"
            
            # Email body
            body = f"""
            <html>
                <body style="font-family: Arial, sans-serif;">
                    <div style="background: #667eea; padding: 20px; text-align: center;">
                        <h2 style="color: white;">Secure Code Repository</h2>
                    </div>
                    <div style="padding: 20px;">
                        <h3>Your OTP Code</h3>
                        <p>Use this code to complete your login:</p>
                        <div style="background: #f0f0f0; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px;">
                            {otp}
                        </div>
                        <p style="color: #666; margin-top: 20px;">
                            This code will expire in 5 minutes.<br>
                            If you didn't request this, please ignore this email.
                        </p>
                    </div>
                </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(self.EMAIL_HOST, self.EMAIL_PORT)
            server.starttls()
            server.login(self.EMAIL_ADDRESS, self.EMAIL_PASSWORD)
            server.send_message(msg)
            server.quit()
            
            return True, "OTP sent successfully"
            
        except Exception as e:
            print(f"Email error: {str(e)}")
            # Fallback: Show OTP in console
            print("\n" + "="*60)
            print(f" EMAIL FAILED - SHOWING OTP IN CONSOLE")
            print(f"To: {to_email}")
            print(f"OTP: {otp}")
            print("="*60 + "\n")
            return False, f"Email failed, OTP: {otp}"
    
    def validate_password(self, password):
        """Validate password complexity requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in password)
        
        if not has_upper:
            return False, "Password must contain at least one uppercase letter"
        if not has_lower:
            return False, "Password must contain at least one lowercase letter"
        if not has_digit:
            return False, "Password must contain at least one digit"
        if not has_special:
            return False, "Password must contain at least one special character"
        
        return True, "Password is valid"
    
    def register_user(self, username, email, password):
        """Register new user with hashed password + salt"""
        cursor = self.db.cursor()
        
        # Validate password complexity
        is_valid, message = self.validate_password(password)
        if not is_valid:
            return False, message
        
        # Check if user exists
        cursor.execute("SELECT user_id FROM users WHERE username = ? OR email = ?", 
                      (username, email))
        if cursor.fetchone():
            return False, "User already exists"
        
        # Generate salt and hash password
        salt = HashUtils.generate_salt()
        password_hash = HashUtils.hash_password(password, salt)
        
        # Generate RSA Key Pair
        private_key, public_key = HashUtils.generate_key_pair()
        encrypted_private_key = HashUtils.encrypt_private_key(private_key, password)
        
        # Insert user
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, salt, public_key, encrypted_private_key)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, email, password_hash, salt, public_key, encrypted_private_key))
        
        self.db.commit()
        return True, "Registration successful"
    
    def authenticate_user(self, username, password):
        """Single-factor authentication with rate limiting"""
        cursor = self.db.cursor()
        
        cursor.execute("""
            SELECT user_id, password_hash, salt, email, failed_login_attempts, lockout_until
            FROM users WHERE username = ?
        """, (username,))
        
        user = cursor.fetchone()
        if not user:
            return False, None, "Invalid credentials"
        
        user_id, stored_hash, salt, email, failed_attempts, lockout_until = user
        
        # Check if account is locked
        if lockout_until:
            lockout_time = datetime.fromisoformat(str(lockout_until))
            if datetime.now() < lockout_time:
                remaining_minutes = int((lockout_time - datetime.now()).total_seconds() / 60)
                return False, None, f"Account locked. Try again in {remaining_minutes} minutes."
            else:
                # Lockout expired, reset counters
                cursor.execute("UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE user_id = ?", (user_id,))
                self.db.commit()
                failed_attempts = 0

        # Verify password
        if HashUtils.verify_password(password, salt, stored_hash):
            # Reset failed attempts on successful login
            cursor.execute("UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE user_id = ?", (user_id,))
            self.db.commit()
            return True, user_id, email
        
        # Handle failed login
        failed_attempts = (failed_attempts or 0) + 1
        
        if failed_attempts >= 5:
            # Lock account for 30 minutes
            lockout_time = datetime.now() + timedelta(minutes=30)
            cursor.execute("""
                UPDATE users 
                SET failed_login_attempts = ?, lockout_until = ? 
                WHERE user_id = ?
            """, (failed_attempts, lockout_time, user_id))
            self.db.commit()
            return False, None, "Too many failed attempts. Account locked for 30 minutes."
        else:
            # Increment failed attempts
            cursor.execute("UPDATE users SET failed_login_attempts = ? WHERE user_id = ?", (failed_attempts, user_id))
            self.db.commit()
            remaining_attempts = 5 - failed_attempts
            return False, None, f"Invalid credentials. {remaining_attempts} attempts remaining."
    
    def generate_otp(self, user_id, email):
        """Generate 6-digit OTP for 2FA and send via email"""
        cursor = self.db.cursor()
        
        # Generate random 6-digit OTP
        otp = ''.join(random.choices(string.digits, k=6))
        
        # Set expiry (5 minutes)
        expires_at = datetime.now() + timedelta(minutes=5)
        
        # Store OTP
        cursor.execute("""
            INSERT INTO otp_codes (user_id, otp_code, expires_at)
            VALUES (?, ?, ?)
        """, (user_id, otp, expires_at))
        
        self.db.commit()
        
        # Send OTP via email
        success, message = self.send_email_otp(email, otp)
        
        return otp, success, message
    
    def verify_otp(self, user_id, otp):
        """Verify OTP for multi-factor authentication"""
        cursor = self.db.cursor()
        
        cursor.execute("""
            SELECT otp_id, expires_at FROM otp_codes
            WHERE user_id = ? AND otp_code = ? AND is_used = 0
            ORDER BY created_at DESC LIMIT 1
        """, (user_id, otp))
        
        result = cursor.fetchone()
        if not result:
            return False, "Invalid OTP"
        
        otp_id, expires_at = result
        
        # Check expiry
        if datetime.now() > datetime.fromisoformat(expires_at):
            return False, "OTP expired"
        
        # Mark OTP as used
        cursor.execute("UPDATE otp_codes SET is_used = 1 WHERE otp_id = ?", (otp_id,))
        self.db.commit()
        
        return True, "OTP verified successfully"