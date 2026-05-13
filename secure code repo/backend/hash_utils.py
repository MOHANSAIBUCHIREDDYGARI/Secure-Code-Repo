import hashlib
import os
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64

class HashUtils:
    """Hashing and Digital Signature utilities"""
    
    @staticmethod
    def generate_salt():
        """Generate random salt for password hashing"""
        return os.urandom(32).hex()
    
    @staticmethod
    def hash_password(password, salt):
        """Hash password with salt using SHA-256"""
        salted_password = password + salt
        return hashlib.sha256(salted_password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password, salt, stored_hash):
        """Verify password against stored hash"""
        computed_hash = HashUtils.hash_password(password, salt)
        return hmac.compare_digest(computed_hash, stored_hash)
    
    @staticmethod
    def hash_file_content(content):
        """Generate SHA-256 hash of file content for integrity"""
        return hashlib.sha256(content.encode()).hexdigest()
    
    @staticmethod
    def generate_commit_hash(repo_id, user_id, message, timestamp):
        """Generate commit hash for version control integrity"""
        commit_string = f"{repo_id}{user_id}{message}{timestamp}"
        return hashlib.sha256(commit_string.encode()).hexdigest()
    
    @staticmethod
    def create_digital_signature(message, private_key_pem):
        """Create digital signature using RSA private key"""
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Create signature
        signature = private_key.sign(
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def verify_digital_signature(message, signature_b64, public_key_pem):
        """Verify digital signature using RSA public key"""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Verify
            public_key.verify(
                signature,
                message.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def generate_key_pair():
        """Generate RSA 2048-bit key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Public Key PEM
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        return private_key, public_pem

    @staticmethod
    def encrypt_private_key(private_key, password):
        """Encrypt private key using password (AES-256 per standard)"""
        encrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        return encrypted_pem.decode()

    @staticmethod
    def decrypt_private_key(encrypted_pem_str, password):
        """Decrypt private key using password"""
        try:
            private_key = serialization.load_pem_private_key(
                encrypted_pem_str.encode(),
                password=password.encode(),
                backend=default_backend()
            )
            return private_key
        except Exception:
            return None