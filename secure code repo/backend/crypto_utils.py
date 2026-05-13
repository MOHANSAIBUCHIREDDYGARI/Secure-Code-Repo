from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
import os
import base64

class CryptoUtils:
    """Encryption and Decryption utilities"""
    
    @staticmethod
    def generate_aes_key():
        """Generate 256-bit AES key"""
        return os.urandom(32)  # 256 bits
    
    @staticmethod
    def generate_rsa_keypair():
        """Generate RSA key pair for hybrid encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def encrypt_aes(plaintext, key):
        """AES encryption with CBC mode"""
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext (both base64 encoded)
        return base64.b64encode(iv + ciphertext).decode()
    
    @staticmethod
    def decrypt_aes(encrypted_data, key):
        """AES decryption"""
        # Decode from base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract IV and ciphertext
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode()
    
    @staticmethod
    def encrypt_rsa(plaintext, public_key):
        """RSA encryption for small data (like AES keys)"""
        ciphertext = public_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
    
    @staticmethod
    def decrypt_rsa(encrypted_data, private_key):
        """RSA decryption"""
        ciphertext = base64.b64decode(encrypted_data)
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    @staticmethod
    def hybrid_encrypt(plaintext, wrapper_public_key_pem=None):
        """Hybrid encryption: RSA for key exchange + AES for data
        wrapper_public_key_pem: If provided, encrypts the output Private Key.
        Returns: (encrypted_data, encrypted_aes_key, private_key_pem, public_key_pem)"""
        
        # 1. Encrypt Content with AES
        aes_key = CryptoUtils.generate_aes_key()
        encrypted_data = CryptoUtils.encrypt_aes(plaintext, aes_key)
        
        # 2. Generate File Keypair
        private_key, public_key = CryptoUtils.generate_rsa_keypair()
        
        # 3. Encrypt Content-AES-Key with File-Public-Key
        encrypted_aes_key = CryptoUtils.encrypt_rsa(aes_key, public_key)
        
        # 4. Handle File-Private-Key
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_pem = private_key_bytes.decode()
        
        if wrapper_public_key_pem:
            # Encrypt the Private Key PEM using the Wrapper Key (Hybrid)
            # We reuse the logic: Encrypt PEM with AES, Encrypt AES Key with Wrapper RSA
            wrapper_key = serialization.load_pem_public_key(
                wrapper_public_key_pem.encode(),
                backend=default_backend()
            )
            
            wrap_aes_key = CryptoUtils.generate_aes_key()
            enc_priv_pem_data = CryptoUtils.encrypt_aes(private_key_pem, wrap_aes_key)
            enc_wrap_aes_key = CryptoUtils.encrypt_rsa(wrap_aes_key, wrapper_key)
            
            # Format: WRAPPED|EncData|EncKey
            private_key_pem = f"WRAPPED|{enc_priv_pem_data}|{enc_wrap_aes_key}"
            
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        return encrypted_data, encrypted_aes_key, private_key_pem, public_key_pem
        
    @staticmethod
    def hybrid_decrypt_wrapper(encrypted_content_string, user_private_key):
        """Decrypts content that might have a WRAPPED private key"""
        parts = encrypted_content_string.split("|")
        # Format: encrypted_data | encrypted_key | private_key_pem (or WRAPPED packet)
        
        encrypted_data = parts[0]
        encrypted_key = parts[1]
        private_key_field = parts[2]
        
        # Unwrap if needed
        if private_key_field.startswith("WRAPPED"):
            # Format: WRAPPED|EncData|EncKey
            # But here parts split by |, so private_key_field is just "WRAPPED"
            # We need to re-parse because the wrapped packet also uses pipes
            # Actually, let's look at how it was joined.
            # In DB: enc_data | enc_key | WRAPPED|enc_priv_data|enc_wrap_key
            # Split gives: [enc_data, enc_key, WRAPPED, enc_priv_data, enc_wrap_key]
            
            enc_priv_data = parts[3]
            enc_wrap_key = parts[4]
            
            # Decrypt wrapping AES key
            wrap_aes_key = CryptoUtils.decrypt_rsa(enc_wrap_key, user_private_key)
            
            # Decrypt File Private Key
            private_key_pem = CryptoUtils.decrypt_aes(enc_priv_data, wrap_aes_key)
        else:
            private_key_pem = private_key_field

        # Now proceed with standard decryption
        return CryptoUtils.hybrid_decrypt(encrypted_data, encrypted_key, private_key_pem)

    @staticmethod
    def encrypt_with_repo_key(plaintext, repo_key_bytes):
        """Encrypt content using the shared Repository AES Key
        Returns: encrypted_data (IV + Ciphertext)"""
        return CryptoUtils.encrypt_aes(plaintext, repo_key_bytes)

    @staticmethod
    def decrypt_with_repo_key(encrypted_data, repo_key_bytes):
        """Decrypt content using the shared Repository AES Key"""
        return CryptoUtils.decrypt_aes(encrypted_data, repo_key_bytes)
    
    @staticmethod
    def encrypt_repo_key(repo_aes_key, user_public_key_pem):
        """Encrypt the Repo AES Key with a User's Public Key"""
        public_key = serialization.load_pem_public_key(
            user_public_key_pem.encode(),
            backend=default_backend()
        )
        return CryptoUtils.encrypt_rsa(repo_aes_key, public_key)

    @staticmethod
    def decrypt_repo_key(encrypted_repo_key, user_private_key):
        """Decrypt the Repo AES Key with User's Private Key"""
        return CryptoUtils.decrypt_rsa(encrypted_repo_key, user_private_key)

    @staticmethod
    def hybrid_decrypt(encrypted_data, encrypted_aes_key, private_key_pem):
        """Standard Hybrid decryption"""
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Decrypt AES key using RSA
        aes_key = CryptoUtils.decrypt_rsa(encrypted_aes_key, private_key)
        
        # Decrypt data using AES
        plaintext = CryptoUtils.decrypt_aes(encrypted_data, aes_key)
        
        return plaintext