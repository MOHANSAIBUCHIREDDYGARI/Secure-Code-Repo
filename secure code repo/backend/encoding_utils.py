import base64
import qrcode
from io import BytesIO

class EncodingUtils:
    """Encoding and Decoding utilities"""
    
    @staticmethod
    def encode_base64(data):
        """Encode data to Base64"""
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def decode_base64(encoded_data):
        """Decode Base64 data"""
        return base64.b64decode(encoded_data).decode()
    
    @staticmethod
    def generate_qr_code(data):
        """Generate QR code for repository sharing"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for storage/display
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return img_str
    
    @staticmethod
    def encode_repo_url(repo_id, repo_name):
        """Encode repository info for QR code"""
        repo_info = f"REPO_ID:{repo_id}|NAME:{repo_name}"
        return EncodingUtils.encode_base64(repo_info)