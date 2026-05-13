import smtplib

EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_ADDRESS = "mohansai1810@gmail.com"  # ← Your full Gmail address
EMAIL_PASSWORD = "bbbzxjmusjipxvis"     # ← 16-char app password (remove spaces!)

try:
    print("Connecting to Gmail...")
    server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
    server.starttls()
    
    print("Logging in...")
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    
    print("✅ Email credentials valid!")
    server.quit()
    
except Exception as e:
    print(f"❌ Email error: {e}")