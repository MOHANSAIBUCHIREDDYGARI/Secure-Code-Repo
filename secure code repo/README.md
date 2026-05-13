# Secure Code Repository: End-to-End Encrypted Collaboration Platform

Secure Code Repository is a secure file storage and collaboration system built with Flask and Python. It prioritizes data privacy and integrity by implementing strong cryptography, including AES-256 for data encryption, RSA-2048 for key management, and digital signatures for identity verification.

##  Key Features

*   **End-to-End Encryption**: Files are encrypted with AES-256 before being stored. The server never sees the raw file content.
*   **Secure Key Sharing**: Repository encryption keys are securely shared between users using RSA public-key cryptography.
*   **Digital Signatures**: Every uploaded file is digitally signed with the uploader's private key, ensuring non-repudiation and proof of origin.
*   **Integrity Checks**: SHA-256 hashing ensures files are not tampered with during storage or transit.
*   **Role-Based Access Control (RBAC)**: Granular permissions (Owner, Read, Write, Delete) for repository access.
*   **Two-Factor Authentication (2FA)**: OTP-based email verification for login.
*   **QR Code Sharing**: Easily share repository access via QR codes.

##  Security Architecture

### Encryption Workflow
1.  **Repository creation**: A random 256-bit AES key (Repo Key) is generated.
2.  **Key Storage**: The Repo Key is encrypted with the Owner's RSA Public Key and stored in the database.
3.  **File Upload**: 
    - The Repo Key is decrypted in memory using the uploader's Private Key.
    - The file is encrypted using the Repo Key (AES-CBC mode).
    - A digital signature is generated using the uploader's Private Key.
4.  **File Access**: 
    - The user decrypts the Repo Key with their Private Key.
    - The file is decrypted using the Repo Key.
    - The digital signature is verified against the uploader's Public Key.

### Identity Management
-   **User Keys**: Upon registration, an RSA-2048 key pair is generated. The private key is encrypted with the user's password (AES) and stored in the database.
-   **Session Security**: Private keys are cached in memory (session-scoped) after login for active operations and discarded on logout.

##  Technology Stack

-   **Backend**: Flask (Python)
-   **Database**: SQLite
-   **Cryptography**: `cryptography` library (hazmat primitives)
-   **Frontend**: HTML5, CSS3
-   **Authentication**: Custom Auth with TOTP/Email fallback

## Project Structure

```
.
├── backend/                # Core Flask application and backend logic
│   ├── app.py              # Main application entry point and route definitions
│   ├── auth.py             # User authentication, registration, and session handling
│   ├── crypto_utils.py     # Cryptographic core (AES-256, RSA-2048 implementation)
│   ├── access_control.py   # Role-Based Access Control (RBAC) logic
│   ├── check_database.py   # Utility to inspect database state
│   └── requirements.txt    # Python dependencies
├── database/               # Database initialization
│   └── schema.sql          # Database schema definition
├── static/                 # Static frontend assets
│   ├── css/                # Stylesheets (style.css)
│   └── js/                 # Client-side scripts
├── templates/              # HTML Templates
│   ├── dashboard.html      # User dashboard showing repositories
│   ├── repository.html     # Repository details and file list
│   ├── login.html          # User login page
│   ├── register.html       # User registration page
│   └── ...                 # Other UI pages (OTP, file views, etc.)
└── README.md               # Project documentation
```

### Key Directories and Files

*   **`backend/`**: This is the heart of the application.
    *   `app.py`: The entry point for the Flask server, handling HTTP requests and routing.
    *   `crypto_utils.py`: Contains the critical security logic for encryption, decryption, and key management.
    *   `auth.py`: Manages user sessions, login/logout flows, and password hashing.
*   **`templates/`**: Contains the user interface. These HTML files are dynamically rendered by Flask to show user-specific data (like their repositories).
*   **`database/`**: Stores the SQL schema used to initialize the SQLite database structure.
*   **`static/`**: Houses the visual styling (CSS) and any client-side behavior (JavaScript) that runs in the user's browser.

##  Installation & Setup

1.  **Create a Virtual Environment**
    ```bash
    python -m venv venv
    # Windows
    venv\Scripts\activate
    # Linux/Mac
    source venv/bin/activate
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r backend/requirements.txt
    ```

3.  **Initialize Database**
    The application automatically connects to `backend/secure_repo_v2.db`. If you need to reset it, you can delete the `.db` file and re-run the initialization logic (usually handled in `app.py` or `migrate_db.py`).

##  Usage

1.  **Start the Server**
    ```bash
    cd backend
    python app.py
    ```
    The application will run at `http://127.0.0.1:5000`.

2.  **Register a New User**
    - Go to `/register`.
    - Create an account. This generates your RSA keys.

3.  **Login**
    - Go to `/login`.
    - Enter credentials.
    - Enter the OTP displayed (in development mode, it's flashed on the screen).

4.  **Create a Repository**
    - Navigate to the Dashboard.
    - Click "Create Repository".

5.  **Share Access**
    - Open a repository.
    - Use "Grant Access" to add other users by username.
    - Or show the QR code to another logged-in user.
