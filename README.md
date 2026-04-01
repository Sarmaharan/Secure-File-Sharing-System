# Secure File Sharing System (Flask + Cryptography)

A production-ready secure file sharing backend/client system with:
- AES-256 encryption (Fernet)
- RSA-2048 key wrapping for AES keys
- SHA-256 integrity checks
- JWT authentication
- Time-limited download tokens
- SQLite persistence
- Encrypted-only file storage

## Architecture

```text
secure-file-transfer-system/
│── server/
│   ├── app.py
│   ├── config.py
│   ├── routes/
│   │   ├── auth_routes.py
│   │   ├── file_routes.py
│   ├── crypto/
│   │   ├── aes.py
│   │   ├── rsa.py
│   │   ├── hashing.py
│   ├── models/
│   │   ├── user_model.py
│   │   ├── file_model.py
│   ├── services/
│   │   ├── file_service.py
│   │   ├── auth_service.py
│   └── utils/
│       ├── jwt_handler.py
│
│── client/
│   ├── uploader.py
│   ├── downloader.py
│
│── tests/
│   ├── test_flow.py
│── requirements.txt
│── README.md
```

## Security Design

1. Client encrypts file bytes using Fernet (AES-256 equivalent authenticated encryption).
2. Client encrypts AES key with server RSA public key (OAEP + SHA-256).
3. Server stores only encrypted file bytes and encrypted AES key.
4. Server verifies encrypted file SHA-256 before storage and before download.
5. Download links are JWTs with expiration (`DOWNLOAD_TOKEN_EXP_MINUTES`).
6. User passwords are hashed with bcrypt.

## Setup (Python 3.10+)

1. Clone and enter project.
2. Create and activate virtual environment.
3. Install dependencies.
4. Set environment variables.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET="change-this-to-a-long-random-value"
# Optional overrides:
# export DATABASE_PATH="/absolute/path/secure_files.db"
# export UPLOAD_DIR="/absolute/path/uploads"
# export RSA_KEYS_DIR="/absolute/path/keys"
# export MAX_CONTENT_LENGTH="20971520"
# export ALLOWED_EXTENSIONS="txt,pdf,png,jpg,jpeg,docx,zip,csv,json"
# export JWT_EXP_MINUTES="60"
# export DOWNLOAD_TOKEN_EXP_MINUTES="10"
```

## Run Server

```bash
python -m server.app
```

Server base URL: `http://127.0.0.1:5000`

## API Endpoints

### Auth
- `POST /api/auth/register`
- `POST /api/auth/login`

### File
- `GET /api/files/public-key` (JWT required)
- `POST /api/files/upload` (JWT required, multipart)
- `POST /api/files/<file_id>/link` (JWT required)
- `GET /api/files/download?token=<download_token>`

### Health
- `GET /health`

## Sample Requests (curl)

### Register
```bash
curl -X POST http://127.0.0.1:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"strongpass123"}'
```

### Login
```bash
curl -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"strongpass123"}'
```

### Get Public Key
```bash
curl http://127.0.0.1:5000/api/files/public-key \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

## Client Usage

### Upload Encrypted File
```bash
python client/uploader.py \
  --base-url http://127.0.0.1:5000 \
  --username alice \
  --password strongpass123 \
  --file ./example.txt
```

Output includes `file_id`.

### Download + Decrypt File
```bash
python client/downloader.py \
  --base-url http://127.0.0.1:5000 \
  --username alice \
  --password strongpass123 \
  --file-id <FILE_ID> \
  --private-key ./server/keys/private_key.pem \
  --output ./recovered_example.txt
```

## Testing

Run automated flow test:
```bash
pytest -q
```

This verifies:
- registration/login
- public key retrieval
- upload encrypted file
- create expiring link
- download and decrypt
- plaintext equality check

## Notes

- Do **not** expose `private_key.pem` publicly.
- Rotate JWT secret and RSA keys in production.
- Place the app behind HTTPS (reverse proxy) in production.
