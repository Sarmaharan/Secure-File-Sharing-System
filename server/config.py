import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", BASE_DIR / "uploads"))
RSA_KEYS_DIR = Path(os.getenv("RSA_KEYS_DIR", BASE_DIR / "server" / "keys"))
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", BASE_DIR / "server" / "secure_files.db"))
MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(20 * 1024 * 1024)))  # 20 MB default
ALLOWED_EXTENSIONS = {
    ext.strip().lower()
    for ext in os.getenv("ALLOWED_EXTENSIONS", "txt,pdf,png,jpg,jpeg,docx,zip,csv,json").split(",")
    if ext.strip()
}
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "60"))
DOWNLOAD_TOKEN_EXP_MINUTES = int(os.getenv("DOWNLOAD_TOKEN_EXP_MINUTES", "10"))


if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable must be set.")

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RSA_KEYS_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
