import sqlite3
import uuid
from pathlib import Path
from typing import Dict

from werkzeug.utils import secure_filename

from server.config import ALLOWED_EXTENSIONS, MAX_CONTENT_LENGTH, UPLOAD_DIR
from server.crypto.hashing import sha256_bytes
from server.models import file_model


class FileService:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _validate_extension(self, filename: str) -> None:
        if "." not in filename:
            raise ValueError("file must have an extension")
        ext = filename.rsplit(".", 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"file extension not allowed: {ext}")

    def save_encrypted_upload(
        self,
        owner_id: int,
        original_filename: str,
        encrypted_bytes: bytes,
        encrypted_aes_key: bytes,
        encrypted_sha256: str,
    ) -> Dict[str, str]:
        if not original_filename:
            raise ValueError("original filename is required")
        self._validate_extension(original_filename)

        if len(encrypted_bytes) > MAX_CONTENT_LENGTH:
            raise ValueError("file exceeds max allowed size")
        if len(encrypted_aes_key) == 0:
            raise ValueError("encrypted AES key is required")

        safe_name = secure_filename(original_filename)
        ext = safe_name.rsplit(".", 1)[1]
        storage_filename = f"{uuid.uuid4().hex}.{ext}.enc"
        storage_path = Path(UPLOAD_DIR) / storage_filename
        storage_path.write_bytes(encrypted_bytes)

        calculated_hash = sha256_bytes(encrypted_bytes)
        if calculated_hash != encrypted_sha256:
            storage_path.unlink(missing_ok=True)
            raise ValueError("encrypted SHA-256 mismatch")

        file_id = file_model.create_file_record(
            self.conn,
            owner_id=owner_id,
            original_filename=safe_name,
            storage_filename=storage_filename,
            encrypted_aes_key=encrypted_aes_key,
            encrypted_file_sha256=encrypted_sha256,
        )
        self.conn.commit()

        return {
            "file_id": file_id,
            "storage_filename": storage_filename,
            "original_filename": safe_name,
        }

    def get_encrypted_file(self, file_id: int):
        record = file_model.get_file_by_id(self.conn, file_id)
        if not record:
            raise ValueError("file not found")

        storage_path = Path(UPLOAD_DIR) / record["storage_filename"]
        if not storage_path.exists():
            raise FileNotFoundError("stored file is missing")

        encrypted_bytes = storage_path.read_bytes()
        calculated = sha256_bytes(encrypted_bytes)
        if calculated != record["encrypted_file_sha256"]:
            raise ValueError("file integrity validation failed")

        return {
            "record": record,
            "encrypted_bytes": encrypted_bytes,
        }
