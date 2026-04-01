import sqlite3
from typing import Optional


def init_file_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            storage_filename TEXT UNIQUE NOT NULL,
            encrypted_aes_key BLOB NOT NULL,
            encrypted_file_sha256 TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
        """
    )


def create_file_record(
    conn: sqlite3.Connection,
    owner_id: int,
    original_filename: str,
    storage_filename: str,
    encrypted_aes_key: bytes,
    encrypted_file_sha256: str,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO files (
            owner_id, original_filename, storage_filename,
            encrypted_aes_key, encrypted_file_sha256
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (owner_id, original_filename, storage_filename, encrypted_aes_key, encrypted_file_sha256),
    )
    return cursor.lastrowid


def get_file_by_id(conn: sqlite3.Connection, file_id: int) -> Optional[sqlite3.Row]:
    cursor = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    return cursor.fetchone()
