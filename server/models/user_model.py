import sqlite3
from typing import Optional


def init_user_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def create_user(conn: sqlite3.Connection, username: str, password_hash: str) -> int:
    cursor = conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    return cursor.lastrowid


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
