import bcrypt
import sqlite3
from typing import Optional

from server.models import user_model


class AuthService:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def register(self, username: str, password: str) -> int:
        if not username or not password:
            raise ValueError("username and password are required")
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")

        existing = user_model.get_user_by_username(self.conn, username)
        if existing:
            raise ValueError("username already exists")

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        user_id = user_model.create_user(self.conn, username, password_hash)
        self.conn.commit()
        return user_id

    def authenticate(self, username: str, password: str) -> Optional[int]:
        user = user_model.get_user_by_username(self.conn, username)
        if not user:
            return None

        password_hash = user["password_hash"].encode("utf-8")
        if bcrypt.checkpw(password.encode("utf-8"), password_hash):
            return int(user["id"])
        return None
