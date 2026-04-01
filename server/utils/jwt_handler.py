from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict

import jwt
from flask import jsonify, request, g

from server.config import JWT_ALGORITHM, JWT_EXP_MINUTES, JWT_SECRET


class JWTHandler:
    @staticmethod
    def create_token(subject: Dict[str, Any], minutes: int = JWT_EXP_MINUTES) -> str:
        payload = {
            **subject,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes),
            "iat": datetime.now(timezone.utc),
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def jwt_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        try:
            claims = JWTHandler.decode_token(token)
            g.user_id = int(claims.get("user_id"))
        except Exception:
            return jsonify({"error": "Invalid or expired token"}), 401

        return view_func(*args, **kwargs)

    return wrapper
