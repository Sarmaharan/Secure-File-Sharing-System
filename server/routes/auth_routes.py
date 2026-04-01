from flask import Blueprint, current_app, jsonify, request

from server.services.auth_service import AuthService
from server.utils.jwt_handler import JWTHandler


auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    try:
        auth_service = AuthService(current_app.config["DB_CONN"])
        user_id = auth_service.register(username=username, password=password)
        return jsonify({"message": "User registered", "user_id": user_id}), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    try:
        auth_service = AuthService(current_app.config["DB_CONN"])
        user_id = auth_service.authenticate(username=username, password=password)
        if not user_id:
            return jsonify({"error": "Invalid credentials"}), 401

        token = JWTHandler.create_token({"user_id": user_id, "username": username})
        return jsonify({"access_token": token}), 200
    except Exception:
        return jsonify({"error": "Internal server error"}), 500
