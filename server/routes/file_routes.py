import base64

from flask import Blueprint, current_app, jsonify, request, send_file, g

from server.config import DOWNLOAD_TOKEN_EXP_MINUTES
from server.services.file_service import FileService
from server.utils.jwt_handler import JWTHandler, jwt_required


file_bp = Blueprint("files", __name__, url_prefix="/api/files")


@file_bp.get("/public-key")
@jwt_required
def get_public_key():
    try:
        public_key_path = current_app.config["PUBLIC_KEY_PATH"]
        return jsonify({"public_key": public_key_path.read_text(encoding="utf-8")}), 200
    except Exception:
        return jsonify({"error": "Could not read public key"}), 500


@file_bp.post("/upload")
@jwt_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "Missing file field"}), 400

    uploaded_file = request.files["file"]
    encrypted_aes_key_b64 = request.form.get("encrypted_aes_key", "")
    encrypted_sha256 = request.form.get("encrypted_sha256", "")

    if not uploaded_file.filename:
        return jsonify({"error": "Missing filename"}), 400

    try:
        encrypted_bytes = uploaded_file.read()
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    except Exception:
        return jsonify({"error": "Invalid base64 encoded encrypted AES key"}), 400

    try:
        file_service = FileService(current_app.config["DB_CONN"])
        result = file_service.save_encrypted_upload(
            owner_id=g.user_id,
            original_filename=uploaded_file.filename,
            encrypted_bytes=encrypted_bytes,
            encrypted_aes_key=encrypted_aes_key,
            encrypted_sha256=encrypted_sha256,
        )
        return jsonify({"message": "File uploaded", **result}), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Internal server error"}), 500


@file_bp.post("/<int:file_id>/link")
@jwt_required
def create_download_link(file_id: int):
    try:
        token = JWTHandler.create_token(
            {"user_id": g.user_id, "file_id": file_id, "scope": "download"},
            minutes=DOWNLOAD_TOKEN_EXP_MINUTES,
        )
        return jsonify({"download_token": token, "expires_in_minutes": DOWNLOAD_TOKEN_EXP_MINUTES}), 200
    except Exception:
        return jsonify({"error": "Could not create download token"}), 500


@file_bp.get("/download")
def download_file():
    token = request.args.get("token", "")
    if not token:
        return jsonify({"error": "Missing download token"}), 400

    try:
        claims = JWTHandler.decode_token(token)
        if claims.get("scope") != "download":
            return jsonify({"error": "Invalid download token scope"}), 403
        file_id = int(claims["file_id"])
    except Exception:
        return jsonify({"error": "Invalid or expired download token"}), 401

    try:
        file_service = FileService(current_app.config["DB_CONN"])
        payload = file_service.get_encrypted_file(file_id)
        record = payload["record"]

        response = send_file(
            current_app.config["UPLOAD_DIR"] / record["storage_filename"],
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=f"{record['original_filename']}.enc",
        )
        response.headers["X-Encrypted-AES-Key"] = base64.b64encode(record["encrypted_aes_key"]).decode("utf-8")
        response.headers["X-Encrypted-SHA256"] = record["encrypted_file_sha256"]
        response.headers["X-Original-Filename"] = record["original_filename"]
        return response
    except (ValueError, FileNotFoundError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Internal server error"}), 500
