import sqlite3

from dotenv import load_dotenv
from flask import Flask, jsonify

load_dotenv()

from server.config import DATABASE_PATH, MAX_CONTENT_LENGTH, RSA_KEYS_DIR, UPLOAD_DIR
from server.crypto.rsa import generate_rsa_keypair
from server.models.file_model import init_file_table
from server.models.user_model import init_user_table
from server.routes.auth_routes import auth_bp
from server.routes.file_routes import file_bp


def create_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(conn: sqlite3.Connection) -> None:
    init_user_table(conn)
    init_file_table(conn)
    conn.commit()


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    app.config["UPLOAD_DIR"] = UPLOAD_DIR

    private_key_path = RSA_KEYS_DIR / "private_key.pem"
    public_key_path = RSA_KEYS_DIR / "public_key.pem"
    generate_rsa_keypair(private_key_path, public_key_path)

    conn = create_db_connection()
    init_database(conn)

    app.config["DB_CONN"] = conn
    app.config["PRIVATE_KEY_PATH"] = private_key_path
    app.config["PUBLIC_KEY_PATH"] = public_key_path

    app.register_blueprint(auth_bp)
    app.register_blueprint(file_bp)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
