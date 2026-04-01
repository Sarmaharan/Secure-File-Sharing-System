import base64
import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret-123")
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("RSA_KEYS_DIR", str(tmp_path / "keys"))

    from server.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client, app


def test_upload_download_flow(app_client, tmp_path):
    client, app = app_client

    register_res = client.post("/api/auth/register", json={"username": "alice", "password": "strongpass123"})
    assert register_res.status_code == 201

    login_res = client.post("/api/auth/login", json={"username": "alice", "password": "strongpass123"})
    assert login_res.status_code == 200
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    pub_key_res = client.get("/api/files/public-key", headers=headers)
    assert pub_key_res.status_code == 200
    public_key = serialization.load_pem_public_key(pub_key_res.get_json()["public_key"].encode("utf-8"))

    original = b"secret file content"
    aes_key = Fernet.generate_key()
    encrypted_file = Fernet(aes_key).encrypt(original)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    digest = hashes.Hash(hashes.SHA256())
    digest.update(encrypted_file)
    encrypted_hash = digest.finalize().hex()

    upload_res = client.post(
        "/api/files/upload",
        headers=headers,
        data={
            "encrypted_aes_key": base64.b64encode(encrypted_key).decode("utf-8"),
            "encrypted_sha256": encrypted_hash,
            "file": (__import__("io").BytesIO(encrypted_file), "sample.txt"),
        },
        content_type="multipart/form-data",
    )
    assert upload_res.status_code == 201
    file_id = upload_res.get_json()["file_id"]

    link_res = client.post(f"/api/files/{file_id}/link", headers=headers)
    assert link_res.status_code == 200
    download_token = link_res.get_json()["download_token"]

    download_res = client.get(f"/api/files/download?token={download_token}")
    assert download_res.status_code == 200

    encrypted_downloaded = download_res.data
    private_key = serialization.load_pem_private_key(Path(app.config["PRIVATE_KEY_PATH"]).read_bytes(), password=None)
    decrypted_key = private_key.decrypt(
        base64.b64decode(download_res.headers["X-Encrypted-AES-Key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    decrypted_file = Fernet(decrypted_key).decrypt(encrypted_downloaded)
    assert decrypted_file == original
