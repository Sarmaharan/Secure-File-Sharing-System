import argparse
import base64
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


def sha256_bytes(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def login(base_url: str, username: str, password: str) -> str:
    response = requests.post(f"{base_url}/api/auth/login", json={"username": username, "password": password}, timeout=30)
    response.raise_for_status()
    return response.json()["access_token"]


def get_public_key(base_url: str, token: str):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{base_url}/api/files/public-key", headers=headers, timeout=30)
    response.raise_for_status()
    public_key_pem = response.json()["public_key"].encode("utf-8")
    return serialization.load_pem_public_key(public_key_pem)


def upload_file(base_url: str, token: str, file_path: Path, public_key):
    file_bytes = file_path.read_bytes()
    aes_key = Fernet.generate_key()
    encrypted_file = Fernet(aes_key).encrypt(file_bytes)

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    encrypted_sha256 = sha256_bytes(encrypted_file)
    headers = {"Authorization": f"Bearer {token}"}

    with file_path.open("rb") as _:
        files = {
            "file": (file_path.name, encrypted_file, "application/octet-stream"),
        }
        data = {
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
            "encrypted_sha256": encrypted_sha256,
        }
        response = requests.post(f"{base_url}/api/files/upload", headers=headers, files=files, data=data, timeout=60)

    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Secure uploader client")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    token = login(args.base_url, args.username, args.password)
    public_key = get_public_key(args.base_url, token)
    result = upload_file(args.base_url, token, file_path, public_key)
    print("Upload successful:", result)


if __name__ == "__main__":
    main()
