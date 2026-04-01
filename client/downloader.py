import argparse
import base64
from pathlib import Path

import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def sha256_bytes(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def login(base_url: str, username: str, password: str) -> str:
    response = requests.post(f"{base_url}/api/auth/login", json={"username": username, "password": password}, timeout=30)
    response.raise_for_status()
    return response.json()["access_token"]


def create_download_link(base_url: str, token: str, file_id: int) -> str:
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{base_url}/api/files/{file_id}/link", headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()["download_token"]


def download_and_decrypt(base_url: str, download_token: str, private_key_path: Path, output_path: Path) -> None:
    response = requests.get(f"{base_url}/api/files/download", params={"token": download_token}, timeout=60)
    response.raise_for_status()

    encrypted_file = response.content
    server_hash = response.headers.get("X-Encrypted-SHA256", "")
    if sha256_bytes(encrypted_file) != server_hash:
        raise ValueError("Encrypted file integrity check failed.")

    encrypted_aes_key = base64.b64decode(response.headers["X-Encrypted-AES-Key"])

    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    plaintext = Fernet(aes_key).decrypt(encrypted_file)
    output_path.write_bytes(plaintext)


def main():
    parser = argparse.ArgumentParser(description="Secure downloader client")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--file-id", type=int, required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    token = login(args.base_url, args.username, args.password)
    download_token = create_download_link(args.base_url, token, args.file_id)
    download_and_decrypt(
        args.base_url,
        download_token,
        Path(args.private_key),
        Path(args.output),
    )
    print(f"File decrypted and saved to {args.output}")


if __name__ == "__main__":
    main()
