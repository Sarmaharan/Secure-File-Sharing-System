from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes


class RSAError(Exception):
    """Raised when RSA operations fail."""


def generate_rsa_keypair(private_key_path: Path, public_key_path: Path) -> None:
    if private_key_path.exists() and public_key_path.exists():
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_path.write_bytes(private_bytes)
    public_key_path.write_bytes(public_bytes)


def load_private_key(path: Path):
    try:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise RSAError(f"Failed to load private key: {exc}") from exc


def load_public_key(path: Path):
    try:
        return serialization.load_pem_public_key(path.read_bytes())
    except Exception as exc:
        raise RSAError(f"Failed to load public key: {exc}") from exc


def encrypt_with_rsa(public_key, plaintext: bytes) -> bytes:
    try:
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise RSAError(f"RSA encryption failed: {exc}") from exc


def decrypt_with_rsa(private_key, ciphertext: bytes) -> bytes:
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise RSAError(f"RSA decryption failed: {exc}") from exc
