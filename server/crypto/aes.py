from cryptography.fernet import Fernet, InvalidToken


class AESError(Exception):
    """Raised when AES/Fernet operations fail."""


def generate_aes_key() -> bytes:
    return Fernet.generate_key()


def encrypt_data(data: bytes, aes_key: bytes) -> bytes:
    try:
        return Fernet(aes_key).encrypt(data)
    except Exception as exc:
        raise AESError(f"AES encryption failed: {exc}") from exc


def decrypt_data(encrypted_data: bytes, aes_key: bytes) -> bytes:
    try:
        return Fernet(aes_key).decrypt(encrypted_data)
    except InvalidToken as exc:
        raise AESError("Invalid AES key or corrupted encrypted payload.") from exc
    except Exception as exc:
        raise AESError(f"AES decryption failed: {exc}") from exc
