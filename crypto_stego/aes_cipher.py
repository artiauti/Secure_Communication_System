"""
AES-256 Cryptographic Engine
----------------------------
Implements AES-256-GCM (Galois/Counter Mode) authenticated symmetric encryption,
cryptographically secure key generation, and PBKDF2-HMAC-SHA256 key derivation.
"""

import os
import binascii
import base64
from typing import Tuple, Union, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class InvalidKeyError(CryptoError):
    """Raised when an encryption or decryption key is malformed or invalid."""
    pass


class AuthenticationError(CryptoError):
    """Raised when AES-GCM authentication fails (wrong key or tampered ciphertext)."""
    pass


PBKDF2_ITERATIONS = 600_000
SALT_SIZE_BYTES = 16
NONCE_SIZE_BYTES = 12
TAG_SIZE_BYTES = 16
KEY_SIZE_BYTES = 32  # 256 bits


def generate_aes256_key() -> bytes:
    """Generate a cryptographically secure 256-bit (32 bytes) random AES key."""
    return AESGCM.generate_key(bit_length=256)


def generate_aes256_key_hex() -> str:
    """Generate a 256-bit key formatted as a 64-character hexadecimal string."""
    return binascii.hexlify(generate_aes256_key()).decode("ascii")


def generate_aes256_key_base64() -> str:
    """Generate a 256-bit key formatted as a base64 string."""
    return base64.b64encode(generate_aes256_key()).decode("ascii")


def derive_key_from_password(password: Union[str, bytes], salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive a 256-bit AES key from a user password/passphrase using PBKDF2-HMAC-SHA256.
    
    :param password: User secret password or passphrase.
    :param salt: 16-byte cryptographic salt.
    :param iterations: Number of PBKDF2 iterations (default 600,000 for NIST compliance).
    :return: 32-byte (256-bit) AES key.
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password

    if not password_bytes:
        raise InvalidKeyError("Password cannot be empty.")

    if len(salt) != SALT_SIZE_BYTES:
        raise CryptoError(f"Salt must be exactly {SALT_SIZE_BYTES} bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password_bytes)


def resolve_key(key_or_password: Union[str, bytes], salt: bytes) -> bytes:
    """
    Resolve user input into a 32-byte AES-256 key.
    Handles:
    - Raw 32 bytes
    - 64-char Hexadecimal string
    - 44-char Base64 string
    - Arbitrary text passphrase (derived via PBKDF2)
    """
    if isinstance(key_or_password, bytes):
        if len(key_or_password) == 32:
            return key_or_password
        # Otherwise treat bytes as password bytes
        return derive_key_from_password(key_or_password, salt)

    if isinstance(key_or_password, str):
        cleaned = key_or_password.strip()
        if not cleaned:
            raise InvalidKeyError("Key or password cannot be empty.")

        # Check if 64-char Hex key
        if len(cleaned) == 64:
            try:
                candidate = binascii.unhexlify(cleaned)
                if len(candidate) == 32:
                    return candidate
            except (binascii.Error, ValueError):
                pass

        # Check if 44-char Base64 key
        if len(cleaned) == 44 and cleaned.endswith("="):
            try:
                candidate = base64.b64decode(cleaned)
                if len(candidate) == 32:
                    return candidate
            except (binascii.Error, ValueError):
                pass

        # Standard text passphrase
        return derive_key_from_password(cleaned, salt)

    raise InvalidKeyError("Key or password must be a string or bytes.")


def encrypt_data(
    plaintext: bytes,
    key_or_password: Union[str, bytes],
    associated_data: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext bytes using AES-256-GCM.
    
    :param plaintext: Data to encrypt as bytes.
    :param key_or_password: 32-byte key, 64-char hex, 44-char base64, or passphrase string.
    :param associated_data: Optional authenticated associated data (AAD).
    :return: Tuple of (salt, nonce, ciphertext_with_tag)
             Note: In cryptography's AESGCM, the returned ciphertext contains the 16-byte tag appended.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise CryptoError("Plaintext must be bytes or bytearray.")

    salt = os.urandom(SALT_SIZE_BYTES)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    aes_key = resolve_key(key_or_password, salt)

    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, bytes(plaintext), associated_data)

    return salt, nonce, ciphertext_with_tag


def decrypt_data(
    salt: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    key_or_password: Union[str, bytes],
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext and verify authentication tag.
    
    :param salt: 16-byte salt used during key derivation.
    :param nonce: 12-byte GCM initialization vector / nonce.
    :param ciphertext_with_tag: Ciphertext containing the 16-byte tag.
    :param key_or_password: The decryption key or passphrase.
    :param associated_data: Optional authenticated associated data used during encryption.
    :return: Decrypted plaintext bytes.
    :raises AuthenticationError: If the key is incorrect or data was tampered with.
    """
    if len(salt) != SALT_SIZE_BYTES:
        raise CryptoError(f"Invalid salt length: expected {SALT_SIZE_BYTES} bytes.")
    if len(nonce) != NONCE_SIZE_BYTES:
        raise CryptoError(f"Invalid nonce length: expected {NONCE_SIZE_BYTES} bytes.")
    if len(ciphertext_with_tag) < TAG_SIZE_BYTES:
        raise CryptoError("Ciphertext is too short to contain a valid authentication tag.")

    aes_key = resolve_key(key_or_password, salt)
    aesgcm = AESGCM(aes_key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext
    except InvalidTag as err:
        raise AuthenticationError(
            "Decryption failed: Incorrect key or ciphertext has been altered/tampered with."
        ) from err


def encrypt_text(text: str, key_or_password: Union[str, bytes]) -> Tuple[bytes, bytes, bytes]:
    """Encrypt a UTF-8 string with AES-256-GCM."""
    if not isinstance(text, str):
        raise CryptoError("Text message must be a string.")
    return encrypt_data(text.encode("utf-8"), key_or_password)


def decrypt_text(
    salt: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    key_or_password: Union[str, bytes]
) -> str:
    """Decrypt ciphertext and decode as UTF-8 string."""
    decrypted_bytes = decrypt_data(salt, nonce, ciphertext_with_tag, key_or_password)
    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError as err:
        raise CryptoError("Decrypted data is not valid UTF-8 text.") from err


def encrypt_file(
    file_bytes: bytes,
    filename: str,
    key_or_password: Union[str, bytes]
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt binary file bytes with AES-256-GCM."""
    return encrypt_data(file_bytes, key_or_password)


def decrypt_file(
    salt: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    key_or_password: Union[str, bytes]
) -> bytes:
    """Decrypt binary file bytes with AES-256-GCM."""
    return decrypt_data(salt, nonce, ciphertext_with_tag, key_or_password)
