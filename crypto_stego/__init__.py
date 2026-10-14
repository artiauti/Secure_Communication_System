"""
Secure Data Hiding Using AES-256 Encryption and Image Steganography
-------------------------------------------------------------------
A comprehensive cybersecurity solution combining AES-256-GCM authenticated
symmetric encryption with Least Significant Bit (LSB) image steganography.
"""

from .aes_cipher import (
    generate_aes256_key,
    generate_aes256_key_hex,
    generate_aes256_key_base64,
    derive_key_from_password,
    encrypt_data,
    decrypt_data,
    encrypt_text,
    decrypt_text,
    encrypt_file,
    decrypt_file,
    CryptoError,
    AuthenticationError,
    InvalidKeyError,
)

from .lsb_stego import (
    LSBSteganography,
    StegoError,
    CapacityExceededError,
    NoPayloadDetectedError,
    PAYLOAD_TYPE_TEXT,
    PAYLOAD_TYPE_FILE,
)

from .metrics import (
    calculate_mse,
    calculate_psnr,
    calculate_ber,
    calculate_image_metrics,
    generate_difference_image,
)

__version__ = "2.0.0"
__all__ = [
    "generate_aes256_key",
    "generate_aes256_key_hex",
    "generate_aes256_key_base64",
    "derive_key_from_password",
    "encrypt_data",
    "decrypt_data",
    "encrypt_text",
    "decrypt_text",
    "encrypt_file",
    "decrypt_file",
    "CryptoError",
    "AuthenticationError",
    "InvalidKeyError",
    "LSBSteganography",
    "StegoError",
    "CapacityExceededError",
    "NoPayloadDetectedError",
    "PAYLOAD_TYPE_TEXT",
    "PAYLOAD_TYPE_FILE",
    "calculate_mse",
    "calculate_psnr",
    "calculate_ber",
    "calculate_image_metrics",
    "generate_difference_image",
]
