"""
Least Significant Bit (LSB) Image Steganography Engine
------------------------------------------------------
Embeds and extracts encrypted binary packets into digital images using
the Least Significant Bit (LSB) spatial domain technique.
Guarantees visual imperceptibility and lossless payload recovery.
"""

import os
import struct
from io import BytesIO
from typing import Tuple, Optional, Union, Dict, Any
from PIL import Image

from .aes_cipher import (
    encrypt_data,
    decrypt_data,
    encrypt_text,
    decrypt_text,
    CryptoError,
    AuthenticationError,
    InvalidKeyError,
    SALT_SIZE_BYTES,
    NONCE_SIZE_BYTES,
)


MAGIC_HEADER = b"AES256STEG"  # 10 bytes identifier
FORMAT_VERSION = 1             # 1 byte version
PAYLOAD_TYPE_TEXT = 0          # 0 = text message
PAYLOAD_TYPE_FILE = 1          # 1 = binary file


class StegoError(Exception):
    """Base exception for steganography errors."""
    pass


class CapacityExceededError(StegoError):
    """Raised when the payload exceeds the cover image's storage capacity."""
    pass


class NoPayloadDetectedError(StegoError):
    """Raised when an image does not contain an AES256-STEG header."""
    pass


class LSBSteganography:
    """
    LSB Steganography Processor.
    """

    @staticmethod
    def get_image_capacity(image: Image.Image) -> Dict[str, Any]:
        """
        Calculate the hiding capacity of a PIL Image in bits, bytes, and kilobytes.
        RGB images have 3 color channels per pixel (3 bits per pixel for 1-LSB).
        """
        width, height = image.size
        total_pixels = width * height
        total_bits = total_pixels * 3  # RGB channels
        total_bytes = total_bits // 8

        # Reserve minimal header space (~64 bytes)
        usable_bytes = max(0, total_bytes - 64)

        return {
            "width": width,
            "height": height,
            "total_pixels": total_pixels,
            "total_capacity_bytes": total_bytes,
            "usable_capacity_bytes": usable_bytes,
            "usable_capacity_kb": round(usable_bytes / 1024, 2),
            "usable_capacity_mb": round(usable_bytes / (1024 * 1024), 2),
        }

    @staticmethod
    def build_packet(
        payload_type: int,
        filename: str,
        salt: bytes,
        nonce: bytes,
        ciphertext_with_tag: bytes
    ) -> bytes:
        """
        Construct binary packet:
        [MAGIC: 10B][VERSION: 1B][TYPE: 1B][FN_LEN: 2B][FN_BYTES: var][SALT: 16B][NONCE: 12B][CT_LEN: 4B][CT: var]
        """
        fn_bytes = filename.encode("utf-8") if filename else b""
        if len(fn_bytes) > 512:
            fn_bytes = fn_bytes[:512]

        fn_len = len(fn_bytes)
        ct_len = len(ciphertext_with_tag)

        header = struct.pack(
            f"!{len(MAGIC_HEADER)}sBBH{fn_len}s{SALT_SIZE_BYTES}s{NONCE_SIZE_BYTES}sI",
            MAGIC_HEADER,
            FORMAT_VERSION,
            payload_type,
            fn_len,
            fn_bytes,
            salt,
            nonce,
            ct_len
        )
        return header + ciphertext_with_tag

    @staticmethod
    def _bytes_to_bits(data: bytes):
        """Generator yielding integer bits (0 or 1) from bytes."""
        for byte in data:
            for shift in range(7, -1, -1):
                yield (byte >> shift) & 1

    @staticmethod
    def encode_packet_into_image(image: Image.Image, packet: bytes) -> Image.Image:
        """
        Embed packet bytes into image pixels using 1-bit LSB replacement across RGB channels.
        Returns a new PIL Image in RGB mode.
        """
        # Ensure image is in RGB mode
        if image.mode != "RGB":
            img = image.convert("RGB")
        else:
            img = image.copy()

        width, height = img.size
        required_bits = len(packet) * 8
        available_bits = width * height * 3

        if required_bits > available_bits:
            raise CapacityExceededError(
                f"Payload size ({len(packet)} bytes = {required_bits} bits) exceeds "
                f"cover image capacity ({available_bits // 8} bytes = {available_bits} bits). "
                f"Please choose a larger cover image or smaller secret data."
            )

        raw_bytes = bytearray(img.tobytes())
        bit_generator = LSBSteganography._bytes_to_bits(packet)

        for i in range(len(raw_bytes)):
            try:
                bit = next(bit_generator)
                raw_bytes[i] = (raw_bytes[i] & ~1) | bit
            except StopIteration:
                break

        stego_img = Image.frombytes("RGB", (width, height), bytes(raw_bytes))
        return stego_img

    @staticmethod
    def decode_packet_from_image(image: Image.Image) -> Tuple[int, str, bytes, bytes, bytes]:
        """
        Extract hidden packet from image pixels.
        Returns: (payload_type, filename, salt, nonce, ciphertext_with_tag)
        """
        if image.mode != "RGB":
            img = image.convert("RGB")
        else:
            img = image

        raw_bytes = img.tobytes()

        def bit_stream():
            for b in raw_bytes:
                yield b & 1

        stream = bit_stream()

        def read_bytes(n: int) -> bytes:
            buf = bytearray(n)
            for i in range(n):
                byte = 0
                for _ in range(8):
                    try:
                        bit = next(stream)
                    except StopIteration:
                        raise StegoError("Premature end of image data.")
                    byte = (byte << 1) | bit
                buf[i] = byte
            return bytes(buf)

        # 1. Read and verify Magic Header
        magic = read_bytes(len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise NoPayloadDetectedError(
                "No hidden AES-256 steganographic payload detected in this image. "
                "Ensure you uploaded the unmodified PNG generated by this system."
            )

        # 2. Read version and payload type
        version_type = read_bytes(2)
        version = version_type[0]
        payload_type = version_type[1]

        if version != FORMAT_VERSION:
            raise StegoError(f"Unsupported packet version: {version}")

        # 3. Read filename length and filename
        fn_len_bytes = read_bytes(2)
        fn_len = struct.unpack("!H", fn_len_bytes)[0]
        filename = ""
        if fn_len > 0:
            fn_bytes = read_bytes(fn_len)
            filename = fn_bytes.decode("utf-8", errors="replace")

        # 4. Read salt (16B), nonce (12B), ciphertext length (4B)
        salt = read_bytes(SALT_SIZE_BYTES)
        nonce = read_bytes(NONCE_SIZE_BYTES)
        ct_len_bytes = read_bytes(4)
        ct_len = struct.unpack("!I", ct_len_bytes)[0]

        # Sanity check ciphertext length against image capacity
        max_possible_ct = (image.width * image.height * 3) // 8
        if ct_len <= 0 or ct_len > max_possible_ct:
            raise StegoError(f"Invalid ciphertext length specified in header: {ct_len} bytes.")

        # 5. Read ciphertext with tag
        ciphertext_with_tag = read_bytes(ct_len)

        return payload_type, filename, salt, nonce, ciphertext_with_tag

    @classmethod
    def hide_text(
        cls,
        cover_image: Image.Image,
        secret_text: str,
        key_or_password: str
    ) -> Tuple[Image.Image, Dict[str, Any]]:
        """
        High-level method: Encrypt secret text with AES-256-GCM and hide into cover image.
        Returns: (stego_image, metadata_dict)
        """
        salt, nonce, ciphertext = encrypt_text(secret_text, key_or_password)
        packet = cls.build_packet(
            payload_type=PAYLOAD_TYPE_TEXT,
            filename="",
            salt=salt,
            nonce=nonce,
            ciphertext_with_tag=ciphertext
        )
        stego_image = cls.encode_packet_into_image(cover_image, packet)

        metadata = {
            "type": "text",
            "plaintext_bytes": len(secret_text.encode("utf-8")),
            "ciphertext_bytes": len(ciphertext),
            "total_packet_bytes": len(packet),
            "capacity_info": cls.get_image_capacity(cover_image),
        }
        return stego_image, metadata

    @classmethod
    def hide_file(
        cls,
        cover_image: Image.Image,
        file_bytes: bytes,
        filename: str,
        key_or_password: str
    ) -> Tuple[Image.Image, Dict[str, Any]]:
        """
        High-level method: Encrypt secret file with AES-256-GCM and hide into cover image.
        Returns: (stego_image, metadata_dict)
        """
        salt, nonce, ciphertext = encrypt_data(file_bytes, key_or_password)
        packet = cls.build_packet(
            payload_type=PAYLOAD_TYPE_FILE,
            filename=filename,
            salt=salt,
            nonce=nonce,
            ciphertext_with_tag=ciphertext
        )
        stego_image = cls.encode_packet_into_image(cover_image, packet)

        metadata = {
            "type": "file",
            "filename": filename,
            "file_size_bytes": len(file_bytes),
            "ciphertext_bytes": len(ciphertext),
            "total_packet_bytes": len(packet),
            "capacity_info": cls.get_image_capacity(cover_image),
        }
        return stego_image, metadata

    @classmethod
    def extract_and_decrypt(
        cls,
        stego_image: Image.Image,
        key_or_password: str
    ) -> Dict[str, Any]:
        """
        High-level method: Extract packet from image and decrypt with AES-256-GCM.
        Returns dictionary containing decrypted data, payload type, and metadata.
        """
        payload_type, filename, salt, nonce, ciphertext = cls.decode_packet_from_image(stego_image)

        # Decrypt using AES-256-GCM
        decrypted_bytes = decrypt_data(salt, nonce, ciphertext, key_or_password)

        if payload_type == PAYLOAD_TYPE_TEXT:
            try:
                decrypted_text = decrypted_bytes.decode("utf-8")
            except UnicodeDecodeError:
                decrypted_text = decrypted_bytes.decode("latin1")

            return {
                "type": "text",
                "text": decrypted_text,
                "bytes_count": len(decrypted_bytes),
                "ciphertext_bytes": len(ciphertext),
                "verified": True,
            }
        else:
            return {
                "type": "file",
                "filename": filename or "extracted_file.bin",
                "file_bytes": decrypted_bytes,
                "file_size": len(decrypted_bytes),
                "ciphertext_bytes": len(ciphertext),
                "verified": True,
            }
