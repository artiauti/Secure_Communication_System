"""
Unit Tests for Secure Data Hiding Using AES-256 and Image Steganography
----------------------------------------------------------------------
Validates:
1. AES-256-GCM authenticated encryption/decryption of text
2. AES-256-GCM encryption/decryption of binary files
3. Key generation (256-bit Hex, Base64)
4. PBKDF2 passphrase derivation
5. Rejection of incorrect keys (AuthenticationError)
6. LSB image steganography embedding & exact recovery of text
7. LSB image steganography embedding & exact recovery of files
8. Cover image capacity boundary enforcement
9. Tamper detection: single-bit modification fails GCM authentication
10. Image quality metrics: PSNR > 50 dB and minimal MSE
"""

import os
import unittest
from io import BytesIO
from PIL import Image

from crypto_stego.aes_cipher import (
    generate_aes256_key,
    generate_aes256_key_hex,
    generate_aes256_key_base64,
    encrypt_text,
    decrypt_text,
    encrypt_data,
    decrypt_data,
    AuthenticationError,
    InvalidKeyError,
)
from crypto_stego.lsb_stego import (
    LSBSteganography,
    CapacityExceededError,
    NoPayloadDetectedError,
)
from crypto_stego.metrics import (
    calculate_mse,
    calculate_psnr,
    calculate_image_metrics,
    generate_difference_image,
)


class TestAES256Cipher(unittest.TestCase):

    def test_key_generation(self):
        raw_key = generate_aes256_key()
        self.assertEqual(len(raw_key), 32)

        hex_key = generate_aes256_key_hex()
        self.assertEqual(len(hex_key), 64)

        b64_key = generate_aes256_key_base64()
        self.assertEqual(len(b64_key), 44)

    def test_text_encryption_decryption_with_passphrase(self):
        message = "Classified Intelligence: Operation CyberShield 2026."
        passphrase = "UltraSecurePassword@2026!#"

        salt, nonce, ciphertext = encrypt_text(message, passphrase)
        recovered = decrypt_text(salt, nonce, ciphertext, passphrase)

        self.assertEqual(recovered, message)

    def test_text_encryption_decryption_with_hex_key(self):
        message = "Top Secret AES-256 Payload."
        hex_key = generate_aes256_key_hex()

        salt, nonce, ciphertext = encrypt_text(message, hex_key)
        recovered = decrypt_text(salt, nonce, ciphertext, hex_key)

        self.assertEqual(recovered, message)

    def test_wrong_key_fails_authentication(self):
        message = "Critical defense credentials."
        correct_key = "CorrectPassphrase123"
        wrong_key = "WrongPassphrase999"

        salt, nonce, ciphertext = encrypt_text(message, correct_key)

        with self.assertRaises(AuthenticationError):
            decrypt_text(salt, nonce, ciphertext, wrong_key)

    def test_ciphertext_tampering_fails(self):
        message = "Financial transactions records."
        key = "CryptoKey777"

        salt, nonce, ciphertext = encrypt_text(message, key)

        # Alter one byte of the ciphertext
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0x01

        with self.assertRaises(AuthenticationError):
            decrypt_text(salt, nonce, bytes(tampered_ct), key)


class TestLSBSteganography(unittest.TestCase):

    def setUp(self):
        # Create a synthetic 100x100 RGB test image
        self.cover_img = Image.new("RGB", (100, 100), color=(128, 64, 200))
        # Add slight gradient
        pixels = []
        for y in range(100):
            for x in range(100):
                pixels.append(((x * 2) % 256, (y * 2) % 256, (x + y) % 256))
        self.cover_img.putdata(pixels)

    def test_capacity_calculation(self):
        cap = LSBSteganography.get_image_capacity(self.cover_img)
        # 100 x 100 x 3 bits = 30,000 bits = 3,750 bytes
        self.assertEqual(cap["total_capacity_bytes"], 3750)
        self.assertTrue(cap["usable_capacity_bytes"] > 3600)

    def test_hide_and_extract_text(self):
        secret = "Department of Defense: Quantum Encryption Directive 404"
        key = "SuperSecretStegoKey"

        stego_img, meta = LSBSteganography.hide_text(self.cover_img, secret, key)
        self.assertIsNotNone(stego_img)

        # Extract
        result = LSBSteganography.extract_and_decrypt(stego_img, key)
        self.assertEqual(result["type"], "text")
        self.assertEqual(result["text"], secret)
        self.assertTrue(result["verified"])

    def test_hide_and_extract_file(self):
        dummy_file_bytes = b"%PDF-1.4 Fake confidential document content \x00\xFF\xFE\xAA" * 10
        filename = "mission_brief.pdf"
        key = "MilitaryGradeKey"

        stego_img, meta = LSBSteganography.hide_file(
            self.cover_img, dummy_file_bytes, filename, key
        )

        result = LSBSteganography.extract_and_decrypt(stego_img, key)
        self.assertEqual(result["type"], "file")
        self.assertEqual(result["filename"], filename)
        self.assertEqual(result["file_bytes"], dummy_file_bytes)
        self.assertTrue(result["verified"])

    def test_wrong_key_on_stego_image_fails(self):
        secret = "Nuclear launch protocols"
        key = "ValidKeyAlpha"
        wrong_key = "InvalidKeyBeta"

        stego_img, _ = LSBSteganography.hide_text(self.cover_img, secret, key)

        with self.assertRaises(AuthenticationError):
            LSBSteganography.extract_and_decrypt(stego_img, wrong_key)

    def test_clean_cover_image_has_no_payload(self):
        clean_img = Image.new("RGB", (50, 50), color=(10, 20, 30))
        with self.assertRaises(NoPayloadDetectedError):
            LSBSteganography.extract_and_decrypt(clean_img, "AnyKey")

    def test_capacity_exceeded_error(self):
        tiny_img = Image.new("RGB", (10, 10))  # 100 px * 3 bits = 300 bits = 37 bytes
        huge_payload = "A" * 500  # 500 bytes exceeds 37 bytes
        with self.assertRaises(CapacityExceededError):
            LSBSteganography.hide_text(tiny_img, huge_payload, "Key")


class TestMetrics(unittest.TestCase):

    def test_identical_images_have_zero_mse(self):
        img = Image.new("RGB", (50, 50), color=(100, 150, 200))
        mse = calculate_mse(img, img)
        self.assertEqual(mse, 0.0)

        psnr = calculate_psnr(img, img)
        self.assertGreaterEqual(psnr, 99.0)

    def test_stego_imperceptibility_quality(self):
        cover = Image.new("RGB", (200, 200), color=(75, 125, 175))
        secret = "Cybersecurity is the practice of protecting critical systems."
        key = "SecretPass"

        stego, _ = LSBSteganography.hide_text(cover, secret, key)

        metrics = calculate_image_metrics(cover, stego)
        # PSNR should be > 55 dB for 1-LSB steganography
        self.assertGreater(metrics["overall_psnr_db"], 55.0)
        self.assertLess(metrics["overall_mse"], 0.1)
        self.assertEqual(metrics["security_grade"], "A+")

        # Test difference map creation
        diff = generate_difference_image(cover, stego, amplification=50)
        self.assertEqual(diff.size, cover.size)


if __name__ == "__main__":
    unittest.main()
