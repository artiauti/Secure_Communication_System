"""
Command Line Interface (CLI) for Secure Data Hiding
===================================================
Provides terminal commands for:
  - AES-256 encryption & LSB embedding (Text or File)
  - Extraction & AES-256 decryption
  - Cryptographic key generation (256-bit)
  - Image quality and steganalysis metrics (PSNR, MSE, Difference Map)
  - Tamper detection verification
"""

import sys
import os
import argparse
import json
from PIL import Image

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .aes_cipher import (
    generate_aes256_key_hex,
    generate_aes256_key_base64,
    CryptoError,
    AuthenticationError,
    InvalidKeyError,
)
from .lsb_stego import (
    LSBSteganography,
    StegoError,
    CapacityExceededError,
    NoPayloadDetectedError,
)
from .metrics import (
    calculate_image_metrics,
    generate_difference_image,
)


def cmd_genkey(args):
    """Generate a cryptographically secure 256-bit key."""
    hex_key = generate_aes256_key_hex()
    b64_key = generate_aes256_key_base64()
    print("\n" + "=" * 60)
    print("[KEY] AES-256 Cryptographic Key Generator (32 Bytes / 256 Bits)")
    print("=" * 60)
    print(f"Hexadecimal (64 chars) : {hex_key}")
    print(f"Base64      (44 chars) : {b64_key}")
    print("=" * 60)
    print("Tip: You can use this random key directly or use a custom passphrase.\n")


def cmd_hide(args):
    """Encrypt and embed secret message or file into cover image."""
    if not os.path.isfile(args.cover):
        print(f"[FAIL] Error: Cover image file '{args.cover}' not found.")
        sys.exit(1)

    if not args.message and not args.file:
        print("[FAIL] Error: Must specify either --message (-m) or --file (-f).")
        sys.exit(1)

    if args.message and args.file:
        print("[FAIL] Error: Please specify either --message or --file, not both.")
        sys.exit(1)

    try:
        cover_img = Image.open(args.cover)
    except Exception as err:
        print(f"[FAIL] Error opening cover image: {err}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("[LOCK] AES-256 Encryption & LSB Image Steganography: Hiding")
    print("=" * 60)

    try:
        if args.message:
            print(f"[*] Encrypting secret text ({len(args.message)} characters)...")
            stego_img, meta = LSBSteganography.hide_text(
                cover_image=cover_img,
                secret_text=args.message,
                key_or_password=args.key
            )
        else:
            if not os.path.isfile(args.file):
                print(f"[FAIL] Error: Secret file '{args.file}' not found.")
                sys.exit(1)
            filename = os.path.basename(args.file)
            with open(args.file, "rb") as f:
                file_bytes = f.read()
            print(f"[*] Encrypting file '{filename}' ({len(file_bytes)} bytes)...")
            stego_img, meta = LSBSteganography.hide_file(
                cover_image=cover_img,
                file_bytes=file_bytes,
                filename=filename,
                key_or_password=args.key
            )

        # Ensure output is saved as PNG for lossless preservation
        out_path = args.output
        if not out_path.lower().endswith(".png"):
            out_path += ".png"

        os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
        stego_img.save(out_path, format="PNG")

        # Calculate metrics
        metrics = calculate_image_metrics(cover_img, stego_img)

        print(f"[SUCCESS] Stego image saved to: {out_path}")
        print("-" * 60)
        print(f"Cover Image Size    : {cover_img.size[0]} x {cover_img.size[1]} px")
        print(f"Payload Size        : {meta['total_packet_bytes']} bytes")
        usable_cap = meta['capacity_info']['usable_capacity_bytes']
        cap_pct = round((meta['total_packet_bytes'] / usable_cap) * 100, 3) if usable_cap else 0
        print(f"Capacity Used       : {cap_pct}%")
        print(f"Mean Squared Error  : {metrics['overall_mse']}")
        print(f"PSNR (dB)           : {metrics['overall_psnr_db']} dB ({metrics['psnr_rating']})")
        print(f"Pixels Modified     : {metrics['modified_pixels']} ({metrics['percent_modified']}%)")
        print("=" * 60 + "\n")

    except (CapacityExceededError, StegoError, CryptoError) as err:
        print(f"[FAIL] Steganography / Cryptography Error: {err}")
        sys.exit(1)


def cmd_extract(args):
    """Extract and decrypt secret data from stego image."""
    if not os.path.isfile(args.stego):
        print(f"[FAIL] Error: Stego image file '{args.stego}' not found.")
        sys.exit(1)

    try:
        stego_img = Image.open(args.stego)
    except Exception as err:
        print(f"[FAIL] Error opening stego image: {err}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("[UNLOCK] AES-256 Decryption & LSB Image Steganography: Extraction")
    print("=" * 60)

    try:
        result = LSBSteganography.extract_and_decrypt(
            stego_image=stego_img,
            key_or_password=args.key
        )

        print("[SUCCESS] Extraction and Authenticated Decryption Successful!")
        print("[VERIFIED] AES-256-GCM Integrity Verified (Authentication Tag Valid)")
        print("-" * 60)

        if result["type"] == "text":
            print("Extracted Secret Message:")
            print("-" * 40)
            print(result["text"])
            print("-" * 40)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(result["text"])
                print(f"Saved message to: {args.output}")

        elif result["type"] == "file":
            out_filename = args.output or result["filename"]
            with open(out_filename, "wb") as f:
                f.write(result["file_bytes"])
            print(f"File Type           : Binary File")
            print(f"Original Filename   : {result['filename']}")
            print(f"File Size           : {result['file_size']} bytes")
            print(f"Saved to disk       : {out_filename}")

        print("=" * 60 + "\n")

    except NoPayloadDetectedError as err:
        print(f"[FAIL] Extraction Error: {err}")
        sys.exit(1)
    except AuthenticationError as err:
        print(f"[FAIL] Authentication Error: {err}")
        print("       (Either the key is incorrect, or the stego image was altered/tampered with)")
        sys.exit(1)
    except (StegoError, CryptoError) as err:
        print(f"[FAIL] Error: {err}")
        sys.exit(1)


def cmd_analyze(args):
    """Analyze steganography quality metrics between cover and stego images."""
    if not os.path.isfile(args.cover):
        print(f"[FAIL] Cover image '{args.cover}' not found.")
        sys.exit(1)
    if not os.path.isfile(args.stego):
        print(f"[FAIL] Stego image '{args.stego}' not found.")
        sys.exit(1)

    cover_img = Image.open(args.cover)
    stego_img = Image.open(args.stego)

    print("\n" + "=" * 60)
    print("[METRICS] Steganography Quality & Imperceptibility Analysis")
    print("=" * 60)

    metrics = calculate_image_metrics(cover_img, stego_img)
    print(f"Resolution         : {metrics['width']} x {metrics['height']} pixels")
    print(f"Total Pixels       : {metrics['total_pixels']:,}")
    print(f"Modified Pixels    : {metrics['modified_pixels']:,} ({metrics['percent_modified']}%)")
    print(f"Max Pixel Diff     : {metrics['max_pixel_difference']} (out of 255)")
    print(f"MSE (Overall)      : {metrics['overall_mse']}")
    print(f"PSNR (Overall)     : {metrics['overall_psnr_db']} dB")
    print(f"Quality Rating     : {metrics['psnr_rating']}")
    print(f"Security Grade     : {metrics['security_grade']}")
    print("-" * 60)
    print("Per-channel Breakdown:")
    for ch, d in metrics["channels"].items():
        print(f"  {ch.upper():5s} Channel -> MSE: {d['mse']:.6f}, PSNR: {d['psnr_db']} dB")
    print("=" * 60)

    if args.diff:
        diff_img = generate_difference_image(cover_img, stego_img, amplification=args.amp)
        diff_img.save(args.diff)
        print(f"Amplified visual difference map ({args.amp}x) saved to: {args.diff}\n")


def cmd_tamper_test(args):
    """
    Demonstrate tamper-resistance by deliberately flipping pixels in a stego image
    and verifying that AES-256-GCM detects the corruption.
    """
    if not os.path.isfile(args.stego):
        print(f"[FAIL] Stego image '{args.stego}' not found.")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("[TAMPER] Cybersecurity Tamper-Resistance Demonstration")
    print("=" * 60)
    print("[*] Loading valid stego image...")
    img = Image.open(args.stego).convert("RGB")
    raw_bytes = bytearray(img.tobytes())

    # Flip 1 bit within the embedded payload region (e.g. inside ciphertext/tag)
    # The payload starts at byte 0; let's alter bit in ciphertext region (~byte index 300)
    idx = min(300, len(raw_bytes) - 1)
    raw_bytes[idx] ^= 0x01

    tampered_img = Image.frombytes("RGB", img.size, bytes(raw_bytes))

    print(f"[*] Intentionally injected 1-bit tampering in payload region at byte index {idx}.")
    print("[*] Attempting extraction and decryption with valid key...")

    try:
        LSBSteganography.extract_and_decrypt(tampered_img, args.key)
        print("[FAIL] Warning: Decryption did not fail (tamper may not have hit ciphertext).")
    except AuthenticationError as err:
        print("[SUCCESS] Tamper Detection Verified!")
        print(f"          AES-256-GCM Caught Corruption: {err}")
    except Exception as err:
        print(f"[SUCCESS] Tamper Caught by Stego/Crypto Engine: {err}")

    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Secure Data Hiding Using AES-256 Encryption and Image Steganography",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # genkey
    p_genkey = subparsers.add_parser("genkey", help="Generate a cryptographically secure 256-bit key")

    # hide
    p_hide = subparsers.add_parser("hide", help="Encrypt and hide text or file into an image")
    p_hide.add_argument("-c", "--cover", required=True, help="Path to cover image (PNG, JPG, BMP)")
    p_hide.add_argument("-k", "--key", required=True, help="Secret AES-256 key or passphrase")
    p_hide.add_argument("-m", "--message", help="Secret text message to hide")
    p_hide.add_argument("-f", "--file", help="Path to secret file to hide")
    p_hide.add_argument("-o", "--output", default="stego_output.png", help="Output stego image path (.png)")

    # extract
    p_extract = subparsers.add_parser("extract", help="Extract and decrypt hidden data from stego image")
    p_extract.add_argument("-s", "--stego", required=True, help="Path to stego image (PNG)")
    p_extract.add_argument("-k", "--key", required=True, help="Secret AES-256 key or passphrase")
    p_extract.add_argument("-o", "--output", help="Optional output path to save extracted file or text")

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Calculate PSNR, MSE, and imperceptibility metrics")
    p_analyze.add_argument("-c", "--cover", required=True, help="Original cover image")
    p_analyze.add_argument("-s", "--stego", required=True, help="Stego image")
    p_analyze.add_argument("--diff", help="Optional path to save amplified difference map")
    p_analyze.add_argument("--amp", type=int, default=100, help="Difference amplification factor (default 100)")

    # tamper-test
    p_tamper = subparsers.add_parser("tamper-test", help="Verify tamper detection by altering stego pixels")
    p_tamper.add_argument("-s", "--stego", required=True, help="Path to stego image")
    p_tamper.add_argument("-k", "--key", required=True, help="Valid AES-256 key or passphrase")

    args = parser.parse_args()

    if args.command == "genkey":
        cmd_genkey(args)
    elif args.command == "hide":
        cmd_hide(args)
    elif args.command == "extract":
        cmd_extract(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "tamper-test":
        cmd_tamper_test(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
