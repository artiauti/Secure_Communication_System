# Secure Communication and Image Steganography Project Report

## 1. Project overview

This project is a Python web application for private messaging and image-based
data hiding. It provides two related workflows:

1. **Secure chat:** registered users can send text messages and optionally
   attach an image. When an image is attached, the app encrypts the message
   for the selected recipient, embeds the encrypted package into a PNG, and
   stores the resulting image with the message.
2. **Steganography workspace:** users can encrypt text or a file with a
   passphrase/key, hide the encrypted payload in an image, then upload the
   resulting PNG to extract and decrypt the payload. It also reports image
   capacity and quality metrics.

The home workspace presents the encryption and hiding tool first. A separate
chat extraction page explains how to recover recipient-bound secure images.

## 2. Problem addressed and solution

Messages sent over ordinary channels can be readable or reveal that a message
was exchanged. This application demonstrates two protections:

- **Confidentiality:** encrypt the message or file so its contents are not
  directly readable from the stored payload.
- **Concealment:** encode encrypted data in the least significant bits of an
  image's RGB channels, then save the carrier as PNG to preserve those bits.

The image-embedding feature is not a replacement for secure key management.
Successful recovery depends on the correct key and, for chat images, the
recipient account's original private key.

## 3. Implemented workflows

### 3.1 Secure chat image messages

1. A user selects a recipient and sends a message with an optional cover image.
2. For an image message, the app generates a random AES-256 key and encrypts
   the message using AES-CBC with PKCS#7 padding.
3. The AES key is encrypted with the recipient's RSA public key using
   OAEP-SHA256.
4. The encrypted payload is compressed, encoded, and embedded into the cover
   image using LSB steganography. The output is a PNG.
5. The recipient downloads and uploads the **original, unmodified PNG** while
   signed into the intended account. The app extracts the payload, uses that
   account's private key to unwrap the AES key, and decrypts the message.

Chat messages without an image are encrypted for the recipient and stored in
the chat database, but they do not contain an image payload and cannot be
recovered through the secure-image upload page.

### 3.2 AES-GCM steganography workspace

The separate steganography module supports hiding and recovering both text
and binary files. It generates 256-bit AES keys or derives keys from a
passphrase using PBKDF2-HMAC-SHA256, then encrypts with AES-256-GCM. The
ciphertext and metadata are packaged and embedded into RGB image data using
1-bit LSB encoding. The app also calculates MSE/PSNR and generates an
amplified difference image for analysis.

This workspace is a distinct implementation from the recipient-bound chat
workflow: it uses a user-supplied secret key and AES-GCM, while secure chat
uses recipient RSA keys and AES-CBC for message encryption. These workflows
should not be described as using the same encryption mode.

## 4. Technologies and tools

| Area | Technology |
|---|---|
| Programming language | Python |
| Web framework and routes | Flask |
| User authentication | Flask-Login, Flask-WTF, WTForms |
| Database and migrations | SQLite, Flask-SQLAlchemy, Flask-Migrate |
| Real-time chat | Flask-SocketIO |
| Scheduled cleanup | Flask-APScheduler |
| Cryptography | Python `cryptography` package; AES-256-GCM in the steganography module; AES-256-CBC and RSA-OAEP-SHA256 in secure chat |
| Image processing | Pillow |
| User interface | HTML, CSS, JavaScript, Bootstrap 5; Font Awesome and Google Fonts are loaded from CDNs |
| Automated verification | Python `unittest` |
| Command-line functionality | `crypto_stego.cli` |

## 5. Main project components

- `app.py` — Flask application, authentication, chat, image upload/download,
  encryption/decryption, steganography API, and scheduled message cleanup.
- `crypto_stego/aes_cipher.py` — AES-GCM encryption, 256-bit key generation,
  and PBKDF2 key derivation.
- `crypto_stego/lsb_stego.py` — image capacity calculation, LSB packet
  embedding/extraction, and text/file payload handling.
- `crypto_stego/metrics.py` — MSE, PSNR, bit-error measurements, and
  difference-image generation.
- `crypto_stego/cli.py` — command-line key generation, hide/extract, analysis,
  and tamper-test commands.
- `templates/` — Flask-rendered pages for the workspace, chat, login, signup,
  and secure-image extraction.
- `tests/test_crypto_stego.py` — cryptography, steganography, capacity, and
  image-metric tests.
- `tests/test_flask_routes.py` — Flask route and API integration tests.

## 6. Implemented features

- Account signup/login and per-user RSA public/private keys.
- Recipient-bound encrypted chat messages with optional secure PNG image
  generation.
- Secure PNG download and authenticated extraction/decryption route.
- Separate AES-GCM tools for text and file payloads.
- Cryptographic key generation and passphrase-based key derivation.
- Image capacity checks and PNG output for lossless payload preservation.
- Image quality analysis, including MSE/PSNR and difference-map generation.
- A command-line interface for core AES-GCM and steganography operations.
- Error handling for missing payloads, wrong keys, invalid images, damaged
  payloads, and unsupported image formats.

## 7. Important operating requirements and limitations

- Secure chat image extraction requires the original secure PNG generated by
  this app. JPEG conversion, image editing, or re-saving can destroy embedded
  LSB data.
- The user must upload a chat image while signed into its intended recipient
  account. The sender is not configured as an additional decrypting party.
- If the recipient account's private key is lost or replaced, the old
  recipient-bound image cannot be decrypted. The sender must send a new
  secure image.
- Text-only chat messages do not contain an image payload.
- Cover image size limits the maximum embedded payload.
- The AES-CBC chat encryption branch does not use an authenticated-encryption
  mode. The separate AES-GCM steganography module does provide authenticated
  encryption and detects an incorrect key or modified ciphertext. These
  designs are distinct; the CBC path should not be represented as having
  AES-GCM's authentication guarantees.
- Database private-key storage and deployment secrets require production
  hardening before use with real sensitive data. The development default
  application secret must be replaced for deployment.

## 8. Running the project

From the project root on Windows:

```powershell
venv\Scripts\python.exe app.py
```

Then open:

```text
http://127.0.0.1:5000/
```

To run the automated tests:

```powershell
venv\Scripts\python.exe -m unittest discover -s tests
```

## 9. Verification performed

The test suite was run using the project's virtual environment: **18 tests
passed**. The Flask home page was also started and checked locally; it returned
HTTP 200 and rendered the Secure Message Workspace. The updated Flask route
tests passed after the white-background workspace changes.

## 10. Summary

The project combines user accounts and recipient-bound chat with a separate
AES-GCM image-steganography workspace. The chat workflow demonstrates sending
a message concealed in an image and restricting recovery to the intended
recipient. The standalone workspace demonstrates key-based encryption,
text/file embedding, extraction, and image-quality analysis. The tests verify
core encryption, recovery, tamper/wrong-key handling, image capacity, metrics,
and the Flask endpoints.
