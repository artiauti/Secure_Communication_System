import os
import io
import json
import base64
import logging
import zlib
import zipfile
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, jsonify, session, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from flask_socketio import SocketIO
from flask_migrate import Migrate
from flask_apscheduler import APScheduler
from flask_wtf.csrf import CSRFProtect, generate_csrf

from PIL import Image

from crypto_stego import (
    generate_aes256_key_hex,
    generate_aes256_key_base64,
    LSBSteganography,
    calculate_image_metrics,
    generate_difference_image,
    AuthenticationError,
    NoPayloadDetectedError,
    CapacityExceededError,
    CryptoError,
    StegoError,
)

# APP CONFIGURATION
# ---------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

app = Flask(__name__)

# Change this in a real deployment.
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-for-production"
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp"}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False
)
csrf = CSRFProtect(app)

scheduler = APScheduler()


# ---------------------------------------------------------------------
# DATABASE MODELS
# ---------------------------------------------------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # AES-CBC data
    iv = db.Column(db.Text, nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)

    # AES key encrypted with receiver's RSA public key
    encrypted_aes_key = db.Column(db.Text, nullable=False)

    # Secure/stego image filename
    image = db.Column(db.String(256), nullable=True)

    # Kept for compatibility with the original repository.
    # The new secure workflow does NOT depend on this field for decryption.
    content = db.Column(db.Text, nullable=True)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship(
        "User",
        foreign_keys=[sender_id],
        backref="sent_messages"
    )
    receiver = db.relationship(
        "User",
        foreign_keys=[receiver_id],
        backref="received_messages"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "timestamp": self.timestamp.isoformat(),
            "content": self.content,
            "image": self.image
        }


# ---------------------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------------------

@app.before_request
def create_tables():
    db.create_all()


# ---------------------------------------------------------------------
# GENERAL HELPERS
# ---------------------------------------------------------------------

def allowed_file(filename):
    return (
        bool(filename)
        and "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------

def generate_rsa_key_pair():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode("utf-8")

    return private_key, public_key


def load_private_key(private_key_text):
    return serialization.load_pem_private_key(
        private_key_text.encode("utf-8"),
        password=None,
        backend=default_backend()
    )


def rsa_encrypt(public_key_str, data):
    public_key = serialization.load_ssh_public_key(
        public_key_str.encode("utf-8"),
        backend=default_backend()
    )

    encrypted_data = public_key.encrypt(
        data,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted_data).decode("utf-8")


def rsa_decrypt(private_key_text, encrypted_data_b64):
    private_key = load_private_key(private_key_text)

    encrypted_data = base64.b64decode(encrypted_data_b64)

    return private_key.decrypt(
        encrypted_data,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ---------------------------------------------------------------------
# AES-256-CBC
# ---------------------------------------------------------------------

def aes_encrypt(key, message):
    iv = os.urandom(16)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return (
        base64.b64encode(iv).decode("utf-8"),
        base64.b64encode(ciphertext).decode("utf-8")
    )


def aes_decrypt(key, iv_b64, ciphertext_b64):
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode("utf-8")


# ---------------------------------------------------------------------
# LSB STEGANOGRAPHY
#
# Format stored in image:
#
#   32-bit unsigned length
#   +
#   UTF-8 payload bytes
#
# Only the RGB least significant bits are changed.
# PNG is recommended because JPEG compression can destroy LSB data.
# ---------------------------------------------------------------------

class Stegno:

    HEADER_SIZE_BITS = 32

    @staticmethod
    def _bytes_to_bits(data):
        bits = []
        for byte in data:
            bits.extend(
                int(bit) for bit in f"{byte:08b}"
            )
        return bits

    @staticmethod
    def _bits_to_bytes(bits):
        if len(bits) % 8 != 0:
            raise ValueError("Invalid hidden data length.")

        output = bytearray()

        for i in range(0, len(bits), 8):
            value = 0
            for bit in bits[i:i + 8]:
                value = (value << 1) | bit
            output.append(value)

        return bytes(output)

    @staticmethod
    def capacity_bytes(image):
        # RGB image: 3 usable LSBs per pixel.
        # 32 bits are reserved for payload length.
        width, height = image.size
        capacity_bits = width * height * 3 - Stegno.HEADER_SIZE_BITS

        if capacity_bits <= 0:
            return 0

        return capacity_bits // 8

    @staticmethod
    def encode(image_path, output_path, secret_data):
        if secret_data is None:
            raise ValueError("Data is empty.")

        payload = secret_data.encode("utf-8")
        image = Image.open(image_path).convert("RGB")

        capacity = Stegno.capacity_bytes(image)

        if len(payload) > capacity:
            raise ValueError(
                f"Message is too large for this image. "
                f"Payload: {len(payload)} bytes, "
                f"available: {capacity} bytes."
            )

        # 32-bit payload length followed by payload.
        data = len(payload).to_bytes(4, byteorder="big") + payload
        bits = Stegno._bytes_to_bits(data)

        pixels = list(image.getdata())
        new_pixels = []

        bit_index = 0

        for pixel in pixels:
            rgb = list(pixel)

            for channel in range(3):
                if bit_index < len(bits):
                    rgb[channel] = (
                        rgb[channel] & 0xFE
                    ) | bits[bit_index]
                    bit_index += 1

            new_pixels.append(tuple(rgb))

        result = Image.new("RGB", image.size)
        result.putdata(new_pixels)

        # Always save as PNG for reliable LSB preservation.
        result.save(output_path, "PNG")

    @staticmethod
    def decode(image_path):
        image = Image.open(image_path).convert("RGB")
        pixels = list(image.getdata())

        bits = []

        # First read 32-bit payload length.
        for pixel in pixels:
            for channel in range(3):
                bits.append(pixel[channel] & 1)

                if len(bits) == Stegno.HEADER_SIZE_BITS:
                    break

            if len(bits) == Stegno.HEADER_SIZE_BITS:
                break

        if len(bits) < Stegno.HEADER_SIZE_BITS:
            raise ValueError("Image does not contain a valid hidden message.")

        length_bytes = Stegno._bits_to_bytes(bits)
        payload_length = int.from_bytes(length_bytes, byteorder="big")

        capacity = Stegno.capacity_bytes(image)

        if payload_length <= 0 or payload_length > capacity:
            raise ValueError("Invalid hidden message or wrong image.")

        required_bits = Stegno.HEADER_SIZE_BITS + payload_length * 8

        bits = []
        for pixel in pixels:
            for channel in range(3):
                bits.append(pixel[channel] & 1)

                if len(bits) >= required_bits:
                    break

            if len(bits) >= required_bits:
                break

        if len(bits) < required_bits:
            raise ValueError("Image does not contain the complete hidden message.")

        payload_bits = bits[Stegno.HEADER_SIZE_BITS:required_bits]
        payload = Stegno._bits_to_bytes(payload_bits)

        return payload.decode("utf-8")


# ---------------------------------------------------------------------
# ENCRYPTED PAYLOAD
#
# This is what is hidden inside the image:
#
# {
#   "version": 1,
#   "iv": "...",
#   "ciphertext": "...",
#   "encrypted_aes_key": "..."
# }
# ---------------------------------------------------------------------

def create_encrypted_payload(receiver, plaintext):
    if not plaintext:
        raise ValueError("Secret message cannot be empty.")

    # AES-256 key
    aes_key = os.urandom(32)

    # Encrypt plaintext with AES-256-CBC
    iv, ciphertext = aes_encrypt(
        aes_key,
        plaintext.encode("utf-8")
    )

    # Protect AES key with receiver's RSA public key
    encrypted_aes_key = rsa_encrypt(
        receiver.public_key,
        aes_key
    )

    payload = {
        "version": 1,
        "algorithm": "AES-256-CBC + RSA-OAEP-SHA256",
        "iv": iv,
        "ciphertext": ciphertext,
        "encrypted_aes_key": encrypted_aes_key
    }

    return payload, aes_key


class InvalidEncryptedPayloadError(ValueError):
    pass


class RecipientKeyError(ValueError):
    pass


def decrypt_payload(payload, receiver):
    required = {
        "version",
        "iv",
        "ciphertext",
        "encrypted_aes_key"
    }

    if not isinstance(payload, dict) or not required.issubset(payload):
        raise InvalidEncryptedPayloadError("Invalid encrypted payload.")

    try:
        aes_key = rsa_decrypt(
            receiver.private_key,
            payload["encrypted_aes_key"]
        )
    except (TypeError, ValueError) as error:
        raise RecipientKeyError(
            "This secure image was encrypted for a different account, "
            "or this account's private key has changed."
        ) from error

    try:
        return aes_decrypt(
            aes_key,
            payload["iv"],
            payload["ciphertext"]
        )
    except (TypeError, ValueError, UnicodeDecodeError) as error:
        raise InvalidEncryptedPayloadError(
            "The encrypted message data is damaged or invalid."
        ) from error


# ---------------------------------------------------------------------
# AUTHENTICATION
# ---------------------------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    # Keep compatibility with the original forms.py.
    from forms import SignupForm

    form = SignupForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash(
                "Username already exists. Please choose a different one.",
                "danger"
            )
            return render_template("signup.html", form=form)

        try:
            private_key, public_key = generate_rsa_key_pair()

            new_user = User(
                username=username,
                password=generate_password_hash(
                    password,
                    method="pbkdf2:sha256"
                ),
                public_key=public_key,
                private_key=private_key
            )

            db.session.add(new_user)
            db.session.commit()

            flash("Signup successful, please login!", "success")
            return redirect(url_for("login"))

        except Exception:
            db.session.rollback()
            logging.exception("Error during signup")
            flash("Error during signup. Please try again.", "danger")

    return render_template("signup.html", form=form)


# ---------------------------------------------------------------------
# CYBERSECURITY SUITE: AES-256 ENCRYPTION & IMAGE STEGANOGRAPHY
# ---------------------------------------------------------------------

@app.route("/")
def index():
    """Main Cybersecurity Solution Portal."""
    return render_template(
        "index.html",
        current_user=current_user,
        csrf_token=generate_csrf()
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    from forms import LoginForm

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(
            username=form.username.data.strip()
        ).first()

        if user and check_password_hash(
            user.password,
            form.password.data
        ):
            login_user(user)
            return redirect(url_for("chat"))

        flash(
            "Login Unsuccessful. Please check username and password.",
            "danger"
        )

    return render_template("login.html", form=form)


# ---------------------------------------------------------------------
# STEGANOGRAPHY & AES-256 REST APIS
# ---------------------------------------------------------------------

@app.route("/api/stego/generate-key", methods=["GET"])
@csrf.exempt
def api_generate_key():
    return jsonify({
        "status": "success",
        "hex_key": generate_aes256_key_hex(),
        "base64_key": generate_aes256_key_base64()
    })


@app.route("/api/stego/capacity", methods=["POST"])
@csrf.exempt
def api_image_capacity():
    file = request.files.get("cover_image")
    if not file or not file.filename:
        return jsonify({"error": "No cover image provided"}), 400
    try:
        img = Image.open(file.stream)
        cap = LSBSteganography.get_image_capacity(img)
        return jsonify(cap)
    except Exception as e:
        return jsonify({"error": f"Invalid image: {str(e)}"}), 400


@app.route("/api/stego/hide", methods=["POST"])
@csrf.exempt
def api_stego_hide():
    cover_file = request.files.get("cover_image")
    key = request.form.get("key", "").strip()
    payload_type = request.form.get("payload_type", "text")

    if not cover_file or not cover_file.filename:
        return jsonify({"error": "Cover image is required."}), 400
    if not key:
        return jsonify({"error": "AES-256 secret key is required."}), 400

    try:
        cover_img = Image.open(cover_file.stream)
        timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

        if payload_type == "text":
            secret_text = request.form.get("secret_text", "").strip()
            if not secret_text:
                return jsonify({"error": "Secret text cannot be empty."}), 400
            stego_img, meta = LSBSteganography.hide_text(cover_img, secret_text, key)
            out_filename = f"stego_text_{timestamp}.png"
        else:
            secret_file = request.files.get("secret_file")
            if not secret_file or not secret_file.filename:
                return jsonify({"error": "Secret file is required."}), 400
            file_bytes = secret_file.read()
            filename = secure_filename(secret_file.filename) or "secret_payload.bin"
            stego_img, meta = LSBSteganography.hide_file(cover_img, file_bytes, filename, key)
            out_filename = f"stego_file_{timestamp}.png"

        out_path = os.path.join(app.config["UPLOAD_FOLDER"], out_filename)
        stego_img.save(out_path, format="PNG")

        metrics = calculate_image_metrics(cover_img, stego_img)
        usable_cap = meta["capacity_info"]["usable_capacity_bytes"]
        cap_pct = round((meta["total_packet_bytes"] / usable_cap) * 100, 3) if usable_cap else 0

        return jsonify({
            "status": "success",
            "stego_image_url": f"/static/uploads/{out_filename}",
            "filename": out_filename,
            "payload_bytes": meta["total_packet_bytes"],
            "capacity_used_pct": cap_pct,
            "metrics": metrics
        })

    except CapacityExceededError as e:
        return jsonify({"error": str(e)}), 400
    except (CryptoError, StegoError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.exception("Error in api_stego_hide")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@app.route("/api/stego/extract", methods=["POST"])
@csrf.exempt
def api_stego_extract():
    stego_file = request.files.get("stego_image")
    key = request.form.get("key", "").strip()

    if not stego_file or not stego_file.filename:
        return jsonify({"error": "Stego image (PNG) is required."}), 400
    if not key:
        return jsonify({"error": "Secret key is required."}), 400

    try:
        stego_img = Image.open(stego_file.stream)
        result = LSBSteganography.extract_and_decrypt(stego_img, key)

        if result["type"] == "text":
            return jsonify({
                "status": "success",
                "type": "text",
                "text": result["text"],
                "bytes_count": result["bytes_count"],
                "verified": True
            })
        else:
            timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
            safe_fn = secure_filename(result["filename"]) or f"extracted_{timestamp}.bin"
            save_name = f"recovered_{timestamp}_{safe_fn}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], save_name)

            with open(save_path, "wb") as f:
                f.write(result["file_bytes"])

            return jsonify({
                "status": "success",
                "type": "file",
                "filename": result["filename"],
                "file_size": result["file_size"],
                "download_url": f"/download/recovered/{save_name}",
                "verified": True
            })

    except NoPayloadDetectedError as e:
        return jsonify({"error": str(e)}), 400
    except AuthenticationError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.exception("Error in api_stego_extract")
        return jsonify({"error": f"Extraction error: {str(e)}"}), 400


@app.route("/download/recovered/<filename>")
def download_recovered_file(filename):
    safe_fn = secure_filename(filename)
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        safe_fn,
        as_attachment=True
    )


@app.route("/api/stego/analyze", methods=["POST"])
@csrf.exempt
def api_stego_analyze():
    cover_file = request.files.get("cover_image")
    stego_file = request.files.get("stego_image")
    amp = int(request.form.get("amplification", 100))

    if not cover_file or not stego_file:
        return jsonify({"error": "Both cover and stego images are required."}), 400

    try:
        cover_img = Image.open(cover_file.stream)
        stego_img = Image.open(stego_file.stream)

        metrics = calculate_image_metrics(cover_img, stego_img)
        diff_img = generate_difference_image(cover_img, stego_img, amplification=amp)

        timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
        diff_filename = f"diff_{timestamp}.png"
        diff_path = os.path.join(app.config["UPLOAD_FOLDER"], diff_filename)
        diff_img.save(diff_path, format="PNG")

        return jsonify({
            "status": "success",
            "diff_image_url": f"/static/uploads/{diff_filename}",
            "metrics": metrics
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/stego/download-sample")
def api_download_sample():
    sample_path = os.path.join(BASE_DIR, "sample_data", "cover_sample.png")
    if os.path.exists(sample_path):
        return send_from_directory(
            os.path.join(BASE_DIR, "sample_data"),
            "cover_sample.png",
            as_attachment=True,
            download_name="cover_sample.png"
        )
    return jsonify({"error": "Sample file not found"}), 404



@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out!", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------
# CHAT
# ---------------------------------------------------------------------

@app.route("/chat", defaults={"selected_user_id": None})
@app.route("/chat/<int:selected_user_id>", methods=["GET", "POST"])
@login_required
def chat(selected_user_id):
    try:
        from forms import LogoutForm

        users = User.query.filter(User.id != current_user.id).all()
        messages = []
        selected_chat = None

        if selected_user_id:
            selected_chat = db.session.get(User, selected_user_id)

            if not selected_chat:
                flash("User not found.", "danger")
                return redirect(url_for("chat"))

            messages = Message.query.filter(
                (
                    (Message.sender_id == current_user.id)
                    &
                    (Message.receiver_id == selected_user_id)
                )
                |
                (
                    (Message.sender_id == selected_user_id)
                    &
                    (Message.receiver_id == current_user.id)
                )
            ).order_by(Message.timestamp.asc()).all()

        form = LogoutForm()

        return render_template(
            "chat.html",
            users=users,
            messages=messages,
            selected_chat=selected_chat,
            form=form,
            current_user=current_user,
            csrf_token=generate_csrf()
        )

    except Exception:
        logging.exception("Error in chat route")
        flash(
            "Error retrieving chat data. Please try again later.",
            "danger"
        )
        return redirect(url_for("login"))


# ---------------------------------------------------------------------
# SEND MESSAGE
#
# IMPORTANT:
# The secure version hides the ENCRYPTED payload in the image,
# not the plaintext message.
# ---------------------------------------------------------------------

@app.route("/send_message", methods=["POST"])
@login_required
def send_message():
    receiver_id = request.form.get("receiver_id")
    content = request.form.get("message", "").strip()
    image_file = request.files.get("image")

    if not receiver_id:
        return jsonify({
            "status": "Error",
            "message": "Receiver is required."
        }), 400

    if not content:
        return jsonify({
            "status": "Error",
            "message": "Message cannot be empty."
        }), 400

    try:
        receiver = db.session.get(User, int(receiver_id))

        if not receiver:
            return jsonify({
                "status": "Error",
                "message": "Receiver not found."
            }), 404

        image_filename = None

        # Image is required for the secure-image workflow.
        if image_file and image_file.filename:
            if not allowed_file(image_file.filename):
                return jsonify({
                    "status": "Error",
                    "message": "Unsupported image type. Use PNG, JPG, JPEG, or GIF."
                }), 400

            original_filename = secure_filename(image_file.filename)

            # Always use PNG output because LSB data can be damaged by JPEG.
            original_stem = os.path.splitext(original_filename)[0]
            encoded_filename = (
                f"secure_{original_stem}_{int(datetime.utcnow().timestamp())}.png"
            )

            original_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                f"source_{encoded_filename}"
            )

            encoded_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                encoded_filename
            )

            image_file.save(original_path)

            # 1. AES encrypt plaintext
            # 2. RSA encrypt AES key
            # 3. Create JSON encrypted payload
            payload, aes_key = create_encrypted_payload(
                receiver,
                content
            )

            payload_text = json.dumps(
                payload,
                separators=(",", ":")
            )

            # Compress the encrypted package before LSB encoding.
            # This reduces the amount of image capacity required.
            compressed_payload = zlib.compress(
                payload_text.encode("utf-8"),
                level=9
            )
            payload_for_lsb = base64.b64encode(
                compressed_payload
            ).decode("ascii")

            # 4. Hide the ENCRYPTED payload inside the image using LSB.
            Stegno.encode(
                original_path,
                encoded_path,
                payload_for_lsb
            )

            image_filename = encoded_filename

            # Remove source image after creating secure image.
            try:
                os.remove(original_path)
            except OSError:
                pass

            iv = payload["iv"]
            ciphertext = payload["ciphertext"]
            encrypted_aes_key = payload["encrypted_aes_key"]

        else:
            # Preserve text-only chat functionality.
            aes_key = os.urandom(32)

            iv, ciphertext = aes_encrypt(
                aes_key,
                content.encode("utf-8")
            )

            encrypted_aes_key = rsa_encrypt(
                receiver.public_key,
                aes_key
            )

        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            iv=iv,
            ciphertext=ciphertext,
            encrypted_aes_key=encrypted_aes_key,
            image=image_filename,

            # Do not store the plaintext for secure-image messages.
            # The original message is recovered only after decryption.
            content=(
                "[Encrypted secure message]"
                if image_filename
                else content
            )
        )

        db.session.add(message)
        db.session.commit()

        socketio.emit(
            "message",
            {
                "sender": {
                    "id": current_user.id,
                    "username": current_user.username
                },
                "sender_id": current_user.id,
                "receiver_id": receiver.id,
                "content": (
                    "[Encrypted secure message]"
                    if image_filename
                    else content
                ),
                "image": bool(image_filename),
                "image_url": image_filename
            }
        )

        return jsonify({
            "status": "Message sent successfully",
            "image_url": image_filename
        })

    except ValueError as e:
        db.session.rollback()

        logging.error("Validation error sending message: %s", e)

        return jsonify({
            "status": "Error",
            "message": str(e)
        }), 400

    except Exception:
        db.session.rollback()

        logging.exception("Error sending message")

        return jsonify({
            "status": "Error",
            "message": "Could not send message due to a server error. Please try again."
        }), 500


# ---------------------------------------------------------------------
# SECURE IMAGE PAGE
#
# The existing chat UI can continue working.
# This route provides a dedicated extraction/decryption workflow.
# ---------------------------------------------------------------------

@app.route("/secure")
@login_required
def secure_page():
    return render_template(
        "secure.html",
        current_user=current_user,
        csrf_token=generate_csrf()
    )


@app.route("/api/users", methods=["GET"])
@login_required
def api_users():
    users = User.query.filter(
        User.id != current_user.id
    ).order_by(User.username.asc()).all()

    return jsonify([
        {
            "id": user.id,
            "username": user.username
        }
        for user in users
    ])


# ---------------------------------------------------------------------
# DOWNLOAD SECURE IMAGE
# ---------------------------------------------------------------------

@app.route("/download/<filename>")
@login_required
def download_secure_image(filename):
    filename = secure_filename(filename)

    if not filename.startswith("secure_"):
        return jsonify({
            "status": "Error",
            "message": "Invalid secure image."
        }), 400

    full_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    if not os.path.isfile(full_path):
        return jsonify({
            "status": "Error",
            "message": "Secure image not found."
        }), 404

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        as_attachment=True,
        download_name=filename
    )


# ---------------------------------------------------------------------
# EXTRACT + DECRYPT SECURE IMAGE
#
# The logged-in user must be the intended receiver because the
# AES key was encrypted using that user's RSA public key.
# ---------------------------------------------------------------------

@app.route("/decode_image", methods=["POST"])
@login_required
def decode_image():
    image_file = request.files.get("image")

    if not image_file or not image_file.filename:
        return jsonify({
            "status": "Error",
            "message": "Please select a secure image."
        }), 400

    if not allowed_file(image_file.filename):
        return jsonify({
            "status": "Error",
            "message": "Invalid image file."
        }), 400

    if image_file.filename.rsplit(".", 1)[1].lower() != "png":
        return jsonify({
            "status": "Error",
            "message": (
                "Secure images must be PNG files generated by this app. "
                "Original JPEG or GIF images cannot be extracted."
            )
        }), 400

    safe_filename = secure_filename(image_file.filename)

    temporary_filename = (
        f"decode_{int(datetime.utcnow().timestamp() * 1000)}_"
        f"{safe_filename}"
    )

    image_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        temporary_filename
    )

    try:
        image_file.save(image_path)

        try:
            with Image.open(image_path) as uploaded_image:
                if uploaded_image.format != "PNG":
                    return jsonify({
                        "status": "Error",
                        "message": (
                            "Secure images must be unmodified PNG files "
                            "generated by this app."
                        )
                    }), 400
        except (OSError, ValueError):
            return jsonify({
                "status": "Error",
                "message": "The uploaded file is not a readable PNG image."
            }), 400

        # Step 1: LSB extraction
        try:
            hidden_data = Stegno.decode(image_path)
        except (OSError, ValueError) as error:
            logging.info(
                "No secure payload in uploaded image for user %s: %s",
                current_user.get_id(),
                error
            )
            return jsonify({
                "status": "Error",
                "message": (
                    "No secure message was found in this image. In the "
                    f"sender's chat, attach an image while sending a message "
                    f"to {current_user.username}, then upload the generated secure PNG here. "
                    "Text-only messages and original images cannot be extracted."
                )
            }), 400

        # Step 2: Decode and decompress the encrypted package
        try:
            compressed_payload = base64.b64decode(
                hidden_data,
                validate=True
            )
            payload_text = zlib.decompress(
                compressed_payload
            ).decode("utf-8")
            payload = json.loads(payload_text)
        except (
            ValueError,
            zlib.error,
            UnicodeDecodeError,
            json.JSONDecodeError
        ) as error:
            logging.info(
                "Invalid secure payload uploaded by user %s: %s",
                current_user.get_id(),
                error
            )
            return jsonify({
                "status": "Error",
                "message": (
                    "The image contains hidden data, but it is not a valid "
                    "secure message from this app. Upload the original "
                    "secure PNG without editing or re-saving it."
                )
            }), 400

        # Step 3: RSA decrypt AES key
        # Step 4: AES decrypt ciphertext
        original_message = decrypt_payload(
            payload,
            current_user
        )

        return jsonify({
            "status": "Success",
            "hidden_message": original_message,
            "message": original_message
        })

    except RecipientKeyError as error:
        logging.info(
            "Secure image recipient key mismatch for user %s: %s",
            current_user.get_id(),
            error
        )
        return jsonify({
            "status": "Error",
            "message": str(error)
        }), 400

    except InvalidEncryptedPayloadError as error:
        logging.info(
            "Invalid encrypted message uploaded by user %s: %s",
            current_user.get_id(),
            error
        )
        return jsonify({
            "status": "Error",
            "message": str(error)
        }), 400

    except Exception:
        logging.exception("Error extracting/decrypting image")

        return jsonify({
            "status": "Error",
            "message": "The server could not process this image. Please try again."
        }), 500

    finally:
        try:
            if os.path.exists(image_path):
                os.remove(image_path)
        except OSError:
            pass


# ---------------------------------------------------------------------
# GET MESSAGES
# ---------------------------------------------------------------------

@app.route("/get_messages/<int:user_id>", methods=["GET"])
@login_required
def get_messages(user_id):
    messages = Message.query.filter(
        (
            (Message.sender_id == current_user.id)
            &
            (Message.receiver_id == user_id)
        )
        |
        (
            (Message.sender_id == user_id)
            &
            (Message.receiver_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()

    return jsonify([
        msg.to_dict()
        for msg in messages
    ])


# ---------------------------------------------------------------------
# DELETE OLD MESSAGES
# ---------------------------------------------------------------------

def delete_old_messages():
    with app.app_context():
        time_threshold = datetime.utcnow() - timedelta(days=1)

        old_messages = Message.query.filter(
            Message.timestamp < time_threshold
        ).all()

        if old_messages:
            for msg in old_messages:
                db.session.delete(msg)

            db.session.commit()

            logging.info(
                "Deleted %s old messages.",
                len(old_messages)
            )


# Avoid duplicate scheduler jobs if this module is imported/reloaded.
try:
    scheduler.add_job(
        id="delete_messages",
        func=delete_old_messages,
        trigger="interval",
        hours=24,
        replace_existing=True
    )
except Exception:
    logging.exception("Could not register scheduler job")


scheduler.init_app(app)


# ---------------------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------------------

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "status": "Error",
        "message": "File is too large. Maximum size is 16 MB."
    }), 413


# ---------------------------------------------------------------------
# START APPLICATION
# ---------------------------------------------------------------------

if __name__ == "__main__":
    scheduler.start()

    # use_reloader=False prevents the scheduler from starting twice
    # when Flask debug mode reloads the application.
    socketio.run(
        app,
        debug=True,
        use_reloader=False
    )
