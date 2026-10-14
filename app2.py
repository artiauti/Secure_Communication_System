from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from forms import LoginForm, SignupForm, MessageForm, LogoutForm
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from flask_socketio import SocketIO
import base64
import os
import logging
from flask_migrate import Migrate
from PIL import Image
import io
from flask_apscheduler import APScheduler
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf

class Stegno:

    @staticmethod
    def gen_data(data):
        """Generate binary data from the input string."""
        return [format(ord(i), '08b') for i in data]

    @staticmethod
    def mod_pix(pix, data):
        """Modify pixel values to encode binary data."""
        data_list = Stegno.gen_data(data)
        data_len = len(data_list)
        img_data = iter(pix)

        for i in range(data_len):
            pix = [value for value in next(img_data)[:3] +
                   next(img_data)[:3] +
                   next(img_data)[:3]]
            for j in range(8):
                if (data_list[i][j] == '0' and pix[j] % 2 != 0):
                    pix[j] -= 1
                elif (data_list[i][j] == '1' and pix[j] % 2 == 0):
                    pix[j] -= 1

            if i == data_len - 1:
                if pix[-1] % 2 == 0:
                    pix[-1] -= 1
            else:
                if pix[-1] % 2 != 0:
                    pix[-1] -= 1

            yield tuple(pix[:3])
            yield tuple(pix[3:6])
            yield tuple(pix[6:9])

    @staticmethod
    def encode(image_path, output_path, secret_data):
        """Encode a secret message into an image."""
        if not secret_data:
            raise ValueError("Data is empty")

        image = Image.open(image_path)
        
        # Ensure the image is in RGB mode
        if image.mode != "RGB":
            image = image.convert("RGB")
        
        new_img = image.copy()
        width, height = new_img.size
        pixels = new_img.getdata()

        new_pixels = []
        for modified_pixel in Stegno.mod_pix(pixels, secret_data):
            new_pixels.append(modified_pixel)

        new_img.putdata(new_pixels)
        # new_img.save(output_path, str(output_path.split(".")[1].upper()))
        new_img.save(output_path, format="JPEG")

        print("Data encoded and saved successfully!")


    @staticmethod
    def decode(image_path):
        """Decode the secret message from an image."""
        image = Image.open(image_path)
        pixels = iter(image.getdata())
        binary_data = ""

        while True:
            pixels_values = [value for value in next(pixels)[:3] +
                             next(pixels)[:3] +
                             next(pixels)[:3]]
            binary_data += ''.join(['0' if value % 2 == 0 else '1' for value in pixels_values[:8]])
            if pixels_values[-1] % 2 != 0:
                break

        decoded_data = ""
        for i in range(0, len(binary_data), 8):
            char = chr(int(binary_data[i:i + 8], 2))
            decoded_data += char
        return decoded_data




# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
scheduler = APScheduler()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
socketio = SocketIO(app, cors_allowed_origins="*")

csrf = CSRFProtect(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    iv = db.Column(db.Text, nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(256), nullable=True)
    content = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'timestamp': self.timestamp.isoformat(),
            'content': self.content
        }

# Create the database
@app.before_request
def create_tables():
    db.create_all()

def rsa_encrypt(public_key_str, data):
    try:
        # Load public key from string
        public_key = serialization.load_ssh_public_key(
            public_key_str.encode(),
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
        encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
        logging.debug(f"Encrypted data (RSA): {encrypted_base64}")
        return encrypted_base64
    except Exception as e:
        logging.error(f"Error encrypting data with RSA: {e}")
        raise

def rsa_decrypt(private_key, enc_data):
    try:
        decoded_data = base64.b64decode(enc_data)
        decrypted_data = private_key.decrypt(
            decoded_data,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logging.debug(f"Decrypted data (RSA): {decrypted_data}")
        return decrypted_data
    except Exception as e:
        logging.error(f"Error decrypting data with RSA: {e}")
        raise

def aes_encrypt(key, message):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ct).decode('utf-8')
    except Exception as e:
        logging.error(f"Error encrypting data with AES: {e}")
        raise

def aes_decrypt(key, iv, ciphertext):
    try:
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return message.decode('utf-8')
    except Exception as e:
        logging.error(f"Error decrypting data with AES: {e}")
        raise

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
    ).decode('utf-8')
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode('utf-8')
    return private_key, public_key

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('signup.html', form=form)

        try:
            private_key, public_key = generate_rsa_key_pair()
            new_user = User(username=username, password=password, public_key=public_key, private_key=private_key)
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful, please login!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Error during signup: {e}")
            flash('Error during signup. Please try again.', 'danger')
    
    return render_template('signup.html', form=form)

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('chat'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)


@app.route('/chat', defaults={'selected_user_id': None})
@app.route('/chat/<int:selected_user_id>', methods=['GET', 'POST'])
@login_required
def chat(selected_user_id):
    try:
        users = User.query.filter(User.id != current_user.id).all()
        messages = []
        selected_chat = None
        
        if selected_user_id:
            selected_chat = db.session.get(User, selected_user_id)
            if not selected_chat:
                flash('User not found', 'danger')
                return redirect(url_for('chat'))
                
            messages = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.receiver_id == selected_user_id)) |
                ((Message.sender_id == selected_user_id) & (Message.receiver_id == current_user.id))
            ).order_by(Message.timestamp.asc()).all()

        form = LogoutForm()
        return render_template('chat2.html', 
                            users=users, 
                            messages=messages, 
                            selected_chat=selected_chat, 
                            form=form,
                            current_user=current_user,csrf_token=generate_csrf())

    except Exception as e:
        logging.error(f"Error in chat route: {str(e)}", exc_info=True)
        flash('Error retrieving chat data. Please try again later.', 'danger')
        return redirect(url_for('login'))


@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('message')
    image_file = request.files.get('image')

    if not receiver_id:
        return jsonify({'status': 'Error', 'message': 'No receiver specified'}), 400

    try:
        image_filename = None
        
        # Handle image file if provided
        if image_file and allowed_file(image_file.filename):
            # Secure the filename
            image_filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            
            # Save the original image
            image_file.save(image_path)
            
            # If there's a message, embed it in the image
            if content:
                encoded_image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"encoded_{image_filename}")
                Stegno.encode(image_path, encoded_image_path, content)
                image_filename = f"encoded_{image_filename}"  # Update to the encoded image filename
                
                # Remove the original image
                os.remove(image_path)
            else:
                # If no message, just use the original image
                pass

        # Generate AES key for encryption
        aes_key = os.urandom(32)  # AES-256 key
        
        # Encrypt the message (even if empty, as it might be in the image)
        iv, encrypted_message = aes_encrypt(aes_key, content.encode('utf-8') if content else b'')

        # Encrypt AES key with receiver's RSA public key
        receiver = User.query.get(receiver_id)
        if not receiver:
            return jsonify({'status': 'Error', 'message': 'Receiver not found'}), 404
            
        encrypted_aes_key = rsa_encrypt(receiver.public_key, aes_key)

        # Store message with encrypted data
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            iv=iv,
            ciphertext=encrypted_message,
            encrypted_aes_key=encrypted_aes_key,
            image=image_filename,
            content=content
        )
        db.session.add(message)
        db.session.commit()

        # Emit message event via SocketIO
        socketio.emit('message', {
            'sender': {'id': current_user.id, 'username': current_user.username},
            'receiver_id': receiver_id,
            'content': content,
            'image_url': image_filename,
            'timestamp': datetime.utcnow().isoformat()
        })

        return jsonify({
            'status': 'Message sent successfully',
            'image_url': image_filename,
            'message': content,
            'ciphertext': encrypted_message.decode('latin1')  # Convert to string for JSON
        })

    except Exception as e:
        logging.error(f"Error sending message: {e}")
        return jsonify({'status': 'Error', 'message': 'Error sending message. Please try again.'}), 500
@app.route('/decode_image', methods=['POST'])
@login_required
def decode_image():
    image_file = request.files.get('image')

    if image_file and allowed_file(image_file.filename):
        image_filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        image_file.save(image_path)
        try:
            hidden_message = Stegno.decode(image_path)
            return jsonify({'status': 'Success', 'hidden_message': hidden_message})
        except Exception as e:
            logging.error(f"Error decoding image: {e}")
            return jsonify({'status': 'Error', 'message': 'Could not decode the image. Please ensure it contains a hidden message.'}), 500
    else:
        return jsonify({'status': 'Error', 'message': 'Invalid image file.'}), 400




@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('login'))


# API to get messages for a user
@app.route('/get_messages/<int:user_id>', methods=['GET'])
def get_messages(user_id):
    messages = Message.query.filter_by(receiver_id=user_id).all()
    return jsonify([msg.to_dict() for msg in messages])


# Function to delete old messages
def delete_old_messages():
    time_threshold = datetime.utcnow() - timedelta(days=1)
    old_messages = Message.query.filter(Message.timestamp < time_threshold).all()
    
    if old_messages:
        for msg in old_messages:
            db.session.delete(msg)
        db.session.commit()
        logging.info(f"Deleted {len(old_messages)} old messages.")

# Schedule the cleanup job to run every 24 hours
scheduler.add_job(id='delete_messages', func=delete_old_messages, trigger='interval', hours=24)
scheduler.init_app(app)
scheduler.start()




if __name__ == '__main__':
    socketio.run(app, debug=True)
