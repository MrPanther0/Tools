from flask import Flask, request, send_file, render_template
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os

app = Flask(__name__)

# Ensure secure storage for encryption keys
KEYS_DIR = "keys"
FILES_DIR = "files"
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)

# Generate a new encryption key
def generate_key():
    key = Fernet.generate_key()
    return key

# Encrypt a file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    return encrypted_file_path

# Decrypt a file
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_data)
    decrypted_file_path = file_path.replace(".enc", "")
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    return decrypted_file_path

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files['file']
    if not file:
        return "Please upload a file to encrypt.", 400

    key = generate_key()
    file_name = secure_filename(file.filename)
    file_path = os.path.join(FILES_DIR, file_name)
    file.save(file_path)

    encrypted_file_path = encrypt_file(file_path, key)

    # Save the encryption key securely
    key_path = os.path.join(KEYS_DIR, file_name + ".key")
    with open(key_path, 'wb') as f:
        f.write(key)

    return {
        "message": "File encrypted successfully!",
        "encrypted_file_url": f"/download/{os.path.basename(encrypted_file_path)}",
        "key_file_url": f"/download/{os.path.basename(key_path)}"
    }, 200

@app.route('/decrypt', methods=['POST'])
def decrypt():
    file = request.files['file']
    key_file = request.files['key']
    if not file or not key_file:
        return "Please provide both the encrypted file and its key.", 400

    file_name = secure_filename(file.filename)
    file_path = os.path.join(FILES_DIR, file_name)
    file.save(file_path)

    key = key_file.read()
    decrypted_file_path = decrypt_file(file_path, key)

    return {
        "message": "File decrypted successfully!",
        "decrypted_file_url": f"/download/{os.path.basename(decrypted_file_path)}"
    }, 200

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(FILES_DIR, filename)
    if not os.path.exists(file_path):
        file_path = os.path.join(KEYS_DIR, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "File not found.", 404

if __name__ == '__main__':
    app.run(debug=True)
