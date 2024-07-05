from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import hashlib

def generate_key():
    """Generate a new AES encryption key."""
    return os.urandom(32)  # 256-bit key

def get_key_from_string(key_string):
    """Generate a key from a string."""
    return base64.urlsafe_b64encode(hashlib.sha256(key_string.encode()).digest()[:32])

def encrypt_file(file_path, key):
    """Encrypt a file and return the encrypted data with IV prepended."""
    iv = os.urandom(16)  # AES block size is 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Padding to make data block size aligned
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV to the encrypted data

def decrypt_file(encrypted_data, key, iv):
    """Decrypt data and return the decrypted content."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpadding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except ValueError as e:
        raise ValueError("Decryption failed: Invalid padding bytes.") from e

    return decrypted_data

