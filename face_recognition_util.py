import face_recognition
import numpy as np
from PIL import Image
import sqlite3
import cv2
from capture_image import capture_image

def load_image(image_path):
    """Load an image from a file path and ensure it's in RGB format."""
    try:
        image = Image.open(image_path)
        image = image.convert('RGB')  # Convert image to RGB format
        return np.array(image)
    except Exception as e:
        raise RuntimeError(f"Error loading image {image_path}: {e}")

def get_face_encoding(image_path):
    """Get face encoding from an image."""
    image_np = load_image(image_path)
    face_locations = face_recognition.face_locations(image_np)
    if not face_locations:
        raise RuntimeError("No face detected in the image.")
    
    face_encodings = face_recognition.face_encodings(image_np, known_face_locations=face_locations)
    if not face_encodings:
        raise RuntimeError("Face encoding could not be computed.")
    
    return face_encodings[0]

def store_face_encoding(aadhaar_number, face_encoding, face_image_path):
    """Store face encoding and image data in the database."""
    with open(face_image_path, 'rb') as img_file:
        face_image_data = img_file.read()
    
    conn = sqlite3.connect('vault.db')
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO users (aadhaar_number, face_encoding, face_image) VALUES (?, ?, ?)',
              (aadhaar_number, face_encoding.tobytes(), face_image_data))
    conn.commit()
    conn.close()

def get_face_data(aadhaar_number):
    """Retrieve face data from the database."""
    conn = sqlite3.connect('vault.db')
    c = conn.cursor()
    c.execute('SELECT face_encoding, face_image FROM users WHERE aadhaar_number = ?', (aadhaar_number,))
    result = c.fetchone()
    conn.close()
    
    if result:
        face_encoding = np.frombuffer(result[0], dtype=np.float64)
        face_image = result[1]
        return face_encoding, face_image
    else:
        return None, None


def capture_face():
    """Capture a face from the webcam."""
    face_image_path = capture_image()  # Function to capture image from webcam
    if face_image_path is None:
        raise RuntimeError("Failed to capture image.")
    
    return get_face_encoding(face_image_path)

def authenticate_face(stored_encoding, captured_encoding):
    """Authenticate a face by comparing stored and captured encodings."""
    return face_recognition.compare_faces([stored_encoding], captured_encoding)[0]
