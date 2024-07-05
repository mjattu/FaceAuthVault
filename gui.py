import tkinter as tk
from tkinter import filedialog, messagebox
import face_recognition_util
import file_encryption_util
import sqlite3
from capture_image import capture_image
import os
import tempfile
from tkinter import Toplevel, Listbox, Scrollbar, Button, Label, Entry, messagebox, filedialog
import file_encryption_util  # Ensure this is the correct import for your encryption functions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

SECURE_DIR = 'secure_files'
if not os.path.exists(SECURE_DIR):
    os.makedirs(SECURE_DIR)

# Global variable to store the Aadhaar number
aadhaar_number = None

def submit_data():
    global aadhaar_number
    aadhaar_number = aadhaar_entry.get()

    # Validate Aadhaar number
    if not aadhaar_number or len(aadhaar_number) != 6:
        messagebox.showerror("Error", "Please enter last 6 digit Aadhaar number.")
        return

    # Retrieve existing face data
    face_encoding, face_image_path = face_recognition_util.get_face_data(aadhaar_number)

    if face_encoding is not None:
        # Aadhaar exists, verify face
        messagebox.showinfo("Info", "Please capture your face for authentication.")
        try:
            # Capture face for authentication
            captured_face_encoding = face_recognition_util.capture_face()
            if not face_recognition_util.authenticate_face(face_encoding, captured_face_encoding):
                messagebox.showerror("Error", "Face authentication failed.")
                return
            messagebox.showinfo("Info", "Face authenticated successfully. You can now manage your files.")
            manage_files_ui()
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))
    else:
        # Aadhaar does not exist, store new data
        messagebox.showinfo("Info", "Please capture your face for registration.")
        try:
            # Capture face for registration
            face_image_path = capture_image()  # Capture image after successful face detection
            face_encoding = face_recognition_util.get_face_encoding(face_image_path)
            if face_image_path is None:
                messagebox.showerror("Error", "Failed to capture image.")
                return
            
            # Store new face encoding and image
            face_recognition_util.store_face_encoding(aadhaar_number, face_encoding, face_image_path)
            messagebox.showinfo("Info", "Face data stored successfully. You can now manage your files.")
            manage_files_ui()
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))

def upload_file():
    global aadhaar_number
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    # Generate key and encrypt the file
    key = file_encryption_util.generate_key()
    encrypted_data_with_iv = file_encryption_util.encrypt_file(file_path, key)

    # Extract the IV from the encrypted data
    iv = encrypted_data_with_iv[:16]
    encrypted_data = encrypted_data_with_iv[16:]

    conn = sqlite3.connect('vault.db')
    c = conn.cursor()
    c.execute('INSERT INTO files (aadhaar_number, file_name, encrypted_data, decryption_key, iv) VALUES (?, ?, ?, ?, ?)',
              (aadhaar_number, os.path.basename(file_path), encrypted_data, key, iv))
    conn.commit()
    conn.close()

    messagebox.showinfo("Info", "File uploaded and encrypted successfully.")


import os
import sqlite3
from tkinter import Toplevel, Listbox, Scrollbar, Button, filedialog, messagebox
import file_encryption_util

def access_files():
    global aadhaar_number
    conn = sqlite3.connect('vault.db')
    c = conn.cursor()
    c.execute('SELECT file_name FROM files WHERE aadhaar_number = ?', (aadhaar_number,))
    files = c.fetchall()
    conn.close()

    if not files:
        messagebox.showinfo("Info", "No files found.")
        return

    def decrypt_and_save_file():
        selected_file = file_listbox.get(file_listbox.curselection())

        # Fetch encrypted data, IV, and key
        conn = sqlite3.connect('vault.db')
        c = conn.cursor()
        c.execute('SELECT encrypted_data, decryption_key, iv FROM files WHERE aadhaar_number = ? AND file_name = ?',
                  (aadhaar_number, selected_file))
        row = c.fetchone()
        conn.close()

        if not row:
            messagebox.showerror("Error", "File not found.")
            return

        encrypted_data = row[0]
        key = row[1]
        iv = row[2]

        # Convert from BLOB to bytes
        encrypted_data = bytes(encrypted_data)
        key = bytes(key)
        iv = bytes(iv)

        # Decrypt the file data
        try:
            decrypted_data = file_encryption_util.decrypt_file(encrypted_data, key, iv)
        except ValueError as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
            return

        # Ask user where to save the decrypted file
        save_path = filedialog.asksaveasfilename(
            defaultextension=os.path.splitext(selected_file)[1],
            filetypes=[("All Files", "*.*"), ("PDF Files", "*.pdf"), ("Text Files", "*.txt")]
        )

        if not save_path:
            messagebox.showinfo("Info", "Save operation cancelled.")
            return

        # Save the decrypted data to the selected path
        with open(save_path, 'wb') as f:
            f.write(decrypted_data)

        # Inform the user
        messagebox.showinfo("Info", "File accessed and saved successfully.")

    access_window = Toplevel()
    access_window.title("Access Files")

    file_listbox = Listbox(access_window)
    file_listbox.pack(side="left", fill="y")

    scrollbar = Scrollbar(access_window, orient="vertical")
    scrollbar.config(command=file_listbox.yview)
    scrollbar.pack(side="left", fill="y")

    file_listbox.config(yscrollcommand=scrollbar.set)
    for file in files:
        file_listbox.insert("end", file[0])

    Button(access_window, text="Decrypt and Save", command=decrypt_and_save_file).pack()



from tkinter import Toplevel, Listbox, Scrollbar, Button, messagebox
import sqlite3

def delete_file():
    global aadhaar_number

    # Connect to the database
    conn = sqlite3.connect('vault.db')
    c = conn.cursor()

    # Fetch files associated with the Aadhaar number
    c.execute('SELECT file_name FROM files WHERE aadhaar_number = ?', (aadhaar_number,))
    files = c.fetchall()
    conn.close()

    if not files:
        messagebox.showinfo("Info", "No files found.")
        return

    def reauthenticate_and_delete():
        selected_file = file_listbox.get(file_listbox.curselection())
        
        # Retrieve stored face encoding
        stored_encoding, _ = face_recognition_util.get_face_data(aadhaar_number)
        if stored_encoding is None:
            messagebox.showerror("Error", "No face data found for the given Aadhaar number.")
            return

        # Capture face for re-authentication
        try:
            captured_encoding = face_recognition_util.capture_face()
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))
            return
        
        if not face_recognition_util.authenticate_face(stored_encoding, captured_encoding):
            messagebox.showinfo("Error", "Face authentication failed.")
            return

        # Delete file record from the database
        conn = sqlite3.connect('vault.db')
        c = conn.cursor()
        c.execute('DELETE FROM files WHERE aadhaar_number = ? AND file_name = ?', 
                  (aadhaar_number, selected_file))
        conn.commit()
        conn.close()

        messagebox.showinfo("Info", "File record deleted successfully.")

    # Create a new window for file deletion
    delete_window = Toplevel()
    delete_window.title("Delete Files")

    # Create Listbox to display files
    file_listbox = Listbox(delete_window)
    file_listbox.pack(side="left", fill="y")

    # Create Scrollbar for Listbox
    scrollbar = Scrollbar(delete_window, orient="vertical")
    scrollbar.config(command=file_listbox.yview)
    scrollbar.pack(side="left", fill="y")
    file_listbox.config(yscrollcommand=scrollbar.set)

    # Populate Listbox with file names
    for file in files:
        file_listbox.insert("end", file[0])

    # Add button for re-authentication and deletion
    Button(delete_window, text="Re-authenticate and Delete", command=reauthenticate_and_delete).pack()


def clear_window():
    """Clear all widgets from the window."""
    for widget in window.winfo_children():
        widget.destroy()

def show_lock_unlock_options():
    """Show the initial options screen."""
    clear_window()
    tk.Label(window, text="Face Auth Vault", font=('Arial', 24)).pack(pady=10)
    tk.Label(window, text="Enter your last 6 digit Aadhaar Number:").pack(pady=5)
    global aadhaar_entry
    aadhaar_entry = tk.Entry(window)
    aadhaar_entry.pack(pady=5)
    tk.Button(window, text="Submit", command=submit_data).pack(pady=10)

def manage_files_ui():
    clear_window()
    tk.Label(window, text="Manage Files", font=('Arial', 20)).pack(pady=10)
    tk.Button(window, text="Upload File", command=show_upload_file_ui).pack(pady=5)
    tk.Button(window, text="Access Files", command=show_access_files_ui).pack(pady=5)
    tk.Button(window, text="Delete File", command=show_delete_file_ui).pack(pady=5)
    tk.Button(window, text="Logout", command=show_lock_unlock_options).pack(pady=10)

def show_upload_file_ui():
    clear_window()
    tk.Label(window, text="Upload File", font=('Arial', 20)).pack(pady=10)
    tk.Button(window, text="Browse and Upload", command=upload_file).pack(pady=5)
    tk.Button(window, text="Back", command=manage_files_ui).pack(pady=10)

def show_access_files_ui():
    clear_window()
    tk.Label(window, text="Access Files", font=('Arial', 20)).pack(pady=10)
    tk.Button(window, text="Browse and Access", command=access_files).pack(pady=5)
    tk.Button(window, text="Back", command=manage_files_ui).pack(pady=10)

def show_delete_file_ui():
    """Show the delete file UI."""
    clear_window()
    tk.Label(window, text="Delete File", font=('Arial', 20)).pack(pady=10)
    tk.Button(window, text="Browse and Delete", command=delete_file).pack(pady=5)
    tk.Button(window, text="Back", command=manage_files_ui).pack(pady=10)

def start_application():
    """Start the Tkinter application."""
    global window
    window = tk.Tk()
    window.title("Face Auth Vault")
    window.geometry("400x300")
    show_lock_unlock_options()
    window.mainloop()

if __name__ == "__main__":
    start_application()
