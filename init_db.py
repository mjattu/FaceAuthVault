
import sqlite3



def init_db():

 
    """Initialize the database with required tables."""
    conn = sqlite3.connect('vault.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            aadhaar_number TEXT PRIMARY KEY,
            face_encoding BLOB,
            face_image BLOB
        )
    ''')
    
    # Create files table
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            aadhaar_number TEXT,
            file_name TEXT,
            encrypted_data BLOB,
            decryption_key BLOB,
            iv BLOB,
            FOREIGN KEY(aadhaar_number) REFERENCES users(aadhaar_number)
        )
    ''')

    conn.commit()
    conn.close()
