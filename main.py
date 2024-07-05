import sqlite3
import init_db
import gui

def initialize_database():
    """Initialize the database with required tables."""
    init_db.init_db()  # Ensure init_db has the init_db function
    print("Database initialized.")

def main():
    # Initialize the database
    initialize_database()
    
    # Start the GUI application
    gui.start_application()

if __name__ == "__main__":
    main()
