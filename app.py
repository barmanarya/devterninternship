import sqlite3
import bcrypt
#  SQLite database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                )''')
conn.commit()
def register_user(username, password):
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
def login_user(username, password):

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    if user:
        # Decode the hashed password from bytes to string
        hashed_password = user[2].decode('utf-8')
        
        # Check if the password matches
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            return True
    return False
register_user('user1', 'password123')
print(login_user('user1', 'password123'))  # Should print True
print(login_user('user1', 'wrongpassword'))  # Should print False
# Close connection
conn.close()
