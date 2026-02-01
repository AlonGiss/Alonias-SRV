import sqlite3
import hashlib
import secrets

DB_NAME = "users.db"


class SQLHandler:
    def __init__(self):
        self.conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        self._create_table()

    # =======================
    # CREATE TABLE
    # =======================
    def _create_table(self):
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            userId TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            connectionStatus INTEGER NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
        """)
        self.conn.commit()

    # =======================
    # HELPERS
    # =======================
    def _generate_user_id(self):
        return secrets.token_hex(3).upper()  # ej: A9F72C

    def _generate_salt(self) -> str:
        return secrets.token_hex(8)

    def _hash_password(self, password: str, salt: str):
        return hashlib.sha256((password + salt).encode()).hexdigest()

    # =======================
    # REGISTER
    # =======================
    def register_user(self, username: str, password: str):
        try:
            user_id = self._generate_user_id()
            salt = self._generate_salt()
            pwd_hash = self._hash_password(password, salt)

            self.conn.execute("""
                INSERT INTO users
                (userId, username, connectionStatus, hashed_password, salt)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, username, 1, pwd_hash, salt))

            self.conn.commit()
            return True

        except sqlite3.IntegrityError:
            return False

    # =======================
    # LOGIN
    # =======================
    def check_login(self, username, password):
        cur = self.conn.execute("""
            SELECT hashed_password, salt
            FROM users
            WHERE username = ?
        """, (username,))

        row = cur.fetchone()
        if not row:
            return False

        stored_hash, salt = row
        return stored_hash == self._hash_password(password, salt)

    # =======================
    # CONNECTION STATUS
    # =======================
    def set_connection_status(self, username, status):
        self.conn.execute("""
            UPDATE users
            SET connectionStatus = ?
            WHERE username = ?
        """, (1 if status else 0, username))
        self.conn.commit()
