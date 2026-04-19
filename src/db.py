import sqlite3

class Database:
    def __init__(self):
        self.conn = sqlite3.connect("database.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.executescript("""
            PRAGMA foreign_keys = ON;
            
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT CHECK(role IN ('ANALYST','MANAGER')) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                locked INTEGER NOT NULL DEFAULT 0 CHECK(locked IN (0,1))
            );
            
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT CHECK(severity IN ('LOW','MED','HIGH')) NOT NULL DEFAULT 'LOW',
                status TEXT CHECK(status IN ('OPEN','IN_PROGRESS','RESOLVED')) NOT NULL DEFAULT 'OPEN',
                owner_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_id TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            
            CREATE TRIGGER IF NOT EXISTS trg_tickets_updated_at
            AFTER UPDATE ON tickets
            FOR EACH ROW
            BEGIN
                UPDATE tickets
                SET updated_at = CURRENT_TIMESTAMP
                WHERE id = OLD.id;
            END;
        """)

    def create_user(self, email, password_hash, role="ANALYST"):
        self.cursor.execute("""
            INSERT INTO users (email, password_hash, role)
            VALUES (?, ?, ?)
        """, (email, password_hash, role))

        self.conn.commit()
        return self.cursor.lastrowid

    def user_update_password(self, id, password_hash):
        self.cursor.execute("""
            UPDATE users SET password_hash = ? WHERE id = ?
        """, (password_hash, id))

        self.conn.commit()


    def get_user_by_email(self, email):
        self.cursor.execute("""
            SELECT * FROM users WHERE email = ?
        """, (email,))
        return self.cursor.fetchone()

    def __del__(self):
        self.conn.close()
