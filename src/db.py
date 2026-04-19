import sqlite3

class Database:
    def __init__(self):
        self.conn = sqlite3.connect("database.db")
        self.cursor = self.conn.cursor()
        self.cursor.executescript("""
            PRAGMA foreign_keys = ON;
            
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT CHECK(role IN ('ANALYST','MANAGER')) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                locked INTEGER NOT NULL DEFAULT 0 CHECK(locked IN (0,1))
            );
            
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            
            CREATE TABLE IF NOT EXISTS tickets (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT CHECK(severity IN ('LOW','MED','HIGH')) NOT NULL DEFAULT 'LOW',
                status TEXT CHECK(status IN ('OPEN','IN_PROGRESS','RESOLVED')) NOT NULL DEFAULT 'OPEN',
                owner_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            );
            
            CREATE INDEX IF NOT EXISTS idx_tickets_owner ON tickets(owner_id);
            CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_id TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource, resource_id);
            
            CREATE TRIGGER IF NOT EXISTS trg_tickets_updated_at
            AFTER UPDATE ON tickets
            FOR EACH ROW
            BEGIN
                UPDATE tickets
                SET updated_at = CURRENT_TIMESTAMP
                WHERE id = OLD.id;
            END;
        """)
    def __del__(self):
        self.conn.close()
