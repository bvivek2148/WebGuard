import os
import sqlite3
import hashlib
import secrets
import time
from typing import Dict, List, Optional, Tuple

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webguard.db")

def get_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory and WAL mode enabled."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Generates a PBKDF2-HMAC-SHA256 hash with a cryptographically secure salt."""
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return key.hex(), salt

def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verifies a password against the stored hash and salt."""
    calculated_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(calculated_hash, password_hash)

def init_db():
    """Initializes all database tables and default admin account if not already present."""
    with get_connection() as conn:
        cursor = conn.cursor()

        # 1. Admin Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'SOC Lead',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 2. Request Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id TEXT UNIQUE,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                client_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                payload TEXT,
                is_blocked INTEGER NOT NULL,
                attack_type TEXT,
                confidence REAL NOT NULL,
                entropy REAL,
                latency_ms REAL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON request_logs(client_ip);")

        # 3. Blacklist Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(client_ip);")

        # 4. System Settings Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            );
        """)

        # Default Admin Account: admin / admin123
        cursor.execute("SELECT id FROM admin_users WHERE username = 'admin';")
        if not cursor.fetchone():
            p_hash, salt = hash_password("admin123")
            cursor.execute(
                "INSERT INTO admin_users (username, password_hash, salt, role) VALUES (?, ?, ?, ?);",
                ("admin", p_hash, salt, "SOC Lead")
            )

        # Default Settings
        default_settings = {
            "waf_mode": "blocking",
            "target_url": "http://localhost:8080",
            "blocking_threshold": "0.80",
            "rate_limit_rpm": "100"
        }
        for k, v in default_settings.items():
            cursor.execute(
                "INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES (?, ?);",
                (k, v)
            )

        conn.commit()

def load_settings() -> Dict[str, any]:
    """Loads all system settings from the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT setting_key, setting_value FROM system_settings;")
        rows = cursor.fetchall()
        settings_dict = {}
        for row in rows:
            k = row["setting_key"]
            v = row["setting_value"]
            if k == "blocking_threshold":
                settings_dict[k] = float(v)
            elif k == "rate_limit_rpm":
                settings_dict[k] = int(v)
            else:
                settings_dict[k] = v
        return settings_dict

def save_setting(key: str, value: any):
    """Upserts a setting key-value pair into the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?) "
            "ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value;",
            (key, str(value))
        )
        conn.commit()

def load_blacklist() -> List[dict]:
    """Retrieves all currently active blacklisted IP records."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT client_ip, reason, blocked_at FROM blacklist ORDER BY blocked_at DESC;")
        rows = cursor.fetchall()
        return [{"client_ip": r["client_ip"], "reason": r["reason"], "timestamp": r["blocked_at"]} for r in rows]

def add_blacklist_ip(client_ip: str, reason: str, expires_at: Optional[str] = None):
    """Inserts or updates an IP in the blacklist table."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO blacklist (client_ip, reason, blocked_at, expires_at) VALUES (?, ?, CURRENT_TIMESTAMP, ?) "
            "ON CONFLICT(client_ip) DO UPDATE SET reason = excluded.reason, blocked_at = CURRENT_TIMESTAMP;",
            (client_ip, reason, expires_at)
        )
        conn.commit()

def remove_blacklist_ip(client_ip: str):
    """Deletes an IP from the blacklist table."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blacklist WHERE client_ip = ?;", (client_ip,))
        conn.commit()

def insert_request_log(entry: dict):
    """Inserts an incoming request log entry into the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR IGNORE INTO request_logs 
            (log_id, timestamp, client_ip, method, path, payload, is_blocked, attack_type, confidence, entropy, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                entry.get("id"),
                entry.get("timestamp"),
                entry.get("client_ip"),
                entry.get("method"),
                entry.get("path"),
                entry.get("payload"),
                1 if entry.get("is_blocked") else 0,
                entry.get("attack_type"),
                entry.get("confidence", 0.0),
                entry.get("entropy", 0.0),
                entry.get("latency_ms", 0.0)
            )
        )
        conn.commit()

def get_recent_logs(limit: int = 100) -> List[dict]:
    """Retrieves the most recent request logs from the database."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT log_id, timestamp, client_ip, method, path, payload, is_blocked, attack_type, confidence, entropy, latency_ms
            FROM request_logs ORDER BY id DESC LIMIT ?;
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        logs = []
        for r in reversed(rows):
            logs.append({
                "id": r["log_id"],
                "timestamp": r["timestamp"],
                "client_ip": r["client_ip"],
                "method": r["method"],
                "path": r["path"],
                "payload": r["payload"],
                "attack_type": r["attack_type"],
                "confidence": r["confidence"],
                "is_blocked": bool(r["is_blocked"]),
                "entropy": r["entropy"],
                "latency_ms": r["latency_ms"]
            })
        return logs

def prune_logs(max_records: int = 100_000):
    """Prunes older request logs to prevent database bloating."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(id) FROM request_logs;")
        count = cursor.fetchone()[0]
        if count > max_records:
            excess = count - max_records
            cursor.execute(
                "DELETE FROM request_logs WHERE id IN (SELECT id FROM request_logs ORDER BY id ASC LIMIT ?);",
                (excess,)
            )
            conn.commit()

def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Verifies user credentials against admin_users table."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, salt, role FROM admin_users WHERE username = ?;", (username,))
        row = cursor.fetchone()
        if not row:
            return None
        if verify_password(password, row["password_hash"], row["salt"]):
            return {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"]
            }
        return None
