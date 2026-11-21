import os
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
    scope TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL REFERENCES users(id),
    type TEXT NOT NULL, resource TEXT NOT NULL, risk INTEGER NOT NULL,
    reason TEXT NOT NULL, status TEXT NOT NULL, timestamp TEXT NOT NULL,
    recommendation TEXT NOT NULL, source TEXT NOT NULL,
    notification_read INTEGER NOT NULL DEFAULT 0,
    notification_dismissed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_user_seq ON events(user_id, seq);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id), t TEXT NOT NULL, msg TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_user_seq ON audit(user_id, seq);

CREATE TABLE IF NOT EXISTS google_login_attempts (
    state_hash TEXT PRIMARY KEY, verifier TEXT NOT NULL, nonce TEXT NOT NULL,
    user_id TEXT REFERENCES users(id), session_hash TEXT, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS google_identities (
    subject TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
    email TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS store_connection (
    user_id TEXT PRIMARY KEY REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gmail_oauth (
    state_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
    session_hash TEXT NOT NULL, verifier TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS gmail_connections (
    user_id TEXT PRIMARY KEY REFERENCES users(id), generation TEXT NOT NULL,
    email TEXT NOT NULL, refresh_token BLOB NOT NULL, next_check INTEGER NOT NULL DEFAULT 0,
    last_checked TEXT, failure TEXT
);
CREATE TABLE IF NOT EXISTS gmail_alerts (
    user_id TEXT NOT NULL REFERENCES users(id), message_id TEXT NOT NULL,
    kind TEXT NOT NULL, timestamp TEXT NOT NULL,
    notification_read INTEGER NOT NULL DEFAULT 0,
    notification_dismissed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(user_id, message_id)
);
CREATE INDEX IF NOT EXISTS gmail_alerts_user_time ON gmail_alerts(user_id, timestamp DESC);

"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(SCHEMA)

    @contextmanager
    def connect(self, *, write=False):
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            with db:
                db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield db


def configured_store():
    return Store(os.environ.get("CYBERGUARD_DB") or ROOT / "var" / "cyberguard.sqlite3")
