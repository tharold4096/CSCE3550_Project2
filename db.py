import sqlite3
from contextlib import closing

DB_FILE = "totally_not_my_privateKeys.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""


def init_db(path=DB_FILE):
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(SCHEMA)
        conn.commit()


def insert_key(pem: bytes, exp: int, path=DB_FILE) -> int:
    with closing(sqlite3.connect(path)) as conn:
        cur = conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp))
        conn.commit()
        return cur.lastrowid


def get_valid_keys(now: int, path=DB_FILE) -> list:
    with closing(sqlite3.connect(path)) as conn:
        return conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ?", (now,)
        ).fetchall()


def get_expired_key(now: int, path=DB_FILE):
    with closing(sqlite3.connect(path)) as conn:
        return conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (now,)
        ).fetchone()
