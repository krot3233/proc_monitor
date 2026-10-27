import os
import sqlite3
from datetime import datetime

from config import DB_NAME


def connect():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = connect()
    try:
        cols = {
            row[1] for row in conn.execute("PRAGMA table_info(whitelist)").fetchall()
        }
        if not cols:
            conn.execute(
                "CREATE TABLE whitelist (name TEXT NOT NULL, exe TEXT NOT NULL, "
                "added_at TEXT, PRIMARY KEY (name, exe))"
            )
        elif "exe" not in cols:
            conn.execute("ALTER TABLE whitelist RENAME TO whitelist_legacy")
            conn.execute(
                "CREATE TABLE whitelist (name TEXT NOT NULL, exe TEXT NOT NULL, "
                "added_at TEXT, PRIMARY KEY (name, exe))"
            )
            conn.execute(
                "INSERT INTO whitelist (name, exe, added_at) "
                "SELECT name, '', added_at FROM whitelist_legacy"
            )
            conn.execute("DROP TABLE whitelist_legacy")

        conn.execute(
            "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, pid INTEGER, name TEXT, exe TEXT, rule TEXT, weight INTEGER, score INTEGER)"
        )
        conn.commit()
    finally:
        conn.close()


def normalize_name(name):
    if name is None or str(name).strip() == "":
        return ""
    return str(name).strip().lower()


def normalize_exe(exe):
    if exe is None:
        return ""
    exe = str(exe).strip()
    if exe == "":
        return ""
    exe = os.path.abspath(exe)
    return os.path.normcase(exe).lower()


def is_whitelisted(name, exe):
    name = normalize_name(name)
    exe = normalize_exe(exe)
    if not name or not exe:
        return False
    conn = connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM whitelist WHERE name = ? AND exe = ?",
            (name, exe),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def add_to_whitelist(name, exe):
    name = normalize_name(name)
    exe = normalize_exe(exe)
    if not name or not exe:
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO whitelist (name, exe, added_at) "
            "VALUES (?, ?, ?)",
            (name, exe, now),
        )
        conn.commit()
    finally:
        conn.close()


def remove_from_whitelist(name, exe):
    name = normalize_name(name)
    exe = normalize_exe(exe)
    if not name or not exe:
        return
    conn = connect()
    try:
        conn.execute(
            "DELETE FROM whitelist WHERE name = ? AND exe = ?",
            (name, exe),
        )
        conn.commit()
    finally:
        conn.close()


def log_event(pid, name, exe, rule, weight, score, ts=None):
    if ts is None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = connect()
    conn.execute(
        "INSERT INTO events (ts, pid, name, exe, rule, weight, score) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, pid, name, exe, rule, weight, score),
    )
    conn.commit()
    conn.close()
