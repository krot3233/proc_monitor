import hashlib
import os
import sqlite3
import threading
import time
from datetime import datetime

from config import DB_NAME

WHITELIST_CACHE_TIME = 2.0
whitelist_cache = None
whitelist_cache_until = 0
whitelist_cache_lock = threading.Lock()
file_hash_cache = {}
file_hash_cache_lock = threading.Lock()


def connect():
    return sqlite3.connect(DB_NAME, timeout=1.0)


def init_db():
    conn = connect()
    try:
        # WAL позволяет GUI читать события, пока монитор пишет новые.
        conn.execute("PRAGMA journal_mode=WAL")
        cols = {
            row[1] for row in conn.execute("PRAGMA table_info(whitelist)").fetchall()
        }
        if not cols:
            conn.execute(
                "CREATE TABLE whitelist (name TEXT NOT NULL, exe TEXT NOT NULL, sha256 TEXT, "
                "added_at TEXT, PRIMARY KEY (name, exe))"
            )
        elif "exe" not in cols:
            # Переносим старый список по имени: путей у таких записей не было.
            conn.execute("ALTER TABLE whitelist RENAME TO whitelist_legacy")
            conn.execute(
                "CREATE TABLE whitelist (name TEXT NOT NULL, exe TEXT NOT NULL, sha256 TEXT, "
                "added_at TEXT, PRIMARY KEY (name, exe))"
            )
            conn.execute(
                "INSERT INTO whitelist (name, exe, added_at) "
                "SELECT name, '', added_at FROM whitelist_legacy"
            )
            conn.execute("DROP TABLE whitelist_legacy")

        cols = {
            row[1] for row in conn.execute("PRAGMA table_info(whitelist)").fetchall()
        }
        if "sha256" not in cols:
            conn.execute("ALTER TABLE whitelist ADD COLUMN sha256 TEXT")

        # Для записей старого формата запоминаем хеш, если файл еще доступен.
        old_entries = conn.execute(
            "SELECT name, exe FROM whitelist WHERE sha256 IS NULL OR sha256 = ''"
        ).fetchall()
        for name, exe in old_entries:
            digest = get_file_hash(exe)
            if digest:
                conn.execute(
                    "UPDATE whitelist SET sha256 = ? WHERE name = ? AND exe = ?",
                    (digest, name, exe),
                )

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
    exe = os.path.normcase(os.path.abspath(exe))
    return os.path.normcase(exe).lower()


def get_file_hash(exe):
    if not exe or not os.path.isfile(exe):
        return ""

    exe = os.path.normcase(os.path.abspath(exe))
    try:
        file_stat = os.stat(exe)
    except OSError:
        return ""
    stat_key = (file_stat.st_mtime_ns, file_stat.st_size)
    with file_hash_cache_lock:
        cached = file_hash_cache.get(exe)
        if cached and cached[0] == stat_key:
            return cached[1]

    # Хешируем частями, чтобы не загружать исполняемый файл целиком в память.
    digest = hashlib.sha256()
    try:
        with open(exe, "rb") as file:
            while True:
                chunk = file.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return ""

    try:
        after_stat = os.stat(exe)
    except OSError:
        return ""
    after_key = (after_stat.st_mtime_ns, after_stat.st_size)
    if after_key != stat_key:
        # Файл менялся во время чтения — такой хеш нельзя считать надежным.
        return ""

    result = digest.hexdigest()
    with file_hash_cache_lock:
        file_hash_cache[exe] = (stat_key, result)
    return result


def is_whitelisted(name, exe):
    global whitelist_cache, whitelist_cache_until

    name = normalize_name(name)
    normalized_exe = normalize_exe(exe)
    if not name or not normalized_exe:
        return False

    with whitelist_cache_lock:
        if whitelist_cache is None or time.monotonic() >= whitelist_cache_until:
            conn = connect()
            try:
                rows = conn.execute(
                    "SELECT name, exe, sha256 FROM whitelist"
                ).fetchall()
                whitelist_cache = {}
                for row_name, row_exe, row_hash in rows:
                    whitelist_cache[
                        (normalize_name(row_name), normalize_exe(row_exe))
                    ] = row_hash
                whitelist_cache_until = time.monotonic() + WHITELIST_CACHE_TIME
            except sqlite3.OperationalError:
                if whitelist_cache is None:
                    raise
                # Если БД временно занята, пользуемся последним загруженным списком.
            finally:
                conn.close()

        expected_hash = whitelist_cache.get((name, normalized_exe))

    if not expected_hash:
        return False
    # Хэш сверяется с сохраненным: путь мог остаться прежним, а сам файл — измениться.
    digest = get_file_hash(normalized_exe)
    return bool(digest and expected_hash == digest)


def add_to_whitelist(name, exe):
    global whitelist_cache, whitelist_cache_until

    name = normalize_name(name)
    exe = normalize_exe(exe)
    digest = get_file_hash(exe)
    if not name or not exe or not digest:
        return False
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO whitelist (name, exe, sha256, added_at) "
            "VALUES (?, ?, ?, ?)",
            (name, exe, digest, now),
        )
        conn.commit()
    finally:
        conn.close()
    with whitelist_cache_lock:
        # Обновляем локальный кэш сразу, не ожидая окончания его срока жизни.
        if whitelist_cache is not None:
            whitelist_cache[(name, exe)] = digest
            whitelist_cache_until = time.monotonic() + WHITELIST_CACHE_TIME
        else:
            whitelist_cache_until = 0
    return True


def remove_from_whitelist(name, exe):
    global whitelist_cache, whitelist_cache_until

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
    with whitelist_cache_lock:
        # Удаление должно сразу отразиться и на проверках из другого потока.
        if whitelist_cache is not None:
            whitelist_cache.pop((name, exe), None)
            whitelist_cache_until = time.monotonic() + WHITELIST_CACHE_TIME
        else:
            whitelist_cache_until = 0


def log_event(pid, name, exe, rule, weight, score, ts=None):
    if ts is None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = connect()
    try:
        conn.execute(
            "INSERT INTO events (ts, pid, name, exe, rule, weight, score) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, pid, name, exe, rule, weight, score),
        )
        conn.commit()
    finally:
        conn.close()
