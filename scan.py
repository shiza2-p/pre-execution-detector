import sys
import json
import time
import sqlite3
from pathlib import Path
from hasher import sha256_of_file
from vt_check import vt_lookup

DB_PATH = Path(__file__).with_name("cache.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS results "
        "(sha256 TEXT PRIMARY KEY, stats TEXT, checked_at REAL)"
    )
    return conn

def lookup(sha256):
    conn = get_db()
    row = conn.execute(
        "SELECT stats FROM results WHERE sha256 = ?", (sha256,)
    ).fetchone()
    if row:
        return json.loads(row[0]), "cache"
    stats = vt_lookup(sha256)
    conn.execute(
        "INSERT OR REPLACE INTO results VALUES (?, ?, ?)",
        (sha256, json.dumps(stats), time.time()),
    )
    conn.commit()
    return stats, "virustotal"

if __name__ == "__main__":
    h = sha256_of_file(sys.argv[1])
    stats, source = lookup(h)
    print("SHA-256:", h)
    print("Answer came from:", source)
    print("Stats:", stats)