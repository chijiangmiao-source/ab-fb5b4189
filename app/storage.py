"""SQLite-backed store for frozen audit conclusions."""
from __future__ import annotations

import json
import os
import sqlite3
import threading


class AuditStore:
    def __init__(self, db_path):
        self._lock = threading.Lock()
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS audits ("
            " audit_id TEXT PRIMARY KEY,"
            " doc TEXT NOT NULL,"
            " created_at TEXT NOT NULL)"
        )
        self._conn.commit()

    def get(self, audit_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT doc FROM audits WHERE audit_id = ?", (audit_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def create(self, audit_id, doc, created_at):
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO audits (audit_id, doc, created_at) VALUES (?, ?, ?)",
                    (audit_id, json.dumps(doc, ensure_ascii=False), created_at),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                return False
        return True

    def close(self):
        self._conn.close()
