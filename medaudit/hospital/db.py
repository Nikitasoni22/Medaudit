"""SQLite storage for the hospital app (users, patients, assignments, sessions, break-glass)."""
from __future__ import annotations

import os
import sqlite3
from ..auditlog.platformio import make_private
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('doctor','nurse','receptionist','admin')),
  pw_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
  failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS patients(
  id INTEGER PRIMARY KEY, pid TEXT UNIQUE NOT NULL, name TEXT NOT NULL, dob TEXT NOT NULL,
  sex TEXT NOT NULL, ward TEXT NOT NULL DEFAULT '',
  diagnosis TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS assignments(
  user_id INTEGER NOT NULL REFERENCES users(id), patient_id INTEGER NOT NULL REFERENCES patients(id),
  PRIMARY KEY(user_id, patient_id));
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  created REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS breakglass(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, patient_id INTEGER NOT NULL,
  reason TEXT NOT NULL, expires REAL NOT NULL);
"""


class DB:
    def __init__(self, path: str):
        self.path = path

    def init(self) -> None:
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        with self.conn() as c:
            c.executescript(SCHEMA)
        make_private(self.path)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()
