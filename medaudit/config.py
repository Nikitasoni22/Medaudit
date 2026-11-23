"""Configuration and on-disk layout shared by the services and scripts.

    DATA/
      hospital/            <- the LOGGING HOST (can be compromised)
        hospital.db           patients, users, sessions
        audit/                audit.log, state.key (current chain key only), anchor.mac
      auditor/             <- AUDITOR side (separate machine / account in production)
        root.keys             root keys for the hospital audit log      (0600)
        checkpoints.jsonl     off-host checkpoints (append-only)
        alerts.jsonl          tamper alerts
        auditors.json         console accounts (PBKDF2 hashes)
        console_root.keys     root key for the console's own activity log
        console_audit/        the console's own tamper-evident activity log
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Config:
    data_dir: str = "data"
    pbkdf2_iters: int = 310_000          # password hashing cost (tests lower this)
    session_idle_seconds: int = 15 * 60
    session_max_seconds: int = 8 * 3600
    lockout_attempts: int = 5
    lockout_seconds: int = 300
    breakglass_minutes: int = 30
    checkpoint_interval: int = 300       # seconds between automatic verify+checkpoint; 0 = off
    hospital_port: int = 8000
    auditor_port: int = 8001

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ.get
        return cls(
            data_dir=e("MEDAUDIT_DATA", "data"),
            checkpoint_interval=int(e("MEDAUDIT_CHECKPOINT_INTERVAL", "300")),
            pbkdf2_iters=int(e("MEDAUDIT_PBKDF2_ITERS", "310000")),
        )

    # -- paths -----------------------------------------------------------------
    @property
    def hospital_dir(self) -> str: return os.path.join(self.data_dir, "hospital")
    @property
    def hospital_db(self) -> str: return os.path.join(self.hospital_dir, "hospital.db")
    @property
    def audit_dir(self) -> str: return os.path.join(self.hospital_dir, "audit")
    @property
    def auditor_dir(self) -> str: return os.path.join(self.data_dir, "auditor")
    @property
    def root_keys(self) -> str: return os.path.join(self.auditor_dir, "root.keys")
    @property
    def checkpoints_file(self) -> str: return os.path.join(self.auditor_dir, "checkpoints.jsonl")
    @property
    def alerts_file(self) -> str: return os.path.join(self.auditor_dir, "alerts.jsonl")
    @property
    def auditors_file(self) -> str: return os.path.join(self.auditor_dir, "auditors.json")
    @property
    def console_keys(self) -> str: return os.path.join(self.auditor_dir, "console_root.keys")
    @property
    def console_audit_dir(self) -> str: return os.path.join(self.auditor_dir, "console_audit")
