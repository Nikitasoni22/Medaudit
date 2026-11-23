"""Tamper-evident, forward-secure, encrypted audit log.

Public API:
    AuditWriter   - runs on the logging host; holds only the *current* chain key.
    AuditVerifier - runs on the auditor side; holds the root key(s).
    Checkpoint    - (seq, hash) published off-host to detect rollback.
"""
from .core import (  # noqa: F401
    AuditWriter, AuditVerifier, Checkpoint, Entry, ScanResult, AuditError,
    IntegrityError, KeyringError, create_keyring, add_key, load_keyring,
    SEVERITIES,
)
