#!/usr/bin/env python3
"""Rotate the audit root key (security-officer operation; needs BOTH the auditor keyring and the host dir).

A new root key is added to the auditor keyring; the host's chain restarts from a key derived from it.
Nothing derived from the old epoch remains on the host, and old records stay readable by the auditor.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from medaudit.auditlog import AuditWriter, add_key
from medaudit.config import Config

cfg = Config(data_dir=os.environ.get("MEDAUDIT_DATA", "data"))
nid, root = add_key(cfg.root_keys)
AuditWriter(cfg.audit_dir).rotate_epoch(nid, root, actor="secofficer")
print(f"rotated: new key epoch {nid} (old records remain verifiable with the auditor keyring)")
