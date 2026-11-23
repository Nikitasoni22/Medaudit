#!/usr/bin/env python3
"""Verify the audit log from the command line (e.g. cron on the auditor machine).

    python scripts/verify_offline.py [--expect SEQ:HASH ...]     exit 0 = ok, 6 = tamper, 7 = key error
"""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from medaudit.auditlog import AuditVerifier, Checkpoint, KeyringError
from medaudit.config import Config

ap = argparse.ArgumentParser(); ap.add_argument("--expect", action="append", default=[]); ap.add_argument("--data", default=os.environ.get("MEDAUDIT_DATA", "data"))
a = ap.parse_args(); cfg = Config(data_dir=a.data)
try:
    r = AuditVerifier(cfg.audit_dir, cfg.root_keys).scan(expect=[Checkpoint.parse(x) for x in a.expect])
except KeyringError as e:
    print("key error:", e); sys.exit(7)
if r.ok: print(f"OK: {r.records} records verified"); sys.exit(0)
print(f"TAMPERING DETECTED at record {r.bad_seq}: {r.reason}"); sys.exit(6)
