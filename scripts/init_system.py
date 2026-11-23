#!/usr/bin/env python3
"""Initialise MedAudit: keys, databases, accounts.   usage: python scripts/init_system.py [--demo] [--data DIR]"""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from medaudit.config import Config
from medaudit.setup import init_system

ap = argparse.ArgumentParser()
ap.add_argument("--data", default=os.environ.get("MEDAUDIT_DATA", "data"))
ap.add_argument("--demo", action="store_true", help="fixed, documented demo passwords (NOT for real use)")
ap.add_argument("--no-seed", action="store_true", help="do not insert the synthetic demo patients")
a = ap.parse_args()
cfg = Config(data_dir=a.data)
pw = init_system(cfg, demo=a.demo, seed_patients=not a.no_seed)
print(f"Initialised in {a.data}/\n")
print("Hospital app (http://127.0.0.1:8000):")
for u in ("admin1", "dr.rao", "dr.sen", "nurse.mehta", "recep.iyer"):
    print(f"  {u:12s} {pw[u]}")
print("Auditor console (http://127.0.0.1:8001):")
print(f"  {'auditor1':12s} {pw['auditor1']}")
if not a.demo:
    print("\nSave these now: they are shown only once.")
