#!/usr/bin/env python3
"""Simulate an attacker with filesystem access to the logging host (FOR DEMOS / TESTING ONLY).

    python scripts/attack_demo.py flip [N]      flip one bit of record N's ciphertext (default 3)
    python scripts/attack_demo.py edit-sev [N]  change a record's plaintext severity
    python scripts/attack_demo.py delete [N]    delete record N
    python scripts/attack_demo.py truncate [K]  silently cut the last K records (default 3)
    python scripts/attack_demo.py backup        take a full backup of the host's audit directory
    python scripts/attack_demo.py rollback      restore that backup over the host (whole-host rollback)
    python scripts/attack_demo.py undo          restore the state from just before the last attack

Then open the Auditor console and press "Verify now".
"""
import os, shutil, sys
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from medaudit.config import Config

cfg = Config(data_dir=os.environ.get("MEDAUDIT_DATA", "data"))
AUD, LOG = cfg.audit_dir, os.path.join(cfg.audit_dir, "audit.log")
BACKUP, PRE = os.path.join(cfg.data_dir, ".attacker_backup"), os.path.join(cfg.data_dir, ".pre_attack")

cmd = sys.argv[1] if len(sys.argv) > 1 else ""
n = int(sys.argv[2]) if len(sys.argv) > 2 else None
def lines(): return open(LOG).read().split("\n")[:-1]
def save(ls): open(LOG, "w", newline="").write("\n".join(ls) + "\n")
def snapshot(dst): shutil.rmtree(dst, ignore_errors=True); shutil.copytree(AUD, dst)
def restore(src): shutil.rmtree(AUD); shutil.copytree(src, AUD)

if cmd in ("flip", "edit-sev", "delete", "truncate"): snapshot(PRE)
if cmd == "flip":
    ls = lines(); i = (n or 3) - 1; f = ls[i].split("|"); f[7] = ("1" if f[7][0] == "0" else "0") + f[7][1:]
    ls[i] = "|".join(f); save(ls); print(f"flipped one ciphertext bit in record {i+1}")
elif cmd == "edit-sev":
    ls = lines(); i = (n or 3) - 1; f = ls[i].split("|"); f[3] = "DEBUG" if f[3] != "DEBUG" else "CRITICAL"
    ls[i] = "|".join(f); save(ls); print(f"edited the severity of record {i+1}")
elif cmd == "delete":
    ls = lines(); i = (n or 3) - 1; del ls[i]; save(ls); print(f"deleted record {i+1}")
elif cmd == "truncate":
    k = n or 3; save(lines()[:-k]); print(f"cut the last {k} records off the log")
elif cmd == "backup": snapshot(BACKUP); print("backup of the whole audit directory taken")
elif cmd == "rollback":
    snapshot(PRE); restore(BACKUP); print("restored the old backup over the host (log + anchor + key state)")
elif cmd == "undo": restore(PRE); print("restored the state from just before the last attack")
else: print(__doc__)
