#!/usr/bin/env python3
"""Start both services as SEPARATE processes (as they would be in production).

    python run.py --demo          # first run: initialises ./data with demo accounts, then starts
    python run.py                 # later runs

Hospital app:     http://127.0.0.1:8000     (logging host: can write the audit log, cannot decrypt it)
Auditor console:  http://127.0.0.1:8001     (holds the root key: verifies, decrypts, reports)
"""
import argparse, os, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from medaudit.config import Config
from medaudit.setup import init_system

ap = argparse.ArgumentParser()
ap.add_argument("--data", default=os.environ.get("MEDAUDIT_DATA", "data"))
ap.add_argument("--demo", action="store_true", help="initialise with documented demo passwords if no data exists")
ap.add_argument("--checkpoint-interval", type=int, default=60, help="seconds between automatic verify+checkpoint (0=off)")
ap.add_argument("--host", default="127.0.0.1")
a = ap.parse_args()

cfg = Config(data_dir=a.data)
if not os.path.exists(cfg.hospital_db):
    if not a.demo:
        sys.exit("No data found. Run:  python scripts/init_system.py   (or: python run.py --demo)")
    pw = init_system(cfg, demo=True)
    print("Initialised demo data in", a.data)
    for u, p in pw.items():
        print(f"   {u:12s} {p}")

env = dict(os.environ, MEDAUDIT_DATA=a.data, MEDAUDIT_CHECKPOINT_INTERVAL=str(a.checkpoint_interval), PYTHONPATH=HERE)
def start(app, port):
    return subprocess.Popen([sys.executable, "-m", "uvicorn", app, "--factory", "--host", a.host, "--port", str(port),
                             "--log-level", "warning"], env=env, cwd=HERE)
procs = [start("medaudit.hospital.app:create", cfg.hospital_port), start("medaudit.auditor.app:create", cfg.auditor_port)]
print(f"\n  Hospital app     http://{a.host}:{cfg.hospital_port}\n  Auditor console  http://{a.host}:{cfg.auditor_port}\n  (Ctrl+C to stop)\n")
try:
    while all(p.poll() is None for p in procs):
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
finally:
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for p in procs:
        try: p.wait(5)
        except subprocess.TimeoutExpired: p.kill()
