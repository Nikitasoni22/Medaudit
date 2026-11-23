"""One-time system initialisation (keys, databases, accounts). Used by scripts/init_system.py and tests."""
from __future__ import annotations

import json
import os
import secrets
import string
import time

from .auditlog import AuditWriter, create_keyring
from .config import Config
from .hospital.db import DB
from .security import hash_password

DEMO_PASSWORDS = {
    "admin1": "Admin#Pass2026", "dr.rao": "Doctor#Pass2026", "dr.sen": "Doctor#Pass2027",
    "nurse.mehta": "Nurse#Pass2026", "recep.iyer": "Recept#Pass2026", "auditor1": "Auditor#Pass2026",
}

USERS = [  # username, full name, role
    ("admin1", "Anita Kulkarni (IT admin)", "admin"),
    ("dr.rao", "Dr. Vikram Rao", "doctor"),
    ("dr.sen", "Dr. Meera Sen", "doctor"),
    ("nurse.mehta", "Nurse Pooja Mehta", "nurse"),
    ("recep.iyer", "Ravi Iyer (front desk)", "receptionist"),
]

PATIENTS = [  # synthetic data only
    ("Aarav Sharma", "1984-03-12", "M", "Cardiology", "Hypertension, stage 2", "BP 160/100 on admission. Started amlodipine 5 mg."),
    ("Diya Nair", "1991-07-30", "F", "Maternity", "Gestational diabetes", "28 weeks. Diet plan reviewed; glucose log requested."),
    ("Kabir Singh", "1972-11-02", "M", "Orthopaedics", "Fractured left femur", "Post-op day 2. Physiotherapy scheduled."),
    ("Ishita Verma", "2003-01-19", "F", "General", "Typhoid fever", "Blood culture positive. IV ceftriaxone."),
    ("Rohan Das", "1965-09-08", "M", "Oncology", "Chronic myeloid leukaemia", "Imatinib 400 mg daily. CBC weekly."),
    ("Sana Khan", "1998-05-22", "F", "Psychiatry", "Major depressive disorder", "Sensitive record. CBT weekly; SSRI started."),
]

ASSIGN = {"dr.rao": [0, 2, 4], "dr.sen": [1, 3, 5], "nurse.mehta": [0, 1]}


def _random_password() -> str:
    a = string.ascii_letters + string.digits
    return "".join(secrets.choice(a) for _ in range(14)) + "#1a"


def init_system(cfg: Config, demo: bool = False, seed_patients: bool = True) -> dict[str, str]:
    """Create everything. Returns {username: password}. Refuses to overwrite an existing install."""
    if os.path.exists(cfg.hospital_db) or os.path.exists(cfg.root_keys):
        raise SystemExit(f"already initialised in {cfg.data_dir} (delete it to start over)")
    for d in (cfg.data_dir, cfg.hospital_dir, cfg.auditor_dir):
        os.makedirs(d, mode=0o700, exist_ok=True)

    # 1. root key lives on the AUDITOR side only; the hospital host receives just the chain start key
    root = create_keyring(cfg.root_keys)
    AuditWriter.initialize(cfg.audit_dir, root)
    del root

    # 2. the console's own activity log (separate key + separate store)
    croot = create_keyring(cfg.console_keys)
    AuditWriter.initialize(cfg.console_audit_dir, croot)

    # 3. hospital database
    pw = {u: (DEMO_PASSWORDS[u] if demo else _random_password()) for u, _, _ in USERS}
    pw["auditor1"] = DEMO_PASSWORDS["auditor1"] if demo else _random_password()
    db = DB(cfg.hospital_db)
    db.init()
    with db.conn() as c:
        for u, name, role in USERS:
            c.execute("INSERT INTO users(username,full_name,role,pw_hash) VALUES(?,?,?,?)",
                      (u, name, role, hash_password(pw[u], cfg.pbkdf2_iters)))
        if seed_patients:
            for i, (n, dob, sex, ward, dx, notes) in enumerate(PATIENTS, start=1):
                c.execute("INSERT INTO patients(id,pid,name,dob,sex,ward,diagnosis,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                          (i, f"P-{1000 + i}", n, dob, sex, ward, dx, notes, time.time()))
            ids = {r["username"]: r["id"] for r in c.execute("SELECT id, username FROM users")}
            for uname, idxs in ASSIGN.items():
                for ix in idxs:
                    c.execute("INSERT INTO assignments(user_id,patient_id) VALUES(?,?)", (ids[uname], ix + 1))

    # 4. auditor console accounts
    acc = {"auditor1": {"full_name": "Neha Joshi (compliance)", "pw_hash": hash_password(pw["auditor1"], cfg.pbkdf2_iters)}}
    fd = os.open(cfg.auditors_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, json.dumps(acc).encode())
    os.close(fd)
    return pw
