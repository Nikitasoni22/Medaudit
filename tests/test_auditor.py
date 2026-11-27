"""Auditor console + end-to-end tests (hospital and auditor apps sharing one data dir)."""
import os
import shutil

import pytest
from fastapi.testclient import TestClient

from medaudit.auditor.app import create as create_auditor
from medaudit.config import Config
from medaudit.hospital.app import create as create_hospital
from medaudit.setup import DEMO_PASSWORDS, init_system


@pytest.fixture
def both(tmp_path):
    cfg = Config(data_dir=str(tmp_path / "data"), pbkdf2_iters=1000, checkpoint_interval=0)
    init_system(cfg, demo=True)
    return TestClient(create_hospital(cfg)), TestClient(create_auditor(cfg)), cfg


def hl(c, u):
    return {"Authorization": "Bearer " + c.post("/api/login", json={"username": u, "password": DEMO_PASSWORDS[u]}).json()["token"]}


def traffic(h, hdr):
    h.get("/api/patients", headers=hdr)
    h.get("/api/patients/P-1001", headers=hdr)
    h.get("/api/patients/P-1002", headers=hdr)  # denied clinical (Dr. Sen's)


def test_auditor_requires_login(both):
    _, a, _ = both
    assert a.get("/api/status").status_code == 401
    assert a.post("/api/login", json={"username": "auditor1", "password": "nope"}).status_code == 401
    # a hospital-staff account does not work on the auditor console
    assert a.post("/api/login", json={"username": "dr.rao", "password": DEMO_PASSWORDS["dr.rao"]}).status_code == 401


def test_status_logs_and_filters(both):
    h, a, cfg = both
    traffic(h, hl(h, "dr.rao"))
    ah = hl(a, "auditor1")
    s = a.get("/api/status", headers=ah).json()
    assert s["ok"] and s["records"] >= 5
    r = a.get("/api/logs?event=ACCESS_DENIED", headers=ah).json()
    assert r["total"] == 1 and r["rows"][0]["data"]["patient"] == "P-1002"
    assert all(x["actor"] == "dr.rao" for x in a.get("/api/logs?user=dr.rao", headers=ah).json()["rows"])
    assert a.get("/api/logs?patient=P-1001", headers=ah).json()["total"] == 1
    assert all(x["severity"] in ("WARN", "ERROR", "CRITICAL") for x in a.get("/api/logs?severity=WARN", headers=ah).json()["rows"])


def test_patient_accounting_of_disclosures_and_break_glass_report(both):
    h, a, _ = both
    hr = hl(h, "dr.rao")
    h.post("/api/patients/P-1002/break-glass", json={"reason": "Patient collapsed in corridor, treating"}, headers=hr)
    h.get("/api/patients/P-1002", headers=hr)
    ah = hl(a, "auditor1")
    rep = a.get("/api/reports/patient/P-1002", headers=ah).json()
    bases = {x["basis"] for x in rep["accesses"]}
    assert "break_glass" in bases and any(x["event"] == "BREAK_GLASS" and "collapsed" in x["reason"] for x in rep["accesses"])
    bg = a.get("/api/reports/break-glass", headers=ah).json()
    assert len(bg["grants"]) == 1 and bg["views_under_break_glass"] == 1
    assert a.get("/api/reports/user/dr.rao", headers=ah).json()["count"] >= 3
    sm = a.get("/api/reports/summary", headers=ah).json()
    assert sm["break_glass"] == 1


def test_tamper_blocks_release_and_raises_alert(both):
    h, a, cfg = both
    traffic(h, hl(h, "dr.rao"))
    ah = hl(a, "auditor1")
    assert a.post("/api/checkpoint", headers=ah).status_code == 200
    log = os.path.join(cfg.audit_dir, "audit.log")
    ls = open(log).read().split("\n")[:-1]
    f = ls[2].split("|"); f[7] = ("1" if f[7][0] == "0" else "0") + f[7][1:]; ls[2] = "|".join(f)
    open(log, "w", newline="").write("\n".join(ls) + "\n")
    r = a.get("/api/logs", headers=ah)
    assert r.status_code == 409 and "withheld" in r.text and r.json()["detail"]["bad_seq"] == 3
    assert a.get("/api/reports/patient/P-1001", headers=ah).status_code == 409
    s = a.get("/api/status", headers=ah).json()
    assert not s["ok"] and s["bad_seq"] == 3
    assert a.post("/api/checkpoint", headers=ah).status_code == 409        # never certify a bad log
    assert len(a.get("/api/alerts", headers=ah).json()) == 1               # one alert, not one per poll


def test_tail_truncation_alert(both):
    h, a, cfg = both
    traffic(h, hl(h, "dr.rao"))
    ah = hl(a, "auditor1")
    log = os.path.join(cfg.audit_dir, "audit.log")
    ls = open(log).read().split("\n")[:-1]
    open(log, "w", newline="").write("\n".join(ls[:-3]) + "\n")
    s = a.post("/api/verify", headers=ah).json()
    assert not s["ok"] and "truncated" in s["reason"]


def test_rollback_detected_by_published_checkpoint(both, tmp_path):
    h, a, cfg = both
    hr = hl(h, "dr.rao"); ah = hl(a, "auditor1")
    traffic(h, hr)
    snap = str(tmp_path / "old_host"); shutil.copytree(cfg.audit_dir, snap)   # attacker backup
    traffic(h, hr); traffic(h, hr)
    assert a.post("/api/checkpoint", headers=ah).json()["checkpoint"]
    shutil.rmtree(cfg.audit_dir); shutil.copytree(snap, cfg.audit_dir)        # full host rollback
    s = a.post("/api/verify", headers=ah).json()
    assert not s["ok"] and "checkpoint" in s["reason"]


def test_concurrent_logging_never_false_alarms(both):
    """Verifier reads while the hospital is writing: must never report tampering."""
    import threading
    h, a, cfg = both
    hr = hl(h, "dr.rao"); ah = hl(a, "auditor1")
    stop = threading.Event(); results = []

    def writer():
        while not stop.is_set():
            h.get("/api/patients/P-1001", headers=hr)

    t = threading.Thread(target=writer); t.start()
    try:
        for _ in range(15):
            results.append(a.post("/api/verify", headers=ah).json()["ok"])
    finally:
        stop.set(); t.join()
    assert all(results)


def test_console_activity_is_itself_logged_and_verifiable(both):
    h, a, cfg = both
    traffic(h, hl(h, "dr.rao"))
    ah = hl(a, "auditor1")
    a.get("/api/logs?patient=P-1001", headers=ah)
    a.get("/api/reports/patient/P-1001", headers=ah)
    rows = a.get("/api/console-log", headers=ah).json()["rows"]
    events = [r["data"]["event"] for r in rows]
    assert "CONSOLE_LOGIN" in events and "VIEW_LOGS" in events and "REPORT_PATIENT" in events
    assert all(r["actor"] == "auditor1" for r in rows if r["data"]["event"] == "VIEW_LOGS")
    # and it is tamper evident
    clog = os.path.join(cfg.console_audit_dir, "audit.log")
    ls = open(clog).read().split("\n")[:-1]
    open(clog, "w").write("\n".join(ls[:-1]) + "\n")
    assert a.get("/api/console-log", headers=ah).status_code == 409


def test_failed_console_logins_are_logged_and_locked(both):
    _, a, cfg = both
    for _ in range(cfg.lockout_attempts):
        a.post("/api/login", json={"username": "auditor1", "password": "wrong"})
    assert a.post("/api/login", json={"username": "auditor1", "password": DEMO_PASSWORDS["auditor1"]}).status_code == 401


def test_root_key_not_on_hospital_side(both):
    """The logging host has no root key: nothing under hospital/ can decrypt the log."""
    _, _, cfg = both
    for dp, _, fs in os.walk(cfg.hospital_dir):
        for f in fs:
            assert "root" not in f
    assert not os.path.exists(os.path.join(cfg.hospital_dir, "root.keys"))
