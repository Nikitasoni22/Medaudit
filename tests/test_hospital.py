"""Hospital service tests: Zero Trust RBAC, break-glass, lockout, fail-closed auditing, no PHI in logs."""
import os
import time

import pytest
from fastapi.testclient import TestClient

from medaudit.auditlog import AuditVerifier, load_keyring
from medaudit.config import Config
from medaudit.hospital.app import create
from medaudit.setup import init_system, DEMO_PASSWORDS


@pytest.fixture
def sys_(tmp_path):
    cfg = Config(data_dir=str(tmp_path / "data"), pbkdf2_iters=1000)
    init_system(cfg, demo=True)
    c = TestClient(create(cfg))
    return c, cfg


def login(c, user, pw=None):
    r = c.post("/api/login", json={"username": user, "password": pw or DEMO_PASSWORDS[user]})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def audit_entries(cfg):
    import json
    r = AuditVerifier(cfg.audit_dir, cfg.root_keys).scan(collect=True)
    assert r.ok, r.reason
    return [(e, json.loads(e.message)) for e in r.entries]


def events(cfg, name):
    return [(e, d) for e, d in audit_entries(cfg) if d["event"] == name]


def test_unauthenticated_is_rejected(sys_):
    c, _ = sys_
    assert c.get("/api/patients").status_code == 401
    assert c.get("/api/patients/P-1001", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_login_logout_and_session(sys_):
    c, cfg = sys_
    h = login(c, "dr.rao")
    assert c.get("/api/me", headers=h).json()["role"] == "doctor"
    assert c.post("/api/logout", headers=h).status_code == 200
    assert c.get("/api/me", headers=h).status_code == 401
    assert events(cfg, "LOGIN_SUCCESS") and events(cfg, "LOGOUT")


def test_failed_login_is_generic_and_logged(sys_):
    c, cfg = sys_
    r1 = c.post("/api/login", json={"username": "dr.rao", "password": "wrong-password"})
    r2 = c.post("/api/login", json={"username": "nobody", "password": "wrong-password"})
    assert r1.status_code == r2.status_code == 401 and r1.json() == r2.json()  # no user enumeration
    ev = events(cfg, "LOGIN_FAILED")
    assert len(ev) == 2
    assert "password" not in str([d for _, d in ev]).lower().replace("bad_credentials", "")


def test_lockout_after_repeated_failures(sys_):
    c, cfg = sys_
    for _ in range(cfg.lockout_attempts):
        c.post("/api/login", json={"username": "dr.sen", "password": "wrong-password"})
    r = c.post("/api/login", json={"username": "dr.sen", "password": DEMO_PASSWORDS["dr.sen"]})
    assert r.status_code == 401                      # even the right password is refused while locked
    assert events(cfg, "ACCOUNT_LOCKED")


def test_session_idle_expiry(sys_):
    c, cfg = sys_
    h = login(c, "dr.rao")
    c.app.state.cfg.session_idle_seconds = 0
    time.sleep(0.05)
    assert c.get("/api/me", headers=h).status_code == 401
    assert events(cfg, "SESSION_REJECTED")


def test_receptionist_sees_demographics_only(sys_):
    c, cfg = sys_
    h = login(c, "recep.iyer")
    p = c.get("/api/patients/P-1001", headers=h).json()
    assert p["name"] and "diagnosis" not in p and p["clinical_access"] == "restricted"
    assert p["can_break_glass"] is False
    assert c.put("/api/patients/P-1001/clinical", json={"notes": "x"}, headers=h).status_code == 403
    assert c.post("/api/patients/P-1001/break-glass", json={"reason": "I would like to see it"}, headers=h).status_code == 403
    assert c.get("/api/admin/users", headers=h).status_code == 403
    assert events(cfg, "ACCESS_DENIED")


def test_doctor_assigned_vs_not_assigned(sys_):
    c, cfg = sys_
    h = login(c, "dr.rao")                                   # assigned to P-1001, P-1003, P-1005
    p = c.get("/api/patients/P-1001", headers=h).json()
    assert p["diagnosis"] and p["clinical_access"] == "assigned" and p["can_edit"]
    q = c.get("/api/patients/P-1002", headers=h).json()      # Dr. Sen's patient
    assert "diagnosis" not in q and q["clinical_access"] == "restricted" and q["can_break_glass"]
    assert c.put("/api/patients/P-1002/clinical", json={"notes": "x"}, headers=h).status_code == 403
    assert any(d.get("patient") == "P-1002" and d["permission"] == "patient.view_clinical"
               for _, d in events(cfg, "ACCESS_DENIED"))


def test_nurse_cannot_edit_but_can_read_assigned(sys_):
    c, _ = sys_
    h = login(c, "nurse.mehta")
    assert c.get("/api/patients/P-1001", headers=h).json()["diagnosis"]
    assert c.put("/api/patients/P-1001/clinical", json={"notes": "x"}, headers=h).status_code == 403


def test_doctor_update_is_audited_without_phi(sys_):
    c, cfg = sys_
    h = login(c, "dr.rao")
    r = c.put("/api/patients/P-1001/clinical", json={"notes": "SECRET-NOTE-XYZ", "diagnosis": "SECRET-DX-QQQ"}, headers=h)
    assert r.status_code == 200
    assert c.get("/api/patients/P-1001", headers=h).json()["notes"] == "SECRET-NOTE-XYZ"
    (e, d), = events(cfg, "PATIENT_UPDATE")
    assert d["patient"] == "P-1001" and d["fields"] == ["diagnosis", "notes"] and e.actor == "dr.rao"
    # no PHI anywhere in the audit log, neither plaintext on disk nor in decrypted records
    blob = open(os.path.join(cfg.audit_dir, "audit.log")).read() + str(audit_entries(cfg))
    for phi in ("SECRET-NOTE-XYZ", "SECRET-DX-QQQ", "Aarav", "Sharma", "Hypertension"):
        assert phi not in blob


def test_search_text_not_logged(sys_):
    c, cfg = sys_
    h = login(c, "recep.iyer")
    assert len(c.get("/api/patients?q=Aarav", headers=h).json()) == 1
    blob = str(audit_entries(cfg))
    assert "Aarav" not in blob
    assert events(cfg, "PATIENT_LIST")[-1][1]["search"] is True


def test_break_glass_flow(sys_):
    c, cfg = sys_
    h = login(c, "dr.rao")
    assert c.post("/api/patients/P-1002/break-glass", json={"reason": "short"}, headers=h).status_code == 422
    assert c.post("/api/patients/P-1001/break-glass", json={"reason": "not needed: already assigned"}, headers=h).status_code == 400
    r = c.post("/api/patients/P-1002/break-glass", json={"reason": "Patient collapsed in corridor, treating"}, headers=h)
    assert r.status_code == 200
    p = c.get("/api/patients/P-1002", headers=h).json()
    assert p["diagnosis"] and p["clinical_access"] == "break_glass"
    (e, d), = events(cfg, "BREAK_GLASS")
    assert e.severity == "CRITICAL" and d["patient"] == "P-1002" and "collapsed" in d["reason"]
    views = [(e, d) for e, d in events(cfg, "PATIENT_VIEW") if d.get("basis") == "break_glass"]
    assert views and views[0][0].severity == "WARN"
    # grant is scoped to that patient only
    assert "diagnosis" not in c.get("/api/patients/P-1004", headers=h).json()


def test_break_glass_expires(sys_):
    c, cfg = sys_
    h = login(c, "dr.rao")
    c.post("/api/patients/P-1002/break-glass", json={"reason": "Emergency treatment needed now"}, headers=h)
    with c.app.state.db.conn() as conn:
        conn.execute("UPDATE breakglass SET expires=?", (time.time() - 1,))
    assert "diagnosis" not in c.get("/api/patients/P-1002", headers=h).json()


def test_admin_has_no_phi_access(sys_):
    c, cfg = sys_
    h = login(c, "admin1")
    assert c.get("/api/patients", headers=h).status_code == 403
    assert c.get("/api/patients/P-1001", headers=h).status_code == 403
    ids = c.get("/api/admin/patient-ids", headers=h).json()
    assert ids and all(i.startswith("P-") for i in ids)
    assert c.post("/api/patients/P-1001/break-glass", json={"reason": "admin wants to look"}, headers=h).status_code == 403


def test_admin_user_management_is_audited(sys_):
    c, cfg = sys_
    h = login(c, "admin1")
    assert c.post("/api/admin/users", json={"username": "x1", "full_name": "X", "role": "doctor", "password": "short"}, headers=h).status_code == 422
    assert c.post("/api/admin/users", json={"username": "x1", "full_name": "New Doc", "role": "doctor", "password": "Strong#Passw0rd!"}, headers=h).status_code == 201
    assert c.post("/api/admin/assign", json={"username": "x1", "pid": "P-1004", "assigned": True}, headers=h).status_code == 200
    h2 = login(c, "x1", "Strong#Passw0rd!")
    assert c.get("/api/patients/P-1004", headers=h2).json()["diagnosis"]
    assert c.post("/api/admin/users/x1/active", json={"active": False}, headers=h).status_code == 200
    assert c.get("/api/me", headers=h2).status_code == 401           # sessions killed on disable
    assert c.post("/api/admin/users/admin1/active", json={"active": False}, headers=h).status_code == 400
    for ev in ("USER_CREATE", "ASSIGNMENT_ADD", "USER_DISABLE"):
        assert events(cfg, ev), ev
    assert events(cfg, "USER_CREATE")[0][1]["target"] == "x1"


def test_create_patient_and_doctor_auto_assigned(sys_):
    c, cfg = sys_
    h = login(c, "dr.sen")
    r = c.post("/api/patients", json={"name": "Test Person", "dob": "2000-01-01", "sex": "F", "ward": "ER"}, headers=h)
    assert r.status_code == 201
    pid = r.json()["pid"]
    assert c.get(f"/api/patients/{pid}", headers=h).json()["clinical_access"] == "assigned"
    assert c.post("/api/patients", json={"name": "x", "dob": "bad", "sex": "F"}, headers=h).status_code == 422
    assert events(cfg, "PATIENT_CREATE")[0][1]["patient"] == pid


def test_fail_closed_when_audit_log_unavailable(sys_):
    """No audit record => no data. Break the audit store and make sure PHI is not served."""
    c, cfg = sys_
    h = login(c, "dr.rao")
    assert c.get("/api/patients/P-1001", headers=h).status_code == 200
    os.rename(os.path.join(cfg.audit_dir, "state.key"), os.path.join(cfg.audit_dir, "state.key.unavailable"))            # writer refuses unsafe state
    r = c.get("/api/patients/P-1001", headers=h)
    assert r.status_code == 503 and "diagnosis" not in r.text
    assert c.get("/api/patients", headers=h).status_code == 503
    assert c.post("/api/login", json={"username": "dr.rao", "password": DEMO_PASSWORDS["dr.rao"]}).status_code == 503


def test_update_not_applied_if_audit_fails(sys_):
    c, cfg = sys_
    h = login(c, "dr.rao")
    os.rename(os.path.join(cfg.audit_dir, "state.key"), os.path.join(cfg.audit_dir, "state.key.unavailable"))
    assert c.put("/api/patients/P-1001/clinical", json={"notes": "CHANGED"}, headers=h).status_code == 503
    os.rename(os.path.join(cfg.audit_dir, "state.key.unavailable"), os.path.join(cfg.audit_dir, "state.key"))
    assert c.get("/api/patients/P-1001", headers=h).json()["notes"] != "CHANGED"


def test_input_validation_and_security_headers(sys_):
    c, _ = sys_
    h = login(c, "dr.rao")
    assert c.get("/api/patients/..%2f..%2fetc", headers=h).status_code == 404
    assert c.get("/api/patients/P-9999", headers=h).status_code == 404
    assert c.get("/api/patients/1' OR '1'='1", headers=h).status_code == 404
    r = c.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff" and "frame-ancestors" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_log_is_verifiable_and_tamper_evident_end_to_end(sys_):
    c, cfg = sys_
    h = login(c, "dr.rao")
    for i in range(3):
        c.get("/api/patients/P-1001", headers=h)
    v = AuditVerifier(cfg.audit_dir, cfg.root_keys)
    assert v.scan().ok
    log = os.path.join(cfg.audit_dir, "audit.log")
    ls = open(log).read().split("\n")[:-1]
    open(log, "w").write("\n".join(ls[:-2]) + "\n")                      # attacker cuts the tail
    assert not v.scan().ok
