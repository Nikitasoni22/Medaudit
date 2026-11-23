"""Hospital records service (FastAPI).

Zero Trust rules enforced on every request:
  * authenticate (bearer session token, idle + absolute expiry, account still active)
  * authorize (role AND care relationship; deny by default)
  * AUDIT FIRST, fail closed: the audit record is written before any patient data is released;
    if the audit log cannot be written, the request is refused with 503.
Patient names / diagnoses are never written to the audit log (only the patient ID).
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..auditlog import AuditWriter
from ..config import Config
from ..security import hash_password, new_token, password_problem, token_digest, verify_password
from .db import DB
from .rbac import ROLES, decide

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
DATE_RE = r"^\d{4}-\d{2}-\d{2}$"
PID_RE = re.compile(r"^P-\d{4,9}$")


# ------------------------------------------------------------------ request models
class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class PatientIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    dob: str = Field(pattern=DATE_RE)
    sex: str = Field(pattern=r"^[MFO]$")
    ward: str = Field(default="", max_length=40)


class ClinicalIn(BaseModel):
    diagnosis: Optional[str] = Field(default=None, max_length=2000)
    notes: Optional[str] = Field(default=None, max_length=8000)


class BreakGlassIn(BaseModel):
    reason: str = Field(min_length=10, max_length=300)


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,32}$")
    full_name: str = Field(min_length=1, max_length=80)
    role: str
    password: str = Field(max_length=200)


class ActiveIn(BaseModel):
    active: bool


class AssignIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,32}$")
    pid: str = Field(pattern=r"^P-\d{4,9}$")
    assigned: bool


# ------------------------------------------------------------------ factory
def create(cfg: Optional[Config] = None) -> FastAPI:
    cfg = cfg or Config.from_env()
    db = DB(cfg.hospital_db)
    writer = AuditWriter(cfg.audit_dir)
    app = FastAPI(title="MedAudit Hospital", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.cfg, app.state.db, app.state.writer = cfg, db, writer

    # -------------------------------------------------- audit helper (fail closed)
    def audit(ctx: dict, event: str, sev: str = "INFO", actor: Optional[str] = None, **fields) -> None:
        payload = {"event": event, "role": ctx.get("role"), "ip": ctx["ip"], "req": ctx["req"], **fields}
        payload = {k: v for k, v in payload.items() if v is not None}
        who = actor or ctx.get("username") or "anonymous"
        try:
            writer.append(who if NAME_RE.match(who) else "anonymous", sev,
                          json.dumps(payload, separators=(",", ":"), sort_keys=True))
        except Exception:
            raise HTTPException(503, "audit log unavailable: request refused")

    def base_ctx(request: Request) -> dict:
        return {"ip": request.client.host if request.client else "unknown", "req": uuid.uuid4().hex[:12]}

    # -------------------------------------------------- authentication dependency
    def current(request: Request) -> dict:
        ctx = base_ctx(request)
        h = request.headers.get("authorization", "")
        if not h.lower().startswith("bearer "):
            raise HTTPException(401, "not authenticated")
        now = time.time()
        with db.conn() as c:
            row = c.execute(
                "SELECT s.token_hash, s.created, s.last_seen, u.id uid, u.username, u.role, u.full_name, u.active "
                "FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
                (token_digest(h[7:].strip()),)).fetchone()
            bad = (row is None or not row["active"] or now - row["last_seen"] > cfg.session_idle_seconds
                   or now - row["created"] > cfg.session_max_seconds)
            if bad:
                if row:
                    c.execute("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
                    c.commit()
                audit(ctx, "SESSION_REJECTED", "WARN", actor=row["username"] if row else None)
                raise HTTPException(401, "session invalid or expired")
            c.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, row["token_hash"]))
        ctx.update(uid=row["uid"], username=row["username"], role=row["role"], full_name=row["full_name"])
        return ctx

    def require(ctx: dict, perm: str, **kw):
        d = decide(ctx["role"], perm, **kw)
        if not d.allow and d.basis == "role_denied":
            audit(ctx, "ACCESS_DENIED", "WARN", permission=perm, basis=d.basis)
            raise HTTPException(403, "forbidden")
        return d

    def patient_row(c, pid: str):
        return c.execute("SELECT * FROM patients WHERE pid=?", (pid,)).fetchone()

    def relationship(c, ctx: dict, patient_id: int) -> tuple[bool, bool]:
        assigned = c.execute("SELECT 1 FROM assignments WHERE user_id=? AND patient_id=?",
                             (ctx["uid"], patient_id)).fetchone() is not None
        bg = c.execute("SELECT 1 FROM breakglass WHERE user_id=? AND patient_id=? AND expires>?",
                       (ctx["uid"], patient_id, time.time())).fetchone() is not None
        return assigned, bg

    def basic(p) -> dict:
        return {"pid": p["pid"], "name": p["name"], "dob": p["dob"], "sex": p["sex"], "ward": p["ward"]}

    # -------------------------------------------------- middleware: security headers
    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "frame-ancestors 'none'")
        if request.url.path.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # -------------------------------------------------- auth endpoints
    @app.post("/api/login")
    def login(body: LoginIn, request: Request):
        ctx = base_ctx(request)
        now = time.time()
        uname = body.username.strip()
        with db.conn() as c:
            u = c.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
            locked = bool(u and u["locked_until"] > now)
            ok = verify_password(body.password, u["pw_hash"] if u else None, cfg.pbkdf2_iters)
            if not (u and ok and u["active"] and not locked):
                actor = uname if (u and NAME_RE.match(uname)) else "anonymous"
                extra = {"attempted_user": uname[:40]} if not u else {}
                if u and not locked:
                    n = u["failed_attempts"] + 1
                    if n >= cfg.lockout_attempts:
                        c.execute("UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?",
                                  (now + cfg.lockout_seconds, u["id"]))
                        audit(ctx | {"role": u["role"]}, "ACCOUNT_LOCKED", "ERROR", actor=actor)
                    else:
                        c.execute("UPDATE users SET failed_attempts=? WHERE id=?", (n, u["id"]))
                    c.commit()
                audit(ctx | ({"role": u["role"]} if u else {}), "LOGIN_FAILED", "WARN", actor=actor,
                      reason="locked" if locked else ("disabled" if u and not u["active"] else "bad_credentials"),
                      **extra)
                raise HTTPException(401, "invalid credentials or account locked")
            c.execute("UPDATE users SET failed_attempts=0 WHERE id=?", (u["id"],))
            tok = new_token()
            c.execute("INSERT INTO sessions(token_hash,user_id,created,last_seen) VALUES(?,?,?,?)",
                      (token_digest(tok), u["id"], now, now))
            c.commit()
            audit(ctx | {"role": u["role"]}, "LOGIN_SUCCESS", actor=u["username"])
        return {"token": tok, "user": {"username": u["username"], "full_name": u["full_name"], "role": u["role"]},
                "idle_seconds": cfg.session_idle_seconds}

    @app.post("/api/logout")
    def logout(request: Request, ctx: dict = Depends(current)):
        h = request.headers["authorization"][7:].strip()
        with db.conn() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (token_digest(h),))
        audit(ctx, "LOGOUT")
        return {"ok": True}

    @app.get("/api/me")
    def me(ctx: dict = Depends(current)):
        return {"username": ctx["username"], "full_name": ctx["full_name"], "role": ctx["role"]}

    # -------------------------------------------------- patients
    @app.get("/api/patients")
    def list_patients(q: str = "", ctx: dict = Depends(current)):
        require(ctx, "patient.list")
        q = q.strip()[:60]
        like = f"%{q}%"
        with db.conn() as c:
            rows = c.execute("SELECT * FROM patients WHERE ?='' OR name LIKE ? OR pid LIKE ? ORDER BY id LIMIT 200",
                             (q, like, like)).fetchall()
        audit(ctx, "PATIENT_LIST", search=bool(q), count=len(rows))  # query text itself is not logged
        return [basic(r) for r in rows]

    @app.post("/api/patients", status_code=201)
    def create_patient(body: PatientIn, ctx: dict = Depends(current)):
        require(ctx, "patient.create")
        with db.conn() as c:
            cur = c.execute("INSERT INTO patients(pid,name,dob,sex,ward,created_at) VALUES('tmp',?,?,?,?,?)",
                            (body.name.strip(), body.dob, body.sex, body.ward.strip(), time.time()))
            pid = f"P-{1000 + cur.lastrowid}"
            c.execute("UPDATE patients SET pid=? WHERE id=?", (pid, cur.lastrowid))
            if ctx["role"] == "doctor":
                c.execute("INSERT INTO assignments(user_id,patient_id) VALUES(?,?)", (ctx["uid"], cur.lastrowid))
            try:
                audit(ctx, "PATIENT_CREATE", patient=pid)
            except HTTPException:
                c.rollback()
                raise
        return {"pid": pid}

    @app.get("/api/patients/{pid}")
    def get_patient(pid: str, ctx: dict = Depends(current)):
        if not PID_RE.match(pid):
            raise HTTPException(404, "not found")
        require(ctx, "patient.view_basic")
        with db.conn() as c:
            p = patient_row(c, pid)
            if not p:
                audit(ctx, "PATIENT_NOT_FOUND", "WARN", patient=pid)
                raise HTTPException(404, "not found")
            assigned, bg = relationship(c, ctx, p["id"])
        d = decide(ctx["role"], "patient.view_clinical", assigned, bg)
        if d.allow:
            audit(ctx, "PATIENT_VIEW", "WARN" if d.basis == "break_glass" else "INFO",
                  patient=pid, scope="clinical", basis=d.basis)
        else:
            audit(ctx, "PATIENT_VIEW", patient=pid, scope="basic")
            if ctx["role"] in ("nurse", "doctor"):
                audit(ctx, "ACCESS_DENIED", "WARN", patient=pid, permission="patient.view_clinical", basis=d.basis)
        out = basic(p)
        if d.allow:
            out |= {"diagnosis": p["diagnosis"], "notes": p["notes"], "clinical_access": d.basis}
        else:
            out |= {"clinical_access": "restricted", "can_break_glass": ctx["role"] in ("nurse", "doctor")}
        out["can_edit"] = d.allow and ctx["role"] == "doctor"
        return out

    @app.put("/api/patients/{pid}/clinical")
    def update_clinical(pid: str, body: ClinicalIn, ctx: dict = Depends(current)):
        if not PID_RE.match(pid):
            raise HTTPException(404, "not found")
        require(ctx, "patient.update_clinical")
        with db.conn() as c:
            p = patient_row(c, pid)
            if not p:
                raise HTTPException(404, "not found")
            assigned, bg = relationship(c, ctx, p["id"])
            d = decide(ctx["role"], "patient.update_clinical", assigned, bg)
            if not d.allow:
                audit(ctx, "ACCESS_DENIED", "WARN", patient=pid, permission="patient.update_clinical", basis=d.basis)
                raise HTTPException(403, "forbidden")
            changed = [k for k in ("diagnosis", "notes") if getattr(body, k) is not None]
            audit(ctx, "PATIENT_UPDATE", patient=pid, fields=changed, basis=d.basis)  # audit BEFORE the write
            for k in changed:
                c.execute(f"UPDATE patients SET {k}=? WHERE id=?", (getattr(body, k), p["id"]))
        return {"ok": True, "updated": changed}

    @app.post("/api/patients/{pid}/break-glass")
    def break_glass(pid: str, body: BreakGlassIn, ctx: dict = Depends(current)):
        if not PID_RE.match(pid):
            raise HTTPException(404, "not found")
        require(ctx, "patient.breakglass")
        with db.conn() as c:
            p = patient_row(c, pid)
            if not p:
                raise HTTPException(404, "not found")
            assigned, _ = relationship(c, ctx, p["id"])
            if assigned:
                raise HTTPException(400, "you are already assigned to this patient")
            exp = time.time() + cfg.breakglass_minutes * 60
            audit(ctx, "BREAK_GLASS", "CRITICAL", patient=pid, reason=body.reason.strip(),
                  minutes=cfg.breakglass_minutes)
            c.execute("INSERT INTO breakglass(user_id,patient_id,reason,expires) VALUES(?,?,?,?)",
                      (ctx["uid"], p["id"], body.reason.strip(), exp))
        return {"ok": True, "expires_in_minutes": cfg.breakglass_minutes}

    # -------------------------------------------------- administration (no PHI)
    @app.get("/api/admin/users")
    def admin_users(ctx: dict = Depends(current)):
        require(ctx, "user.manage")
        audit(ctx, "USER_LIST")
        with db.conn() as c:
            rows = c.execute("SELECT username, full_name, role, active FROM users ORDER BY id").fetchall()
            asg = c.execute("SELECT u.username, p.pid FROM assignments a JOIN users u ON u.id=a.user_id "
                            "JOIN patients p ON p.id=a.patient_id ORDER BY u.username, p.pid").fetchall()
        return {"users": [dict(r) | {"active": bool(r["active"])} for r in rows],
                "assignments": [dict(r) for r in asg]}

    @app.get("/api/admin/patient-ids")
    def admin_patient_ids(ctx: dict = Depends(current)):
        require(ctx, "patient.list_ids")
        with db.conn() as c:
            return [r["pid"] for r in c.execute("SELECT pid FROM patients ORDER BY id")]

    @app.post("/api/admin/users", status_code=201)
    def admin_create_user(body: UserIn, ctx: dict = Depends(current)):
        require(ctx, "user.manage")
        if body.role not in ROLES:
            raise HTTPException(422, "unknown role")
        problem = password_problem(body.password)
        if problem:
            raise HTTPException(422, problem)
        with db.conn() as c:
            if c.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
                raise HTTPException(409, "username taken")
            audit(ctx, "USER_CREATE", "WARN", target=body.username, new_role=body.role)
            c.execute("INSERT INTO users(username,full_name,role,pw_hash) VALUES(?,?,?,?)",
                      (body.username, body.full_name.strip(), body.role, hash_password(body.password, cfg.pbkdf2_iters)))
        return {"ok": True}

    @app.post("/api/admin/users/{username}/active")
    def admin_set_active(username: str, body: ActiveIn, ctx: dict = Depends(current)):
        require(ctx, "user.manage")
        if username == ctx["username"]:
            raise HTTPException(400, "you cannot change your own status")
        with db.conn() as c:
            u = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not u:
                raise HTTPException(404, "not found")
            audit(ctx, "USER_ENABLE" if body.active else "USER_DISABLE", "WARN", target=username)
            c.execute("UPDATE users SET active=? WHERE id=?", (int(body.active), u["id"]))
            if not body.active:
                c.execute("DELETE FROM sessions WHERE user_id=?", (u["id"],))
        return {"ok": True}

    @app.post("/api/admin/assign")
    def admin_assign(body: AssignIn, ctx: dict = Depends(current)):
        require(ctx, "patient.assign")
        with db.conn() as c:
            u = c.execute("SELECT id, role FROM users WHERE username=?", (body.username,)).fetchone()
            p = patient_row(c, body.pid)
            if not u or not p:
                raise HTTPException(404, "not found")
            if u["role"] not in ("doctor", "nurse"):
                raise HTTPException(422, "only doctors and nurses can be assigned to patients")
            audit(ctx, "ASSIGNMENT_ADD" if body.assigned else "ASSIGNMENT_REMOVE", "WARN",
                  target=body.username, patient=body.pid)
            if body.assigned:
                c.execute("INSERT OR IGNORE INTO assignments(user_id,patient_id) VALUES(?,?)", (u["id"], p["id"]))
            else:
                c.execute("DELETE FROM assignments WHERE user_id=? AND patient_id=?", (u["id"], p["id"]))
        return {"ok": True}

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    static = os.path.join(os.path.dirname(__file__), "static")
    app.mount("/", StaticFiles(directory=static, html=True), name="static")
    return app
