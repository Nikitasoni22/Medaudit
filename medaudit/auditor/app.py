"""Auditor console (FastAPI): independent verification, decryption and compliance reports.

This service is the ONLY place that holds the root key. It:
  * re-verifies the hospital audit log (tags, hash chain, sequence, authenticated anchor)
  * publishes checkpoints (seq:hash) to its own append-only store and checks the log against ALL of them,
    which exposes tail truncation and whole-host rollback
  * refuses to release any log content from a log that fails verification
  * writes its own tamper-evident activity log (who looked at the audit trail)
"""
from __future__ import annotations

import json
import os
import threading
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..auditlog import (AuditError, AuditVerifier, AuditWriter, Checkpoint, KeyringError, ScanResult)
from ..config import Config
from ..security import new_token, token_digest, verify_password

SEV_ORDER = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3, "CRITICAL": 4}


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


def _append_jsonl(path: str, obj: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(obj, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_jsonl(path: str) -> list[dict]:
    try:
        return [json.loads(l) for l in open(path) if l.strip()]
    except FileNotFoundError:
        return []


def create(cfg: Optional[Config] = None) -> FastAPI:
    cfg = cfg or Config.from_env()
    verifier = AuditVerifier(cfg.audit_dir, cfg.root_keys)
    console_writer = AuditWriter(cfg.console_audit_dir)
    console_verifier = AuditVerifier(cfg.console_audit_dir, cfg.console_keys)
    scan_lock = threading.Lock()
    cache: dict = {"key": None, "res": None, "at": 0.0}
    sessions: dict[str, dict] = {}
    fails: dict[str, list] = {}
    stop = threading.Event()

    # ------------------------------------------------------------ checkpoints, alerts, scanning
    def checkpoints() -> list[Checkpoint]:
        return [Checkpoint(c["seq"], c["hash"]) for c in _read_jsonl(cfg.checkpoints_file)]

    def run_scan(force: bool = False) -> ScanResult:
        """Verify + decrypt, with all published checkpoints enforced. Cached until files change."""
        with scan_lock:
            cps = checkpoints()
            key = (verifier.fingerprint(), len(cps), os.path.getmtime(cfg.root_keys))
            if not force and cache["key"] == key and cache["res"] is not None:
                return cache["res"]
            res = verifier.scan(collect=True, expect=cps)
            cache.update(key=key, res=res, at=time.time())
            if not res.ok:
                last = (_read_jsonl(cfg.alerts_file) or [{}])[-1]
                if (last.get("bad_seq"), last.get("reason")) != (res.bad_seq, res.reason):
                    _append_jsonl(cfg.alerts_file, {"time": time.time(), "bad_seq": res.bad_seq, "reason": res.reason})
            return res

    def publish_checkpoint(res: ScanResult) -> Optional[Checkpoint]:
        if not res.ok or res.records == 0:
            return None
        cps = checkpoints()
        if cps and cps[-1].seq >= res.records:
            return None
        cp = Checkpoint(res.records, res.head_hash)
        _append_jsonl(cfg.checkpoints_file, {"time": time.time(), "seq": cp.seq, "hash": cp.hash})
        return cp

    def scheduler():
        while not stop.wait(cfg.checkpoint_interval):
            try:
                res = run_scan(force=True)
                cp = publish_checkpoint(res) if res.ok else None
                console_writer.append("scheduler", "INFO" if res.ok else "CRITICAL", json.dumps(
                    {"event": "SCHEDULED_VERIFY", "ok": res.ok, "records": res.records, "bad_seq": res.bad_seq or None,
                     "reason": res.reason or None, "checkpoint": str(cp) if cp else None}, separators=(",", ":")))
            except Exception:
                pass

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if cfg.checkpoint_interval > 0:
            threading.Thread(target=scheduler, daemon=True).start()
        yield
        stop.set()

    app = FastAPI(title="MedAudit Auditor Console", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.cfg = cfg

    # ------------------------------------------------------------ own activity log (fail closed)
    def clog(ctx: dict, event: str, sev: str = "INFO", **fields) -> None:
        payload = {"event": event, "ip": ctx["ip"], **fields}
        try:
            console_writer.append(ctx.get("username") or "anonymous", sev, json.dumps(payload, separators=(",", ":"), sort_keys=True))
        except Exception:
            raise HTTPException(503, "console activity log unavailable: request refused")

    def base(request: Request) -> dict:
        return {"ip": request.client.host if request.client else "unknown"}

    def current(request: Request) -> dict:
        ctx = base(request)
        h = request.headers.get("authorization", "")
        s = sessions.get(token_digest(h[7:].strip())) if h.lower().startswith("bearer ") else None
        now = time.time()
        if not s or now - s["last"] > 900 or now - s["created"] > 8 * 3600:
            if s:
                sessions.pop(token_digest(h[7:].strip()), None)
            raise HTTPException(401, "not authenticated")
        s["last"] = now
        ctx.update(username=s["user"], full_name=s["full_name"])
        return ctx

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                   "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        if request.url.path.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------ auth
    @app.post("/api/login")
    def login(body: LoginIn, request: Request):
        ctx = base(request)
        now = time.time()
        accounts = json.load(open(cfg.auditors_file))
        acc = accounts.get(body.username)
        recent = [t for t in fails.get(body.username, []) if now - t < cfg.lockout_seconds]
        locked = len(recent) >= cfg.lockout_attempts
        ok = verify_password(body.password, acc["pw_hash"] if acc else None, cfg.pbkdf2_iters)
        if not (acc and ok) or locked:
            fails[body.username] = recent + [now]
            clog(ctx | {"username": body.username if acc else None}, "CONSOLE_LOGIN_FAILED", "WARN",
                 reason="locked" if locked else "bad_credentials")
            raise HTTPException(401, "invalid credentials or account locked")
        fails.pop(body.username, None)
        tok = new_token()
        sessions[token_digest(tok)] = {"user": body.username, "full_name": acc["full_name"], "created": now, "last": now}
        clog(ctx | {"username": body.username}, "CONSOLE_LOGIN")
        return {"token": tok, "user": {"username": body.username, "full_name": acc["full_name"]}}

    @app.post("/api/logout")
    def logout(request: Request, ctx: dict = Depends(current)):
        sessions.pop(token_digest(request.headers["authorization"][7:].strip()), None)
        clog(ctx, "CONSOLE_LOGOUT")
        return {"ok": True}

    @app.get("/api/me")
    def me(ctx: dict = Depends(current)):
        return {"username": ctx["username"], "full_name": ctx["full_name"]}

    # ------------------------------------------------------------ verification
    def report(res: ScanResult) -> dict:
        cps = _read_jsonl(cfg.checkpoints_file)
        return {"ok": res.ok, "records": res.records, "head_hash": res.head_hash, "bad_seq": res.bad_seq or None,
                "reason": res.reason or None, "checked_at": cache["at"], "checkpoints": len(cps),
                "alerts": len(_read_jsonl(cfg.alerts_file)),
                "last_checkpoint": cps[-1] if cps else None}

    def safe_scan(force: bool = False) -> ScanResult:
        try:
            return run_scan(force)
        except KeyringError:
            raise HTTPException(500, "root key unavailable on this host")

    @app.get("/api/status")
    def status(ctx: dict = Depends(current)):
        return report(safe_scan())

    @app.post("/api/verify")
    def verify(ctx: dict = Depends(current)):
        res = safe_scan(force=True)
        clog(ctx, "VERIFY", "INFO" if res.ok else "CRITICAL", ok=res.ok, records=res.records, bad_seq=res.bad_seq or None)
        return report(res)

    @app.post("/api/checkpoint")
    def checkpoint(ctx: dict = Depends(current)):
        res = safe_scan(force=True)
        if not res.ok:
            clog(ctx, "CHECKPOINT_REFUSED", "CRITICAL", reason=res.reason)
            raise HTTPException(409, f"refusing to certify a log that fails verification: {res.reason}")
        cp = publish_checkpoint(res)
        clog(ctx, "CHECKPOINT", checkpoint=str(cp) if cp else "unchanged")
        return {"checkpoint": str(cp) if cp else None, **report(res)}

    @app.get("/api/alerts")
    def alerts(ctx: dict = Depends(current)):
        return list(reversed(_read_jsonl(cfg.alerts_file)))[:50]

    @app.get("/api/checkpoints")
    def list_checkpoints(ctx: dict = Depends(current)):
        return list(reversed(_read_jsonl(cfg.checkpoints_file)))[:50]

    # ------------------------------------------------------------ reading the trail
    def trusted_entries() -> list[dict]:
        res = safe_scan()
        if not res.ok:  # fail closed: a log that fails verification releases nothing
            raise HTTPException(409, {"error": "AUDIT LOG FAILED VERIFICATION: contents withheld",
                                      "bad_seq": res.bad_seq, "reason": res.reason})
        out = []
        for e in res.entries:
            try:
                data = json.loads(e.message)
            except ValueError:
                data = {"event": "UNPARSEABLE", "raw": e.message[:200]}
            out.append({"seq": e.seq, "time": e.timestamp, "severity": e.severity, "actor": e.actor,
                        "event": data.get("event"), "data": data})
        return out

    @app.get("/api/logs")
    def logs(request: Request, event: str = "", user: str = "", patient: str = "", severity: str = "",
             q: str = "", limit: int = 100, offset: int = 0, ctx: dict = Depends(current)):
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        rows = trusted_entries()
        flt = {k: v for k, v in dict(event=event, user=user, patient=patient, severity=severity, q=q).items() if v}
        clog(ctx, "VIEW_LOGS", filters=flt)
        if event: rows = [r for r in rows if r["event"] == event]
        if user: rows = [r for r in rows if r["actor"] == user]
        if patient: rows = [r for r in rows if r["data"].get("patient") == patient]
        if severity: rows = [r for r in rows if SEV_ORDER.get(r["severity"], 0) >= SEV_ORDER.get(severity.upper(), 0)]
        if q: rows = [r for r in rows if q.lower() in json.dumps(r["data"]).lower()]
        rows.reverse()
        return {"total": len(rows), "rows": rows[offset:offset + limit]}

    @app.get("/api/reports/summary")
    def summary(ctx: dict = Depends(current)):
        rows = trusted_entries()
        clog(ctx, "REPORT_SUMMARY")
        by_event: dict[str, int] = {}
        for r in rows:
            by_event[r["event"]] = by_event.get(r["event"], 0) + 1
        return {"total": len(rows), "by_event": dict(sorted(by_event.items(), key=lambda kv: -kv[1])),
                "failed_logins": by_event.get("LOGIN_FAILED", 0), "denied": by_event.get("ACCESS_DENIED", 0),
                "break_glass": by_event.get("BREAK_GLASS", 0), "locked": by_event.get("ACCOUNT_LOCKED", 0)}

    @app.get("/api/reports/patient/{pid}")
    def patient_report(pid: str, ctx: dict = Depends(current)):
        """Accounting of disclosures: who touched this patient's record, when, and on what basis."""
        rows = [r for r in trusted_entries() if r["data"].get("patient") == pid]
        clog(ctx, "REPORT_PATIENT", patient=pid, results=len(rows))
        return {"patient": pid, "accesses": [
            {"seq": r["seq"], "time": r["time"], "user": r["actor"], "role": r["data"].get("role"), "event": r["event"],
             "scope": r["data"].get("scope"), "basis": r["data"].get("basis"), "severity": r["severity"],
             "reason": r["data"].get("reason")} for r in reversed(rows)]}

    @app.get("/api/reports/user/{username}")
    def user_report(username: str, ctx: dict = Depends(current)):
        rows = [r for r in trusted_entries() if r["actor"] == username]
        clog(ctx, "REPORT_USER", target=username, results=len(rows))
        return {"user": username, "count": len(rows), "events": list(reversed(rows))[:300]}

    @app.get("/api/reports/break-glass")
    def break_glass_report(ctx: dict = Depends(current)):
        rows = trusted_entries()
        bg = [r for r in rows if r["event"] == "BREAK_GLASS"]
        views = [r for r in rows if r["event"] == "PATIENT_VIEW" and r["data"].get("basis") == "break_glass"]
        clog(ctx, "REPORT_BREAK_GLASS", results=len(bg))
        return {"grants": list(reversed(bg)), "views_under_break_glass": len(views)}

    @app.get("/api/console-log")
    def console_log(ctx: dict = Depends(current)):
        """The console's own activity trail, verified independently (who has been reading the audit logs)."""
        res = console_verifier.scan(collect=True)
        if not res.ok:
            raise HTTPException(409, {"error": "console activity log failed verification", "bad_seq": res.bad_seq, "reason": res.reason})
        return {"ok": True, "rows": [{"seq": e.seq, "time": e.timestamp, "severity": e.severity, "actor": e.actor,
                                      "data": json.loads(e.message)} for e in reversed(res.entries)][:200]}

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True), name="static")
    return app
