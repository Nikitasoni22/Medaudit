"""Auditor-only investigation and evidence routes, sharing the app's trust gates."""
import csv
import io
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from ..hospital.rbac import ROLE_PERMS, decide
from .insights import csv_cell, event_digest, findings, review_projection


class ReviewIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    status: Literal['reviewed', 'flagged']
    note: str = Field(min_length=10, max_length=500)
    revision: int = Field(ge=0)


def create_router(current, clog, safe_scan, trusted_entries, console_verifier, checkpoints):
    router = APIRouter(prefix='/api')
    review_lock = threading.Lock()

    def trusted_console():
        try:
            scan = console_verifier.scan(collect=True)
        except Exception:
            raise HTTPException(503, 'console verification unavailable')
        if not scan.ok:
            raise HTTPException(409, 'console activity log failed verification')
        return scan

    def reviews(rows):
        scan = trusted_console()
        return review_projection([r for r in rows if r['event'] == 'BREAK_GLASS'], scan.entries)

    @router.get('/reviews')
    def review_list(ctx=Depends(current)):
        result = reviews(trusted_entries())
        clog(ctx, 'VIEW_REVIEWS', results=len(result))
        return {'grants': result, 'pending': sum(r['review']['status'] == 'pending' for r in result)}

    @router.post('/reviews/{seq}')
    def review(seq: int, body: ReviewIn, ctx=Depends(current)):
        with review_lock:
            grant = next((r for r in reviews(trusted_entries()) if r['seq'] == seq), None)
            if grant is None:
                raise HTTPException(404, 'emergency grant not found')
            if grant['review']['revision'] != body.revision:
                raise HTTPException(409, 'review changed; reload before submitting')
            original = {k: v for k, v in grant.items() if k != 'review'}
            clog(ctx, 'EMERGENCY_REVIEW', 'WARN' if body.status == 'flagged' else 'INFO',
                 grant_seq=seq, grant_digest=event_digest(original), status=body.status,
                 note=body.note, previous_revision=body.revision)
            return {'ok': True, 'status': body.status}

    @router.get('/findings')
    def security_findings(ctx=Depends(current)):
        result = findings(trusted_entries())
        clog(ctx, 'VIEW_FINDINGS', results=len(result))
        return {'findings': result, 'rules': [
            {'id': 'repeated-logins', 'threshold': 5, 'window_minutes': 15},
            {'id': 'repeated-denials', 'threshold': 3, 'window_minutes': 15},
            {'id': 'emergency-access', 'threshold': 1, 'window_minutes': None}]}

    @router.get('/export')
    def export(format: Literal['json', 'csv'] = 'json',
               event: str = Query('', max_length=64), user: str = Query('', max_length=64),
               patient: str = Query('', max_length=32), since: datetime | None = None,
               until: datetime | None = None, ctx=Depends(current)):
        if any(t is not None and t.tzinfo is None for t in (since, until)):
            raise HTTPException(422, 'timestamps must include a timezone')
        if since and until and since > until:
            raise HTTPException(422, 'start must precede end')
        snapshot = safe_scan(force=True)
        rows = trusted_entries(snapshot)
        trusted_console()
        rows = [r for r in rows if (not event or r['event'] == event)
                and (not user or r['actor'] == user)
                and (not patient or r['data'].get('patient') == patient)
                and (not since or datetime.fromisoformat(r['time'].replace('Z', '+00:00')) >= since)
                and (not until or datetime.fromisoformat(r['time'].replace('Z', '+00:00')) <= until)]
        filters = {'event': event, 'user': user, 'patient': patient,
                   'since': since.isoformat() if since else None, 'until': until.isoformat() if until else None}
        clog(ctx, 'EVIDENCE_EXPORT', format=format, count=len(rows), head_hash=snapshot.head_hash,
             filters=filters)
        payload = {'schema': 'medaudit-evidence-v1', 'generated_at': datetime.now(timezone.utc).isoformat(),
                   'generated_by': ctx['username'], 'filters': filters, 'count': len(rows),
                   'verification': {'ok': True, 'records': snapshot.records, 'head_hash': snapshot.head_hash},
                   'checkpoints': [{'seq': cp.seq, 'hash': cp.hash} for cp in checkpoints() if cp.seq <= snapshot.records],
                   'rows': rows, 'content_digest': event_digest({'rows': rows}),
                   'notice': 'Verified snapshot; content digest is not an independent digital signature.'}
        headers = {'Content-Disposition': f'attachment; filename="medaudit-evidence.{format}"',
                   'X-MedAudit-Head': snapshot.head_hash, 'X-MedAudit-Records': str(snapshot.records)}
        if format == 'json':
            return Response(json.dumps(payload, indent=2), media_type='application/json', headers=headers)
        output = io.StringIO(newline='')
        writer = csv.writer(output)
        writer.writerow(['sequence', 'time', 'severity', 'actor', 'event', 'patient', 'basis', 'reason'])
        for row in rows:
            writer.writerow([csv_cell(v) for v in [row['seq'], row['time'], row['severity'], row['actor'],
                row['event'], row['data'].get('patient'), row['data'].get('basis'), row['data'].get('reason')]])
        return Response(output.getvalue(), media_type='text/csv', headers=headers)

    @router.get('/engineering')
    def engineering(ctx=Depends(current)):
        manifest = json.loads(Path(__file__).with_name('engineering.json').read_text(encoding='utf-8'))
        clog(ctx, 'VIEW_ENGINEERING')
        return manifest

    @router.get('/engineering/policy')
    def policy(role: Literal['doctor', 'nurse', 'receptionist', 'admin'],
               permission: str = Query(max_length=64), assigned: bool = False,
               breakglass: bool = False, ctx=Depends(current)):
        if permission not in set().union(*ROLE_PERMS.values()):
            raise HTTPException(422, 'unknown permission')
        decision = decide(role, permission, assigned, breakglass)
        clog(ctx, 'POLICY_SIMULATION', role=role, permission=permission,
             assigned=assigned, breakglass=breakglass, allow=decision.allow)
        return {'allow': decision.allow, 'basis': decision.basis, 'simulation': True}

    return router
