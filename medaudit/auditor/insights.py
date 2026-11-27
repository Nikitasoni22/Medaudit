"""Deterministic audit analysis; all inputs must come from a verified snapshot."""
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone


def csv_cell(value) -> str:
    text = str(value if value is not None else '')
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')) else text


def event_digest(row: dict) -> str:
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def findings(rows: list[dict], now: float | None = None) -> list[dict]:
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    groups = defaultdict(list)
    result = []
    for row in rows:
        at = datetime.fromisoformat(row['time'].replace('Z', '+00:00')).timestamp()
        if row['event'] == 'BREAK_GLASS':
            result.append({'id': f"emergency-{row['seq']}", 'rule': 'emergency-access',
                           'title': 'Emergency access requires review', 'severity': 'WARN',
                           'actor': row['actor'], 'patient': row['data'].get('patient'),
                           'time': row['time'], 'evidence': [row['seq']], 'window_minutes': None,
                           'explanation': 'A care-relationship override was granted. Check the justification and subsequent access.'})
        if 0 <= now - at <= 900 and row['event'] in ('LOGIN_FAILED', 'ACCESS_DENIED'):
            actor = row['data'].get('attempted_user') or row['actor']
            groups[(row['event'], actor)].append(row)
    for (event, actor), group in groups.items():
        threshold = 5 if event == 'LOGIN_FAILED' else 3
        if len(group) >= threshold:
            rule = 'repeated-logins' if event == 'LOGIN_FAILED' else 'repeated-denials'
            result.append({'id': f'{rule}-{actor}', 'rule': rule,
                           'title': 'Repeated failed sign-ins' if event == 'LOGIN_FAILED' else 'Repeated access denials',
                           'severity': 'ERROR', 'actor': actor, 'patient': None,
                           'time': group[-1]['time'], 'evidence': [r['seq'] for r in group],
                           'window_minutes': 15,
                           'explanation': f'{len(group)} events within 15 minutes meet the threshold of {threshold}. Investigate context; this rule does not prove malicious intent.'})
    return sorted(result, key=lambda row: (row['severity'] == 'ERROR', row['time']), reverse=True)


def review_projection(grants: list[dict], console_entries) -> list[dict]:
    latest = {}
    for entry in console_entries:
        data = json.loads(entry.message)
        if data.get('event') == 'EMERGENCY_REVIEW':
            latest[(data['grant_seq'], data['grant_digest'])] = {
                'status': data['status'], 'note': data['note'], 'reviewer': entry.actor,
                'time': entry.timestamp, 'revision': entry.seq,
            }
    return [row | {'review': latest.get((row['seq'], event_digest(row)), {
        'status': 'pending', 'note': '', 'reviewer': None, 'time': None, 'revision': 0})}
        for row in reversed(grants)]
