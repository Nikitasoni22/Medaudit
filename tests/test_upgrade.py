"""Security acceptance tests for the review, evidence, and engineering workflows."""
import csv
import io
import json
import os

import pytest
from fastapi.testclient import TestClient

from medaudit.auditor.app import create as auditor
from medaudit.config import Config
from medaudit.hospital.app import create as hospital
from medaudit.setup import DEMO_PASSWORDS, init_system


def login(client, name):
    response = client.post('/api/login', json={'username': name, 'password': DEMO_PASSWORDS[name]})
    assert response.status_code == 200, response.text
    return {'Authorization': 'Bearer ' + response.json()['token']}


@pytest.fixture
def system(tmp_path):
    cfg = Config(data_dir=str(tmp_path / 'data'), pbkdf2_iters=1000, checkpoint_interval=0)
    init_system(cfg, demo=True)
    h, a = TestClient(hospital(cfg)), TestClient(auditor(cfg))
    return h, a, cfg, login(h, 'dr.rao'), login(a, 'auditor1')


def grant(system):
    h, a, _, hh, ah = system
    assert h.post('/api/patients/P-1002/break-glass', headers=hh,
                  json={'reason': 'Patient collapsed; emergency treatment'}).status_code == 200
    return a.get('/api/reviews', headers=ah).json()['grants'][0]


@pytest.mark.parametrize('path', ['/api/reviews', '/api/findings', '/api/export', '/api/engineering'])
def test_new_workflows_require_auditor(system, path):
    _, a, _, hh, _ = system
    assert a.get(path).status_code == 401
    assert a.get(path, headers=hh).status_code == 401


def test_review_persists_and_rejects_stale_revision(system):
    _, a, cfg, _, ah = system
    item = grant(system)
    body = {'status': 'reviewed', 'note': 'Emergency justification checked.', 'revision': 0}
    response = a.post(f"/api/reviews/{item['seq']}", headers=ah, json=body)
    assert response.status_code == 200, response.text
    assert a.post(f"/api/reviews/{item['seq']}", headers=ah, json=body).status_code == 409
    restarted = TestClient(auditor(cfg))
    row = restarted.get('/api/reviews', headers=login(restarted, 'auditor1')).json()['grants'][0]
    assert row['review']['status'] == 'reviewed'
    assert row['review']['reviewer'] == 'auditor1'
    assert row['review']['revision'] > 0


def test_review_requires_real_grant_and_meaningful_note(system):
    _, a, _, _, ah = system
    body = {'status': 'reviewed', 'note': 'Valid reviewed note.', 'revision': 0}
    assert a.post('/api/reviews/999999', headers=ah, json=body).status_code == 404
    item = grant(system)
    body['note'] = ' ' * 15
    assert a.post(f"/api/reviews/{item['seq']}", headers=ah, json=body).status_code == 422


def test_findings_are_explainable(system):
    h, a, _, hh, ah = system
    for _ in range(3):
        h.get('/api/patients/P-1002', headers=hh)
    findings = a.get('/api/findings', headers=ah).json()['findings']
    denial = next(f for f in findings if f['rule'] == 'repeated-denials')
    assert denial['actor'] == 'dr.rao'
    assert len(denial['evidence']) == 3
    assert denial['explanation'] and denial['window_minutes'] == 15


def test_verified_export_filters_and_audits(system):
    h, a, cfg, hh, ah = system
    h.get('/api/patients/P-1001', headers=hh)
    h.get('/api/patients/P-1002', headers=hh)
    response = a.get('/api/export?patient=P-1001', headers=ah)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload['verification']['ok'] is True
    assert payload['count'] == len(payload['rows']) > 0
    assert all(r['data']['patient'] == 'P-1001' for r in payload['rows'])
    assert 'diagnosis' not in response.text and 'notes' not in response.text
    trail = a.get('/api/console-log', headers=ah).json()['rows']
    assert any(r['data']['event'] == 'EVIDENCE_EXPORT' for r in trail)
    csv_response = a.get('/api/export?format=csv&patient=P-1001', headers=ah)
    assert len(list(csv.DictReader(io.StringIO(csv_response.text)))) == payload['count']


def test_csv_formula_cells_are_inert():
    from medaudit.auditor.insights import csv_cell
    for cell in ['=HYPERLINK("bad")', '+123', '-123', '@SUM(A1)', '\t=1', '  =1', '\r=1']:
        assert csv_cell(cell).startswith("'")
    assert csv_cell('P-1001') == 'P-1001'


@pytest.mark.parametrize('path', ['/api/reviews', '/api/findings', '/api/export'])
def test_tamper_blocks_new_evidence_paths(system, path):
    h, a, cfg, hh, ah = system
    h.get('/api/patients/P-1001', headers=hh)
    log = os.path.join(cfg.audit_dir, 'audit.log')
    with open(log, encoding='utf-8') as f:
        lines = f.readlines()
    fields = lines[0].strip().split('|')
    fields[7] = ('0' if fields[7][0] != '0' else '1') + fields[7][1:]
    lines[0] = '|'.join(fields) + '\n'
    with open(log, 'w', encoding='utf-8', newline='') as f:
        f.writelines(lines)
    assert a.get(path, headers=ah).status_code == 409


def test_review_and_export_fail_closed_on_console_failure(system):
    _, a, cfg, _, ah = system
    item = grant(system)
    state = os.path.join(cfg.console_audit_dir, 'state.key')
    os.rename(state, state + '.unavailable')
    body = {'status': 'flagged', 'note': 'Requires further investigation.', 'revision': 0}
    assert a.post(f"/api/reviews/{item['seq']}", headers=ah, json=body).status_code == 503
    assert a.get('/api/export', headers=ah).status_code == 503
    os.rename(state + '.unavailable', state)
    assert a.get('/api/reviews', headers=ah).json()['grants'][0]['review']['status'] == 'pending'


def test_engineering_policy_simulates_without_changing_access(system):
    h, a, _, hh, ah = system
    result = a.get('/api/engineering', headers=ah).json()
    assert result['requirements'] and result['threats'] and result['demo']
    denied = a.get('/api/engineering/policy?role=admin&permission=patient.view_clinical&assigned=true', headers=ah)
    assert denied.json() == {'allow': False, 'basis': 'role_denied', 'simulation': True}
    allowed = a.get('/api/engineering/policy?role=doctor&permission=patient.view_clinical&breakglass=true', headers=ah)
    assert allowed.json()['allow'] is True
    assert h.get('/api/patients/P-1002', headers=hh).json()['clinical_access'] == 'restricted'


@pytest.mark.parametrize('body', [
    {'name': '   ', 'dob': '2000-01-01', 'sex': 'F'},
    {'name': 'Synthetic Patient', 'dob': '2000-02-31', 'sex': 'F'},
    {'name': 'Synthetic Patient', 'dob': '2000-01-01', 'sex': 'F', 'role': 'admin'},
])
def test_patient_boundary_validation(system, body):
    h, _, _, hh, _ = system
    assert h.post('/api/patients', headers=hh, json=body).status_code == 422


def test_blank_emergency_reason_rejected(system):
    h, _, _, hh, _ = system
    assert h.post('/api/patients/P-1002/break-glass', headers=hh,
                  json={'reason': ' ' * 20}).status_code == 422
