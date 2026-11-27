#!/usr/bin/env python3
"""Rehearse critical UI flows on disposable data and save screenshots."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from medaudit.config import Config
from medaudit.setup import DEMO_PASSWORDS, init_system


def main():
    from playwright.sync_api import sync_playwright
    output = ROOT / 'docs' / 'screenshots'
    output.mkdir(parents=True, exist_ok=True)
    errors = []
    with tempfile.TemporaryDirectory(prefix='medaudit-browser-') as temp:
        cfg = Config(data_dir=str(Path(temp) / 'data'), pbkdf2_iters=1000)
        init_system(cfg, demo=True)
        env = dict(os.environ, MEDAUDIT_DATA=cfg.data_dir, MEDAUDIT_CHECKPOINT_INTERVAL='0')
        processes = [subprocess.Popen([sys.executable, '-m', 'uvicorn', f'medaudit.{service}.app:create',
                     '--factory', '--port', str(port), '--log-level', 'error'], cwd=ROOT, env=env,
                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                     for service, port in [('hospital', 18000), ('auditor', 18001)]]
        try:
            for port in [18000, 18001]:
                for attempt in range(100):
                    try:
                        urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=1)
                        break
                    except OSError:
                        if any(p.poll() is not None for p in processes):
                            raise RuntimeError('Test service failed to start')
                        time.sleep(.1)
                else:
                    raise RuntimeError('Service startup timeout')
            with sync_playwright() as p:
                browser = p.chromium.launch()
                context = browser.new_context(viewport={'width': 1440, 'height': 1100}, device_scale_factor=1)
                h, a = context.new_page(), context.new_page()
                for page in [h, a]:
                    page.on('pageerror', lambda error: errors.append(str(error)))
                h.goto('http://127.0.0.1:18000')
                h.screenshot(path=str(output / 'hospital-sign-in.png'), full_page=True)
                h.get_by_label('Username', exact=True).fill('dr.rao')
                h.get_by_label('Password', exact=True).fill(DEMO_PASSWORDS['dr.rao'])
                h.get_by_role('button', name='Sign in to hospital').click()
                h.get_by_role('button', name='Aarav Sharma').wait_for()
                h.screenshot(path=str(output / 'hospital-directory.png'), full_page=True)
                h.get_by_role('button', name='Aarav Sharma').click()
                h.get_by_label('Diagnosis', exact=True).wait_for()
                h.screenshot(path=str(output / 'clinical-record.png'), full_page=True)
                for _ in range(3):
                    h.get_by_role('button', name='Back', exact=False).click()
                    h.get_by_role('button', name='Diya Nair').click()
                    h.get_by_label('Reason for emergency access').wait_for()
                h.get_by_label('Reason for emergency access').fill('Patient collapsed in corridor; urgent assessment required.')
                h.get_by_role('button', name='Break glass', exact=True).click()
                h.get_by_label('Diagnosis', exact=True).wait_for()
                h.screenshot(path=str(output / 'emergency-access.png'), full_page=True)
                a.goto('http://127.0.0.1:18001')
                a.get_by_label('Username', exact=True).fill('auditor1')
                a.get_by_label('Password', exact=True).fill(DEMO_PASSWORDS['auditor1'])
                a.get_by_role('button', name='Sign in to workspace').click()
                a.get_by_role('heading', name='Your audit trail checks out.').wait_for()
                a.get_by_role('button', name='Publish checkpoint', exact=True).click()
                a.get_by_role('heading', name='Your audit trail checks out.').wait_for()
                a.screenshot(path=str(output / 'auditor-overview.png'), full_page=True)
                a.get_by_role('button', name='Emergency reviews', exact=False).first.click()
                a.get_by_label('Review explanation').fill('Emergency reason and patient access checked; appropriate response.')
                a.get_by_role('button', name='Save review', exact=True).click()
                a.get_by_text('Last review by auditor1', exact=False).wait_for()
                a.screenshot(path=str(output / 'emergency-review.png'), full_page=True)
                a.get_by_role('button', name='Security findings', exact=False).click()
                a.get_by_role('heading', name='Repeated access denials').wait_for()
                a.screenshot(path=str(output / 'security-findings.png'), full_page=True)
                a.get_by_role('button', name='Engineering', exact=False).click()
                a.get_by_role('heading', name='Engineering assurance').wait_for()
                a.screenshot(path=str(output / 'engineering-requirements.png'), full_page=True)
                a.get_by_role('button', name='Policy simulator', exact=True).click()
                a.get_by_label('Staff role').select_option('admin')
                a.get_by_label('Assigned to this patient').check()
                a.get_by_role('button', name='Evaluate policy').click()
                a.get_by_text('Decision basis: role_denied', exact=False).wait_for()
                a.screenshot(path=str(output / 'policy-simulator.png'), full_page=True)
                a.get_by_role('button', name='Evidence export', exact=False).click()
                a.get_by_label('Patient ID (optional)').fill('P-1002')
                with a.expect_download() as downloaded:
                    a.get_by_role('button', name='Download verified evidence', exact=False).click()
                report = json.loads(Path(downloaded.value.path()).read_text())
                assert report['verification']['ok'] and report['count'] > 0
                assert all(r['data']['patient'] == 'P-1002' for r in report['rows'])
                a.screenshot(path=str(output / 'evidence-export.png'), full_page=True)
                for name in ['Audit trail', 'Patient reports', 'Checkpoints', 'Demo guide', 'Console activity']:
                    a.get_by_role('button', name=name, exact=False).first.click()
                    a.locator('.loading').wait_for(state='detached')
                    assert not a.get_by_role('heading', name='Evidence unavailable').count(), name
                a.set_viewport_size({'width':390,'height':844})
                a.get_by_role('button', name='Overview', exact=False).click()
                a.get_by_role('heading', name='Your audit trail checks out.').wait_for()
                assert a.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'mobile overflow'
                a.screenshot(path=str(output / 'mobile-overview.png'), full_page=True)
                assert not errors, errors
                browser.close()
                print('PASS: hospital access, emergency grant, review, findings, policy simulation, export, all navigation, mobile layout; no page errors.')
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                process.wait(timeout=10)


if __name__ == '__main__':
    main()
