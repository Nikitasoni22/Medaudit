#!/usr/bin/env python3
"""An isolated integrity experiment. Never opens the running hospital's data."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from medaudit.auditlog import AuditVerifier, AuditWriter, Checkpoint, create_keyring


def main():
    with tempfile.TemporaryDirectory(prefix='medaudit-lab-') as temporary:
        keys = os.path.join(temporary, 'root.keys')
        writer = AuditWriter.initialize(os.path.join(temporary, 'audit'), create_keyring(keys))
        verifier = AuditVerifier(writer.dir, keys)
        for event in ['LOGIN_SUCCESS', 'PATIENT_VIEW', 'ACCESS_DENIED']:
            writer.append('demo.doctor', 'INFO', json.dumps({'event': event, 'patient': 'P-1001'}))
        clean = verifier.scan()
        print(f'1. CLEAN LOG: verified={clean.ok}, records={clean.records}')
        assert clean.ok
        original = Path(writer.log_path).read_bytes()
        lines = original.decode().splitlines()
        fields = lines[1].split('|')
        fields[7] = ('0' if fields[7][0] != '0' else '1') + fields[7][1:]
        lines[1] = '|'.join(fields)
        Path(writer.log_path).write_bytes(('\n'.join(lines) + '\n').encode())
        tampered = verifier.scan()
        print(f'2. ALTERED CIPHERTEXT: verified={tampered.ok}, record={tampered.bad_seq}, reason={tampered.reason}')
        assert not tampered.ok and tampered.bad_seq == 2
        Path(writer.log_path).write_bytes(original)
        restored = verifier.scan()
        print(f'3. RESTORED: verified={restored.ok}')
        assert restored.ok
        old_anchor = Path(writer.anchor_path).read_bytes()
        old_state = Path(writer.state_path).read_bytes()
        writer.append('demo.doctor', 'INFO', '{"event":"PATIENT_VIEW"}')
        latest = verifier.scan()
        checkpoint = Checkpoint(latest.records, latest.head_hash)
        Path(writer.log_path).write_bytes(original)
        Path(writer.anchor_path).write_bytes(old_anchor)
        Path(writer.state_path).write_bytes(old_state)
        rolled_back = verifier.scan(expect=[checkpoint])
        print(f'4. COMPLETE ROLLBACK: verified={rolled_back.ok}, reason={rolled_back.reason}')
        assert not rolled_back.ok
        print('PASS: both attacks detected. Running hospital data was never accessed.')


if __name__ == '__main__':
    main()
