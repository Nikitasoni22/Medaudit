"""Platform security regressions: run on Windows and POSIX without bypasses."""
import os

import pytest

from medaudit.auditlog import AuditVerifier, AuditWriter, KeyringError, create_keyring
from medaudit.auditlog import platformio


def test_native_roundtrip_and_private_key(tmp_path):
    key_path = str(tmp_path / "root.keys")
    root = create_keyring(key_path)
    writer = AuditWriter.initialize(str(tmp_path / "audit"), root)
    writer.append("alice", "INFO", '{"event":"NATIVE_PLATFORM"}')
    platformio.check_private(key_path)
    result = AuditVerifier(writer.dir, key_path).scan(collect=True)
    assert result.ok and result.entries[0].actor == "alice"


def test_public_key_permissions_are_refused(tmp_path):
    key_path = str(tmp_path / "root.keys")
    root = create_keyring(key_path)
    writer = AuditWriter.initialize(str(tmp_path / "audit"), root)
    platformio.make_private(writer.dir)
    if os.name == "nt":
        import ntsecuritycon
        import win32security
        descriptor = win32security.GetFileSecurity(key_path, win32security.DACL_SECURITY_INFORMATION)
        acl = descriptor.GetSecurityDescriptorDacl()
        everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid, None)
        acl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ, everyone)
        win32security.SetNamedSecurityInfo(
            key_path, win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None)
    else:
        os.chmod(key_path, 0o644)
    with pytest.raises(KeyringError):
        AuditVerifier(writer.dir, key_path).scan()


def test_missing_lock_cannot_bypass_verifier_coordination(tmp_path):
    key_path = str(tmp_path / "root.keys")
    root = create_keyring(key_path)
    writer = AuditWriter.initialize(str(tmp_path / "audit"), root)
    writer.append("alice", "INFO", '{"event":"ACCESS"}')
    os.unlink(writer.lock_path)
    result = AuditVerifier(writer.dir, key_path).scan()
    assert not result.ok and "lock" in result.reason
