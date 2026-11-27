"""Engine tests: confidentiality, tamper evidence, truncation, rollback, forward security."""
import multiprocessing as mp
import os
import shutil

import pytest

from medaudit.auditlog import (AuditWriter, AuditVerifier, Checkpoint, AuditError, IntegrityError,
                               KeyringError, create_keyring, add_key, load_keyring)
from medaudit.auditlog import core
from medaudit.auditlog import platformio


@pytest.fixture
def env(tmp_path):
    keys = str(tmp_path / "root.keys")
    root = create_keyring(keys)
    d = str(tmp_path / "host")
    w = AuditWriter.initialize(d, root)
    v = AuditVerifier(d, keys)
    return w, v, d, keys, tmp_path


def lines(d):
    return open(os.path.join(d, "audit.log")).read().split("\n")[:-1]


def put(d, ls):
    with open(os.path.join(d, "audit.log"), "w", newline="") as stream:
        stream.write("\n".join(ls) + ("\n" if ls else ""))


def public_permissions(path):
    if os.name == "nt":
        import ntsecuritycon
        import win32security
        descriptor = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
        acl = descriptor.GetSecurityDescriptorDacl()
        acl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ,
                               win32security.CreateWellKnownSid(win32security.WinWorldSid, None))
        win32security.SetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None)
    else:
        os.chmod(path, 0o644)


def fill(w, n):
    for i in range(n):
        w.append("alice", "INFO", '{"event":"E","i":%d}' % i)


def setf(line, idx, val):
    f = line.split("|"); f[idx] = val; return "|".join(f)


def flip(h):
    return ("1" if h[0] == "0" else "0") + h[1:]


def test_roundtrip_and_confidentiality(env):
    w, v, d, *_ = env
    secret = '{"event":"X","note":"super-secret-value-123"}'
    w.append("alice", "WARN", secret)
    raw = open(os.path.join(d, "audit.log")).read()
    assert "super-secret-value-123" not in raw
    r = v.scan(collect=True)
    assert r.ok and r.records == 1
    e = r.entries[0]
    assert (e.seq, e.actor, e.severity, e.message) == (1, "alice", "WARN", secret)


def test_empty_log_ok(env):
    assert env[1].scan().ok


@pytest.mark.parametrize("field", [7, 8])  # ciphertext, tag
def test_tamper_ciphertext_and_tag(env, field):
    w, v, d, *_ = env
    fill(w, 4)
    ls = lines(d); ls[1] = setf(ls[1], field, flip(ls[1].split("|")[field])); put(d, ls)
    r = v.scan(collect=True)
    assert not r.ok and r.bad_seq == 2 and "tag" in r.reason and r.entries == []


@pytest.mark.parametrize("idx,val", [(3, "CRITICAL"), (4, "mallory"), (2, "2000-01-01T00:00:00Z")])
def test_metadata_is_authenticated(env, idx, val):
    w, v, d, *_ = env
    fill(w, 3)
    ls = lines(d); ls[1] = setf(ls[1], idx, val); put(d, ls)
    r = v.scan()
    assert not r.ok and r.bad_seq == 2


def test_delete_swap_replay(env, tmp_path):
    w, v, d, *_ = env
    fill(w, 5)
    orig = lines(d)
    put(d, orig[:2] + orig[3:])
    assert v.scan().bad_seq == 3
    ls = list(orig); ls[1], ls[2] = ls[2], ls[1]; put(d, ls)
    assert v.scan().bad_seq == 2
    put(d, orig + [orig[-1]])
    assert not v.scan().ok
    put(d, orig[1:])
    assert v.scan().bad_seq == 1
    ls = list(orig); ls[2] = setf(ls[2], 9, "a" * 64); put(d, ls)
    assert v.scan().bad_seq == 3


def test_garbage_and_partial(env):
    w, v, d, *_ = env
    fill(w, 3)
    ls = lines(d); put(d, ls + ["not a record"]); assert not v.scan().ok
    put(d, ls)
    with open(os.path.join(d, "audit.log"), "r+") as f:  # chop the final newline + bytes
        data = f.read(); f.seek(0); f.truncate(); f.write(data[:-10])
    assert not v.scan().ok
    with pytest.raises(IntegrityError):
        w.append("alice", "INFO", '{"a":1}')  # writer refuses to extend a damaged log


def test_tail_truncation_detected(env):
    w, v, d, *_ = env
    fill(w, 6)
    ls = lines(d); put(d, ls[:-3])
    r = v.scan()
    assert not r.ok and "truncated" in r.reason
    with pytest.raises(IntegrityError):
        w.append("alice", "INFO", '{"a":1}')


def test_truncation_plus_anchor_deleted(env):
    w, v, d, *_ = env
    fill(w, 6)
    put(d, lines(d)[:-2]); os.remove(os.path.join(d, "anchor.mac"))
    r = v.scan()
    assert not r.ok and "anchor" in r.reason


def test_forged_anchor_and_swapped_anchor(env, tmp_path):
    w, v, d, keys, _ = env
    fill(w, 6)
    put(d, lines(d)[:-2])
    open(os.path.join(d, "anchor.mac"), "w").write(f"4:{'a'*64}:{'b'*64}\n")
    assert not v.scan().ok
    # anchor from a different log
    k2 = str(tmp_path / "k2"); r2 = create_keyring(k2); d2 = str(tmp_path / "h2")
    w2 = AuditWriter.initialize(d2, r2); fill(w2, 4)
    shutil.copy(os.path.join(d2, "anchor.mac"), os.path.join(d, "anchor.mac"))
    assert not v.scan().ok


def test_log_deleted_and_bad_anchor_file(env):
    w, v, d, *_ = env
    fill(w, 3)
    open(os.path.join(d, "anchor.mac"), "w").write("nonsense\n")
    assert not v.scan().ok
    os.remove(os.path.join(d, "audit.log"))
    assert not v.scan().ok


def test_crash_recovery(env):
    w, v, d, *_ = env
    fill(w, 3)
    st, an = open(w.state_path).read(), open(w.anchor_path).read()
    fill(w, 1)  # pretend this append crashed after the record was written:
    for p, data in ((w.state_path, st), (w.anchor_path, an)):
        open(p, "w").write(data); os.chmod(p, 0o600)
    w.append("alice", "INFO", '{"post":"crash"}')
    assert v.scan().ok


def test_forward_security(env):
    w, v, d, keys, _ = env
    fill(w, 6)
    ls = lines(d)
    root = load_keyring(keys)[1]
    # verifier can re-derive every record key
    ck = core.start_key(root, 1)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    for l in ls:
        r = core.parse_line(l)
        assert AESGCM(core.enc_key(ck)).decrypt(r.iv, r.ct + r.tag, r.aad)
        ck = core.next_key(ck)
    # an attacker who steals state.key AFTER the writes cannot decrypt any of them
    stolen = bytes.fromhex(open(w.state_path).read().strip().split(":")[2])
    k, cracked = stolen, 0
    for _ in range(32):
        for l in ls:
            r = core.parse_line(l)
            try:
                AESGCM(core.enc_key(k)).decrypt(r.iv, r.ct + r.tag, r.aad); cracked += 1
            except Exception:
                pass
        k = core.next_key(k)
    assert cracked == 0
    # state really moves forward on each append
    w.append("alice", "INFO", '{"a":1}')
    now = bytes.fromhex(open(w.state_path).read().strip().split(":")[2])
    assert now == core.next_key(stolen)
    # writer works with the root key absent (it never had it); verifier then needs it
    assert v.scan().ok


def test_rotation(env):
    w, v, d, keys, _ = env
    fill(w, 2)
    nid, nroot = add_key(keys)
    w.rotate_epoch(nid, nroot)
    fill(w, 2)
    r = v.scan(collect=True)
    assert r.ok
    kids = {core.parse_line(l).key_id for l in lines(d)}
    assert kids == {1, 2}
    # forward security across the epoch boundary: host state is derived from the NEW root only
    stolen = bytes.fromhex(open(w.state_path).read().strip().split(":")[2])
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k = stolen
    for _ in range(16):
        for l in lines(d):
            rec = core.parse_line(l)
            with pytest.raises(Exception):
                AESGCM(core.enc_key(k)).decrypt(rec.iv, rec.ct + rec.tag, rec.aad)
        k = core.next_key(k)
    with pytest.raises(AuditError):
        w.rotate_epoch(1, nroot)  # ids must increase


def test_rollback_needs_external_checkpoint(env, tmp_path):
    w, v, d, *_ = env
    fill(w, 3)
    snap = str(tmp_path / "snap"); shutil.copytree(d, snap)      # attacker backup of whole host
    fill(w, 3)
    cp = v.checkpoint()
    fill(w, 2)
    assert v.scan(expect=[cp]).ok
    shutil.rmtree(d); shutil.copytree(snap, d)                    # full rollback
    assert v.scan().ok                                            # locally self-consistent...
    r = v.scan(expect=[cp])                                       # ...but the checkpoint exposes it
    assert not r.ok and "checkpoint" in r.reason
    assert not v.scan(expect=[Checkpoint(2, "0" * 64)]).ok


def test_checkpoint_parse_and_refusal(env):
    w, v, d, *_ = env
    c = Checkpoint.parse("5:" + "ab" * 32)
    assert c.seq == 5 and str(c) == "5:" + "ab" * 32
    for bad in ("abc", "5:xyz", "0:" + "a" * 64, ":" + "a" * 64):
        with pytest.raises(ValueError):
            Checkpoint.parse(bad)
    with pytest.raises(AuditError):
        v.checkpoint()                      # empty log
    fill(w, 3)
    put(d, lines(d)[:1] + lines(d)[2:])
    with pytest.raises(IntegrityError):
        v.checkpoint()                      # never certify a tampered log


def test_key_file_handling(env):
    w, v, d, keys, _ = env
    fill(w, 1)
    public_permissions(keys)
    with pytest.raises(KeyringError):
        v.scan()
    platformio.make_private(keys)
    public_permissions(w.state_path)
    with pytest.raises(KeyringError):
        w.append("alice", "INFO", '{"a":1}')
    platformio.make_private(w.state_path)
    open(w.state_path, "w").write("garbage\n")
    with pytest.raises(KeyringError):
        w.append("alice", "INFO", '{"a":1}')
    os.remove(keys)
    with pytest.raises(KeyringError):
        v.scan()


def test_permissions_and_reinit(env):
    w, v, d, keys, tmp = env
    fill(w, 1)
    for p in (w.log_path, w.state_path, w.anchor_path, keys):
        platformio.check_private(p)
    platformio.check_private(d, directory=True)
    with pytest.raises(IntegrityError):
        AuditWriter.initialize(d, b"x" * 32)


def test_input_validation(env):
    w, *_ = env
    for actor, sev, msg in [("bad|name", "INFO", "x"), ("a", "NOPE", "x"), ("a", "INFO", ""),
                            ("a", "INFO", "line\nbreak"), ("a", "INFO", "x" * 20000), ("", "INFO", "x")]:
        with pytest.raises(AuditError):
            w.append(actor, sev, msg)


def test_iv_uniqueness_and_reuse_detected(env):
    w, v, d, *_ = env
    fill(w, 200)
    ls = lines(d)
    ivs = {l.split("|")[6] for l in ls}
    assert len(ivs) == 200
    ls[5] = setf(ls[5], 6, ls[4].split("|")[6]); put(d, ls)
    assert not v.scan().ok


def _worker(d, n):
    w = AuditWriter(d)
    for i in range(n):
        w.append("alice", "INFO", '{"p":%d}' % os.getpid())


def test_concurrent_writers(env):
    w, v, d, *_ = env
    ps = [mp.Process(target=_worker, args=(d, 25)) for _ in range(4)]
    [p.start() for p in ps]; [p.join() for p in ps]
    assert all(p.exitcode == 0 for p in ps)
    r = v.scan()
    assert r.ok and r.records == 100
