"""Core of the audit log: record format, key schedule, writer and verifier.

Record (one text line):
    SL1|seq|timestamp|severity|actor|key_id|iv|ciphertext|tag|prev_hash

* ciphertext = AES-256-GCM(message) under a per-record key (forward security).
* AAD        = "SL1|seq|timestamp|severity|actor|key_id|prev_hash".
* prev_hash  = SHA-256 of the previous full line (zeros for record 1).

Key schedule (one-way ratchet):
    CK[first] = HMAC(root, "securelog/init/v1|<first_seq>")      start of an epoch
    CK[i+1]   = HMAC(CK[i], "securelog/next/v1")                 old key is overwritten
    EK[i]     = HMAC(CK[i], "securelog/enc/v1")                  AES key for record i only

The writer stores only CK[next] in state.key. The root key never touches the logging host.
After every record the writer stores an authenticated anchor (seq, hash, MAC) so that
records cut off the tail are detected; checkpoints published off-host detect a full rollback.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = "SL1"
IV_LEN = 12
TAG_LEN = 16
HASH_LEN = 32
MAX_PLAIN = 16384
MAX_LINE = 2 * MAX_PLAIN + 512
ZERO_HASH = "0" * 64
SEVERITIES = ("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEX_RE = re.compile(r"^[0-9a-f]*$")


class AuditError(Exception):
    """Base class. Messages are generic and never contain key material."""


class IntegrityError(AuditError):
    """The log (or its state) cannot be trusted or extended."""


class KeyringError(AuditError):
    """Key file missing, malformed or with unsafe permissions."""


# --------------------------------------------------------------------------- primitives
def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def start_key(root: bytes, first_seq: int) -> bytes:
    return _hmac(root, b"securelog/init/v1|" + str(first_seq).encode())


def next_key(ck: bytes) -> bytes:
    return _hmac(ck, b"securelog/next/v1")


def enc_key(ck: bytes) -> bytes:
    return _hmac(ck, b"securelog/enc/v1")


def anchor_mac(ck: bytes, seq: int, hash_hex: str) -> bytes:
    mk = _hmac(ck, b"securelog/anchor/v1")
    return _hmac(mk, f"SL1-ANCHOR|{seq}|{hash_hex}".encode())


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def valid_name(s: str) -> bool:
    return bool(_NAME_RE.match(s))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- records
@dataclass
class Entry:
    seq: int
    timestamp: str
    severity: str
    actor: str
    message: str


@dataclass(frozen=True)
class Checkpoint:
    seq: int
    hash: str

    def __str__(self) -> str:
        return f"{self.seq}:{self.hash}"

    @staticmethod
    def parse(text: str) -> "Checkpoint":
        seq_s, _, h = text.strip().partition(":")
        h = h.lower()
        if not seq_s.isdigit() or int(seq_s) < 1 or len(h) != 64 or not _HEX_RE.match(h):
            raise ValueError("checkpoint must look like SEQ:64-hex")
        return Checkpoint(int(seq_s), h)


@dataclass
class _Record:
    seq: int
    ts: str
    sev: str
    actor: str
    key_id: int
    iv: bytes
    ct: bytes
    tag: bytes
    prev: str
    line: str

    @property
    def aad(self) -> bytes:
        return make_aad(self.seq, self.ts, self.sev, self.actor, self.key_id, self.prev)


def make_aad(seq: int, ts: str, sev: str, actor: str, key_id: int, prev: str) -> bytes:
    return f"{MAGIC}|{seq}|{ts}|{sev}|{actor}|{key_id}|{prev}".encode()


def _hex(s: str, n: Optional[int] = None) -> Optional[bytes]:
    if not _HEX_RE.match(s) or len(s) % 2 or (n is not None and len(s) != 2 * n):
        return None
    return bytes.fromhex(s)


def parse_line(line: str) -> Optional[_Record]:
    """Strict parser: exact field count, shapes and lengths."""
    if not line or len(line) > MAX_LINE:
        return None
    f = line.split("|")
    if len(f) != 10 or f[0] != MAGIC:
        return None
    if not (f[1].isdigit() and f[1].isascii() and f[5].isdigit() and f[5].isascii()):
        return None
    seq, kid = int(f[1]), int(f[5])
    if seq < 1 or not 1 <= kid <= 0xFFFFFFFF or f[1] != str(seq) or f[5] != str(kid):
        return None
    if not _TS_RE.match(f[2]) or f[3] not in SEVERITIES or not valid_name(f[4]):
        return None
    iv, tag = _hex(f[6], IV_LEN), _hex(f[8], TAG_LEN)
    if iv is None or tag is None or len(f[7]) > 2 * MAX_PLAIN * 2:
        return None
    ct = _hex(f[7])
    if ct is None or _hex(f[9], HASH_LEN) is None:
        return None
    return _Record(seq, f[2], f[3], f[4], kid, iv, ct, tag, f[9], line)


# --------------------------------------------------------------------------- file helpers
def _check_private(path: str) -> None:
    """Secret files must be regular, not symlinks, and not group/other accessible."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise KeyringError(f"missing: {os.path.basename(path)}")
    if not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o077):
        raise KeyringError(f"unsafe permissions: {os.path.basename(path)}")


def _fsync_dir(path: str) -> None:
    fd = os.open(path or ".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: str, data: bytes) -> None:
    """Old-or-new, never torn: write temp, fsync, rename, fsync dir."""
    tmp = path + ".tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(path))


def _read_private(path: str) -> str:
    _check_private(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.read(fd, 1 << 20).decode()
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- keyring (root keys)
def create_keyring(path: str) -> bytes:
    """New key file (0600, O_EXCL) with key id 1. Returns the key (caller may need it once)."""
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, f"1:{key.hex()}\n".encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return key


def load_keyring(path: str) -> dict[int, bytes]:
    text = _read_private(path)
    keys: dict[int, bytes] = {}
    for line in text.splitlines():
        if not line:
            continue
        kid_s, _, hx = line.partition(":")
        kb = _hex(hx.strip().lower(), 32)
        if not kid_s.isdigit() or int(kid_s) < 1 or kb is None or int(kid_s) in keys:
            raise KeyringError("malformed key file")
        keys[int(kid_s)] = kb
    if not keys:
        raise KeyringError("empty key file")
    return keys


def add_key(path: str) -> tuple[int, bytes]:
    """Append a fresh root key with id = max+1. Returns (id, key)."""
    keys = load_keyring(path)
    nid = max(keys) + 1
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, f"{nid}:{key.hex()}\n".encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return nid, key


# --------------------------------------------------------------------------- writer
class _State:
    __slots__ = ("index", "key_id", "ck")

    def __init__(self, index: int, key_id: int, ck: bytes):
        self.index, self.key_id, self.ck = index, key_id, ck

    def dump(self) -> bytes:
        return f"{self.index}:{self.key_id}:{self.ck.hex()}\n".encode()


class AuditWriter:
    """Appends encrypted records. Holds only the current chain key (never the root key)."""

    def __init__(self, directory: str):
        self.dir = directory
        self.log_path = os.path.join(directory, "audit.log")
        self.state_path = os.path.join(directory, "state.key")
        self.anchor_path = os.path.join(directory, "anchor.mac")
        self.lock_path = os.path.join(directory, ".lock")

    # -- setup ---------------------------------------------------------------
    @classmethod
    def initialize(cls, directory: str, root_key: bytes, key_id: int = 1) -> "AuditWriter":
        os.makedirs(directory, mode=0o700, exist_ok=True)
        w = cls(directory)
        if os.path.exists(w.state_path) or os.path.exists(w.log_path):
            raise IntegrityError("audit store already initialised")
        _atomic_write(w.state_path, _State(1, key_id, start_key(root_key, 1)).dump())
        return w

    # -- internals -----------------------------------------------------------
    def _load_state(self) -> _State:
        text = _read_private(self.state_path).strip()
        parts = text.split(":")
        ck = _hex(parts[2], 32) if len(parts) == 3 else None
        if ck is None or not (parts[0].isdigit() and parts[1].isdigit()):
            raise KeyringError("malformed state")
        return _State(int(parts[0]), int(parts[1]), ck)

    def _read_head(self, fd: int) -> tuple[int, str]:
        size = os.fstat(fd).st_size
        if size == 0:
            return 0, ZERO_HASH
        n = min(size, 2 * MAX_LINE)
        tail = os.pread(fd, n, size - n)
        if len(tail) != n or not tail.endswith(b"\n"):
            raise IntegrityError("partial record at end of log")
        tail = tail[:-1]
        p = tail.rfind(b"\n")
        if p == -1 and n < size:
            raise IntegrityError("oversized record")
        last = tail[p + 1:].decode("utf-8", "replace")
        rec = parse_line(last)
        if rec is None:
            raise IntegrityError("malformed last record")
        return rec.seq, sha256_hex(last)

    def _write_anchor(self, seq: int, hash_hex: str, ck: bytes) -> None:
        _atomic_write(self.anchor_path, f"{seq}:{hash_hex}:{anchor_mac(ck, seq, hash_hex).hex()}\n".encode())

    def _sync(self, st: _State, head_seq: int, head_hash: str) -> None:
        """Align key state with the log tail; repair a crash between write and ratchet."""
        if head_seq + 1 == st.index:
            return
        if head_seq == st.index:  # record written, anchor/ratchet interrupted
            self._write_anchor(head_seq, head_hash, st.ck)
            st.ck, st.index = next_key(st.ck), st.index + 1
            _atomic_write(self.state_path, st.dump())
            return
        raise IntegrityError("log and key state disagree; refusing to append")

    class _Locked:
        def __init__(self, w: "AuditWriter"):
            self.w = w

        def __enter__(self):
            self.lf = os.open(self.w.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(self.lf, fcntl.LOCK_EX)
            self.fd = os.open(self.w.log_path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            if os.fstat(self.fd).st_mode & 0o022:
                self.__exit__()
                raise IntegrityError("log file is group/other writable")
            return self.fd

        def __exit__(self, *a):
            os.close(self.fd)
            os.close(self.lf)  # releases the flock

    # -- API -----------------------------------------------------------------
    def append(self, actor: str, severity: str, message: str) -> int:
        """Encrypt and append one event. Returns its sequence number. Raises on any problem."""
        if not valid_name(actor) or severity not in SEVERITIES:
            raise AuditError("invalid actor or severity")
        plain = message.encode()
        if not plain or len(plain) > MAX_PLAIN or b"\n" in plain or b"\r" in plain:
            raise AuditError("invalid message")
        with self._Locked(self) as fd:
            st = self._load_state()
            head_seq, head_hash = self._read_head(fd)
            self._sync(st, head_seq, head_hash)
            seq = st.index
            iv = secrets.token_bytes(IV_LEN)
            ts = utc_now()
            aad = make_aad(seq, ts, severity, actor, st.key_id, head_hash)
            sealed = AESGCM(enc_key(st.ck)).encrypt(iv, plain, aad)
            ct, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
            line = "|".join([MAGIC, str(seq), ts, severity, actor, str(st.key_id), iv.hex(), ct.hex(), tag.hex(), head_hash])
            os.write(fd, (line + "\n").encode())
            os.fsync(fd)
            self._write_anchor(seq, sha256_hex(line), st.ck)
            # forward security: ratchet, persist, forget CK[seq]
            st.ck, st.index = next_key(st.ck), seq + 1
            _atomic_write(self.state_path, st.dump())
            return seq

    def rotate_epoch(self, new_key_id: int, new_root_key: bytes, actor: str = "system") -> None:
        """Start a new key epoch from a new root key (supplied in memory, never stored here)."""
        self.append(actor, "INFO", '{"event":"KEY_ROTATION_STARTED","new_key_id":%d}' % new_key_id)
        with self._Locked(self) as fd:
            st = self._load_state()
            head_seq, head_hash = self._read_head(fd)
            self._sync(st, head_seq, head_hash)
            if new_key_id <= st.key_id:
                raise AuditError("key id must increase")
            st.ck, st.key_id = start_key(new_root_key, st.index), new_key_id
            _atomic_write(self.state_path, st.dump())
        self.append(actor, "INFO", '{"event":"KEY_ROTATED","new_key_id":%d}' % new_key_id)


# --------------------------------------------------------------------------- verifier
@dataclass
class ScanResult:
    ok: bool = False
    records: int = 0
    head_hash: str = ZERO_HASH
    bad_seq: int = 0
    reason: str = ""
    entries: list[Entry] = field(default_factory=list)


class AuditVerifier:
    """Read-only. Holds root key(s); re-derives the chain to verify and decrypt."""

    def __init__(self, directory: str, keyring_path: str):
        self.dir = directory
        self.log_path = os.path.join(directory, "audit.log")
        self.anchor_path = os.path.join(directory, "anchor.mac")
        self.lock_path = os.path.join(directory, ".lock")
        self.keyring_path = keyring_path

    def fingerprint(self) -> tuple:
        """Cheap change detector (used by callers that cache scan results)."""
        def sig(p):
            try:
                s = os.stat(p)
                return (s.st_size, s.st_mtime_ns)
            except OSError:
                return None
        return (sig(self.log_path), sig(self.anchor_path))

    def _load_anchor(self):
        try:
            text = open(self.anchor_path, "r").read()
        except FileNotFoundError:
            return None
        parts = text.strip().split(":")
        if len(parts) != 3 or not parts[0].isdigit() or _hex(parts[1], 32) is None or _hex(parts[2], 32) is None:
            return "malformed"
        return int(parts[0]), parts[1], bytes.fromhex(parts[2])

    def scan(self, collect: bool = False, expect: Iterable[Checkpoint] = ()) -> ScanResult:
        keys = load_keyring(self.keyring_path)  # raises KeyringError -> caller decides
        expect_map = {c.seq: c.hash for c in expect}
        res = ScanResult()

        def fail(at: int, why: str) -> ScanResult:
            res.ok, res.bad_seq, res.reason, res.entries = False, at, why, []
            return res

        # Shared lock on the writer's lock file: we never observe a half-written record
        # (which would raise a false tamper alarm). Writers wait only for the brief read.
        lock_fd = None
        try:
            lock_fd = os.open(self.lock_path, os.O_RDONLY)
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
        except OSError:
            lock_fd = None
        try:
            anchor = self._load_anchor()      # anchor is read BEFORE the log, so anchor <= log
            try:
                with open(self.log_path, "rb") as f:
                    data = f.read()
            except FileNotFoundError:
                data = None
        finally:
            if lock_fd is not None:
                os.close(lock_fd)

        if anchor == "malformed":
            return fail(1, "anchor file malformed")
        if data is None:
            if anchor is not None:
                return fail(1, "log file missing but anchor exists")
            if expect_map:
                return fail(1, "log shorter than external checkpoint")
            res.ok = True
            return res

        text = data.decode("utf-8", "replace")
        lines = text.split("\n")
        if lines[-1] != "":
            return fail(len(lines), "incomplete or truncated record")
        lines.pop()

        seen_iv: set[bytes] = set()
        prev, cur_kid, ck = ZERO_HASH, 0, b""
        idx = 0
        for line in lines:
            idx += 1
            r = parse_line(line)
            if r is None:
                return fail(idx, "malformed record")
            if r.seq != idx:
                return fail(idx, "sequence mismatch (record deleted, duplicated or reordered)")
            if r.prev != prev:
                return fail(idx, "hash chain broken")
            if r.key_id != cur_kid:
                if r.key_id < cur_kid:
                    return fail(idx, "key id regression")
                if r.key_id not in keys:
                    return fail(idx, "unknown key id")
                ck, cur_kid = start_key(keys[r.key_id], r.seq), r.key_id
            if r.iv in seen_iv:
                return fail(idx, "IV reuse detected")
            seen_iv.add(r.iv)
            try:
                plain = AESGCM(enc_key(ck)).decrypt(r.iv, r.ct + r.tag, r.aad)
            except InvalidTag:
                return fail(idx, "authentication tag mismatch")
            h = sha256_hex(line)
            if anchor and idx == anchor[0]:
                if h != anchor[1] or not hmac.compare_digest(anchor_mac(ck, idx, h), anchor[2]):
                    return fail(idx, "authenticated anchor does not match record")
            if idx in expect_map and expect_map[idx] != h:
                return fail(idx, "record differs from external checkpoint")
            if collect:
                res.entries.append(Entry(r.seq, r.ts, r.sev, r.actor, plain.decode("utf-8", "replace")))
            ck, prev = next_key(ck), h
            res.records = idx

        # end-of-log checks: these catch records cut off the tail
        if anchor and anchor[0] > idx:
            return fail(idx + 1, "log truncated: shorter than authenticated anchor")
        if anchor is None and idx > 0:
            return fail(idx, "authenticated anchor missing")
        if expect_map and max(expect_map) > idx:
            return fail(idx + 1, "log shorter than external checkpoint")
        res.ok, res.head_hash = True, prev
        return res

    def checkpoint(self, expect: Iterable[Checkpoint] = ()) -> Checkpoint:
        r = self.scan(expect=expect)
        if not r.ok:
            raise IntegrityError(f"refusing to checkpoint a log that fails verification: {r.reason}")
        if r.records == 0:
            raise AuditError("log is empty")
        return Checkpoint(r.records, r.head_hash)
