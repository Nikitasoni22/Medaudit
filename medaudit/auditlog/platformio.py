"""File safety and process locks for POSIX and native Windows.

Windows uses protected DACLs and write-through replacement; POSIX uses modes,
O_NOFOLLOW, flock and directory fsync. Cryptographic formats stay identical.
"""
from __future__ import annotations

import os
import stat

if os.name == "nt":
    import msvcrt
    import ntsecuritycon
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32security
else:
    import fcntl


def _user_sid():
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        return win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()


def _private_descriptor():
    descriptor = win32security.SECURITY_DESCRIPTOR()
    acl = win32security.ACL()
    inheritance = win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE
    acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inheritance,
                             ntsecuritycon.FILE_ALL_ACCESS, _user_sid())
    descriptor.SetSecurityDescriptorDacl(1, acl, 0)
    descriptor.SetSecurityDescriptorControl(win32security.SE_DACL_PROTECTED,
                                           win32security.SE_DACL_PROTECTED)
    return descriptor


def make_private(path: str) -> None:
    """Protect freshly generated files/directories; never use to repair untrusted keys."""
    if os.name == "nt":
        win32security.SetFileSecurity(
            path, win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            _private_descriptor())
    else:
        os.chmod(path, 0o700 if os.path.isdir(path) else 0o600)


def check_private(path: str, *, directory: bool = False) -> None:
    st = os.lstat(path)
    expected = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
    if not expected or (getattr(st, "st_file_attributes", 0) & 0x400):
        raise PermissionError("not a regular private path")
    if os.name != "nt":
        if st.st_mode & 0o077:
            raise PermissionError("group or other access")
        return
    descriptor = win32security.GetFileSecurity(
        path, win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
    trusted = {_sid_text(_user_sid()),
               _sid_text(win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)),
               _sid_text(win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None))}
    if _sid_text(descriptor.GetSecurityDescriptorOwner()) not in trusted:
        raise PermissionError("untrusted owner")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise PermissionError("unrestricted DACL")
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        kind = ace[0][0]
        if kind == win32security.ACCESS_DENIED_ACE_TYPE:
            continue
        if kind != win32security.ACCESS_ALLOWED_ACE_TYPE or _sid_text(ace[-1]) not in trusted:
            raise PermissionError("untrusted ACL grant")


def _sid_text(sid):
    return win32security.ConvertSidToStringSid(sid)


def private_open(path: str, flags: int, mode: int = 0o600) -> int:
    """Open binary files without following a final symlink, privately at creation."""
    if os.name != "nt":
        return os.open(path, flags | os.O_NOFOLLOW, mode)
    access = win32con.GENERIC_READ
    if flags & (os.O_WRONLY | os.O_RDWR):
        access = win32con.GENERIC_WRITE
        if flags & os.O_RDWR:
            access |= win32con.GENERIC_READ
    disposition = win32con.OPEN_EXISTING
    if flags & os.O_CREAT:
        disposition = win32con.CREATE_NEW if flags & os.O_EXCL else win32con.OPEN_ALWAYS
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = _private_descriptor()
    try:
        handle = win32file.CreateFile(
            path, access,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            attributes, disposition, win32file.FILE_FLAG_OPEN_REPARSE_POINT, None)
    except pywintypes.error as exc:
        if exc.winerror in (80, 183):
            raise FileExistsError(path) from exc
        if exc.winerror in (2, 3):
            raise FileNotFoundError(path) from exc
        raise OSError(exc.winerror, "cannot open audit file") from exc
    try:
        if win32file.GetFileInformationByHandle(handle)[0] & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError("reparse point refused")
        fd = msvcrt.open_osfhandle(handle.Detach(), flags | os.O_BINARY)
    finally:
        handle.Close()
    if flags & os.O_APPEND:
        os.lseek(fd, 0, os.SEEK_END)
    return fd


def lock(fd: int, *, shared: bool = False) -> None:
    if os.name == "nt":
        win32file.LockFileEx(msvcrt.get_osfhandle(fd),
                             0 if shared else win32con.LOCKFILE_EXCLUSIVE_LOCK,
                             1, 0, pywintypes.OVERLAPPED())
    else:
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)


def read_at(fd: int, size: int, offset: int) -> bytes:
    if os.name != "nt":
        return os.pread(fd, size, offset)
    old = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, size)
    finally:
        os.lseek(fd, old, os.SEEK_SET)


def replace_and_sync(source: str, destination: str) -> None:
    if os.name == "nt":
        # Windows has no directory fsync; request a write-through metadata move.
        win32file.MoveFileEx(source, destination,
                             win32file.MOVEFILE_REPLACE_EXISTING | win32file.MOVEFILE_WRITE_THROUGH)
    else:
        os.replace(source, destination)
        fd = os.open(os.path.dirname(destination) or ".", os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
