"""Role + relationship based access decisions (deny by default).

  receptionist : register patients, see demographics only
  nurse        : demographics for all; clinical data for ASSIGNED patients (or break-glass)
  doctor       : demographics for all; read/update clinical data for ASSIGNED patients (or break-glass)
  admin        : manage accounts and assignments; NO access to patient data at all
"""
from __future__ import annotations

from dataclasses import dataclass

ROLES = ("doctor", "nurse", "receptionist", "admin")

ROLE_PERMS: dict[str, set[str]] = {
    "receptionist": {"patient.list", "patient.view_basic", "patient.create"},
    "nurse": {"patient.list", "patient.view_basic", "patient.view_clinical", "patient.breakglass"},
    "doctor": {"patient.list", "patient.view_basic", "patient.create", "patient.view_clinical",
               "patient.update_clinical", "patient.breakglass"},
    "admin": {"user.manage", "patient.assign", "patient.list_ids"},
}

# permissions that additionally require a care relationship (assignment) or active break-glass
NEEDS_RELATIONSHIP = {"patient.view_clinical", "patient.update_clinical"}


@dataclass(frozen=True)
class Decision:
    allow: bool
    basis: str  # role | assigned | break_glass | role_denied | not_assigned


def decide(role: str, perm: str, assigned: bool = False, breakglass: bool = False) -> Decision:
    if perm not in ROLE_PERMS.get(role, set()):
        return Decision(False, "role_denied")
    if perm in NEEDS_RELATIONSHIP:
        if assigned:
            return Decision(True, "assigned")
        if breakglass:
            return Decision(True, "break_glass")
        return Decision(False, "not_assigned")
    return Decision(True, "role")
