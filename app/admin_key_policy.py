"""Explicit, owner-bound admission policy for administrator unmetered keys."""

from typing import Any


ADMIN_UNMETERED_SCOPE = "admin:unmetered"
ADMIN_EXEMPT_REASON = "Active administrator key with the exact admin:unmetered scope."


class AdminKeyPolicyError(ValueError):
    pass


def admin_unmetered(key_row: Any, *, owner_role: Any, owner_status: Any) -> bool:
    """Evaluate fresh database rows; the scope never grants an endpoint itself.

    A misplaced administrator scope denies admission, including on otherwise
    eligible pending users. Callers must obtain the owner state from the DB.
    """
    scopes = set(str(key_row["scopes"] or "").replace(",", " ").split())
    if ADMIN_UNMETERED_SCOPE not in scopes:
        return False
    if owner_role != "admin" or owner_status != "active":
        raise AdminKeyPolicyError("Administrator API keys require an active administrator owner.")
    return True
