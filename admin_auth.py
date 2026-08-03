"""Admin username/password gateway authentication."""

from werkzeug.security import check_password_hash, generate_password_hash

from config import ADMIN_GATEWAY_PASSWORD, ADMIN_GATEWAY_USERNAME
from personnel_registry import GATEWAY_ROLES


def hash_gateway_password(password: str) -> str:
    return generate_password_hash(password)


def verify_gateway_login(
    username: str,
    password: str,
    registry,
) -> tuple[bool, str, str, str, str]:
    """
    Validate admin gateway credentials.

    Returns (ok, badge_id, role, full_name, reason).
    """
    username = str(username or "").strip()
    password = str(password or "")
    if not username or not password:
        return False, "", "", "", "Username and password are required."

    if username == ADMIN_GATEWAY_USERNAME and password == ADMIN_GATEWAY_PASSWORD:
        badge_id, role, full_name = _resolve_bootstrap_identity(registry)
        return True, badge_id, role, full_name, "Bootstrap gateway authentication."

    record = registry.get(username)
    if not record:
        return False, "", "", "", "Invalid credentials."

    role = record.get("role", "FIELD_OFFICER")
    if role not in GATEWAY_ROLES:
        return False, "", "", "", "This account is not authorized for admin gateway access."

    stored_hash = record.get("password_hash")
    if not stored_hash or not check_password_hash(stored_hash, password):
        return False, "", "", "", "Invalid credentials."

    return (
        True,
        username,
        role,
        record.get("full_name", username),
        "Admin gateway authentication.",
    )


def _resolve_bootstrap_identity(registry) -> tuple[str, str, str]:
    for badge_id, record in registry.records.items():
        if record.get("role") == "SYSTEM_ADMIN" and record.get("active", True):
            return badge_id, "SYSTEM_ADMIN", record.get("full_name", badge_id)
    return ADMIN_GATEWAY_USERNAME.upper(), "SYSTEM_ADMIN", "Gateway Administrator"
