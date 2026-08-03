"""JWT session tokens for authenticated API access."""

from datetime import datetime, timedelta, timezone
import jwt

from config import JWT_EXPIRY_HOURS, JWT_SECRET


def create_access_token(badge_id: str, role: str, full_name: str) -> tuple[str, int]:
    expires_hours = JWT_EXPIRY_HOURS
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=expires_hours)
    payload = {
        "sub": badge_id,
        "role": role,
        "full_name": full_name,
        "iat": now,
        "exp": exp,
        "type": "access",
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token, int(expires_hours * 3600)


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "access":
            return None
        return payload
    except jwt.PyJWTError:
        return None
