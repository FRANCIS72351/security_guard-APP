"""Request auth helpers for Flask routes."""

from functools import wraps
from flask import request, jsonify

from auth_tokens import decode_access_token


def extract_bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return None


def get_auth_context() -> dict | None:
    token = extract_bearer_token()
    if not token:
        return None
    return decode_access_token(token)


def require_auth(roles: set[str] | None = None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if request.method == "OPTIONS":
                return fn(*args, **kwargs)
            ctx = get_auth_context()
            if not ctx:
                return jsonify({
                    "status": "DENIED",
                    "reason": "Valid session token required.",
                }), 401
            if roles and ctx.get("role") not in roles:
                return jsonify({
                    "status": "DENIED",
                    "reason": "Insufficient privileges.",
                }), 403
            request.auth_context = ctx
            return fn(*args, **kwargs)

        return wrapper

    return decorator
