"""Deployment environment configuration (dev / staging / prod)."""

import os
from pathlib import Path

ENV = os.environ.get("SECUREGUARD_ENV", "dev").lower()
BASE_DIR = Path(__file__).resolve().parent

_DEFAULT_JWT_SECRET = "dev-only-change-in-production-secureguard"
JWT_SECRET = os.environ.get("JWT_SECRET", _DEFAULT_JWT_SECRET)

if ENV == "prod" and JWT_SECRET == _DEFAULT_JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET must be set to a strong value when SECUREGUARD_ENV=prod"
    )
JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "8"))

# Production should set REQUIRE_HTTPS=1
REQUIRE_HTTPS = os.environ.get("REQUIRE_HTTPS", "0") == "1"

# Audit log retention (GDPR / compliance)
AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "90"))

# Regional privacy defaults
PRIVACY_REGION = os.environ.get("PRIVACY_REGION", "global")

# Geofence hardening
MAX_GPS_ACCURACY_METERS = float(os.environ.get("MAX_GPS_ACCURACY_METERS", "75"))
MAX_CHECKIN_SPEED_MPS = float(os.environ.get("MAX_CHECKIN_SPEED_MPS", "55"))

# Geofence enforcement — strict by default (set DEV_RELAX_*=1 only for local debugging)
DEV_RELAX_GEOFENCE = os.environ.get("DEV_RELAX_GEOFENCE", "0") == "1"
DEV_RELAX_GPS = os.environ.get("DEV_RELAX_GPS", "0") == "1"

# Duty tracking — GPS heartbeats while shift is active
DUTY_HEARTBEAT_INTERVAL_SECONDS = int(
    os.environ.get("DUTY_HEARTBEAT_INTERVAL_SECONDS", "60")
)
DUTY_TRAIL_MAX_POINTS = int(os.environ.get("DUTY_TRAIL_MAX_POINTS", "30"))

ENV_LABELS = {
    "dev": "Development",
    "staging": "Staging",
    "prod": "Production",
}

# Admin RBAC gateway (username/password before command center)
ADMIN_GATEWAY_USERNAME = os.environ.get("ADMIN_GATEWAY_USERNAME", "admin")
ADMIN_GATEWAY_PASSWORD = os.environ.get("ADMIN_GATEWAY_PASSWORD", "Chrifranix2026!")


def public_config() -> dict:
    return {
        "environment": ENV,
        "environment_label": ENV_LABELS.get(ENV, ENV),
        "require_https": REQUIRE_HTTPS,
        "audit_retention_days": AUDIT_RETENTION_DAYS,
        "privacy_region": PRIVACY_REGION,
        "jwt_expiry_hours": JWT_EXPIRY_HOURS,
        "max_gps_accuracy_meters": MAX_GPS_ACCURACY_METERS,
        "geofence_radius_feet": int(
            float(os.environ.get("GEOFENCE_RADIUS_METERS", "304.8")) * 3.28084
        ),
        "require_gdpr_consent": os.environ.get("REQUIRE_GDPR_CONSENT", "1") == "1",
        "dev_relax_geofence": DEV_RELAX_GEOFENCE,
        "dev_relax_gps": DEV_RELAX_GPS,
        "duty_heartbeat_interval_seconds": DUTY_HEARTBEAT_INTERVAL_SECONDS,
    }
