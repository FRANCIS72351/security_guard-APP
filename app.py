from flask import Flask, request, jsonify
from security_engine import SecurityOperationsEngine
from config import REQUIRE_HTTPS, public_config, PRIVACY_REGION, DEV_RELAX_GPS, DEV_RELAX_GEOFENCE
from auth_tokens import create_access_token, decode_access_token
from auth_middleware import require_auth, extract_bearer_token, get_auth_context
from admin_auth import verify_gateway_login
from audit_log import AuditLogStore
from geofence_tracker import GeofenceTracker
from duty_tracker import DutyTracker

app = Flask(__name__)
security_core = SecurityOperationsEngine()
audit_store = AuditLogStore()
geofence_tracker = GeofenceTracker()
duty_tracker = DutyTracker()


@app.before_request
def enforce_https_and_cors_preflight():
    if request.method == "OPTIONS":
        return None
    if REQUIRE_HTTPS and not request.is_secure:
        forwarded = request.headers.get("X-Forwarded-Proto", "")
        if forwarded != "https":
            return jsonify({
                "status": "DENIED",
                "reason": "HTTPS required in production.",
            }), 403
    return None


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, Authorization"
    )
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
    return response


def _parse_coordinates(data: dict) -> tuple[float | None, float | None, str | None]:
    if data.get("latitude") is None or data.get("longitude") is None:
        return None, None, "latitude and longitude are required."
    try:
        return float(data.get("latitude")), float(data.get("longitude")), None
    except (TypeError, ValueError):
        return None, None, "latitude and longitude must be valid numbers."


def _run_authentication(data: dict) -> tuple[dict, int]:
    username = str(data.get("username") or "").strip()
    if not username:
        return {"status": "DENIED", "reason": "Badge ID required."}, 400

    latitude, longitude, coord_error = _parse_coordinates(data)
    if coord_error:
        return {"status": "DENIED", "reason": coord_error}, 400

    require_consent = public_config().get("require_gdpr_consent", True)
    if require_consent and not data.get("gdpr_consent"):
        audit_store.record(
            "CHECK_IN_DENIED",
            username,
            "GDPR/data processing consent not recorded",
            success=False,
        )
        return {
            "status": "CONSENT_REQUIRED",
            "reason": "Data processing consent required before check-in.",
        }, 403

    base64_face_image = data.get("face_image")
    client_post_id = data.get("post_id")
    offline_sync = data.get("offline_sync", False)
    location_trusted = data.get("location_trusted", False)
    gps_mocked = data.get("gps_mocked", False)
    gps_accuracy_meters = data.get("gps_accuracy_meters")

    ok, assigned_post_id, assign_msg = security_core.resolve_assigned_post_for_geofence(
        username
    )
    if not ok:
        audit_store.record(
            "CHECK_IN_DENIED",
            username,
            f"Post assignment error: {assign_msg}",
            success=False,
        )
        return {
            "status": "POST_ASSIGNMENT_DENIED",
            "reason": assign_msg,
        }, 403

    if assigned_post_id and client_post_id and client_post_id != assigned_post_id:
        audit_store.record(
            "CHECK_IN_DENIED",
            username,
            f"Post spoofing attempt: claimed {client_post_id}, assigned {assigned_post_id}",
            {"client_post_id": client_post_id, "assigned_post_id": assigned_post_id},
            success=False,
        )
        return {
            "status": "POST_SPOOF_DETECTED",
            "reason": (
                f"Assignment locked by server. You are assigned to {assigned_post_id}; "
                "the device cannot claim a different post."
            ),
            "assigned_post_id": assigned_post_id,
        }, 403

    if assigned_post_id and client_post_id and client_post_id == assigned_post_id:
        pass  # Client echo matches — OK

    if assigned_post_id and not location_trusted and not DEV_RELAX_GPS:
        audit_store.record(
            "CHECK_IN_DENIED",
            username,
            "GPS not trusted (simulator/fallback/denied)",
            success=False,
        )
        return {
            "status": "GPS_TRUST_DENIED",
            "reason": "Live GPS lock required. Cannot verify deployment coordinates.",
        }, 403

    if assigned_post_id and gps_mocked and not DEV_RELAX_GPS:
        audit_store.record(
            "CHECK_IN_DENIED",
            username,
            "Mock/spoofed GPS detected",
            success=False,
        )
        return {
            "status": "GPS_SPOOF_DETECTED",
            "reason": "Mock location detected. Disable fake GPS apps to check in.",
        }, 403

    if assigned_post_id:
        acc_ok, acc_msg = security_core.validate_gps_accuracy(
            gps_accuracy_meters,
            required=not DEV_RELAX_GPS,
        )
        if not acc_ok and not DEV_RELAX_GPS:
            audit_store.record(
                "CHECK_IN_DENIED",
                username,
                acc_msg,
                {"gps_accuracy_meters": gps_accuracy_meters},
                success=False,
            )
            return {"status": "GPS_ACCURACY_DENIED", "reason": acc_msg}, 403

        vel_ok, vel_msg = geofence_tracker.validate_velocity(username, latitude, longitude)
        if not vel_ok and not DEV_RELAX_GPS:
            audit_store.record(
                "CHECK_IN_DENIED",
                username,
                vel_msg,
                success=False,
            )
            return {"status": "GPS_VELOCITY_DENIED", "reason": vel_msg}, 403

    hardware_profile = data.get("hardware_fingerprint", {})
    device_model = hardware_profile.get("hardware_model", "Unknown")
    device_os = hardware_profile.get("os_type", "Unknown")

    geofence_post_id = assigned_post_id
    distance_meters = 0.0
    if assign_msg == "GEOFENCE_EXEMPT_ADMIN":
        distance_telemetry_log = "Geofence exempt (system administrator)."
        geofence_passed = True
    elif DEV_RELAX_GEOFENCE:
        distance_telemetry_log = "Dev mode: geofence check relaxed for testing."
        geofence_passed = True
    elif geofence_post_id:
        geofence_passed, distance_meters, distance_telemetry_log = security_core.evaluate_geofence(
            latitude, longitude, geofence_post_id
        )
    else:
        geofence_passed = True
        distance_telemetry_log = "No geofence post required."

    if not geofence_passed:
        audit_store.record(
            "CHECK_IN_DENIED",
            username,
            f"Geofence violation: {distance_telemetry_log}",
            {
                "distance_meters": distance_meters,
                "offline_sync": offline_sync,
                "assigned_post_id": geofence_post_id,
                "gps_accuracy_meters": gps_accuracy_meters,
                "latitude": latitude,
                "longitude": longitude,
            },
            success=False,
        )
        return {
            "status": "GEOFENCE_VIOLATION",
            "distance_meters": round(float(distance_meters), 1),
            "reason": f"Access Blocked. {distance_telemetry_log}",
            "post_id": geofence_post_id,
            "assigned_post_id": geofence_post_id,
        }, 403

    biometric_clearance, message = security_core.verify_face_biometrics(
        username, base64_face_image
    )
    if not biometric_clearance:
        audit_store.record(
            "CHECK_IN_DENIED",
            username,
            f"Biometric mismatch: {message}",
            {"offline_sync": offline_sync},
            success=False,
        )
        return {
            "status": "BIOMETRIC_MISMATCH",
            "reason": (
                f"Geofence verified clear ({distance_telemetry_log}). "
                f"Auth failed: {message}"
            ),
            "post_id": geofence_post_id,
        }, 401

    profile = security_core.get_personnel_profile(username) or {
        "badge_id": username,
        "full_name": username,
        "role": "FIELD_OFFICER",
        "post_id": geofence_post_id,
    }

    badge_id = profile.get("badge_id", username)
    role = profile.get("role", "FIELD_OFFICER")
    full_name = profile.get("full_name", username)
    token, expires_in = create_access_token(badge_id, role, full_name)

    audit_store.record(
        "CHECK_IN_SUCCESS",
        badge_id,
        f"Geofence cleared: {distance_telemetry_log}",
        {
            "post_id": profile.get("post_id") or geofence_post_id,
            "offline_sync": offline_sync,
            "gps_accuracy_meters": gps_accuracy_meters,
            "latitude": latitude,
            "longitude": longitude,
        },
        success=True,
    )

    if assigned_post_id:
        geofence_tracker.record_success(badge_id, latitude, longitude, geofence_post_id)

    if role == "FIELD_OFFICER" and geofence_post_id:
        duty_tracker.start_duty(
            badge_id,
            geofence_post_id,
            latitude,
            longitude,
            full_name=full_name,
        )
        audit_store.record(
            "DUTY_STARTED",
            badge_id,
            f"Duty shift started at {geofence_post_id}.",
            {
                "post_id": geofence_post_id,
                "latitude": latitude,
                "longitude": longitude,
            },
            success=True,
        )

    return {
        "status": "SUCCESS",
        "reason": f"Authentication Complete. Geofence Cleared: {distance_telemetry_log}",
        "post_id": profile.get("post_id") or geofence_post_id,
        "assigned_post_id": profile.get("post_id") or geofence_post_id,
        "badge_id": badge_id,
        "full_name": full_name,
        "role": role,
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }, 200


@app.route("/", methods=["GET"])
def api_status():
    return jsonify({
        "status": "ONLINE",
        "service": "SecureGuard Field Operations API",
        "biometric_engine": security_core.biometric_engine,
        "config": public_config(),
        "endpoints": {
            "GET /": "API status",
            "GET /health": "Health check",
            "GET /config": "Public deployment config",
            "GET /posts": "List deployment posts",
            "POST /authenticate": "Officer biometric check-in",
            "POST /admin/login": "Admin RBAC gateway login",
            "POST /checkin/sync": "Batch offline check-in sync",
            "POST /auth/refresh": "Refresh session token",
            "POST /register": "Admin personnel enrollment",
            "GET /personnel": "List active personnel",
            "GET /audit/logs": "Compliance audit log",
            "GET /operations/map": "Geofence operations map snapshot",
            "GET /duty/active": "Active duty shifts",
            "POST /duty/heartbeat": "Duty GPS heartbeat",
            "POST /duty/end": "End duty shift",
            "GET /compliance/privacy": "Regional privacy policy",
            "GET /system/status": "Bootstrap status",
        },
    }), 200


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "config": public_config()}), 200


@app.route("/config", methods=["GET", "OPTIONS"])
def deployment_config():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({"status": "OK", "config": public_config()}), 200


@app.route("/compliance/privacy", methods=["GET", "OPTIONS"])
def privacy_policy():
    if request.method == "OPTIONS":
        return "", 204
    policies = {
        "global": {
            "region": "global",
            "data_minimization": True,
            "biometric_consent_required": True,
            "right_to_erasure": True,
            "audit_retention_days": audit_store.compliance_summary()["retention_days"],
        },
        "eu": {
            "region": "eu",
            "gdpr_applicable": True,
            "lawful_basis": "legitimate_interest_and_contract",
            "data_minimization": True,
            "right_to_erasure": True,
            "right_to_access": True,
            "audit_retention_days": audit_store.compliance_summary()["retention_days"],
        },
    }
    policy = policies.get(PRIVACY_REGION, policies["global"])
    return jsonify({"status": "OK", "policy": policy}), 200


@app.route("/posts", methods=["GET", "OPTIONS"])
def list_deployment_posts():
    if request.method == "OPTIONS":
        return "", 204
    posts = security_core.list_assigned_posts()
    fields = security_core.list_posts_with_roster()
    return jsonify({
        "status": "OK",
        "posts": posts,
        "fields": fields,
        "geofence_radius_meters": security_core.post_registry.radius_meters,
        "geofence_radius_feet": round(security_core.post_registry.radius_meters * 3.28084),
    }), 200


@app.route("/posts/<post_id>", methods=["PUT", "POST", "OPTIONS"])
@require_auth({"SYSTEM_ADMIN"})
def upsert_deployment_post(post_id: str):
    """Pin or relocate a deployment post on the operations map (admin)."""
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    latitude = data.get("latitude")
    longitude = data.get("longitude")
    label = data.get("label")
    if latitude is None or longitude is None:
        return jsonify({
            "status": "DENIED",
            "reason": "latitude and longitude are required.",
        }), 400

    ok, message, resolved = security_core.upsert_deployment_post(
        post_id, latitude, longitude, label
    )
    if not ok:
        audit_store.record(
            "POST_UPSERT_FAILED",
            request.auth_context.get("sub"),
            message,
            {"post_id": post_id},
            success=False,
        )
        return jsonify({"status": "DENIED", "reason": message}), 400

    audit_store.record(
        "POST_UPSERTED",
        request.auth_context.get("sub"),
        message,
        {
            "post_id": resolved,
            "latitude": latitude,
            "longitude": longitude,
            "label": label,
        },
        success=True,
    )
    return jsonify({
        "status": "OK",
        "post_id": resolved,
        "reason": message,
        "posts": security_core.list_assigned_posts(),
    }), 200


@app.route("/posts/<post_id>/supervisor", methods=["PUT", "POST", "OPTIONS"])
@require_auth({"SYSTEM_ADMIN"})
def assign_post_supervisor(post_id: str):
    """Link a SUPERVISOR badge to a deployment field (one supervisor per field)."""
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    supervisor_badge = str(data.get("supervisor_badge_id") or "").strip() or None

    ok, message = security_core.assign_post_supervisor(post_id, supervisor_badge)
    if not ok:
        audit_store.record(
            "POST_SUPERVISOR_FAILED",
            request.auth_context.get("sub"),
            message,
            {"post_id": post_id, "supervisor_badge_id": supervisor_badge},
            success=False,
        )
        return jsonify({"status": "DENIED", "reason": message}), 403

    resolved = security_core.post_registry.resolve(post_id)
    audit_store.record(
        "POST_SUPERVISOR_ASSIGNED",
        request.auth_context.get("sub"),
        message,
        {"post_id": resolved, "supervisor_badge_id": supervisor_badge},
        success=True,
    )
    return jsonify({
        "status": "OK",
        "post_id": resolved,
        "supervisor_badge_id": supervisor_badge,
        "reason": message,
        "fields": security_core.list_posts_with_roster(),
    }), 200


@app.route("/operations/map", methods=["GET", "OPTIONS"])
@require_auth({"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"})
def operations_map_snapshot():
    """Live operations picture: deployment perimeters + last officer check-ins."""
    if request.method == "OPTIONS":
        return "", 204
    positions = geofence_tracker.list_for_map()
    duty_positions = duty_tracker.positions_for_map()
    merged = {p["badge_id"]: p for p in positions}
    for dp in duty_positions:
        merged[dp["badge_id"]] = dp
    snapshot = security_core.build_operations_map(list(merged.values()))
    snapshot["active_duty_count"] = len(duty_tracker.list_active())
    return jsonify({"status": "OK", **snapshot}), 200


def _evaluate_duty_heartbeat(badge_id: str, data: dict) -> tuple[dict, int]:
    latitude, longitude, coord_error = _parse_coordinates(data)
    if coord_error:
        return {"status": "DENIED", "reason": coord_error}, 400

    session = duty_tracker.get_active(badge_id)
    if not session:
        return {
            "status": "DENIED",
            "reason": "No active duty shift. Check in to start duty.",
        }, 403

    gps_mocked = bool(data.get("gps_mocked"))
    gps_accuracy = data.get("gps_accuracy_meters")
    location_trusted = bool(data.get("location_trusted", False))

    if gps_mocked and not DEV_RELAX_GPS:
        audit_store.record(
            "DUTY_GPS_SPOOF",
            badge_id,
            "Mock GPS detected during duty heartbeat.",
            {"latitude": latitude, "longitude": longitude},
            success=False,
        )
        return {
            "status": "GPS_SPOOF_DETECTED",
            "reason": "Mock GPS detected. Disable fake location apps.",
        }, 403

    if not location_trusted and not DEV_RELAX_GPS:
        audit_store.record(
            "DUTY_GPS_UNTRUSTED",
            badge_id,
            "Untrusted GPS during duty heartbeat.",
            success=False,
        )
        return {
            "status": "GPS_TRUST_DENIED",
            "reason": "GPS signal not trusted for duty tracking.",
        }, 403

    post_id = session.get("post_id")
    inside = True
    distance_m = 0.0
    geofence_msg = "No geofence post assigned."

    if post_id and not DEV_RELAX_GEOFENCE:
        inside, distance_m, geofence_msg = security_core.evaluate_geofence(
            latitude, longitude, post_id
        )
    elif post_id:
        inside, distance_m, geofence_msg = security_core.evaluate_geofence(
            latitude, longitude, post_id
        )

    updated, violation_new, _ = duty_tracker.record_heartbeat(
        badge_id,
        latitude,
        longitude,
        inside_geofence=inside,
        distance_meters=distance_m,
        gps_mocked=gps_mocked,
        gps_accuracy_meters=float(gps_accuracy) if gps_accuracy is not None else None,
    )

    if violation_new:
        audit_store.record(
            "DUTY_GEOFENCE_VIOLATION",
            badge_id,
            geofence_msg,
            {
                "post_id": post_id,
                "latitude": latitude,
                "longitude": longitude,
                "distance_meters": round(distance_m, 1),
            },
            success=False,
        )

    geofence_tracker.record_success(badge_id, latitude, longitude, post_id or "")

    return {
        "status": "OK",
        "reason": geofence_msg,
        "inside_geofence": inside,
        "distance_meters": round(distance_m, 1),
        "duty": updated,
        "violation_recorded": violation_new,
    }, 200


@app.route("/duty/start", methods=["POST", "OPTIONS"])
@require_auth({"FIELD_OFFICER", "SUPERVISOR", "SYSTEM_ADMIN"})
def start_duty_shift():
    if request.method == "OPTIONS":
        return "", 204
    ctx = request.auth_context
    badge_id = ctx.get("sub")
    data = request.get_json() or {}
    latitude, longitude, coord_error = _parse_coordinates(data)
    if coord_error:
        return jsonify({"status": "DENIED", "reason": coord_error}), 400

    ok, post_id, msg = security_core.resolve_assigned_post_for_geofence(badge_id)
    if not ok or not post_id:
        return jsonify({"status": "DENIED", "reason": msg}), 403

    profile = security_core.get_personnel_profile(badge_id) or {}
    session = duty_tracker.start_duty(
        badge_id,
        post_id,
        latitude,
        longitude,
        full_name=profile.get("full_name", badge_id),
    )
    audit_store.record(
        "DUTY_STARTED",
        badge_id,
        f"Duty shift started at {post_id}.",
        {"post_id": post_id, "latitude": latitude, "longitude": longitude},
        success=True,
    )
    return jsonify({"status": "OK", "duty": session}), 200


@app.route("/duty/heartbeat", methods=["POST", "OPTIONS"])
@require_auth({"FIELD_OFFICER", "SUPERVISOR", "SYSTEM_ADMIN"})
def duty_heartbeat():
    if request.method == "OPTIONS":
        return "", 204
    ctx = request.auth_context
    badge_id = ctx.get("sub")
    data = request.get_json() or {}
    body, code = _evaluate_duty_heartbeat(badge_id, data)
    return jsonify(body), code


@app.route("/duty/end", methods=["POST", "OPTIONS"])
@require_auth({"FIELD_OFFICER", "SUPERVISOR", "SYSTEM_ADMIN"})
def end_duty_shift():
    if request.method == "OPTIONS":
        return "", 204
    ctx = request.auth_context
    badge_id = ctx.get("sub")
    session = duty_tracker.end_duty(badge_id)
    if not session:
        return jsonify({
            "status": "DENIED",
            "reason": "No active duty shift to end.",
        }), 404

    audit_store.record(
        "DUTY_ENDED",
        badge_id,
        f"Duty shift ended. Heartbeats: {session.get('heartbeat_count', 0)}, "
        f"violations: {session.get('violation_count', 0)}.",
        {
            "post_id": session.get("post_id"),
            "started_at": session.get("started_at"),
            "ended_at": session.get("ended_at"),
            "violation_count": session.get("violation_count", 0),
        },
        success=True,
    )
    return jsonify({"status": "OK", "duty": session}), 200


@app.route("/duty/status", methods=["GET", "OPTIONS"])
@require_auth({"FIELD_OFFICER", "SUPERVISOR", "SYSTEM_ADMIN", "AUDITOR"})
def duty_status():
    if request.method == "OPTIONS":
        return "", 204
    ctx = request.auth_context
    badge = request.args.get("badge_id") or ctx.get("sub")
    role = ctx.get("role", "FIELD_OFFICER")
    if badge != ctx.get("sub") and role not in {"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"}:
        return jsonify({"status": "DENIED", "reason": "Insufficient privileges."}), 403

    session = duty_tracker.get_active(badge)
    return jsonify({
        "status": "OK",
        "on_duty": session is not None,
        "duty": session,
    }), 200


@app.route("/duty/active", methods=["GET", "OPTIONS"])
@require_auth({"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"})
def list_active_duty():
    if request.method == "OPTIONS":
        return "", 204
    active = duty_tracker.list_active()
    return jsonify({
        "status": "OK",
        "active_duty": active,
        "count": len(active),
    }), 200


@app.route("/system/status", methods=["GET", "OPTIONS"])
def system_status():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "status": "OK",
        "needs_admin_bootstrap": not security_core._has_enrolled_system_admin(),
        "biometric_engine": security_core.biometric_engine,
        "config": public_config(),
    }), 200


@app.route("/auth/refresh", methods=["POST", "OPTIONS"])
def refresh_token():
    if request.method == "OPTIONS":
        return "", 204
    ctx = get_auth_context()
    if not ctx:
        return jsonify({"status": "DENIED", "reason": "Invalid or expired token."}), 401

    badge_id = ctx.get("sub")
    role = ctx.get("role", "FIELD_OFFICER")
    full_name = ctx.get("full_name", badge_id)
    token, expires_in = create_access_token(badge_id, role, full_name)

    return jsonify({
        "status": "OK",
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }), 200


@app.route("/admin/login", methods=["POST", "OPTIONS"])
def admin_gateway_login():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data:
        return jsonify({"status": "DENIED", "reason": "Missing login payload"}), 400

    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")

    ok, badge_id, role, full_name, reason = verify_gateway_login(
        username,
        password,
        security_core.personnel_registry,
    )
    if not ok:
        audit_store.record(
            "ADMIN_LOGIN_DENIED",
            username or "UNKNOWN",
            reason,
            success=False,
        )
        return jsonify({
            "status": "DENIED",
            "authenticated": False,
            "reason": reason,
        }), 401

    profile = security_core.get_personnel_profile(badge_id) or {}
    post_id = profile.get("post_id")
    token, expires_in = create_access_token(badge_id, role, full_name)

    audit_store.record(
        "ADMIN_LOGIN_SUCCESS",
        badge_id,
        reason,
        {"role": role, "gateway_username": username},
        success=True,
    )

    return jsonify({
        "status": "SUCCESS",
        "authenticated": True,
        "reason": reason,
        "badge_id": badge_id,
        "full_name": full_name,
        "role": role,
        "post_id": post_id,
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }), 200


@app.route("/personnel/assignment", methods=["GET", "OPTIONS"])
def get_officer_assignment():
    """Returns server-authoritative post for geofence (pre-check-in display)."""
    if request.method == "OPTIONS":
        return "", 204
    badge = request.args.get("badge_id", "").strip()
    if not badge:
        return jsonify({"status": "DENIED", "reason": "badge_id required"}), 400

    ok, post_id, msg = security_core.resolve_assigned_post_for_geofence(badge)
    if not ok:
        return jsonify({"status": "DENIED", "reason": msg}), 403

    exempt = msg == "GEOFENCE_EXEMPT_ADMIN"
    radius_m = security_core.post_registry.radius_meters
    post_meta = (
        security_core.post_registry.posts.get(post_id, {}) if post_id else {}
    )
    return jsonify({
        "status": "OK",
        "badge_id": badge,
        "assigned_post_id": post_id,
        "post_label": post_meta.get("label", post_id),
        "post_latitude": post_meta.get("latitude"),
        "post_longitude": post_meta.get("longitude"),
        "geofence_exempt": exempt,
        "geofence_radius_meters": radius_m,
        "geofence_radius_feet": round(radius_m * 3.28084),
    }), 200


@app.route("/personnel/assignment", methods=["PUT", "POST", "OPTIONS"])
@require_auth({"SYSTEM_ADMIN", "SUPERVISOR"})
def update_officer_assignment():
    """Admin or post supervisor assigns officer to a deployment field."""
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json() or {}
    badge = str(data.get("badge_id") or "").strip()
    post_id = str(data.get("post_id") or "").strip()
    if not badge or not post_id:
        return jsonify({"status": "DENIED", "reason": "badge_id and post_id required."}), 400

    ctx = request.auth_context
    requester = ctx.get("sub")
    requester_role = ctx.get("role", "FIELD_OFFICER")

    if requester_role == "SUPERVISOR":
        ok, message = security_core.assign_officer_post_scoped(requester, badge, post_id)
    else:
        ok, message = security_core.assign_officer_post(badge, post_id)

    if not ok:
        audit_store.record(
            "ASSIGNMENT_FAILED",
            requester,
            message,
            {"target_badge": badge, "post_id": post_id},
            success=False,
        )
        return jsonify({"status": "DENIED", "reason": message}), 403

    resolved = security_core.post_registry.resolve(post_id)
    audit_store.record(
        "ASSIGNMENT_UPDATED",
        requester,
        message,
        {"target_badge": badge, "post_id": resolved},
        success=True,
    )
    return jsonify({
        "status": "OK",
        "badge_id": badge,
        "assigned_post_id": resolved,
        "reason": message,
    }), 200


@app.route("/personnel", methods=["GET", "OPTIONS"])
@require_auth({"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"})
def list_personnel():
    if request.method == "OPTIONS":
        return "", 204

    ctx = request.auth_context
    requester = ctx.get("sub")

    ok, message, personnel = security_core.list_personnel(requester)
    if not ok:
        return jsonify({"status": "DENIED", "reason": message}), 403
    return jsonify({
        "status": "OK",
        "personnel": personnel,
        "count": len(personnel),
    }), 200


@app.route("/audit/logs", methods=["GET", "OPTIONS"])
@require_auth({"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"})
def audit_logs():
    if request.method == "OPTIONS":
        return "", 204
    ctx = request.auth_context
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except (TypeError, ValueError):
        return jsonify({"status": "DENIED", "reason": "Invalid limit parameter."}), 400
    badge_filter = request.args.get("badge_id")
    event_type = request.args.get("event_type")
    entries = audit_store.list_entries(
        ctx.get("role"),
        limit=limit,
        badge_filter=badge_filter,
        event_type=event_type,
    )
    return jsonify({
        "status": "OK",
        "entries": entries,
        "summary": audit_store.compliance_summary(),
        "count": len(entries),
    }), 200


@app.route("/register", methods=["POST", "OPTIONS"])
def handle_personnel_registration():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data:
        return jsonify({"status": "DENIED", "reason": "Missing enrollment payload"}), 400

    try:
        badge_id = data.get("badge_id")
        full_name = data.get("full_name")
        base64_face_image = data.get("face_image")
        role = str(data.get("role", "FIELD_OFFICER")).strip().upper()

        if security_core._has_enrolled_system_admin():
            ctx = get_auth_context()
            if not ctx:
                return jsonify({
                    "status": "DENIED",
                    "reason": "Valid admin session token required for enrollment.",
                }), 401
            admin_badge = ctx.get("sub")
        else:
            if role != "SYSTEM_ADMIN":
                return jsonify({
                    "status": "DENIED",
                    "reason": "Bootstrap: enroll the first SYSTEM_ADMIN first.",
                }), 403
            admin_badge = None

        enrolled, message = security_core.register_personnel(
            badge_id,
            full_name,
            base64_face_image,
            admin_badge=admin_badge,
            role=role,
            post_id=data.get("post_id", "BANK_HQ_VAULT"),
        )
        if not enrolled:
            audit_store.record("ENROLLMENT_FAILED", admin_badge, message, success=False)
            return jsonify({"status": "ENROLLMENT_FAILED", "reason": message}), 400

        gateway_password = data.get("gateway_password")
        if gateway_password and role in {"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"}:
            security_core.personnel_registry.set_gateway_password(
                badge_id,
                str(gateway_password),
            )

        audit_store.record("ENROLLMENT_SUCCESS", badge_id, message, {"admin": admin_badge})
        return jsonify({
            "status": "REGISTERED",
            "reason": message,
            "badge_id": badge_id,
        }), 201
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "reason": f"Enrollment kernel dropped execution sequence: {str(e)}",
        }), 500


@app.route("/checkin/sync", methods=["POST", "OPTIONS"])
def sync_offline_checkins():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data:
        return jsonify({"status": "DENIED", "reason": "Missing sync payload"}), 400

    items = data.get("checkins", [])
    results = []
    for item in items:
        try:
            item = dict(item)
            item["offline_sync"] = True
            body, code = _run_authentication(item)
            results.append({
                "client_id": item.get("client_id"),
                "status": body.get("status"),
                "http_code": code,
                "badge_id": body.get("badge_id"),
                "reason": body.get("reason"),
            })
        except Exception as e:
            results.append({
                "client_id": item.get("client_id") if isinstance(item, dict) else None,
                "status": "ERROR",
                "http_code": 500,
                "reason": str(e),
            })

    return jsonify({
        "status": "OK",
        "synced": len(results),
        "results": results,
    }), 200


@app.route("/authenticate", methods=["POST", "OPTIONS"])
def handle_guard_authentication():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json()
    if not data:
        return jsonify({"status": "DENIED", "reason": "Missing operational framework payload"}), 400

    try:
        body, code = _run_authentication(data)
        return jsonify(body), code
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "reason": f"System kernel dropped execution sequence: {str(e)}",
        }), 500


if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", 5001))
    cfg = public_config()
    flask_debug = os.environ.get("FLASK_DEBUG", "1" if cfg["environment"] == "dev" else "0") == "1"
    print(f"[SECUREGUARD API] env={cfg['environment']} port={port} https_required={REQUIRE_HTTPS}")
    app.run(host="0.0.0.0", port=port, debug=flask_debug, use_reloader=False)
