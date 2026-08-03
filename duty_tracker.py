"""Active duty shifts with GPS heartbeat trail and geofence monitoring."""

import json
from datetime import datetime, timezone
from pathlib import Path

from config import BASE_DIR, DUTY_TRAIL_MAX_POINTS


class DutyTracker:
    def __init__(self, store_path: Path | None = None):
        self.store_path = store_path or BASE_DIR / "duty_sessions.json"
        self.active: dict[str, dict] = {}
        self.history: list[dict] = []
        self._load()

    def _load(self):
        if not self.store_path.exists():
            self.active = {}
            self.history = []
            self._save()
            return
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            self.active = data.get("active", {})
            self.history = data.get("history", [])
        except json.JSONDecodeError:
            print(f"[DUTY WARNING] Corrupt store at {self.store_path}; resetting.")
            self.active = {}
            self.history = []
            self._save()

    def _save(self):
        payload = {"active": self.active, "history": self.history[-500:]}
        self.store_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def start_duty(
        self,
        badge_id: str,
        post_id: str | None,
        latitude: float,
        longitude: float,
        full_name: str | None = None,
    ) -> dict:
        badge_id = str(badge_id).strip()
        session = {
            "badge_id": badge_id,
            "full_name": full_name or badge_id,
            "post_id": post_id,
            "started_at": self._now(),
            "ended_at": None,
            "last_latitude": latitude,
            "last_longitude": longitude,
            "last_heartbeat_at": self._now(),
            "inside_geofence": True,
            "distance_meters": 0.0,
            "heartbeat_count": 1,
            "violation_count": 0,
            "trail": [
                {
                    "latitude": latitude,
                    "longitude": longitude,
                    "timestamp": self._now(),
                }
            ],
        }
        self.active[badge_id] = session
        self._save()
        return session

    def end_duty(self, badge_id: str) -> dict | None:
        badge_id = str(badge_id).strip()
        session = self.active.pop(badge_id, None)
        if not session:
            return None
        session["ended_at"] = self._now()
        self.history.append(session)
        self._save()
        return session

    def get_active(self, badge_id: str) -> dict | None:
        return self.active.get(str(badge_id).strip())

    def list_active(self) -> list[dict]:
        return list(self.active.values())

    def record_heartbeat(
        self,
        badge_id: str,
        latitude: float,
        longitude: float,
        *,
        inside_geofence: bool,
        distance_meters: float,
        gps_mocked: bool = False,
        gps_accuracy_meters: float | None = None,
    ) -> tuple[dict | None, bool, bool]:
        """
        Returns (session, geofence_violation_new, gps_spoof).
        geofence_violation_new is True when officer transitions outside geofence.
        """
        badge_id = str(badge_id).strip()
        session = self.active.get(badge_id)
        if not session:
            return None, False, gps_mocked

        was_inside = session.get("inside_geofence", True)
        violation_new = was_inside and not inside_geofence

        session["last_latitude"] = latitude
        session["last_longitude"] = longitude
        session["last_heartbeat_at"] = self._now()
        session["inside_geofence"] = inside_geofence
        session["distance_meters"] = round(distance_meters, 1)
        session["heartbeat_count"] = int(session.get("heartbeat_count", 0)) + 1
        if violation_new:
            session["violation_count"] = int(session.get("violation_count", 0)) + 1
        if gps_accuracy_meters is not None:
            session["last_gps_accuracy_meters"] = gps_accuracy_meters

        trail = session.get("trail", [])
        trail.append(
            {
                "latitude": latitude,
                "longitude": longitude,
                "timestamp": self._now(),
                "inside_geofence": inside_geofence,
            }
        )
        session["trail"] = trail[-DUTY_TRAIL_MAX_POINTS:]
        self.active[badge_id] = session
        self._save()
        return session, violation_new, gps_mocked

    def positions_for_map(self) -> list[dict]:
        rows = []
        for badge, session in self.active.items():
            rows.append(
                {
                    "badge_id": badge,
                    "latitude": session.get("last_latitude"),
                    "longitude": session.get("last_longitude"),
                    "timestamp": session.get("last_heartbeat_at"),
                    "source": "duty_heartbeat",
                    "on_duty": True,
                    "inside_geofence": session.get("inside_geofence"),
                    "post_id": session.get("post_id"),
                }
            )
        return rows
