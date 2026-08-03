"""Tracks last check-in coordinates to detect impossible GPS jumps."""

import json
import math
from datetime import datetime, timezone
from pathlib import Path

from config import BASE_DIR, MAX_CHECKIN_SPEED_MPS


def _haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    earth_radius = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlon / 2) ** 2
    return earth_radius * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


class GeofenceTracker:
    def __init__(self, store_path: Path | None = None):
        self.store_path = store_path or BASE_DIR / "last_checkin_positions.json"
        self.records: dict[str, dict] = {}
        self._load()

    def _load(self):
        if self.store_path.exists():
            try:
                data = json.loads(self.store_path.read_text(encoding="utf-8"))
                self.records = data.get("officers", {})
            except json.JSONDecodeError:
                print(f"[GEOFENCE WARNING] Corrupt store at {self.store_path}; starting empty.")
                self.records = {}
                self._save()
        else:
            self.records = {}
            self._save()

    def _save(self):
        payload = {"officers": self.records}
        self.store_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def validate_velocity(
        self,
        badge_id: str,
        lat: float,
        lon: float,
    ) -> tuple[bool, str]:
        prev = self.records.get(badge_id)
        if not prev:
            return True, "OK"

        try:
            prev_time = datetime.fromisoformat(
                prev["timestamp"].replace("Z", "+00:00")
            )
            elapsed = (datetime.now(timezone.utc) - prev_time).total_seconds()
            if elapsed < 30:
                return True, "OK"

            distance = _haversine_meters(
                prev["latitude"], prev["longitude"], lat, lon
            )
            speed = distance / elapsed if elapsed > 0 else 0
            if speed > MAX_CHECKIN_SPEED_MPS:
                return False, (
                    f"Impossible movement detected ({speed:.0f} m/s). "
                    "GPS spoofing or teleported coordinates suspected."
                )
        except (KeyError, ValueError, TypeError):
            return True, "OK"

        return True, "OK"

    def record_success(self, badge_id: str, lat: float, lon: float, post_id: str):
        self.records[badge_id] = {
            "latitude": lat,
            "longitude": lon,
            "post_id": post_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._save()

    def list_for_map(self) -> list[dict]:
        return [
            {"badge_id": badge, **record}
            for badge, record in self.records.items()
        ]
