"""Compliance audit log with configurable retention."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import AUDIT_RETENTION_DAYS, BASE_DIR


class AuditLogStore:
    def __init__(self, log_path: Path | None = None):
        self.log_path = log_path or BASE_DIR / "audit_log.json"
        self.entries: list[dict] = []
        self._load()
        self._apply_retention()

    def _load(self):
        if self.log_path.exists():
            try:
                data = json.loads(self.log_path.read_text(encoding="utf-8"))
                self.entries = data.get("entries", [])
            except json.JSONDecodeError:
                print(f"[AUDIT WARNING] Corrupt log at {self.log_path}; starting empty.")
                self.entries = []
                self._save()
        else:
            self.entries = []
            self._save()

    def _save(self):
        payload = {
            "retention_days": AUDIT_RETENTION_DAYS,
            "entries": self.entries,
        }
        self.log_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _apply_retention(self):
        cutoff = datetime.now(timezone.utc) - timedelta(days=AUDIT_RETENTION_DAYS)
        kept = []
        for entry in self.entries:
            ts = entry.get("timestamp")
            if not ts:
                continue
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt >= cutoff:
                    kept.append(entry)
            except ValueError:
                kept.append(entry)
        if len(kept) != len(self.entries):
            self.entries = kept
            self._save()

    def record(
        self,
        event_type: str,
        badge_id: str | None,
        detail: str,
        metadata: dict | None = None,
        success: bool = True,
    ):
        entry = {
            "id": f"{datetime.now(timezone.utc).timestamp()}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "badge_id": badge_id,
            "detail": detail,
            "success": success,
            "metadata": metadata or {},
        }
        self.entries.append(entry)
        self._apply_retention()
        self._save()
        return entry

    def list_entries(
        self,
        requester_role: str,
        limit: int = 100,
        badge_filter: str | None = None,
        event_type: str | None = None,
    ) -> list[dict]:
        if requester_role not in {"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"}:
            return []

        items = list(reversed(self.entries))
        if badge_filter:
            items = [e for e in items if e.get("badge_id") == badge_filter]
        if event_type:
            wanted = event_type.strip().upper()
            items = [e for e in items if (e.get("event_type") or "").upper() == wanted]
        return items[:limit]

    def compliance_summary(self) -> dict:
        violations = 0
        duty_events = 0
        check_ins = 0
        for entry in self.entries:
            event = (entry.get("event_type") or "").upper()
            if event in {
                "GEOFENCE_VIOLATION",
                "DUTY_GEOFENCE_VIOLATION",
                "POST_SPOOF_DETECTED",
                "GPS_SPOOF_DETECTED",
                "DUTY_GPS_SPOOF",
            }:
                violations += 1
            if event.startswith("DUTY_"):
                duty_events += 1
            if event == "CHECK_IN_SUCCESS":
                check_ins += 1
        return {
            "retention_days": AUDIT_RETENTION_DAYS,
            "total_entries": len(self.entries),
            "oldest_entry": self.entries[0]["timestamp"] if self.entries else None,
            "latest_entry": self.entries[-1]["timestamp"] if self.entries else None,
            "violation_events": violations,
            "duty_events": duty_events,
            "check_in_successes": check_ins,
        }
