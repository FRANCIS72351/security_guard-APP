"""Personnel profiles: roles, posts, and activation (global RBAC layer)."""

import json
from pathlib import Path

VALID_ROLES = {
    "SYSTEM_ADMIN",
    "SUPERVISOR",
    "FIELD_OFFICER",
    "AUDITOR",
}

ROLE_CAN_ENROLL = {"SYSTEM_ADMIN"}
ROLE_CAN_VIEW_ALL = {"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"}
GATEWAY_ROLES = {"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"}


class PersonnelRegistry:
    def __init__(self, registry_path: Path):
        self.registry_path = registry_path
        self.records: dict[str, dict] = {}
        self._load()

    def _load(self):
        if self.registry_path.exists():
            try:
                data = json.loads(self.registry_path.read_text(encoding="utf-8"))
                self.records = data.get("personnel", {})
            except json.JSONDecodeError:
                print(f"[REGISTRY WARNING] Corrupt JSON at {self.registry_path}; starting empty.")
                self.records = {}
                self._save()
        else:
            self.records = {}
            self._save()

    def _save(self):
        payload = {"personnel": self.records}
        self.registry_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get(self, badge_id: str) -> dict | None:
        record = self.records.get(str(badge_id).strip())
        if not record or not record.get("active", True):
            return None
        return record

    def upsert(
        self,
        badge_id: str,
        full_name: str,
        role: str = "FIELD_OFFICER",
        post_id: str | None = "BANK_HQ_VAULT",
        password_hash: str | None = None,
    ):
        badge_id = str(badge_id).strip()
        role = str(role).strip().upper()
        if role not in VALID_ROLES:
            role = "FIELD_OFFICER"

        existing = self.records.get(badge_id, {})
        record = {
            "full_name": full_name.strip(),
            "role": role,
            "post_id": post_id,
            "active": True,
        }
        if password_hash:
            record["password_hash"] = password_hash
        elif existing.get("password_hash"):
            record["password_hash"] = existing["password_hash"]
        self.records[badge_id] = record
        self._save()

    def set_gateway_password(self, badge_id: str, plain_password: str):
        from admin_auth import hash_gateway_password

        badge_id = str(badge_id).strip()
        record = self.records.get(badge_id)
        if not record:
            return False
        record["password_hash"] = hash_gateway_password(plain_password)
        self._save()
        return True

    def can_enroll(self, badge_id: str) -> bool:
        record = self.get(badge_id)
        if not record:
            return False
        return record.get("role") in ROLE_CAN_ENROLL

    def list_active(self) -> list[dict]:
        items = []
        for badge_id, record in sorted(self.records.items()):
            if record.get("active", True):
                items.append({
                    "badge_id": badge_id,
                    "full_name": record.get("full_name", badge_id),
                    "role": record.get("role", "FIELD_OFFICER"),
                    "post_id": record.get("post_id"),
                    "active": True,
                })
        return items

    def sync_name_from_legacy(self, badge_id: str, full_name: str):
        """Keep registry aligned when only known_faces/*.txt exists."""
        badge_id = str(badge_id).strip()
        if badge_id not in self.records:
            self.upsert(badge_id, full_name, "FIELD_OFFICER", "BANK_HQ_VAULT")
        elif not self.records[badge_id].get("full_name"):
            self.records[badge_id]["full_name"] = full_name
            self._save()
