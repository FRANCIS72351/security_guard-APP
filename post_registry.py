"""Deployment post registry — authoritative geofence anchor coordinates."""

import json
import re
from pathlib import Path

import numpy as np

from config import BASE_DIR


def normalize_post_id(raw: str) -> str:
    """BROAD STREET / broad_street -> BROAD_STREET"""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", str(raw or "").strip())
    return cleaned.strip("_").upper()


class PostRegistry:
    def __init__(self, path: Path | None = None):
        self.path = path or (BASE_DIR / "deployment_posts.json")
        self.radius_meters = 304.8
        self.posts: dict[str, dict] = {}
        self.coords: dict[str, np.ndarray] = {}
        self.reload()

    def reload(self):
        self.posts = {}
        self.coords = {}
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.radius_meters = float(data.get("geofence_radius_meters", 304.8))
        for post_id, meta in (data.get("posts") or {}).items():
            key = normalize_post_id(post_id)
            if not key:
                continue
            lat = float(meta["latitude"])
            lon = float(meta["longitude"])
            self.posts[key] = {
                "post_id": key,
                "label": meta.get("label", key),
                "latitude": lat,
                "longitude": lon,
                "supervisor_badge_id": meta.get("supervisor_badge_id"),
            }
            self.coords[key] = np.array([lat, lon])

    def is_valid(self, post_id: str) -> bool:
        return normalize_post_id(post_id) in self.coords

    def resolve(self, post_id: str) -> str | None:
        key = normalize_post_id(post_id)
        return key if key in self.coords else None

    def list_for_api(self) -> dict:
        return {
            post_id: {
                "label": meta["label"],
                "latitude": meta["latitude"],
                "longitude": meta["longitude"],
                "radius_meters": self.radius_meters,
                "supervisor_badge_id": meta.get("supervisor_badge_id"),
            }
            for post_id, meta in self.posts.items()
        }

    def set_supervisor(self, post_id: str, supervisor_badge_id: str | None) -> bool:
        key = normalize_post_id(post_id)
        if key not in self.posts:
            return False
        self.posts[key]["supervisor_badge_id"] = supervisor_badge_id or None
        self._persist()
        return True

    def find_post_for_supervisor(self, supervisor_badge_id: str) -> str | None:
        badge = str(supervisor_badge_id).strip()
        for post_id, meta in self.posts.items():
            if meta.get("supervisor_badge_id") == badge:
                return post_id
        return None

    def clear_supervisor_badge(self, supervisor_badge_id: str):
        badge = str(supervisor_badge_id).strip()
        for post_id, meta in self.posts.items():
            if meta.get("supervisor_badge_id") == badge:
                meta["supervisor_badge_id"] = None
        self._persist()

    def upsert_post(
        self,
        post_id: str,
        latitude: float,
        longitude: float,
        label: str | None = None,
    ) -> tuple[bool, str, str | None]:
        key = normalize_post_id(post_id)
        if not key:
            return False, "Post ID is required.", None
        try:
            lat = float(latitude)
            lon = float(longitude)
        except (TypeError, ValueError):
            return False, "Latitude and longitude must be valid numbers.", None
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return False, "Coordinates out of valid range.", None

        display = (label or self.posts.get(key, {}).get("label") or key).strip()
        existing = self.posts.get(key, {})
        self.posts[key] = {
            "post_id": key,
            "label": display,
            "latitude": lat,
            "longitude": lon,
            "supervisor_badge_id": existing.get("supervisor_badge_id"),
        }
        self.coords[key] = np.array([lat, lon])
        self._persist()
        return True, f"Deployment post {key} saved.", key

    def _persist(self):
        payload = {
            "geofence_radius_meters": self.radius_meters,
            "posts": {
                post_id: {
                    "label": meta["label"],
                    "latitude": meta["latitude"],
                    "longitude": meta["longitude"],
                    "supervisor_badge_id": meta.get("supervisor_badge_id"),
                }
                for post_id, meta in self.posts.items()
            },
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
