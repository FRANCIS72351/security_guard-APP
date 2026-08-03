from pathlib import Path
import base64
import numpy as np
import cv2

from personnel_registry import PersonnelRegistry
from config import BASE_DIR, MAX_GPS_ACCURACY_METERS
from post_registry import PostRegistry, normalize_post_id

try:
    import face_recognition

    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    face_recognition = None
    FACE_RECOGNITION_AVAILABLE = False


class SecurityOperationsEngine:
    def __init__(self):
        self.base_dir = BASE_DIR
        self.known_faces_dir = self.base_dir / "known_faces"
        self.known_faces_dir.mkdir(exist_ok=True)

        self.post_registry = PostRegistry()
        self.maximum_allowed_radius_meters = self.post_registry.radius_meters
        self.approved_device_serial = "ARM64_SECURE_BUILD_NODE"

        self.known_face_encodings = []
        self.known_face_badges = []
        self.known_face_templates = {}

        self.personnel_registry = PersonnelRegistry(self.base_dir / "personnel_registry.json")

        self._face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )

        self.biometric_engine = (
            "face_recognition" if FACE_RECOGNITION_AVAILABLE else "opencv"
        )
        print(f"[BIOMETRIC SYSTEM] Engine mode: {self.biometric_engine}")
        self.load_authorized_personnel_registry()

    def _extract_face_gray(self, bgr_image):
        gray = cv2.cvtColor(bgr_image, cv2.COLOR_BGR2GRAY)
        faces = self._face_cascade.detectMultiScale(
            gray, scaleFactor=1.1, minNeighbors=5, minSize=(80, 80)
        )
        if len(faces) == 0:
            return None

        x, y, w, h = max(faces, key=lambda box: box[2] * box[3])
        face = gray[y : y + h, x : x + w]
        return cv2.resize(face, (160, 160))

    def load_authorized_personnel_registry(self):
        """Indexes registered face templates from the physical data layer."""
        print("[BIOMETRIC SYSTEM] Indexing authorized face templates...")
        for img_path in self.known_faces_dir.glob("*.jpg"):
            try:
                badge_number = img_path.stem
                if FACE_RECOGNITION_AVAILABLE:
                    loaded_image = face_recognition.load_image_file(str(img_path))
                    face_encodings = face_recognition.face_encodings(loaded_image)
                    if len(face_encodings) > 0:
                        self.known_face_encodings.append(face_encodings[0])
                        self.known_face_badges.append(badge_number)
                        print(f"[REGISTRY SUCCESS] Mapped badge: {badge_number}")
                else:
                    frame = cv2.imread(str(img_path))
                    if frame is None:
                        continue
                    template = self._extract_face_gray(frame)
                    if template is not None:
                        self.known_face_templates[badge_number] = template
                        self.known_face_badges.append(badge_number)
                        print(f"[REGISTRY SUCCESS] OpenCV template for badge: {badge_number}")

                meta_path = self.known_faces_dir / f"{badge_number}.txt"
                if meta_path.exists():
                    full_name = meta_path.read_text(encoding="utf-8").strip()
                    self.personnel_registry.sync_name_from_legacy(badge_number, full_name)
            except Exception as e:
                print(f"[ERROR LOADING FACE] {img_path.name}: {e}")

    def calculate_haversine_distance(self, coord1, coord2):
        """Computes physical distance in meters between two Earth-surface coordinates."""
        earth_radius_meters = 6371000.0

        lat1, lon1 = np.radians(coord1[0]), np.radians(coord1[1])
        lat2, lon2 = np.radians(coord2[0]), np.radians(coord2[1])

        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = np.sin(dlat / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2) ** 2
        c = 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))

        return earth_radius_meters * c

    def validate_gps_accuracy(
        self, accuracy_meters: float | None, *, required: bool = True
    ) -> tuple[bool, str]:
        if accuracy_meters is None:
            if required:
                return False, "GPS accuracy unknown. Wait for a stable GPS fix before check-in."
            return True, "OK"
        try:
            accuracy = float(accuracy_meters)
        except (TypeError, ValueError):
            return False, "Invalid GPS accuracy reading."
        if accuracy > MAX_GPS_ACCURACY_METERS:
            return False, (
                f"GPS accuracy too low ({accuracy:.0f}m). "
                f"Required ≤ {MAX_GPS_ACCURACY_METERS:.0f}m for check-in."
            )
        return True, "OK"

    def validate_enrollment_post(self, post_id: str) -> tuple[bool, str]:
        resolved = self.post_registry.resolve(post_id)
        if not resolved:
            return False, f"Post '{post_id}' is not a registered deployment site."
        return True, "OK"

    def evaluate_geofence(
        self, current_lat: float, current_lon: float, post_id: str
    ) -> tuple[bool, float, str]:
        """Returns (inside_perimeter, distance_meters, telemetry_message)."""
        resolved = self.post_registry.resolve(post_id)
        if not resolved:
            return False, 0.0, f"Invalid deployment post '{post_id}'."

        center = self.post_registry.coords[resolved]
        current = np.array([current_lat, current_lon])
        distance_meters = self.calculate_haversine_distance(center, current)
        limit_feet = self.maximum_allowed_radius_meters * 3.28084
        distance_feet = distance_meters * 3.28084

        label = self.post_registry.posts[resolved].get("label", resolved)
        msg = (
            f"{label} ({resolved}): {distance_feet:.0f} ft from post center "
            f"(limit {limit_feet:.0f} ft)."
        )
        if distance_meters > self.maximum_allowed_radius_meters:
            return False, distance_meters, msg + " OUTSIDE GEOFENCE."
        return True, distance_meters, msg + " Within perimeter."

    def resolve_assigned_post_for_geofence(self, badge_id: str) -> tuple[bool, str | None, str]:
        """Server-authoritative post — client cannot choose a different assignment."""
        profile = self.get_personnel_profile(badge_id)
        if not profile:
            return False, None, "Badge not registered in personnel registry."

        role = profile.get("role", "FIELD_OFFICER")
        post_id = profile.get("post_id")

        if role == "SYSTEM_ADMIN" and not post_id:
            return True, None, "GEOFENCE_EXEMPT_ADMIN"

        if not post_id:
            return False, None, "No deployment post assigned to this officer."

        resolved = self.post_registry.resolve(post_id)
        if not resolved:
            return False, None, f"Assigned post '{post_id}' is not a valid deployment site."

        return True, resolved, "OK"

    def process_contextual_threat_matrix(
        self, current_lat, current_lon, device_model, device_os, targeted_post_id
    ):
        """Legacy hook — geofence uses evaluate_geofence(); hardware checks are advisory only."""
        inside, distance_m, msg = self.evaluate_geofence(
            current_lat, current_lon, targeted_post_id
        )
        if not inside:
            return 1.0, msg
        return 0.0, msg

    def _verify_with_face_recognition(self, badge_number, rgb_frame):
        uploaded_encodings = face_recognition.face_encodings(rgb_frame)
        if len(uploaded_encodings) == 0:
            return False, "Biometric evaluation failed: No face structural layout detected."

        incoming_vector = uploaded_encodings[0]
        if badge_number not in self.known_face_badges:
            return False, "Badge identifier unregistered inside central network schema."

        registry_index = self.known_face_badges.index(badge_number)
        target_encoding = self.known_face_encodings[registry_index]

        match_results = face_recognition.compare_faces(
            [target_encoding], incoming_vector, tolerance=0.55
        )
        if match_results[0]:
            return True, "Biometric alignment verified."
        return False, "Identity vector matching mismatch."

    def _verify_with_opencv(self, badge_number, bgr_frame):
        if badge_number not in self.known_face_templates:
            return False, "Badge identifier unregistered inside central network schema."

        incoming_face = self._extract_face_gray(bgr_frame)
        if incoming_face is None:
            return False, "Biometric evaluation failed: No face structural layout detected."

        reference_face = self.known_face_templates[badge_number]
        score = cv2.matchTemplate(incoming_face, reference_face, cv2.TM_CCOEFF_NORMED)[0][0]

        if score >= 0.45:
            return True, f"Biometric alignment verified (OpenCV score: {score:.2f})."
        return False, f"Identity vector matching mismatch (OpenCV score: {score:.2f})."

    def verify_face_biometrics(self, badge_number, base64_image_string):
        """Decodes incoming mobile streams and handles biometric template lookups."""
        try:
            image_bytes = base64.b64decode(base64_image_string)
            nparr = np.frombuffer(image_bytes, np.uint8)
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if frame is None:
                return False, "Biometric evaluation failed: Invalid image payload."

            if FACE_RECOGNITION_AVAILABLE:
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                return self._verify_with_face_recognition(badge_number, rgb_frame)

            return self._verify_with_opencv(badge_number, frame)
        except Exception as e:
            return False, f"Pipeline execution drop: {str(e)}"

    def _has_enrolled_system_admin(self) -> bool:
        for badge_id, record in self.personnel_registry.records.items():
            if record.get("role") == "SYSTEM_ADMIN" and badge_id in self.known_face_badges:
                return True
        return False

    def get_personnel_profile(self, badge_id: str) -> dict | None:
        record = self.personnel_registry.get(badge_id)
        if not record:
            name_path = self.known_faces_dir / f"{badge_id}.txt"
            if name_path.exists() and badge_id in self.known_face_badges:
                return {
                    "badge_id": badge_id,
                    "full_name": name_path.read_text(encoding="utf-8").strip(),
                    "role": "FIELD_OFFICER",
                    "post_id": "BANK_HQ_VAULT",
                }
            return None
        return {
            "badge_id": badge_id,
            "full_name": record.get("full_name", badge_id),
            "role": record.get("role", "FIELD_OFFICER"),
            "post_id": record.get("post_id"),
        }

    def register_personnel(
        self,
        badge_id,
        full_name,
        base64_image_string,
        admin_badge=None,
        role="FIELD_OFFICER",
        post_id="BANK_HQ_VAULT",
    ):
        """Enrolls a new officer face template into the known_faces registry."""
        badge_id = str(badge_id).strip()
        full_name = str(full_name).strip()
        role = str(role or "FIELD_OFFICER").strip().upper()
        post_id = post_id or "BANK_HQ_VAULT"
        resolved_post = self.post_registry.resolve(post_id) or normalize_post_id(post_id)

        if not badge_id or not full_name:
            return False, "Badge ID and legal full name are required for enrollment."

        if badge_id in self.known_face_badges:
            return False, f"Badge {badge_id} is already registered in central network schema."

        if role != "SYSTEM_ADMIN":
            post_ok, post_msg = self.validate_enrollment_post(resolved_post)
            if not post_ok:
                return False, post_msg

        if self._has_enrolled_system_admin():
            if not admin_badge or not self.personnel_registry.can_enroll(admin_badge):
                return False, "Enrollment denied: valid system admin authorization required."
        else:
            if role != "SYSTEM_ADMIN":
                return False, (
                    "Bootstrap: enroll the first SYSTEM_ADMIN before other roles."
                )

        try:
            image_bytes = base64.b64decode(base64_image_string)
            nparr = np.frombuffer(image_bytes, np.uint8)
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if frame is None:
                return False, "Enrollment failed: Invalid image payload."

            if FACE_RECOGNITION_AVAILABLE:
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                encodings = face_recognition.face_encodings(rgb_frame)
                if len(encodings) == 0:
                    return False, "Enrollment failed: No face structural layout detected."
                self.known_face_encodings.append(encodings[0])
            else:
                template = self._extract_face_gray(frame)
                if template is None:
                    return False, "Enrollment failed: No face structural layout detected."
                self.known_face_templates[badge_id] = template

            image_path = self.known_faces_dir / f"{badge_id}.jpg"
            cv2.imwrite(str(image_path), frame)

            metadata_path = self.known_faces_dir / f"{badge_id}.txt"
            metadata_path.write_text(full_name, encoding="utf-8")

            self.known_face_badges.append(badge_id)
            self.personnel_registry.upsert(
                badge_id,
                full_name,
                role=role,
                post_id=resolved_post if role != "SYSTEM_ADMIN" else None,
            )
            return True, f"Officer {full_name} (Badge {badge_id}) enrolled successfully."
        except Exception as e:
            return False, f"Enrollment pipeline drop: {str(e)}"

    def list_personnel(self, requester_badge: str | None) -> tuple[bool, str, list]:
        if not requester_badge:
            return False, "Authorization badge required.", []
        record = self.personnel_registry.get(requester_badge)
        if not record:
            return False, "Unknown authorization badge.", []
        role = record.get("role")
        if role not in {"SYSTEM_ADMIN", "SUPERVISOR", "AUDITOR"}:
            return False, "Insufficient privileges to list personnel.", []

        all_active = self.personnel_registry.list_active()
        if role == "SUPERVISOR":
            supervisor_post = record.get("post_id")
            if not supervisor_post:
                supervisor_post = self.post_registry.find_post_for_supervisor(requester_badge)
            if supervisor_post:
                filtered = [
                    p for p in all_active
                    if p.get("post_id") == supervisor_post
                    or p.get("badge_id") == requester_badge
                ]
            else:
                filtered = [
                    p for p in all_active if p.get("badge_id") == requester_badge
                ]
            return True, "OK", filtered

        return True, "OK", all_active

    def assign_officer_post(self, badge_id: str, post_id: str) -> tuple[bool, str]:
        badge_id = str(badge_id).strip()
        resolved = self.post_registry.resolve(post_id)
        if not resolved:
            return False, f"Post '{post_id}' is not a registered deployment site."
        record = self.personnel_registry.get(badge_id)
        if not record:
            return False, "Badge not registered in personnel registry."
        if record.get("role") == "SYSTEM_ADMIN":
            return False, "Cannot assign geofence post to system administrator."

        role = record.get("role", "FIELD_OFFICER")
        if role == "SUPERVISOR":
            ok, msg = self.assign_post_supervisor(resolved, badge_id)
            if not ok:
                return False, msg
            return True, f"Supervisor {badge_id} assigned to field {resolved}."

        self.personnel_registry.upsert(
            badge_id,
            record.get("full_name", badge_id),
            role=role,
            post_id=resolved,
        )
        return True, f"Officer {badge_id} assigned to {resolved}."

    def assign_officer_post_scoped(
        self,
        requester_badge: str,
        target_badge: str,
        post_id: str,
    ) -> tuple[bool, str]:
        requester = self.personnel_registry.get(requester_badge)
        if not requester or requester.get("role") != "SUPERVISOR":
            return False, "Only post supervisors can assign officers within their field."

        supervisor_post = requester.get("post_id") or self.post_registry.find_post_for_supervisor(
            requester_badge
        )
        if not supervisor_post:
            return False, "Supervisor is not linked to a deployment field."

        resolved = self.post_registry.resolve(post_id)
        if resolved != supervisor_post:
            return False, f"Supervisors may only assign officers to {supervisor_post}."

        target = self.personnel_registry.get(target_badge)
        if not target:
            return False, "Target badge not registered."
        if target.get("role") != "FIELD_OFFICER":
            return False, "Supervisors can only assign field officers."

        return self.assign_officer_post(target_badge, post_id)

    def assign_post_supervisor(
        self,
        post_id: str,
        supervisor_badge_id: str | None,
    ) -> tuple[bool, str]:
        resolved = self.post_registry.resolve(post_id)
        if not resolved:
            return False, f"Post '{post_id}' is not a registered deployment field."

        if not supervisor_badge_id:
            self.post_registry.set_supervisor(resolved, None)
            return True, f"Supervisor removed from {resolved}."

        badge = str(supervisor_badge_id).strip()
        record = self.personnel_registry.get(badge)
        if not record:
            return False, "Supervisor badge not found in personnel registry."
        if record.get("role") != "SUPERVISOR":
            return False, "Assigned person must have SUPERVISOR role. Enroll or update role first."

        self.post_registry.clear_supervisor_badge(badge)
        self.post_registry.set_supervisor(resolved, badge)
        self.personnel_registry.upsert(
            badge,
            record.get("full_name", badge),
            role="SUPERVISOR",
            post_id=resolved,
        )
        return True, f"Supervisor {badge} assigned to field {resolved}."

    def list_posts_with_roster(self) -> list[dict]:
        posts = self.post_registry.list_for_api()
        personnel = self.personnel_registry.list_active()
        by_post: dict[str, list] = {}
        for person in personnel:
            pid = person.get("post_id")
            if pid:
                by_post.setdefault(pid, []).append(person)

        result = []
        for post_id, meta in sorted(posts.items()):
            sup_badge = meta.get("supervisor_badge_id")
            sup_name = None
            if sup_badge:
                sup = self.personnel_registry.get(sup_badge)
                sup_name = sup.get("full_name") if sup else sup_badge
            roster = by_post.get(post_id, [])
            officers = [p for p in roster if p.get("role") == "FIELD_OFFICER"]
            result.append({
                "post_id": post_id,
                "label": meta.get("label", post_id),
                "latitude": meta.get("latitude"),
                "longitude": meta.get("longitude"),
                "radius_meters": meta.get("radius_meters"),
                "supervisor_badge_id": sup_badge,
                "supervisor_name": sup_name,
                "officer_count": len(officers),
                "has_supervisor": bool(sup_badge),
            })
        return result

    def list_assigned_posts(self):
        """Returns registered deployment posts for client configuration."""
        return self.post_registry.list_for_api()

    def upsert_deployment_post(
        self,
        post_id: str,
        latitude: float,
        longitude: float,
        label: str | None = None,
    ) -> tuple[bool, str, str | None]:
        return self.post_registry.upsert_post(post_id, latitude, longitude, label)

    def build_operations_map(self, officer_positions: list[dict]) -> dict:
        """Merge deployment posts with officer positions (duty heartbeat preferred)."""
        posts = self.post_registry.list_for_api()
        personnel_by_badge = {
            p["badge_id"]: p
            for p in self.personnel_registry.list_active()
            if p.get("badge_id")
        }

        by_badge: dict[str, dict] = {}
        for row in officer_positions:
            badge = row.get("badge_id")
            if not badge:
                continue
            existing = by_badge.get(badge)
            if existing is None or row.get("source") == "duty_heartbeat":
                by_badge[badge] = row

        officers = []
        for badge, row in by_badge.items():
            profile = personnel_by_badge.get(badge, {})
            assigned = profile.get("post_id") or row.get("post_id")
            lat = row.get("latitude")
            lon = row.get("longitude")
            inside = row.get("inside_geofence")
            distance_m = row.get("distance_meters")
            if assigned and lat is not None and lon is not None and inside is None:
                inside, distance_m, _ = self.evaluate_geofence(
                    float(lat), float(lon), assigned
                )
            officers.append({
                "badge_id": badge,
                "full_name": profile.get("full_name", badge),
                "role": profile.get("role", "FIELD_OFFICER"),
                "assigned_post_id": assigned,
                "latitude": lat,
                "longitude": lon,
                "last_seen_at": row.get("timestamp"),
                "position_source": row.get("source", "check_in"),
                "on_duty": row.get("on_duty", row.get("source") == "duty_heartbeat"),
                "inside_geofence": inside,
                "distance_meters": round(distance_m, 1)
                if isinstance(distance_m, (int, float))
                else distance_m,
            })

        return {
            "posts": posts,
            "officers": officers,
            "geofence_radius_meters": self.post_registry.radius_meters,
            "geofence_radius_feet": round(self.post_registry.radius_meters * 3.28084),
        }
