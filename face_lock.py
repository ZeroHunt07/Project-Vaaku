#!/usr/bin/env python3
"""
face_lock.py — Webcam Presence & Facial Recognition Auto-Lock for Project-Vaaku.

Features:
- Periodic webcam capture (default: every 15 seconds).
- Deep-learning face detection (YuNet) and recognition (SFace) via OpenCV.
- Enforces "ONLY authorized user's face" policy:
    * Continues if and only if every detected face is recognized.
    * Locks the PC if no face is detected (user walked away).
    * Locks the PC if any detected face is not recognized.
- Multi-platform screen locking (Linux GNOME/Wayland/X11/KDE, Windows, macOS).
- Enrollment tool: register user face from live webcam or existing photos.
"""

import os
import sys
import time
import shutil
import logging
import platform
import argparse
import subprocess
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = None
    np = None

logger = logging.getLogger("face_lock")

# Default model download URLs (OpenCV Zoo)
YUNET_URLS = [
    "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
    "https://raw.githubusercontent.com/opencv/opencv_zoo/master/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
]
SFACE_URLS = [
    "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
    "https://raw.githubusercontent.com/opencv/opencv_zoo/master/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
]


def lock_workstation() -> Tuple[bool, str]:
    """
    Lock the workstation across various platforms (Linux, Windows, macOS).
    Returns (success: bool, method_or_error: str).
    """
    system = platform.system().lower()

    if system == "linux":
        # 1. loginctl (systemd standard - works on Wayland & X11)
        if shutil.which("loginctl"):
            try:
                res = subprocess.run(
                    ["loginctl", "lock-session"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                if res.returncode == 0:
                    return True, "loginctl lock-session"
            except Exception as e:
                logger.debug(f"loginctl failed: {e}")

        # 2. GNOME ScreenSaver via D-Bus
        try:
            res = subprocess.run(
                [
                    "dbus-send",
                    "--type=method_call",
                    "--dest=org.gnome.ScreenSaver",
                    "/org/gnome/ScreenSaver",
                    "org.gnome.ScreenSaver.Lock",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            if res.returncode == 0:
                return True, "dbus org.gnome.ScreenSaver"
        except Exception as e:
            logger.debug(f"gnome dbus lock failed: {e}")

        # 3. Freedesktop ScreenSaver via D-Bus
        try:
            res = subprocess.run(
                [
                    "dbus-send",
                    "--type=method_call",
                    "--dest=org.freedesktop.ScreenSaver",
                    "/org/freedesktop/ScreenSaver",
                    "org.freedesktop.ScreenSaver.Lock",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            if res.returncode == 0:
                return True, "dbus org.freedesktop.ScreenSaver"
        except Exception as e:
            logger.debug(f"freedesktop dbus lock failed: {e}")

        # 4. xdg-screensaver
        if shutil.which("xdg-screensaver"):
            try:
                res = subprocess.run(
                    ["xdg-screensaver", "lock"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                if res.returncode == 0:
                    return True, "xdg-screensaver lock"
            except Exception as e:
                logger.debug(f"xdg-screensaver failed: {e}")

        # 5. gnome-screensaver-command
        if shutil.which("gnome-screensaver-command"):
            try:
                res = subprocess.run(
                    ["gnome-screensaver-command", "-l"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                if res.returncode == 0:
                    return True, "gnome-screensaver-command -l"
            except Exception as e:
                logger.debug(f"gnome-screensaver-command failed: {e}")

        # 6. KDE Screenlocker
        if shutil.which("qdbus"):
            try:
                res = subprocess.run(
                    ["qdbus", "org.kde.kscreenlocker", "/MainApplication", "lock"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                if res.returncode == 0:
                    return True, "qdbus org.kde.kscreenlocker"
            except Exception as e:
                logger.debug(f"qdbus failed: {e}")

        # 7. Common window manager lockers
        for locker in ["xflock4", "swaylock", "i3lock", "slock"]:
            if shutil.which(locker):
                try:
                    subprocess.Popen([locker])
                    return True, locker
                except Exception as e:
                    logger.debug(f"{locker} failed: {e}")

        return False, "No working Linux screen locker found"

    elif system == "windows":
        try:
            import ctypes
            if ctypes.windll.user32.LockWorkStation():
                return True, "LockWorkStation"
            return False, "LockWorkStation returned failure"
        except Exception as e:
            return False, f"Windows lock error: {e}"

    elif system == "darwin":
        try:
            cgsession = "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession"
            if os.path.isfile(cgsession):
                res = subprocess.run(
                    [cgsession, "-suspend"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                if res.returncode == 0:
                    return True, "CGSession -suspend"
        except (OSError, subprocess.SubprocessError) as e:
            logger.debug(f"CGSession lock failed: {e}")
        try:
            res = subprocess.run(
                [
                    "osascript",
                    "-e",
                    'tell application "System Events" to keystroke "q" '
                    "using {control down, command down}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            if res.returncode == 0:
                return True, "macOS Control-Command-Q"
            return False, res.stderr.decode(errors="replace").strip() or \
                "macOS lock shortcut failed"
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"macOS lock error: {e}"

    return False, f"Unsupported OS: {system}"


def send_desktop_notification(title: str, message: str):
    """Send a desktop notification using notify-send if available."""
    if shutil.which("notify-send"):
        try:
            subprocess.run(
                ["notify-send", "-u", "critical", "-a", "Project-Vaaku", title, message],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
        except Exception:
            pass


class FaceSecurityEngine:
    """
    Handles face detection (YuNet) and face recognition / feature extraction (SFace).
    """

    def __init__(
        self,
        models_dir: str = "models",
        faces_dir: str = "faces",
        similarity_threshold: float = 0.363,
        score_threshold: float = 0.6,
        nms_threshold: float = 0.3,
    ):
        if cv2 is None or np is None:
            raise RuntimeError(
                "OpenCV and NumPy are required for FaceSecurityEngine. "
                "Please run: pip install opencv-python numpy"
            )

        self.models_dir = Path(models_dir)
        self.faces_dir = Path(faces_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.faces_dir.mkdir(parents=True, exist_ok=True)

        self.similarity_threshold = float(similarity_threshold)
        self.score_threshold = float(score_threshold)
        self.nms_threshold = float(nms_threshold)

        self.yunet_model_path = self.models_dir / "face_detection_yunet_2023mar.onnx"
        self.sface_model_path = self.models_dir / "face_recognition_sface_2021dec.onnx"

        self._ensure_models()

        self.detector = cv2.FaceDetectorYN.create(
            model=str(self.yunet_model_path),
            config="",
            input_size=(320, 320),
            score_threshold=self.score_threshold,
            nms_threshold=self.nms_threshold,
            top_k=5000,
        )

        self.recognizer = cv2.FaceRecognizerSF.create(
            model=str(self.sface_model_path),
            config="",
        )

        self.enrolled_features: List[np.ndarray] = []
        self.load_enrolled_faces()

    def _ensure_models(self):
        """Download detection and recognition ONNX models if missing."""
        import urllib.request

        def download_file(urls: List[str], dest: Path):
            if dest.exists() and dest.stat().st_size > 50000:
                return
            logger.info(f"Downloading model to {dest}...")
            print(f"[FaceSecurity] Downloading model to {dest}...")
            for url in urls:
                try:
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "Project-Vaaku/1.0"}
                    )
                    with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as f:
                        shutil.copyfileobj(resp, f)
                    if dest.stat().st_size > 50000:
                        logger.info(f"Successfully downloaded {dest}")
                        return
                except Exception as e:
                    logger.warning(f"Download failed from {url}: {e}")
            raise RuntimeError(f"Could not download model {dest.name}. Check internet connection.")

        download_file(YUNET_URLS, self.yunet_model_path)
        download_file(SFACE_URLS, self.sface_model_path)

    def load_enrolled_faces(self) -> int:
        """Load enrolled face embeddings from profile and images in faces_dir."""
        self.enrolled_features.clear()

        # 1. Check user_profile.npz
        profile_path = self.faces_dir / "user_profile.npz"
        if profile_path.exists():
            try:
                data = np.load(str(profile_path))
                if "embeddings" in data:
                    embeddings = data["embeddings"]
                    for emb in embeddings:
                        self.enrolled_features.append(emb.reshape(1, -1).astype(np.float32))
            except Exception as e:
                logger.error(f"Failed to load {profile_path}: {e}")

        # 2. Check any individual image files in faces_dir (e.g. .jpg, .png)
        valid_exts = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
        for img_path in sorted(self.faces_dir.iterdir()):
            if (img_path.suffix.lower() in valid_exts
                    and not img_path.name.startswith(("sample_", "imported_"))):
                emb = self.extract_feature_from_image_path(str(img_path))
                if emb is not None:
                    self.enrolled_features.append(emb)

        logger.info(f"Loaded {len(self.enrolled_features)} enrolled face embeddings.")
        return len(self.enrolled_features)

    def extract_feature_from_image_path(self, path: str) -> Optional[np.ndarray]:
        """Extract a single face embedding from an image file."""
        img = cv2.imread(path)
        if img is None:
            return None
        return self.extract_feature_from_bgr(img)

    def extract_feature_from_bgr(self, bgr_img: np.ndarray) -> Optional[np.ndarray]:
        """Detect the most prominent face and extract SFace embedding."""
        features = self.extract_features_from_bgr(bgr_img)
        return features[0] if features else None

    def extract_features_from_bgr(self, bgr_img: np.ndarray) -> List[np.ndarray]:
        """Extract embeddings for every confidently detected face in an image."""
        h, w = bgr_img.shape[:2]
        self.detector.setInputSize((w, h))
        _, faces = self.detector.detect(bgr_img)
        if faces is None or len(faces) == 0:
            return []
        ordered_faces = sorted(faces, key=lambda face: face[14], reverse=True)
        features = []
        for face in ordered_faces:
            if face[14] < self.score_threshold:
                continue
            aligned = self.recognizer.alignCrop(bgr_img, face)
            features.append(self.recognizer.feature(aligned))
        return features

    def enroll_from_frame(self, frame: np.ndarray, save_sample_num: Optional[int] = None) -> bool:
        """Enroll a face from a BGR video frame."""
        h, w = frame.shape[:2]
        self.detector.setInputSize((w, h))
        _, faces = self.detector.detect(frame)
        if faces is None or len(faces) != 1:
            return False

        face = faces[0]
        score = face[14]
        if score < self.score_threshold:
            return False

        aligned = self.recognizer.alignCrop(frame, face)
        feature = self.recognizer.feature(aligned)
        self.enrolled_features.append(feature)

        if save_sample_num is not None:
            sample_path = self.faces_dir / f"sample_{save_sample_num}.jpg"
            cv2.imwrite(str(sample_path), frame, [cv2.IMWRITE_JPEG_QUALITY, 95])

        self.save_profile()
        return True

    def save_profile(self):
        """Save current enrolled features into user_profile.npz."""
        if not self.enrolled_features:
            return
        matrix = np.vstack(self.enrolled_features)
        profile_path = self.faces_dir / "user_profile.npz"
        np.savez_compressed(str(profile_path), embeddings=matrix)
        logger.info(f"Saved {len(self.enrolled_features)} embeddings to {profile_path}")

    def verify_frame(self, frame: np.ndarray) -> Dict[str, Any]:
        """
        Verify that every face in the frame matches an enrolled face.

        Returns a dictionary:
        {
            "status": "AUTHORIZED" | "NO_FACE" | "MULTIPLE_FACES" | "UNAUTHORIZED_FACE" | "NO_ENROLLED_USER",
            "allow": bool,
            "face_count": int,
            "best_similarity": float,
            "reason": str
        }
        """
        if len(self.enrolled_features) == 0:
            return {
                "status": "NO_ENROLLED_USER",
                "allow": False,
                "face_count": 0,
                "best_similarity": 0.0,
                "reason": "No authorized user face is enrolled. Please run face enrollment first.",
            }

        h, w = frame.shape[:2]
        self.detector.setInputSize((w, h))
        _, faces = self.detector.detect(frame)

        if faces is None or len(faces) == 0:
            return {
                "status": "NO_FACE",
                "allow": False,
                "face_count": 0,
                "best_similarity": 0.0,
                "reason": "No face detected in camera view (user absent)",
            }

        face_similarities = []
        for face_index, face in enumerate(faces, start=1):
            aligned = self.recognizer.alignCrop(frame, face)
            feature = self.recognizer.feature(aligned)

            best_sim = max(
                float(
                    self.recognizer.match(
                        feature, ref_feat, cv2.FaceRecognizerSF_FR_COSINE
                    )
                )
                for ref_feat in self.enrolled_features
            )
            face_similarities.append({
                "face_index": face_index,
                "best_similarity": round(best_sim, 4),
                "recognized": best_sim >= self.similarity_threshold,
            })

        face_count = len(face_similarities)
        minimum_similarity = min(
            item["best_similarity"] for item in face_similarities
        )
        unrecognized_faces = [
            item for item in face_similarities if not item["recognized"]
        ]
        if not unrecognized_faces:
            if face_count > 1:
                reason = f"All {face_count} detected faces were recognized."
            else:
                similarity = face_similarities[0]["best_similarity"]
                reason = (
                    f"Authorized user verified (similarity {similarity:.3f} "
                    f">= {self.similarity_threshold:.3f})"
                )
            return {
                "status": "AUTHORIZED",
                "allow": True,
                "face_count": face_count,
                "best_similarity": minimum_similarity,
                "face_similarities": face_similarities,
                "reason": reason,
            }

        if face_count > 1:
            indices = ", ".join(
                str(item["face_index"]) for item in unrecognized_faces
            )
            status = "MULTIPLE_FACES"
            reason = (
                f"{len(unrecognized_faces)} of {face_count} detected faces "
                f"were not recognized (face(s) {indices}); locking required."
            )
        else:
            status = "UNAUTHORIZED_FACE"
            reason = (
                "Unauthorized face detected "
                f"(similarity {minimum_similarity:.3f} "
                f"< {self.similarity_threshold:.3f})"
            )
        return {
            "status": status,
            "allow": False,
            "face_count": face_count,
            "best_similarity": minimum_similarity,
            "face_similarities": face_similarities,
            "reason": reason,
        }


class FaceLockWatcher:
    """
    Periodic background loop that captures a webcam frame every N seconds (default 15s)
    and locks the workstation if the enrolled user is not solely recognized.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        event_callback: Optional[Any] = None,
    ):
        raw_cfg = config or {}
        face_cfg = raw_cfg.get("face_lock", {})

        self.enabled = bool(face_cfg.get("enabled", True))
        self.interval_seconds = float(face_cfg.get("interval_seconds", 15.0))
        self.similarity_threshold = float(face_cfg.get("similarity_threshold", 0.363))
        self.consecutive_failures_to_lock = int(face_cfg.get("consecutive_failures_to_lock", 1))
        self.camera_index = int(face_cfg.get("camera_index", raw_cfg.get("camera_index", 0)))
        self.camera_width = int(face_cfg.get("camera_width", raw_cfg.get("camera_width", 640)))
        self.camera_height = int(face_cfg.get("camera_height", raw_cfg.get("camera_height", 480)))
        self.warmup_frames = int(face_cfg.get("camera_warmup_frames", 3))
        self.notify_on_lock = bool(face_cfg.get("notify_on_lock", True))

        models_dir = face_cfg.get("models_dir", "models")
        faces_dir = face_cfg.get("faces_dir", "faces")

        self.engine = FaceSecurityEngine(
            models_dir=models_dir,
            faces_dir=faces_dir,
            similarity_threshold=self.similarity_threshold,
        )

        self.event_callback = event_callback
        self.running = False
        self.consecutive_failures = 0
        self.lock_cooldown_until = 0.0

    def capture_frame(self) -> Optional[np.ndarray]:
        """
        Open webcam briefly, grab frame, and release camera immediately.
        This keeps the camera privacy LED off between checks.
        """
        try:
            cap = cv2.VideoCapture(self.camera_index)
            if not cap.isOpened():
                logger.warning(f"Could not open camera index {self.camera_index}")
                return None

            cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.camera_width)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.camera_height)

            # Warmup frames for auto-exposure
            for _ in range(max(1, self.warmup_frames)):
                cap.grab()

            ok, frame = cap.read()
            cap.release()

            if ok and frame is not None:
                return frame
            return None
        except Exception as e:
            logger.error(f"Error capturing frame: {e}")
            return None

    def _capture_verification_result(self) -> Dict[str, Any]:
        frame = self.capture_frame()
        if frame is None:
            return {
                "status": "CAMERA_ERROR",
                "allow": False,
                "face_count": 0,
                "best_similarity": 0.0,
                "reason": "Failed to read from webcam",
            }
        return self.engine.verify_frame(frame)

    def _adaptive_warning_seconds(self, result: Dict[str, Any]) -> int:
        status = result["status"]
        if status == "UNAUTHORIZED_FACE":
            similarity = float(result.get("best_similarity", 0.0))
            difference = self.similarity_threshold - similarity
            if difference <= 0.05:
                return 12
            if difference <= 0.15:
                return 8
            return 4
        if status == "MULTIPLE_FACES":
            return 5
        if status in {"NO_FACE", "CAMERA_ERROR"}:
            return 10
        return 8

    @staticmethod
    def _warning_reason(result: Dict[str, Any]) -> str:
        status = result["status"]
        if status == "UNAUTHORIZED_FACE":
            return "The enrolled ZeroHunt face was not recognized."
        if status == "MULTIPLE_FACES":
            return "One or more faces were not recognized."
        if status == "NO_FACE":
            return "No face is visible to the camera."
        if status == "CAMERA_ERROR":
            return "The camera did not respond."
        return "The enrolled ZeroHunt face could not be verified."

    def _wait_for_recognition(
        self,
        result: Dict[str, Any],
        warning_seconds: int,
    ) -> Dict[str, Any]:
        if self.notify_on_lock:
            send_desktop_notification(
                "Vaaku face lock warning",
                f"{self._warning_reason(result)} Look at the camera to prevent locking.",
            )

        deadline = time.monotonic() + warning_seconds
        next_check = time.monotonic() + 1.0
        latest_result = result

        try:
            import tkinter as tk
        except ImportError as error:
            logger.warning("Full-screen face-lock warning unavailable: %s", error)
            return self._wait_without_warning_window(
                latest_result, deadline, next_check
            )

        root = None
        try:
            root = tk.Tk()
            root.title("Vaaku Face Lock")
            root.configure(bg="#7f0000")
            root.attributes("-fullscreen", True)
            root.attributes("-topmost", True)
            root.protocol("WM_DELETE_WINDOW", lambda: None)
            root.bind("<Escape>", lambda _event: "break")

            message = tk.Label(
                root,
                text="LOCKING THIS DEVICE",
                font=("Arial", 42, "bold"),
                fg="white",
                bg="#7f0000",
            )
            message.pack(expand=True, pady=(80, 10))
            reason_label = tk.Label(
                root,
                text=self._warning_reason(latest_result),
                font=("Arial", 24),
                fg="white",
                bg="#7f0000",
                wraplength=1200,
            )
            reason_label.pack(pady=20)
            countdown_label = tk.Label(
                root,
                text="",
                font=("Arial", 32, "bold"),
                fg="white",
                bg="#7f0000",
            )
            countdown_label.pack(expand=True, pady=20)
            instruction = tk.Label(
                root,
                text="Look at the camera now. Locking is cancelled if your enrolled face is recognized.",
                font=("Arial", 18),
                fg="white",
                bg="#7f0000",
                wraplength=1400,
            )
            instruction.pack(expand=True, pady=(10, 80))

            def update_warning() -> None:
                nonlocal latest_result, next_check

                if not self.enabled:
                    root.destroy()
                    return

                remaining = max(0, int(deadline - time.monotonic() + 0.999))
                if remaining == 0:
                    root.destroy()
                    return

                countdown_label.configure(
                    text=f"Locking in {remaining} second"
                    f"{'s' if remaining != 1 else ''}"
                )
                now = time.monotonic()
                if now >= next_check:
                    latest_result = self._capture_verification_result()
                    if latest_result["allow"]:
                        root.destroy()
                        return
                    reason_label.configure(
                        text=self._warning_reason(latest_result)
                    )
                    next_check = now + 1.5

                root.after(250, update_warning)

            root.after(0, update_warning)
            root.mainloop()
            return latest_result
        except (tk.TclError, OSError, RuntimeError) as error:
            if root is not None:
                try:
                    root.destroy()
                except tk.TclError as cleanup_error:
                    logger.debug(
                        "Could not close the incomplete warning window: %s",
                        cleanup_error,
                    )
            logger.warning(
                "Full-screen face-lock warning could not be shown: %s", error
            )
            return self._wait_without_warning_window(
                latest_result, deadline, next_check
            )

    def _wait_without_warning_window(
        self,
        latest_result: Dict[str, Any],
        deadline: float,
        next_check: float,
    ) -> Dict[str, Any]:
        while self.enabled and time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_check:
                latest_result = self._capture_verification_result()
                if latest_result["allow"]:
                    return latest_result
                next_check = now + 1.5
            time.sleep(min(0.25, max(0.0, deadline - now)))
        return latest_result

    def _record_verified(self, result: Dict[str, Any]) -> None:
        self.consecutive_failures = 0
        if self.event_callback:
            try:
                self.event_callback(
                    "face_lock",
                    "agent",
                    {
                        "action": "verified",
                        "status": result["status"],
                        "similarity": result["best_similarity"],
                        "face_count": result["face_count"],
                        "reason": result["reason"],
                    },
                )
            except Exception as error:
                logger.error("Face-lock verification callback error: %s", error)

    def trigger_lock(self, reason: str, details: Dict[str, Any]):
        """Lock workstation and emit notification & audit log."""
        if self.notify_on_lock:
            send_desktop_notification(
                "Security Alert: Locking PC",
                f"Vaaku Face-Lock: {reason}"
            )

        success, method = lock_workstation()
        logger.warning(f"WORKSTATION LOCKED: {reason} (via {method}, success={success})")

        if self.event_callback:
            try:
                self.event_callback(
                    "face_lock",
                    "security",
                    {
                        "action": "locked",
                        "reason": reason,
                        "lock_method": method,
                        "lock_success": success,
                        **details,
                    },
                )
            except Exception as e:
                logger.error(f"Callback error: {e}")

        # Set a cooldown of 20 seconds so we don't spam lock commands while already locked
        self.lock_cooldown_until = time.time() + 20.0

    def check_once(self) -> Dict[str, Any]:
        """Perform a single webcam capture and face verification check."""
        result = self._capture_verification_result()

        if not self.enabled:
            return result

        if result["allow"]:
            self._record_verified(result)
        else:
            self.consecutive_failures += 1
            logger.info(
                f"Face check failed ({self.consecutive_failures}/{self.consecutive_failures_to_lock}): "
                f"{result['reason']}"
            )

            # If user has not enrolled a face yet, notify instead of permanent lock trap
            if result["status"] == "NO_ENROLLED_USER":
                logger.warning(result["reason"])
                if self.event_callback:
                    self.event_callback("face_lock", "agent", result)
                return result

            if (self.enabled
                    and self.consecutive_failures >= self.consecutive_failures_to_lock):
                now = time.time()
                if now >= self.lock_cooldown_until:
                    warning_seconds = self._adaptive_warning_seconds(result)
                    logger.warning(
                        "Face lock warning started (%ss): %s",
                        warning_seconds,
                        self._warning_reason(result),
                    )
                    result = self._wait_for_recognition(result, warning_seconds)
                    if result["allow"]:
                        self._record_verified(result)
                    elif self.enabled:
                        self.trigger_lock(result["reason"], result)

        return result

    def run_loop(self):
        """Continuous monitor loop running every interval_seconds."""
        self.running = True
        logger.info(
            f"Face-Lock Watcher started (interval: {self.interval_seconds}s, "
            f"threshold: {self.similarity_threshold})"
        )
        print(
            f"[FaceLock] Active — checking webcam every {self.interval_seconds}s. "
            f"Will lock if not only your face is present."
        )

        while self.running:
            if self.enabled:
                try:
                    self.check_once()
                except Exception as e:
                    logger.error(f"Error in face check cycle: {e}")

            # Sleep in small increments for responsive shutdown
            slept = 0.0
            step = 0.5
            while self.running and slept < self.interval_seconds:
                time.sleep(step)
                slept += step

    def stop(self):
        """Stop the background loop."""
        self.running = False


# ============================================================================
# CLI Face Enrollment & Standalone Testing
# ============================================================================

def interactive_enrollment(
    camera_index: int = 0,
    faces_dir: str = "faces",
    models_dir: str = "models",
    samples_needed: int = 4,
):
    """Guide the user to register their face using the webcam."""
    print("=" * 65)
    print(" PROJECT-VAAKU: SECURE FACE ENROLLMENT")
    print("=" * 65)
    print("Enroll one or more authorized users. Capture one person at a time.")
    print("Look at the camera. We will capture a few reference samples.")
    print("-" * 65)

    if samples_needed < 1:
        print("[!] At least one sample is required.")
        return False

    engine = FaceSecurityEngine(models_dir=models_dir, faces_dir=faces_dir)

    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        print(f"[!] Error: Could not open camera {camera_index}.")
        return False

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    samples_collected = 0
    instructions = [
        "Look straight at the camera.",
        "Turn your head very slightly to the right.",
        "Turn your head very slightly to the left.",
        "Smile slightly or tilt your head up slightly.",
    ]
    sample_numbers = []
    for sample_path in engine.faces_dir.glob("sample_*.jpg"):
        try:
            sample_numbers.append(int(sample_path.stem.removeprefix("sample_")))
        except ValueError:
            continue
    next_sample_num = max(sample_numbers, default=0) + 1

    try:
        for idx in range(samples_needed):
            prompt = (instructions[idx] if idx < len(instructions)
                      else "Adjust your angle or expression.")
            print(f"\n--> Sample {idx + 1}/{samples_needed}: {prompt}")
            time.sleep(1.5)

            # Capture multiple frames and pick a valid face frame
            captured = False
            for attempt in range(15):
                ok, frame = cap.read()
                if not ok or frame is None:
                    time.sleep(0.1)
                    continue

                if engine.enroll_from_frame(
                        frame, save_sample_num=next_sample_num + samples_collected):
                    samples_collected += 1
                    print(f"    [+] Sample {samples_collected} captured successfully!")
                    captured = True
                    time.sleep(0.5)
                    break
                time.sleep(0.2)

            if not captured:
                print("    [-] Could not detect a clear single face for this sample. Retrying...")

        if samples_collected > 0:
            engine.save_profile()
            print("\n" + "=" * 65)
            print(f"[SUCCESS] Enrolled {samples_collected} face samples successfully!")
            print(f"Profile saved to: {Path(faces_dir).resolve() / 'user_profile.npz'}")
            print("=" * 65)
            return True
        else:
            print("\n[!] Failed to enroll any face samples. Make sure lighting is good and camera is uncovered.")
            return False
    finally:
        cap.release()


def enroll_from_image_file(
    image_path: str,
    faces_dir: str = "faces",
    models_dir: str = "models",
):
    """Enroll a user face from an existing photo file."""
    path = Path(image_path).expanduser().resolve()
    if not path.exists():
        print(f"[!] Image file not found: {path}")
        return False

    print(f"Enrolling face from: {path}")
    engine = FaceSecurityEngine(models_dir=models_dir, faces_dir=faces_dir)
    img = cv2.imread(str(path))
    if img is None:
        print("[!] Could not read image.")
        return False

    features = engine.extract_features_from_bgr(img)
    if not features:
        print("[!] No clear face found in image.")
        return False

    engine.enrolled_features.extend(features)
    sample_dest = Path(faces_dir) / f"imported_{path.name}"
    shutil.copyfile(str(path), str(sample_dest))
    engine.save_profile()
    print(f"[SUCCESS] Enrolled {len(features)} face(s) from {path.name} into "
          f"{faces_dir}/user_profile.npz")
    return True


def run_standalone_test(
    camera_index: int = 0,
    interval: float = 5.0,
    dry_run: bool = True,
):
    """Run a test mode where face verification is displayed live without locking unless dry_run=False."""
    print(f"[FaceLock Test] Starting test loop (camera: {camera_index}, dry_run: {dry_run})...")
    watcher = FaceLockWatcher(
        config={
            "face_lock": {
                "enabled": True,
                "interval_seconds": interval,
                "camera_index": camera_index,
            }
        }
    )

    if len(watcher.engine.enrolled_features) == 0:
        print("[!] WARNING: No enrolled faces found. Run enrollment first:")
        print("    python3 face_lock.py enroll")
        return

    print(f"Loaded {len(watcher.engine.enrolled_features)} enrolled face features.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            t0 = time.time()
            res = watcher.check_once()
            dt = time.time() - t0
            sim = res.get("best_similarity", 0.0)
            status = res.get("status", "")
            allow = res.get("allow", False)
            reason = res.get("reason", "")
            indicator = "[OK] CONTINUING" if allow else "[X] LOCK TRIGGERED"
            print(f"[{time.strftime('%H:%M:%S')}] {indicator} | Status: {status} | Sim: {sim:.3f} | {reason} ({dt:.2f}s)")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nTest stopped.")


def main():
    parser = argparse.ArgumentParser(description="Project-Vaaku Face Lock Security")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # enroll
    p_enroll = sub.add_parser("enroll", help="Enroll your face using the webcam")
    p_enroll.add_argument("--camera", type=int, default=0, help="Camera index")
    p_enroll.add_argument("--samples", type=int, default=4, help="Number of face samples")
    p_enroll.add_argument(
        "--image", action="append",
        help="Import face(s) from an image; repeat for multiple images",
    )

    # test
    p_test = sub.add_parser("test", help="Test face check once or repeatedly")
    p_test.add_argument("--camera", type=int, default=0, help="Camera index")
    p_test.add_argument("--interval", type=float, default=3.0, help="Check interval in seconds")
    p_test.add_argument("--no-dry-run", action="store_true", help="Actually lock PC on failure")

    # lock-test
    sub.add_parser("lock-test", help="Test screen locking mechanism immediately")

    # run
    p_run = sub.add_parser("run", help="Run standalone background face lock watcher")
    p_run.add_argument("--interval", type=float, default=15.0, help="Interval in seconds (default 15)")
    p_run.add_argument("--camera", type=int, default=0, help="Camera index")

    args = parser.parse_args()

    if args.cmd == "enroll":
        if args.image:
            for image_path in args.image:
                enroll_from_image_file(image_path)
        else:
            interactive_enrollment(camera_index=args.camera, samples_needed=args.samples)
    elif args.cmd == "lock-test":
        print("Testing screen lock in 3 seconds...")
        time.sleep(3)
        ok, method = lock_workstation()
        print(f"Lock result: success={ok}, method={method}")
    elif args.cmd == "test":
        run_standalone_test(
            camera_index=args.camera,
            interval=args.interval,
            dry_run=not args.no_dry_run,
        )
    elif args.cmd == "run":
        watcher = FaceLockWatcher(
            config={
                "face_lock": {
                    "enabled": True,
                    "interval_seconds": args.interval,
                    "camera_index": args.camera,
                }
            }
        )
        try:
            watcher.run_loop()
        except KeyboardInterrupt:
            watcher.stop()
            print("\nStopped Face-Lock.")


if __name__ == "__main__":
    main()
