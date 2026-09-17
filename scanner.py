from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
import os


@dataclass
class Detection:
    file_path: Path
    signature_name: str


@dataclass
class ScanSummary:
    scanned_files: int = 0
    inaccessible_paths: list[Path] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)


class MalwareScanner:
    """Signature-based malware scanner that can run across full system roots."""

    SIGNATURES: dict[str, bytes] = {
        "EICAR-Test-File": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    }

    VIRTUAL_DIRS: set[Path] = {
        Path("/proc"),
        Path("/sys"),
        Path("/dev"),
        Path("/run"),
    }

    def __init__(self, signatures: dict[str, bytes] | None = None) -> None:
        self.signatures = signatures or self.SIGNATURES

    def scan_file(self, path: Path) -> list[Detection]:
        if not path.is_file():
            return []

        try:
            data = path.read_bytes()
        except (PermissionError, OSError):
            return []

        detections: list[Detection] = []
        normalized_data = data.lower()
        for signature_name, signature_bytes in self.signatures.items():
            if signature_bytes.lower() in normalized_data:
                detections.append(Detection(file_path=path, signature_name=signature_name))

        return detections

    def scan_paths(self, paths: Iterable[Path]) -> ScanSummary:
        summary = ScanSummary()
        normalized_paths = self._normalize_roots(paths)
        for path in normalized_paths:
            summary.scanned_files += self._scan_path(path, summary)
        return summary

    @staticmethod
    def _normalize_roots(paths: Iterable[Path]) -> list[Path]:
        resolved: list[Path] = []
        for p in sorted((Path(p).resolve() for p in paths), key=lambda x: len(x.parts)):
            if not any(r == p or r in p.parents for r in resolved):
                resolved.append(p)
        return resolved

    def _scan_path(self, path: Path, summary: ScanSummary) -> int:
        if path.is_file():
            if self._is_virtual_dir(path):
                return 0
            summary.detections.extend(self.scan_file(path))
            return 1

        scanned_files = 0
        for current_root, directories, files in os.walk(path, onerror=lambda _: None):
            current_path = Path(current_root)
            directories[:] = [
                item
                for item in directories
                if not self._is_virtual_dir(current_path / item)
                and self._is_accessible(current_path / item, summary)
            ]

            for file_name in files:
                file_path = current_path / file_name
                if self._is_virtual_dir(file_path):
                    continue
                if not self._is_accessible(file_path, summary):
                    continue
                summary.detections.extend(self.scan_file(file_path))
                scanned_files += 1

        if scanned_files == 0 and not self._is_accessible(path, summary):
            return 0
        return scanned_files

    @classmethod
    def _is_virtual_dir(cls, path: Path) -> bool:
        if os.name != "posix":
            return False
        try:
            resolved = path.resolve()
        except (PermissionError, OSError):
            resolved = path
        return any(v_dir == resolved or v_dir in resolved.parents for v_dir in cls.VIRTUAL_DIRS)

    @staticmethod
    def _is_accessible(path: Path, summary: ScanSummary) -> bool:
        try:
            path.stat()
            return True
        except (PermissionError, OSError):
            if path not in summary.inaccessible_paths:
                summary.inaccessible_paths.append(path)
            return False


def is_chromebook() -> bool:
    """Detect if the system is running on ChromeOS / Chromebook (including Crostini Linux container)."""
    if os.name != "posix":
        return False

    # Check for ChromeOS / Crostini / Chromium OS in system release files
    for os_file in (Path("/etc/lsb-release"), Path("/etc/os-release")):
        if os_file.exists():
            try:
                content = os_file.read_text(encoding="utf-8", errors="ignore").lower()
                if any(k in content for k in ("chromeos", "chromiumos", "cros")):
                    return True
            except OSError:
                pass

    # Check /proc/version
    proc_version = Path("/proc/version")
    if proc_version.exists():
        try:
            content = proc_version.read_text(encoding="utf-8", errors="ignore").lower()
            if "chrome-bot" in content or "chromeos" in content:
                return True
        except OSError:
            pass

    # Check for Chromebook mount points or devices
    cros_paths = (
        Path("/mnt/chromeos"),
        Path("/dev/cros_ec"),
        Path("/dev/cros_fp"),
    )
    if any(p.exists() for p in cros_paths):
        return True

    # Check environment variables
    cros_envs = ("CHROMEOS_INSIDE_CONTAINER", "CROS_USER", "CROS_BOARD", "CONTAINER_TYPE")
    for env in cros_envs:
        val = os.environ.get(env, "").lower()
        if "cros" in val or "chrome" in val or env in os.environ:
            return True

    return False


def get_system_scan_roots() -> list[Path]:
    if os.name == "nt":
        roots: list[Path] = []
        for drive_code in range(ord("A"), ord("Z") + 1):
            candidate = Path(f"{chr(drive_code)}:/")
            if candidate.exists():
                roots.append(candidate)
        return roots or [Path("C:/")]

    roots: list[Path] = [Path("/")]

    if is_chromebook():
        chromebook_roots = [
            Path("/mnt/chromeos"),
            Path("/mnt/chromeos/MyFiles"),
            Path("/mnt/chromeos/GoogleDrive"),
            Path("/mnt/chromeos/removable"),
            Path("/mnt/chromeos/PlayFiles"),
            Path("/mnt/shared"),
            Path("/media/fuse"),
            Path("/home/chronos"),
        ]
        for cb_root in chromebook_roots:
            if cb_root.exists() and cb_root not in roots:
                roots.append(cb_root)

    return roots
