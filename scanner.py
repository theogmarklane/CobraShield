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
        for path in paths:
            summary.scanned_files += self._scan_path(path, summary)
        return summary

    def _scan_path(self, path: Path, summary: ScanSummary) -> int:
        if path.is_file():
            summary.detections.extend(self.scan_file(path))
            return 1

        scanned_files = 0
        for current_root, directories, files in os.walk(path, onerror=lambda _: None):
            current_path = Path(current_root)
            directories[:] = [
                item
                for item in directories
                if self._is_accessible(current_path / item, summary)
            ]

            for file_name in files:
                file_path = current_path / file_name
                if not self._is_accessible(file_path, summary):
                    continue
                summary.detections.extend(self.scan_file(file_path))
                scanned_files += 1

        if scanned_files == 0 and not self._is_accessible(path, summary):
            return 0
        return scanned_files

    @staticmethod
    def _is_accessible(path: Path, summary: ScanSummary) -> bool:
        try:
            path.stat()
            return True
        except (PermissionError, OSError):
            if path not in summary.inaccessible_paths:
                summary.inaccessible_paths.append(path)
            return False


def get_system_scan_roots() -> list[Path]:
    if os.name == "nt":
        roots: list[Path] = []
        for drive_code in range(ord("A"), ord("Z") + 1):
            candidate = Path(f"{chr(drive_code)}:/")
            if candidate.exists():
                roots.append(candidate)
        return roots or [Path("C:/")]

    return [Path("/")]
