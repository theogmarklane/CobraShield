from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable
import hashlib
import html
import json
import math
import os
import shutil
import uuid


@dataclass
class Detection:
    file_path: Path
    signature_name: str
    severity: str = "high"
    detection_type: str = "signature"
    detail: str = ""


@dataclass
class ScanSummary:
    scanned_files: int = 0
    inaccessible_paths: list[Path] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)


class MalwareScanner:
    """Signature + heuristic malware scanner that can run across full system roots."""

    SIGNATURES: dict[str, bytes] = {
        "EICAR-Test-File": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    }

    VIRTUAL_DIRS: set[Path] = {
        Path("/proc"),
        Path("/sys"),
        Path("/dev"),
        Path("/run"),
    }

    RISKY_EXECUTABLE_EXTS: set[str] = {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".msi",
        ".js", ".jse", ".vbs", ".vbe", ".ps1", ".apk", ".jar",
    }

    DOC_LIKE_EXTS: set[str] = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".gif", ".txt", ".csv", ".zip", ".rar",
    }

    ENTROPY_MIN_SIZE: int = 16 * 1024
    ENTROPY_THRESHOLD: float = 7.2

    # Formats that are legitimately high-entropy (compressed/encrypted by design).
    ENTROPY_SKIP_EXTS: set[str] = {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svgz",
        ".zip", ".gz", ".xz", ".bz2", ".7z", ".rar", ".tar", ".zst", ".lz4",
        ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".webm", ".flac", ".ogg", ".wav",
        ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".pack", ".idx", ".body", ".whl", ".class", ".pyc", ".pyo",
        ".jar", ".apk", ".dmg", ".iso", ".img",
    }

    def __init__(self, signatures: dict[str, bytes] | None = None, enable_heuristics: bool = True) -> None:
        self.signatures = signatures or self.SIGNATURES
        self.enable_heuristics = enable_heuristics

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
                detections.append(Detection(
                    file_path=path,
                    signature_name=signature_name,
                    severity="high",
                    detection_type="signature",
                    detail="Matched known malware signature",
                ))

        if self.enable_heuristics:
            detections.extend(self._run_heuristics(path, data))

        return detections

    def _run_heuristics(self, path: Path, data: bytes) -> list[Detection]:
        """Signature-free detection: catches threats no AV database knows yet."""
        results: list[Detection] = []

        suffixes = [suffix.lower() for suffix in path.suffixes]
        if (
            len(suffixes) >= 2
            and suffixes[-1] in self.RISKY_EXECUTABLE_EXTS
            and suffixes[-2] in self.DOC_LIKE_EXTS
        ):
            results.append(Detection(
                file_path=path,
                signature_name="HEUR:DoubleExtension",
                severity="high",
                detection_type="heuristic",
                detail=f"Poses as a '{suffixes[-2]}' document but is a '{suffixes[-1]}' executable",
            ))

        if (
            len(data) >= self.ENTROPY_MIN_SIZE
            and (not suffixes or suffixes[-1] not in self.ENTROPY_SKIP_EXTS)
        ):
            entropy = shannon_entropy(data)
            if entropy >= self.ENTROPY_THRESHOLD:
                results.append(Detection(
                    file_path=path,
                    signature_name="HEUR:HighEntropy",
                    severity="medium",
                    detection_type="heuristic",
                    detail=f"Shannon entropy {entropy:.2f}/8.0 suggests a packed or encrypted payload",
                ))

        return results

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


def get_quick_scan_roots() -> list[Path]:
    """High-traffic user folders — where malware actually lands."""
    candidates = [
        Path.home() / "Downloads",
        Path.home() / "Documents",
        Path.home() / "Desktop",
        Path.home(),
    ]
    roots = [p for p in candidates if p.is_dir()]
    if is_chromebook():
        for cb_root in (
            Path("/mnt/chromeos/MyFiles/Downloads"),
            Path("/mnt/chromeos/GoogleDrive/MyDrive"),
            Path("/mnt/chromeos/removable"),
            Path("/mnt/shared"),
        ):
            if cb_root.is_dir() and cb_root not in roots:
                roots.append(cb_root)
    return roots or [Path.home()]


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0–8). Packed/encrypted payloads score ~7.2+."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


@dataclass
class QuarantineRecord:
    record_id: str
    original_path: str
    quarantined_file: str
    signature_name: str
    severity: str
    quarantined_at: str


class QuarantineManager:
    """Isolates detected threats into a neutralized vault with restore/destroy support."""

    def __init__(self, quarantine_dir: Path | None = None) -> None:
        self.quarantine_dir = quarantine_dir or (Path.home() / ".cobrashield" / "quarantine")
        self.metadata_path = self.quarantine_dir / "quarantine.json"

    def _load_records(self) -> list[dict]:
        if not self.metadata_path.exists():
            return []
        try:
            return json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []

    def _save_records(self, records: list[dict]) -> None:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    def list_records(self) -> list[QuarantineRecord]:
        return [QuarantineRecord(**record) for record in self._load_records()]

    def count(self) -> int:
        return len(self._load_records())

    def quarantine(self, detection: Detection) -> QuarantineRecord:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        record_id = uuid.uuid4().hex[:12]
        destination = self.quarantine_dir / f"{record_id}.qs"
        shutil.move(str(detection.file_path), destination)
        try:
            os.chmod(destination, 0o400)  # neutralize: read-only, non-executable
        except OSError:
            pass
        record = QuarantineRecord(
            record_id=record_id,
            original_path=str(detection.file_path),
            quarantined_file=str(destination),
            signature_name=detection.signature_name,
            severity=detection.severity,
            quarantined_at=datetime.now().isoformat(timespec="seconds"),
        )
        records = self._load_records()
        records.append(record.__dict__)
        self._save_records(records)
        return record

    def restore(self, record_id: str) -> Path:
        records = self._load_records()
        record = next((r for r in records if r["record_id"] == record_id), None)
        if record is None:
            raise KeyError(f"No quarantine record: {record_id}")
        source = Path(record["quarantined_file"])
        target = Path(record["original_path"])
        if target.exists():
            raise FileExistsError(f"Original path already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), target)
        try:
            os.chmod(target, 0o644)
        except OSError:
            pass
        self._save_records([r for r in records if r["record_id"] != record_id])
        return target

    def delete(self, record_id: str) -> None:
        records = self._load_records()
        record = next((r for r in records if r["record_id"] == record_id), None)
        if record is None:
            return
        try:
            Path(record["quarantined_file"]).unlink(missing_ok=True)
        except OSError:
            pass
        self._save_records([r for r in records if r["record_id"] != record_id])


class HoneyfileSentinel:
    """Plants decoy 'honeyfile' tripwires that ransomware and infostealers love to touch.

    If a honeyfile is modified or deleted, something hostile is tampering with the
    folder — a classic tripwire defense consumer AVs don't ship.
    """

    MARKER = "CSHL-TRIPWIRE"
    DEFAULT_NAMES = (
        "Passwords-Backup.txt",
        "Wallet-Recovery-Keys.txt",
        "Tax-Returns-2026.pdf.txt",
    )

    def __init__(self, state_file: Path | None = None) -> None:
        self.state_file = state_file or (Path.home() / ".cobrashield" / "honeyfiles.json")

    def _load_state(self) -> dict[str, str]:
        if not self.state_file.exists():
            return {}
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_state(self, state: dict[str, str]) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

    @staticmethod
    def _digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def default_directories(self) -> list[Path]:
        directories = [Path.home()]
        for extra in (
            Path.home() / "Documents",
            Path.home() / "Downloads",
            Path("/mnt/chromeos/MyFiles"),
            Path("/mnt/chromeos/GoogleDrive/MyDrive"),
        ):
            if extra.is_dir() and extra not in directories:
                directories.append(extra)
        return directories

    def plant(self, directories: Iterable[Path]) -> list[Path]:
        planted: list[Path] = []
        state = self._load_state()
        token = uuid.uuid4().hex
        for directory in directories:
            directory = Path(directory)
            if not directory.is_dir():
                continue
            for name in self.DEFAULT_NAMES:
                target = directory / name
                if target.exists():
                    continue
                try:
                    target.write_text(
                        f"{self.MARKER}::{token}\n"
                        "Decoy file planted by CobraShield. Do not modify or delete.\n",
                        encoding="utf-8",
                    )
                    state[str(target)] = self._digest(target)
                    planted.append(target)
                except OSError:
                    continue
        self._save_state(state)
        return planted

    def check(self) -> list[tuple[Path, str]]:
        """Return (path, status) alerts where status is 'modified', 'deleted' or 'unreadable'."""
        alerts: list[tuple[Path, str]] = []
        for raw_path, digest in self._load_state().items():
            path = Path(raw_path)
            if not path.exists():
                alerts.append((path, "deleted"))
                continue
            try:
                if self._digest(path) != digest:
                    alerts.append((path, "modified"))
            except OSError:
                alerts.append((path, "unreadable"))
        return alerts

    def planted_count(self) -> int:
        return len(self._load_state())


def compute_health_score(summary: ScanSummary, quarantine_count: int = 0, honeyfile_alerts: int = 0) -> tuple[int, str]:
    """0–100 device health score with a SECURE / AT RISK / CRITICAL verdict."""
    high = sum(1 for d in summary.detections if d.severity == "high")
    score = 100
    score -= high * 25
    score -= (len(summary.detections) - high) * 10
    score -= min(15, len(summary.inaccessible_paths) // 20)
    score -= honeyfile_alerts * 30
    score = max(0, min(100, score))
    if score >= 85:
        return score, "SECURE"
    if score >= 60:
        return score, "AT RISK"
    return score, "CRITICAL"


def export_html_report(summary: ScanSummary, roots: list[Path], output_path: Path, quarantined: int = 0) -> Path:
    """Write a shareable dark-themed HTML report of a scan."""
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    platform = "ChromeOS / Chromebook" if is_chromebook() else "Desktop"
    rows = []
    for d in summary.detections:
        color = {"high": "#f87171", "medium": "#fbbf24"}.get(d.severity, "#22d3ee")
        rows.append(
            "<tr>"
            f"<td style='color:{color};font-weight:700'>{html.escape(d.severity.upper())}</td>"
            f"<td>{html.escape(str(d.file_path))}</td>"
            f"<td>{html.escape(d.signature_name)}</td>"
            f"<td>{html.escape(d.detection_type)}</td>"
            f"<td>{html.escape(d.detail)}</td>"
            "</tr>"
        )
    table = "\n".join(rows) if rows else "<tr><td colspan='5' style='text-align:center;color:#34d399'>No threats detected</td></tr>"
    page = f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>CobraShield Scan Report</title>
<style>
body{{background:#0b1220;color:#e8eef7;font-family:'Segoe UI',system-ui,sans-serif;margin:0;padding:40px}}
.card{{background:#101a2c;border:1px solid #22314d;border-radius:12px;padding:24px;max-width:1100px;margin:auto}}
h1{{color:#22d3ee;margin-top:0}}
.stats span{{display:inline-block;background:#16233a;border-radius:8px;padding:10px 16px;margin:4px 8px 4px 0;font-weight:600}}
table{{width:100%;border-collapse:collapse;margin-top:18px;font-size:14px}}
th{{text-align:left;color:#8ea0b8;border-bottom:1px solid #22314d;padding:8px}}
td{{padding:8px;border-bottom:1px solid #16233a;word-break:break-all}}
</style></head><body><div class='card'>
<h1>CobraShield Scan Report</h1>
<p style='color:#8ea0b8'>Generated {html.escape(generated)} &bull; Platform: {html.escape(platform)}</p>
<div class='stats'>
<span>Files scanned: {summary.scanned_files:,}</span>
<span>Detections: {len(summary.detections)}</span>
<span>Blocked paths: {len(summary.inaccessible_paths)}</span>
<span>Quarantined threats: {quarantined}</span>
</div>
<p style='color:#8ea0b8'>Roots: {html.escape(', '.join(str(r) for r in roots))}</p>
<table><tr><th>Severity</th><th>File</th><th>Signature</th><th>Engine</th><th>Detail</th></tr>
{table}
</table></div></body></html>"""
    output_path.write_text(page, encoding="utf-8")
    return output_path
