from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable
import hashlib
import html
import json
import math
import os
import shutil
import socket
import subprocess
import threading
import uuid


@dataclass
class Detection:
    file_path: Path
    signature_name: str
    severity: str = "high"
    detection_type: str = "signature"
    detail: str = ""
    file_hash: str = ""


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

    def __init__(
        self,
        signatures: dict[str, bytes] | None = None,
        enable_heuristics: bool = True,
        allowlist: "Allowlist | None" = None,
        excluded_paths: Iterable[Path] | None = None,
    ) -> None:
        self.signatures = signatures or self.SIGNATURES
        self.enable_heuristics = enable_heuristics
        self.allowlist = allowlist
        self.excluded_paths = tuple(
            self._safe_resolve(p)
            for p in (excluded_paths if excluded_paths is not None else default_exclusions())
        )

    @staticmethod
    def _safe_resolve(path: Path) -> Path:
        try:
            return path.resolve()
        except OSError:
            return path

    def _is_excluded(self, path: Path) -> bool:
        """False-positive guard: never flag CobraShield's own data (vault, reports, state)."""
        if not self.excluded_paths:
            return False
        if any(ex == path or ex in path.parents for ex in self.excluded_paths):
            return True
        if not path.is_absolute():
            candidate = self._safe_resolve(path)
            return any(ex == candidate or ex in candidate.parents for ex in self.excluded_paths)
        return False

    def scan_file(self, path: Path) -> list[Detection]:
        if not path.is_file():
            return []
        if self._is_excluded(path):
            return []

        try:
            data = path.read_bytes()
        except (PermissionError, OSError):
            return []

        digest = hashlib.sha256(data).hexdigest()
        if self.allowlist is not None and self.allowlist.is_allowed(path, digest):
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
                    file_hash=digest,
                ))

        if self.enable_heuristics:
            detections.extend(self._run_heuristics(path, data, digest))

        return detections

    def _run_heuristics(self, path: Path, data: bytes, digest: str = "") -> list[Detection]:
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
                file_hash=digest,
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
                    file_hash=digest,
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
                and not self._is_excluded(current_path / item)
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


def default_exclusions() -> list[Path]:
    """Locations that must never be flagged — CobraShield's own vault, reports and state."""
    return [Path.home() / ".cobrashield"]


class Allowlist:
    """User-approved known-safe files (by SHA-256 hash or exact path).

    Entries suppress future detections — the standard answer to false positives.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (Path.home() / ".cobrashield" / "allowlist.json")
        self._cache: dict | None = None
        self._cache_mtime: float | None = None

    def _load(self) -> dict:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            mtime = None
        if self._cache is not None and mtime == self._cache_mtime:
            return self._cache
        data = {"hashes": [], "paths": []}
        if mtime is not None:
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                data = {"hashes": raw.get("hashes", []), "paths": raw.get("paths", [])}
            except (OSError, json.JSONDecodeError):
                pass
        self._cache = data
        self._cache_mtime = mtime
        return data

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._cache = None

    def entries(self) -> dict:
        return {"hashes": list(self._load()["hashes"]), "paths": list(self._load()["paths"])}

    def count(self) -> int:
        data = self._load()
        return len(data["hashes"]) + len(data["paths"])

    def is_allowed(self, path: Path, digest: str = "") -> bool:
        data = self._load()
        if digest and digest in data["hashes"]:
            return True
        try:
            resolved = str(path.resolve())
        except OSError:
            resolved = str(path)
        return resolved in data["paths"] or str(path) in data["paths"]

    def add(self, path: Path | None = None, digest: str = "") -> None:
        data = self._load()
        if digest and digest not in data["hashes"]:
            data["hashes"].append(digest)
        if path is not None:
            try:
                resolved = str(path.resolve())
            except OSError:
                resolved = str(path)
            if resolved not in data["paths"]:
                data["paths"].append(resolved)
        self._save(data)

    def remove(self, value: str) -> bool:
        data = self._load()
        removed = False
        if value in data["hashes"]:
            data["hashes"].remove(value)
            removed = True
        if value in data["paths"]:
            data["paths"].remove(value)
            removed = True
        if removed:
            self._save(data)
        return removed


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


@dataclass
class StartupEntry:
    source: str
    name: str
    location: str
    risk: str  # "low" | "medium" | "high"
    note: str


class StartupAuditor:
    """Flags persistence mechanisms: things configured to launch at boot/login.

    Works on Linux/ChromeOS (autostart .desktop files, crontab) and Windows
    (Startup folder, Run registry keys via reg.exe).
    """

    SUSPICIOUS_KEYWORDS = (
        "temp", "tmp", "appdata\\local\\temp", "/tmp/", "powershell -e",
        "powershell.exe -w hidden", "base64", "curl ", "wget ", "http://",
        "rundll32", "regsvr32", "mshta",
    )

    def audit(self) -> list[StartupEntry]:
        entries: list[StartupEntry] = []
        entries.extend(self._autostart_dirs())
        entries.extend(self._crontab())
        if os.name == "nt":
            entries.extend(self._windows_startup_folder())
            entries.extend(self._windows_registry_run_keys())
        return entries

    def _risk_of(self, text: str) -> tuple[str, str]:
        lowered = text.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in lowered:
                return "high", f"Suspicious pattern '{keyword.strip()}' in launch command"
        if lowered.startswith(("/tmp", "/dev/shm")) or "\\temp\\" in lowered:
            return "high", "Launches from a temporary directory"
        return "low", "Standard autostart entry"

    def _autostart_dirs(self) -> list[StartupEntry]:
        entries: list[StartupEntry] = []
        candidates = [
            Path.home() / ".config" / "autostart",
            Path("/etc/xdg/autostart"),
        ]
        for directory in candidates:
            if not directory.is_dir():
                continue
            try:
                children = sorted(directory.iterdir())
            except OSError:
                continue
            for child in children:
                if child.suffix != ".desktop":
                    continue
                try:
                    content = child.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                exec_line = next(
                    (line.split("=", 1)[1].strip() for line in content.splitlines() if line.startswith("Exec=")),
                    "",
                )
                risk, note = self._risk_of(exec_line)
                entries.append(StartupEntry(
                    source="autostart",
                    name=child.stem,
                    location=exec_line or str(child),
                    risk=risk,
                    note=note,
                ))
        return entries

    def _crontab(self) -> list[StartupEntry]:
        entries: list[StartupEntry] = []
        if os.name == "nt":
            return entries
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=5,
            )
            lines = result.stdout.splitlines() if result.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired):
            lines = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            risk, note = self._risk_of(line)
            entries.append(StartupEntry(
                source="crontab",
                name=line[:40] + ("…" if len(line) > 40 else ""),
                location=line,
                risk=risk,
                note=note,
            ))
        return entries

    def _windows_startup_folder(self) -> list[StartupEntry]:
        entries: list[StartupEntry] = []
        startup = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if not startup.is_dir():
            return entries
        try:
            children = sorted(startup.iterdir())
        except OSError:
            return entries
        for child in children:
            risk, note = self._risk_of(child.name)
            entries.append(StartupEntry(
                source="startup-folder",
                name=child.name,
                location=str(child),
                risk=risk,
                note=note,
            ))
        return entries

    def _windows_registry_run_keys(self) -> list[StartupEntry]:
        entries: list[StartupEntry] = []
        keys = (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        )
        for key in keys:
            try:
                result = subprocess.run(
                    ["reg", "query", key], capture_output=True, text=True, timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                parts = line.split("    ")
                parts = [p.strip() for p in parts if p.strip()]
                if len(parts) < 3:
                    continue
                name, _, command = parts[0], parts[1], " ".join(parts[2:])
                risk, note = self._risk_of(command)
                entries.append(StartupEntry(
                    source="registry-run",
                    name=name,
                    location=command,
                    risk=risk,
                    note=note,
                ))
        return entries


@dataclass
class ExtensionEntry:
    browser: str
    name: str
    extension_id: str
    risk: str
    note: str


class BrowserExtensionAuditor:
    """Inventories Chromium browser extensions (Chrome, Edge, Brave) and scores risk.

    Browser extensions are the #1 infostealer vector on Chromebooks and PCs.
    """

    CHROME_RELATIVE = {
        "nt": [
            ("Chrome", Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data"),
            ("Edge", Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data"),
            ("Brave", Path(os.environ.get("LOCALAPPDATA", "")) / "BraveSoftware" / "Brave-Browser" / "User Data"),
        ],
        "posix": [
            ("Chrome", Path.home() / ".config" / "google-chrome"),
            ("Chromium", Path.home() / ".config" / "chromium"),
            ("Brave", Path.home() / ".config" / "BraveSoftware" / "Brave-Browser"),
            ("Edge", Path.home() / ".config" / "microsoft-edge"),
        ],
    }

    RISKY_PERMISSIONS = (
        "<all_urls>", "cookies", "webrequest", "webrequestblocking",
        "debugger", "nativemessaging", "clipboardread", "history",
    )

    def audit(self) -> list[ExtensionEntry]:
        findings: list[ExtensionEntry] = []
        for browser, user_data in self.CHROME_RELATIVE["nt" if os.name == "nt" else "posix"]:
            if not user_data.is_dir():
                continue
            for profile in sorted(user_data.iterdir()):
                if profile.name not in ("Default", "Guest Profile") and not profile.name.startswith("Profile "):
                    continue
                ext_dir = profile / "Extensions"
                if not ext_dir.is_dir():
                    continue
                try:
                    ext_ids = sorted(ext_dir.iterdir())
                except OSError:
                    continue
                for ext_id_dir in ext_ids:
                    finding = self._inspect_extension(browser, ext_id_dir)
                    if finding is not None:
                        findings.append(finding)
        return findings

    def _inspect_extension(self, browser: str, ext_id_dir: Path) -> ExtensionEntry | None:
        manifest_path: Path | None = None
        try:
            versions = sorted(ext_id_dir.iterdir())
        except OSError:
            return None
        for version in versions:
            candidate = version / "manifest.json"
            if candidate.exists():
                manifest_path = candidate
                break
        if manifest_path is None:
            return None
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return ExtensionEntry(browser, "(unreadable manifest)", ext_id_dir.name, "medium", "Manifest could not be parsed")

        name = str(manifest.get("name", ext_id_dir.name))
        if name.startswith("__MSG_"):
            name = name.strip("_")[:6].upper() + "…"
        permissions = [str(p).lower() for p in manifest.get("permissions", [])]
        host_permissions = [str(p).lower() for p in manifest.get("host_permissions", [])]
        granted = permissions + host_permissions

        hits = [p for p in granted if any(r in p for r in self.RISKY_PERMISSIONS)]
        if len(hits) >= 3 or "<all_urls>" in granted and "cookies" in granted:
            risk, note = "high", f"Powerful permissions: {', '.join(hits[:4])}"
        elif hits:
            risk, note = "medium", f"Notable permissions: {', '.join(hits[:3])}"
        else:
            risk, note = "low", "Standard permissions"
        return ExtensionEntry(browser, name, ext_id_dir.name, risk, note)


@dataclass
class ConnectionEntry:
    process: str
    local: str
    remote: str
    state: str
    risk: str
    note: str


class NetworkAuditor:
    """Snapshots outbound connections and flags plain-HTTP listeners and odd ports."""

    COMMON_SAFE_PORTS = {80, 443, 53, 123, 993, 587, 465, 22, 853, 5353}

    def audit(self) -> list[ConnectionEntry]:
        entries: list[ConnectionEntry] = []
        if os.name == "nt":
            rows = self._netstat_windows()
        else:
            rows = self._ss_posix()
        for process, local, remote, state in rows:
            risk = "low"
            note = ""
            if remote:
                port = self._port_of(remote)
                if state.upper().startswith("LISTEN"):
                    risk, note = "medium", "Listening for inbound connections"
                elif port is not None and port not in self.COMMON_SAFE_PORTS:
                    risk, note = "medium", f"Unusual destination port {port}"
            entries.append(ConnectionEntry(process, local, remote, state, risk, note or "Standard connection"))
        return entries

    @staticmethod
    def _port_of(address: str) -> int | None:
        try:
            return int(address.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            return None

    def _ss_posix(self) -> list[tuple[str, str, str, str]]:
        try:
            result = subprocess.run(
                ["ss", "-tunap"], capture_output=True, text=True, timeout=8,
            )
            lines = result.stdout.splitlines() if result.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired):
            return []
        rows: list[tuple[str, str, str, str]] = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            state = parts[1]
            local, remote = parts[4], parts[5] if len(parts) > 5 else ""
            process = ""
            if "users:" in line:
                process = line.split('"')[1] if line.count('"') >= 2 else ""
            rows.append((process or "?", local, remote, state))
        return rows[:200]

    def _netstat_windows(self) -> list[tuple[str, str, str, str]]:
        try:
            result = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True, timeout=15,
            )
            lines = result.stdout.splitlines() if result.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired):
            return []
        rows: list[tuple[str, str, str, str]] = []
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
                continue
            state = parts[3] if parts[0] == "TCP" else "UDP"
            rows.append(("pid:" + parts[-1], parts[1], parts[2], state))
        return rows[:200]


@dataclass
class ProcessEntry:
    pid: int
    name: str
    cmdline: str
    risk: str
    note: str


class ProcessAuditor:
    """Heuristic review of running processes: odd launch dirs, script engines, masquerades."""

    SCRIPT_ENGINES = ("powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32")

    def audit(self) -> list[ProcessEntry]:
        if os.name == "nt":
            return self._audit_windows()
        return self._audit_posix()

    def _classify(self, name: str, cmdline: str, cwd: str = "") -> tuple[str, str]:
        lowered = cmdline.lower()
        for engine in self.SCRIPT_ENGINES:
            if engine in lowered and ("-e " in lowered or "enc " in lowered or "base64" in lowered):
                return "high", f"Script engine '{engine}' running encoded commands"
        if cwd.startswith(("/tmp", "/dev/shm", "/var/tmp")) or "\\temp\\" in cwd.lower():
            return "medium", "Running from a temporary directory"
        return "low", "Normal"

    def _audit_posix(self) -> list[ProcessEntry]:
        entries: list[ProcessEntry] = []
        proc = Path("/proc")
        if not proc.is_dir():
            return entries
        for child in proc.iterdir():
            if not child.name.isdigit():
                continue
            pid = int(child.name)
            try:
                name = (child / "comm").read_text(encoding="utf-8", errors="ignore").strip()
                cmdline = (child / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                try:
                    cwd = os.readlink(child / "cwd")
                except OSError:
                    cwd = ""
            except OSError:
                continue
            risk, note = self._classify(name, cmdline or name, cwd)
            if risk != "low":
                entries.append(ProcessEntry(pid, name, (cmdline or name)[:120], risk, note))
        return entries

    def _audit_windows(self) -> list[ProcessEntry]:
        entries: list[ProcessEntry] = []
        try:
            result = subprocess.run(
                ["wmic", "process", "get", "ProcessId,Name,CommandLine,ExecutablePath", "/format:csv"],
                capture_output=True, text=True, timeout=20,
            )
            lines = result.stdout.splitlines() if result.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired):
            return entries
        for line in lines:
            parts = line.split(",")
            if len(parts) < 5:
                continue
            _, cmdline, exe_path, name, pid = parts[0], parts[1], parts[2], parts[3], parts[4]
            if not pid.strip().isdigit():
                continue
            risk, note = self._classify(name, cmdline or name, exe_path)
            if risk != "low":
                entries.append(ProcessEntry(int(pid), name, (cmdline or name)[:120], risk, note))
        return entries


class ScanScheduler:
    """Runs scans on a simple interval (every N hours) with completion callbacks."""

    def __init__(self) -> None:
        self.interval_hours = 24.0
        self.enabled = False
        self.mode = "quick"
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.next_run_at: float | None = None
        self.last_run_at: str | None = None

    def start(self, scan_fn: Callable[[], None]) -> None:
        self.stop()
        self._stop.clear()
        self.enabled = True
        self.next_run_at = __import__("time").time() + self.interval_hours * 3600

        def loop() -> None:
            while not self._stop.is_set():
                import time
                wait = max(5.0, (self.next_run_at or 0) - time.time())
                if self._stop.wait(min(wait, 30.0)):
                    return
                if self.next_run_at and time.time() >= self.next_run_at:
                    scan_fn()
                    self.last_run_at = datetime.now().isoformat(timespec="seconds")
                    self.next_run_at = time.time() + self.interval_hours * 3600

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.enabled = False
        self._stop.set()
        self._thread = None
        self.next_run_at = None

    def status(self) -> dict:
        next_in = None
        if self.enabled and self.next_run_at:
            import time
            next_in = max(0, int(self.next_run_at - time.time()))
        return {
            "enabled": self.enabled,
            "interval_hours": self.interval_hours,
            "mode": self.mode,
            "next_in_seconds": next_in,
            "last_run_at": self.last_run_at,
        }


class ThreatHistory:
    """Persistent JSON timeline of scans, detections, actions and guard events."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (Path.home() / ".cobrashield" / "history.json")
        self._cache: list[dict] | None = None
        self._cache_mtime: float | None = None

    def _load(self) -> list[dict]:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            mtime = None
        if self._cache is not None and mtime == self._cache_mtime:
            return self._cache
        events: list[dict] = []
        if mtime is not None:
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    events = raw
            except (OSError, json.JSONDecodeError):
                pass
        self._cache = events
        self._cache_mtime = mtime
        return events

    def _save(self, events: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(events[-500:], indent=1), encoding="utf-8")
        self._cache = None

    def record(self, kind: str, title: str, detail: str = "") -> None:
        events = self._load()
        events.append({
            "time": datetime.now().isoformat(timespec="seconds"),
            "kind": kind,
            "title": title,
            "detail": detail,
        })
        self._save(events)

    def recent(self, limit: int = 50) -> list[dict]:
        return list(reversed(self._load()[-limit:]))


def load_signature_packs(directory: Path | None = None) -> dict[str, bytes]:
    """Load extra signatures from ~/.cobrashield/signatures/*.txt (one per line, '#' = comment)."""
    directory = directory or (Path.home() / ".cobrashield" / "signatures")
    signatures: dict[str, bytes] = {}
    if not directory.is_dir():
        return signatures
    try:
        packs = sorted(directory.glob("*.txt"))
    except OSError:
        return signatures
    for pack in packs:
        try:
            lines = pack.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for index, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            signatures[f"PACK:{pack.stem}#{index}"] = line.encode("utf-8", errors="ignore")
    return signatures


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
