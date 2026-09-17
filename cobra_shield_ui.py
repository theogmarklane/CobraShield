from __future__ import annotations

from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import getpass
import json
import os
import socket
import sys
import threading
import webbrowser

from scanner import (
    Detection,
    HoneyfileSentinel,
    MalwareScanner,
    QuarantineManager,
    ScanSummary,
    compute_health_score,
    export_html_report,
    get_quick_scan_roots,
    get_system_scan_roots,
    is_chromebook,
)

APP_HTML_PATH = Path(__file__).resolve().parent / "ui" / "app.html"
REPORT_DIR = Path.home() / ".cobrashield" / "reports"


class ApiError(Exception):
    pass


class CobraShieldService:
    """Holds scanner state and executes every action the web UI can trigger."""

    def __init__(self) -> None:
        self.scanner = MalwareScanner()
        self.quarantine = QuarantineManager()
        self.sentinel = HoneyfileSentinel()
        self.lock = threading.Lock()

        self.last_summary = ScanSummary()
        self.last_roots: list[Path] = []
        self.last_scan_at: str | None = None
        self.detections: list[Detection] = []
        self.auto_action = "report"

        self.scan_running = False
        self.scan_progress: dict = {"current": 0, "total": 0, "label": ""}
        self.scan_mode = "quick"
        self.scan_actions: list[str] = []

        self.guard_stop = threading.Event()
        self.guard_thread: threading.Thread | None = None
        self.guard_events: list[dict] = []

    # ---------- helpers ----------

    def _guard_log(self, message: str, kind: str = "info") -> None:
        with self.lock:
            self.guard_events.append(
                {"time": datetime.now().strftime("%H:%M:%S"), "message": message, "kind": kind}
            )
            self.guard_events = self.guard_events[-200:]

    def _apply_auto_action(self, detection: Detection) -> str:
        if self.auto_action == "quarantine":
            try:
                self.quarantine.quarantine(detection)
                return f"Auto-quarantined {detection.file_path}"
            except OSError as err:
                return f"Failed to quarantine {detection.file_path}: {err}"
        if self.auto_action == "delete":
            try:
                detection.file_path.unlink()
                return f"Auto-deleted {detection.file_path}"
            except OSError as err:
                return f"Failed to delete {detection.file_path}: {err}"
        return ""

    @staticmethod
    def _detection_payload(detection: Detection) -> dict:
        return {
            "file_path": str(detection.file_path),
            "signature_name": detection.signature_name,
            "severity": detection.severity,
            "detection_type": detection.detection_type,
            "detail": detection.detail,
        }

    # ---------- stats ----------

    def get_stats(self) -> dict:
        alerts = self.sentinel.check()
        score, status = compute_health_score(self.last_summary, self.quarantine.count(), len(alerts))
        return {
            "user": getpass.getuser().replace(".", " ").title(),
            "platform": "chromeos" if is_chromebook() else "desktop",
            "files_scanned": self.last_summary.scanned_files,
            "detections": len(self.detections),
            "quarantined": self.quarantine.count(),
            "tripwires": self.sentinel.planted_count(),
            "tripwire_alerts": len(alerts),
            "health_score": score,
            "health_status": status,
            "guard_running": self.guard_running(),
            "last_scan": self.last_scan_at,
            "detections_list": [self._detection_payload(d) for d in self.detections],
        }

    # ---------- scanning ----------

    def start_scan(self, mode: str, auto_action: str | None = None) -> None:
        if self.scan_running:
            raise ApiError("A scan is already running.")
        if auto_action in ("report", "quarantine", "delete"):
            self.auto_action = auto_action
        roots = get_quick_scan_roots() if mode == "quick" else get_system_scan_roots()
        self.scan_running = True
        self.scan_mode = mode
        self.scan_actions = []
        self.scan_progress = {"current": 0, "total": len(roots), "label": "Starting scan…"}
        threading.Thread(target=self._scan_worker, args=(roots,), daemon=True).start()

    def _scan_worker(self, roots: list[Path]) -> None:
        combined = ScanSummary()
        try:
            for index, root in enumerate(roots, start=1):
                partial = self.scanner.scan_paths([root])
                combined.scanned_files += partial.scanned_files
                combined.inaccessible_paths.extend(partial.inaccessible_paths)
                for detection in partial.detections:
                    action_result = self._apply_auto_action(detection)
                    if action_result:
                        self.scan_actions.append(action_result)
                        self._guard_log(action_result, "info")
                    else:
                        combined.detections.append(detection)
                self.scan_progress = {
                    "current": index,
                    "total": len(roots),
                    "label": f"[{index}/{len(roots)}] {root} — {partial.scanned_files:,} files",
                }
            with self.lock:
                self.last_summary = combined
                self.detections = combined.detections
                self.last_roots = roots
                self.last_scan_at = datetime.now().isoformat(timespec="seconds")
        finally:
            self.scan_progress["label"] = "Scan complete"
            self.scan_running = False

    def scan_status(self) -> dict:
        result = None
        if not self.scan_running and self.last_scan_at:
            result = {
                "mode": self.scan_mode,
                "files_scanned": self.last_summary.scanned_files,
                "detections": [self._detection_payload(d) for d in self.detections],
                "inaccessible": len(self.last_summary.inaccessible_paths),
                "actions": self.scan_actions,
            }
        return {"running": self.scan_running, **self.scan_progress, "result": result}

    # ---------- detections ----------

    def detection_action(self, index: int, action: str) -> dict:
        try:
            detection = self.detections[index]
        except IndexError:
            raise ApiError("No such detection.")
        if action == "quarantine":
            try:
                record = self.quarantine.quarantine(detection)
            except OSError as err:
                raise ApiError(str(err))
            self.detections.pop(index)
            return {"ok": True, "path": record.original_path}
        if action == "delete":
            try:
                detection.file_path.unlink()
            except OSError as err:
                raise ApiError(str(err))
            self.detections.pop(index)
            return {"ok": True, "path": str(detection.file_path)}
        if action == "dismiss":
            self.detections.pop(index)
            return {"ok": True, "path": str(detection.file_path)}
        raise ApiError(f"Unknown action: {action}")

    # ---------- quarantine ----------

    def quarantine_list(self) -> dict:
        return {"records": [r.__dict__ for r in self.quarantine.list_records()]}

    def quarantine_action(self, record_id: str, action: str) -> dict:
        if action == "restore":
            try:
                restored = self.quarantine.restore(record_id)
            except (OSError, KeyError) as err:
                raise ApiError(str(err))
            return {"ok": True, "path": str(restored)}
        if action == "delete":
            self.quarantine.delete(record_id)
            return {"ok": True, "path": record_id}
        raise ApiError(f"Unknown action: {action}")

    # ---------- honeyfiles ----------

    def honeyfiles_plant(self) -> dict:
        planted = self.sentinel.plant(self.sentinel.default_directories())
        return {"planted": len(planted), "total": self.sentinel.planted_count()}

    def honeyfiles_check(self) -> dict:
        alerts = self.sentinel.check()
        return {
            "total": self.sentinel.planted_count(),
            "alerts": [{"path": str(p), "status": s} for p, s in alerts],
        }

    # ---------- live guard ----------

    def guard_running(self) -> bool:
        return self.guard_thread is not None and self.guard_thread.is_alive()

    def guard_toggle(self) -> dict:
        if self.guard_running():
            self.guard_stop.set()
            self.guard_thread = None
            self._guard_log("Live Guard stopped.")
            return {"running": False}
        roots = get_quick_scan_roots()
        self.guard_stop.clear()
        self.guard_thread = threading.Thread(target=self._guard_loop, args=(roots,), daemon=True)
        self.guard_thread.start()
        self._guard_log("Live Guard armed — baseline snapshot taken.")
        return {"running": True, "roots": [str(r) for r in roots]}

    def _guard_loop(self, roots: list[Path]) -> None:
        seen: dict[Path, float] = {}
        baseline = True
        while not self.guard_stop.is_set():
            for root in roots:
                for dirpath, directories, files in os.walk(root, onerror=lambda _: None):
                    directories[:] = [
                        d for d in directories
                        if not MalwareScanner._is_virtual_dir(Path(dirpath) / d)
                    ]
                    for name in files:
                        candidate = Path(dirpath) / name
                        try:
                            stat = candidate.stat()
                        except OSError:
                            continue
                        if stat.st_size > 64 * 1024 * 1024:
                            continue
                        if seen.get(candidate) == stat.st_mtime:
                            continue
                        seen[candidate] = stat.st_mtime
                        if baseline:
                            continue
                        for detection in self.scanner.scan_file(candidate):
                            msg = f"[{detection.severity.upper()}] {detection.file_path} — {detection.signature_name}"
                            action_result = self._apply_auto_action(detection)
                            if action_result:
                                msg += " → " + action_result
                            else:
                                with self.lock:
                                    self.detections.append(detection)
                            self._guard_log(msg, "detection")
            baseline = False
            self.guard_stop.wait(3.0)

    def guard_events_since(self) -> dict:
        with self.lock:
            events = self.guard_events[:]
            self.guard_events.clear()
        return {"events": events, "running": self.guard_running()}

    # ---------- report ----------

    def report_export(self) -> dict:
        if not self.last_roots:
            raise ApiError("Run a scan first.")
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        target = REPORT_DIR / f"cobrashield-report-{datetime.now():%Y%m%d-%H%M%S}.html"
        export_html_report(self.last_summary, self.last_roots, target, quarantined=self.quarantine.count())
        return {"ok": True, "path": str(target)}

    def shutdown(self) -> None:
        self.guard_stop.set()


class ApiHandler(BaseHTTPRequestHandler):
    service: CobraShieldService  # injected by serve()

    def log_message(self, *_args) -> None:  # silence request logs
        pass

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            return {}

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html", "/app.html"):
            body = APP_HTML_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/stats":
            self._send_json(self.service.get_stats())
            return
        if self.path == "/api/scan/status":
            self._send_json(self.service.scan_status())
            return
        if self.path == "/api/detections":
            self._send_json({"detections": [self.service._detection_payload(d) for d in self.service.detections]})
            return
        if self.path == "/api/quarantine/list":
            self._send_json(self.service.quarantine_list())
            return
        if self.path == "/api/honeyfiles/check":
            self._send_json(self.service.honeyfiles_check())
            return
        if self.path == "/api/guard/events":
            self._send_json(self.service.guard_events_since())
            return
        self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        body = self._read_body()
        try:
            if self.path == "/api/scan/start":
                self.service.start_scan(body.get("mode", "quick"), body.get("auto_action"))
                self._send_json({"ok": True})
                return
            if self.path == "/api/auto-action":
                self.service.auto_action = body.get("value", "report")
                self._send_json({"ok": True})
                return
            if self.path == "/api/detection/action":
                self._send_json(self.service.detection_action(int(body.get("index", -1)), body.get("action", "")))
                return
            if self.path == "/api/quarantine/action":
                self._send_json(self.service.quarantine_action(body.get("id", ""), body.get("action", "")))
                return
            if self.path == "/api/honeyfiles/plant":
                self._send_json(self.service.honeyfiles_plant())
                return
            if self.path == "/api/guard/toggle":
                self._send_json(self.service.guard_toggle())
                return
            if self.path == "/api/report/export":
                self._send_json(self.service.report_export())
                return
            self._send_json({"error": "not found"}, 404)
        except ApiError as err:
            self._send_json({"ok": False, "error": str(err)}, 400)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_cli_scan(auto_action: str = "report", quick: bool = False) -> None:
    print("CobraShield Antivirus Scanner")
    print("=============================")
    if is_chromebook():
        print("Platform: Chromebook / ChromeOS Environment Detected")
    else:
        print("Platform: Standard System Environment")

    scanner = MalwareScanner()
    roots = get_quick_scan_roots() if quick else get_system_scan_roots()
    print(f"Scanning scan roots: {', '.join(str(r) for r in roots)}...")

    summary = scanner.scan_paths(roots)

    print("\nScan Results:")
    print(f"  Scanned files: {summary.scanned_files}")
    print(f"  Inaccessible paths: {len(summary.inaccessible_paths)}")
    print(f"  Detections: {len(summary.detections)}")

    if summary.detections:
        print("\nDetections list:")
        for detection in summary.detections:
            print(
                f"  - [{detection.severity.upper()}] [{detection.signature_name}] "
                f"({detection.detection_type}) {detection.file_path}"
            )

        if auto_action == "quarantine":
            manager = QuarantineManager()
            print("\nAuto-quarantining detections...")
            for detection in summary.detections:
                try:
                    manager.quarantine(detection)
                    print(f"  quarantined: {detection.file_path}")
                except OSError as err:
                    print(f"  FAILED: {detection.file_path} ({err})")
        elif auto_action == "delete":
            print("\nAuto-deleting detections...")
            for detection in summary.detections:
                try:
                    detection.file_path.unlink()
                    print(f"  deleted: {detection.file_path}")
                except OSError as err:
                    print(f"  FAILED: {detection.file_path} ({err})")
    else:
        print("\nNo threats detected.")


def serve(port: int | None = None, open_browser: bool = True) -> None:
    service = CobraShieldService()
    ApiHandler.service = service
    port = port or _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), ApiHandler)
    url = f"http://127.0.0.1:{port}/"
    print("CobraShield Protection Center")
    print(f"Running at {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        service.shutdown()
        server.server_close()


def main() -> None:
    argv = sys.argv[1:]
    if "--cli" in argv:
        action = "report"
        if "--auto-quarantine" in argv:
            action = "quarantine"
        elif "--auto-delete" in argv:
            action = "delete"
        run_cli_scan(auto_action=action, quick="--quick" in argv)
        return

    port = None
    for i, arg in enumerate(argv):
        if arg == "--port" and i + 1 < len(argv):
            try:
                port = int(argv[i + 1])
            except ValueError:
                pass
    serve(port=port, open_browser="--no-browser" not in argv)


if __name__ == "__main__":
    main()
