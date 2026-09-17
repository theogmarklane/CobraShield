from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from scanner import (
    Allowlist,
    HoneyfileSentinel,
    MalwareScanner,
    QuarantineManager,
    compute_health_score,
    get_system_scan_roots,
    is_chromebook,
)


class ScannerTests(unittest.TestCase):
    def test_detects_eicar_signature(self) -> None:
        scanner = MalwareScanner()
        with tempfile.TemporaryDirectory() as tmp:
            test_file = Path(tmp) / "eicar.txt"
            test_file.write_text(
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            )

            detections = scanner.scan_file(test_file)

            self.assertEqual(len(detections), 1)
            self.assertEqual(detections[0].signature_name, "EICAR-Test-File")

    def test_recursively_scans_directory(self) -> None:
        scanner = MalwareScanner(signatures={"custom": b"evil-pattern"})
        with tempfile.TemporaryDirectory() as tmp:
            nested_dir = Path(tmp) / "nested"
            nested_dir.mkdir()
            harmless = nested_dir / "harmless.txt"
            harmless.write_text("all good")
            malicious = nested_dir / "malicious.txt"
            malicious.write_text("this contains evil-pattern")

            summary = scanner.scan_paths([Path(tmp)])

            self.assertEqual(summary.scanned_files, 2)
            self.assertEqual(len(summary.detections), 1)
            self.assertEqual(summary.detections[0].file_path, malicious)

    def test_normalize_roots_deduplication(self) -> None:
        paths = [
            Path("/mnt/chromeos/MyFiles"),
            Path("/"),
            Path("/mnt/chromeos"),
            Path("/home/user"),
        ]
        normalized = MalwareScanner._normalize_roots(paths)
        self.assertEqual(normalized, [Path("/")])

    @patch("scanner.is_chromebook", return_value=True)
    def test_get_system_scan_roots_chromebook(self, mock_is_cb) -> None:
        with patch.object(Path, "exists", autospec=True) as mock_exists:
            mock_exists.side_effect = lambda p: str(p) in ("/mnt/chromeos", "/mnt/shared")
            roots = get_system_scan_roots()
            self.assertIn(Path("/"), roots)
            self.assertIn(Path("/mnt/chromeos"), roots)
            self.assertIn(Path("/mnt/shared"), roots)

    @patch("os.name", "posix")
    def test_is_chromebook_detection_env(self) -> None:
        with patch.dict("os.environ", {"CHROMEOS_INSIDE_CONTAINER": "1"}):
            self.assertTrue(is_chromebook())

    def test_is_virtual_dir(self) -> None:
        self.assertTrue(MalwareScanner._is_virtual_dir(Path("/proc")))
        self.assertTrue(MalwareScanner._is_virtual_dir(Path("/proc/sys/fs")))
        self.assertTrue(MalwareScanner._is_virtual_dir(Path("/sys/kernel")))
        self.assertTrue(MalwareScanner._is_virtual_dir(Path("/dev/pts")))
        self.assertFalse(MalwareScanner._is_virtual_dir(Path("/home/user/doc.txt")))

    def test_detects_double_extension_masquerade(self) -> None:
        scanner = MalwareScanner(signatures={"x": b"zzz-not-present"})
        with tempfile.TemporaryDirectory() as tmp:
            fake_doc = Path(tmp) / "invoice.pdf.exe"
            fake_doc.write_bytes(b"tiny")

            detections = scanner.scan_file(fake_doc)

            self.assertTrue(any(d.detection_type == "heuristic" for d in detections))
            self.assertTrue(any(d.signature_name == "HEUR:DoubleExtension" for d in detections))

    def test_detects_high_entropy_payload(self) -> None:
        scanner = MalwareScanner(signatures={"x": b"zzz-not-present"})
        with tempfile.TemporaryDirectory() as tmp:
            blob = Path(tmp) / "payload.bin"
            blob.write_bytes(os.urandom(32 * 1024))

            detections = scanner.scan_file(blob)

            self.assertTrue(any(d.signature_name == "HEUR:HighEntropy" for d in detections))

    def test_heuristics_can_be_disabled(self) -> None:
        scanner = MalwareScanner(signatures={"x": b"zzz-not-present"}, enable_heuristics=False)
        with tempfile.TemporaryDirectory() as tmp:
            fake_doc = Path(tmp) / "invoice.pdf.exe"
            fake_doc.write_bytes(b"tiny")

            self.assertEqual(scanner.scan_file(fake_doc), [])

    def test_quarantine_restore_and_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = QuarantineManager(Path(tmp) / "vault")
            target = Path(tmp) / "eicar.txt"
            target.write_text(
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            )
            scanner = MalwareScanner()

            detection = scanner.scan_file(target)[0]
            record = manager.quarantine(detection)
            self.assertFalse(target.exists())
            self.assertEqual(manager.count(), 1)

            restored = manager.restore(record.record_id)
            self.assertTrue(restored.exists())
            self.assertEqual(manager.count(), 0)

            detection = scanner.scan_file(target)[0]
            record = manager.quarantine(detection)
            manager.delete(record.record_id)
            self.assertEqual(manager.count(), 0)
            self.assertFalse((Path(tmp) / "vault" / f"{record.record_id}.qs").exists())

    def test_honeyfile_tripwire_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = HoneyfileSentinel(Path(tmp) / "state.json")
            watch_dir = Path(tmp) / "watched"
            watch_dir.mkdir()

            planted = sentinel.plant([watch_dir])
            self.assertTrue(planted)
            self.assertEqual(sentinel.check(), [])

            planted[0].write_text("ransom note", encoding="utf-8")
            alerts = sentinel.check()
            self.assertEqual(alerts[0][1], "modified")

            for leftover in planted[1:]:
                leftover.unlink()
            statuses = {status for _, status in sentinel.check()}
            self.assertIn("deleted", statuses)

    def test_health_score_drops_with_detections(self) -> None:
        scanner = MalwareScanner()
        with tempfile.TemporaryDirectory() as tmp:
            clean = scanner.scan_paths([Path(tmp)])
            score, status = compute_health_score(clean)
            self.assertEqual((score, status), (100, "SECURE"))

            bad = Path(tmp) / "eicar.txt"
            bad.write_text(
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            )
            dirty = scanner.scan_paths([Path(tmp)])
            score, status = compute_health_score(dirty)
            self.assertLess(score, 100)
            self.assertNotEqual(status, "SECURE")

    def test_scanner_never_flags_its_own_vault(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / ".cobrashield" / "quarantine"
            vault.mkdir(parents=True)
            quarantined = vault / "abc123.qs"
            quarantined.write_text(
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            )
            scanner = MalwareScanner(excluded_paths=[Path(tmp) / ".cobrashield"])

            summary = scanner.scan_paths([Path(tmp)])

            self.assertEqual(summary.detections, [])
            self.assertEqual(scanner.scan_file(quarantined), [])

    def test_allowlist_suppresses_false_positive_by_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            allowlist = Allowlist(Path(tmp) / "allowlist.json")
            target = Path(tmp) / "eicar.txt"
            target.write_text(
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            )
            scanner = MalwareScanner(allowlist=allowlist, excluded_paths=[])

            self.assertEqual(len(scanner.scan_file(target)), 1)

            allowlist.add(path=target)
            self.assertEqual(scanner.scan_file(target), [])

            self.assertTrue(allowlist.remove(str(target.resolve())))
            self.assertEqual(len(scanner.scan_file(target)), 1)

    def test_allowlist_suppresses_false_positive_by_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import hashlib as _hashlib

            content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            digest = _hashlib.sha256(content).hexdigest()
            allowlist = Allowlist(Path(tmp) / "allowlist.json")
            allowlist.add(digest=digest)

            target = Path(tmp) / "renamed-copy.txt"
            target.write_bytes(content)
            scanner = MalwareScanner(allowlist=allowlist, excluded_paths=[])

            self.assertEqual(scanner.scan_file(target), [])


if __name__ == "__main__":
    unittest.main()
