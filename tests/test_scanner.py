from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from scanner import MalwareScanner, get_system_scan_roots, is_chromebook


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


if __name__ == "__main__":
    unittest.main()
