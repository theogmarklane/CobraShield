from pathlib import Path
import tempfile
import unittest

from scanner import MalwareScanner


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


if __name__ == "__main__":
    unittest.main()
