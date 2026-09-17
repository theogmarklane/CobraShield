from __future__ import annotations

from pathlib import Path
import sys
import threading
import tkinter as tk
from tkinter import ttk

from scanner import MalwareScanner, get_system_scan_roots, is_chromebook


class CobraShieldApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        title_suffix = " (Chromebook Compatible)" if is_chromebook() else ""
        self.root.title(f"CobraShield Antivirus{title_suffix}")
        self.root.geometry("860x560")

        self.scanner = MalwareScanner()

        self.status_var = tk.StringVar(value="Ready")
        self.stats_var = tk.StringVar(value="No scans run yet")

        frame = ttk.Frame(root, padding=14)
        frame.pack(fill=tk.BOTH, expand=True)

        header_text = "CobraShield Antivirus Scanner"
        if is_chromebook():
            header_text += " - Chromebook / ChromeOS Edition"

        ttk.Label(
            frame,
            text=header_text,
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor=tk.W)

        subtitle_text = (
            "Scans system roots and ChromeOS shared files (My Files, Google Drive, SD cards)."
            if is_chromebook()
            else "Scans all system roots that this process can access."
        )

        ttk.Label(
            frame,
            text=subtitle_text,
        ).pack(anchor=tk.W, pady=(2, 8))

        action_row = ttk.Frame(frame)
        action_row.pack(fill=tk.X, pady=(0, 8))

        self.scan_button = ttk.Button(
            action_row,
            text="Scan System & Storage",
            command=self.start_full_scan,
        )
        self.scan_button.pack(side=tk.LEFT)

        ttk.Label(action_row, textvariable=self.status_var).pack(side=tk.LEFT, padx=(12, 0))

        ttk.Label(frame, textvariable=self.stats_var).pack(anchor=tk.W, pady=(0, 8))

        columns = ("file", "signature")
        self.detections_table = ttk.Treeview(frame, columns=columns, show="headings", height=18)
        self.detections_table.heading("file", text="File")
        self.detections_table.heading("signature", text="Signature")
        self.detections_table.column("file", width=640)
        self.detections_table.column("signature", width=180)
        self.detections_table.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.detections_table.yview)
        self.detections_table.configure(yscroll=scrollbar.set)
        scrollbar.place(relx=1.0, rely=1.0, anchor="se")

    def start_full_scan(self) -> None:
        self.scan_button.configure(state=tk.DISABLED)
        self.status_var.set("Scanning…")
        self.stats_var.set("Starting full-system scan")
        self._clear_results()

        worker = threading.Thread(target=self._run_scan_worker, daemon=True)
        worker.start()

    def _run_scan_worker(self) -> None:
        roots = get_system_scan_roots()
        summary = self.scanner.scan_paths(roots)

        self.root.after(0, lambda: self._render_summary(summary, roots))

    def _render_summary(self, summary, roots: list[Path]) -> None:
        for detection in summary.detections:
            self.detections_table.insert(
                "",
                tk.END,
                values=(str(detection.file_path), detection.signature_name),
            )

        self.stats_var.set(
            f"Scanned {summary.scanned_files} files across "
            f"{', '.join(str(root) for root in roots)} | "
            f"Detections: {len(summary.detections)} | "
            f"Blocked paths: {len(summary.inaccessible_paths)}"
        )
        self.status_var.set("Scan complete")
        self.scan_button.configure(state=tk.NORMAL)

    def _clear_results(self) -> None:
        for item_id in self.detections_table.get_children():
            self.detections_table.delete(item_id)


def run_cli_scan() -> None:
    print("CobraShield Antivirus Scanner")
    print("=============================")
    if is_chromebook():
        print("Platform: Chromebook / ChromeOS Environment Detected")
    else:
        print("Platform: Standard System Environment")

    scanner = MalwareScanner()
    roots = get_system_scan_roots()
    print(f"Scanning scan roots: {', '.join(str(r) for r in roots)}...")

    summary = scanner.scan_paths(roots)

    print("\nScan Results:")
    print(f"  Scanned files: {summary.scanned_files}")
    print(f"  Inaccessible paths: {len(summary.inaccessible_paths)}")
    print(f"  Detections: {len(summary.detections)}")

    if summary.detections:
        print("\nDetections list:")
        for detection in summary.detections:
            print(f"  - [{detection.signature_name}] {detection.file_path}")
    else:
        print("\nNo threats detected.")


def main() -> None:
    if "--cli" in sys.argv:
        run_cli_scan()
        return

    try:
        root = tk.Tk()
        CobraShieldApp(root)
        root.mainloop()
    except tk.TclError as err:
        print(f"Graphical display not available ({err}). Falling back to CLI mode.\n")
        run_cli_scan()


if __name__ == "__main__":
    main()
