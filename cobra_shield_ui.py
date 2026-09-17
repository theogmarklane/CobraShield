from __future__ import annotations

from datetime import datetime
from pathlib import Path
import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

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

PALETTE = {
    "bg": "#0b1220",
    "panel": "#101a2c",
    "panel_alt": "#16233a",
    "border": "#22314d",
    "text": "#e8eef7",
    "muted": "#8ea0b8",
    "accent": "#22d3ee",
    "accent_hover": "#0ea5b7",
    "danger": "#f87171",
    "danger_hover": "#dc2626",
    "success": "#34d399",
    "warning": "#fbbf24",
}

AUTO_ACTIONS = ("Report only", "Auto-quarantine", "Auto-delete")


def _font(size: int = 10, weight: str = "normal") -> tuple:
    family = "Segoe UI" if sys.platform.startswith("win") else "DejaVu Sans"
    return (family, size, weight)


class CobraShieldApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.on_chromebook = is_chromebook()
        title = "CobraShield Antivirus"
        if self.on_chromebook:
            title += " — ChromeOS Edition"
        self.root.title(title)
        self.root.geometry("1120x700")
        self.root.minsize(980, 640)
        self.root.configure(bg=PALETTE["bg"])

        self.scanner = MalwareScanner()
        self.quarantine = QuarantineManager()
        self.sentinel = HoneyfileSentinel()

        self.last_summary = ScanSummary()
        self.last_roots: list[Path] = []
        self.scan_running = False

        self.guard_stop = threading.Event()
        self.guard_thread: threading.Thread | None = None
        self.guard_active = False

        self._configure_styles()
        self._build_header()
        self._build_body()
        self._build_statusbar()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.show_page("dashboard")

    # ---------- styling & layout ----------

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=PALETTE["bg"])
        style.configure(
            "Treeview",
            background=PALETTE["panel_alt"],
            fieldbackground=PALETTE["panel_alt"],
            foreground=PALETTE["text"],
            bordercolor=PALETTE["border"],
            rowheight=26,
            font=_font(9),
        )
        style.configure("Treeview.Heading", background=PALETTE["panel"], foreground=PALETTE["muted"], font=_font(9, "bold"))
        style.map(
            "Treeview",
            background=[("selected", PALETTE["accent_hover"])],
            foreground=[("selected", "#04121a")],
        )
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=PALETTE["panel"],
            background=PALETTE["accent"],
            bordercolor=PALETTE["border"],
        )
        style.configure("TCombobox", fieldbackground=PALETTE["panel_alt"], background=PALETTE["panel_alt"], foreground=PALETTE["text"])

    def _action_button(self, parent: tk.Widget, text: str, command, bg: str, hover: str | None = None) -> tk.Button:
        dark_text_on = (PALETTE["accent"], PALETTE["danger"], PALETTE["success"], PALETTE["warning"])
        fg = "#04121a" if bg in dark_text_on else PALETTE["text"]
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover or bg,
            activeforeground=fg,
            relief="flat",
            bd=0,
            padx=14,
            pady=8,
            font=_font(10, "bold"),
            cursor="hand2",
            highlightthickness=0,
        )

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=PALETTE["panel"], height=58)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        badge = tk.Label(header, text="CS", bg=PALETTE["accent"], fg="#04121a", font=_font(14, "bold"), width=3)
        badge.pack(side=tk.LEFT, padx=(16, 10), pady=12)
        tk.Label(header, text="CobraShield", bg=PALETTE["panel"], fg=PALETTE["text"], font=_font(15, "bold")).pack(side=tk.LEFT)
        platform_text = "ChromeOS / Chromebook" if self.on_chromebook else "Desktop"
        tk.Label(header, text=f"  •  {platform_text}", bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(10)).pack(side=tk.LEFT, pady=(4, 0))

    def _build_body(self) -> None:
        body = tk.Frame(self.root, bg=PALETTE["bg"])
        body.pack(fill=tk.BOTH, expand=True)

        sidebar = tk.Frame(body, bg=PALETTE["panel"], width=190)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        self.content = tk.Frame(body, bg=PALETTE["bg"])
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.nav_buttons: dict[str, tk.Button] = {}
        for key, label in (
            ("dashboard", "Dashboard"),
            ("scan", "Scan Center"),
            ("quarantine", "Quarantine Vault"),
            ("guard", "Live Guard"),
            ("reports", "Reports"),
        ):
            btn = tk.Button(
                sidebar,
                text=label,
                anchor="w",
                command=lambda k=key: self.show_page(k),
                bg=PALETTE["panel"],
                fg=PALETTE["muted"],
                activebackground=PALETTE["panel_alt"],
                activeforeground=PALETTE["text"],
                relief="flat",
                bd=0,
                padx=18,
                pady=12,
                font=_font(10, "bold"),
                cursor="hand2",
                highlightthickness=0,
            )
            btn.pack(fill=tk.X)
            self.nav_buttons[key] = btn

        self.pages: dict[str, tk.Frame] = {
            "dashboard": self._build_dashboard_page(),
            "scan": self._build_scan_page(),
            "quarantine": self._build_quarantine_page(),
            "guard": self._build_guard_page(),
            "reports": self._build_reports_page(),
        }

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self.root, bg=PALETTE["panel"], height=26)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        self.statusbar_var = tk.StringVar(value="Ready")
        tk.Label(bar, textvariable=self.statusbar_var, bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(8)).pack(side=tk.LEFT, padx=12)
        tk.Label(bar, text="CobraShield v2.0", bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(8)).pack(side=tk.RIGHT, padx=12)

    def show_page(self, name: str) -> None:
        for key, frame in self.pages.items():
            frame.pack_forget()
            self.nav_buttons[key].configure(bg=PALETTE["panel"], fg=PALETTE["muted"])
        self.pages[name].pack(fill=tk.BOTH, expand=True)
        self.nav_buttons[name].configure(bg=PALETTE["panel_alt"], fg=PALETTE["accent"])
        if name == "dashboard":
            self.refresh_dashboard()
        elif name == "quarantine":
            self.refresh_quarantine_table()

    # ---------- dashboard ----------

    def _build_dashboard_page(self) -> tk.Frame:
        page = tk.Frame(self.content, bg=PALETTE["bg"])

        top = tk.Frame(page, bg=PALETTE["bg"])
        top.pack(fill=tk.X, padx=20, pady=20)

        ring_card = tk.Frame(top, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        ring_card.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 14))
        self.ring_canvas = tk.Canvas(ring_card, width=170, height=170, bg=PALETTE["panel"], highlightthickness=0)
        self.ring_canvas.pack(padx=18, pady=(16, 4))
        tk.Label(ring_card, text="Device Health", bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9, "bold")).pack(pady=(0, 14))

        cards = tk.Frame(top, bg=PALETTE["bg"])
        cards.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.card_vars: dict[str, tk.StringVar] = {}
        for key, caption in (
            ("files", "Files scanned (last run)"),
            ("detections", "Active detections"),
            ("quarantined", "Threats in vault"),
            ("tripwires", "Honeyfile tripwires"),
        ):
            card = tk.Frame(cards, bg=PALETTE["panel_alt"], highlightbackground=PALETTE["border"], highlightthickness=1)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6)
            var = tk.StringVar(value="—")
            self.card_vars[key] = var
            tk.Label(card, textvariable=var, bg=PALETTE["panel_alt"], fg=PALETTE["text"], font=_font(24, "bold")).pack(padx=16, pady=(20, 2), anchor="w")
            tk.Label(card, text=caption, bg=PALETTE["panel_alt"], fg=PALETTE["muted"], font=_font(9), wraplength=140, justify="left").pack(padx=16, pady=(0, 18), anchor="w")

        features = tk.Frame(page, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        features.pack(fill=tk.X, padx=20, pady=(0, 20))
        tk.Label(features, text="CobraShield-exclusive defenses", bg=PALETTE["panel"], fg=PALETTE["accent"], font=_font(11, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        for line in (
            "•  Honeyfile Tripwires — decoy password/wallet files that scream when ransomware touches them",
            "•  Live Guard — real-time interception of new files landing in Downloads, Drive and USB storage",
            "•  Entropy Radar — heuristic engine that sniffs out packed & encrypted payloads with no signature",
            "•  ChromeOS-native — scans My Files, Google Drive, Play Files and SD cards other AVs can't see",
        ):
            tk.Label(features, text=line, bg=PALETTE["panel"], fg=PALETTE["text"], font=_font(10)).pack(anchor="w", padx=16, pady=1)
        tk.Frame(features, bg=PALETTE["panel"], height=10).pack()
        return page

    def refresh_dashboard(self) -> None:
        alerts = self.sentinel.check()
        score, status = compute_health_score(self.last_summary, self.quarantine.count(), len(alerts))
        self.card_vars["files"].set(f"{self.last_summary.scanned_files:,}")
        self.card_vars["detections"].set(str(len(self.last_summary.detections)))
        self.card_vars["quarantined"].set(str(self.quarantine.count()))
        self.card_vars["tripwires"].set(
            f"{self.sentinel.planted_count()} OK" if not alerts else f"{len(alerts)} ALERT"
        )
        color = PALETTE["success"] if score >= 85 else (PALETTE["warning"] if score >= 60 else PALETTE["danger"])
        canvas = self.ring_canvas
        canvas.delete("all")
        canvas.create_oval(20, 20, 150, 150, outline=PALETTE["border"], width=10)
        canvas.create_arc(20, 20, 150, 150, start=90, extent=-(score / 100) * 359.9, style="arc", outline=color, width=10)
        canvas.create_text(85, 78, text=str(score), fill=PALETTE["text"], font=_font(26, "bold"))
        canvas.create_text(85, 108, text=status, fill=color, font=_font(10, "bold"))

    # ---------- scan center ----------

    def _build_scan_page(self) -> tk.Frame:
        page = tk.Frame(self.content, bg=PALETTE["bg"])

        controls = tk.Frame(page, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        controls.pack(fill=tk.X, padx=20, pady=(20, 12))

        row = tk.Frame(controls, bg=PALETTE["panel"])
        row.pack(fill=tk.X, padx=14, pady=12)
        self._action_button(row, "Full System Scan", lambda: self.start_scan("full"), PALETTE["accent"], PALETTE["accent_hover"]).pack(side=tk.LEFT, padx=(0, 8))
        self._action_button(row, "Quick Scan", lambda: self.start_scan("quick"), PALETTE["panel_alt"], PALETTE["border"]).pack(side=tk.LEFT, padx=(0, 8))
        self._action_button(row, "Choose Folder…", lambda: self.start_scan("custom"), PALETTE["panel_alt"], PALETTE["border"]).pack(side=tk.LEFT, padx=(0, 16))

        tk.Label(row, text="On detection:", bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9)).pack(side=tk.LEFT)
        self.auto_action = tk.StringVar(value=AUTO_ACTIONS[0])
        combo = ttk.Combobox(row, textvariable=self.auto_action, values=AUTO_ACTIONS, state="readonly", width=16)
        combo.pack(side=tk.LEFT, padx=(6, 0))
        combo.bind("<<ComboboxSelected>>", self._on_auto_action_change)

        progress_row = tk.Frame(controls, bg=PALETTE["panel"])
        progress_row.pack(fill=tk.X, padx=14, pady=(0, 12))
        self.progress = ttk.Progressbar(progress_row, mode="indeterminate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.scan_status_var = tk.StringVar(value="Idle — pick a scan mode to begin")
        tk.Label(progress_row, textvariable=self.scan_status_var, bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9)).pack(side=tk.LEFT, padx=(12, 0))

        table_card = tk.Frame(page, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        table_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 12))

        columns = ("severity", "file", "signature", "type")
        self.det_tree = ttk.Treeview(table_card, columns=columns, show="headings", height=14)
        for col, text, width in (
            ("severity", "Severity", 90),
            ("file", "File", 560),
            ("signature", "Signature", 200),
            ("type", "Engine", 90),
        ):
            self.det_tree.heading(col, text=text)
            self.det_tree.column(col, width=width, anchor="w")
        self.det_tree.tag_configure("high", foreground=PALETTE["danger"])
        self.det_tree.tag_configure("medium", foreground=PALETTE["warning"])
        self.det_tree.tag_configure("low", foreground=PALETTE["accent"])
        self.det_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)

        scroll = ttk.Scrollbar(table_card, orient=tk.VERTICAL, command=self.det_tree.yview)
        self.det_tree.configure(yscroll=scroll.set)
        scroll.pack(side=tk.LEFT, fill=tk.Y, pady=10, padx=(0, 8))

        self.det_tree.bind("<Button-3>", self._show_detection_menu)
        self.det_menu = tk.Menu(self.root, tearoff=0, bg=PALETTE["panel_alt"], fg=PALETTE["text"], activebackground=PALETTE["accent_hover"])
        self.det_menu.add_command(label="Quarantine", command=self.quarantine_selected)
        self.det_menu.add_command(label="Delete permanently", command=self.delete_selected)
        self.det_menu.add_separator()
        self.det_menu.add_command(label="Dismiss from list", command=self.dismiss_selected)

        actions = tk.Frame(page, bg=PALETTE["bg"])
        actions.pack(fill=tk.X, padx=20, pady=(0, 16))
        self._action_button(actions, "Quarantine selected", self.quarantine_selected, PALETTE["panel_alt"], PALETTE["border"]).pack(side=tk.LEFT, padx=(0, 8))
        self._action_button(actions, "Delete selected", self.delete_selected, PALETTE["danger"], PALETTE["danger_hover"]).pack(side=tk.LEFT)

        self._det_by_item: dict[str, Detection] = {}
        return page

    def start_scan(self, mode: str) -> None:
        if self.scan_running:
            return
        if mode == "custom":
            folder = filedialog.askdirectory()
            if not folder:
                return
            roots = [Path(folder)]
        elif mode == "quick":
            roots = get_quick_scan_roots()
        else:
            roots = get_system_scan_roots()
        self.scan_running = True
        self.last_roots = roots
        self.scan_status_var.set(f"Scanning {len(roots)} root(s)…")
        self.progress.start(12)
        self._clear_detection_table()
        threading.Thread(target=self._scan_worker, args=(roots,), daemon=True).start()

    def _scan_worker(self, roots: list[Path]) -> None:
        combined = ScanSummary()
        total = len(roots)
        for index, root_path in enumerate(roots, start=1):
            partial = self.scanner.scan_paths([root_path])
            combined.scanned_files += partial.scanned_files
            combined.detections.extend(partial.detections)
            combined.inaccessible_paths.extend(partial.inaccessible_paths)
            self.root.after(
                0,
                lambda i=index, r=root_path, n=partial.scanned_files, t=total:
                    self.scan_status_var.set(f"[{i}/{t}] {r} — {n:,} files"),
            )
        actions = self._apply_auto_action(combined)
        self.root.after(0, lambda: self._scan_finished(combined, actions))

    def _apply_auto_action(self, summary: ScanSummary) -> list[str]:
        choice = self.auto_action.get()
        results: list[str] = []
        for detection in summary.detections:
            if choice == AUTO_ACTIONS[1]:
                try:
                    self.quarantine.quarantine(detection)
                    results.append(f"Quarantined {detection.file_path}")
                except OSError:
                    results.append(f"Failed to quarantine {detection.file_path}")
            elif choice == AUTO_ACTIONS[2]:
                try:
                    detection.file_path.unlink()
                    results.append(f"Deleted {detection.file_path}")
                except OSError:
                    results.append(f"Failed to delete {detection.file_path}")
        return results

    def _scan_finished(self, summary: ScanSummary, actions: list[str]) -> None:
        self.progress.stop()
        self.scan_running = False
        self.last_summary = summary
        for detection in summary.detections:
            self._add_detection_row(detection)
        acted = f" | Auto-actions: {len(actions)}" if actions else ""
        message = (
            f"Done — {summary.scanned_files:,} files, {len(summary.detections)} detections, "
            f"{len(summary.inaccessible_paths)} blocked paths{acted}"
        )
        self.scan_status_var.set(message)
        self.statusbar_var.set(message)
        self.refresh_dashboard()
        if summary.detections and not actions:
            messagebox.showwarning("Threats found", f"{len(summary.detections)} detection(s). Review them in the Scan Center.")

    def _add_detection_row(self, detection: Detection) -> None:
        item = self.det_tree.insert(
            "",
            tk.END,
            values=(detection.severity.upper(), str(detection.file_path), detection.signature_name, detection.detection_type),
            tags=(detection.severity,),
        )
        self._det_by_item[item] = detection

    def _clear_detection_table(self) -> None:
        for item in self.det_tree.get_children():
            self.det_tree.delete(item)
        self._det_by_item.clear()

    def _selected_detections(self) -> list[tuple[str, Detection]]:
        return [(item, self._det_by_item[item]) for item in self.det_tree.selection() if item in self._det_by_item]

    def _show_detection_menu(self, event) -> None:
        item = self.det_tree.identify_row(event.y)
        if item:
            self.det_tree.selection_set(item)
            self.det_menu.tk_popup(event.x_root, event.y_root)

    def _on_auto_action_change(self, _event=None) -> None:
        if self.auto_action.get() == AUTO_ACTIONS[2]:
            messagebox.showwarning("Auto-delete armed", "Detections from future scans will be permanently deleted without prompting.")

    def quarantine_selected(self) -> None:
        for item, detection in self._selected_detections():
            try:
                self.quarantine.quarantine(detection)
                self.det_tree.delete(item)
                self._det_by_item.pop(item, None)
            except OSError as err:
                messagebox.showerror("Quarantine failed", f"{detection.file_path}\n{err}")
        self.refresh_quarantine_table()
        self.refresh_dashboard()

    def delete_selected(self) -> None:
        if not self._selected_detections():
            return
        if not messagebox.askyesno("Confirm delete", "Permanently delete the selected file(s)? This cannot be undone."):
            return
        for item, detection in self._selected_detections():
            try:
                detection.file_path.unlink()
                self.det_tree.delete(item)
                self._det_by_item.pop(item, None)
            except OSError as err:
                messagebox.showerror("Delete failed", f"{detection.file_path}\n{err}")
        self.refresh_dashboard()

    def dismiss_selected(self) -> None:
        for item in self.det_tree.selection():
            self.det_tree.delete(item)
            self._det_by_item.pop(item, None)

    # ---------- quarantine vault ----------

    def _build_quarantine_page(self) -> tk.Frame:
        page = tk.Frame(self.content, bg=PALETTE["bg"])

        card = tk.Frame(page, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        tk.Label(card, text="Quarantine Vault", bg=PALETTE["panel"], fg=PALETTE["text"], font=_font(13, "bold")).pack(anchor="w", padx=16, pady=(14, 2))
        tk.Label(
            card,
            text="Isolated threats are neutralized (read-only) and can be restored or permanently destroyed.",
            bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9),
        ).pack(anchor="w", padx=16, pady=(0, 10))

        columns = ("original", "signature", "severity", "date")
        self.q_tree = ttk.Treeview(card, columns=columns, show="headings", height=14)
        for col, text, width in (
            ("original", "Original location", 500),
            ("signature", "Signature", 190),
            ("severity", "Severity", 90),
            ("date", "Quarantined at", 170),
        ):
            self.q_tree.heading(col, text=text)
            self.q_tree.column(col, width=width, anchor="w")
        self.q_tree.tag_configure("high", foreground=PALETTE["danger"])
        self.q_tree.tag_configure("medium", foreground=PALETTE["warning"])
        self.q_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(14, 0), pady=(0, 12))
        scroll = ttk.Scrollbar(card, orient=tk.VERTICAL, command=self.q_tree.yview)
        self.q_tree.configure(yscroll=scroll.set)
        scroll.pack(side=tk.LEFT, fill=tk.Y, pady=(0, 12), padx=(0, 10))

        btns = tk.Frame(page, bg=PALETTE["bg"])
        btns.pack(fill=tk.X, padx=20, pady=(0, 18))
        self._action_button(btns, "Restore selected", self.restore_selected_quarantine, PALETTE["panel_alt"], PALETTE["border"]).pack(side=tk.LEFT, padx=(0, 8))
        self._action_button(btns, "Destroy selected", self.delete_selected_quarantine, PALETTE["danger"], PALETTE["danger_hover"]).pack(side=tk.LEFT)

        self._q_by_item: dict[str, str] = {}
        return page

    def refresh_quarantine_table(self) -> None:
        for item in self.q_tree.get_children():
            self.q_tree.delete(item)
        self._q_by_item.clear()
        for record in self.quarantine.list_records():
            item = self.q_tree.insert(
                "",
                tk.END,
                values=(record.original_path, record.signature_name, record.severity.upper(), record.quarantined_at),
                tags=(record.severity,),
            )
            self._q_by_item[item] = record.record_id

    def restore_selected_quarantine(self) -> None:
        for item in self.q_tree.selection():
            record_id = self._q_by_item.get(item)
            if not record_id:
                continue
            try:
                restored = self.quarantine.restore(record_id)
                self.q_tree.delete(item)
                self._q_by_item.pop(item, None)
                messagebox.showinfo("Restored", f"File restored to:\n{restored}")
            except (OSError, KeyError) as err:
                messagebox.showerror("Restore failed", str(err))
        self.refresh_dashboard()

    def delete_selected_quarantine(self) -> None:
        if not self.q_tree.selection():
            return
        if not messagebox.askyesno("Confirm destroy", "Permanently destroy quarantined file(s)? This cannot be undone."):
            return
        for item in self.q_tree.selection():
            record_id = self._q_by_item.get(item)
            if record_id:
                self.quarantine.delete(record_id)
                self.q_tree.delete(item)
                self._q_by_item.pop(item, None)
        self.refresh_dashboard()

    # ---------- live guard & honeyfiles ----------

    def _build_guard_page(self) -> tk.Frame:
        page = tk.Frame(self.content, bg=PALETTE["bg"])

        honey = tk.Frame(page, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        honey.pack(fill=tk.X, padx=20, pady=(20, 12))
        tk.Label(honey, text="Honeyfile Tripwires", bg=PALETTE["panel"], fg=PALETTE["text"], font=_font(12, "bold")).pack(anchor="w", padx=16, pady=(14, 2))
        tk.Label(
            honey,
            text="Plants irresistible decoy files (passwords, wallet keys) across your folders. "
                 "If ransomware or an infostealer touches one, you get an instant alarm.",
            bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9), wraplength=860, justify="left",
        ).pack(anchor="w", padx=16)
        row = tk.Frame(honey, bg=PALETTE["panel"])
        row.pack(fill=tk.X, padx=16, pady=12)
        self._action_button(row, "Plant tripwires", self.plant_honeyfiles, PALETTE["accent"], PALETTE["accent_hover"]).pack(side=tk.LEFT, padx=(0, 8))
        self._action_button(row, "Check integrity now", self.check_honeyfiles, PALETTE["panel_alt"], PALETTE["border"]).pack(side=tk.LEFT)
        self.honey_status_var = tk.StringVar(value="No tripwires planted yet")
        tk.Label(row, textvariable=self.honey_status_var, bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9)).pack(side=tk.LEFT, padx=(10, 0))

        guard = tk.Frame(page, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        guard.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        tk.Label(guard, text="Live Guard — real-time file interception", bg=PALETTE["panel"], fg=PALETTE["text"], font=_font(12, "bold")).pack(anchor="w", padx=16, pady=(14, 2))
        tk.Label(
            guard,
            text="Watches your Downloads, Drive and removable storage. Every new or changed file is scanned "
                 "the moment it lands — before it can run. Uses the Scan Center's on-detection action.",
            bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9), wraplength=860, justify="left",
        ).pack(anchor="w", padx=16)

        row2 = tk.Frame(guard, bg=PALETTE["panel"])
        row2.pack(fill=tk.X, padx=16, pady=10)
        self.guard_button = self._action_button(row2, "Start Live Guard", self.toggle_guard, PALETTE["success"])
        self.guard_button.pack(side=tk.LEFT)
        self.guard_status_var = tk.StringVar(value="Live Guard is off")
        tk.Label(row2, textvariable=self.guard_status_var, bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9)).pack(side=tk.LEFT, padx=(10, 0))

        self.guard_log = tk.Text(
            guard,
            height=10,
            bg=PALETTE["panel_alt"],
            fg=PALETTE["text"],
            insertbackground=PALETTE["text"],
            relief="flat",
            font=_font(9),
            state="disabled",
        )
        self.guard_log.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 14))
        return page

    def plant_honeyfiles(self) -> None:
        planted = self.sentinel.plant(self.sentinel.default_directories())
        total = self.sentinel.planted_count()
        self.honey_status_var.set(f"{total} tripwire(s) armed ({len(planted)} new)")
        self._guard_log_line(f"Planted {len(planted)} honeyfile tripwire(s); {total} total armed.")
        self.refresh_dashboard()

    def check_honeyfiles(self) -> None:
        alerts = self.sentinel.check()
        if not alerts:
            self.honey_status_var.set(f"All {self.sentinel.planted_count()} tripwires intact")
        else:
            self.honey_status_var.set(f"WARNING: {len(alerts)} tripwire alert(s)")
            for path, status in alerts:
                self._guard_log_line(f"TRIPWIRE {status.upper()}: {path}")
            messagebox.showwarning("Tripwire triggered", "\n".join(f"{s.upper()}: {p}" for p, s in alerts))
        self.refresh_dashboard()

    def toggle_guard(self) -> None:
        if self.guard_active:
            self.guard_stop.set()
            self.guard_active = False
            self.guard_button.configure(text="Start Live Guard", bg=PALETTE["success"])
            self.guard_status_var.set("Live Guard stopped")
            self._guard_log_line("Live Guard stopped.")
            return
        roots = get_quick_scan_roots()
        self.guard_stop.clear()
        self.guard_thread = threading.Thread(target=self._guard_loop, args=(roots,), daemon=True)
        self.guard_thread.start()
        self.guard_active = True
        self.guard_button.configure(text="Stop Live Guard", bg=PALETTE["danger"])
        self.guard_status_var.set("Watching: " + ", ".join(str(r) for r in roots))
        self._guard_log_line("Live Guard armed. Baseline snapshot taken; new/changed files will be scanned.")

    def _guard_loop(self, roots: list[Path]) -> None:
        seen: dict[Path, float] = {}
        baseline = True
        while not self.guard_stop.is_set():
            for root_path in roots:
                for dirpath, directories, files in os.walk(root_path, onerror=lambda _: None):
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
                        mtime = stat.st_mtime
                        if seen.get(candidate) == mtime:
                            continue
                        seen[candidate] = mtime
                        if baseline:
                            continue
                        for detection in self.scanner.scan_file(candidate):
                            self.root.after(0, lambda det=detection: self._guard_detection(det))
            baseline = False
            self.guard_stop.wait(3.0)

    def _guard_detection(self, detection: Detection) -> None:
        self._guard_log_line(f"[{detection.severity.upper()}] {detection.file_path} — {detection.signature_name}")
        self.last_summary.detections.append(detection)
        self._add_detection_row(detection)
        choice = self.auto_action.get()
        if choice == AUTO_ACTIONS[1]:
            try:
                self.quarantine.quarantine(detection)
                self._guard_log_line("  -> auto-quarantined")
            except OSError as err:
                self._guard_log_line(f"  -> quarantine failed: {err}")
        elif choice == AUTO_ACTIONS[2]:
            try:
                detection.file_path.unlink()
                self._guard_log_line("  -> auto-deleted")
            except OSError as err:
                self._guard_log_line(f"  -> delete failed: {err}")
        self.refresh_dashboard()

    def _guard_log_line(self, text: str) -> None:
        self.guard_log.configure(state="normal")
        self.guard_log.insert(tk.END, f"[{datetime.now():%H:%M:%S}] {text}\n")
        self.guard_log.see(tk.END)
        self.guard_log.configure(state="disabled")

    # ---------- reports ----------

    def _build_reports_page(self) -> tk.Frame:
        page = tk.Frame(self.content, bg=PALETTE["bg"])
        card = tk.Frame(page, bg=PALETTE["panel"], highlightbackground=PALETTE["border"], highlightthickness=1)
        card.pack(fill=tk.X, padx=20, pady=20)
        tk.Label(card, text="Threat Reports", bg=PALETTE["panel"], fg=PALETTE["text"], font=_font(13, "bold")).pack(anchor="w", padx=16, pady=(14, 2))
        tk.Label(
            card,
            text="Export a shareable dark-themed HTML report of the latest scan — handy for IT support or bragging rights.",
            bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9), wraplength=860, justify="left",
        ).pack(anchor="w", padx=16)
        row = tk.Frame(card, bg=PALETTE["panel"])
        row.pack(fill=tk.X, padx=16, pady=14)
        self._action_button(row, "Export HTML report", self.export_report, PALETTE["accent"], PALETTE["accent_hover"]).pack(side=tk.LEFT)
        self.report_status_var = tk.StringVar(value="Run a scan first, then export its results.")
        tk.Label(row, textvariable=self.report_status_var, bg=PALETTE["panel"], fg=PALETTE["muted"], font=_font(9)).pack(side=tk.LEFT, padx=(12, 0))
        return page

    def export_report(self) -> None:
        if not self.last_roots:
            messagebox.showinfo("Nothing to report", "Run a scan first.")
            return
        default_name = f"cobrashield-report-{datetime.now():%Y%m%d-%H%M%S}.html"
        target = filedialog.asksaveasfilename(
            defaultextension=".html",
            initialfile=default_name,
            filetypes=[("HTML report", "*.html")],
        )
        if not target:
            return
        path = export_html_report(self.last_summary, self.last_roots, Path(target), quarantined=self.quarantine.count())
        self.report_status_var.set(f"Saved: {path}")

    # ---------- lifecycle ----------

    def _on_close(self) -> None:
        self.guard_stop.set()
        self.root.destroy()


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

    try:
        root = tk.Tk()
    except tk.TclError as err:
        print(f"Graphical display not available ({err}). Falling back to CLI mode.\n")
        run_cli_scan()
        return

    CobraShieldApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
