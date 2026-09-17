# CobraShield

CobraShield is a desktop antivirus prototype focused on full-system scanning with a simple UI, now fully Chromebook and ChromeOS compatible.

## Features
- **Chromebook & ChromeOS Compatibility**: Automatically detects ChromeOS / Crostini environments and targets ChromeOS shared storage locations (including `My Files`, `Google Drive`, external USB/SD drives, Android Play files under `/mnt/chromeos` & `/mnt/shared`).
- **Modern Protection Center UI**: Web-based interface (served locally, opens in your browser) with a device-health ring, stat cards, protection timeline, dark sidebar and lime accent theme — no Qt/WebKit/display server needed, perfect for ChromeOS.
- **Quarantine Vault**: Isolate detected threats into a neutralized (read-only) vault, then restore or permanently destroy them.
- **Auto-actions**: Per-scan behavior — report only, auto-quarantine, or auto-delete.
- **Heuristic engine ("Entropy Radar")**: Flags high-entropy packed/encrypted payloads and double-extension masquerades (`invoice.pdf.exe`) even with no signature match.
- **Honeyfile Tripwires** *(exclusive)*: Plants decoy password/wallet files; any modification or deletion raises an instant ransomware alarm.
- **Live Guard** *(exclusive)*: Real-time interception — every new or changed file in watched folders (Downloads, Drive, USB) is scanned the moment it lands.
- **HTML threat reports**: Export shareable dark-themed scan reports.
- **Whole-PC scan roots**: Scans all available drive roots (Windows) or system roots (`/` and Chromebook mount points on Linux/ChromeOS).
- **Virtual Directory Exclusions**: Automatically skips Linux/ChromeOS virtual pseudo-filesystems (`/proc`, `/sys`, `/dev`, `/run`) for faster, safer scanning.
- **Root Deduplication**: Prevents duplicate scanning when child storage paths overlap with parent system roots.
- **Live UI & CLI Fallback**: Run via graphical interface or headless CLI mode (`--cli` or auto-fallback on displayless Chromebook setups).
- **Signature detections**: Identifies known malware test signatures (including EICAR).
- **False-positive guard**: Never flags CobraShield's own data (quarantine vault, reports, tripwire state) — quarantined malware bytes can't re-trigger scans. **Allowlist** lets you mark known-safe files (by SHA-256 or path) so they're never flagged again.
- **Access tracking**: Reports blocked/inaccessible paths encountered during scan.

## Run

### Graphical UI (web-based)
CobraShield serves its Protection Center UI locally and opens it in your default browser — no display server, Qt, or WebKit required. Works identically on ChromeOS (Crostini) and desktop:

```bash
python cobra_shield_ui.py
```

Options:
```bash
python cobra_shield_ui.py --no-browser   # don't auto-open a browser tab
python cobra_shield_ui.py --port 8080    # serve on a fixed port
```

The UI has four pages: **Overview** (health ring, stat cards, protection timeline), **Threats** (smart/full scans, auto-actions, per-detection quarantine/delete), **Vault** (restore or destroy quarantined files), and **Live Guard** (honeyfile tripwires + real-time file interception with an activity log).

### CLI Mode (Ideal for Chromebook / Headless Terminals)
```bash
python cobra_shield_ui.py --cli
```

Quick scan of high-traffic user folders only:
```bash
python cobra_shield_ui.py --cli --quick
```

Automatically handle detections:
```bash
python cobra_shield_ui.py --cli --auto-quarantine
python cobra_shield_ui.py --cli --auto-delete    # destructive: deletes without prompting
```

## Tests
```bash
python -m unittest discover -s tests
```
