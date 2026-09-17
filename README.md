# CobraShield

CobraShield is a desktop antivirus prototype focused on full-system scanning with a simple UI, now fully Chromebook and ChromeOS compatible.

## Features
- **Chromebook & ChromeOS Compatibility**: Automatically detects ChromeOS / Crostini environments and targets ChromeOS shared storage locations (including `My Files`, `Google Drive`, external USB/SD drives, Android Play files under `/mnt/chromeos` & `/mnt/shared`).
- **Modern dark UI**: Polished dashboard with a device-health ring, stat cards, Scan Center, Quarantine Vault, Live Guard and Reports pages — looks at home on ChromeOS and desktop.
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
- **Access tracking**: Reports blocked/inaccessible paths encountered during scan.

## Run

### Graphical UI
```bash
python cobra_shield_ui.py
```

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
