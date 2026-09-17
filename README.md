# CobraShield

CobraShield is a desktop antivirus prototype focused on full-system scanning with a simple UI, now fully Chromebook and ChromeOS compatible.

## Features
- **Chromebook & ChromeOS Compatibility**: Automatically detects ChromeOS / Crostini environments and targets ChromeOS shared storage locations (including `My Files`, `Google Drive`, external USB/SD drives, Android Play files under `/mnt/chromeos` & `/mnt/shared`).
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

## Tests
```bash
python -m unittest discover -s tests
```
