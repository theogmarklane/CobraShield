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
- **Scheduled scans**: Set-and-forget automatic re-scans (every 6h → weekly), configurable from the System page.
- **Startup & persistence audit**: Lists everything configured to launch at boot/login — autostart entries, cron jobs, and on Windows the Startup folder + registry Run keys — with risk flags for temp-directory launches and encoded commands.
- **Browser extension audit**: Inventories Chrome, Edge, Brave and Chromium extensions and flags dangerous permission combos (cookies + all URLs etc.) — the #1 infostealer vector on Chromebooks.
- **Network connection audit**: Snapshots outbound connections and listeners; flags unusual destination ports and open listeners.
- **Suspicious process heuristics**: Reviews running processes for encoded script-engine commands and binaries launched from temp directories (Windows: via `wmic`; Linux: via `/proc`).
- **Signature packs**: Drop `.txt` files (one signature per line) into `~/.cobrashield/signatures/` and load community threat feeds or custom IOCs from the System page.
- **Threat history**: Persistent JSON timeline of scans, detections and actions, surfaced live in the Overview protection timeline.
- **Cross-platform**: Windows (registry/Startup-folder audits, `Path.home()` state), Linux, and ChromeOS/Crostini all supported — pure stdlib, zero dependencies.
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

The UI has five pages: **Overview** (health ring, stat cards, live protection timeline), **Threats** (smart/full scans, auto-actions, per-detection quarantine/delete/safe, allowlist manager), **Vault** (restore or destroy quarantined files), **Live Guard** (honeyfile tripwires + real-time file interception with an activity log), and **System** (scheduled scans, signature packs, startup/extension/network/process audits).

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
