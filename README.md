# CobraShield

CobraShield is a desktop antivirus prototype focused on full-system scanning with a simple UI.

## Features
- **Whole-PC scan roots**: scans all available drive roots (Windows) or `/` (Linux/macOS).
- **Live UI flow**: start a full scan from a desktop window and review detections.
- **Signature detections**: identifies known malware test signatures (including EICAR).
- **Access tracking**: reports blocked/inaccessible paths encountered during scan.

## Run
```bash
python cobra_shield_ui.py
```

## Tests
```bash
python -m unittest discover -s tests
```
