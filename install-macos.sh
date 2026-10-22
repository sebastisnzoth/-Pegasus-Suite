#!/bin/sh
# Safe installer for Intel Macs running macOS Catalina (10.15).
set -eu
cd "$(dirname "$0")"
if [ "$(uname -s)" != "Darwin" ]; then
  echo "This installer is intended for macOS." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required. Install a Catalina-compatible Python 3 release first." >&2
  exit 1
fi
python3 - <<'PY'
import sys
if not ((3, 8) <= sys.version_info[:2] < (3, 13)):
    sys.exit("Use Python 3.8–3.12 compatible with macOS Catalina, not the system Python 2.")
print("Python:", sys.version.split()[0])
PY
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
echo "Installed in .venv. Run: ./.venv/bin/python Pegasus-Suite.py"
