"""iosf-ng: Next-Gen iOS Mobile Security & API Testing Framework.

Recon-ng style interactive console entrypoint.
Usage:
    python main.py
"""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
IOSTESTER_DIR = BASE_DIR / "iostester"

if IOSTESTER_DIR.exists() and str(IOSTESTER_DIR) not in sys.path:
    sys.path.insert(0, str(IOSTESTER_DIR))

if __name__ == "__main__":
    try:
        from iostester.cli import cli
        cli()
    except KeyboardInterrupt:
        print("\n[!] Exited iosf-ng.")
        sys.exit(0)
