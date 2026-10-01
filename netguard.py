"""Launcher NetGuard — jalankan: python netguard.py <perintah>"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from netguard.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
