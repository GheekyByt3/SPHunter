#!/usr/bin/env python3
"""
SPHunter entry point — run directly without package installation.

Usage:
    python3 sphunter.py --help
    python3 sphunter.py --cookie-file cookies.txt --site-url <url> --mode search
"""

import sys
import os

# Ensure the project root is in the path so sphunter package resolves correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sphunter.cli import main

if __name__ == "__main__":
    main()
