"""Put the project root on sys.path so `pytest` finds the `dns_server` package.

No pytest? Run the suite with the standard library instead:

    python -m unittest discover -s tests   # (if you adapt tests to unittest)

or the quick loop shown in the README.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
