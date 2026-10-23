import sys
from pathlib import Path

# Ensure ransomware_detection directory is on sys.path
pkg_dir = Path(__file__).resolve().parent
if str(pkg_dir) not in sys.path:
    sys.path.insert(0, str(pkg_dir))
