import sys
from pathlib import Path

# Ensure backend and ransomware_detection root directories are on sys.path for direct pytest invocations
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

ransomware_detection_dir = backend_dir.parent / "ransomware_detection"
if str(ransomware_detection_dir) not in sys.path:
    sys.path.insert(0, str(ransomware_detection_dir))
