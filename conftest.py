"""Root conftest: ensure the repo root is importable."""
import pathlib
import sys

_ROOT = str(pathlib.Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
