#!/usr/bin/env python3
"""Build a standalone Windows executable for gui_app.py.

Run this on a machine with the project's dependencies installed
(pip install -r requirements.txt, plus `pip install pyinstaller`).
The result, dist/DORA_Assessment_Tool.exe, needs nothing else on the
target machine -- no Python, no pip, no terminal.
"""

from __future__ import annotations

import pathlib

import PyInstaller.__main__

ROOT = pathlib.Path(__file__).resolve().parent
SEP = ";"  # PyInstaller --add-data separator on Windows (":" on Linux/macOS)

args = [
    str(ROOT / "gui_app.py"),
    "--name", "DORA_Assessment_Tool",
    "--onefile",
    "--windowed",
    "--noconfirm",
    "--add-data", f"{ROOT / 'wordlists'}{SEP}wordlists",
    "--add-data", f"{ROOT / 'data'}{SEP}data",
    # Optional headless-browser rendering and PDF export are skipped in this
    # build: they need native binaries (Chromium / GTK) that aren't part of
    # a "just double-click it" handoff. The modules degrade gracefully
    # without them (see modules/browser_render.py).
    "--exclude-module", "playwright",
    "--exclude-module", "weasyprint",
]

# python-dotenv has a deferred `import IPython` inside its (unused) Jupyter
# magic hook. PyInstaller's static analysis follows it anyway and drags in
# IPython's entire notebook stack (matplotlib, numpy, pandas, pytest, jupyter,
# tornado, ...) from this dev machine's global site-packages -- ~60MB of dead
# weight the app never touches. Cut it all.
_DEAD_WEIGHT = [
    "IPython", "ipykernel", "ipywidgets", "jupyter_client", "jupyter_core",
    "nbformat", "notebook", "matplotlib", "numpy", "pandas", "geopandas",
    "PIL", "Pillow", "tornado", "pytest", "_pytest", "Cython", "pyparsing",
    "wheel",
]
for _mod in _DEAD_WEIGHT:
    args.extend(["--exclude-module", _mod])

if __name__ == "__main__":
    PyInstaller.__main__.run(args)
    print("\nBuilt: dist/DORA_Assessment_Tool.exe")
    print("Hand that single file to your colleague -- no install needed.")
