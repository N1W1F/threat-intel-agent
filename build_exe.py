"""Build Securo.exe — a real Windows executable with the app icon
embedded as a resource, instead of running via pythonw.exe (which shows
Python's own icon in the taskbar, not ours).

Must run with the SAME Python environment that has pywebview installed
(the one launch.vbs points at), or the bundle will be missing it.

Run:  python build_exe.py
Output: dist/Securo.exe (then copy next to this file to run it —
persistent data lives beside the exe, see security.py's FROZEN branch).
"""
import shutil
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
APP_DIR = BASE_DIR / "app"


def main() -> int:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "Securo",
        "--onefile",
        "--windowed",
        "--icon", str(APP_DIR / "app.ico"),
        "--version-file", str(APP_DIR / "version_info.txt"),
        "--add-data", f"{APP_DIR / 'static'};static",
        "--add-data", f"{APP_DIR / 'app.ico'};.",
        "--distpath", str(BASE_DIR / "dist"),
        "--workpath", str(BASE_DIR / "build"),
        "--specpath", str(BASE_DIR / "build"),
        "--noconfirm",
        str(APP_DIR / "desktop_app.py"),
    ]
    result = subprocess.run(cmd, cwd=str(APP_DIR))
    if result.returncode != 0:
        return result.returncode

    built = BASE_DIR / "dist" / "Securo.exe"
    target = BASE_DIR / "Securo.exe"
    shutil.copy2(built, target)
    print(f"\nBuilt: {built}")
    print(f"Copied to: {target}  (run it from here — persistent data lands next to it)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
