"""Build Network Security Studio into a single windowed .exe.

Run it (double-click or from a terminal):

    python build_exe.py             # one-file exe  -> dist\\NetworkSecurityStudio.exe
    python build_exe.py --onedir    # folder build  -> dist\\NetworkSecurityStudio\\NetworkSecurityStudio.exe
    python build_exe.py --run       # run the app from source, no build
    python build_exe.py --clean     # remove this builder's build/dist output

PyInstaller is installed automatically the first time if it is missing.
The app source stays in firewall_gui.py — edit that file, then run this again.
"""

import os
import py_compile
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
APP = ROOT / "firewall_gui.py"
NAME = "NetworkSecurityStudio"
DIST = ROOT / "dist"
WORK = ROOT / "build_exe"
ICON = ROOT / "app.ico"


def run(cmd, **kwargs):
    print("> " + " ".join(str(part) for part in cmd))
    return subprocess.call(cmd, cwd=str(ROOT), **kwargs)


def pause():
    try:
        if sys.stdin and sys.stdin.isatty():
            input("\nPress Enter to close...")
    except Exception:
        pass


def clean():
    shutil.rmtree(WORK, ignore_errors=True)
    exe = DIST / f"{NAME}.exe"
    if exe.is_file():
        exe.unlink()
    onedir = DIST / NAME
    if onedir.is_dir():
        shutil.rmtree(onedir, ignore_errors=True)
    print("Cleaned build_exe/ and this builder's output in dist/.")


def ensure_pyinstaller() -> bool:
    try:
        import PyInstaller  # noqa: F401
        return True
    except ImportError:
        print("PyInstaller is not installed — installing it with pip...")
        code = run([sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"])
        if code != 0:
            print("\nCould not install PyInstaller.")
            print("Run this manually, then try again:")
            print(f'  "{sys.executable}" -m pip install --upgrade pyinstaller')
            return False
        return True


def check_source() -> bool:
    if not APP.is_file():
        print(f"Missing app source: {APP}")
        return False
    try:
        py_compile.compile(str(APP), doraise=True)
    except py_compile.PyCompileError as exc:
        print("The app has a syntax error, fix it first:\n")
        print(exc)
        return False
    return True


def main() -> int:
    args = set(sys.argv[1:])

    if "--run" in args:
        os.chdir(ROOT)
        return run([sys.executable, str(APP)])

    if "--clean" in args:
        clean()
        return 0

    if not check_source() or not ensure_pyinstaller():
        return 1

    onedir = "--onedir" in args
    mode = "onedir" if onedir else "onefile"

    existing = (DIST / NAME / f"{NAME}.exe") if onedir else (DIST / f"{NAME}.exe")
    if existing.is_file():
        try:
            with open(existing, "rb+"):
                pass
        except OSError:
            print(f"\n{existing.name} is running. Close the app, then run this again.")
            return 1

    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "work").mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--noupx",
        "--name", NAME,
        "--distpath", str(DIST),
        "--workpath", str(WORK / "work"),
        "--specpath", str(WORK),
        "--collect-all", "customtkinter",
        "--windowed",
        "--onedir" if onedir else "--onefile",
    ]
    if ICON.is_file():
        cmd += ["--icon", str(ICON)]
    cmd.append(str(APP))

    print(f"\nBuilding {NAME} ({mode})...\n")
    code = run(cmd)
    if code != 0:
        print("\nBuild failed — see the PyInstaller output above.")
        return code

    target = (DIST / NAME / f"{NAME}.exe") if onedir else (DIST / f"{NAME}.exe")
    if not target.is_file():
        print("\nBuild finished but the exe was not found where expected.")
        return 1

    size_mb = target.stat().st_size / (1024 * 1024)
    print("\nDone.")
    print(f"  {target}")
    print(f"  {size_mb:.1f} MB")
    print("\nDouble-click it to start. Firewall/DNS changes still use the in-app 'Enable admin' button.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        pause()
        raise
    except Exception as exc:  # keep the window usable on a crash
        print(f"\nUnexpected error: {exc}")
        pause()
        raise
