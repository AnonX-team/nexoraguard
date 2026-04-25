"""
build_installer.py — Compile NexoraGuard_Setup.iss into a Setup.exe
Usage:  python build_installer.py
"""
import subprocess
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ISS_FILE     = os.path.join(PROJECT_ROOT, "NexoraGuard_Setup.iss")
OUTPUT_EXE   = os.path.join(PROJECT_ROOT, "installer", "NexoraGuard_Setup.exe")

ISCC_CANDIDATES = [
    r"C:\Program Files (x86)\Inno Setup 6\iscc.exe",
    r"C:\Program Files\Inno Setup 6\iscc.exe",
    r"C:\Program Files (x86)\Inno Setup 5\iscc.exe",
    r"C:\Program Files\Inno Setup 5\iscc.exe",
]


def find_iscc() -> str:
    for path in ISCC_CANDIDATES:
        if os.path.isfile(path):
            return path
    # Last resort: check if iscc is on PATH
    import shutil
    on_path = shutil.which("iscc")
    if on_path:
        return on_path
    return ""


def main():
    print("=" * 55)
    print("  NexoraGuard Installer Builder")
    print("=" * 55)

    # 1. Locate iscc.exe
    iscc = find_iscc()
    if not iscc:
        print("\n[ERROR] iscc.exe not found.")
        print("  Install Inno Setup 6 from: https://jrsoftware.org/isinfo.php")
        sys.exit(1)
    print(f"[OK] Inno Setup compiler : {iscc}")

    # 2. Confirm the .iss file exists
    if not os.path.isfile(ISS_FILE):
        print(f"\n[ERROR] ISS script not found: {ISS_FILE}")
        sys.exit(1)
    print(f"[OK] ISS script          : {ISS_FILE}")

    # 3. Run iscc
    print("\n[...] Compiling installer — please wait...\n")
    result = subprocess.run(
        [iscc, ISS_FILE],
        cwd=PROJECT_ROOT,
        capture_output=False,   # stream iscc output directly to terminal
    )

    # 4. Report result
    print()
    if result.returncode != 0:
        print(f"[FAILED] iscc exited with code {result.returncode}")
        sys.exit(result.returncode)

    if os.path.isfile(OUTPUT_EXE):
        size_mb = os.path.getsize(OUTPUT_EXE) / (1024 * 1024)
        print("=" * 55)
        print("  Build SUCCESSFUL")
        print(f"  Output : {OUTPUT_EXE}")
        print(f"  Size   : {size_mb:.1f} MB")
        print("=" * 55)
    else:
        print("[WARN] iscc reported success but the output file was not found.")
        print(f"       Expected: {OUTPUT_EXE}")
        print("       Check the OutputDir= setting in the .iss file.")
        sys.exit(1)


if __name__ == "__main__":
    main()
