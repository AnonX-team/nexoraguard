"""
NexoraGuard Agent — Build Script
Run this to build NexoraGuard_Agent_Setup.exe

Usage:
    python build_agent.py

Requirements:
    pip install pyinstaller
    Inno Setup 6.x installed (https://jrsoftware.org/isinfo.php)
"""
import os
import sys
import subprocess
import shutil

ROOT    = os.path.dirname(os.path.abspath(__file__))
DIST    = os.path.join(ROOT, "dist")
AGENT_EXE = os.path.join(DIST, "NexoraGuard-Agent.exe")
ISCC_PATHS = [
    r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    r"C:\Program Files\Inno Setup 6\ISCC.exe",
]

def run(cmd, cwd=None):
    print(f"\n>>> {' '.join(cmd) if isinstance(cmd, list) else cmd}\n")
    result = subprocess.run(cmd, cwd=cwd or ROOT, shell=isinstance(cmd, str))
    if result.returncode != 0:
        print(f"ERROR: Command failed with code {result.returncode}")
        sys.exit(1)

def main():
    print("=" * 60)
    print("  NexoraGuard Agent Build Script")
    print("=" * 60)

    # Step 1: PyInstaller
    print("\n[1/2] Building EXE with PyInstaller...")
    run(["pyinstaller", "nexoraguard_agent.spec", "--clean", "--noconfirm"])

    if not os.path.exists(AGENT_EXE):
        print(f"ERROR: EXE not found at {AGENT_EXE}")
        sys.exit(1)
    size_mb = os.path.getsize(AGENT_EXE) / 1e6
    print(f"EXE built: {AGENT_EXE} ({size_mb:.1f} MB)")

    # Step 2: Inno Setup
    print("\n[2/2] Building installer with Inno Setup...")
    iscc = next((p for p in ISCC_PATHS if os.path.exists(p)), None)

    if not iscc:
        print("\nInno Setup not found. Install from: https://jrsoftware.org/isinfo.php")
        print("Then run: iscc NexoraGuard_Agent_Setup.iss")
        print(f"\nEXE is ready at: {AGENT_EXE}")
        return

    run([iscc, "NexoraGuard_Agent_Setup.iss"])

    installer = os.path.join(ROOT, "installer", "NexoraGuard_Agent_Setup.exe")
    if os.path.exists(installer):
        size_mb = os.path.getsize(installer) / 1e6
        print(f"\n{'=' * 60}")
        print(f"  SUCCESS!")
        print(f"  Installer: {installer} ({size_mb:.1f} MB)")
        print(f"{'=' * 60}")
    else:
        print("Installer build may have failed — check output above.")

if __name__ == "__main__":
    main()
