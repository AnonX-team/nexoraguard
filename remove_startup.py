"""
NexoraGuard — Remove Windows Startup Registry Entry
Run this ONCE as Administrator to stop the crash loop.
"""
import winreg
import sys

APP_NAME = "NexoraGuard"
RUN_KEY  = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

def remove_startup_entry(hive, hive_name: str) -> bool:
    removed = False
    try:
        with winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_ALL_ACCESS) as key:
            try:
                val, _ = winreg.QueryValueEx(key, APP_NAME)
                winreg.DeleteValue(key, APP_NAME)
                print(f"[OK] Removed from {hive_name}\\{RUN_KEY}")
                print(f"     Was: {val}")
                removed = True
            except FileNotFoundError:
                print(f"[--] Not found in {hive_name}\\{RUN_KEY}")
    except PermissionError:
        print(f"[!!] Access denied: {hive_name}\\{RUN_KEY} — run as Administrator")
    except Exception as e:
        print(f"[!!] Error reading {hive_name}: {e}")
    return removed

print("=" * 55)
print("NexoraGuard — Startup Registry Cleanup")
print("=" * 55)

found_any = False
found_any |= remove_startup_entry(winreg.HKEY_CURRENT_USER,  "HKCU")
found_any |= remove_startup_entry(winreg.HKEY_LOCAL_MACHINE, "HKLM")

print("=" * 55)
if found_any:
    print("Done. NexoraGuard will NO LONGER auto-start on login.")
else:
    print("No NexoraGuard startup entries found.")
    print("The crash loop may be caused by a Scheduled Task instead.")
    print("Check Task Scheduler > Task Scheduler Library for 'NexoraGuard'.")

print("=" * 55)
input("\nPress Enter to exit...")
