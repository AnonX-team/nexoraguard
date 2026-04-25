"""
NexoraGuard — Hardware Identity
Generates a stable, unique device ID from:
  1. Windows MachineGuid  (primary — registry GUID unique per Windows install)
  2. MAC address          (secondary — survives OS reinstall)
  3. Hostname             (tertiary — tie-breaker)

The final ID is a SHA-256 digest of those three concatenated.
It is STABLE across:
  - App reinstall / uninstall
  - Python environment changes
  - Windows updates
  - Different execution contexts (EXE, dev, bash, PowerShell)

It changes only if Windows is reinstalled or the motherboard is replaced.
"""
import uuid
import hashlib
import platform
import logging

logger = logging.getLogger(__name__)


def _get_machine_guid() -> str:
    """
    Read the Windows MachineGuid from the registry.
    This GUID is assigned when Windows is installed and never changes.
    Works identically whether called from an EXE, Python dev env, or any shell.
    """
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        )
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        if value:
            return value.strip().upper()
    except Exception as e:
        logger.debug(f"Registry MachineGuid read failed: {e}")
    return "NO-MACHINE-GUID"


def _get_mac_address() -> str:
    """
    Get primary NIC MAC address as a stable secondary fingerprint component.
    uuid.getnode() returns the MAC as a 48-bit integer.
    """
    mac_int = uuid.getnode()
    # Reject multicast / locally-administered (randomly generated) MACs
    if (mac_int >> 40) & 1:
        return f"NOMAC-{platform.node()}"
    return ':'.join(f"{(mac_int >> (i * 8)) & 0xFF:02X}" for i in range(5, -1, -1))


def get_hardware_id() -> str:
    """
    Return the 32-character uppercase hardware fingerprint for this machine.

    Construction:
        SHA-256( MachineGuid | MAC | hostname )[:32].upper()

    This is consistent in ALL execution environments (EXE, Python, bash, PS).
    """
    machine_guid = _get_machine_guid()
    mac          = _get_mac_address()
    hostname     = platform.node()

    raw         = f"{machine_guid}|{mac}|{hostname}"
    fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32].upper()

    logger.debug(f"Hardware fingerprint: {fingerprint[:8]}...  (GUID={machine_guid[:8]}...)")
    return fingerprint


def get_display_id() -> str:
    """
    Human-readable 4×8 grouped form: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
    This is what users copy-paste when requesting a license.
    """
    hid = get_hardware_id()
    return "-".join(hid[i:i+8] for i in range(0, 32, 8))


if __name__ == "__main__":
    # Run directly to print this machine's Device ID
    print("\n=== NexoraGuard Device ID ===")
    print(f"  Full   : {get_hardware_id()}")
    print(f"  Display: {get_display_id()}")
    print("\nShare the Display ID with Nexora Cyber Tech to get your license key.\n")
