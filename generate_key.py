"""
NexoraGuard — Admin License Key Generator
Nexora Cyber Tech

USAGE:
    python generate_key.py
    python generate_key.py --device "XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"

HOW IT WORKS:
    1. Customer opens NexoraGuard.exe (no license.txt present)
    2. License wall appears, showing their unique Device ID (e.g. A3F9B2C1-...)
    3. Customer sends you the Device ID on WhatsApp: +92 342 4217045
    4. You run this script, enter their Device ID, copy the 16-char key
    5. Customer creates license.txt beside NexoraGuard.exe and pastes the key
    6. They click "Re-check License" — dashboard unlocks

IMPORTANT:
    The LICENSE_SALT below MUST match the value in backend/license_manager.py.
    If you ever change the salt, all previously issued keys will stop working.
"""

import hashlib
import sys
import argparse
import datetime

# ── Must match backend/license_manager.py exactly ────────────────────────────
LICENSE_SALT = "NexoraGuard_Secure_2026"


def generate_key(device_id: str) -> str:
    """
    Generate a 16-character license key for a given Device ID.

    Args:
        device_id: The Device ID shown on the customer's license wall.
                   Dashes and spaces are stripped automatically.
                   Case-insensitive.

    Returns:
        16-character uppercase hex license key.
    """
    clean_id = device_id.strip().upper().replace("-", "").replace(" ", "")

    if len(clean_id) < 8:
        raise ValueError(
            f"Device ID is too short ({len(clean_id)} chars after stripping). "
            "It should be 32 characters. Check the value and try again."
        )

    raw = clean_id + LICENSE_SALT
    raw_key = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()
    return "-".join(raw_key[i:i+4] for i in range(0, 16, 4))


def print_banner():
    print()
    print("=" * 54)
    print("  NexoraGuard License Key Generator")
    print("  Nexora Cyber Tech  |  ADMIN USE ONLY")
    print("=" * 54)
    print()


def interactive_mode():
    print_banner()
    print("Instructions:")
    print("  1. Ask the customer to open NexoraGuard.exe")
    print("  2. The license wall shows their Device ID")
    print("  3. Enter that Device ID below")
    print()

    while True:
        device_id = input("  Customer Device ID: ").strip()
        if not device_id:
            print("  [!] No input. Please enter the Device ID.\n")
            continue

        try:
            key = generate_key(device_id)
            break
        except ValueError as e:
            print(f"  [!] Error: {e}\n")
            continue

    # Clean display ID for readability
    clean = device_id.strip().upper().replace("-", "").replace(" ", "")
    display_id = "-".join(clean[i:i+8] for i in range(0, min(32, len(clean)), 8))

    print()
    print("=" * 54)
    print(f"  Device ID : {display_id}")
    print(f"  Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print()
    print(f"  LICENSE KEY:  {key}")
    print("=" * 54)
    print()
    print("  Instructions for customer:")
    print(f"  1. Create a file named  license.txt")
    print(f"  2. Place it in the SAME folder as NexoraGuard.exe")
    print(f"  3. Open license.txt and paste ONLY the key:")
    print(f"     {key}")
    print(f"  4. Save the file, then click 'Re-check License'")
    print()

    # Ask to generate another key
    again = input("  Generate another key? (y/n): ").strip().lower()
    if again == "y":
        print()
        interactive_mode()


def cli_mode(device_id: str):
    print_banner()
    try:
        key = generate_key(device_id)
    except ValueError as e:
        print(f"  [ERROR] {e}")
        sys.exit(1)

    clean = device_id.strip().upper().replace("-", "").replace(" ", "")
    display_id = "-".join(clean[i:i+8] for i in range(0, min(32, len(clean)), 8))

    print(f"  Device ID  : {display_id}")
    print(f"  License Key: {key}")
    print()
    print(f"  Tell the customer to paste  {key}  into license.txt")
    print(f"  File must be in the same folder as NexoraGuard.exe")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NexoraGuard Admin License Key Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--device", "-d",
        metavar="DEVICE_ID",
        help="Customer Device ID (32 hex chars, dashes optional)"
    )
    args = parser.parse_args()

    if args.device:
        cli_mode(args.device)
    else:
        interactive_mode()
