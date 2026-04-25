"""
fix_icon.py — Convert any image (PNG/JPEG/etc.) into a valid multi-size Win32 ICO.
Inno Setup requires a real ICO with at least 256x256, 48x48, 32x32, 16x16 layers.

Usage:
    python fix_icon.py                   # converts logo.ico -> logo.ico (in-place)
    python fix_icon.py myimage.png       # converts any source image
    python fix_icon.py myimage.png out.ico
"""
import sys
import os
import shutil
from PIL import Image

# ── Config ────────────────────────────────────────────────────────────────────
SIZES = [256, 48, 32, 16]   # all layers Inno Setup + Windows shell expect

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# Resolve source and destination from CLI args or use defaults
if len(sys.argv) >= 3:
    src_path = sys.argv[1]
    dst_path = sys.argv[2]
elif len(sys.argv) == 2:
    src_path = sys.argv[1]
    dst_path = os.path.splitext(sys.argv[1])[0] + ".ico"
else:
    src_path = os.path.join(PROJECT_ROOT, "logo.ico")   # default: existing file
    dst_path = os.path.join(PROJECT_ROOT, "logo.ico")   # overwrite in-place


def make_ico(src: str, dst: str):
    print(f"Source : {src}")

    if not os.path.isfile(src):
        print(f"[ERROR] File not found: {src}")
        sys.exit(1)

    # Open and inspect original
    img = Image.open(src)
    print(f"Format : {img.format}  |  Size: {img.size}  |  Mode: {img.mode}")

    # Convert to RGBA so transparency is preserved properly in every layer
    img = img.convert("RGBA")

    # If the source is square, great. If not, pad to square with transparency.
    w, h = img.size
    if w != h:
        side = max(w, h)
        square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
        square.paste(img, ((side - w) // 2, (side - h) // 2))
        img = square
        print(f"Padded : {w}x{h} → {side}x{side} (added transparent border)")

    # Build one resampled frame per required size
    frames = []
    for size in SIZES:
        frame = img.resize((size, size), Image.LANCZOS)
        frames.append(frame)
        print(f"Layer  : {size}x{size}  OK")

    # Back up the old file if we are overwriting
    if os.path.isfile(dst) and os.path.abspath(src) == os.path.abspath(dst):
        backup = dst + ".bak"
        shutil.copy2(dst, backup)
        print(f"Backup : {backup}")

    # Save as a genuine ICO — Pillow writes the ICONDIR / ICONDIRENTRY headers
    frames[0].save(
        dst,
        format="ICO",
        sizes=[(s, s) for s in SIZES],
        append_images=frames[1:],
    )

    size_kb = os.path.getsize(dst) / 1024
    print(f"\n[OK] ICO written : {dst}  ({size_kb:.1f} KB)")
    print("     Layers      : " + ", ".join(f"{s}x{s}" for s in SIZES))
    print("\nInno Setup and Windows shell will now accept this icon.")


if __name__ == "__main__":
    make_ico(src_path, dst_path)
