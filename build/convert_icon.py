#!/usr/bin/env python3
"""Regenerate the Windows icon from the PNG artwork.

JsOwl embeds img/jsowl.ico into the Windows executables (rsrc turns it
into a Win32 resource), so the .ico must be a real ICO container rather
than a renamed PNG. Keep this asset in sync whenever img/jsowl.png
changes:

    python build/convert_icon.py

The output path defaults to img/jsowl.ico, so the icon keeps its place.
Requires Pillow (PIL) for resizing and ICO writing.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image

# Classic Windows icon grid. 256 records as 0 in an ICO directory entry
# and is stored as PNG; the smaller sizes are written as BMP DIBs so the
# icon stays crisp in every Explorer view.
DEFAULT_SIZES = (16, 32, 48, 64, 128, 256)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert a PNG source into a multi-size Windows .ico.")
    parser.add_argument(
        "-s", "--source", default="img/jsowl.png",
        help="source PNG (default: img/jsowl.png)")
    parser.add_argument(
        "-o", "--output", default="img/jsowl.ico",
        help="output .ico (default: img/jsowl.ico, keeps the icon path)")
    parser.add_argument(
        "--sizes", type=int, nargs="+", default=list(DEFAULT_SIZES),
        help="square sizes to embed (default: 16 32 48 64 128 256)")
    args = parser.parse_args()

    source, output = Path(args.source), Path(args.output)
    if not source.is_file():
        parser.error(f"source PNG not found: {source}")

    image = Image.open(source)
    if image.mode not in ("RGBA", "LA"):
        image = image.convert("RGBA")

    sizes = sorted({(size, size) for size in args.sizes})
    image.save(output, format="ICO", sizes=sizes)

    names = ", ".join(f"{size}x{size}" for size, _ in sizes)
    print(f"wrote {output} ({len(sizes)} sizes: {names})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())