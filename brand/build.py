"""Rebuild the Sentrook logo variants from the master mark.

sentrook-mark.svg is the only hand-edited file. Everything else in this folder
is written by this script:

    python3 brand/build.py

Writes the fixed-colour marks, one tile SVG per entry in TILES, and a 512 px
PNG of each tile. PNGs need Inkscape or rsvg-convert; without either, only the
SVGs are rebuilt. To add a colour option, add a line to TILES and rerun.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MASTER = HERE / "sentrook-mark.svg"
TILE_DIR = HERE / "tiles"

# name: (tile background, mark colour). Colours are the FIDU site palette.
TILES = {
    "purple-white": ("#3e1964", "#ffffff"),
    "purple-lavender": ("#3e1964", "#eddcff"),
    "lavender-purple": ("#eddcff", "#3e1964"),
    "plum-white": ("#2b1440", "#ffffff"),
    "green-white": ("#2e6417", "#ffffff"),
    "black-white": ("#14161a", "#ffffff"),
}
PRIMARY = "purple-white"

SIZE = 512
MARK_SCALE = 0.72  # mark size inside the tile; the rest is padding
CORNER_RADIUS = 96
PNG_SIZE = 512

INKSCAPE_APP = Path("/Applications/Inkscape.app/Contents/MacOS/inkscape")


def mark_path() -> str:
    match = re.search(r' d="([^"]+)"', MASTER.read_text())
    if not match:
        sys.exit(f"no path data in {MASTER}")
    return match.group(1)


def svg(body: str) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SIZE} {SIZE}">{body}</svg>\n'


def tile_svg(d: str, background: str, ink: str) -> str:
    offset = SIZE / 2 * (1 - MARK_SCALE)
    transform = f"matrix({MARK_SCALE} 0 0 {MARK_SCALE} {offset:g} {offset:g})"
    return svg(
        f'<rect width="{SIZE}" height="{SIZE}" rx="{CORNER_RADIUS}" fill="{background}"/>'
        f'<path fill="{ink}" transform="{transform}" d="{d}"/>'
    )


def png_renderer() -> list[str] | None:
    inkscape = shutil.which("inkscape") or (str(INKSCAPE_APP) if INKSCAPE_APP.exists() else None)
    if inkscape:
        return [
            inkscape,
            "--export-type=png",
            "-w",
            str(PNG_SIZE),
            "-h",
            str(PNG_SIZE),
            "--export-filename",
        ]
    rsvg = shutil.which("rsvg-convert")
    if rsvg:
        return [rsvg, "-w", str(PNG_SIZE), "-h", str(PNG_SIZE), "-o"]
    return None


def render_png(renderer: list[str], source: Path, target: Path) -> None:
    subprocess.run([*renderer, str(target), str(source)], check=True, capture_output=True)


def main() -> None:
    d = mark_path()
    written: list[Path] = []

    for name, colour in (("black", "#000000"), ("white", "#ffffff")):
        target = HERE / f"sentrook-mark-{name}.svg"
        target.write_text(svg(f'<path fill="{colour}" d="{d}"/>'))
        written.append(target)

    TILE_DIR.mkdir(exist_ok=True)
    tiles: dict[str, Path] = {}
    for name, (background, ink) in TILES.items():
        target = TILE_DIR / f"sentrook-tile-{name}.svg"
        target.write_text(tile_svg(d, background, ink))
        tiles[name] = target
        written.append(target)

    primary = HERE / "sentrook-tile.svg"
    primary.write_text(tiles[PRIMARY].read_text())
    written.append(primary)

    renderer = png_renderer()
    if renderer is None:
        print("no Inkscape or rsvg-convert found: PNGs not rebuilt", file=sys.stderr)
    else:
        for name, source in tiles.items():
            target = TILE_DIR / f"sentrook-icon-{name}-{PNG_SIZE}.png"
            render_png(renderer, source, target)
            written.append(target)
        target = HERE / f"sentrook-icon-{PNG_SIZE}.png"
        render_png(renderer, primary, target)
        written.append(target)

    for path in written:
        print(path.relative_to(HERE))


if __name__ == "__main__":
    main()
