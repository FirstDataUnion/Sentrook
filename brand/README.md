# Sentrook logo

| File | Use |
|---|---|
| `sentrook-mark.svg` | Master. One path on a 512 square, `fill="currentColor"`, so it takes the text colour of the page it sits in. Inline it where the page theme can change (the plugin dashboards). |
| `sentrook-mark-black.svg`, `sentrook-mark-white.svg` | The mark in a fixed colour, for places that ignore `currentColor` (an `<img>` tag, GitHub Markdown). |
| `sentrook-tile.svg`, `sentrook-icon-512.png` | The store icon: white mark on FIDU purple `#3e1964`, rounded square. The PNG is what plugin stores take. |
| `tiles/` | Other colour options for the tile, each as SVG and 512 px PNG. |

Only `sentrook-mark.svg` is edited by hand. Everything else comes from it:

```bash
python3 brand/build.py
```

The PNGs need Inkscape or `rsvg-convert`. To add a colour option, add a line to `TILES` in `build.py` and rerun.

The mark keeps its shape down to about 32 px. At 20 to 24 px the shield outline and the gaps between the feathers
blur, leaving the outline of the wings and the crossed tips.
