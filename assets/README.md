# Brand assets

`mark.svg` is the logo: three open arcs, an ensō. `mark-small.svg` is the same
mark with the finest arc dropped and the rest thickened.

## Why two cuts

A 1.8px stroke on a 64px canvas is a third of a pixel at 16px. It does not
render as a faint line, it renders as a grey smudge that makes the whole mark
look blurry. Rather than ship that, sizes at or below 32px use the two-arc cut,
which keeps the same silhouette with strokes thick enough to survive.

Use `mark.svg` at 48px and above, `mark-small.svg` below that.

## Regenerating

Geometry is generated rather than hand-written, so the arcs stay evenly spaced
and the endpoints land exactly on the circle. The script in the commit that
added these files builds the path data from (radius, start angle, sweep,
stroke width) tuples.

Icons are rasterised with resvg and resized with `sips`:

```bash
npx @resvg/resvg-js-cli --fit-width 1024 assets/icon.svg /tmp/icon.png
sips -z 128 128 /tmp/icon.png
```

**Do not use `qlmanage` for this.** It ships with macOS and looks like the
obvious choice, but it flattens alpha onto white — the corners outside the
squircle come out opaque white instead of transparent, which is invisible on a
white page and glaring in the Dock. It also renders an SVG at its intrinsic
size inside the thumbnail box rather than scaling up, so a small source lands
in the corner of a large canvas.

The sources are authored at 1024 square regardless of target size; downscaling
gives cleaner antialiasing on a curve this thin than rendering small directly.

## The tile is a superellipse, not a rounded rect

macOS icon shapes are superellipses. At the same corner radius a rounded rect
has a visible straight-to-curve join, and the icon reads as subtly wrong in a
row of real ones. The generator samples `|x|^n + |y|^n = 1` at n=5.

The macOS tile also covers only 82% of the canvas. That margin is not padding
to taste — the Dock sizes every icon to the full canvas, so an icon drawn edge
to edge renders visibly larger and squarer than its neighbours. Browser
toolbars have no such convention, so the extension tiles fill 98%.

The app icon set comes from `cargo tauri icon`, which also emits `android/` and
`ios/` directories — delete them, this is a macOS-only app.
