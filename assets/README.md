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

Icons are rasterised with Quick Look and resized with `sips`, both of which
ship with macOS:

```bash
qlmanage -t -s 1024 -o /tmp/out assets/icon.svg
sips -z 128 128 /tmp/out/icon.svg.png
```

The sources are authored at 1024 square even when the target is 32px: Quick
Look renders an SVG at its intrinsic size inside the thumbnail box rather than
scaling it up, so a 32-unit source lands in the corner of a 1024 canvas.
Downscaling from 1024 also gives cleaner antialiasing on a curve this thin than
rendering small directly.

The app icon set comes from `cargo tauri icon`, which also emits `android/` and
`ios/` directories — delete them, this is a macOS-only app.
