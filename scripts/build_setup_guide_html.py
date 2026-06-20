#!/usr/bin/env python3
"""
build_setup_guide_html.py — turn docs/START_HERE.md into a single, fully self-contained
IoTSentinel-Setup-Guide.html that ships inside the downloaded image package.

Non-technical buyers won't open a .md on GitHub, so the release/artifact includes a
double-clickable HTML. It is rendered entirely at BUILD time (Python `markdown`) and
all images are inlined - raster screenshots as base64 data URIs (shrunk with Pillow
when available), the flow diagram as inline SVG - so the file works **offline**, with
no CDN, no JavaScript, and no external files. That matters because a user may open the
guide on the same phone that is connected to the offline IoTSentinel-Setup hotspot.

Usage:
    python scripts/build_setup_guide_html.py [output.html] [source.md]
Defaults: output = IoTSentinel-Setup-Guide.html, source = docs/START_HERE.md
"""
import base64
import io
import re
import sys
from pathlib import Path

import markdown  # required (pure-Python); install with: pip install markdown

REPO = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "IoTSentinel-Setup-Guide.html"
SRC = Path(sys.argv[2]) if len(sys.argv) > 2 else REPO / "docs" / "START_HERE.md"

MAX_IMG_WIDTH = 1100   # screenshots are 1600-2560px wide; shrink to keep the file small

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IoTSentinel - Setup Guide</title>
<style>
  :root {{ --accent:#1976d2; --ink:#1a2230; --muted:#5b6b7f; --line:#e3e8ef; --bg:#f6f8fb; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
         font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:820px; margin:0 auto; padding:32px 20px 80px; }}
  .card {{ background:#fff; border:1px solid var(--line); border-radius:16px;
          padding:28px 34px; box-shadow:0 6px 24px rgba(20,40,80,.06); }}
  h1 {{ font-size:2rem; margin:.2em 0 .4em; }}
  h2 {{ font-size:1.35rem; margin:1.8em 0 .5em; padding-top:.6em; border-top:1px solid var(--line); }}
  h1, h2 {{ color:var(--ink); }}
  a {{ color:var(--accent); }}
  code {{ background:#eef2f7; padding:.12em .4em; border-radius:6px; font-size:.92em; }}
  pre code {{ display:block; padding:12px 14px; overflow:auto; }}
  blockquote {{ margin:1em 0; padding:.6em 1em; background:#eef5ff; border-left:4px solid var(--accent);
               border-radius:0 10px 10px 0; color:var(--ink); }}
  table {{ border-collapse:collapse; width:100%; margin:1em 0; }}
  th, td {{ border:1px solid var(--line); padding:9px 12px; text-align:left; vertical-align:top; }}
  th {{ background:#f0f4f9; }}
  ol, ul {{ padding-left:1.4em; }}
  li {{ margin:.3em 0; }}
  img {{ max-width:100%; height:auto; display:block; margin:1.2em auto; border-radius:12px;
        border:1px solid var(--line); box-shadow:0 4px 18px rgba(20,40,80,.10); }}
  .diagram {{ text-align:center; margin:1.4em 0; }}
  .diagram svg {{ max-width:520px; height:auto; }}
  .brand {{ color:var(--accent); font-weight:700; letter-spacing:.02em; }}
  footer {{ text-align:center; color:var(--muted); font-size:.85rem; margin-top:24px; }}
  @media print {{ body{{background:#fff}} .card{{box-shadow:none;border:none;padding:0}} }}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <p class="brand">IoTSentinel</p>
    {content}
  </div>
  <footer>IoTSentinel - home network security. github.com/ritiksah141/iotsentinel</footer>
</div>
</body>
</html>
"""


def _encode_raster(path: Path) -> str | None:
    """Return a base64 data URI for a PNG/JPEG, resized/recompressed when possible."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
    try:
        from PIL import Image  # optional — only to shrink large screenshots
        im = Image.open(io.BytesIO(data))
        if im.width > MAX_IMG_WIDTH:
            h = round(im.height * MAX_IMG_WIDTH / im.width)
            im = im.resize((MAX_IMG_WIDTH, h), Image.LANCZOS)
            buf = io.BytesIO()
            if mime == "image/png":
                im.save(buf, format="PNG", optimize=True)
            else:
                im.convert("RGB").save(buf, format="JPEG", quality=82)
            data = buf.getvalue()
    except Exception:
        pass  # Pillow missing or odd image — embed the original bytes
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"


def embed_images(html: str, base_dir: Path) -> str:
    """Make every <img> self-contained: SVGs are inlined, rasters become data URIs."""
    def repl(m: re.Match) -> str:
        tag = m.group(0)
        src_m = re.search(r'src="([^"]+)"', tag)
        if not src_m:
            return tag
        src = src_m.group(1)
        if src.startswith(("http://", "https://", "data:")):
            return tag
        path = (base_dir / src).resolve()
        if path.suffix.lower() == ".svg":
            try:
                return f'<div class="diagram">{path.read_text(encoding="utf-8")}</div>'
            except OSError:
                print(f"WARNING: svg not found: {src}", file=sys.stderr)
                return tag
        uri = _encode_raster(path)
        if uri is None:
            print(f"WARNING: image not found: {src}", file=sys.stderr)
            return tag
        return re.sub(r'src="[^"]+"', f'src="{uri}"', tag)
    return re.sub(r"<img\b[^>]*>", repl, html)


def main() -> int:
    if not SRC.exists():
        print(f"ERROR: source not found: {SRC}", file=sys.stderr)
        return 1
    md_text = SRC.read_text(encoding="utf-8")
    body = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "sane_lists", "attr_list"],
    )
    body = embed_images(body, SRC.parent)
    OUT.write_text(TEMPLATE.format(content=body), encoding="utf-8")
    print(f"Wrote {OUT} ({OUT.stat().st_size // 1024} KB, offline/self-contained) from {SRC.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
