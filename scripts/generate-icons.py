#!/usr/bin/env python3
"""Generate original IEC104 Studio SVGs and app PNGs (requires rsvg-convert).

Run from any directory: python3 scripts/generate-icons.py
Generated assets contain no fonts, external images, scripts or network references.
"""
from pathlib import Path
import argparse
import base64
import json
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "ui" / "assets"

GLYPHS = {
    "overview": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 18h7m-3.5-3.5v7"/>',
    "points": '<path d="M8 5h13M8 12h13M8 19h13"/><circle cx="3.5" cy="5" r=".6"/><circle cx="3.5" cy="12" r=".6"/><circle cx="3.5" cy="19" r=".6"/>',
    "traffic": '<path d="M3 7h17m-4-4 4 4-4 4M21 17H4m4-4-4 4 4 4"/>',
    "inspect": '<path d="m8 5-5 7 5 7m8-14 5 7-5 7m-3-16-2 18"/>',
    "server": '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 6.5h5M12 17.5h5"/>',
    "client": '<rect x="3" y="3" width="18" height="13" rx="2"/><path d="M8 21h8m-4-5v5M6 10h3l2-4 3 7 2-3h2"/>',
    "connect": '<path d="m8 3 2 5m6-5-2 5M6 8h12v3a6 6 0 0 1-12 0V8Zm6 9v4"/>',
    "disconnect": '<path d="m3 3 18 18M8 3l1 3m7-3-2 5M6 8v3a6 6 0 0 0 10.4 4M12 17v4M12 8h6v3"/>',
    "play": '<path d="m8 4 12 8-12 8V4Z"/>',
    "stop": '<rect x="5" y="5" width="14" height="14" rx="2"/>',
    "scan": '<path d="M8 3H4a1 1 0 0 0-1 1v4m13-5h4a1 1 0 0 1 1 1v4M3 16v4a1 1 0 0 0 1 1h4m13-5v4a1 1 0 0 1-1 1h-4M3 12h18"/>',
    "counter": '<path d="M5 20V10m7 10V4m7 16v-7M3 20h18"/>',
    "select": '<path d="M9 3H4a1 1 0 0 0-1 1v5m12-6h5a1 1 0 0 1 1 1v5M3 15v5a1 1 0 0 0 1 1h5m12-6v5a1 1 0 0 1-1 1h-5m-7-9 3 3 5-6"/>',
    "execute": '<path d="m13 2-9 12h7l-1 8 10-13h-7l0-7Z"/>',
    "save": '<path d="M5 3h12l4 4v13a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a2 2 0 0 1 2-2Z"/><path d="M7 3v6h9V3M7 21v-7h10v7"/>',
    "load": '<path d="M12 3v12m-4-4 4 4 4-4M4 15v5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5"/>',
    "settings": '<path d="M3 6h18M3 18h18"/><circle cx="8" cy="6" r="3" fill="#fff"/><circle cx="16" cy="18" r="3" fill="#fff"/>',
    "shield": '<path d="m12 3 9 4v5c0 5-5 8-9 10-4-2-9-5-9-10V7l9-4Z"/><path d="m8 12 3 3 5-6"/>',
}


def app_svg(role: str) -> str:
    accent = "#73D6BE" if role == "client" else "#F2A77C"
    mark = '''<rect x="244" y="275" width="536" height="350" rx="48" fill="#F0F5E9"/>
    <rect x="275" y="306" width="474" height="288" rx="24" fill="#193D38"/>
    <path d="M319 466h76l46-84 76 153 51-91h137" fill="none" stroke="#73D6BE" stroke-width="30" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M512 643v74m-107 0h214" fill="none" stroke="#F0F5E9" stroke-width="30" stroke-linecap="round"/>
    <circle cx="745" cy="685" r="91" fill="#E47C52" stroke="#142C29" stroke-width="14"/>
    <path d="M704 685h79m-31-31 31 31-31 31" fill="none" stroke="#FFF8ED" stroke-width="18" stroke-linecap="round" stroke-linejoin="round"/>''' if role == "client" else '''<rect x="273" y="240" width="478" height="180" rx="40" fill="#F0F5E9"/>
    <rect x="273" y="452" width="478" height="180" rx="40" fill="#F0F5E9"/>
    <circle cx="338" cy="330" r="19" fill="#D7774D"/><circle cx="338" cy="542" r="19" fill="#D7774D"/>
    <path d="M406 330h98m-98 212h98" fill="none" stroke="#234C41" stroke-width="24" stroke-linecap="round"/>
    <path d="M649 315v30m32-30v30m-32 182v30m32-30v30" fill="none" stroke="#91ADA0" stroke-width="10" stroke-linecap="round"/>
    <path d="M512 659v72M364 760v-29h296v29" fill="none" stroke="#F2A77C" stroke-width="24" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="364" cy="774" r="26" fill="#F2A77C"/><circle cx="512" cy="731" r="17" fill="#F2A77C"/><circle cx="660" cy="774" r="26" fill="#F2A77C"/>'''
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
  <defs>
    <linearGradient id="tile" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#2C5145"/><stop offset="1" stop-color="#102725"/></linearGradient>
    <radialGradient id="glow" cx=".18" cy=".1" r=".95"><stop stop-color="{accent}" stop-opacity=".15"/><stop offset="1" stop-color="{accent}" stop-opacity="0"/></radialGradient>
  </defs>
  <rect x="64" y="64" width="896" height="896" rx="205" fill="url(#tile)"/>
  <rect x="64" y="64" width="896" height="896" rx="205" fill="url(#glow)"/>
  <rect x="80" y="80" width="864" height="864" rx="191" fill="none" stroke="#BED4BF" stroke-opacity=".19" stroke-width="3"/>
  <path d="M212 200h72m-72 0v72m528-72h72v72M212 752v72h72m528-72v72h-72" fill="none" stroke="{accent}" stroke-opacity=".22" stroke-width="8" stroke-linecap="round"/>
  {mark}
</svg>
'''


def icon_data_module() -> str:
    """Embed small UI marks to avoid NSH 0.3 external-root asset path bugs.

    The full-sized packaging PNGs stay as files. Both independent app roots
    import this shared module without leaking absolute filesystem asset URLs.
    """
    def uri(path: Path, mime: str) -> str:
        return f"data:{mime};base64," + base64.b64encode(path.read_bytes()).decode("ascii")
    marks = {role: uri(ASSETS / f"app-{role}-128.png", "image/png") for role in ("client", "server")}
    glyphs = {name: uri(ASSETS / "glyphs" / f"{name}.svg", "image/svg+xml") for name in GLYPHS}
    return (
        "// Generated by scripts/generate-icons.py; do not edit.\n"
        "// Inline local bytes keep shared icons portable across independent NSH app roots.\n"
        + "export const marks = " + json.dumps(marks, indent=2) + " as const;\n"
        + "export const glyphs = " + json.dumps(glyphs, indent=2) + " as const;\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--svg-only", action="store_true", help="Write SVG sources without rendering PNG files")
    args = parser.parse_args()
    renderer = shutil.which("rsvg-convert")
    if not args.svg_only and not renderer:
        parser.error("rsvg-convert is required: brew install librsvg, or install librsvg2-bin on Debian/Ubuntu")
    ASSETS.mkdir(parents=True, exist_ok=True)
    (ASSETS / "glyphs").mkdir(exist_ok=True)
    for role in ("client", "server"):
        source = ASSETS / f"app-{role}.svg"
        source.write_text(app_svg(role), encoding="utf-8")
        if not args.svg_only:
            for size, suffix in ((1024, ""), (128, "-128")):
                destination = ASSETS / f"app-{role}{suffix}.png"
                subprocess.run([renderer, "--width", str(size), "--height", str(size), "--output", str(destination), str(source)], check=True)
                print(destination.relative_to(ROOT))
    for name, shapes in GLYPHS.items():
        svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{shapes}</svg>\n'
        (ASSETS / "glyphs" / f"{name}.svg").write_text(svg, encoding="utf-8")
    if not args.svg_only:
        (ROOT / "ui" / "shared" / "icon-data.ts").write_text(icon_data_module(), encoding="utf-8")
    print(f"Generated 2 original app icons and {len(GLYPHS)} interface glyphs.")


if __name__ == "__main__":
    main()
