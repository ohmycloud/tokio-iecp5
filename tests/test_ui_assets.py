"""Offline integrity checks for the original UI assets and package identities.

Run: python3 -m unittest discover -s tests -p 'test_ui_assets.py' -v
No third-party Python libraries or NSH runtime required.
"""
import importlib.util
import json
from pathlib import Path
import struct
import unittest
import xml.etree.ElementTree as ET
import zlib

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "ui" / "assets"
SVG = "{http://www.w3.org/2000/svg}"


def png_size_and_validate(path):
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise AssertionError(f"Invalid PNG signature: {path}")
    size = None
    image_data = bytearray()
    offset = 8
    ended = False
    while offset < len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        crc = struct.unpack_from(">I", data, offset + 8 + length)[0]
        if zlib.crc32(kind + payload) != crc:
            raise AssertionError(f"Invalid PNG chunk checksum: {path}")
        if kind == b"IHDR":
            size = struct.unpack_from(">II", payload)
        if kind == b"IDAT":
            image_data.extend(payload)
        if kind == b"IEND":
            ended = True
        offset += length + 12
    if not ended or not image_data or not zlib.decompress(image_data):
        raise AssertionError(f"Incomplete PNG: {path}")
    return size


class UIAssets(unittest.TestCase):
    def test_svg_sources_are_generated_and_self_contained(self):
        spec = importlib.util.spec_from_file_location("icon_generator", ROOT / "scripts" / "generate-icons.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        for role in ("client", "server"):
            self.assertEqual((ASSETS / f"app-{role}.svg").read_text(), generator.app_svg(role))
        paths = list(ASSETS.glob("*.svg")) + list((ASSETS / "glyphs").glob("*.svg"))
        self.assertEqual(len(paths), 2 + len(generator.GLYPHS))
        for path in paths:
            with self.subTest(path=path.name):
                root = ET.parse(path).getroot()
                self.assertEqual(root.tag, SVG + "svg")
                for element in root.iter():
                    self.assertNotIn(element.tag, [SVG + "script", SVG + "text", SVG + "image", SVG + "foreignObject"])
                    for name in element.attrib:
                        self.assertFalse(name.startswith("on") or name.endswith("href"))
        self.assertEqual((ROOT / "ui" / "shared" / "icon-data.ts").read_text(), generator.icon_data_module())
        for name, shapes in generator.GLYPHS.items():
            self.assertIn(shapes, (ASSETS / "glyphs" / f"{name}.svg").read_text())

    def test_app_pngs_are_complete_and_have_required_sizes(self):
        for role in ("client", "server"):
            for suffix, size in (("", 1024), ("-128", 128)):
                with self.subTest(role=role, size=size):
                    self.assertEqual(png_size_and_validate(ASSETS / f"app-{role}{suffix}.png"), (size, size))
        self.assertNotEqual((ASSETS / "app-client.png").read_bytes(), (ASSETS / "app-server.png").read_bytes())

    def test_package_identities_and_icon_paths_are_distinct(self):
        configs = []
        for role in ("client", "server"):
            directory = ROOT / "ui" / role
            config = json.loads((directory / "nsh.json").read_text())
            configs.append(config)
            self.assertEqual(config["id"], f"com.ohmycloud.iec104studio.{role}")
            self.assertEqual((directory / config["icon"]).resolve(), ASSETS / f"app-{role}.png")
            self.assertIn(f'launch("{role}")', (directory / "App.tsx").read_text())
            self.assertEqual(config["capabilities"], json.loads((ROOT / "ui" / "nsh.json").read_text())["capabilities"])
        self.assertNotEqual(configs[0]["name"], configs[1]["name"])
        self.assertNotEqual(configs[0]["id"], configs[1]["id"])
        self.assertNotEqual(configs[0]["icon"], configs[1]["icon"])


if __name__ == "__main__":
    unittest.main()
