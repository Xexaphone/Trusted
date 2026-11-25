#!/usr/bin/env python3
"""Package the extension for store upload.

Creates dist/site-inspector-firefox.zip and dist/site-inspector-chrome.zip with
manifest.json at the ZIP root (stores reject ZIPs that contain the folder itself).
The Chrome build drops the Firefox-only `browser_specific_settings` key.

Usage: python3 build.py
"""
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
FILES = ["popup.html", "popup.css", "popup.js", "report.html"]


def build(name: str, manifest: dict) -> Path:
    out = DIST / f"site-inspector-{name}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
        for f in FILES:
            zf.write(ROOT / f, arcname=f)
    return out


def main() -> None:
    DIST.mkdir(exist_ok=True)
    manifest = json.loads((ROOT / "manifest.json").read_text())

    chrome_manifest = {k: v for k, v in manifest.items() if k != "browser_specific_settings"}

    for path in (build("firefox", manifest), build("chrome", chrome_manifest)):
        print(f"Built {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
