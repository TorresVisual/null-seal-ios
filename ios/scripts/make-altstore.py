#!/usr/bin/env python3
"""AltStore source for the mirror's releases (#84). Stdlib only; runs in the public mirror's CI.

  make-altstore.py <ipa> <tag> <build-number> <out.json>   write the source for one release
  make-altstore.py --check <altstore.json> [--resolve]      validate; --resolve also fetches the URLs

The file is a release asset (releases/latest/download/altstore.json), not a committed file: the
mirror is force-pushed as a snapshot, so a committed copy would be wiped. One version per file;
AltStore offers the update because the newest release always carries the newest version.
"""
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

REPO = "TorresVisual/null-seal-ios"
BASE = f"https://github.com/{REPO}"
BUNDLE_ID = "app.nullseal.ios"
SOURCE_URL = f"{BASE}/releases/latest/download/altstore.json"
# Only these hosts may appear: no relay or other endpoint URL belongs in this file (#14).
HOSTS = {"github.com", "raw.githubusercontent.com"}


def build(ipa: Path, tag: str, build_no: str, now: datetime) -> dict:
    data = ipa.read_bytes()
    return {
        "name": "Null Seal",
        "identifier": BUNDLE_ID + ".source",
        "sourceURL": SOURCE_URL,
        "apps": [{
            "name": "Null Seal",
            "bundleIdentifier": BUNDLE_ID,
            "developerName": "Null Seal",
            "subtitle": "Personal password manager",
            "localizedDescription": "Zero-knowledge password manager.",
            "iconURL": f"https://raw.githubusercontent.com/{REPO}/main/ios/icon.png",
            "tintColor": "000000",
            "versions": [{
                "version": tag.removeprefix("v"),
                "buildVersion": build_no,
                "date": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "downloadURL": f"{BASE}/releases/download/{tag}/NullSeal-{tag}.ipa",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "minOSVersion": "17.0",
            }],
            "appPermissions": {"entitlements": [], "privacy": {}},
        }],
        "news": [],
    }


def check(src: dict, resolve: bool = False) -> None:
    """Raise AssertionError on the first problem."""
    (app,) = src["apps"]
    assert app["bundleIdentifier"] == BUNDLE_ID, "bundle id"
    (v,) = app["versions"]
    assert re.fullmatch(r"\d+\.\d+\.\d+(-[\w.]+)?", v["version"]), f"version {v['version']!r}"
    assert v["size"] > 0 and re.fullmatch(r"[0-9a-f]{64}", v["sha256"]), "size/sha256"
    assert v["downloadURL"].startswith(f"{BASE}/releases/download/"), "downloadURL"
    for url in re.findall(r"https?://[^\s\"]+", json.dumps(src)):
        assert urlparse(url).hostname in HOSTS, f"host not allowed: {urlparse(url).hostname}"
    if resolve:
        for url in (src["sourceURL"], v["downloadURL"]):
            with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=30) as r:
                assert r.status == 200, f"{url} -> {r.status}"


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "--check":
        check(json.loads(Path(a[1]).read_text()), "--resolve" in a)
        print("altstore.json ok")
    else:
        ipa, tag, build_no, out = a
        Path(out).write_text(json.dumps(build(Path(ipa), tag, build_no, datetime.now(timezone.utc)), indent=2) + "\n")
