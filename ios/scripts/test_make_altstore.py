"""Run: python ios/scripts/test_make_altstore.py"""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import importlib.util

spec = importlib.util.spec_from_file_location("m", Path(__file__).with_name("make-altstore.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class AltStore(unittest.TestCase):
    def src(self, tag="v1.2.3"):
        with tempfile.NamedTemporaryFile(suffix=".ipa", delete=False) as f:
            f.write(b"ipa-bytes")
        return m.build(Path(f.name), tag, "7", datetime(2026, 1, 1, tzinfo=timezone.utc))

    def test_valid(self):
        s = self.src()
        m.check(s)
        v = s["apps"][0]["versions"][0]
        self.assertEqual((v["version"], v["size"]), ("1.2.3", 9))
        self.assertTrue(v["downloadURL"].endswith("/v1.2.3/NullSeal-v1.2.3.ipa"))

    def test_rejects_foreign_host(self):
        s = self.src()
        s["apps"][0]["localizedDescription"] = "relay at https://relay.example.com/"
        with self.assertRaises(AssertionError):
            m.check(s)

    def test_rejects_bad_version(self):
        with self.assertRaises(AssertionError):
            m.check(self.src("vNext"))


if __name__ == "__main__":
    unittest.main()
