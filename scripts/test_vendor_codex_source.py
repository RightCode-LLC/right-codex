#!/usr/bin/env python3
"""Small source-integrity checks; no network, Cargo or credentials."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("vendor-codex-source.py")
SPEC = importlib.util.spec_from_file_location("vendor_codex_source", SCRIPT)
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)


class PinnedSourceIntegrity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.tree = root / "codex"
        self.tree.mkdir()
        (self.tree / "plain").write_text("fixed")
        (self.tree / "link").symlink_to("plain")
        self.original_destination, self.original_lock = vendor.DESTINATION, vendor.LOCK
        self.addCleanup(self.restore_paths)
        vendor.DESTINATION, vendor.LOCK = self.tree, root / "lock.json"
        entries = vendor.inventory(self.tree)
        vendor.LOCK.write_text(json.dumps({
            "source_commit": vendor.COMMIT,
            "repository": vendor.REPOSITORY,
            "files": entries,
            "files_sha256": hashlib.sha256(vendor.canonical(entries)).hexdigest(),
        }))

    def restore_paths(self):
        vendor.DESTINATION, vendor.LOCK = self.original_destination, self.original_lock

    def test_exact_inventory_accepts(self):
        self.assertEqual(vendor.check()["files"], 2)

    def test_changed_contents_reject_without_overwrite(self):
        (self.tree / "plain").write_text("changed")
        with self.assertRaisesRegex(ValueError, "vendor drift"):
            vendor.check()
        self.assertEqual((self.tree / "plain").read_text(), "changed")

    def test_changed_symlink_rejects(self):
        (self.tree / "link").unlink()
        (self.tree / "link").symlink_to("wrong")
        with self.assertRaisesRegex(ValueError, "vendor drift"):
            vendor.check()

    def test_wrong_commit_rejects(self):
        locked = json.loads(vendor.LOCK.read_bytes())
        locked["source_commit"] = "0" * 40
        vendor.LOCK.write_text(json.dumps(locked))
        with self.assertRaisesRegex(ValueError, "fixed commit"):
            vendor.check()


if __name__ == "__main__":
    unittest.main()
