#!/usr/bin/env python3
"""Verify the independent protocol seed against the pinned exported source."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profiles/0.160.0"
COMMIT = "a956835d020762cb2b570053af06f643a11c0ecc"


def main():
    manifest = json.loads((PROFILE / "source-manifest.json").read_text())
    assert manifest["source_commit"] == COMMIT
    count = 0
    for module in manifest["modules"]:
        for entry in module["sources"]:
            contents = (ROOT / "vendor/codex" / entry["path"]).read_bytes()
            assert hashlib.sha256(contents).hexdigest() == entry["sha256"], entry["path"]
            git_blob = hashlib.sha1(b"blob " + str(len(contents)).encode() + b"\0" + contents).hexdigest()
            assert git_blob == entry["git_blob"], entry["path"]
            count += 1
    catalogs = []
    for entry in manifest["existing_catalogs"]:
        contents = (ROOT / entry["path"]).read_bytes()
        assert hashlib.sha256(contents).hexdigest() == entry["sha256"], entry["path"]
        catalog = json.loads(contents)
        assert catalog["source_commit"] == COMMIT
        count_key = "event_count" if "events" in catalog else "metric_count"
        assert catalog[count_key] == entry["count"], entry["path"]
        catalogs.append({"path": entry["path"], "count": entry["count"]})
    assert not manifest["qualification"]["complete_network_entry_inventory"]
    assert not manifest["qualification"]["differential_qualified"]
    print(json.dumps({"result": "pass", "source_commit": COMMIT, "source_entries": count, "modules": len(manifest["modules"]), "catalogs": catalogs, "qualification": "source_provenance_only"}, indent=2))


if __name__ == "__main__":
    main()
