#!/usr/bin/env python3
"""Export one pinned official Git tree without reading working-tree files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib


COMMIT = "a956835d020762cb2b570053af06f643a11c0ecc"
REPOSITORY = "https://github.com/openai/codex"
PROJECT = Path(__file__).resolve().parents[1]
DESTINATION = PROJECT / "vendor" / "codex"
LOCK = PROJECT / "vendor" / "codex-source-lock.json"
CRATES = {
    "codex-api": "codex-rs/codex-api",
    "codex-client": "codex-rs/codex-client",
    "codex-http-client": "codex-rs/http-client",
    "codex-login": "codex-rs/login",
    "codex-protocol": "codex-rs/protocol",
}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(directory: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for base, directories, files in os.walk(directory, followlinks=False):
        # os.walk puts symlinks to directories in directories, even without following them.
        paths = files + [name for name in directories if (Path(base) / name).is_symlink()]
        for name in sorted(paths):
            path = Path(base) / name
            info = path.lstat()
            relative = path.relative_to(directory).as_posix()
            if stat.S_ISLNK(info.st_mode):
                contents = os.fsencode(os.readlink(path))
                kind = "symlink"
                sha = hashlib.sha256(contents).hexdigest()
                size = len(contents)
                mode = "120000"
            elif stat.S_ISREG(info.st_mode):
                kind = "file"
                sha = file_sha(path)
                size = info.st_size
                mode = "100755" if info.st_mode & stat.S_IXUSR else "100644"
            else:
                raise ValueError(f"unsupported source entry: {relative}")
            result[relative] = {"kind": kind, "mode": mode, "size": size, "sha256": sha}
    return dict(sorted(result.items()))


def git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def check() -> dict[str, object]:
    if DESTINATION.is_symlink() or not DESTINATION.is_dir() or not LOCK.is_file():
        raise ValueError("pinned vendor tree and source lock are required")
    locked = json.loads(LOCK.read_bytes())
    if locked.get("source_commit") != COMMIT or locked.get("repository") != REPOSITORY:
        raise ValueError("official source lock does not identify the fixed commit")
    actual = inventory(DESTINATION)
    if actual != locked.get("files"):
        expected = locked.get("files", {})
        changed = sorted(path for path in set(actual) | set(expected) if actual.get(path) != expected.get(path))
        raise ValueError(f"vendor drift: {len(changed)} entries; first={changed[:8]}")
    tree_sha = hashlib.sha256(canonical(actual)).hexdigest()
    if tree_sha != locked.get("files_sha256"):
        raise ValueError("official source inventory digest does not match")
    return {
        "source_commit": COMMIT,
        "files": len(actual),
        "files_sha256": tree_sha,
        "source_lock_sha256": file_sha(LOCK),
    }


def export(repository: Path) -> dict[str, object]:
    resolved = git(repository, "rev-parse", "--verify", f"{COMMIT}^{{commit}}")
    if resolved != COMMIT:
        raise ValueError("source commit resolution changed")
    if DESTINATION.exists() or DESTINATION.is_symlink() or LOCK.exists():
        # Repeated exports are read-only; local edits are never erased.
        return check()
    tree_oid = git(repository, "rev-parse", f"{COMMIT}^{{tree}}")
    if any(line.startswith("160000 ") for line in git(repository, "ls-tree", "-r", COMMIT).splitlines()):
        raise ValueError("git archive does not populate submodules")
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="codex-fixed-source-", dir=DESTINATION.parent) as temporary:
        temporary_path = Path(temporary)
        archive = temporary_path / "source.tar"
        subprocess.run(
            ["git", "-C", str(repository), "archive", "--format=tar", f"--output={archive}", COMMIT],
            check=True,
        )
        staged = temporary_path / "codex"
        staged.mkdir()
        with tarfile.open(archive, "r:") as source:
            source.extractall(staged, filter="data")
        files = inventory(staged)
        workspace = tomllib.loads((staged / "codex-rs" / "Cargo.toml").read_text())
        toolchain = tomllib.loads((staged / "codex-rs" / "rust-toolchain.toml").read_text())
        if workspace["workspace"]["package"]["version"] != "0.160.0":
            raise ValueError("unexpected official workspace version")
        for name, relative in CRATES.items():
            manifest = tomllib.loads((staged / relative / "Cargo.toml").read_text())
            if manifest["package"]["name"] != name:
                raise ValueError(f"official crate name changed: {name}")
        locked = {
            "schema_version": 1,
            "repository": REPOSITORY,
            "source_commit": COMMIT,
            "git_tree_oid": tree_oid,
            "git_archive_sha256": file_sha(archive),
            "export_method": "git archive --format=tar <fixed-commit>",
            "working_tree_files_read": False,
            "source_category": "pinned-third-party-source",
            "workspace_version": workspace["workspace"]["package"]["version"],
            "workspace_edition": workspace["workspace"]["package"]["edition"],
            "rust_toolchain": toolchain["toolchain"]["channel"],
            "crate_paths": CRATES,
            "root_cargo_patch_required": workspace.get("patch", {}),
            "file_count": len(files),
            "file_bytes": sum(entry["size"] for entry in files.values()),
            "files_sha256": hashlib.sha256(canonical(files)).hexdigest(),
            "files": files,
        }
        staged_lock = temporary_path / "codex-source-lock.json"
        staged_lock.write_text(json.dumps(locked, sort_keys=True, indent=2) + "\n")
        staged.rename(DESTINATION)
        staged_lock.rename(LOCK)
    return check()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, help="local official Git object repository")
    parser.add_argument("--check", action="store_true", help="verify every exported entry against the source lock")
    args = parser.parse_args()
    if not args.check and args.source_repo is None:
        parser.error("--source-repo is required for export")
    try:
        result = check() if args.check else export(args.source_repo.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"official source export failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
