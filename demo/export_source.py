#!/usr/bin/env python3
"""Export one stopped Mission checkout into a deterministic source archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence

MAX_FILES = 10_000
MAX_BYTES = 64 << 20
_EXCLUDED = frozenset({".git", ".shadow-mission", "__pycache__"})
_MAX_FORBIDDEN_VALUES = 64
_MAX_FORBIDDEN_VALUE_BYTES = 4096
_MAX_FORBIDDEN_INPUT_BYTES = 512 << 10
_CREDENTIAL_NAME = re.compile(
    r"^(?:\.env(?:\..*)?|\.aws|\.ssh|\.npmrc|\.pypirc|credentials?|secrets?|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|.*(?:api[_-]?key|access[_-]?token).*)$",
    re.IGNORECASE,
)


class ExportError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def safe_relative(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ExportError("source path escaped checkout") from error
    pure = PurePosixPath(relative.as_posix())
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ExportError("source path is unsafe")
    if any(part in _EXCLUDED for part in pure.parts):
        raise ExportError("source path enters private state")
    if any(_CREDENTIAL_NAME.fullmatch(part) for part in pure.parts):
        raise ExportError("source path has a credential-like name")
    return pure.as_posix()


def source_paths(root: Path) -> Iterable[Path]:
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name, reverse=True)
        except OSError as error:
            raise ExportError("cannot walk final checkout") from error
        for child in children:
            if child.name in _EXCLUDED:
                continue
            relative = safe_relative(child, root)
            try:
                metadata = child.lstat()
            except OSError as error:
                raise ExportError("cannot inspect final checkout") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise ExportError("final checkout contains a symbolic link")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(child)
            elif stat.S_ISREG(metadata.st_mode):
                yield child
            else:
                raise ExportError("final checkout contains a special file")


def file_digest(path: Path, canaries: Sequence[bytes]) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    overlap = max((len(item) for item in canaries), default=1) - 1
    prior = b""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                material = prior + chunk
                if any(canary and canary in material for canary in canaries):
                    raise ExportError("secret canary survived source export")
                prior = material[-overlap:] if overlap else b""
                digest.update(chunk)
    except ExportError:
        raise
    except OSError as error:
        raise ExportError("cannot read final checkout file") from error
    return digest.hexdigest(), size


def git_output(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ("git", "-C", str(root), *arguments),
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ExportError("cannot inspect final checkout Git state") from error
    return result.stdout


def build_manifest(root: Path, canaries: Sequence[bytes]) -> dict:
    files: list[dict] = []
    total = 0
    for path in sorted(source_paths(root), key=lambda item: item.relative_to(root).as_posix()):
        relative = safe_relative(path, root)
        metadata = path.lstat()
        digest, size = file_digest(path, canaries)
        if size != metadata.st_size:
            raise ExportError("final checkout changed during export")
        total += size
        if len(files) >= MAX_FILES or total > MAX_BYTES:
            raise ExportError("final checkout exceeds export bounds")
        files.append(
            {
                "path": relative,
                "mode": stat.S_IMODE(metadata.st_mode) & 0o777,
                "size": size,
                "sha256": digest,
            }
        )
    tree_digest = hashlib.sha256(canonical_json({"files": files})).hexdigest()
    dirty = tuple(
        sorted(
            line
            for line in git_output(
                root,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ).splitlines()
            if line
        )
    )
    manifest = {
        "schema_version": "0.1",
        "final_commit": git_output(root, "rev-parse", "--verify", "HEAD").strip(),
        "dirty_state": dirty,
        "working_tree_digest": tree_digest,
        "files": files,
    }
    manifest["record_digest"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
    return manifest


def write_archive(root: Path, path: Path, manifest: dict) -> None:
    with tarfile.open(path, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for record in manifest["files"]:
            source = root.joinpath(*PurePosixPath(record["path"]).parts)
            metadata_before = source.lstat()
            if not stat.S_ISREG(metadata_before.st_mode) or source.is_symlink():
                raise ExportError("final checkout changed during archive creation")
            info = tarfile.TarInfo(record["path"])
            info.size = record["size"]
            info.mode = record["mode"]
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(source, flags)
            with os.fdopen(descriptor, "rb") as handle:
                archive.addfile(info, handle)
            metadata_after = source.lstat()
            if (
                metadata_before.st_dev,
                metadata_before.st_ino,
                metadata_before.st_size,
                metadata_before.st_mtime_ns,
            ) != (
                metadata_after.st_dev,
                metadata_after.st_ino,
                metadata_after.st_size,
                metadata_after.st_mtime_ns,
            ):
                raise ExportError("final checkout changed during archive creation")


def atomic_outputs(root: Path, archive_path: Path, manifest_path: Path, canaries: Sequence[bytes]) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    if archive_path.parent.resolve() != manifest_path.parent.resolve():
        raise ExportError("archive and manifest must share one output directory")
    manifest = build_manifest(root, canaries)
    with tempfile.TemporaryDirectory(dir=archive_path.parent, prefix=".source-export-") as temporary:
        temporary_root = Path(temporary)
        temporary_archive = temporary_root / "final-source.tar"
        temporary_manifest = temporary_root / "final-source-manifest.json"
        write_archive(root, temporary_archive, manifest)
        temporary_manifest.write_bytes(canonical_json(manifest) + b"\n")
        for output in (temporary_archive, temporary_manifest):
            with output.open("rb") as handle:
                os.fsync(handle.fileno())
        os.replace(temporary_archive, archive_path)
        os.replace(temporary_manifest, manifest_path)
        directory = os.open(archive_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _read_forbidden_values_from_stdin(enabled: bool) -> tuple[bytes, ...]:
    if not enabled:
        return ()
    payload = sys.stdin.buffer.read(_MAX_FORBIDDEN_INPUT_BYTES + 1)
    if len(payload) > _MAX_FORBIDDEN_INPUT_BYTES:
        raise ExportError("forbidden value descriptor exceeds its byte limit")
    try:
        value = json.loads(payload)
        if (
            not isinstance(value, dict)
            or set(value) != {"forbidden_values"}
            or not isinstance(value["forbidden_values"], list)
            or not value["forbidden_values"]
            or len(value["forbidden_values"]) > _MAX_FORBIDDEN_VALUES
            or canonical_json(value) + b"\n" != payload
        ):
            raise ExportError("forbidden value descriptor is invalid")
        result: list[bytes] = []
        for item in value["forbidden_values"]:
            if (
                not isinstance(item, str)
                or not item
                or "\x00" in item
                or "\r" in item
                or "\n" in item
            ):
                raise ExportError("forbidden value descriptor is invalid")
            encoded = item.encode("utf-8")
            if len(encoded) > _MAX_FORBIDDEN_VALUE_BYTES:
                raise ExportError("forbidden value descriptor is invalid")
            result.append(encoded)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise ExportError("forbidden value descriptor is invalid") from error
    if len(result) != len(set(result)):
        raise ExportError("forbidden value descriptor is invalid")
    return tuple(result)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--repo", type=Path, required=True)
    value.add_argument("--archive", type=Path, required=True)
    value.add_argument("--manifest", type=Path, required=True)
    value.add_argument("--secret-canary", action="append", default=[])
    value.add_argument("--forbidden-values-stdin", action="store_true")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        root = arguments.repo.resolve(strict=True)
        if not root.is_dir() or arguments.repo.is_symlink():
            raise ExportError("final checkout root is invalid")
        argument_canaries = tuple(
            value.encode("utf-8") for value in arguments.secret_canary if value
        )
        private_canaries = _read_forbidden_values_from_stdin(
            arguments.forbidden_values_stdin
        )
        atomic_outputs(
            root,
            arguments.archive,
            arguments.manifest,
            (*argument_canaries, *private_canaries),
        )
    except ExportError as error:
        print(f"source export failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
