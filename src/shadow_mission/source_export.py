"""Host-side validation and safe extraction for final Mission source archives."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .protocol import DIGEST_PATTERN, canonical_json

MAX_SOURCE_FILES = 10_000
MAX_SOURCE_BYTES = 64 << 20
_EXCLUDED_COMPONENTS = frozenset({".git", ".shadow-mission", "__pycache__"})
_CREDENTIAL_NAME = re.compile(
    r"^(?:\.env(?:\..*)?|\.aws|\.ssh|\.npmrc|\.pypirc|credentials?|secrets?|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|.*(?:api[_-]?key|access[_-]?token).*)$",
    re.IGNORECASE,
)


class SourceArchiveError(ValueError):
    """A final-source archive or manifest violates its sealed contract."""


class SourceFileRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=4096)
    mode: int = Field(ge=0, le=0o777)
    size: int = Field(ge=0, le=MAX_SOURCE_BYTES)
    sha256: str = Field(pattern=DIGEST_PATTERN)


class FinalSourceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^0\.1$")
    final_commit: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    dirty_state: tuple[str, ...]
    working_tree_digest: str = Field(pattern=DIGEST_PATTERN)
    files: tuple[SourceFileRecord, ...]
    record_digest: str = Field(pattern=DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_manifest(self) -> FinalSourceManifest:
        paths = [item.path for item in self.files]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("source manifest paths are not sorted and unique")
        if len(paths) > MAX_SOURCE_FILES:
            raise ValueError("source manifest exceeds its file bound")
        if sum(item.size for item in self.files) > MAX_SOURCE_BYTES:
            raise ValueError("source manifest exceeds its byte bound")
        for item in self.files:
            validate_member_name(item.path)
        expected_tree = working_tree_digest(self.files)
        if self.working_tree_digest != expected_tree:
            raise ValueError("source manifest tree digest differs")
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        expected = hashlib.sha256(canonical_json(value)).hexdigest()
        if supplied != expected:
            raise ValueError("source manifest record digest differs")
        return self


@dataclass(frozen=True)
class ValidatedSourceArchive:
    archive_path: Path
    manifest_path: Path
    archive_digest: str
    manifest_digest: str
    manifest: FinalSourceManifest


def validate_member_name(name: str) -> PurePosixPath:
    """Return one safe relative POSIX member path."""

    if not name or "\\" in name or "\x00" in name:
        raise SourceArchiveError("source member name is invalid")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SourceArchiveError("source member path escapes the checkout")
    if any(part in _EXCLUDED_COMPONENTS for part in path.parts):
        raise SourceArchiveError("source member enters a private directory")
    if any(_CREDENTIAL_NAME.fullmatch(part) for part in path.parts):
        raise SourceArchiveError("source member has a credential-like name")
    return path


def working_tree_digest(files: Sequence[SourceFileRecord]) -> str:
    payload = {
        "files": [
            item.model_dump(mode="json")
            for item in sorted(files, key=lambda record: record.path)
        ]
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except OSError as error:
        raise SourceArchiveError("cannot read final-source artifact") from error
    return digest.hexdigest()


def load_manifest(path: Path) -> FinalSourceManifest:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise SourceArchiveError("source manifest is not a regular file")
        payload = path.read_bytes()
        value = json.loads(payload)
        if not isinstance(value, Mapping) or canonical_json(value) + b"\n" != payload:
            raise SourceArchiveError("source manifest is not canonical JSON")
        return FinalSourceManifest.model_validate(value)
    except SourceArchiveError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SourceArchiveError("source manifest is invalid") from error


def validate_source_archive(
    archive_path: Path,
    manifest_path: Path,
    *,
    secret_canaries: Sequence[bytes] = (),
) -> ValidatedSourceArchive:
    """Validate exact archive membership, metadata, content, and manifest binding."""

    manifest = load_manifest(manifest_path)
    try:
        metadata = archive_path.lstat()
        if archive_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise SourceArchiveError("source archive is not a regular file")
    except OSError as error:
        raise SourceArchiveError("cannot inspect source archive") from error
    expected = {item.path: item for item in manifest.files}
    observed: set[str] = set()
    total_bytes = 0
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if names != sorted(names) or len(names) != len(set(names)):
                raise SourceArchiveError("source archive members are not sorted and unique")
            if len(names) > MAX_SOURCE_FILES:
                raise SourceArchiveError("source archive exceeds its file bound")
            for member in members:
                validate_member_name(member.name)
                if not member.isfile() or member.linkname:
                    raise SourceArchiveError("source archive contains a non-regular member")
                record = expected.get(member.name)
                if record is None:
                    raise SourceArchiveError("source archive contains an unmanifested member")
                if member.size != record.size or member.mode & 0o777 != record.mode:
                    raise SourceArchiveError("source archive metadata differs from manifest")
                total_bytes += member.size
                if total_bytes > MAX_SOURCE_BYTES:
                    raise SourceArchiveError("source archive exceeds its byte bound")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise SourceArchiveError("source archive member cannot be read")
                digest = hashlib.sha256()
                overlap = max((len(canary) for canary in secret_canaries), default=1) - 1
                prior = b""
                while True:
                    chunk = extracted.read(1 << 20)
                    if not chunk:
                        break
                    material = prior + chunk
                    if any(
                        canary and canary in material for canary in secret_canaries
                    ):
                        raise SourceArchiveError("secret canary survived source export")
                    prior = material[-overlap:] if overlap else b""
                    digest.update(chunk)
                if digest.hexdigest() != record.sha256:
                    raise SourceArchiveError("source archive content differs from manifest")
                observed.add(member.name)
    except SourceArchiveError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise SourceArchiveError("source archive is invalid") from error
    if observed != set(expected):
        raise SourceArchiveError("source archive omits a manifest member")
    return ValidatedSourceArchive(
        archive_path=archive_path,
        manifest_path=manifest_path,
        archive_digest=_sha256_file(archive_path),
        manifest_digest=_sha256_file(manifest_path),
        manifest=manifest,
    )


def safe_extract_source(
    validated: ValidatedSourceArchive,
    destination: Path,
) -> Path:
    """Extract a previously validated archive without following links."""

    if destination.exists():
        raise SourceArchiveError("source extraction destination already exists")
    destination.mkdir(parents=True, mode=0o700)
    root = destination.resolve(strict=True)
    try:
        with tarfile.open(validated.archive_path, mode="r:") as archive:
            for record in validated.manifest.files:
                member = archive.getmember(record.path)
                relative = validate_member_name(record.path)
                target = root.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if target.exists() or target.is_symlink():
                    raise SourceArchiveError("source extraction target already exists")
                resolved_parent = target.parent.resolve(strict=True)
                if resolved_parent != root and root not in resolved_parent.parents:
                    raise SourceArchiveError("source extraction parent escaped")
                source = archive.extractfile(member)
                if source is None:
                    raise SourceArchiveError("source archive member cannot be read")
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    record.mode,
                )
                try:
                    with os.fdopen(descriptor, "wb") as output:
                        for chunk in iter(lambda: source.read(1 << 20), b""):
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                except BaseException:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    raise
                os.chmod(target, record.mode)
        for record in validated.manifest.files:
            target = root.joinpath(*PurePosixPath(record.path).parts)
            if target.stat().st_size != record.size or _sha256_file(target) != record.sha256:
                raise SourceArchiveError("extracted source differs from manifest")
    except SourceArchiveError:
        raise
    except (OSError, tarfile.TarError, KeyError) as error:
        raise SourceArchiveError("safe source extraction failed") from error
    return root
