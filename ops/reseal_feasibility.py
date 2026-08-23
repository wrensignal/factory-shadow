#!/usr/bin/env python3
"""Externally authorized feasibility-fixture re-seal workflow."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence


_BOOTSTRAP_ROOT = Path(__file__).resolve().parents[1]
_CANONICAL_FIXTURE = _BOOTSTRAP_ROOT / "tests" / "fixtures" / "feasibility"
_CANONICAL_PIN = (
    _BOOTSTRAP_ROOT / "tests" / "fixtures" / "feasibility-manifest.sha256"
)
_TRUSTED_SIGNERS_PATH = _BOOTSTRAP_ROOT / "ops" / "reseal-trusted-signers.sha256"
_TRUSTED_OPENSSL_PATHS = (
    Path("/opt/homebrew/bin/openssl"),
    Path("/usr/local/bin/openssl"),
    Path("/usr/bin/openssl"),
)
_SOURCE_ROOT = _BOOTSTRAP_ROOT / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from shadow_mission.feasibility import (  # noqa: E402
    run_dry_run,
    verify_sealed_fixture,
)
from shadow_mission.profile import (  # noqa: E402
    FactoryProfileError,
    compute_gate_surface_digest,
    compute_plugin_artifact_digest,
    validate_factory_profile,
)
from shadow_mission.protocol import canonical_json  # noqa: E402


_SCHEMA_VERSION = "0.1"
_OPERATION = "reseal-feasibility-fixture"
_REQUEST_ID = re.compile(r"^reseal-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_FIELDS = {
    "schema_version",
    "operation",
    "request_id",
    "created_at",
    "expires_at",
    "predecessor",
    "successor",
    "transition_basis",
    "gate_surface_digest",
    "installed_plugin_artifact_digest",
}
_STATE_DIGEST_FIELDS = {"profile_sha256", "manifest_sha256", "pin_sha256"}
_RECEIPT_FIELDS = {
    "schema_version",
    "operation",
    "status",
    "request_id",
    "request_digest",
    "signer_public_key_sha256",
    "signature_sha256",
    "predecessor",
    "successor",
    "applied_at",
    "offline_result_digest",
    "record_digest",
}
_CANDIDATE_FILES = {
    "factory-profile.json",
    "manifest.json",
    "manifest.sha256",
    "request.json",
}
_ALLOWED_PROFILE_DELTA = {
    "gate_surface_digest",
    "installed_plugin_artifact_digest",
    "resolved_plugin_source",
}
_TRANSITION_BASIS = {
    "authorization": "external-ed25519-signature-over-canonical-request",
    "derived_fields": {
        "resolved_plugin_source": "sha256:<installed_plugin_artifact_digest>",
    },
    "measured_fields": [
        "gate_surface_digest",
        "installed_plugin_artifact_digest",
    ],
    "precommit_check": "staged-run_dry_run-success-required-before-canonical-write",
    "predecessor_authority": "external-pin+verify_sealed_fixture",
    "preserved_fields": "all-other-profile-fields-byte-identical",
    "shadow_activation": "preserved-false",
    "signed_bindings": [
        "predecessor-digests",
        "successor-digests",
        "measured-current-bindings",
    ],
    "successor_derivation": "predecessor+disk-measured-current-bindings",
}
_MAX_REQUEST_BYTES = 64 * 1024
_MAX_RECORD_BYTES = 64 * 1024
_MAX_PROFILE_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_FIXTURE_FILE_BYTES = 16 * 1024 * 1024
_MAX_PUBLIC_KEY_BYTES = 64 * 1024
_MAX_TRUSTED_SIGNERS_BYTES = 64 * 1024
_SIGNATURE_BYTES = 64
_ED25519_SPKI_BYTES = 44
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_OPENSSL_TIMEOUT_SECONDS = 10


class ResealError(ValueError):
    """Raised when a re-seal trust or transaction check fails."""


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True)
class _Candidate:
    directory: Path
    profile_bytes: bytes
    profile: dict[str, Any]
    manifest_bytes: bytes
    manifest: dict[str, Any]
    pin_bytes: bytes
    pin_digest: str
    request_bytes: bytes
    request: dict[str, Any]


@dataclass(frozen=True)
class _CanonicalState:
    profile_bytes: bytes
    manifest_bytes: bytes
    pin_bytes: bytes
    profile_mode: int
    manifest_mode: int
    pin_mode: int


@dataclass(frozen=True)
class _SignatureBinding:
    public_key_sha256: str
    signature_sha256: str


@dataclass(frozen=True)
class _CurrentBindings:
    gate_surface_digest: str
    installed_plugin_artifact_digest: str


@dataclass(frozen=True)
class _Preflight:
    project_root: Path
    fixture: Path
    fixture_manifest_pin: Path
    candidate: _Candidate
    signature_binding: _SignatureBinding
    current_bindings: _CurrentBindings
    canonical_state: _CanonicalState


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json(value) + b"\n"


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey(key)
        value[key] = item
    return value


def _load_json(payload: bytes, description: str, *, canonical: bool) -> dict[str, Any]:
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=_object_from_pairs)
    except (UnicodeError, json.JSONDecodeError, _DuplicateKey) as error:
        raise ResealError(f"{description} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ResealError(f"{description} must be a JSON object")
    if canonical and _canonical_bytes(value) != payload:
        raise ResealError(f"{description} is not canonical")
    return value


def _validate_digest(value: Any, description: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ResealError(f"{description} is not a lowercase SHA-256 digest")
    return value


def _current_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else os.getuid()


def _read_bounded_regular(
    path: Path,
    *,
    maximum: int,
    description: str,
    exact_mode: int | None = None,
    require_owner: bool = False,
    require_single_link: bool = False,
    reject_shared_write: bool = False,
) -> tuple[bytes, int]:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise ResealError(f"cannot read {description}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ResealError(f"{description} must be a regular non-symlink file")
    if before.st_size < 0 or before.st_size > maximum:
        raise ResealError(f"{description} exceeds its byte bound")
    mode = stat.S_IMODE(before.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise ResealError(f"{description} mode must be {exact_mode:04o}")
    if require_owner and before.st_uid != _current_uid():
        raise ResealError(f"{description} owner differs")
    if require_single_link and before.st_nlink != 1:
        raise ResealError(f"{description} must have one filesystem link")
    if reject_shared_write and mode & 0o022:
        raise ResealError(f"{description} is writable outside its owner")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size > maximum
        ):
            raise ResealError(f"{description} changed while it was opened")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) > maximum
            or after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != len(payload)
        ):
            raise ResealError(f"{description} changed while it was read")
        return payload, mode
    except ResealError:
        raise
    except OSError as error:
        raise ResealError(f"cannot read {description}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_directory(
    path: Path,
    description: str,
    *,
    exact_mode: int | None = None,
    require_owner: bool = True,
    reject_shared_write: bool = False,
) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise ResealError(f"cannot access {description}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ResealError(f"{description} must be a non-symlink directory")
    mode = stat.S_IMODE(metadata.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise ResealError(f"{description} mode must be {exact_mode:04o}")
    if require_owner and metadata.st_uid != _current_uid():
        raise ResealError(f"{description} owner differs")
    if reject_shared_write and mode & 0o022:
        raise ResealError(f"{description} is writable outside its owner")


def _resolve_existing(path: Path, description: str) -> Path:
    try:
        before = os.lstat(path)
        resolved = path.resolve(strict=True)
        after = os.lstat(resolved)
    except OSError as error:
        raise ResealError(f"cannot resolve {description}") from error
    if stat.S_ISLNK(before.st_mode):
        raise ResealError(f"{description} must not be a symlink")
    if before.st_dev != after.st_dev or before.st_ino != after.st_ino:
        raise ResealError(f"{description} changed while it was resolved")
    return resolved


def _require_direct_file(path: Path, directory: Path, description: str) -> None:
    resolved = _resolve_existing(path, description)
    try:
        resolved_directory = directory.resolve(strict=True)
    except OSError as error:
        raise ResealError(f"cannot resolve {description} parent") from error
    if resolved.parent != resolved_directory:
        raise ResealError(f"{description} escapes its required directory")


def _resolved_is_within(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def _validate_protected_parent(
    path: Path,
    description: str,
    *,
    exact_mode: int | None = None,
) -> Path:
    _validate_directory(
        path.parent,
        f"{description} parent",
        exact_mode=exact_mode,
        require_owner=True,
        reject_shared_write=True,
    )
    try:
        return path.parent.resolve(strict=True)
    except OSError as error:
        raise ResealError(f"cannot resolve {description} parent") from error


def _validate_fixture_directory(fixture: Path) -> None:
    _validate_directory(fixture, "canonical fixture", require_owner=True)
    try:
        fixture_mode = stat.S_IMODE(os.lstat(fixture).st_mode)
        entries = list(os.scandir(fixture))
    except OSError as error:
        raise ResealError("cannot inspect canonical fixture") from error
    if fixture_mode & 0o022:
        raise ResealError("canonical fixture is writable outside its owner")
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as error:
            raise ResealError("cannot inspect canonical fixture entry") from error
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ResealError(
                "canonical fixture entries must be regular non-symlink files"
            )
        if metadata.st_uid != _current_uid():
            raise ResealError("canonical fixture entry owner differs")
        if metadata.st_nlink != 1:
            raise ResealError("canonical fixture entry must have one filesystem link")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ResealError(
                "canonical fixture entry is writable outside its owner"
            )

def _validate_anchored_state_paths(
    *,
    project_root: Path,
    fixture: Path,
    fixture_manifest_pin: Path,
) -> tuple[Path, Path, Path]:
    _validate_directory(
        _BOOTSTRAP_ROOT,
        "bootstrap root",
        require_owner=True,
        reject_shared_write=True,
    )
    bootstrap_root = _resolve_existing(_BOOTSTRAP_ROOT, "bootstrap root")
    _validate_directory(
        project_root,
        "project root",
        require_owner=True,
        reject_shared_write=True,
    )
    resolved_project_root = _resolve_existing(project_root, "project root")
    if resolved_project_root != bootstrap_root:
        raise ResealError("project root does not match the trusted bootstrap root")

    _validate_protected_parent(_CANONICAL_FIXTURE, "canonical fixture")
    _validate_protected_parent(_CANONICAL_PIN, "canonical fixture pin")
    canonical_fixture = _resolve_existing(
        _CANONICAL_FIXTURE,
        "trusted canonical fixture",
    )
    canonical_pin = _resolve_existing(
        _CANONICAL_PIN,
        "trusted canonical fixture pin",
    )
    resolved_fixture = _resolve_existing(fixture, "canonical fixture")
    resolved_pin = _resolve_existing(fixture_manifest_pin, "canonical fixture pin")
    if resolved_fixture != canonical_fixture:
        raise ResealError("fixture does not match the trusted canonical fixture")
    if resolved_pin != canonical_pin:
        raise ResealError("fixture pin does not match the trusted canonical pin")
    if resolved_fixture.parent != resolved_pin.parent:
        raise ResealError("trusted canonical state is not co-located")

    _validate_fixture_directory(resolved_fixture)
    _read_bounded_regular(
        resolved_pin,
        maximum=128,
        description="canonical fixture pin",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    return resolved_project_root, resolved_fixture, resolved_pin


def _parse_pin(payload: bytes, description: str) -> str:
    if len(payload) != 65 or not payload.endswith(b"\n"):
        raise ResealError(f"{description} is not canonical")
    try:
        value = payload[:-1].decode("ascii")
    except UnicodeError as error:
        raise ResealError(f"{description} is not canonical") from error
    return _validate_digest(value, description)


def _validate_manifest(
    value: Mapping[str, Any], description: str
) -> Mapping[str, str]:
    if (
        set(value) != {"schema_version", "files"}
        or value.get("schema_version") != "0.1"
    ):
        raise ResealError(f"{description} fields differ")
    files = value.get("files")
    if not isinstance(files, dict) or not files:
        raise ResealError(f"{description} file inventory is invalid")
    for name, digest in files.items():
        if (
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or name == "manifest.json"
        ):
            raise ResealError(f"{description} contains an unsafe file name")
        _validate_digest(digest, f"{description} file digest")
    if "factory-profile.json" not in files:
        raise ResealError(f"{description} omits the Factory profile")
    return files


def _validate_fixture_file_set(
    fixture: Path, manifest: Mapping[str, Any]
) -> None:
    expected = set(_validate_manifest(manifest, "candidate manifest"))
    try:
        actual = {
            entry.name
            for entry in os.scandir(fixture)
            if entry.name != "manifest.json"
        }
    except OSError as error:
        raise ResealError("cannot inspect canonical fixture file set") from error
    if actual != expected:
        raise ResealError("canonical fixture file set differs")


def _validate_request_schema(request: Mapping[str, Any]) -> None:
    if set(request) != _REQUEST_FIELDS:
        raise ResealError("request fields differ")
    if request.get("schema_version") != _SCHEMA_VERSION:
        raise ResealError("request schema differs")
    if request.get("operation") != _OPERATION:
        raise ResealError("request operation differs")
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
        raise ResealError("request ID is invalid")
    created_at = request.get("created_at")
    expires_at = request.get("expires_at")
    if type(created_at) is not int or type(expires_at) is not int:
        raise ResealError("request times must be integer Unix times")
    if created_at < 0 or expires_at <= created_at:
        raise ResealError("request time interval is invalid")

    for state_name in ("predecessor", "successor"):
        state_value = request.get(state_name)
        if (
            not isinstance(state_value, dict)
            or set(state_value) != _STATE_DIGEST_FIELDS
        ):
            raise ResealError(f"request {state_name} fields differ")
        for field_name in sorted(_STATE_DIGEST_FIELDS):
            _validate_digest(
                state_value[field_name],
                f"request {state_name} {field_name}",
            )
    predecessor = request["predecessor"]
    successor = request["successor"]
    if any(
        predecessor[field_name] == successor[field_name]
        for field_name in _STATE_DIGEST_FIELDS
    ):
        raise ResealError("request predecessor and successor states must differ")
    if request.get("transition_basis") != _TRANSITION_BASIS:
        raise ResealError("request transition basis differs")
    _validate_digest(request.get("gate_surface_digest"), "gate surface digest")
    _validate_digest(
        request.get("installed_plugin_artifact_digest"),
        "installed plugin artifact digest",
    )


def _validate_request_time(request: Mapping[str, Any], now: int) -> None:
    if type(now) is not int or now < 0:
        raise ResealError("current time must be a nonnegative integer Unix time")
    if request["created_at"] > now:
        raise ResealError("request is from the future")
    if request["expires_at"] <= now:
        raise ResealError("request has expired")

def _validate_request_not_future(request: Mapping[str, Any], now: int) -> None:
    if type(now) is not int or now < 0:
        raise ResealError("current time must be a nonnegative integer Unix time")
    if request["created_at"] > now:
        raise ResealError("request is from the future")


def _now(value: int | None) -> int:
    current = int(time.time()) if value is None else value
    if type(current) is not int or current < 0:
        raise ResealError("current time must be a nonnegative integer Unix time")
    return current


def _current_bindings(project_root: Path) -> _CurrentBindings:
    try:
        gate_digest = compute_gate_surface_digest(project_root)
        plugin_digest = compute_plugin_artifact_digest(project_root)
    except (FactoryProfileError, OSError, ValueError) as error:
        raise ResealError("cannot compute current Factory bindings") from error
    return _CurrentBindings(
        gate_surface_digest=gate_digest,
        installed_plugin_artifact_digest=plugin_digest,
    )


def _load_profile(
    payload: bytes, description: str, *, canonical: bool
) -> dict[str, Any]:
    profile = _load_json(payload, description, canonical=canonical)
    try:
        validate_factory_profile(profile)
    except (FactoryProfileError, TypeError, ValueError) as error:
        raise ResealError(
            f"{description} is not an approved Factory profile"
        ) from error
    return profile


def _validate_profile_transition(
    predecessor: Mapping[str, Any],
    successor: Mapping[str, Any],
    *,
    gate_digest: str,
    plugin_digest: str,
) -> None:
    try:
        predecessor_result = validate_factory_profile(predecessor)
        successor_result = validate_factory_profile(successor)
    except (FactoryProfileError, TypeError, ValueError) as error:
        raise ResealError("Factory profile transition validation failed") from error
    if predecessor_result.activation_enabled:
        raise ResealError("predecessor Factory profile must be inactive")
    if successor_result.activation_enabled:
        raise ResealError("successor Factory profile must be inactive")
    if successor.get("shadow_activation") != predecessor.get("shadow_activation"):
        raise ResealError("successor Factory profile must preserve Shadow activation")
    if successor.get("gate_surface_digest") != gate_digest:
        raise ResealError("successor Factory profile gate binding is stale")
    if successor.get("installed_plugin_artifact_digest") != plugin_digest:
        raise ResealError("successor Factory profile plugin binding is stale")
    if successor.get("resolved_plugin_source") != f"sha256:{plugin_digest}":
        raise ResealError("successor Factory profile source binding is stale")
    if set(successor) != set(predecessor):
        raise ResealError("successor Factory profile field inventory differs")

    predecessor_preserved = {
        name: value
        for name, value in predecessor.items()
        if name not in _ALLOWED_PROFILE_DELTA
    }
    successor_preserved = {
        name: value
        for name, value in successor.items()
        if name not in _ALLOWED_PROFILE_DELTA
    }
    if canonical_json(predecessor_preserved) != canonical_json(successor_preserved):
        raise ResealError(
            "successor Factory profile changes byte-preserved fields"
        )
    changed_fields = {
        name
        for name in predecessor
        if predecessor[name] != successor[name]
    }
    # A re-seal may move either measured binding independently. The gate surface
    # and the plugin artifact do not always change together, so require the
    # change set to be a non-empty SUBSET of the allowed delta rather than the
    # whole set. Fields outside the delta are byte-compared above.
    if not changed_fields:
        raise ResealError("predecessor Factory profile is already current")
    if not changed_fields <= _ALLOWED_PROFILE_DELTA:
        raise ResealError("successor Factory profile delta is not exact")


def _derive_successor_profile(
    predecessor: Mapping[str, Any],
    *,
    gate_digest: str,
    plugin_digest: str,
) -> dict[str, Any]:
    if (
        predecessor.get("gate_surface_digest") == gate_digest
        and predecessor.get("installed_plugin_artifact_digest") == plugin_digest
    ):
        raise ResealError("predecessor Factory profile is already current")
    successor = json.loads(canonical_json(predecessor))
    successor.update(
        {
            "gate_surface_digest": gate_digest,
            "installed_plugin_artifact_digest": plugin_digest,
            "resolved_plugin_source": f"sha256:{plugin_digest}",
        }
    )
    _validate_profile_transition(
        predecessor,
        successor,
        gate_digest=gate_digest,
        plugin_digest=plugin_digest,
    )
    return successor


def _successor_manifest(
    predecessor_manifest: Mapping[str, Any], profile_digest: str
) -> dict[str, Any]:
    files = dict(_validate_manifest(predecessor_manifest, "predecessor manifest"))
    files["factory-profile.json"] = profile_digest
    return {
        "schema_version": predecessor_manifest["schema_version"],
        "files": files,
    }


def _fsync_directory(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
    except OSError as error:
        raise ResealError("cannot make directory update durable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _exclusive_write(path: Path, payload: bytes, mode: int) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags, mode)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        raise ResealError("cannot create exclusive workflow file") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _create_candidate(directory: Path, files: Mapping[str, bytes]) -> None:
    if set(files) != _CANDIDATE_FILES:
        raise ResealError("candidate file set differs")
    try:
        os.mkdir(directory, 0o700)
        os.chmod(directory, 0o700)
    except OSError as error:
        raise ResealError("cannot create exclusive candidate directory") from error
    written: list[Path] = []
    try:
        _validate_directory(
            directory,
            "candidate directory",
            exact_mode=0o700,
            require_owner=True,
        )
        for name in (
            "factory-profile.json",
            "manifest.json",
            "manifest.sha256",
            "request.json",
        ):
            path = directory / name
            _exclusive_write(path, files[name], 0o600)
            written.append(path)
        _fsync_directory(directory)
        _fsync_directory(directory.parent)
    except Exception:
        for path in reversed(written):
            try:
                path.unlink()
            except OSError:
                pass
        try:
            directory.rmdir()
        except OSError:
            pass
        raise


def _validate_candidate_path(
    directory: Path,
    *,
    fixture: Path,
    fixture_pin: Path,
    must_exist: bool,
) -> Path:
    parent = _validate_protected_parent(directory, "candidate directory")
    if must_exist:
        _validate_directory(
            directory,
            "candidate directory",
            exact_mode=0o700,
            require_owner=True,
            reject_shared_write=True,
        )
        resolved = _resolve_existing(directory, "candidate directory")
    else:
        try:
            os.lstat(directory)
        except FileNotFoundError:
            resolved = parent / directory.name
        except OSError as error:
            raise ResealError("cannot inspect candidate directory") from error
        else:
            raise ResealError("candidate directory already exists")

    resolved_fixture = _resolve_existing(fixture, "canonical fixture")
    resolved_pin = _resolve_existing(fixture_pin, "canonical fixture pin")
    if _resolved_is_within(resolved, resolved_fixture) or resolved == resolved_pin:
        raise ResealError("candidate directory overlaps canonical state")
    return resolved


def prepare_reseal(
    *,
    project_root: Path,
    fixture: Path,
    fixture_manifest_pin: Path,
    candidate_dir: Path,
    valid_for_seconds: int = 3600,
    now: int | None = None,
) -> dict[str, Any]:
    resolved_project_root, resolved_fixture, resolved_pin = (
        _validate_anchored_state_paths(
            project_root=project_root,
            fixture=fixture,
            fixture_manifest_pin=fixture_manifest_pin,
        )
    )
    resolved_candidate = _validate_candidate_path(
        candidate_dir,
        fixture=resolved_fixture,
        fixture_pin=resolved_pin,
        must_exist=False,
    )
    if type(valid_for_seconds) is not int or valid_for_seconds <= 0:
        raise ResealError("request validity must be a positive integer")

    pin_bytes, _ = _read_bounded_regular(
        resolved_pin,
        maximum=128,
        description="canonical fixture pin",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    predecessor_manifest_digest = _parse_pin(pin_bytes, "canonical fixture pin")
    try:
        verify_sealed_fixture(
            resolved_fixture,
            expected_manifest_digest=predecessor_manifest_digest,
        )
    except Exception as error:
        raise ResealError("predecessor sealed fixture verification failed") from error

    _require_direct_file(
        resolved_fixture / "factory-profile.json",
        resolved_fixture,
        "predecessor Factory profile",
    )
    _require_direct_file(
        resolved_fixture / "manifest.json",
        resolved_fixture,
        "predecessor manifest",
    )
    predecessor_profile_bytes, _ = _read_bounded_regular(
        resolved_fixture / "factory-profile.json",
        maximum=_MAX_PROFILE_BYTES,
        description="predecessor Factory profile",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    predecessor_manifest_bytes, _ = _read_bounded_regular(
        resolved_fixture / "manifest.json",
        maximum=_MAX_MANIFEST_BYTES,
        description="predecessor manifest",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    if _sha256_bytes(predecessor_manifest_bytes) != predecessor_manifest_digest:
        raise ResealError("predecessor manifest changed after verification")
    predecessor_manifest = _load_json(
        predecessor_manifest_bytes,
        "predecessor manifest",
        canonical=False,
    )
    predecessor_files = _validate_manifest(
        predecessor_manifest,
        "predecessor manifest",
    )
    if predecessor_files["factory-profile.json"] != _sha256_bytes(
        predecessor_profile_bytes
    ):
        raise ResealError("predecessor profile digest differs from its manifest")
    predecessor_profile = _load_profile(
        predecessor_profile_bytes,
        "predecessor Factory profile",
        canonical=False,
    )

    current_bindings = _current_bindings(resolved_project_root)
    successor_profile = _derive_successor_profile(
        predecessor_profile,
        gate_digest=current_bindings.gate_surface_digest,
        plugin_digest=current_bindings.installed_plugin_artifact_digest,
    )
    successor_profile_bytes = _canonical_bytes(successor_profile)
    successor_profile_sha256 = _sha256_bytes(successor_profile_bytes)
    successor_manifest = _successor_manifest(
        predecessor_manifest,
        successor_profile_sha256,
    )
    successor_manifest_bytes = _canonical_bytes(successor_manifest)
    successor_manifest_sha256 = _sha256_bytes(successor_manifest_bytes)
    successor_pin_bytes = successor_manifest_sha256.encode("ascii") + b"\n"

    created_at = _now(now)
    request = {
        "schema_version": _SCHEMA_VERSION,
        "operation": _OPERATION,
        "request_id": f"reseal-{secrets.token_hex(16)}",
        "created_at": created_at,
        "expires_at": created_at + valid_for_seconds,
        "predecessor": {
            "profile_sha256": _sha256_bytes(predecessor_profile_bytes),
            "manifest_sha256": _sha256_bytes(predecessor_manifest_bytes),
            "pin_sha256": _sha256_bytes(pin_bytes),
        },
        "successor": {
            "profile_sha256": successor_profile_sha256,
            "manifest_sha256": successor_manifest_sha256,
            "pin_sha256": _sha256_bytes(successor_pin_bytes),
        },
        "transition_basis": _TRANSITION_BASIS,
        "gate_surface_digest": current_bindings.gate_surface_digest,
        "installed_plugin_artifact_digest": (
            current_bindings.installed_plugin_artifact_digest
        ),
    }
    _validate_request_schema(request)
    request_bytes = _canonical_bytes(request)
    if len(request_bytes) > _MAX_REQUEST_BYTES:
        raise ResealError("request exceeds its byte bound")

    _create_candidate(
        resolved_candidate,
        {
            "factory-profile.json": successor_profile_bytes,
            "manifest.json": successor_manifest_bytes,
            "manifest.sha256": successor_pin_bytes,
            "request.json": request_bytes,
        },
    )
    return {
        "schema_version": _SCHEMA_VERSION,
        "status": "prepared",
        "request_id": request["request_id"],
        "request_digest": _sha256_bytes(request_bytes),
        "expires_at": request["expires_at"],
    }


def _load_candidate(
    directory: Path,
    *,
    fixture: Path,
    fixture_pin: Path,
) -> _Candidate:
    resolved_directory = _validate_candidate_path(
        directory,
        fixture=fixture,
        fixture_pin=fixture_pin,
        must_exist=True,
    )
    try:
        names = {entry.name for entry in os.scandir(resolved_directory)}
    except OSError as error:
        raise ResealError("cannot inspect candidate directory") from error
    if names != _CANDIDATE_FILES:
        raise ResealError("candidate file set differs")
    descriptions = {
        "factory-profile.json": "candidate Factory profile",
        "manifest.json": "candidate manifest",
        "manifest.sha256": "candidate manifest pin",
        "request.json": "candidate request",
    }
    for name, description in descriptions.items():
        _require_direct_file(
            resolved_directory / name,
            resolved_directory,
            description,
        )

    profile_bytes, _ = _read_bounded_regular(
        resolved_directory / "factory-profile.json",
        maximum=_MAX_PROFILE_BYTES,
        description="candidate Factory profile",
        exact_mode=0o600,
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    manifest_bytes, _ = _read_bounded_regular(
        resolved_directory / "manifest.json",
        maximum=_MAX_MANIFEST_BYTES,
        description="candidate manifest",
        exact_mode=0o600,
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    pin_bytes, _ = _read_bounded_regular(
        resolved_directory / "manifest.sha256",
        maximum=128,
        description="candidate manifest pin",
        exact_mode=0o600,
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    request_bytes, _ = _read_bounded_regular(
        resolved_directory / "request.json",
        maximum=_MAX_REQUEST_BYTES,
        description="candidate request",
        exact_mode=0o600,
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    profile = _load_profile(
        profile_bytes,
        "candidate Factory profile",
        canonical=True,
    )
    manifest = _load_json(manifest_bytes, "candidate manifest", canonical=True)
    _validate_manifest(manifest, "candidate manifest")
    pin_digest = _parse_pin(pin_bytes, "candidate manifest pin")
    request = _load_json(request_bytes, "candidate request", canonical=True)
    _validate_request_schema(request)
    return _Candidate(
        directory=resolved_directory,
        profile_bytes=profile_bytes,
        profile=profile,
        manifest_bytes=manifest_bytes,
        manifest=manifest,
        pin_bytes=pin_bytes,
        pin_digest=pin_digest,
        request_bytes=request_bytes,
        request=request,
    )


def _validate_candidate_bindings(
    candidate: _Candidate,
    *,
    gate_digest: str,
    plugin_digest: str,
) -> None:
    request = candidate.request
    if request["gate_surface_digest"] != gate_digest:
        raise ResealError("request gate binding is stale")
    if request["installed_plugin_artifact_digest"] != plugin_digest:
        raise ResealError("request plugin binding is stale")

    successor = request["successor"]
    expected_successor = {
        "profile_sha256": _sha256_bytes(candidate.profile_bytes),
        "manifest_sha256": _sha256_bytes(candidate.manifest_bytes),
        "pin_sha256": _sha256_bytes(candidate.pin_bytes),
    }
    if successor != expected_successor:
        raise ResealError("candidate bytes differ from the signed successor")
    if candidate.pin_digest != expected_successor["manifest_sha256"]:
        raise ResealError("candidate pin differs from the candidate manifest")
    manifest_files = _validate_manifest(candidate.manifest, "candidate manifest")
    if manifest_files["factory-profile.json"] != expected_successor["profile_sha256"]:
        raise ResealError("candidate profile differs from the candidate manifest")

    try:
        profile_result = validate_factory_profile(candidate.profile)
    except (FactoryProfileError, TypeError, ValueError) as error:
        raise ResealError("candidate Factory profile validation failed") from error
    if profile_result.activation_enabled:
        raise ResealError("candidate Factory profile must be inactive")
    if candidate.profile.get("gate_surface_digest") != gate_digest:
        raise ResealError("candidate Factory profile gate binding is stale")
    if candidate.profile.get("installed_plugin_artifact_digest") != plugin_digest:
        raise ResealError("candidate Factory profile plugin binding is stale")
    if candidate.profile.get("resolved_plugin_source") != f"sha256:{plugin_digest}":
        raise ResealError("candidate Factory profile source binding is stale")


def _path_is_within(path: Path, directory: Path, description: str) -> bool:
    resolved_path = _resolve_existing(path, description)
    try:
        resolved_directory = directory.resolve(strict=True)
    except OSError as error:
        raise ResealError(f"cannot resolve {description} boundary") from error
    return _resolved_is_within(resolved_path, resolved_directory)


def _resolve_trusted_openssl() -> Path:
    for configured_path in _TRUSTED_OPENSSL_PATHS:
        if not configured_path.is_absolute():
            continue
        try:
            resolved = configured_path.resolve(strict=True)
            metadata = os.lstat(resolved)
        except OSError:
            continue
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            stat.S_ISREG(metadata.st_mode)
            and mode & 0o111
            and not mode & 0o022
            and os.access(resolved, os.X_OK)
        ):
            return resolved
    raise ResealError("trusted OpenSSL capability is unavailable")


def _load_trusted_signer_digests() -> frozenset[str]:
    _validate_protected_parent(
        _TRUSTED_SIGNERS_PATH,
        "trusted signer anchor",
    )
    payload, _ = _read_bounded_regular(
        _TRUSTED_SIGNERS_PATH,
        maximum=_MAX_TRUSTED_SIGNERS_BYTES,
        description="trusted signer anchor",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    if not payload or not payload.endswith(b"\n"):
        raise ResealError("trusted signer anchor is not canonical")
    try:
        lines = payload[:-1].decode("ascii").split("\n")
    except UnicodeError as error:
        raise ResealError("trusted signer anchor is not canonical") from error
    if (
        not lines
        or any(_DIGEST.fullmatch(line) is None for line in lines)
        or len(set(lines)) != len(lines)
    ):
        raise ResealError("trusted signer anchor is not canonical")
    return frozenset(lines)


def _verify_signature(
    *,
    candidate: _Candidate,
    signature: Path,
    trusted_public_key: Path,
) -> _SignatureBinding:
    public_key_parent = _validate_protected_parent(
        trusted_public_key,
        "trusted public key",
    )
    signature_parent = _validate_protected_parent(
        signature,
        "request signature",
    )
    resolved_public_key = _resolve_existing(
        trusted_public_key,
        "trusted public key",
    )
    resolved_signature = _resolve_existing(signature, "request signature")
    if resolved_public_key.parent != public_key_parent:
        raise ResealError("trusted public key escapes its protected parent")
    if resolved_signature.parent != signature_parent:
        raise ResealError("request signature escapes its protected parent")
    if _path_is_within(
        resolved_public_key,
        candidate.directory,
        "trusted public key",
    ):
        raise ResealError("trusted public key must be external to the candidate")
    if _path_is_within(
        resolved_signature,
        candidate.directory,
        "request signature",
    ):
        raise ResealError("request signature must be external to the candidate")

    public_key_bytes, _ = _read_bounded_regular(
        resolved_public_key,
        maximum=_MAX_PUBLIC_KEY_BYTES,
        description="trusted public key",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    signature_bytes, _ = _read_bounded_regular(
        resolved_signature,
        maximum=_SIGNATURE_BYTES + 1,
        description="request signature",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    if not public_key_bytes:
        raise ResealError("trusted public key is empty")
    if len(signature_bytes) != _SIGNATURE_BYTES:
        raise ResealError("request signature must be exactly 64 bytes")

    public_key_digest = _sha256_bytes(public_key_bytes)
    if public_key_digest not in _load_trusted_signer_digests():
        raise ResealError("trusted public key is not anchored")
    openssl = _resolve_trusted_openssl()

    try:
        with tempfile.TemporaryDirectory(
            prefix=".shadow-reseal-signature-"
        ) as temporary:
            temporary_path = Path(temporary)
            key_snapshot = temporary_path / "trusted-public-key.pem"
            signature_snapshot = temporary_path / "request.sig"
            request_snapshot = temporary_path / "request.json"
            _exclusive_write(key_snapshot, public_key_bytes, 0o600)
            _exclusive_write(signature_snapshot, signature_bytes, 0o600)
            _exclusive_write(request_snapshot, candidate.request_bytes, 0o600)
            environment = {"LANG": "C", "LC_ALL": "C"}
            key_result = subprocess.run(
                [
                    str(openssl),
                    "pkey",
                    "-pubin",
                    "-in",
                    str(key_snapshot),
                    "-outform",
                    "DER",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=_OPENSSL_TIMEOUT_SECONDS,
                check=False,
                close_fds=True,
                env=environment,
                shell=False,
            )
            if key_result.returncode != 0:
                raise ResealError("trusted public key conversion failed")
            public_key_der = key_result.stdout
            if (
                len(public_key_der) != _ED25519_SPKI_BYTES
                or not public_key_der.startswith(_ED25519_SPKI_PREFIX)
            ):
                raise ResealError("trusted public key is not an Ed25519 SPKI")
            verification = subprocess.run(
                [
                    str(openssl),
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_snapshot),
                    "-rawin",
                    "-in",
                    str(request_snapshot),
                    "-sigfile",
                    str(signature_snapshot),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_OPENSSL_TIMEOUT_SECONDS,
                check=False,
                close_fds=True,
                env=environment,
                shell=False,
            )
    except ResealError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        raise ResealError("request signature verification failed") from error
    if verification.returncode != 0:
        raise ResealError("request signature verification failed")
    return _SignatureBinding(
        public_key_sha256=public_key_digest,
        signature_sha256=_sha256_bytes(signature_bytes),
    )


def _read_canonical_state(fixture: Path, pin: Path) -> _CanonicalState:
    _validate_fixture_directory(fixture)
    _require_direct_file(
        fixture / "factory-profile.json",
        fixture,
        "canonical Factory profile",
    )
    _require_direct_file(
        fixture / "manifest.json",
        fixture,
        "canonical manifest",
    )
    _require_direct_file(pin, fixture.parent, "canonical fixture pin")
    profile_bytes, profile_mode = _read_bounded_regular(
        fixture / "factory-profile.json",
        maximum=_MAX_PROFILE_BYTES,
        description="canonical Factory profile",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    manifest_bytes, manifest_mode = _read_bounded_regular(
        fixture / "manifest.json",
        maximum=_MAX_MANIFEST_BYTES,
        description="canonical manifest",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    pin_bytes, pin_mode = _read_bounded_regular(
        pin,
        maximum=128,
        description="canonical fixture pin",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    return _CanonicalState(
        profile_bytes=profile_bytes,
        manifest_bytes=manifest_bytes,
        pin_bytes=pin_bytes,
        profile_mode=profile_mode,
        manifest_mode=manifest_mode,
        pin_mode=pin_mode,
    )

def _preflight(
    *,
    project_root: Path,
    fixture: Path,
    fixture_manifest_pin: Path,
    candidate_dir: Path,
    signature: Path,
    trusted_public_key: Path,
) -> _Preflight:
    resolved_project_root, resolved_fixture, resolved_pin = (
        _validate_anchored_state_paths(
            project_root=project_root,
            fixture=fixture,
            fixture_manifest_pin=fixture_manifest_pin,
        )
    )
    candidate = _load_candidate(
        candidate_dir,
        fixture=resolved_fixture,
        fixture_pin=resolved_pin,
    )
    signature_binding = _verify_signature(
        candidate=candidate,
        signature=signature,
        trusted_public_key=trusted_public_key,
    )
    current_bindings = _current_bindings(resolved_project_root)
    _validate_candidate_bindings(
        candidate,
        gate_digest=current_bindings.gate_surface_digest,
        plugin_digest=current_bindings.installed_plugin_artifact_digest,
    )
    _validate_fixture_file_set(resolved_fixture, candidate.manifest)
    canonical_state = _read_canonical_state(resolved_fixture, resolved_pin)
    return _Preflight(
        project_root=resolved_project_root,
        fixture=resolved_fixture,
        fixture_manifest_pin=resolved_pin,
        candidate=candidate,
        signature_binding=signature_binding,
        current_bindings=current_bindings,
        canonical_state=canonical_state,
    )


def _classify_transaction_state(
    state: _CanonicalState, request: Mapping[str, Any]
) -> int:
    actual = (
        _sha256_bytes(state.profile_bytes),
        _sha256_bytes(state.manifest_bytes),
        _sha256_bytes(state.pin_bytes),
    )
    predecessor = request["predecessor"]
    successor = request["successor"]
    old = (
        predecessor["profile_sha256"],
        predecessor["manifest_sha256"],
        predecessor["pin_sha256"],
    )
    new = (
        successor["profile_sha256"],
        successor["manifest_sha256"],
        successor["pin_sha256"],
    )
    allowed = (
        old,
        (new[0], old[1], old[2]),
        (new[0], new[1], old[2]),
        new,
    )
    try:
        return allowed.index(actual)
    except ValueError as error:
        raise ResealError(
            "canonical transaction state is not an allowed crash prefix"
        ) from error


def _validate_predecessor_relation(
    *,
    state: _CanonicalState,
    state_index: int,
    candidate: _Candidate,
    fixture: Path,
    gate_digest: str,
    plugin_digest: str,
) -> None:
    request = candidate.request
    predecessor = request["predecessor"]
    if state_index < 3:
        expected_pin_digest = predecessor["manifest_sha256"]
        current_pin_digest = _parse_pin(state.pin_bytes, "canonical fixture pin")
        if current_pin_digest != expected_pin_digest:
            raise ResealError(
                "canonical fixture pin content differs from its signed state"
            )

    if state_index <= 1:
        predecessor_manifest = _load_json(
            state.manifest_bytes,
            "predecessor manifest",
            canonical=False,
        )
        predecessor_files = _validate_manifest(
            predecessor_manifest,
            "predecessor manifest",
        )
        successor_files = _validate_manifest(candidate.manifest, "candidate manifest")
        if (
            predecessor_files.get("factory-profile.json")
            != predecessor["profile_sha256"]
        ):
            raise ResealError("predecessor profile binding differs from the request")
        if {
            name: digest
            for name, digest in predecessor_files.items()
            if name != "factory-profile.json"
        } != {
            name: digest
            for name, digest in successor_files.items()
            if name != "factory-profile.json"
        }:
            raise ResealError("candidate changes immutable fixture bindings")

    if state_index == 0:
        predecessor_profile = _load_profile(
            state.profile_bytes,
            "predecessor Factory profile",
            canonical=False,
        )
        _validate_profile_transition(
            predecessor_profile,
            candidate.profile,
            gate_digest=gate_digest,
            plugin_digest=plugin_digest,
        )
        try:
            verify_sealed_fixture(
                fixture,
                expected_manifest_digest=predecessor["manifest_sha256"],
            )
        except Exception as error:
            raise ResealError(
                "predecessor sealed fixture verification failed"
            ) from error


def _stage_successor_fixture(
    *,
    fixture: Path,
    candidate: _Candidate,
    project_root: Path,
) -> dict[str, Any]:
    files = _validate_manifest(candidate.manifest, "candidate manifest")
    try:
        with tempfile.TemporaryDirectory(prefix=".shadow-reseal-stage-") as temporary:
            temporary_root = Path(temporary)
            staged_fixture = temporary_root / "fixture"
            os.mkdir(staged_fixture, 0o700)
            for name in sorted(files):
                if name == "factory-profile.json":
                    payload = candidate.profile_bytes
                else:
                    _require_direct_file(
                        fixture / name,
                        fixture,
                        "canonical immutable fixture file",
                    )
                    payload, _ = _read_bounded_regular(
                        fixture / name,
                        maximum=_MAX_FIXTURE_FILE_BYTES,
                        description="canonical immutable fixture file",
                        require_owner=True,
                        require_single_link=True,
                        reject_shared_write=True,
                    )
                _exclusive_write(staged_fixture / name, payload, 0o600)
            _exclusive_write(
                staged_fixture / "manifest.json",
                candidate.manifest_bytes,
                0o600,
            )
            staged_pin = temporary_root / "manifest.sha256"
            _exclusive_write(staged_pin, candidate.pin_bytes, 0o600)
            result = run_dry_run(
                fixture_path=staged_fixture,
                fixture_manifest_pin=staged_pin,
                output_path=None,
                project_root=project_root,
            )
    except ResealError:
        raise
    except Exception as error:
        raise ResealError("staged ordinary dry run failed") from error
    return _require_offline_pass(result, "staged ordinary dry run")


def _require_offline_pass(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ResealError(f"{description} returned an invalid result")
    result = dict(value)
    checks = result.get("checks")
    if (
        result.get("status") != "offline-harness-pass"
        or not isinstance(checks, Mapping)
        or not checks
        or any(item != "pass" for item in checks.values())
    ):
        raise ResealError(f"{description} did not pass")
    try:
        canonical_json(result)
    except (TypeError, ValueError) as error:
        raise ResealError(f"{description} returned a noncanonical value") from error
    return result


def _durable_replace(
    path: Path,
    payload: bytes,
    *,
    expected_digest: str,
    mode: int,
    staging_directory: Path,
) -> None:
    _validate_directory(
        staging_directory,
        "canonical replacement staging directory",
        require_owner=True,
        reject_shared_write=True,
    )
    resolved_staging_directory = _resolve_existing(
        staging_directory,
        "canonical replacement staging directory",
    )
    target_parent = _validate_protected_parent(
        path,
        "canonical transaction file",
    )
    try:
        staging_device = os.lstat(resolved_staging_directory).st_dev
        target_device = os.lstat(target_parent).st_dev
        if staging_device != target_device:
            raise ResealError(
                "canonical replacement staging directory is on another filesystem"
            )
    except OSError as error:
        raise ResealError("cannot inspect canonical replacement filesystem") from error
    if type(mode) is not int or mode < 0 or mode > 0o777 or mode & 0o022:
        raise ResealError("canonical transaction mode is unsafe")

    current, _ = _read_bounded_regular(
        path,
        maximum=max(len(payload), _MAX_MANIFEST_BYTES),
        description="canonical transaction file",
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    if _sha256_bytes(current) != expected_digest:
        raise ResealError("canonical transaction file changed before replacement")
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".shadow-reseal-{path.name}-",
            dir=resolved_staging_directory,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        _fsync_directory(target_parent)
        if resolved_staging_directory != target_parent:
            _fsync_directory(resolved_staging_directory)
    except ResealError:
        raise
    except OSError as error:
        raise ResealError("durable canonical replacement failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _apply_transaction(
    *,
    fixture: Path,
    pin: Path,
    state: _CanonicalState,
    state_index: int,
    candidate: _Candidate,
) -> None:
    predecessor = candidate.request["predecessor"]
    replacements = (
        (
            fixture / "factory-profile.json",
            candidate.profile_bytes,
            predecessor["profile_sha256"],
            state.profile_mode,
        ),
        (
            fixture / "manifest.json",
            candidate.manifest_bytes,
            predecessor["manifest_sha256"],
            state.manifest_mode,
        ),
        (
            pin,
            candidate.pin_bytes,
            predecessor["pin_sha256"],
            state.pin_mode,
        ),
    )
    for path, payload, expected_digest, mode in replacements[state_index:]:
        _durable_replace(
            path,
            payload,
            expected_digest=expected_digest,
            mode=mode,
            staging_directory=fixture.parent,
        )


def _validate_receipt_parent(receipt: Path) -> Path:
    _validate_directory(
        receipt.parent,
        "receipt parent",
        exact_mode=0o700,
        require_owner=True,
        reject_shared_write=True,
    )
    try:
        return receipt.parent.resolve(strict=True)
    except OSError as error:
        raise ResealError("cannot resolve receipt parent") from error


def _validate_receipt_path(
    receipt: Path,
    *,
    candidate: Path,
    fixture: Path,
    fixture_pin: Path,
    must_exist: bool,
) -> Path:
    try:
        unresolved_parent = receipt.parent.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
        resolved_fixture = fixture.resolve(strict=True)
        resolved_pin = fixture_pin.resolve(strict=True)
    except OSError as error:
        raise ResealError("cannot resolve receipt containment") from error
    location = unresolved_parent / receipt.name
    if (
        _resolved_is_within(location, resolved_candidate)
        or _resolved_is_within(location, resolved_fixture)
        or location == resolved_pin
    ):
        raise ResealError("receipt must be external to candidate and fixture state")

    parent = _validate_receipt_parent(receipt)
    location = parent / receipt.name
    if must_exist:
        resolved = _resolve_existing(receipt, "receipt")
        if resolved != location:
            raise ResealError("receipt escapes its private parent")
        return resolved
    _require_absent(receipt, "receipt")
    return location


def _require_absent(path: Path, description: str) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ResealError(f"cannot inspect {description}") from error
    raise ResealError(f"{description} already exists")


def _receipt_value(
    *,
    candidate: _Candidate,
    signature_binding: _SignatureBinding,
    applied_at: int,
    offline_result: Mapping[str, Any],
) -> dict[str, Any]:
    material: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "operation": _OPERATION,
        "status": "applied",
        "request_id": candidate.request["request_id"],
        "request_digest": _sha256_bytes(candidate.request_bytes),
        "signer_public_key_sha256": signature_binding.public_key_sha256,
        "signature_sha256": signature_binding.signature_sha256,
        "predecessor": dict(candidate.request["predecessor"]),
        "successor": dict(candidate.request["successor"]),
        "applied_at": applied_at,
        "offline_result_digest": _sha256_bytes(canonical_json(offline_result)),
    }
    material["record_digest"] = _sha256_bytes(canonical_json(material))
    return material


def _write_receipt(receipt: Path, value: Mapping[str, Any]) -> None:
    payload = _canonical_bytes(value)
    if len(payload) > _MAX_RECORD_BYTES:
        raise ResealError("receipt exceeds its byte bound")
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{receipt.name}.reseal-",
            dir=receipt.parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, receipt, follow_symlinks=False)
        temporary_path.unlink()
        temporary_path = None
        _fsync_directory(receipt.parent)
    except ResealError:
        raise
    except OSError as error:
        raise ResealError("cannot create exclusive atomic receipt") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def apply_reseal(
    *,
    project_root: Path,
    fixture: Path,
    fixture_manifest_pin: Path,
    candidate_dir: Path,
    signature: Path,
    trusted_public_key: Path,
    receipt: Path,
) -> dict[str, Any]:
    preflight = _preflight(
        project_root=project_root,
        fixture=fixture,
        fixture_manifest_pin=fixture_manifest_pin,
        candidate_dir=candidate_dir,
        signature=signature,
        trusted_public_key=trusted_public_key,
    )
    resolved_receipt = _validate_receipt_path(
        receipt,
        candidate=preflight.candidate.directory,
        fixture=preflight.fixture,
        fixture_pin=preflight.fixture_manifest_pin,
        must_exist=False,
    )

    effective_now = _now(None)
    _validate_request_time(preflight.candidate.request, effective_now)
    state_index = _classify_transaction_state(
        preflight.canonical_state,
        preflight.candidate.request,
    )
    _validate_predecessor_relation(
        state=preflight.canonical_state,
        state_index=state_index,
        candidate=preflight.candidate,
        fixture=preflight.fixture,
        gate_digest=preflight.current_bindings.gate_surface_digest,
        plugin_digest=(
            preflight.current_bindings.installed_plugin_artifact_digest
        ),
    )
    _stage_successor_fixture(
        fixture=preflight.fixture,
        candidate=preflight.candidate,
        project_root=preflight.project_root,
    )

    applied_at = _now(None)
    _validate_request_time(preflight.candidate.request, applied_at)
    _apply_transaction(
        fixture=preflight.fixture,
        pin=preflight.fixture_manifest_pin,
        state=preflight.canonical_state,
        state_index=state_index,
        candidate=preflight.candidate,
    )
    completed_state = _read_canonical_state(
        preflight.fixture,
        preflight.fixture_manifest_pin,
    )
    if _classify_transaction_state(
        completed_state,
        preflight.candidate.request,
    ) != 3:
        raise ResealError("canonical transaction did not reach successor state")

    try:
        final_result = run_dry_run(
            fixture_path=preflight.fixture,
            fixture_manifest_pin=preflight.fixture_manifest_pin,
            output_path=None,
            project_root=preflight.project_root,
        )
    except Exception as error:
        raise ResealError("canonical ordinary dry run failed") from error
    final_result = _require_offline_pass(final_result, "canonical ordinary dry run")
    receipt_value = _receipt_value(
        candidate=preflight.candidate,
        signature_binding=preflight.signature_binding,
        applied_at=applied_at,
        offline_result=final_result,
    )
    _write_receipt(resolved_receipt, receipt_value)
    return {
        "schema_version": _SCHEMA_VERSION,
        "status": "applied",
        "request_id": preflight.candidate.request["request_id"],
        "request_digest": _sha256_bytes(preflight.candidate.request_bytes),
        "receipt_digest": receipt_value["record_digest"],
    }


def _load_and_validate_receipt(
    *,
    receipt: Path,
    candidate: _Candidate,
    signature_binding: _SignatureBinding,
) -> dict[str, Any]:
    payload, _ = _read_bounded_regular(
        receipt,
        maximum=_MAX_RECORD_BYTES,
        description="receipt",
        exact_mode=0o644,
        require_owner=True,
        require_single_link=True,
        reject_shared_write=True,
    )
    value = _load_json(payload, "receipt", canonical=True)
    if set(value) != _RECEIPT_FIELDS:
        raise ResealError("receipt fields differ")
    if value.get("schema_version") != _SCHEMA_VERSION:
        raise ResealError("receipt schema differs")
    if value.get("operation") != _OPERATION or value.get("status") != "applied":
        raise ResealError("receipt operation or status differs")
    applied_at = value.get("applied_at")
    if type(applied_at) is not int:
        raise ResealError("receipt applied time is invalid")
    if not (
        candidate.request["created_at"]
        <= applied_at
        < candidate.request["expires_at"]
    ):
        raise ResealError("receipt applied time is outside the request interval")

    expected_bindings = {
        "request_id": candidate.request["request_id"],
        "request_digest": _sha256_bytes(candidate.request_bytes),
        "signer_public_key_sha256": signature_binding.public_key_sha256,
        "signature_sha256": signature_binding.signature_sha256,
        "predecessor": candidate.request["predecessor"],
        "successor": candidate.request["successor"],
    }
    if any(value.get(name) != expected for name, expected in expected_bindings.items()):
        raise ResealError("receipt bindings differ")
    _validate_digest(
        value.get("offline_result_digest"),
        "receipt offline result digest",
    )
    supplied_record_digest = _validate_digest(
        value.get("record_digest"),
        "receipt record digest",
    )
    material = dict(value)
    del material["record_digest"]
    if supplied_record_digest != _sha256_bytes(canonical_json(material)):
        raise ResealError("receipt record digest differs")
    return value


def verify_reseal(
    *,
    project_root: Path,
    fixture: Path,
    fixture_manifest_pin: Path,
    candidate_dir: Path,
    signature: Path,
    trusted_public_key: Path,
    receipt: Path,
) -> dict[str, Any]:
    preflight = _preflight(
        project_root=project_root,
        fixture=fixture,
        fixture_manifest_pin=fixture_manifest_pin,
        candidate_dir=candidate_dir,
        signature=signature,
        trusted_public_key=trusted_public_key,
    )
    resolved_receipt = _validate_receipt_path(
        receipt,
        candidate=preflight.candidate.directory,
        fixture=preflight.fixture,
        fixture_pin=preflight.fixture_manifest_pin,
        must_exist=True,
    )
    effective_now = _now(None)
    _validate_request_not_future(preflight.candidate.request, effective_now)

    if _classify_transaction_state(
        preflight.canonical_state,
        preflight.candidate.request,
    ) != 3:
        raise ResealError("canonical fixture is not exactly the signed successor")
    try:
        verify_sealed_fixture(
            preflight.fixture,
            expected_manifest_digest=(
                preflight.candidate.request["successor"]["manifest_sha256"]
            ),
        )
    except Exception as error:
        raise ResealError("successor sealed fixture verification failed") from error
    receipt_value = _load_and_validate_receipt(
        receipt=resolved_receipt,
        candidate=preflight.candidate,
        signature_binding=preflight.signature_binding,
    )

    try:
        offline_result = run_dry_run(
            fixture_path=preflight.fixture,
            fixture_manifest_pin=preflight.fixture_manifest_pin,
            output_path=None,
            project_root=preflight.project_root,
        )
    except Exception as error:
        raise ResealError("canonical ordinary dry run failed") from error
    offline_result = _require_offline_pass(
        offline_result,
        "canonical ordinary dry run",
    )
    offline_result_digest = _sha256_bytes(canonical_json(offline_result))
    if receipt_value["offline_result_digest"] != offline_result_digest:
        raise ResealError("receipt offline result digest differs")
    return {
        "schema_version": _SCHEMA_VERSION,
        "status": "verified",
        "request_id": preflight.candidate.request["request_id"],
        "request_digest": _sha256_bytes(preflight.candidate.request_bytes),
        "receipt_digest": receipt_value["record_digest"],
    }


def _add_common_state_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-manifest-pin", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)


def _add_signature_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--trusted-public-key", type=Path, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Externally authorized feasibility-fixture re-seal workflow"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare")
    _add_common_state_arguments(prepare)
    prepare.add_argument("--valid-for-seconds", type=int, default=3600)
    prepare.add_argument("--now", type=int)

    apply = commands.add_parser("apply")
    _add_common_state_arguments(apply)
    _add_signature_arguments(apply)
    apply.add_argument("--receipt", type=Path, required=True)

    verify = commands.add_parser("verify")
    _add_common_state_arguments(verify)
    _add_signature_arguments(verify)
    verify.add_argument("--receipt", type=Path, required=True)
    return parser


def _run_command(options: argparse.Namespace) -> dict[str, Any]:
    common = {
        "project_root": options.project_root,
        "fixture": options.fixture,
        "fixture_manifest_pin": options.fixture_manifest_pin,
        "candidate_dir": options.candidate_dir,
    }
    if options.command == "prepare":
        return prepare_reseal(
            **common,
            valid_for_seconds=options.valid_for_seconds,
            now=options.now,
        )
    signed = {
        **common,
        "signature": options.signature,
        "trusted_public_key": options.trusted_public_key,
        "receipt": options.receipt,
    }
    if options.command == "apply":
        return apply_reseal(**signed)
    if options.command == "verify":
        return verify_reseal(**signed)
    raise ResealError("unknown command")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    options = parser.parse_args(argv)
    try:
        result = _run_command(options)
    except ResealError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except Exception:
        print("error: re-seal operation failed", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(_canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
