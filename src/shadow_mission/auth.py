"""Run-scoped transport integrity and signed state for the feasibility harness."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
import time
from threading import Lock
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit
from .evidence import (
    EvidenceRegistryError,
    FrozenObservationRegistry,
    authorize_protected_transition,
)

RUN_FILE_ENV = "SHADOW_MISSION_RUN_FILE"
RUN_DESCRIPTOR_ENV = "SHADOW_MISSION_RUN_DESCRIPTOR"
RUN_SECRET_ENV = "SHADOW_MISSION_RUN_SECRET"
SCHEMA_VERSION = "0.1"

_HEADER_KEY_ID = "X-Shadow-Key-Id"
_HEADER_TIMESTAMP = "X-Shadow-Timestamp"
_HEADER_NONCE = "X-Shadow-Nonce"
_HEADER_SIGNATURE = "X-Shadow-Signature"


class AuthenticationError(ValueError):
    """Raised when run-scoped integrity state fails validation."""


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def generate_run_secret() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def _decode_secret(encoded: str) -> bytes:
    if not isinstance(encoded, str) or not encoded:
        raise AuthenticationError("missing run secret")
    try:
        padding = "=" * (-len(encoded) % 4)
        secret = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise AuthenticationError("invalid run secret encoding") from error
    if len(secret) != 32:
        raise AuthenticationError("run secret must contain 32 bytes")
    return secret


def make_alias(secret: str, kind: str, raw_value: str) -> str:
    if not raw_value:
        return f"{kind}-missing"
    digest = hmac.new(
        _decode_secret(secret),
        f"alias\n{kind}\n{raw_value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:20]
    return f"{kind}-{digest}"


def _signature(value: Mapping[str, Any], secret: str) -> str:
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    return hmac.new(
        _decode_secret(secret), canonical_json(unsigned), hashlib.sha256
    ).hexdigest()


def _signed(value: Mapping[str, Any], secret: str) -> dict[str, Any]:
    result = dict(value)
    result["signature"] = _signature(result, secret)
    return result


def _verify_signature(value: Mapping[str, Any], secret: str) -> None:
    signature = value.get("signature")
    if not isinstance(signature, str):
        raise AuthenticationError("missing signature")
    expected = _signature(value, secret)
    if not hmac.compare_digest(signature, expected):
        raise AuthenticationError("invalid signature")


def _validate_loopback_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/events"
        or parsed.query
        or parsed.fragment
    ):
        raise AuthenticationError("collector URL must be loopback HTTP /events")
    if parsed.port is None:
        raise AuthenticationError("collector URL must include an explicit port")

def _validate_digest(value: str, field_name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AuthenticationError(f"{field_name} must be a lowercase SHA-256 digest")

def production_latch_head_path(latch_path: Path) -> Path:
    """Return the descriptor-bound head path for a production latch."""
    return latch_path.with_name(f"{latch_path.stem}-head{latch_path.suffix}")


def _validate_private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AuthenticationError("cannot read private state directory") from error
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise AuthenticationError("private state parent must be a directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise AuthenticationError("private state directory mode must be 0700")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise AuthenticationError("private state directory owner does not match")


def _validate_private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AuthenticationError(f"cannot read private file: {path.name}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise AuthenticationError("private state must be a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise AuthenticationError("private state file mode must be 0600")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise AuthenticationError("private state file owner does not match the process")


def _atomic_private_write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _validate_private_directory(path.parent)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(file_descriptor, 0o600)
        payload = canonical_json(value) + b"\n"
        with os.fdopen(file_descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def create_descriptor(
    path: Path,
    secret: str,
    *,
    run_id: str,
    key_id: str,
    collector_url: str,
    mission_root_digest: str,
    profile_digest: str,
    isolation_digest: str,
    gate_surface_digest: str,
    installed_artifact_digest: str,
    latch_path: Path,
    now: int | None = None,
    ttl_seconds: int = 3_600,
) -> dict[str, Any]:
    _decode_secret(secret)
    _validate_loopback_url(collector_url)
    if ttl_seconds <= 0:
        raise AuthenticationError("descriptor TTL must be positive")
    if not isinstance(run_id, str) or not run_id:
        raise AuthenticationError("run ID must be a non-empty string")
    if not isinstance(key_id, str) or not key_id:
        raise AuthenticationError("key ID must be a non-empty string")
    resolved_latch_path = latch_path.resolve()
    resolved_head_path = production_latch_head_path(resolved_latch_path)
    if (
        resolved_latch_path.parent != path.parent.resolve()
        or resolved_head_path.parent != path.parent.resolve()
        or resolved_head_path == resolved_latch_path
    ):
        raise AuthenticationError(
            "latch paths must stay in the private run directory"
        )
    for field_name, digest in (
        ("mission_root_digest", mission_root_digest),
        ("profile_digest", profile_digest),
        ("isolation_digest", isolation_digest),
        ("gate_surface_digest", gate_surface_digest),
        ("installed_artifact_digest", installed_artifact_digest),
    ):
        _validate_digest(digest, field_name)
    created_at = int(time.time()) if now is None else int(now)
    descriptor = _signed(
        {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "key_id": key_id,
            "collector_url": collector_url,
            "provenance_capability": "transport_integrity_only",
            "mission_root_digest": mission_root_digest,
            "profile_digest": profile_digest,
            "isolation_digest": isolation_digest,
            "gate_surface_digest": gate_surface_digest,
            "installed_artifact_digest": installed_artifact_digest,
            "latch_path": str(latch_path.resolve()),
            "latch_head_path": str(resolved_head_path),
            "created_at": created_at,
            "expires_at": created_at + ttl_seconds,
            "descriptor_nonce": secrets.token_hex(16),
        },
        secret,
    )
    _atomic_private_write(path, descriptor)
    return descriptor


def _load_private_json(path: Path) -> dict[str, Any]:
    _validate_private_file(path)
    _validate_private_directory(path.parent)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuthenticationError(f"invalid private JSON: {path.name}") from error
    if not isinstance(value, dict):
        raise AuthenticationError("private JSON root must be an object")
    return value


def write_signed_private_state(
    path: Path, secret: str, value: Mapping[str, Any]
) -> dict[str, Any]:
    """Write one HMAC-bound private JSON object with durable replacement."""
    _decode_secret(secret)
    if "signature" in value:
        raise AuthenticationError("unsigned private state must omit signature")
    signed = _signed(value, secret)
    _atomic_private_write(path, signed)
    return signed


def load_signed_private_state(path: Path, secret: str) -> dict[str, Any]:
    """Load and authenticate one private JSON object."""
    _decode_secret(secret)
    value = _load_private_json(path)
    _verify_signature(value, secret)
    return value


def load_descriptor(
    path: Path, secret: str, *, now: int | None = None
) -> dict[str, Any]:
    descriptor = _load_private_json(path)
    _verify_signature(descriptor, secret)
    required = {
        "schema_version",
        "run_id",
        "key_id",
        "collector_url",
        "provenance_capability",
        "mission_root_digest",
        "profile_digest",
        "isolation_digest",
        "latch_path",
        "latch_head_path",
        "gate_surface_digest",
        "installed_artifact_digest",
        "created_at",
        "expires_at",
        "descriptor_nonce",
        "signature",
    }
    if set(descriptor) != required:
        raise AuthenticationError("descriptor fields do not match the contract")
    if descriptor["schema_version"] != SCHEMA_VERSION:
        raise AuthenticationError("unsupported descriptor schema")
    _validate_loopback_url(str(descriptor["collector_url"]))
    for field_name in (
        "mission_root_digest",
        "profile_digest",
        "isolation_digest",
        "gate_surface_digest",
        "installed_artifact_digest",
    ):
        _validate_digest(str(descriptor[field_name]), field_name)
    if not isinstance(descriptor["run_id"], str) or not descriptor["run_id"]:
        raise AuthenticationError("descriptor run ID is invalid")
    if not isinstance(descriptor["key_id"], str) or not descriptor["key_id"]:
        raise AuthenticationError("descriptor key ID is invalid")
    if descriptor["provenance_capability"] != "transport_integrity_only":
        raise AuthenticationError("descriptor overstates hook provenance")
    latch_path = Path(str(descriptor["latch_path"]))
    latch_head_path = Path(str(descriptor["latch_head_path"]))
    if (
        not latch_path.is_absolute()
        or latch_path.parent != path.parent.resolve()
        or not latch_head_path.is_absolute()
        or latch_head_path.parent != path.parent.resolve()
        or latch_head_path != production_latch_head_path(latch_path)
    ):
        raise AuthenticationError(
            "descriptor latch paths must stay in the private run directory"
        )
    if (
        not isinstance(descriptor["created_at"], int)
        or isinstance(descriptor["created_at"], bool)
        or not isinstance(descriptor["expires_at"], int)
        or isinstance(descriptor["expires_at"], bool)
        or descriptor["created_at"] >= descriptor["expires_at"]
    ):
        raise AuthenticationError("descriptor time bounds are invalid")
    if (
        not isinstance(descriptor["descriptor_nonce"], str)
        or not descriptor["descriptor_nonce"]
    ):
        raise AuthenticationError("descriptor nonce is invalid")
    observed_at = int(time.time()) if now is None else int(now)
    if observed_at > int(descriptor["expires_at"]):
        raise AuthenticationError("descriptor expired")
    return descriptor


def _event_message(
    *,
    schema_version: str,
    run_id: str,
    event_id: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    body_digest = hashlib.sha256(body).hexdigest()
    return "\n".join(
        (schema_version, run_id, event_id, timestamp, nonce, body_digest)
    ).encode("utf-8")


def sign_event_headers(
    body: bytes,
    secret: str,
    descriptor: Mapping[str, Any],
    *,
    event_id: str,
    now: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    timestamp = str(int(time.time()) if now is None else int(now))
    request_nonce = nonce or secrets.token_hex(16)
    message = _event_message(
        schema_version=SCHEMA_VERSION,
        run_id=str(descriptor["run_id"]),
        event_id=event_id,
        timestamp=timestamp,
        nonce=request_nonce,
        body=body,
    )
    signature = hmac.new(_decode_secret(secret), message, hashlib.sha256).hexdigest()
    return {
        _HEADER_KEY_ID: str(descriptor["key_id"]),
        _HEADER_TIMESTAMP: timestamp,
        _HEADER_NONCE: request_nonce,
        _HEADER_SIGNATURE: signature,
    }


class EventAuthenticator:
    """Stateful replay guard for one collector run."""

    def __init__(
        self, secret: str, descriptor: Mapping[str, Any], *, max_skew_seconds: int = 30
    ) -> None:
        self._secret = secret
        self._descriptor = descriptor
        self._max_skew_seconds = max_skew_seconds
        self._nonces: set[str] = set()
        self._event_digests: dict[str, str] = {}
        self._lock = Lock()

    def verify(
        self, headers: Mapping[str, str], body: bytes, *, now: int | None = None
    ) -> str:
        try:
            key_id = headers[_HEADER_KEY_ID]
            timestamp = headers[_HEADER_TIMESTAMP]
            nonce = headers[_HEADER_NONCE]
            supplied_signature = headers[_HEADER_SIGNATURE]
        except KeyError as error:
            raise AuthenticationError("missing authentication header") from error
        if key_id != self._descriptor["key_id"]:
            raise AuthenticationError("wrong key ID")
        try:
            event_time = int(timestamp)
        except ValueError as error:
            raise AuthenticationError("invalid event timestamp") from error
        current_time = int(time.time()) if now is None else int(now)
        if abs(current_time - event_time) > self._max_skew_seconds:
            raise AuthenticationError("event timestamp is outside the clock window")
        try:
            payload = json.loads(body)
            event_id = payload["event_id"]
            run_id = payload["run_id"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise AuthenticationError("event body lacks run or event identity") from error
        if not isinstance(event_id, str) or not event_id:
            raise AuthenticationError("invalid event ID")
        if run_id != self._descriptor["run_id"]:
            raise AuthenticationError("event belongs to another run")
        message = _event_message(
            schema_version=SCHEMA_VERSION,
            run_id=str(run_id),
            event_id=event_id,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        expected = hmac.new(
            _decode_secret(self._secret), message, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(supplied_signature, expected):
            raise AuthenticationError("invalid event signature")
        digest = hashlib.sha256(body).hexdigest()
        with self._lock:
            if nonce in self._nonces:
                raise AuthenticationError("event nonce replay")
            prior_digest = self._event_digests.get(event_id)
            if prior_digest is not None and prior_digest != digest:
                raise AuthenticationError("event ID reused with different content")
            self._nonces.add(nonce)
            self._event_digests[event_id] = digest
        return event_id


def write_latch(
    path: Path,
    secret: str,
    descriptor: Mapping[str, Any],
    *,
    registry: FrozenObservationRegistry,
    scope: str,
    target_id: str,
    evidence_target_id: str | None = None,
    blocker_id: str,
    state: str,
    generation: int,
    direct_evidence_ids: list[str],
    probe_result_id: str,
    correction_evidence_ids: list[str],
    provenance_status: str,
    now: int | None = None,
    ttl_seconds: int = 600,
) -> dict[str, Any]:
    if state not in {"active", "resolved"}:
        raise AuthenticationError("invalid latch state")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 0
        or ttl_seconds <= 0
    ):
        raise AuthenticationError("invalid latch generation or TTL")
    if provenance_status not in {"hook_authenticated", "untrusted_provenance"}:
        raise AuthenticationError("invalid latch provenance status")
    if scope not in {"worker", "mission"}:
        raise AuthenticationError("invalid latch scope")
    if path.resolve() != Path(str(descriptor.get("latch_path", ""))).resolve():
        raise AuthenticationError("latch path does not match the descriptor")
    if not isinstance(target_id, str) or not target_id:
        raise AuthenticationError("invalid latch target identity")
    evidence_target = target_id if evidence_target_id is None else evidence_target_id
    if not isinstance(evidence_target, str) or not evidence_target:
        raise AuthenticationError("invalid latch evidence target identity")
    if not isinstance(blocker_id, str) or not blocker_id:
        raise AuthenticationError("invalid latch blocker ID")
    if (
        not direct_evidence_ids
        or not all(
            isinstance(value, str) and value for value in direct_evidence_ids
        )
        or not isinstance(probe_result_id, str)
        or not probe_result_id
        or not all(
            isinstance(value, str) and value for value in correction_evidence_ids
        )
        or (state == "active" and correction_evidence_ids)
        or (state == "resolved" and not correction_evidence_ids)
    ):
        raise AuthenticationError("invalid latch evidence identifiers")
    run_id = str(descriptor.get("run_id", ""))
    try:
        authorize_protected_transition(
            registry=registry,
            provenance_status=provenance_status,
            transition="blocker_create",
            observation_ids=tuple(direct_evidence_ids) + (probe_result_id,),
            run_id=run_id,
            target_id=evidence_target,
            risk_id=blocker_id,
        )
        if state == "resolved":
            authorize_protected_transition(
                registry=registry,
                provenance_status=provenance_status,
                transition="blocker_clear",
                observation_ids=tuple(correction_evidence_ids),
                run_id=run_id,
                target_id=evidence_target,
                risk_id=blocker_id,
            )
    except EvidenceRegistryError as error:
        raise AuthenticationError("latch evidence is not authorized") from error
    created_at = int(time.time()) if now is None else int(now)
    latch = _signed(
        {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "key_id": descriptor["key_id"],
            "scope": scope,
            "target_alias": make_alias(secret, "session", target_id),
            "blocker_id": blocker_id,
            "state": state,
            "generation": generation,
            "direct_evidence_ids": list(direct_evidence_ids),
            "probe_result_id": probe_result_id,
            "correction_evidence_ids": list(correction_evidence_ids),
            "provenance_status": provenance_status,
            "observation_registry_digest": registry.source_digest,
            "created_at": created_at,
            "expires_at": created_at + ttl_seconds,
        },
        secret,
    )
    _atomic_private_write(path, latch)
    return latch


def load_latch(
    path: Path,
    secret: str,
    descriptor: Mapping[str, Any],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    latch = _load_private_json(path)
    _verify_signature(latch, secret)
    required = {
        "schema_version",
        "run_id",
        "key_id",
        "scope",
        "target_alias",
        "blocker_id",
        "state",
        "generation",
        "direct_evidence_ids",
        "probe_result_id",
        "correction_evidence_ids",
        "provenance_status",
        "observation_registry_digest",
        "created_at",
        "expires_at",
        "signature",
    }
    if set(latch) != required:
        raise AuthenticationError("latch fields do not match the contract")
    if latch.get("schema_version") != SCHEMA_VERSION:
        raise AuthenticationError("unsupported latch schema")
    if latch.get("run_id") != descriptor.get("run_id"):
        raise AuthenticationError("latch run does not match descriptor run")
    if latch.get("key_id") != descriptor.get("key_id"):
        raise AuthenticationError("latch key does not match descriptor key")
    if latch.get("scope") not in {"worker", "mission"}:
        raise AuthenticationError("invalid latch scope")
    if (
        not isinstance(latch["created_at"], int)
        or isinstance(latch["created_at"], bool)
        or not isinstance(latch["expires_at"], int)
        or isinstance(latch["expires_at"], bool)
        or latch["created_at"] >= latch["expires_at"]
    ):
        raise AuthenticationError("latch time bounds are invalid")
    observed_at = int(time.time()) if now is None else int(now)
    if observed_at > latch["expires_at"]:
        raise AuthenticationError("latch expired")
    if latch.get("state") not in {"active", "resolved"}:
        raise AuthenticationError("invalid latch state")
    if not isinstance(latch.get("generation"), int) or isinstance(
        latch.get("generation"), bool
    ):
        raise AuthenticationError("invalid latch generation")
    direct_ids = latch.get("direct_evidence_ids")
    correction_ids = latch.get("correction_evidence_ids")
    probe_result_id = latch.get("probe_result_id")
    if (
        not isinstance(direct_ids, list)
        or not direct_ids
        or not all(isinstance(value, str) and value for value in direct_ids)
        or not isinstance(probe_result_id, str)
        or not probe_result_id
        or not isinstance(correction_ids, list)
        or not all(isinstance(value, str) and value for value in correction_ids)
        or (latch["state"] == "active" and correction_ids)
        or (latch["state"] == "resolved" and not correction_ids)
    ):
        raise AuthenticationError("invalid latch evidence identifiers")
    if latch.get("provenance_status") not in {
        "hook_authenticated",
        "untrusted_provenance",
    }:
        raise AuthenticationError("invalid latch provenance status")
    _validate_digest(
        latch.get("observation_registry_digest"),
        "observation_registry_digest",
    )
    if not isinstance(latch["target_alias"], str) or not latch["target_alias"]:
        raise AuthenticationError("invalid latch target alias")
    if not isinstance(latch["blocker_id"], str) or not latch["blocker_id"]:
        raise AuthenticationError("invalid latch blocker ID")
    return latch
