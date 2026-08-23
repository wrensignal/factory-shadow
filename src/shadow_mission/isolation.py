"""Validation for the selected disposable Lima environment."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .auth import SCHEMA_VERSION

_PINNED_IMAGE_DIGEST = (
    "sha256:7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc"
)
_PINNED_CONFIG_DIGEST = (
    "4827a29ac2adf6a1dfa8c10021b1acffe0523d32386215253a5d7b59b5a6dac6"
)
_LIVE_CANARY_FIELDS = (
    "host_read_canary_denied",
    "host_write_canary_unchanged",
    "guest_protected_read_denied",
    "fixture_read_allowed",
    "guest_mount_table_clean",
    "guest_visible_paths_allowlisted",
    "teardown_confirmed",
)
_REQUIRED_FIELDS = {
    "schema_version",
    "mechanism",
    "lima_version",
    "vm_name",
    "image_digest",
    "config_sha256",
    "host_mounts",
    "ssh_agent_forwarding",
    "proxy_environment_propagation",
    "containerd_enabled",
    "factory_sandbox_enabled",
    "factory_sandbox_mode",
    *_LIVE_CANARY_FIELDS,
    "phase",
}


class IsolationError(ValueError):
    """Raised when disposable-environment evidence is incomplete or unsafe."""


@dataclass(frozen=True)
class IsolationResult:
    mechanism: str
    config_digest: str
    image_digest: str
    host_mounts: tuple[str, ...]
    live_canaries_verified: bool


def _load_manifest(value: Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Path):
        try:
            loaded = json.loads(value.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise IsolationError("invalid isolation manifest JSON") from error
    else:
        loaded = dict(value)
    if not isinstance(loaded, dict):
        raise IsolationError("isolation manifest root must be an object")
    return loaded




def capture_live_isolation_manifest(
    *,
    lima_config: Path,
    lima_version: str,
    canaries: Mapping[str, bool],
    vm_name: str,
    image_digest: str,
    host_mounts: list[str],
    ssh_agent_forwarding: bool,
    proxy_environment_propagation: bool,
    containerd_enabled: bool,
    factory_sandbox_enabled: bool,
    factory_sandbox_mode: str,
) -> dict[str, Any]:
    expected_canaries = {
        "host_read_canary_denied",
        "host_write_canary_unchanged",
        "guest_protected_read_denied",
        "fixture_read_allowed",
        "guest_mount_table_clean",
        "guest_visible_paths_allowlisted",
    }
    if (
        set(canaries) != expected_canaries
        or any(value is not True for value in canaries.values())
    ):
        raise IsolationError("live isolation canaries are incomplete")
    try:
        config_digest = hashlib.sha256(lima_config.read_bytes()).hexdigest()
    except OSError as error:
        raise IsolationError("cannot read Lima configuration") from error
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "mechanism": "lima",
        "lima_version": lima_version,
        "vm_name": vm_name,
        "image_digest": image_digest,
        "config_sha256": config_digest,
        "host_mounts": host_mounts,
        "ssh_agent_forwarding": ssh_agent_forwarding,
        "proxy_environment_propagation": proxy_environment_propagation,
        "containerd_enabled": containerd_enabled,
        "factory_sandbox_enabled": factory_sandbox_enabled,
        "factory_sandbox_mode": factory_sandbox_mode,
        **dict(canaries),
        "teardown_confirmed": None,
        "phase": "live-preflight",
    }
    validate_isolation_manifest(
        manifest,
        lima_config,
        require_live_canaries=False,
    )
    return manifest


def validate_isolation_manifest(
    manifest_value: Path | Mapping[str, Any],
    lima_config: Path,
    *,
    require_live_canaries: bool,
) -> IsolationResult:
    manifest = _load_manifest(manifest_value)
    if set(manifest) != _REQUIRED_FIELDS:
        raise IsolationError("isolation manifest fields differ from the contract")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise IsolationError("unsupported isolation manifest schema")
    if manifest["mechanism"] != "lima" or manifest["lima_version"] != "2.2.0":
        raise IsolationError("isolation mechanism or Lima version mismatch")
    if manifest["vm_name"] != "shadow-feasibility":
        raise IsolationError("unexpected Lima instance name")
    if manifest["image_digest"] != _PINNED_IMAGE_DIGEST:
        raise IsolationError("Lima image is not pinned to the approved digest")
    if manifest["host_mounts"] != []:
        raise IsolationError("Lima host mounts must be empty")
    if manifest["ssh_agent_forwarding"] is not False:
        raise IsolationError("SSH agent forwarding must be disabled")
    if manifest["proxy_environment_propagation"] is not False:
        raise IsolationError("proxy environment propagation must be disabled")
    if manifest["containerd_enabled"] is not False:
        raise IsolationError("containerd must be disabled")
    if manifest["factory_sandbox_enabled"] is not True:
        raise IsolationError("Factory sandbox must be enabled")
    if manifest["factory_sandbox_mode"] != "whole-process":
        raise IsolationError("Factory sandbox must use whole-process mode")

    try:
        config_bytes = lima_config.read_bytes()
    except OSError as error:
        raise IsolationError("cannot read Lima configuration") from error
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    if config_digest != _PINNED_CONFIG_DIGEST:
        raise IsolationError("Lima configuration differs from the approved template")
    if manifest["config_sha256"] != config_digest:
        raise IsolationError("Lima configuration digest mismatch")

    live_values = [manifest[field] for field in _LIVE_CANARY_FIELDS]
    if require_live_canaries and any(value is not True for value in live_values):
        raise IsolationError("every live canary and teardown check must pass")
    if not require_live_canaries and any(value not in {None, True} for value in live_values):
        raise IsolationError("offline live canary fields must be null or true")

    return IsolationResult(
        mechanism="lima",
        config_digest=config_digest,
        image_digest=_PINNED_IMAGE_DIGEST,
        host_mounts=(),
        live_canaries_verified=all(value is True for value in live_values),
    )
