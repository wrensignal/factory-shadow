"""Canonical inventory for Factory configuration inherited by Missions."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import __version__ as _SOURCE_VERSION
from .auth import SCHEMA_VERSION, canonical_json

# The live protocol remains at the stable base version.
PLUGIN_VERSION = _SOURCE_VERSION

_EXPECTED_SETTINGS = {
    "cloud_session_sync": False,
    "hooks_disabled": False,
    "logo_animation": "off",
    "marketplace_source": "approved-local",
    "plugin_activation": "shadow-mission@shadow-feasibility-local",
    "sandbox": {
        "enabled": True,
        "denied_read_roots": ["credential", "input", "private", "protected"],
        "mode": "whole-process",
        "network_allowed_domains": ["loopback"],
    },
    "trusted_root": "mission-workspace",
}
_EXPECTED_HOOK_EVENTS = [
    "PostToolUse",
    "SessionEnd",
    "SessionStart",
    "Stop",
    "SubagentStop",
    "UserPromptSubmit",
]
_EXPECTED_HOOK_COMMAND = 'python3 "${DROID_PLUGIN_ROOT}/hooks/shadow_hook.py"'
_REQUIRED_FIELDS = {
    "schema_version",
    "settings",
    "plugins",
    "hooks",
    "mcp_servers",
    "custom_skills",
    "custom_droids",
    "builtin_droids",
    "instruction_files",
    "managed_settings",
    "unknown_surfaces",
    "gate_surface_digest",
    "installed_plugin_artifact_digest",
    "resolved_plugin_source",
    "shadow_activation",
}

GATE_SURFACE_PATHS = (
    ".factory-plugin/plugin.json",
    "hooks/hooks.json",
    "hooks/shadow_hook.py",
    "hooks/hook_runtime.py",
)
PLUGIN_ARTIFACT_ROOTS = (
    ".factory-plugin",
    "hooks",
    "src/shadow_mission",
    "pyproject.toml",
)
_IGNORED_ARTIFACT_PARTS = {"__pycache__", ".pytest_cache"}
_APPROVED_USER_SETTINGS = {
    "cloudSessionSync",
    "enabledPlugins",
    "extraKnownMarketplaces",
    "hooksDisabled",
    "logoAnimation",
    "sandbox",
    "trustedFolders",
}
_APPROVED_BUILTIN_DROIDS: dict[str, str] = {}


def _expected_builtin_droids() -> list[dict[str, str]]:
    return [
        {
            "name": name,
            "sha256": digest,
            "source": "factory-builtin",
        }
        for name, digest in sorted(_APPROVED_BUILTIN_DROIDS.items())
    ]


class FactoryProfileError(ValueError):
    """Raised when inherited Factory configuration is not fully known."""


@dataclass(frozen=True)
class FactoryProfileResult:
    digest: str
    activation_enabled: bool
    status: str

@dataclass(frozen=True)
class FactoryProfileComparison:
    identical_except_activation: bool
    baseline_digest: str
    shadow_digest: str


def _validate_digest(value: Any, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise FactoryProfileError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _validate_artifact_permissions(path: Path, relative_name: str) -> None:
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    shared_group_write = bool(mode & 0o020) and metadata.st_gid != metadata.st_uid
    if mode & 0o002 or shared_group_write:
        raise FactoryProfileError(
            f"artifact path is writable outside its private owner group: {relative_name}"
        )
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise FactoryProfileError(f"artifact path owner differs: {relative_name}")


def _artifact_files(root: Path, roots: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for relative_name in roots:
        path = root / relative_name
        if not path.exists():
            raise FactoryProfileError(f"artifact path is missing: {relative_name}")
        if path.is_symlink():
            raise FactoryProfileError(f"artifact path is a symlink: {relative_name}")
        _validate_artifact_permissions(path, relative_name)
        if path.is_file():
            files.append(path)
            continue
        if not path.is_dir():
            raise FactoryProfileError(f"artifact path is not regular: {relative_name}")
        for child in path.rglob("*"):
            relative = child.relative_to(root)
            if any(part in _IGNORED_ARTIFACT_PARTS for part in relative.parts):
                continue
            if child.is_symlink():
                raise FactoryProfileError(f"artifact contains a symlink: {relative}")
            _validate_artifact_permissions(child, relative.as_posix())
            if child.is_dir():
                continue
            if not child.is_file() or child.suffix in {".pyc", ".pyo"}:
                continue
            files.append(child)
    return sorted(set(files), key=lambda item: item.relative_to(root).as_posix())


def artifact_manifest(root: Path, roots: Iterable[str]) -> dict[str, Any]:
    resolved_root = root.resolve()
    records: list[dict[str, Any]] = []
    for path in _artifact_files(resolved_root, roots):
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise FactoryProfileError(f"artifact is not a regular file: {path.name}")
        records.append(
            {
                "path": path.relative_to(resolved_root).as_posix(),
                "mode": stat.S_IMODE(metadata.st_mode),
                "size": metadata.st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return {"schema_version": SCHEMA_VERSION, "files": records}


def compute_gate_surface_digest(project_root: Path) -> str:
    manifest = artifact_manifest(project_root, GATE_SURFACE_PATHS)
    if tuple(record["path"] for record in manifest["files"]) != tuple(
        sorted(GATE_SURFACE_PATHS)
    ):
        raise FactoryProfileError("gate surface file set differs from the contract")
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def resolve_installed_plugin_root(
    plugins_root: Path,
    *,
    plugin_name: str,
    plugin_version: str,
    expected_digest: str,
) -> Path:
    _validate_digest(expected_digest, "installed plugin artifact digest")
    try:
        root = plugins_root.resolve(strict=True)
    except OSError as error:
        raise FactoryProfileError("Factory plugin state is unavailable") from error
    if not root.is_dir() or root.is_symlink():
        raise FactoryProfileError("Factory plugin state is invalid")
    manifests = list(root.rglob(".factory-plugin/plugin.json"))
    if len(manifests) > 256:
        raise FactoryProfileError("Factory plugin inventory exceeds its bound")
    matches: list[Path] = []
    for manifest_path in manifests:
        try:
            if manifest_path.is_symlink():
                raise FactoryProfileError("installed plugin manifest is a symlink")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise FactoryProfileError(
                "installed plugin manifest is unreadable"
            ) from error
        if not isinstance(manifest, Mapping):
            raise FactoryProfileError("installed plugin manifest is invalid")
        if manifest.get("name") != plugin_name:
            continue
        if manifest.get("version") != plugin_version:
            raise FactoryProfileError("installed plugin version differs")
        candidate = manifest_path.parent.parent.resolve(strict=True)
        if root not in candidate.parents:
            raise FactoryProfileError("installed plugin escaped Factory state")
        if compute_plugin_artifact_digest(candidate) == expected_digest:
            matches.append(candidate)
    if len(matches) != 1:
        raise FactoryProfileError(
            "exactly one installed plugin artifact must match Factory state"
        )
    return matches[0]


def compute_plugin_artifact_digest(project_root: Path) -> str:
    manifest = artifact_manifest(project_root, PLUGIN_ARTIFACT_ROOTS)
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def capture_factory_profile(
    *,
    factory_root: Path,
    project_root: Path,
    installed_plugin_root: Path,
    trusted_root: Path,
    credential_root: Path,
    input_root: Path,
    private_root: Path,
    protected_root: Path,
    marketplace_root: Path,
    system_settings_path: Path,
    shadow_activation: bool,
) -> dict[str, Any]:
    """Measure the exact Factory configuration inherited by the guest Mission."""
    try:
        resolved_factory_root = factory_root.resolve(strict=True)
        resolved_project_root = project_root.resolve(strict=True)
        resolved_installed_root = installed_plugin_root.resolve(strict=True)
        resolved_trusted_root = trusted_root.resolve(strict=True)
        resolved_credential_root = credential_root.resolve(strict=True)
        resolved_input_root = input_root.resolve(strict=True)
        resolved_private_root = private_root.resolve(strict=True)
        resolved_protected_root = protected_root.resolve(strict=True)
        resolved_marketplace_root = marketplace_root.resolve(strict=True)
        settings_path = resolved_factory_root / "settings.json"
        settings_metadata = settings_path.lstat()
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FactoryProfileError("Factory user settings are unavailable") from error
    if (
        resolved_factory_root.is_symlink()
        or settings_path.is_symlink()
        or not stat.S_ISREG(settings_metadata.st_mode)
        or not isinstance(settings, Mapping)
    ):
        raise FactoryProfileError("Factory user settings are invalid")
    if set(settings) != _APPROVED_USER_SETTINGS:
        raise FactoryProfileError("Factory user settings contain an unknown surface")
    expected_enabled_plugin = {
        "shadow-mission@shadow-feasibility-local": True,
    }
    expected_marketplace = {
        "shadow-feasibility-local": {
            "source": {
                "source": "local",
                "path": str(resolved_marketplace_root),
            }
        }
    }
    trusted_folders = settings.get("trustedFolders")
    if (
        settings.get("enabledPlugins") != expected_enabled_plugin
        or settings.get("extraKnownMarketplaces") != expected_marketplace
        or settings.get("cloudSessionSync") is not False
        or settings.get("hooksDisabled") is not False
        or settings.get("logoAnimation") != "off"
        or settings.get("sandbox")
        != {
            "enabled": True,
            "mode": "whole-process",
            "filesystem": {
                "denyRead": [
                    str(resolved_credential_root),
                    str(resolved_input_root),
                    str(resolved_private_root),
                    str(resolved_protected_root),
                ]
            },
            "network": {"allowedDomains": ["127.0.0.1"]},
        }
        or not isinstance(trusted_folders, Mapping)
        or set(trusted_folders) != {str(resolved_trusted_root)}
    ):
        raise FactoryProfileError("Factory user settings differ from the approved set")
    trust_record = trusted_folders[str(resolved_trusted_root)]
    if (
        not isinstance(trust_record, Mapping)
        or set(trust_record) != {"trustedAt"}
        or not isinstance(trust_record.get("trustedAt"), str)
        or not str(trust_record["trustedAt"]).endswith("Z")
    ):
        raise FactoryProfileError("Factory trusted-folder evidence is invalid")

    installed_digest = compute_plugin_artifact_digest(resolved_installed_root)
    resolved_plugin = resolve_installed_plugin_root(
        resolved_factory_root / "plugins",
        plugin_name="shadow-mission",
        plugin_version=PLUGIN_VERSION,
        expected_digest=installed_digest,
    )
    if resolved_plugin != resolved_installed_root:
        raise FactoryProfileError("Factory resolved a different plugin source")

    forbidden_user_surfaces = (
        resolved_factory_root / "hooks.json",
        resolved_factory_root / "mcp.json",
        resolved_factory_root / "commands",
        resolved_factory_root / "skills",
    )
    forbidden_project_surfaces = (
        resolved_project_root / "AGENTS.md",
        resolved_project_root / ".droid.yaml",
        resolved_project_root / ".factory",
    )
    if system_settings_path.exists() or any(
        path.exists() for path in (*forbidden_user_surfaces, *forbidden_project_surfaces)
    ):
        raise FactoryProfileError("Factory configuration contains an unknown surface")

    droids_root = resolved_factory_root / "droids"
    try:
        observed_droids = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in droids_root.iterdir()
            if path.is_file() and not path.is_symlink()
        }
    except OSError as error:
        raise FactoryProfileError("Factory built-in droid inventory is unavailable") from error
    if observed_droids != _APPROVED_BUILTIN_DROIDS:
        raise FactoryProfileError("Factory custom droid inventory is not approved")

    sandbox = settings["sandbox"]
    assert isinstance(sandbox, Mapping)
    profile = {
        "schema_version": SCHEMA_VERSION,
        "settings": {
            "cloud_session_sync": settings["cloudSessionSync"],
            "hooks_disabled": settings["hooksDisabled"],
            "logo_animation": settings["logoAnimation"],
            "marketplace_source": "approved-local",
            "plugin_activation": next(iter(expected_enabled_plugin)),
            "sandbox": {
                "denied_read_roots": [
                    "credential",
                    "input",
                    "private",
                    "protected",
                ],
                "enabled": sandbox["enabled"],
                "mode": sandbox["mode"],
                "network_allowed_domains": ["loopback"],
            },
            "trusted_root": "mission-workspace",
        },
        "plugins": [
            {
                "name": "shadow-mission",
                "version": PLUGIN_VERSION,
                "enabled": True,
            }
        ],
        "hooks": [
            {
                "source": "shadow-mission",
                "events": list(_EXPECTED_HOOK_EVENTS),
                "command": _EXPECTED_HOOK_COMMAND,
                "timeout": 2,
            }
        ],
        "mcp_servers": [],
        "custom_skills": [],
        "builtin_droids": [
            {
                "name": name,
                "sha256": digest,
                "source": "factory-builtin",
            }
            for name, digest in sorted(observed_droids.items())
        ],
        "custom_droids": [],
        "instruction_files": [],
        "managed_settings": {},
        "unknown_surfaces": [],
        "gate_surface_digest": compute_gate_surface_digest(resolved_project_root),
        "installed_plugin_artifact_digest": installed_digest,
        "resolved_plugin_source": f"sha256:{installed_digest}",
        "shadow_activation": shadow_activation,
    }
    validate_factory_profile(profile)
    return profile

def _normalized_without_activation(profile: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: profile[key]
        for key in sorted(profile)
        if key != "shadow_activation"
    }


def validate_factory_profile(profile: Mapping[str, Any]) -> FactoryProfileResult:
    if set(profile) != _REQUIRED_FIELDS:
        missing = sorted(_REQUIRED_FIELDS - set(profile))
        extra = sorted(set(profile) - _REQUIRED_FIELDS)
        raise FactoryProfileError(
            f"Factory profile fields differ; missing={missing}, extra={extra}"
        )
    if profile["schema_version"] != SCHEMA_VERSION:
        raise FactoryProfileError("unsupported Factory profile schema")
    unknown = profile["unknown_surfaces"]
    if not isinstance(unknown, list) or unknown:
        raise FactoryProfileError("unknown Factory surfaces must be empty")
    if profile["settings"] != _EXPECTED_SETTINGS:
        raise FactoryProfileError("Factory settings differ from the approved set")

    plugins = profile["plugins"]
    if not isinstance(plugins, list) or plugins != [
        {
            "name": "shadow-mission",
            "version": PLUGIN_VERSION,
            "enabled": True,
        }
    ]:
        raise FactoryProfileError("Factory plugin inventory is not approved")
    expected_hook = {
        "source": "shadow-mission",
        "events": _EXPECTED_HOOK_EVENTS,
        "command": _EXPECTED_HOOK_COMMAND,
        "timeout": 2,
    }
    if profile["hooks"] != [expected_hook]:
        raise FactoryProfileError("Factory hook contract is not approved")

    for empty_surface in (
        "builtin_droids",
        "custom_droids",
        "mcp_servers",
        "custom_skills",
        "instruction_files",
    ):
        if profile[empty_surface] != []:
            raise FactoryProfileError(
                f"clean profile has unapproved {empty_surface.replace('_', ' ')}"
            )
    managed_settings = profile["managed_settings"]
    if profile["builtin_droids"] != _expected_builtin_droids():
        raise FactoryProfileError("Factory built-in droid inventory is not approved")
    if not isinstance(managed_settings, dict):
        raise FactoryProfileError("managed settings inventory must be an object")
    profile_status = "pass"
    if managed_settings:
        profile_status = "fallback"
        for name, evidence in managed_settings.items():
            if not isinstance(name, str) or not name or not isinstance(evidence, dict):
                raise FactoryProfileError("managed setting evidence is malformed")
            if set(evidence) != {
                "mandatory",
                "readable",
                "sealed_digest",
                "negative_control_passed",
            }:
                raise FactoryProfileError("managed setting evidence fields differ")
            if (
                evidence["mandatory"] is not True
                or evidence["readable"] is not True
                or evidence["negative_control_passed"] is not True
            ):
                raise FactoryProfileError("managed setting fallback is not proven")
            _validate_digest(evidence["sealed_digest"], "managed setting sealed_digest")
    _validate_digest(profile["gate_surface_digest"], "gate_surface_digest")
    _validate_digest(
        profile["installed_plugin_artifact_digest"],
        "installed_plugin_artifact_digest",
    )
    expected_source = f"sha256:{profile['installed_plugin_artifact_digest']}"
    if profile["resolved_plugin_source"] != expected_source:
        raise FactoryProfileError(
            "resolved plugin source does not match the installed artifact"
        )
    if not isinstance(profile["shadow_activation"], bool):
        raise FactoryProfileError("Shadow activation must be boolean")

    digest = hashlib.sha256(
        canonical_json(_normalized_without_activation(profile))
    ).hexdigest()
    return FactoryProfileResult(
        digest=digest,
        activation_enabled=bool(profile["shadow_activation"]),
        status=profile_status,
    )


def compare_factory_profiles(
    baseline: Mapping[str, Any], shadow: Mapping[str, Any]
) -> FactoryProfileComparison:
    baseline_result = validate_factory_profile(baseline)
    shadow_result = validate_factory_profile(shadow)
    return FactoryProfileComparison(
        identical_except_activation=(
            baseline_result.digest == shadow_result.digest
            and baseline["shadow_activation"] is False
            and shadow["shadow_activation"] is True
        ),
        baseline_digest=baseline_result.digest,
        shadow_digest=shadow_result.digest,
    )
