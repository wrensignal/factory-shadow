"""No-spend construction of one fresh, approval-bound release preflight."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Callable, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .correlation import factory_relation_source_digest
from .isolation import IsolationError, validate_isolation_manifest
from .profile import (
    FactoryProfileError,
    compute_gate_surface_digest,
    compute_plugin_artifact_digest,
    validate_factory_profile,
)
from .protocol import BaselineRunRecord, CapabilityFlags, canonical_json
from .runtime import (
    BudgetApproval,
    CommandRunner,
    PreflightError,
    ReleasePreflight,
    SubprocessCommandRunner,
    _repository_head,
    _require_clean_repository,
    _sha256_file,
    compute_full_source_digest,
    release_preflight_digest,
)


class PreflightBuildError(ValueError):
    """A fresh release preflight cannot be built without spending."""


def release_approval_digest(value: Mapping[str, Any]) -> str:
    material = {key: item for key, item in value.items() if key != "record_digest"}
    return hashlib.sha256(canonical_json(material)).hexdigest()


class ReleaseApproval(BaseModel):
    """Direct, host-held approval and measured release capability input."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    preflight_id: str = Field(min_length=1, max_length=128)
    authorization_id: str = Field(min_length=1, max_length=128)
    authorized_by: str = Field(min_length=1, max_length=128)
    approved_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)
    paid_run_authorized: Literal[True]
    authorization_scope: Literal["one-shadow-mission"]
    release_gate_verdict: Literal["primary-pass", "fallback-pass"]
    initial_commit: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    droid_installation_channel: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    droid_auto_update_control: Literal["env-false", "npm-build-disabled"]
    models: dict[str, str]
    reasoning: dict[str, str]
    role_configuration: dict[str, Any]
    budget: BudgetApproval
    capabilities: CapabilityFlags
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_approval(self) -> "ReleaseApproval":
        if self.expires_at <= self.approved_at:
            raise ValueError("release approval expiry is invalid")
        if self.capabilities.release_gate_verdict != self.release_gate_verdict:
            raise ValueError("release approval capability verdict differs")
        if self.record_digest != release_approval_digest(self.model_dump(mode="json")):
            raise ValueError("release approval digest differs")
        return self


def load_release_approval(path: Path) -> ReleaseApproval:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
        value = json.loads(payload)
        approval = ReleaseApproval.model_validate(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise PreflightBuildError("release approval is invalid") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or canonical_json(approval.model_dump(mode="json")) + b"\n" != payload
    ):
        raise PreflightBuildError("release approval is not canonical and private")
    return approval


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreflightBuildError(f"{description} is unavailable") from error
    if not isinstance(value, dict):
        raise PreflightBuildError(f"{description} must be an object")
    return value


def _write_private_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    parent = path.parent.resolve(strict=True)
    metadata = parent.lstat()
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise PreflightBuildError("release preflight output root is not private")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(parent / path.name, flags, 0o600)
    except OSError as error:
        raise PreflightBuildError("release preflight output is unavailable") from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        descriptor = -1
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def build_release_preflight(
    *,
    project_root: Path,
    repo: Path,
    mission_file: Path,
    evaluator: Path,
    profile_manifest: Path,
    isolation_manifest: Path,
    lima_config: Path,
    feasibility_record: Path,
    droid_path: Path,
    approval_path: Path,
    output_path: Path,
    baseline_record: Path | None = None,
    command_runner: CommandRunner | None = None,
    clock: Callable[[], float] = time.time,
) -> ReleasePreflight:
    """Build one immutable release preflight without a model or Mission call."""

    try:
        project_root = project_root.resolve(strict=True)
        repo = repo.resolve(strict=True)
        mission_file = mission_file.resolve(strict=True)
        evaluator = evaluator.resolve(strict=True)
        profile_manifest = profile_manifest.resolve(strict=True)
        isolation_manifest = isolation_manifest.resolve(strict=True)
        lima_config = lima_config.resolve(strict=True)
        feasibility_record = feasibility_record.resolve(strict=True)
        droid_path = droid_path.resolve(strict=True)
        approval_path = approval_path.resolve(strict=True)
    except OSError as error:
        raise PreflightBuildError("release preflight input is unavailable") from error
    if mission_file.parent != repo and repo not in mission_file.parents:
        raise PreflightBuildError("Mission file must remain inside the repository")
    if not evaluator.is_file() or not os.access(evaluator, os.X_OK):
        raise PreflightBuildError("evaluator is not executable")
    if not droid_path.is_file() or not os.access(droid_path, os.X_OK):
        raise PreflightBuildError("Droid binary is not executable")

    approval = load_release_approval(approval_path)
    now = int(clock())
    if now < approval.approved_at or now >= approval.expires_at:
        raise PreflightBuildError("release approval is not active")
    initial_commit = _repository_head(repo)
    if initial_commit != approval.initial_commit:
        raise PreflightBuildError("release approval commit differs")
    try:
        _require_clean_repository(repo)
    except PreflightError as error:
        raise PreflightBuildError("Mission repository must be clean") from error

    historical = _read_json(feasibility_record, "historical feasibility record")
    if (
        historical.get("core_feasibility_verdict") != "pass"
        or historical.get("live_run_count") != 2
        or not isinstance(historical.get("bindings"), Mapping)
    ):
        raise PreflightBuildError("historical feasibility record is not releasable")
    historical_bindings = historical["bindings"]
    historical_digest = hashlib.sha256(canonical_json(historical)).hexdigest()
    historical_launch_digest = historical_bindings.get(
        "launch_installed_plugin_artifact_digest"
    )
    if not isinstance(historical_launch_digest, str):
        raise PreflightBuildError("historical launch artifact binding is missing")

    gate_digest = compute_gate_surface_digest(project_root)
    artifact_digest = compute_plugin_artifact_digest(project_root)
    full_run_digest = compute_full_source_digest(project_root)
    profile_value = _read_json(profile_manifest, "Factory profile")
    try:
        profile_result = validate_factory_profile(profile_value)
    except FactoryProfileError as error:
        raise PreflightBuildError("Factory profile is not approved") from error
    if (
        not profile_result.activation_enabled
        or profile_value.get("gate_surface_digest") != gate_digest
        or profile_value.get("installed_plugin_artifact_digest") != artifact_digest
    ):
        raise PreflightBuildError("Factory profile binding differs")
    try:
        isolation_result = validate_isolation_manifest(
            isolation_manifest,
            lima_config,
            require_live_canaries=False,
        )
    except IsolationError as error:
        raise PreflightBuildError("isolation manifest is not approved") from error
    if historical_bindings.get("isolation_config_digest") != isolation_result.config_digest:
        raise PreflightBuildError("historical isolation binding differs")

    droid_digest = _sha256_file(droid_path)
    runner = command_runner or SubprocessCommandRunner()
    observation = runner.run(
        (str(droid_path), "--version"),
        environment={
            "HOME": os.environ.get("HOME", "/home/shadow"),
            "PATH": f"{droid_path.parent}:/usr/bin:/bin",
            "FACTORY_DROID_AUTO_UPDATE_ENABLED": "false",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        cwd=repo,
        timeout_seconds=30,
    )
    if observation.returncode != 0 or not re.search(
        rf"(?<![0-9.]){re.escape(approval.capabilities.droid_version)}(?![0-9.])",
        observation.stdout,
    ):
        raise PreflightBuildError("Droid version observation differs")

    plugin_value = _read_json(
        project_root / ".factory-plugin/plugin.json",
        "plugin manifest",
    )
    try:
        sdk_version = importlib.metadata.version("droid-sdk")
    except importlib.metadata.PackageNotFoundError as error:
        raise PreflightBuildError("Droid SDK is unavailable") from error
    current_bindings = {
        "droid_version": approval.capabilities.droid_version,
        "plugin_version": str(plugin_value.get("version", "")),
        "droid_sdk_version": sdk_version,
        "lima_version": approval.capabilities.lima_version,
        "vm_image_digest": isolation_result.image_digest,
        "factory_profile_digest": profile_result.digest,
        "isolation_digest": isolation_result.config_digest,
        "gate_surface_digest": gate_digest,
        "installed_plugin_artifact_digest": artifact_digest,
    }
    capability_value = approval.capabilities.model_dump(mode="json")
    if any(capability_value[name] != value for name, value in current_bindings.items()):
        raise PreflightBuildError("release capability binding differs")

    models = dict(approval.models)
    reasoning = dict(approval.reasoning)
    role_configuration = dict(approval.role_configuration)
    role_digest = hashlib.sha256(
        canonical_json(
            {
                "models": models,
                "reasoning": reasoning,
                "role_configuration": role_configuration,
            }
        )
    ).hexdigest()
    baseline_id: str | None = None
    baseline_digest: str | None = None
    if baseline_record is not None:
        try:
            baseline_path = baseline_record.resolve(strict=True)
            baseline_value = _read_json(baseline_path, "baseline record")
            baseline = BaselineRunRecord.model_validate(baseline_value)
        except (OSError, ValueError) as error:
            raise PreflightBuildError("baseline record is invalid") from error
        if canonical_json(baseline.model_dump(mode="json")) + b"\n" != baseline_path.read_bytes():
            raise PreflightBuildError("baseline record is not canonical")
        baseline_id = baseline.baseline_id
        baseline_digest = baseline.record_digest

    value: dict[str, Any] = {
        "schema_version": "0.1",
        "preflight_id": approval.preflight_id,
        "approved_at": approval.approved_at,
        "expires_at": approval.expires_at,
        "authorization_id": approval.authorization_id,
        "paid_run_authorized": approval.paid_run_authorized,
        "authorization_scope": approval.authorization_scope,
        "release_gate_verdict": approval.release_gate_verdict,
        "historical_record_digest": historical_digest,
        "historical_launch_artifact_digest": historical_launch_digest,
        "droid_version": current_bindings["droid_version"],
        "droid_installation_channel": approval.droid_installation_channel,
        "droid_binary_digest": droid_digest,
        "droid_auto_update_control": approval.droid_auto_update_control,
        "plugin_version": current_bindings["plugin_version"],
        "droid_sdk_version": current_bindings["droid_sdk_version"],
        "lima_version": current_bindings["lima_version"],
        "vm_image_digest": current_bindings["vm_image_digest"],
        "factory_profile_digest": current_bindings["factory_profile_digest"],
        "profile_manifest_digest": _sha256_file(profile_manifest),
        "isolation_digest": current_bindings["isolation_digest"],
        "isolation_manifest_digest": _sha256_file(isolation_manifest),
        "gate_surface_digest": current_bindings["gate_surface_digest"],
        "resolved_plugin_source": f"sha256:{artifact_digest}",
        "installed_plugin_artifact_digest": artifact_digest,
        "full_run_artifact_digest": full_run_digest,
        "mission_digest": _sha256_file(mission_file),
        "mission_role_config_digest": role_digest,
        "mission_relation_source_digest": factory_relation_source_digest(
            droid_digest
        ),
        "evaluator_digest": _sha256_file(evaluator),
        "initial_commit": initial_commit,
        "baseline_id": baseline_id,
        "baseline_record_digest": baseline_digest,
        "models": models,
        "reasoning": reasoning,
        "role_configuration": role_configuration,
        "budget": approval.budget.model_dump(mode="json"),
        "capabilities": capability_value,
        "record_digest": "0" * 64,
    }
    value["record_digest"] = release_preflight_digest(value)
    try:
        preflight = ReleasePreflight.model_validate(value)
    except ValueError as error:
        raise PreflightBuildError("release preflight is invalid") from error
    _write_private_exclusive(output_path, preflight.model_dump(mode="json"))
    return preflight
