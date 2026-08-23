#!/usr/bin/env python3
"""Create one seeded commit and matching clean baseline and Shadow checkouts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Callable, Mapping, Sequence
from shadow_mission.profile import (
    compute_gate_surface_digest,
    compute_plugin_artifact_digest,
    validate_factory_profile,
)

_PINNED_CONFIG_DIGEST = "4827a29ac2adf6a1dfa8c10021b1acffe0523d32386215253a5d7b59b5a6dac6"
_PINNED_IMAGE_DIGEST = "sha256:7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc"


class PreparationError(RuntimeError):
    pass
_PINNED_SEED_TREE_DIGEST = (
    "b20779ae15b960f071ef1216fda01d22697d9a019b23360900ffe682bcf72df3"
)
_PINNED_MISSION_DIGEST = (
    "1b33958caa8673a937ab3ef5cb8ddcd27708972e2a60067499cf277f3f33c6b7"
)
_PINNED_ROLE_CONFIG_DIGEST = (
    "d9dfa2c17f81796f147c410b5965d30af57771892eed78cee9c0d317c0dd21db"
)
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_FROZEN_SEED = _PROJECT_ROOT / "demo" / "seed"
_FROZEN_MISSION = _PROJECT_ROOT / "demo" / "mission.md"
_FROZEN_ROLE_CONFIG = _PROJECT_ROOT / "demo" / "role-config.json"
_MODEL_ROLES = frozenset(
    {"orchestrator", "worker", "validator", "extractor", "probe"}
)




def canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise PreparationError(f"{path.name} is not a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative_path = path.relative_to(root)
        if ".git" in relative_path.parts or "__pycache__" in relative_path.parts:
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise PreparationError(f"demo tree contains a symlink: {relative_path}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise PreparationError(f"demo tree contains a non-regular file: {relative_path}")
        payload = path.read_bytes()
        files.append(
            {
                "path": relative_path.as_posix(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return hashlib.sha256(canonical_json({"files": files})).hexdigest()


def load_string_mapping(path: Path, description: str) -> dict[str, str]:
    try:
        metadata = path.lstat()
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreparationError(f"{description} is invalid") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or not isinstance(value, dict)
        or set(value) != _MODEL_ROLES
        or any(not isinstance(item, str) or not item for item in value.values())
    ):
        raise PreparationError(f"{description} is invalid")
    return dict(sorted(value.items()))


def _invoke(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    arguments: tuple[str, ...],
    *,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    result = runner(
        arguments,
        cwd=cwd,
        capture_output=True,
        text=True,
        shell=False,
        timeout=120,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
        },
    )
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).strip()[:2048]
        raise PreparationError(f"command failed: {diagnostic}")
    return result


def _validate_materialization_paths(
    *,
    seed: Path,
    mission: Path,
    role_config: Path,
    workspace: Path,
    output: Path,
) -> tuple[Path, Path]:
    if not workspace.is_absolute() or not output.is_absolute():
        raise PreparationError("workspace and output paths must be absolute")
    resolved_workspace = workspace.resolve(strict=False)
    resolved_output = output.resolve(strict=False)
    for name, path in (("workspace", resolved_workspace), ("output", resolved_output)):
        if (
            path == _PROJECT_ROOT
            or _PROJECT_ROOT in path.parents
            or path in _PROJECT_ROOT.parents
        ):
            raise PreparationError(f"{name} must be isolated outside the project")
    if resolved_workspace in resolved_output.parents:
        raise PreparationError("host evidence output must remain outside the workspace")
    if seed.resolve(strict=True) != _FROZEN_SEED:
        raise PreparationError("demo seed is not the frozen project seed")
    if mission.resolve(strict=True) != _FROZEN_MISSION:
        raise PreparationError("demo Mission is not the frozen project Mission")
    if role_config.resolve(strict=True) != _FROZEN_ROLE_CONFIG:
        raise PreparationError("demo role configuration is not frozen")
    return resolved_workspace, resolved_output


def prepare(
    *,
    seed: Path,
    mission: Path,
    workspace: Path,
    lima_config: Path,
    profile_manifest: Path,
    role_config: Path,
    models: Mapping[str, str],
    reasoning: Mapping[str, str],
    factory_profile_digest: str,
    gate_surface_digest: str,
    installed_plugin_artifact_digest: str,
    output: Path,
    baseline_checkout: str,
    shadow_checkout: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, object]:
    workspace, output = _validate_materialization_paths(
        seed=seed,
        mission=mission,
        role_config=role_config,
        workspace=workspace,
        output=output,
    )
    if sha256_file(lima_config) != _PINNED_CONFIG_DIGEST:
        raise PreparationError("Mission Lima configuration differs from the pinned template")
    mission_digest = sha256_file(mission)
    profile_digest = sha256_file(profile_manifest)
    try:
        profile_value = json.loads(profile_manifest.read_bytes())
        if not isinstance(profile_value, dict):
            raise ValueError("profile is not an object")
        observed_profile_digest = validate_factory_profile(profile_value).digest
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise PreparationError("Factory profile manifest is invalid") from error
    observed_gate_digest = compute_gate_surface_digest(_PROJECT_ROOT)
    observed_plugin_digest = compute_plugin_artifact_digest(_PROJECT_ROOT)
    role_config_digest = sha256_file(role_config)
    seed_digest = tree_digest(seed)
    if mission_digest != _PINNED_MISSION_DIGEST:
        raise PreparationError("demo Mission digest differs from its frozen value")
    if role_config_digest != _PINNED_ROLE_CONFIG_DIGEST:
        raise PreparationError("role configuration digest differs from its frozen value")
    if set(models) != _MODEL_ROLES or set(reasoning) != _MODEL_ROLES:
        raise PreparationError("model and reasoning bindings are incomplete")
    if any(not isinstance(value, str) or not value for value in (*models.values(), *reasoning.values())):
        raise PreparationError("model and reasoning bindings are invalid")
    role_configuration = json.loads(role_config.read_bytes())
    mission_role_config_digest = hashlib.sha256(
        canonical_json(
            {
                "models": dict(models),
                "reasoning": dict(reasoning),
                "role_configuration": role_configuration,
            }
        )
    ).hexdigest()
    if seed_digest != _PINNED_SEED_TREE_DIGEST:
        raise PreparationError("demo seed digest differs from its frozen value")
    for name, supplied, observed in (
        ("factory profile", factory_profile_digest, observed_profile_digest),
        ("gate surface", gate_surface_digest, observed_gate_digest),
        (
            "installed plugin artifact",
            installed_plugin_artifact_digest,
            observed_plugin_digest,
        ),
    ):
        if supplied != observed:
            raise PreparationError(f"{name} digest differs from the observed artifact")
    if workspace.exists() or output.exists():
        raise PreparationError("preparation output already exists")
    if seed.is_symlink() or not seed.is_dir():
        raise PreparationError("demo seed is invalid")
    checkout = workspace / "seeded-checkout"
    checkout.parent.mkdir(parents=True, mode=0o700)
    shutil.copytree(
        seed,
        checkout,
        symlinks=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    if tree_digest(checkout) != seed_digest:
        raise PreparationError("materialized demo seed digest differs")
    shutil.copy2(mission, checkout / "mission.md")
    for arguments in (
        ("git", "init", "-q", str(checkout)),
        ("git", "-C", str(checkout), "add", "."),
        (
            "git",
            "-C",
            str(checkout),
            "-c",
            "user.name=Shadow Demo",
            "-c",
            "user.email=shadow-demo@example.invalid",
            "commit",
            "-qm",
            "seed",
        ),
    ):
        _invoke(runner, arguments, cwd=workspace)
    head = _invoke(
        runner,
        ("git", "-C", str(checkout), "rev-parse", "HEAD"),
        cwd=workspace,
    ).stdout.strip()
    if len(head) not in {40, 64} or any(character not in "0123456789abcdef" for character in head):
        raise PreparationError("seed commit is invalid")

    checkout_names = (baseline_checkout, shadow_checkout)
    if (
        len(set(checkout_names)) != 2
        or any(
            not name
            or name in {".", "..", "seeded-checkout"}
            or Path(name).name != name
            for name in checkout_names
        )
    ):
        raise PreparationError("checkout names must be distinct safe path components")
    checkout_heads: dict[str, str] = {}
    for name in checkout_names:
        destination = workspace / name
        shutil.copytree(checkout, destination, symlinks=True)
        observed_head = _invoke(
            runner,
            ("git", "-C", str(destination), "rev-parse", "HEAD"),
            cwd=workspace,
        ).stdout.strip()
        if observed_head != head:
            raise PreparationError("baseline and Shadow checkout HEAD hashes differ")
        dirty_state = _invoke(
            runner,
            ("git", "-C", str(destination), "status", "--porcelain"),
            cwd=workspace,
        ).stdout
        if dirty_state.strip():
            raise PreparationError("prepared demonstration checkout is dirty")
        checkout_heads[name] = observed_head

    value: dict[str, object] = {
        "schema_version": "0.1",
        "seed_commit": head,
        "seed_tree_digest": tree_digest(checkout),
        "mission_digest": mission_digest,
        "profile_manifest_digest": profile_digest,
        "role_config_digest": role_config_digest,
        "mission_role_config_digest": mission_role_config_digest,
        "lima_config_digest": _PINNED_CONFIG_DIGEST,
        "vm_image_digest": _PINNED_IMAGE_DIGEST,
        "factory_profile_digest": factory_profile_digest,
        "gate_surface_digest": gate_surface_digest,
        "installed_plugin_artifact_digest": installed_plugin_artifact_digest,
        "baseline_checkout": baseline_checkout,
        "shadow_checkout": shadow_checkout,
        "checkout_heads": dict(sorted(checkout_heads.items())),
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, output)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--seed", type=Path, required=True)
    value.add_argument("--mission", type=Path, required=True)
    value.add_argument("--workspace", type=Path, required=True)
    value.add_argument("--lima-config", type=Path, required=True)
    value.add_argument("--profile-manifest", type=Path, required=True)
    value.add_argument("--role-config", type=Path, required=True)
    value.add_argument("--models", type=Path, required=True)
    value.add_argument("--reasoning", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    value.add_argument("--factory-profile-digest", required=True)
    value.add_argument("--gate-surface-digest", required=True)
    value.add_argument("--installed-plugin-artifact-digest", required=True)
    value.add_argument("--baseline-checkout", default="baseline-checkout")
    value.add_argument("--shadow-checkout", default="shadow-checkout")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        value = prepare(
            seed=arguments.seed,
            mission=arguments.mission,
            workspace=arguments.workspace,
            lima_config=arguments.lima_config,
            profile_manifest=arguments.profile_manifest,
            role_config=arguments.role_config,
            models=load_string_mapping(arguments.models, "model bindings"),
            reasoning=load_string_mapping(arguments.reasoning, "reasoning bindings"),
            factory_profile_digest=arguments.factory_profile_digest,
            gate_surface_digest=arguments.gate_surface_digest,
            installed_plugin_artifact_digest=arguments.installed_plugin_artifact_digest,
            output=arguments.output,
            baseline_checkout=arguments.baseline_checkout,
            shadow_checkout=arguments.shadow_checkout,
            runner=subprocess.run,
        )
    except (PreparationError, OSError, ValueError) as error:
        print(f"demo preparation stopped: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "baseline_checkout": str(
                    arguments.workspace / str(value["baseline_checkout"])
                ),
                "output": str(arguments.output),
                "seed_commit": value["seed_commit"],
                "shadow_checkout": str(
                    arguments.workspace / str(value["shadow_checkout"])
                ),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
