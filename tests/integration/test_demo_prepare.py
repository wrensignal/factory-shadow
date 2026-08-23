from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from demo.prepare import PreparationError, main, prepare, sha256_file, tree_digest
from shadow_mission.profile import (
    compute_gate_surface_digest,
    compute_plugin_artifact_digest,
    validate_factory_profile,
)


PROJECT_ROOT = Path(__file__).parents[2]
HEAD = "1" * 40
MODEL_BINDINGS = {
    role: f"model-{role}"
    for role in ("orchestrator", "worker", "validator", "extractor", "probe")
}
REASONING_BINDINGS = dict.fromkeys(MODEL_BINDINGS, "high")
PROFILE = PROJECT_ROOT / "tests/fixtures/feasibility/factory-profile.json"
FACTORY_PROFILE_DIGEST = validate_factory_profile(json.loads(PROFILE.read_bytes())).digest
GATE_SURFACE_DIGEST = compute_gate_surface_digest(PROJECT_ROOT)
PLUGIN_ARTIFACT_DIGEST = compute_plugin_artifact_digest(PROJECT_ROOT)




class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, arguments: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(arguments)
        stdout = HEAD + "\n" if arguments[-2:] == ("rev-parse", "HEAD") else ""
        return subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr="")


def test_prepare_seeds_identical_external_host_checkouts(tmp_path: Path) -> None:
    runner = FakeRunner()
    workspace = tmp_path / "workspace"
    output = tmp_path / "preparation.json"
    profile = PROFILE

    value = prepare(
        seed=PROJECT_ROOT / "demo/seed",
        mission=PROJECT_ROOT / "demo/mission.md",
        workspace=workspace,
        lima_config=PROJECT_ROOT / "ops/lima/shadow-feasibility.yaml",
        profile_manifest=profile,
        role_config=PROJECT_ROOT / "demo/role-config.json",
        factory_profile_digest=FACTORY_PROFILE_DIGEST,
        models=MODEL_BINDINGS,
        reasoning=REASONING_BINDINGS,
        gate_surface_digest=GATE_SURFACE_DIGEST,
        installed_plugin_artifact_digest=PLUGIN_ARTIFACT_DIGEST,
        output=output,
        baseline_checkout="baseline-checkout",
        shadow_checkout="shadow-checkout",
        runner=runner,
    )

    assert value["seed_commit"] == HEAD
    assert value["checkout_heads"] == {
        "baseline-checkout": HEAD,
        "shadow-checkout": HEAD,
    }
    assert value["profile_manifest_digest"] == sha256_file(profile)
    assert json.loads(output.read_bytes()) == value
    assert not any(call[0] == "limactl" for call in runner.calls)
    expected_role_digest = hashlib.sha256(
        json.dumps(
            {
                "models": MODEL_BINDINGS,
                "reasoning": REASONING_BINDINGS,
                "role_configuration": json.loads(
                    (PROJECT_ROOT / "demo/role-config.json").read_bytes()
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    assert value["mission_role_config_digest"] == expected_role_digest
    assert (workspace / "baseline-checkout" / "api-schema.json").is_file()
    assert (workspace / "shadow-checkout" / "api-schema.json").is_file()
    assert (workspace / "baseline-checkout" / "mission.md").is_file()
    assert (workspace / "shadow-checkout" / "mission.md").is_file()
    assert value["baseline_checkout"] == "baseline-checkout"
    assert value["shadow_checkout"] == "shadow-checkout"


def test_prepare_rejects_mission_visible_workspace_inside_project(tmp_path: Path) -> None:
    runner = FakeRunner()

    with pytest.raises(PreparationError, match="isolated outside"):
        prepare(
            seed=PROJECT_ROOT / "demo/seed",
            mission=PROJECT_ROOT / "demo/mission.md",
            workspace=PROJECT_ROOT / "demo/workspace",
            lima_config=PROJECT_ROOT / "ops/lima/shadow-feasibility.yaml",
            profile_manifest=PROJECT_ROOT / "tests/fixtures/feasibility/factory-profile.json",
            role_config=PROJECT_ROOT / "demo/role-config.json",
            factory_profile_digest="2" * 64,
            models=MODEL_BINDINGS,
            reasoning=REASONING_BINDINGS,
            gate_surface_digest="3" * 64,
            installed_plugin_artifact_digest="4" * 64,
            output=tmp_path / "preparation.json",
            baseline_checkout="baseline-checkout",
            shadow_checkout="shadow-checkout",
            runner=runner,
        )

    assert runner.calls == []


def test_main_materializes_host_checkouts_without_starting_vms(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    output = tmp_path / "preparation.json"
    models_path = tmp_path / "models.json"
    reasoning_path = tmp_path / "reasoning.json"
    models_path.write_text(json.dumps(MODEL_BINDINGS), encoding="utf-8")
    reasoning_path.write_text(json.dumps(REASONING_BINDINGS), encoding="utf-8")

    result = main(
        [
            "--seed",
            str(PROJECT_ROOT / "demo/seed"),
            "--mission",
            str(PROJECT_ROOT / "demo/mission.md"),
            "--workspace",
            str(workspace),
            "--lima-config",
            str(PROJECT_ROOT / "ops/lima/shadow-feasibility.yaml"),
            "--profile-manifest",
            str(PROFILE),
            "--role-config",
            str(PROJECT_ROOT / "demo/role-config.json"),
            "--models",
            str(models_path),
            "--reasoning",
            str(reasoning_path),
            "--output",
            str(output),
            "--factory-profile-digest",
            FACTORY_PROFILE_DIGEST,
            "--gate-surface-digest",
            GATE_SURFACE_DIGEST,
            "--installed-plugin-artifact-digest",
            PLUGIN_ARTIFACT_DIGEST,
        ]
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out)["output"] == str(output)
    assert (workspace / "baseline-checkout" / ".git").is_dir()
    assert (workspace / "shadow-checkout" / ".git").is_dir()


def test_prepare_rejects_symlinked_seed_content(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    shutil.copytree(PROJECT_ROOT / "demo/seed", seed)
    (seed / "leak").symlink_to(PROJECT_ROOT / "demo/mission.md")

    with pytest.raises(PreparationError, match="symlink"):
        tree_digest(seed)
