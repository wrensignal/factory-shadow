from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import demo.run_baseline as baseline_module
from shadow_mission.evaluation import EvaluationRecord
from shadow_mission.protocol import BaselineRunRecord, canonical_json
from shadow_mission.source_export import validate_source_archive
from tests.integration.test_source_export import export, make_repo
from tests.unit.test_evaluation import evaluator_result
from tests.unit.test_reporting import final_run


class FakeHostRunner:
    def __init__(self, mission_root: Path, head: str, *, returncode: int = 0) -> None:
        self.mission_root = mission_root
        self.head = head
        self.returncode = returncode
        self.mission_arguments: tuple[str, ...] = ()
        self.environments: list[dict[str, str]] = []

    def __call__(
        self,
        arguments: tuple[str, ...],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        if arguments[0] == "git" and arguments[-2:] == ("rev-parse", "HEAD"):
            return subprocess.CompletedProcess(arguments, 0, stdout=self.head + "\n", stderr="")
        if arguments[0] == "git" and arguments[-2:] == ("status", "--porcelain"):
            return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")
        self.mission_arguments = arguments
        self.environments.append(dict(kwargs["environment"]))
        mission = self.mission_root / "mission-baseline"
        mission.mkdir()
        (mission / "state.json").write_text(
            json.dumps(
                {
                    "createdAt": "1970-01-01T00:01:40Z",
                    "workingDirectory": str(kwargs["cwd"]),
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(
            arguments,
            self.returncode,
            stdout="",
            stderr="baseline defect" if self.returncode else "",
        )


def write_inputs(tmp_path: Path) -> tuple[Any, ...]:
    checkout = make_repo(tmp_path)
    archive, manifest, exported = export(checkout, tmp_path / "exported")
    assert exported.returncode == 0
    source = validate_source_archive(archive, manifest)
    evaluation = EvaluationRecord.model_validate(
        evaluator_result(archive, manifest, status="fail")
    )
    config = tmp_path / "evaluator.yaml"
    config.write_text("mounts: []\n", encoding="utf-8")
    mission_file = tmp_path / "mission.md"
    mission_file.write_text("Build the payment service.\n", encoding="utf-8")
    droid_path = tmp_path / "droid"
    droid_path.write_bytes(b"pinned droid")
    exporter_path = tmp_path / "export.py"
    exporter_path.write_bytes(b"pinned exporter")
    profile_manifest = tmp_path / "factory-profile.json"
    profile_manifest.write_bytes(b"{}\n")
    role_config = tmp_path / "role-config.json"
    role_config.write_bytes(b"{}\n")

    run_value = final_run("template").model_dump(mode="json")
    bindings = {
        name: run_value[name]
        for name in baseline_module._BINDING_FIELDS
    }
    bindings.update(
        {
            "baseline_id": "baseline-test-preflight",
            "initial_commit": source.manifest.final_commit,
            "isolation_digest": hashlib.sha256(config.read_bytes()).hexdigest(),
            "mission_digest": hashlib.sha256(mission_file.read_bytes()).hexdigest(),
            "droid_binary_digest": hashlib.sha256(droid_path.read_bytes()).hexdigest(),
            "approved_evaluator_digest": "8" * 64,
            "preparation_record_digest": "",
            "profile_manifest_digest": hashlib.sha256(
                profile_manifest.read_bytes()
            ).hexdigest(),
            "role_config_file_digest": hashlib.sha256(
                role_config.read_bytes()
            ).hexdigest(),
            "source_exporter_digest": hashlib.sha256(
                exporter_path.read_bytes()
            ).hexdigest(),
        }
    )
    preparation = {
        "schema_version": "0.1",
        "seed_commit": bindings["initial_commit"],
        "mission_digest": bindings["mission_digest"],
        "mission_role_config_digest": bindings["mission_role_config_digest"],
        "role_config_digest": bindings["role_config_file_digest"],
        "factory_profile_digest": bindings["factory_profile_digest"],
        "gate_surface_digest": bindings["gate_surface_digest"],
        "installed_plugin_artifact_digest": bindings[
            "installed_plugin_artifact_digest"
        ],
        "vm_image_digest": bindings["vm_image_digest"],
        "lima_config_digest": bindings["isolation_digest"],
        "profile_manifest_digest": bindings["profile_manifest_digest"],
        "baseline_checkout": checkout.name,
        "shadow_checkout": "shadow-checkout",
        "checkout_heads": {
            checkout.name: bindings["initial_commit"],
            "shadow-checkout": bindings["initial_commit"],
        },
    }
    preparation["record_digest"] = hashlib.sha256(
        canonical_json(preparation)
    ).hexdigest()
    preparation_path = tmp_path / "preparation.json"
    preparation_path.write_bytes(canonical_json(preparation) + b"\n")

    derived = {
        "approved_evaluator_digest",
        "baseline_id",
        "budget_ledger",
        "mission_relation_record_digest",
        "provenance_status",
        "redaction_status",
        "release_preflight_digest",
        "source_exporter_digest",
    }
    preflight = {
        name: bindings[name]
        for name in baseline_module._BINDING_FIELDS - derived
    }
    preflight.update(
        {
            "preflight_id": "test-preflight",
            "evaluator_digest": bindings["approved_evaluator_digest"],
            "budget": bindings["budget_ledger"],
            "models": {
                "orchestrator": "gpt-5.4-mini",
                "worker": "gpt-5.4-mini",
                "validator": "gpt-5.4-mini",
                "extractor": "gpt-5.4-mini",
                "probe": "gpt-5.6-luna",
            },
            "reasoning": {
                "orchestrator": "low",
                "worker": "low",
                "validator": "low",
                "extractor": "low",
                "probe": "none",
            },
        }
    )
    preflight["record_digest"] = hashlib.sha256(canonical_json(preflight)).hexdigest()
    preflight_path = tmp_path / "release-preflight.json"
    preflight_path.write_bytes(canonical_json(preflight) + b"\n")
    return (
        preparation_path,
        preflight_path,
        profile_manifest,
        role_config,
        checkout,
        mission_file,
        source,
        evaluation,
        bindings,
    )


def factory_root(tmp_path: Path) -> Path:
    home = tmp_path / ".factory"
    missions = home / "missions"
    missions.mkdir(parents=True)
    (home / "sessions").mkdir()
    return missions


def test_trusted_git_probe_has_explicit_timeout(tmp_path: Path) -> None:
    observed: dict[str, object] = {}

    def runner(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.update(kwargs)
        return subprocess.CompletedProcess(arguments, 0, stdout="ok\n", stderr="")

    result = baseline_module._invoke(
        runner,
        ("git", "status", "--porcelain"),
        cwd=tmp_path,
    )

    assert result.returncode == 0
    assert observed["timeout"] == baseline_module._GIT_PROBE_TIMEOUT_SECONDS


def test_bounded_mission_runner_caps_and_marks_both_streams(
    tmp_path: Path,
) -> None:
    stream_limit = 1024
    emitted_per_stream = stream_limit * 4
    script = (
        "import os,signal,time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"payload = b'x' * {emitted_per_stream}\n"
        "os.write(1, payload)\n"
        "os.write(2, payload)\n"
        "while True:\n"
        "    time.sleep(1)\n"
    )
    started = time.monotonic()

    with pytest.raises(
        baseline_module.BaselineError,
        match="output limit exceeded",
    ) as caught:
        baseline_module._run_bounded_mission(
            (sys.executable, "-c", script),
            cwd=tmp_path,
            environment={},
            timeout_seconds=10,
            stream_limit_bytes=stream_limit,
            termination_grace_seconds=1.0,
        )

    assert time.monotonic() - started < 3.0
    error = caught.value
    for output in (error.stdout, error.stderr):
        assert baseline_module._OUTPUT_TRUNCATION_MARKER in output
        retained_bytes = len(output.encode("utf-8"))
        assert retained_bytes <= stream_limit
        assert retained_bytes < emitted_per_stream
    assert error.process_group_id is not None
    with pytest.raises(ProcessLookupError):
        os.killpg(error.process_group_id, 0)


def test_bounded_mission_runner_kills_process_group_at_deadline(
    tmp_path: Path,
) -> None:
    script = "import time\nwhile True:\n    time.sleep(1)\n"
    started = time.monotonic()

    with pytest.raises(
        baseline_module.BaselineError,
        match="timed out",
    ) as caught:
        baseline_module._run_bounded_mission(
            (sys.executable, "-c", script),
            cwd=tmp_path,
            environment={},
            timeout_seconds=0.1,
            stream_limit_bytes=1024,
            termination_grace_seconds=1.0,
        )

    assert time.monotonic() - started < 3.0
    assert caught.value.process_group_id is not None
    with pytest.raises(ProcessLookupError):
        os.killpg(caught.value.process_group_id, 0)


def test_bounded_mission_runner_kills_grandchild_holding_pipes(
    tmp_path: Path,
) -> None:
    grandchild = "import time\nwhile True:\n    time.sleep(1)\n"
    parent = (
        "import os,subprocess,sys\n"
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}])\n"
        "os.write(1, f'{os.getpgrp()}\\n'.encode())\n"
        "os._exit(0)\n"
    )
    started = time.monotonic()

    result = baseline_module._run_bounded_mission(
        (sys.executable, "-c", parent),
        cwd=tmp_path,
        environment={},
        timeout_seconds=10,
        stream_limit_bytes=1024,
        termination_grace_seconds=1.0,
    )

    assert time.monotonic() - started < 3.0
    assert result.returncode == 0
    with pytest.raises(ProcessLookupError):
        os.killpg(int(result.stdout.strip()), 0)


@pytest.mark.parametrize(
    "description",
    ("baseline output", "baseline artifacts", "baseline state"),
)
def test_host_private_paths_cannot_overlap_checkout(
    tmp_path: Path,
    description: str,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    with pytest.raises(baseline_module.BaselineError, match="outside the checkout"):
        baseline_module._require_disjoint_host_paths(
            checkout,
            (checkout / "private", description),
        )


def approval_record() -> SimpleNamespace:
    return SimpleNamespace(
        authorization_id="baseline-authorization",
        record_digest="1" * 64,
        budget=SimpleNamespace(live_run_count=2),
    )


def test_host_baseline_omits_shadow_activation_and_persists_failed_evaluation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        preparation,
        preflight,
        profile,
        role_config,
        checkout,
        mission_file,
        source,
        evaluation,
        values,
    ) = write_inputs(tmp_path)
    mission_root = factory_root(tmp_path)
    runner = FakeHostRunner(mission_root, values["initial_commit"])
    events: list[str] = []
    monkeypatch.setattr(baseline_module, "validate_evaluator_assets", lambda *_: "8" * 64)
    monkeypatch.setattr(baseline_module, "load_release_preflight", lambda _: approval_record())

    def export_source(**_: object) -> Any:
        events.append("export")
        return source

    def evaluate_source(**_: object) -> EvaluationRecord:
        events.append("evaluate")
        return evaluation

    monkeypatch.setattr(baseline_module, "export_final_source", export_source)
    monkeypatch.setattr(baseline_module, "run_isolated_evaluator", evaluate_source)
    ticks = iter((100, 105))
    output = tmp_path / "baseline.json"

    record = baseline_module.run_host_baseline(
        preparation_path=preparation,
        preflight_path=preflight,
        profile_manifest=profile,
        role_config=role_config,
        checkout=checkout,
        mission_file=mission_file,
        exporter_path=tmp_path / "export.py",
        evaluator_lima_config=tmp_path / "evaluator.yaml",
        evaluator_path=tmp_path / "evaluate.py",
        output_path=output,
        artifact_root=tmp_path / "artifacts",
        evaluator_vm="evaluator-vm",
        droid_path=tmp_path / "droid",
        evaluator_driver=object(),
        secret_canaries=(),
        factory_mission_root=mission_root,
        state_root=tmp_path / "state",
        environment={
            "AWS_SECRET_ACCESS_KEY": "must-not-propagate",
            "HOME": str(tmp_path / "factory-home"),
            "SAFE": "must-not-propagate",
            "SHADOW_MISSION_RUN_FILE": "/private/run.json",
        },
        runner=runner,
        mission_runner=runner,
        clock=lambda: next(ticks),
    )

    assert isinstance(record, BaselineRunRecord)
    assert record.evaluator_outcome["status"] == "fail"
    assert record.duration_seconds == 5.0
    assert record.usage_data == {
        "cleanup_observations": {
            "evaluator_vm_deleted": True,
            "mission_process_group_stopped": True,
        },
        "consumed_authorization_reference": {
            "authorization_id_digest": hashlib.sha256(
                b"baseline-authorization"
            ).hexdigest(),
            "consumed_at": 100,
            "preflight_record_digest": "1" * 64,
            "run_id": "baseline-test-preflight",
        },
        "failure_classification": "baseline-qualification-failed",
        "factory_mission_id": "mission-baseline",
        "status": "unavailable",
    }
    assert runner.mission_arguments[-12:] == (
        "--model",
        "gpt-5.4-mini",
        "--reasoning-effort",
        "low",
        "--worker-model",
        "gpt-5.4-mini",
        "--worker-reasoning-effort",
        "low",
        "--validator-model",
        "gpt-5.4-mini",
        "--validator-reasoning-effort",
        "low",
    )
    assert events == ["export", "evaluate"]
    assert runner.environments == [
        {
            "HOME": str(tmp_path / "factory-home"),
            "FACTORY_DROID_AUTO_UPDATE_ENABLED": "false",
        }
    ]
    authorizations = tuple((tmp_path / "state/authorizations").iterdir())
    assert len(authorizations) == 1
    assert json.loads(authorizations[0].read_bytes())["run_id"] == "baseline-test-preflight"
    assert BaselineRunRecord.model_validate(json.loads(output.read_bytes())) == record


def test_failed_host_baseline_persists_consumed_authorization_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        preparation,
        preflight,
        profile,
        role_config,
        checkout,
        mission_file,
        _,
        _,
        values,
    ) = write_inputs(tmp_path)
    mission_root = factory_root(tmp_path)
    runner = FakeHostRunner(mission_root, values["initial_commit"], returncode=1)
    monkeypatch.setattr(baseline_module, "validate_evaluator_assets", lambda *_: "8" * 64)
    monkeypatch.setattr(baseline_module, "load_release_preflight", lambda _: approval_record())
    output = tmp_path / "baseline.json"

    with pytest.raises(baseline_module.BaselineError, match="Mission failed"):
        baseline_module.run_host_baseline(
            preparation_path=preparation,
            preflight_path=preflight,
            profile_manifest=profile,
            role_config=role_config,
            checkout=checkout,
            mission_file=mission_file,
            exporter_path=tmp_path / "export.py",
            evaluator_lima_config=tmp_path / "evaluator.yaml",
            evaluator_path=tmp_path / "evaluate.py",
            output_path=output,
            artifact_root=tmp_path / "artifacts",
            evaluator_vm="evaluator-vm",
            droid_path=tmp_path / "droid",
            evaluator_driver=object(),
            secret_canaries=(),
            factory_mission_root=mission_root,
            state_root=tmp_path / "state",
            runner=runner,
            mission_runner=runner,
        )

    authorization_path = next((tmp_path / "state/authorizations").iterdir())
    authorization = json.loads(authorization_path.read_bytes())
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    record = BaselineRunRecord.model_validate(json.loads(output.read_bytes()))
    assert record.mission_outcome == "mission-failed"
    assert record.final_source_archive_digest is None
    assert record.evaluator_outcome is None
    assert record.usage_data["failure_classification"] == "mission-execution-failed"
    assert record.usage_data["cleanup_observations"] == {
        "evaluator_vm_deleted": None,
        "mission_process_group_stopped": True,
    }
    assert record.usage_data["consumed_authorization_reference"] == {
        "authorization_id_digest": authorization["authorization_id_digest"],
        "consumed_at": authorization["consumed_at"],
        "preflight_record_digest": authorization["preflight_record_digest"],
        "run_id": authorization["run_id"],
    }


@pytest.mark.parametrize("persisted_evaluator_evidence", (False, True))
def test_evaluator_failure_persists_available_source_and_evaluator_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    persisted_evaluator_evidence: bool,
) -> None:
    (
        preparation,
        preflight,
        profile,
        role_config,
        checkout,
        mission_file,
        source,
        evaluation,
        values,
    ) = write_inputs(tmp_path)
    mission_root = factory_root(tmp_path)
    runner = FakeHostRunner(mission_root, values["initial_commit"])
    monkeypatch.setattr(
        baseline_module,
        "validate_evaluator_assets",
        lambda *_: "8" * 64,
    )
    monkeypatch.setattr(
        baseline_module,
        "load_release_preflight",
        lambda _: approval_record(),
    )
    monkeypatch.setattr(baseline_module, "export_final_source", lambda **_: source)

    def fail_evaluator(**kwargs: object) -> EvaluationRecord:
        if persisted_evaluator_evidence:
            evaluation_path = kwargs["output_path"]
            assert isinstance(evaluation_path, Path)
            evaluation_path.parent.mkdir(parents=True)
            evaluation_path.write_bytes(
                canonical_json(evaluation.model_dump(mode="json")) + b"\n"
            )
        raise RuntimeError("evaluator stopped")

    monkeypatch.setattr(baseline_module, "run_isolated_evaluator", fail_evaluator)
    output = tmp_path / "baseline.json"
    ticks = iter((100, 105))

    with pytest.raises(RuntimeError, match="evaluator stopped"):
        baseline_module.run_host_baseline(
            preparation_path=preparation,
            preflight_path=preflight,
            profile_manifest=profile,
            role_config=role_config,
            checkout=checkout,
            mission_file=mission_file,
            exporter_path=tmp_path / "export.py",
            evaluator_lima_config=tmp_path / "evaluator.yaml",
            evaluator_path=tmp_path / "evaluate.py",
            output_path=output,
            artifact_root=tmp_path / "artifacts",
            evaluator_vm="evaluator-vm",
            droid_path=tmp_path / "droid",
            evaluator_driver=object(),
            secret_canaries=(),
            factory_mission_root=mission_root,
            state_root=tmp_path / "state",
            runner=runner,
            mission_runner=runner,
            clock=lambda: next(ticks),
        )

    record = BaselineRunRecord.model_validate(json.loads(output.read_bytes()))
    assert record.mission_outcome == "mission-failed"
    assert record.final_commit == source.manifest.final_commit
    assert record.final_source_archive_digest == source.archive_digest
    assert record.evaluator_outcome == (
        evaluation.model_dump(mode="json")
        if persisted_evaluator_evidence
        else None
    )
    assert record.usage_data["failure_classification"] == "evaluator-failed"
    assert record.usage_data["cleanup_observations"] == {
        "evaluator_vm_deleted": None,
        "mission_process_group_stopped": True,
    }


@pytest.mark.parametrize(
    "failure",
    ("baseline Mission output limit exceeded", "baseline Mission timed out"),
)
def test_mission_boundary_error_persists_frozen_failure_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    (
        preparation,
        preflight,
        profile,
        role_config,
        checkout,
        mission_file,
        _,
        _,
        values,
    ) = write_inputs(tmp_path)
    mission_root = factory_root(tmp_path)
    git_runner = FakeHostRunner(mission_root, values["initial_commit"])
    monkeypatch.setattr(
        baseline_module,
        "validate_evaluator_assets",
        lambda *_: "8" * 64,
    )
    monkeypatch.setattr(
        baseline_module,
        "load_release_preflight",
        lambda _: approval_record(),
    )
    output = tmp_path / "baseline.json"

    def fail_mission(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
        raise baseline_module.BaselineError(failure)

    with pytest.raises(baseline_module.BaselineError, match=failure):
        baseline_module.run_host_baseline(
            preparation_path=preparation,
            preflight_path=preflight,
            profile_manifest=profile,
            role_config=role_config,
            checkout=checkout,
            mission_file=mission_file,
            exporter_path=tmp_path / "export.py",
            evaluator_lima_config=tmp_path / "evaluator.yaml",
            evaluator_path=tmp_path / "evaluate.py",
            output_path=output,
            artifact_root=tmp_path / "artifacts",
            evaluator_vm="evaluator-vm",
            droid_path=tmp_path / "droid",
            evaluator_driver=object(),
            secret_canaries=(),
            factory_mission_root=mission_root,
            state_root=tmp_path / "state",
            runner=git_runner,
            mission_runner=fail_mission,
        )

    record = BaselineRunRecord.model_validate(json.loads(output.read_bytes()))
    assert record.mission_outcome == "mission-failed"
    assert record.evaluator_outcome is None
    assert record.usage_data["failure_classification"] == "mission-execution-failed"
    assert record.usage_data["cleanup_observations"] == {
        "evaluator_vm_deleted": None,
        "mission_process_group_stopped": None,
    }
    assert len(tuple((tmp_path / "state/authorizations").iterdir())) == 1


def test_main_executes_host_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}

    def run(**kwargs: object) -> SimpleNamespace:
        observed.update(kwargs)
        return SimpleNamespace(
            baseline_id="baseline-demo",
            evaluator_outcome={
                "status": "fail",
                "assertions": [
                    {
                        "assertion_id": "api_amount_unit_is_integer_cents",
                        "status": "pass",
                    },
                    {
                        "assertion_id": "api_preserves_integer_cents",
                        "status": "pass",
                    },
                    {
                        "assertion_id": "database_column_is_amount_cents",
                        "status": "pass",
                    },
                    {
                        "assertion_id": (
                            "ten_dollars_crosses_all_boundaries_as_1000_cents"
                        ),
                        "status": "fail",
                    },
                ],
            },
            record_digest="1" * 64,
        )

    monkeypatch.setattr(baseline_module, "run_host_baseline", run)
    monkeypatch.setattr(baseline_module, "LimaVmDriver", lambda: object())
    values = {
        name: tmp_path / name
        for name in (
            "preparation",
            "release-preflight",
            "profile",
            "role-config",
            "checkout",
            "mission",
            "exporter",
            "evaluator-config",
            "evaluator",
            "output",
            "artifacts",
            "droid",
            "missions",
            "state",
        )
    }

    result = baseline_module.main(
        [
            "--preparation", str(values["preparation"]),
            "--release-preflight", str(values["release-preflight"]),
            "--profile-manifest", str(values["profile"]),
            "--role-config", str(values["role-config"]),
            "--checkout", str(values["checkout"]),
            "--mission-file", str(values["mission"]),
            "--exporter", str(values["exporter"]),
            "--evaluator-lima-config", str(values["evaluator-config"]),
            "--evaluator", str(values["evaluator"]),
            "--output", str(values["output"]),
            "--artifact-root", str(values["artifacts"]),
            "--evaluator-vm", "evaluator-vm",
            "--droid-path", str(values["droid"]),
            "--factory-mission-root", str(values["missions"]),
            "--state-root", str(values["state"]),
        ]
    )
    assert len(observed["secret_canaries"]) == 2
    assert all(
        str(value).startswith("shadow-baseline-canary-")
        for value in observed["secret_canaries"]
    )

    assert result == 0
    assert observed["checkout"] == values["checkout"]
    assert observed["state_root"] == values["state"]
    assert json.loads(capsys.readouterr().out) == {
        "baseline_id": "baseline-demo",
        "evaluator_status": "fail",
        "output": str(values["output"]),
        "record_digest": "1" * 64,
    }


def test_intended_baseline_failure_rejects_any_other_failure() -> None:
    record = SimpleNamespace(
        evaluator_outcome={
            "status": "fail",
            "assertions": [
                {
                    "assertion_id": "api_amount_unit_is_integer_cents",
                    "status": "fail",
                },
                {
                    "assertion_id": "api_preserves_integer_cents",
                    "status": "pass",
                },
                {
                    "assertion_id": "database_column_is_amount_cents",
                    "status": "pass",
                },
                {
                    "assertion_id": (
                        "ten_dollars_crosses_all_boundaries_as_1000_cents"
                    ),
                    "status": "fail",
                },
            ],
        }
    )

    assert baseline_module._is_intended_baseline_failure(record) is False
