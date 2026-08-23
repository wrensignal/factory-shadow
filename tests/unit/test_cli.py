from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import shadow_mission.cli as cli_module

from shadow_mission.cli import _parser, main
from shadow_mission.protocol import canonical_json
from shadow_mission.status import status_record
from tests.unit.test_reporting import make_final_run_dir


def test_cli_exposes_exact_public_commands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        _parser().parse_args(["--help"])

    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    assert "mission" in output
    assert "status" in output
    assert "report" in output
    assert "baseline" not in output
    assert "rebuild" not in output


def test_preflight_command_builds_one_no_spend_record(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def build(**values: object) -> SimpleNamespace:
        observed.update(values)
        return SimpleNamespace(
            preflight_id="preflight-fresh",
            record_digest="a" * 64,
        )

    monkeypatch.setattr(cli_module, "build_release_preflight", build)
    arguments = ["preflight"]
    for option, value in (
        ("--plugin-root", tmp_path / "plugin"),
        ("--repo", tmp_path / "repo"),
        ("--file", tmp_path / "mission.md"),
        ("--evaluator", tmp_path / "evaluate.py"),
        ("--profile-manifest", tmp_path / "profile.json"),
        ("--isolation-manifest", tmp_path / "isolation.json"),
        ("--lima-config", tmp_path / "lima.yaml"),
        ("--feasibility-record", tmp_path / "feasibility.json"),
        ("--droid", tmp_path / "droid"),
        ("--approval", tmp_path / "approval.json"),
        ("--output", tmp_path / "release.json"),
    ):
        arguments.extend((option, str(value)))

    assert main(arguments) == 0
    assert observed["output_path"] == tmp_path / "release.json"
    assert json.loads(capsys.readouterr().out) == {
        "output": str(tmp_path / "release.json"),
        "preflight_id": "preflight-fresh",
        "record_digest": "a" * 64,
    }

    def stop(**_: object) -> None:
        raise cli_module.PreflightBuildError("approval expired")

    monkeypatch.setattr(cli_module, "build_release_preflight", stop)
    assert main(arguments) == 2
    assert "preflight build stopped" in capsys.readouterr().err


def test_mission_requires_explicit_bound_inputs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["mission"])

    assert exit_info.value.code == 2
    error = capsys.readouterr().err
    for option in (
        "--repo",
        "--file",
        "--evaluator",
        "--profile-manifest",
        "--isolation-manifest",
        "--feasibility-record",
        "--release-preflight",
        "--source-exporter",
        "--evaluator-lima-config",
        "--evaluator-vm-name",
        "--droid",
        "--plugin-root",
        "--state-root",
        "--factory-credential-file",
        "--orchestrator-model",
        "--probe-reasoning",
    ):
        assert option in error
    assert "--mission-vm-name" not in error
    assert "--mission-guest-repo" not in error

def test_mission_exit_contract_covers_success_failure_and_preflight(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = [
        "mission",
        "--repo",
        str(tmp_path / "repo"),
        "--file",
        str(tmp_path / "mission.md"),
        "--evaluator",
        str(tmp_path / "evaluate.py"),
        "--profile-manifest",
        str(tmp_path / "profile.json"),
        "--isolation-manifest",
        str(tmp_path / "isolation.json"),
        "--lima-config",
        str(tmp_path / "mission.yaml"),
        "--feasibility-record",
        str(tmp_path / "feasibility.json"),
        "--release-preflight",
        str(tmp_path / "release.json"),
        "--factory-mission-root",
        str(tmp_path / ".factory" / "missions"),
        "--source-exporter",
        str(tmp_path / "export_source.py"),
        "--evaluator-lima-config",
        str(tmp_path / "evaluator.yaml"),
        "--evaluator-vm-name",
        "evaluator-vm",
        "--droid",
        str(tmp_path / "droid"),
        "--plugin-root",
        str(tmp_path / "plugin"),
        "--state-root",
        str(tmp_path / "private-state"),
        "--factory-credential-file",
        str(tmp_path / "factory.env"),
    ]
    for role in ("orchestrator", "worker", "validator", "extractor", "probe"):
        arguments.extend((f"--{role}-model", "model", f"--{role}-reasoning", "high"))

    class Runtime:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def run(self, _: object, **values: object) -> SimpleNamespace:
            assert isinstance(
                values["review_controller_factory"],
                cli_module.ProductionReviewControllerFactory,
            )
            return SimpleNamespace(
                run_id="run-complete",
                mission_process_stopped=True,
            )
        def take_finalization_canaries(self, run_id: str) -> tuple[str, ...]:
            assert run_id == "run-complete"
            return ("protected-canary",)

    driver = object()
    finalizer_arguments: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "MissionRuntime", Runtime)
    credential_paths: list[Path] = []

    def load_credential(path: Path) -> dict[str, str]:
        credential_paths.append(path)
        return {"FACTORY_API_KEY": "test-only-key"}

    monkeypatch.setattr(
        cli_module,
        "load_private_factory_environment",
        load_credential,
    )
    monkeypatch.setattr(cli_module, "LimaVmDriver", lambda: driver)

    def succeed(**values: object) -> SimpleNamespace:
        finalizer_arguments.update(values)
        return SimpleNamespace(
            run_record=SimpleNamespace(
                run_id="run-complete",
                mission_outcome="mission-complete",
                runtime_outcome="mission-terminated",
            ),
            evaluation_record=SimpleNamespace(status="pass"),
        )

    monkeypatch.setattr(cli_module, "finalize_run", succeed)
    assert main(arguments) == 0
    assert credential_paths == [tmp_path / "factory.env"]
    assert json.loads(capsys.readouterr().out) == {
        "mission_outcome": "mission-complete",
        "runtime_outcome": "mission-terminated",
        "run_id": "run-complete",
        "status": "pass",
    }
    assert set(finalizer_arguments) == {
        "evaluator_driver",
        "evaluator_vm_name",
        "evaluator_lima_config",
        "mission_repo",
        "exporter_path",
        "evaluator_path",
        "run_dir",
        "mission_process_stopped",
        "hooks_stopped",
        "secret_canaries",
        "mission_process_succeeded",
    }
    assert finalizer_arguments["secret_canaries"] == ("protected-canary",)
    assert finalizer_arguments["evaluator_driver"] is driver
    assert finalizer_arguments["mission_repo"] == tmp_path / "repo"
    assert finalizer_arguments["mission_process_stopped"] is True
    assert finalizer_arguments["hooks_stopped"] is True
    assert finalizer_arguments["mission_process_succeeded"] is True

    def fail(**_: object) -> None:
        raise cli_module.FinalizationError("cleanup failed")

    monkeypatch.setattr(cli_module, "finalize_run", fail)
    assert main(arguments) == 1
    assert "Mission finalization failed" in capsys.readouterr().err

    class FailedRuntime(Runtime):
        runtime_outcome = "completion-blocked"
        mission_process_stopped = True

        def run(self, _: object, **__: object) -> SimpleNamespace:
            raise cli_module.MissionExecutionError(
                "Droid Mission failed",
                run_record=SimpleNamespace(
                    run_id="run-failed",
                    runtime_outcome=self.runtime_outcome,
                    mission_process_stopped=self.mission_process_stopped,
                ),
            )

        def take_finalization_canaries(self, run_id: str) -> tuple[str, ...]:
            assert run_id == "run-failed"
            return ("failed-run-canary",)

    failed_finalizer_arguments: dict[str, object] = {}

    def finalize_failed_mission(**values: object) -> SimpleNamespace:
        failed_finalizer_arguments.update(values)
        return SimpleNamespace(
            run_record=SimpleNamespace(
                run_id="run-failed",
                mission_outcome="mission-failed",
                runtime_outcome="completion-blocked",
            ),
            evaluation_record=SimpleNamespace(status="pass"),
        )

    monkeypatch.setattr(cli_module, "MissionRuntime", FailedRuntime)
    monkeypatch.setattr(cli_module, "finalize_run", finalize_failed_mission)
    # A deliberate completion block remains reportable after evaluator success.
    assert main(arguments) == 0
    failed_output = capsys.readouterr()
    assert "Mission process failed after finalization" in failed_output.err
    assert json.loads(failed_output.out) == {
        "mission_outcome": "mission-failed",
        "runtime_outcome": "completion-blocked",
        "run_id": "run-failed",
        "status": "pass",
    }
    assert failed_finalizer_arguments["secret_canaries"] == (
        "failed-run-canary",
    )
    assert failed_finalizer_arguments["mission_process_succeeded"] is False

    class CleanupFailedRuntime(FailedRuntime):
        runtime_outcome = "cleanup-failed"

    def finalize_cleanup_failed(**_: object) -> SimpleNamespace:
        return SimpleNamespace(
            run_record=SimpleNamespace(
                run_id="run-failed",
                mission_outcome="mission-failed",
                runtime_outcome="cleanup-failed",
            ),
            evaluation_record=SimpleNamespace(status="pass"),
        )

    monkeypatch.setattr(cli_module, "MissionRuntime", CleanupFailedRuntime)
    monkeypatch.setattr(cli_module, "finalize_run", finalize_cleanup_failed)
    assert main(arguments) == 1
    cleanup_output = capsys.readouterr()
    assert "runtime outcome is not release-reportable" in cleanup_output.err
    assert json.loads(cleanup_output.out)["runtime_outcome"] == "cleanup-failed"

    class UnstoppedRuntime(FailedRuntime):
        runtime_outcome = "cleanup-failed"
        mission_process_stopped = False

    unstopped_finalizer_arguments: dict[str, object] = {}

    def reject_unstopped(**values: object) -> None:
        unstopped_finalizer_arguments.update(values)
        raise cli_module.FinalizationError("mission process did not stop")

    monkeypatch.setattr(cli_module, "MissionRuntime", UnstoppedRuntime)
    monkeypatch.setattr(cli_module, "finalize_run", reject_unstopped)
    assert main(arguments) == 1
    assert unstopped_finalizer_arguments["mission_process_stopped"] is False
    assert "Mission finalization failed" in capsys.readouterr().err

    class StoppedRuntime(Runtime):
        def run(self, _: object, **__: object) -> SimpleNamespace:
            raise cli_module.PreflightError("binding differs")

    monkeypatch.setattr(cli_module, "MissionRuntime", StoppedRuntime)
    assert main(arguments) == 2
    assert "preflight stopped" in capsys.readouterr().err


def test_status_exit_contract_for_known_unknown_and_corrupt_runs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    state_root = repo / ".shadow-mission"
    run_dir = state_root / "runs/run-active"
    run_dir.mkdir(parents=True)
    now = int(time.time())
    record = status_record(
        {
            "schema_version": "0.1",
            "run_id": "run-active",
            "state": "active",
            "daemon_health": "healthy",
            "queue": {"items": 2, "bytes": 100},
            "spool": {"events": 200, "review": 300},
            "sessions": ("session-a",),
            "roles": {"worker-a": "session-a"},
            "capability_path": {"identity": "pass"},
            "unresolved_risks": ("risk-a",),
            "intervention_state": {
                "unresolved": 1,
                "unresolved_intervention_ids": ("intervention-a",),
                "by_state": {"delivered": 1},
            },
            "usage": {"status": "unavailable"},
            "started_at": now - 5,
            "duration_seconds": 5.0,
            "live_run_count": 3,
            "budget_ledger": {"hard_stop_cents": 5000},
            "updated_at": now,
        }
    )
    (state_root / "mission.lock").write_text("active", encoding="utf-8")
    (run_dir / "events.jsonl").write_bytes(b"")
    (run_dir / "review.jsonl").write_bytes(b"")
    (run_dir / "status.json").write_bytes(
        canonical_json(record.model_dump(mode="json")) + b"\n"
    )

    assert main(["status", "--repo", str(repo), "--run", "run-active"]) == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["daemon_health"] == "healthy"
    assert rendered["queue"] == {"bytes": 100, "items": 2}
    assert rendered["unresolved_risks"] == ["risk-a"]
    assert (
        main(
            [
                "status",
                "--repo",
                str(repo),
                "--state-root",
                str(state_root),
                "--run",
                "run-active",
            ]
        )
        == 0
    )
    capsys.readouterr()
    stale_value = record.model_dump(mode="json")
    stale_value["updated_at"] = now - 100
    stale = status_record(stale_value)
    (run_dir / "status.json").write_bytes(
        canonical_json(stale.model_dump(mode="json")) + b"\n"
    )
    assert main(["status", "--repo", str(repo), "--run", "run-active"]) == 0
    stale_output = json.loads(capsys.readouterr().out)
    assert stale_output["daemon_health"] == "degraded"
    assert "active heartbeat is stale" in stale_output["unresolved_risks"]

    assert main(["status", "--repo", str(repo), "--run", "run-missing"]) == 2
    assert "unknown run" in capsys.readouterr().err

    (run_dir / "status.json").write_text("{broken", encoding="utf-8")
    assert main(["status", "--repo", str(repo), "--run", "run-active"]) == 1
    assert "status failed" in capsys.readouterr().err


def test_report_rebuild_exit_contract_and_outputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    state_root = repo / ".shadow-mission"
    runs = state_root / "runs"
    runs.mkdir(parents=True)
    run_dir = make_final_run_dir(runs, run_id="run-report")

    assert main(["report", "--repo", str(repo), "--run", "run-report"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert Path(output["report_json"]) == run_dir / "report.json"
    assert Path(output["report_markdown"]) == run_dir / "report.md"
    assert (run_dir / "report.json").is_file()
    assert (run_dir / "report.md").is_file()
    assert (
        main(
            [
                "report",
                "--repo",
                str(repo),
                "--run",
                "run-report",
                "--baseline-record",
                str(tmp_path / "unused-baseline.json"),
            ]
        )
        == 2
    )
    assert "not baseline-bound" in capsys.readouterr().err
    assert (
        main(
            [
                "report",
                "--repo",
                str(repo),
                "--run",
                "../run-report",
            ]
        )
        == 2
    )
    assert "run ID is invalid" in capsys.readouterr().err

    assert main(["report", "--repo", str(repo), "--run", "run-missing"]) == 2
    assert "unknown run" in capsys.readouterr().err

    (run_dir / "events.jsonl").write_bytes(b"partial")
    assert main(["report", "--repo", str(repo), "--run", "run-report"]) == 1
    assert "report failed" in capsys.readouterr().err


def test_private_commands_remain_rejected() -> None:
    for command in ("baseline", "rebuild"):
        with pytest.raises(SystemExit) as exit_info:
            main([command])
        assert exit_info.value.code == 2

def test_final_status_rejects_missing_evaluation_artifact(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    runs = repo / ".shadow-mission/runs"
    runs.mkdir(parents=True)
    run_dir = make_final_run_dir(runs, run_id="run-final")
    (run_dir / "evaluation.json").unlink()

    assert main(["status", "--repo", str(repo), "--run", "run-final"]) == 1
    assert "status failed" in capsys.readouterr().err
