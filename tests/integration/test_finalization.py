from __future__ import annotations

import hashlib
import json
import subprocess
import os
from pathlib import Path

import pytest

import shadow_mission.finalization as finalization_module
from shadow_mission.evaluation import EvaluationBoundaryError
from shadow_mission.finalization import FinalizationError, finalize_run
from shadow_mission.protocol import canonical_json
from shadow_mission.reporting import (
    ReportCorruptionError,
    load_run_record,
    rebuild_report,
)
from shadow_mission.status import StatusCorruptionError, load_status
from tests.integration.test_source_export import EXPORTER, make_repo
from tests.unit.test_evaluation import (
    FUNCTION_RUNNER,
    FakeDriver,
    evaluator_result,
)
from tests.unit.test_reporting import make_run_dir

PROJECT_ROOT = Path(__file__).parents[2]


class OrderedEvaluatorDriver(FakeDriver):
    def __init__(self, result_value: dict, events: list[str], pre_evaluation: Path) -> None:
        super().__init__(result_value)
        self.events = events
        self.pre_evaluation = pre_evaluation

    def start(self, name: str, config: Path) -> None:
        assert self.pre_evaluation.is_file()
        self.events.append("evaluator-start")
        super().start(name, config)

    def copy_to(self, name: str, source: Path, destination: str) -> None:
        assert source.name != "export_source.py"
        self.events.append("evaluator-copy-input")
        super().copy_to(name, source, destination)

    def delete(self, name: str) -> bool:
        self.events.append("evaluator-delete")
        return super().delete(name)


def finalization_inputs(
    tmp_path: Path,
    *,
    runtime_outcome: str = "mission-terminated",
):
    source_root = tmp_path / "source-root"
    source_root.mkdir()
    source_repo = make_repo(source_root)
    state_root = tmp_path / "state"
    runs_root = state_root / "runs"
    runs_root.mkdir(parents=True)
    run_dir = make_run_dir(runs_root, run_id="run-finalize")
    evaluator = tmp_path / "evaluate.py"
    evaluator.write_text("raise SystemExit(0)\n", encoding="utf-8")
    (tmp_path / "function_runner.py").write_bytes(
        FUNCTION_RUNNER.read_bytes()
    )
    run_path = run_dir / "run.json"
    run_value = json.loads(run_path.read_bytes())
    commit = (
        __import__("subprocess")
        .run(
            ("git", "-C", str(source_repo), "rev-parse", "HEAD"),
            check=True,
            capture_output=True,
            text=True,
        )
        .stdout.strip()
    )
    run_value.update(
        {
            "mission_outcome": (
                "mission-complete"
                if runtime_outcome == "mission-terminated"
                else "mission-failed"
            ),
            "runtime_outcome": runtime_outcome,
            "mission_process_stopped": True,
            "evaluator_outcome": runtime_outcome,
            "final_commit": commit,
            "final_source_archive_digest": None,
            "approved_evaluator_digest": hashlib.sha256(
                evaluator.read_bytes()
            ).hexdigest(),
            "source_exporter_digest": hashlib.sha256(EXPORTER.read_bytes()).hexdigest(),
            "record_digest": "0" * 64,
        }
    )
    material = dict(run_value)
    material.pop("record_digest")
    run_value["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    run_path.write_bytes(canonical_json(run_value) + b"\n")
    config = PROJECT_ROOT / "ops/lima/shadow-evaluator.yaml"
    return source_repo, run_dir, evaluator, config


def test_source_export_subprocess_uses_private_credential_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    exporter = tmp_path / "export_source.py"
    exporter.write_text("raise SystemExit(1)\n", encoding="utf-8")
    observed: dict[str, object] = {}
    credential = "factory-credential-for-export-process-boundary"
    monkeypatch.setenv("FACTORY_API_KEY", credential)

    def run(
        arguments: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed["arguments"] = tuple(arguments)
        observed.update(kwargs)
        return subprocess.CompletedProcess(arguments, 1, stdout="", stderr="")

    monkeypatch.setattr(finalization_module.subprocess, "run", run)

    with pytest.raises(FinalizationError, match="mission source export exited 1"):
        finalization_module.export_final_source(
            mission_repo=repo,
            exporter_path=exporter,
            expected_exporter_digest=hashlib.sha256(
                exporter.read_bytes()
            ).hexdigest(),
            artifact_root=tmp_path / "artifacts",
            secret_canaries=(credential,),
        )

    assert (
        observed["timeout"]
        == finalization_module._SOURCE_EXPORT_TIMEOUT_SECONDS
    )
    environment = observed["env"]
    launch_arguments = observed["arguments"]
    descriptor = observed["input"]
    assert isinstance(environment, dict)
    assert isinstance(launch_arguments, tuple)
    assert isinstance(descriptor, bytes)
    assert observed["close_fds"] is True
    assert observed["shell"] is False
    assert set(environment) == {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONUTF8",
    }
    assert credential not in json.dumps(environment)
    assert "--forbidden-values-stdin" in launch_arguments
    assert credential.encode("utf-8") not in b"\0".join(
        os.fsencode(value) for value in launch_arguments
    )
    assert json.loads(descriptor) == {
        "forbidden_values": [credential]
    }
    assert observed["stdout"] is subprocess.DEVNULL
    assert observed["stderr"] is subprocess.DEVNULL
    assert "capture_output" not in observed


def test_source_export_rejects_exact_factory_credential_from_private_input(
    tmp_path: Path,
) -> None:
    repo = make_repo(tmp_path)
    credential = "factory-credential-value-for-exact-export-boundary"
    (repo / "src/private_value.py").write_text(
        f"VALUE = {credential!r}\n",
        encoding="utf-8",
    )
    artifact_root = tmp_path / "artifacts"

    with pytest.raises(
        FinalizationError,
        match="mission source export exited 1",
    ) as caught:
        finalization_module.export_final_source(
            mission_repo=repo,
            exporter_path=EXPORTER,
            expected_exporter_digest=hashlib.sha256(
                EXPORTER.read_bytes()
            ).hexdigest(),
            artifact_root=artifact_root,
            secret_canaries=(credential,),
        )

    assert credential not in str(caught.value)
    assert not (artifact_root / "final-source.tar").exists()
    assert not (artifact_root / "final-source-manifest.json").exists()


@pytest.mark.parametrize(
    ("failure", "expected_message"),
    (
        (
            subprocess.TimeoutExpired(
                cmd=("private-exporter-argument",),
                timeout=120,
                output=b"private output",
                stderr=b"private error",
            ),
            "mission source export timed out",
        ),
        (
            OSError("private launch detail"),
            "mission source exporter did not start",
        ),
    ),
)
def test_source_export_reports_nonsecret_subprocess_failure_class(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    expected_message: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    exporter = tmp_path / "export_source.py"
    exporter.write_text("raise SystemExit(0)\n", encoding="utf-8")

    def fail_run(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr(finalization_module.subprocess, "run", fail_run)

    with pytest.raises(FinalizationError) as caught:
        finalization_module.export_final_source(
            mission_repo=repo,
            exporter_path=exporter,
            expected_exporter_digest=hashlib.sha256(
                exporter.read_bytes()
            ).hexdigest(),
            artifact_root=tmp_path / "artifacts",
            secret_canaries=("protected-canary",),
        )

    assert str(caught.value) == expected_message
    assert "private" not in str(caught.value)
    assert caught.value.__suppress_context__ is True


def test_exclusive_record_write_never_leaves_partial_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "pre-evaluation.json"
    real_write = os.write
    calls = 0

    def partial_then_fail(descriptor: int, payload: object) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, memoryview(payload)[:5])
        raise OSError("injected partial write")

    monkeypatch.setattr(finalization_module.os, "write", partial_then_fail)

    with pytest.raises(OSError, match="injected partial write"):
        finalization_module._exclusive_canonical_json(
            target,
            {"status": "bound"},
        )

    assert not target.exists()
    assert tuple(tmp_path.glob(".pre-evaluation.json.*.tmp")) == ()


def _finalize(
    tmp_path: Path,
    *,
    source_repo: Path,
    run_dir: Path,
    evaluator: Path,
    config: Path,
    evaluation_driver,
    secret_canaries: tuple[str, ...] = ("protected-canary",),
    mission_process_stopped: bool = True,
    hooks_stopped: bool = True,
    mission_process_succeeded: bool = True,
):
    return finalize_run(
        evaluator_driver=evaluation_driver,
        evaluator_vm_name="shadow-evaluator",
        evaluator_lima_config=config,
        mission_repo=source_repo,
        exporter_path=EXPORTER,
        evaluator_path=evaluator,
        run_dir=run_dir,
        mission_process_stopped=mission_process_stopped,
        hooks_stopped=hooks_stopped,
        secret_canaries=secret_canaries,
        mission_process_succeeded=mission_process_succeeded,
    )


def test_corrupt_run_record_is_wrapped_before_finalization_work(
    tmp_path: Path,
) -> None:
    source_repo, run_dir, evaluator, config = finalization_inputs(tmp_path)
    (run_dir / "run.json").write_bytes(b"{\n")
    driver = FakeDriver({"status": "pass"})

    with pytest.raises(
        FinalizationError,
        match="run record is unavailable or corrupt",
    ):
        _finalize(
            tmp_path,
            source_repo=source_repo,
            run_dir=run_dir,
            evaluator=evaluator,
            config=config,
            evaluation_driver=driver,
        )

    assert driver.calls == []


def test_finalization_orders_export_persistence_and_evaluation(
    tmp_path: Path,
) -> None:
    source_repo, run_dir, evaluator, config = finalization_inputs(tmp_path)
    events: list[str] = []
    # Build a matching evaluator result after export by running finalize once
    # through a driver that records after the archive exists.
    first_events: list[str] = []

    class RecordingDriver(OrderedEvaluatorDriver):
        def start(self, name: str, lima_config: Path) -> None:
            archive = run_dir / "final-source" / "final-source.tar"
            manifest = run_dir / "final-source" / "final-source-manifest.json"
            self.result_value = evaluator_result(archive, manifest)
            super().start(name, lima_config)

    evaluation_driver = RecordingDriver(
        {"status": "pass"},
        first_events,
        run_dir / "pre-evaluation.json",
    )
    result = _finalize(
        tmp_path,
        source_repo=source_repo,
        run_dir=run_dir,
        evaluator=evaluator,
        config=config,
        evaluation_driver=evaluation_driver,
    )

    assert first_events[0] == "evaluator-start"
    assert "evaluator-copy-input" in first_events
    assert first_events[-1] == "evaluator-delete"
    assert result.pre_evaluation_record.mission_process_stopped is True
    assert result.evaluation_record.status == "pass"
    persisted = load_run_record(run_dir / "run.json")
    assert persisted.final_source_archive_digest == result.source_archive_digest
    assert persisted.evaluator_outcome["record_digest"] == result.evaluation_record.record_digest
    assert persisted.evaluator_vm_deleted is True
    assert persisted.mission_process_stopped is True
    assert persisted.capabilities.sandbox_isolation == "fallback"
    for artifact in ("run.json", "pre-evaluation.json"):
        persisted_value = json.loads((run_dir / artifact).read_bytes())
        assert not any(key.startswith("mission_vm_") for key in persisted_value)
    rebuilt = rebuild_report(run_dir)
    assert rebuilt.final_source["archive_digest"] == result.source_archive_digest

    pre_evaluation_path = run_dir / "pre-evaluation.json"
    changed = json.loads(pre_evaluation_path.read_bytes())
    changed["evaluator_digest"] = "0" * 64
    changed["record_digest"] = "0" * 64
    material = dict(changed)
    material.pop("record_digest")
    changed["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    pre_evaluation_path.write_bytes(canonical_json(changed) + b"\n")
    with pytest.raises(ReportCorruptionError):
        rebuild_report(run_dir)


def test_failed_mission_process_is_evaluated_without_becoming_complete(
    tmp_path: Path,
) -> None:
    source_repo, run_dir, evaluator, config = finalization_inputs(
        tmp_path,
        runtime_outcome="completion-blocked",
    )
    events: list[str] = []

    class RecordingDriver(OrderedEvaluatorDriver):
        def start(self, name: str, lima_config: Path) -> None:
            archive = run_dir / "final-source" / "final-source.tar"
            manifest = run_dir / "final-source" / "final-source-manifest.json"
            self.result_value = evaluator_result(archive, manifest)
            super().start(name, lima_config)

    result = _finalize(
        tmp_path,
        source_repo=source_repo,
        run_dir=run_dir,
        evaluator=evaluator,
        config=config,
        evaluation_driver=RecordingDriver(
            {"status": "pass"},
            events,
            run_dir / "pre-evaluation.json",
        ),
        mission_process_succeeded=False,
    )

    assert result.evaluation_record.status == "pass"
    assert result.run_record.mission_outcome == "mission-failed"
    assert load_run_record(run_dir / "run.json").mission_outcome == "mission-failed"
    assert result.run_record.runtime_outcome == "completion-blocked"
    assert rebuild_report(run_dir).outcome == "pass"
    assert load_status(run_dir.parents[1], run_dir.name).state == "final"


def test_failed_evaluator_persists_failure_after_evaluator_cleanup(
    tmp_path: Path,
) -> None:
    source_repo, run_dir, evaluator, config = finalization_inputs(tmp_path)
    events: list[str] = []

    class FailingDriver(OrderedEvaluatorDriver):
        def start(self, name: str, lima_config: Path) -> None:
            archive = run_dir / "final-source" / "final-source.tar"
            manifest = run_dir / "final-source" / "final-source-manifest.json"
            self.result_value = evaluator_result(archive, manifest, status="fail")
            super().start(name, lima_config)

    evaluation_driver = FailingDriver(
        {"status": "fail"},
        events,
        run_dir / "pre-evaluation.json",
    )
    with pytest.raises(FinalizationError, match="evaluator reported failure"):
        _finalize(
            tmp_path,
            source_repo=source_repo,
            run_dir=run_dir,
            evaluator=evaluator,
            config=config,
            evaluation_driver=evaluation_driver,
        )

    persisted = load_run_record(run_dir / "run.json")
    assert persisted.evaluator_outcome["status"] == "fail"
    assert persisted.evaluator_vm_deleted is True
    assert persisted.mission_process_stopped is True
    assert events[-1] == "evaluator-delete"


def test_evaluator_boundary_failure_is_wrapped_after_cleanup(
    tmp_path: Path,
) -> None:
    source_repo, run_dir, evaluator, config = finalization_inputs(tmp_path)
    events: list[str] = []

    class MissingResultDriver(OrderedEvaluatorDriver):
        def copy_from(
            self,
            name: str,
            source: str,
            destination: Path,
        ) -> None:
            raise EvaluationBoundaryError("evaluator result is missing")

    driver = MissingResultDriver(
        {"status": "fail"},
        events,
        run_dir / "pre-evaluation.json",
    )
    with pytest.raises(FinalizationError, match="isolated evaluator failed"):
        _finalize(
            tmp_path,
            source_repo=source_repo,
            run_dir=run_dir,
            evaluator=evaluator,
            config=config,
            evaluation_driver=driver,
        )

    assert events[-1] == "evaluator-delete"


def test_finalization_rejects_live_process_or_hooks_before_export(
    tmp_path: Path,
) -> None:
    source_repo, run_dir, evaluator, config = finalization_inputs(tmp_path)
    events: list[str] = []
    evaluation_driver = OrderedEvaluatorDriver(
        {"status": "pass"},
        events,
        run_dir / "pre-evaluation.json",
    )
    with pytest.raises(FinalizationError, match="must stop"):
        _finalize(
            tmp_path,
            source_repo=source_repo,
            run_dir=run_dir,
            evaluator=evaluator,
            config=config,
            evaluation_driver=evaluation_driver,
            mission_process_stopped=False,
        )
    assert events == []


def test_changed_approved_evaluator_stops_before_evaluator_vm_start(
    tmp_path: Path,
) -> None:
    source_repo, run_dir, evaluator, config = finalization_inputs(tmp_path)
    evaluator.write_text("raise SystemExit(1)\n", encoding="utf-8")
    events: list[str] = []
    with pytest.raises(FinalizationError, match="approved evaluator"):
        _finalize(
            tmp_path,
            source_repo=source_repo,
            run_dir=run_dir,
            evaluator=evaluator,
            config=config,
            evaluation_driver=OrderedEvaluatorDriver(
                {"status": "pass"},
                events,
                run_dir / "pre-evaluation.json",
            ),
        )
    assert events == []
    assert not (run_dir / "pre-evaluation.json").exists()


def test_non_reportable_runtime_outcome_cannot_be_released_by_evaluator_pass(
    tmp_path: Path,
) -> None:
    source_repo, run_dir, evaluator, config = finalization_inputs(
        tmp_path,
        runtime_outcome="cleanup-failed",
    )
    events: list[str] = []

    class RecordingDriver(OrderedEvaluatorDriver):
        def start(self, name: str, lima_config: Path) -> None:
            archive = run_dir / "final-source" / "final-source.tar"
            manifest = run_dir / "final-source" / "final-source-manifest.json"
            self.result_value = evaluator_result(archive, manifest)
            super().start(name, lima_config)

    result = _finalize(
        tmp_path,
        source_repo=source_repo,
        run_dir=run_dir,
        evaluator=evaluator,
        config=config,
        evaluation_driver=RecordingDriver(
            {"status": "pass"},
            events,
            run_dir / "pre-evaluation.json",
        ),
        mission_process_succeeded=False,
    )

    assert result.run_record.runtime_outcome == "cleanup-failed"
    with pytest.raises(ReportCorruptionError, match="provenance binding"):
        rebuild_report(run_dir)

    with pytest.raises(StatusCorruptionError, match="finalization provenance"):
        load_status(run_dir.parents[1], run_dir.name)



def test_changed_source_exporter_stops_before_host_export(tmp_path: Path) -> None:
    source_repo, run_dir, evaluator, config = finalization_inputs(tmp_path)
    fake_exporter = tmp_path / "export_source.py"
    fake_exporter.write_text("raise SystemExit(1)\n", encoding="utf-8")
    events: list[str] = []
    with pytest.raises(FinalizationError, match="source exporter digest"):
        finalize_run(
            evaluator_driver=OrderedEvaluatorDriver(
                {"status": "pass"},
                events,
                run_dir / "pre-evaluation.json",
            ),
            evaluator_vm_name="shadow-evaluator",
            evaluator_lima_config=config,
            mission_repo=source_repo,
            exporter_path=fake_exporter,
            evaluator_path=evaluator,
            run_dir=run_dir,
            mission_process_stopped=True,
            hooks_stopped=True,
            secret_canaries=("protected-canary",),
        )
    assert events == []
