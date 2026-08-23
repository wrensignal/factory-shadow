from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import shadow_mission.evaluation as evaluation_module
from shadow_mission.evaluation import (
    HOST_SHARE_MOUNT_TEST,
    EvaluationBoundaryError,
    EvaluationCleanupError,
    LimaVmDriver,
    run_isolated_evaluator,
)
from shadow_mission.protocol import canonical_json
from shadow_mission.source_export import validate_source_archive
from tests.integration.test_source_export import export, make_repo

PROJECT_ROOT = Path(__file__).parents[2]
FUNCTION_RUNNER = PROJECT_ROOT / "demo/evaluator/function_runner.py"


class Result:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeDriver:
    def __init__(
        self,
        result_value: dict,
        *,
        cleanup: bool = True,
        start_failure: bool = False,
        partial_start: bool = False,
        preexisting: bool = False,
        attestation: dict[str, bool] | None = None,
    ) -> None:
        self.result_value = result_value
        self.cleanup = cleanup
        self.start_failure = start_failure
        self.partial_start = partial_start
        self.present = preexisting
        self.attestation = attestation
        self.calls: list[tuple] = []

    def instance_exists(self, name: str) -> bool:
        self.calls.append(("exists", name))
        return self.present

    def start(self, name: str, config: Path) -> None:
        self.calls.append(("start", name, config))
        if self.start_failure:
            self.present = self.partial_start
            raise EvaluationBoundaryError("start failed")
        self.present = True

    def attest_clean(self, name: str) -> dict[str, bool]:
        self.calls.append(("attest", name))
        return self.attestation if self.attestation is not None else {
            "factory_profile_absent": True,
            "shadow_state_absent": True,
            "prior_inputs_absent": True,
            "credential_environment_absent": True,
            "host_mount_absent": True,
            "passwordless_sudo_absent": True,
        }

    def copy_to(self, name: str, source: Path, destination: str) -> None:
        self.calls.append(("copy_to", name, source.name, destination))

    def copy_from(self, name: str, source: str, destination: Path) -> None:
        self.calls.append(("copy_from", name, source, destination))
        destination.write_bytes(canonical_json(self.result_value) + b"\n")

    def run(self, name: str, arguments: tuple[str, ...]) -> Result:
        self.calls.append(("run", name, arguments))
        if any(argument.endswith("/evaluate.py") for argument in arguments):
            return Result(0 if self.result_value["status"] == "pass" else 1)
        return Result()

    def delete(self, name: str) -> bool:
        self.calls.append(("delete", name))
        self.present = False
        return self.cleanup


def evaluator_result(archive: Path, manifest: Path, *, status: str = "pass") -> dict:
    validated = validate_source_archive(archive, manifest)
    assertions = [
        {"assertion_id": "cross-feature", "status": status},
    ]
    value = {
        "schema_version": "0.1",
        "status": status,
        "archive_digest": validated.archive_digest,
        "working_tree_digest": validated.manifest.working_tree_digest,
        "assertions": assertions,
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    repo = make_repo(tmp_path)
    archive, manifest, exported = export(repo, tmp_path / "source")
    assert exported.returncode == 0
    evaluator = tmp_path / "evaluate.py"
    evaluator.write_text("raise SystemExit(0)\n", encoding="utf-8")
    (tmp_path / "function_runner.py").write_bytes(
        FUNCTION_RUNNER.read_bytes()
    )
    config = PROJECT_ROOT / "ops/lima/shadow-evaluator.yaml"
    return archive, manifest, evaluator, config


def test_isolated_evaluator_copies_only_allowlisted_inputs_and_uses_no_shell(
    tmp_path: Path,
) -> None:
    archive, manifest, evaluator, config = inputs(tmp_path)
    driver = FakeDriver(evaluator_result(archive, manifest))
    output = tmp_path / "host-output/result.json"

    record = run_isolated_evaluator(
        driver=driver,
        vm_name="shadow-evaluator",
        lima_config=config,
        archive_path=archive,
        manifest_path=manifest,
        evaluator_path=evaluator,
        output_path=output,
    )

    assert record.status == "pass"
    copied_names = [call[2] for call in driver.calls if call[0] == "copy_to"]
    assert copied_names == [
        "final-source.tar",
        "final-source-manifest.json",
        "evaluate.py",
        "function_runner.py",
    ]
    evaluator_call = next(
        call
        for call in driver.calls
        if call[0] == "run"
        and any(argument.endswith("/evaluate.py") for argument in call[2])
    )
    arguments = evaluator_call[2]
    assert arguments[:2] == ("/usr/bin/env", "-i")
    assert not any(argument in {"sh", "bash", "-c"} for argument in arguments)
    assert "--secure-isolation" in arguments
    assert driver.calls[-1] == ("delete", "shadow-evaluator")


@pytest.mark.parametrize(
    "attestation",
    (
        {
            "factory_profile_absent": True,
            "shadow_state_absent": True,
            "prior_inputs_absent": True,
            "credential_environment_absent": True,
            "host_mount_absent": True,
        },
        {
            "factory_profile_absent": True,
            "shadow_state_absent": True,
            "prior_inputs_absent": True,
            "credential_environment_absent": True,
            "host_mount_absent": True,
            "passwordless_sudo_absent": True,
            "unexpected_field": True,
        },
    ),
)
def test_isolated_evaluator_requires_exact_clean_attestation_fields(
    tmp_path: Path,
    attestation: dict[str, bool],
) -> None:
    archive, manifest, evaluator, config = inputs(tmp_path)
    driver = FakeDriver(
        evaluator_result(archive, manifest),
        attestation=attestation,
    )

    with pytest.raises(
        EvaluationBoundaryError,
        match="clean-state proof is incomplete",
    ):
        run_isolated_evaluator(
            driver=driver,
            vm_name="shadow-evaluator",
            lima_config=config,
            archive_path=archive,
            manifest_path=manifest,
            evaluator_path=evaluator,
            output_path=tmp_path / "result.json",
        )

    assert driver.calls[-1] == ("delete", "shadow-evaluator")


def test_isolated_evaluator_accepts_bound_failure_result(tmp_path: Path) -> None:
    archive, manifest, evaluator, config = inputs(tmp_path)
    driver = FakeDriver(evaluator_result(archive, manifest, status="fail"))

    record = run_isolated_evaluator(
        driver=driver,
        vm_name="shadow-evaluator",
        lima_config=config,
        archive_path=archive,
        manifest_path=manifest,
        evaluator_path=evaluator,
        output_path=tmp_path / "result.json",
    )

    assert record.status == "fail"


def test_cleanup_failure_cannot_report_evaluator_success(tmp_path: Path) -> None:
    archive, manifest, evaluator, config = inputs(tmp_path)
    driver = FakeDriver(evaluator_result(archive, manifest), cleanup=False)

    with pytest.raises(EvaluationCleanupError, match="cleanup failed"):
        run_isolated_evaluator(
            driver=driver,
            vm_name="shadow-evaluator",
            lima_config=config,
            archive_path=archive,
            manifest_path=manifest,
            evaluator_path=evaluator,
            output_path=tmp_path / "result.json",
        )


def test_preexisting_evaluator_vm_is_never_started_or_deleted(
    tmp_path: Path,
) -> None:
    archive, manifest, evaluator, config = inputs(tmp_path)
    driver = FakeDriver(
        evaluator_result(archive, manifest),
        preexisting=True,
    )

    with pytest.raises(EvaluationBoundaryError, match="name is already in use"):
        run_isolated_evaluator(
            driver=driver,
            vm_name="shadow-evaluator",
            lima_config=config,
            archive_path=archive,
            manifest_path=manifest,
            evaluator_path=evaluator,
            output_path=tmp_path / "result.json",
        )

    assert driver.calls == [("exists", "shadow-evaluator")]

def test_evaluator_rejects_changed_archive_binding(tmp_path: Path) -> None:
    archive, manifest, evaluator, config = inputs(tmp_path)
    value = evaluator_result(archive, manifest)
    value["archive_digest"] = "0" * 64
    material = dict(value)
    material.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    driver = FakeDriver(value)

    with pytest.raises(EvaluationBoundaryError, match="archive binding"):
        run_isolated_evaluator(
            driver=driver,
            vm_name="shadow-evaluator",
            lima_config=config,
            archive_path=archive,
            manifest_path=manifest,
            evaluator_path=evaluator,
            output_path=tmp_path / "result.json",
        )
    assert driver.calls[-1] == ("delete", "shadow-evaluator")


def test_lima_driver_never_enables_shell_mode(tmp_path: Path) -> None:
    calls: list[tuple[tuple[str, ...], dict]] = []

    def process_factory(arguments, **kwargs):
        calls.append((tuple(arguments), kwargs))
        return subprocess.Popen((sys.executable, "-c", ""), **kwargs)

    driver = LimaVmDriver(process_factory=process_factory)
    assert driver.instance_exists("shadow-evaluator") is False
    driver.start("shadow-evaluator", tmp_path / "evaluator.yaml")
    driver.run("shadow-evaluator", ("/usr/bin/python3", "-V"))
    driver.copy_to("shadow-evaluator", tmp_path / "input", "/home/shadow/input")
    driver.delete("shadow-evaluator")

    assert all(kwargs["shell"] is False for _, kwargs in calls)
    assert all(kwargs["close_fds"] is True for _, kwargs in calls)
    assert all(kwargs["start_new_session"] is True for _, kwargs in calls)
    assert calls[2][0] == (
        "limactl",
        "shell",
        "shadow-evaluator",
        "--",
        "/usr/bin/python3",
        "-V",
    )

@pytest.mark.parametrize("stream_name", ("stdout", "stderr"))
def test_lima_driver_caps_and_marks_guest_output(stream_name: str) -> None:
    def noisy_process_factory(arguments, **kwargs):
        return subprocess.Popen(
            (
                sys.executable,
                "-c",
                f"import sys; sys.{stream_name}.write('x' * 4096); sys.{stream_name}.flush()",
            ),
            **kwargs,
        )

    driver = LimaVmDriver(
        process_factory=noisy_process_factory,
        output_limit_bytes=128,
    )

    result = driver._invoke(("limactl", "shell", "shadow-evaluator"))

    assert result.returncode != 0
    captured = getattr(result, stream_name)
    assert captured.endswith(evaluation_module.OUTPUT_TRUNCATION_MARKER.decode())
    assert len(captured.encode()) <= 128


def test_oversized_evaluation_result_is_rejected_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result_path = tmp_path / "result.json"
    result_path.write_bytes(b"x" * (evaluation_module.MAX_EVALUATION_RESULT_BYTES + 1))
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path == result_path:
            raise AssertionError("oversized result was read")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    with pytest.raises(EvaluationBoundaryError, match="byte limit"):
        evaluation_module._load_evaluation_record(result_path)


def test_deeply_nested_evaluation_result_is_a_boundary_error(
    tmp_path: Path,
) -> None:
    result_path = tmp_path / "result.json"
    result_path.write_text("[" * 2_000 + "]" * 2_000, encoding="utf-8")

    with pytest.raises(EvaluationBoundaryError, match="result is invalid"):
        evaluation_module._load_evaluation_record(result_path)


def test_evaluator_rejects_changed_vm_template_before_start(tmp_path: Path) -> None:
    archive, manifest, evaluator, config = inputs(tmp_path)
    changed_config = tmp_path / "changed-evaluator.yaml"
    changed_config.write_text(
        config.read_text(encoding="utf-8").replace("mounts: []", "mounts: [/tmp]"),
        encoding="utf-8",
    )
    driver = FakeDriver(evaluator_result(archive, manifest))

    with pytest.raises(EvaluationBoundaryError, match="pinned template"):
        run_isolated_evaluator(
            driver=driver,
            vm_name="shadow-evaluator",
            lima_config=changed_config,
            archive_path=archive,
            manifest_path=manifest,
            evaluator_path=evaluator,
            output_path=tmp_path / "result.json",
        )

    assert driver.calls == []



def test_partial_start_failure_still_attempts_cleanup(tmp_path: Path) -> None:
    archive, manifest, evaluator, config = inputs(tmp_path)
    driver = FakeDriver(
        evaluator_result(archive, manifest),
        start_failure=True,
        partial_start=True,
    )

    with pytest.raises(EvaluationBoundaryError, match="start failed"):
        run_isolated_evaluator(
            driver=driver,
            vm_name="shadow-evaluator",
            lima_config=config,
            archive_path=archive,
            manifest_path=manifest,
            evaluator_path=evaluator,
            output_path=tmp_path / "result.json",
        )

    assert driver.calls == [
        ("exists", "shadow-evaluator"),
        ("start", "shadow-evaluator", config),
        ("exists", "shadow-evaluator"),
        ("delete", "shadow-evaluator"),
    ]


def test_lima_cloud_init_image_is_not_a_host_share() -> None:
    """Lima always attaches its cloud-init ISO at /mnt/lima-cidata.

    That iso9660 device shares nothing with the host. Treating it as a host
    mount failed every clean-state attestation and blocked the evaluator.
    """

    def shares_host(line: str) -> bool:
        return bool(eval(HOST_SHARE_MOUNT_TEST, {}, {"line": line}))

    assert not shares_host(
        "/dev/vdb /mnt/lima-cidata iso9660 ro,relatime,nojoliet 0 0"
    )
    assert not shares_host("/dev/vda1 / ext4 rw,relatime 0 0")
    assert shares_host("mount0 /Users/scott virtiofs rw,relatime 0 0")
    assert shares_host("host /mnt/host 9p rw,trans=virtio 0 0")
    assert shares_host(":/Users/scott /Users/scott fuse.lima rw 0 0")
    assert shares_host("share /mnt/lima-share virtiofs rw 0 0")