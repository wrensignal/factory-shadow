import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from shadow_mission.feasibility import (
    GateClassificationError,
    _write_private_result,
    run_dry_run,
)


def test_dry_run_exercises_harness_without_claiming_live_feasibility(
    tmp_path: Path,
) -> None:
    output = tmp_path / "offline-result.json"
    result = run_dry_run(
        fixture_path=Path("tests/fixtures/feasibility"),
        fixture_manifest_pin=Path("tests/fixtures/feasibility-manifest.sha256"),
        output_path=output,
        project_root=Path.cwd(),
    )

    assert result["status"] == "offline-harness-pass"
    assert result["live_gate_verdict"] == "unverified"
    assert result["live_run_count_incremented"] is False
    assert result["external_network_calls"] == 0
    assert result["factory_calls"] == 0
    assert result["model_calls"] == 0
    assert result["checks"]["target_only_guidance"] == "pass"
    assert result["checks"]["collector_outage_latch"] == "pass"
    assert result["checks"]["self_session_exclusion"] == "pass"
    assert json.loads(output.read_text()) == result
    assert os.stat(output).st_mode & 0o777 == 0o600


def test_private_result_writer_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("preserve")
    output = tmp_path / "output.json"
    output.symlink_to(target)

    with pytest.raises(GateClassificationError, match="symlink"):
        _write_private_result(output, {"status": "pass"})

    assert target.read_text() == "preserve"


def test_private_result_writer_accepts_sticky_shared_directory(
    tmp_path: Path,
) -> None:
    shared_directory = tmp_path / "shared"
    shared_directory.mkdir(mode=0o1777)
    os.chmod(shared_directory, 0o1777)
    output = shared_directory / "offline-result.json"

    _write_private_result(output, {"status": "pass"})

    assert json.loads(output.read_text()) == {"status": "pass"}
    assert os.stat(output).st_mode & 0o777 == 0o600


def test_dry_run_output_contains_no_sealed_secret_or_raw_identifiers(
    tmp_path: Path,
) -> None:
    output = tmp_path / "offline-result.json"
    run_dry_run(
        fixture_path=Path("tests/fixtures/feasibility"),
        fixture_manifest_pin=Path("tests/fixtures/feasibility-manifest.sha256"),
        output_path=output,
        project_root=Path.cwd(),
    )
    encoded = output.read_text()

    for forbidden in (
        "sk-shadow-feasibility-NEVER-PERSIST-7319",
        "worker-a-raw",
        "worker-b-raw",
        "SHADOW_MISSION_RUN_SECRET",
    ):
        assert forbidden not in encoded


def test_documented_cli_finds_external_pin_in_guest_layout(
    tmp_path: Path,
) -> None:
    guest_input = tmp_path / "input"
    guest_input.mkdir()
    fixture = guest_input / "feasibility"
    pin = guest_input / "feasibility-manifest.sha256"
    shutil.copytree(Path("tests/fixtures/feasibility"), fixture)
    shutil.copy2(Path("tests/fixtures/feasibility-manifest.sha256"), pin)
    output = tmp_path / "output/gate.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "shadow_mission.feasibility",
            "--fixture",
            str(fixture),
            "--fixture-manifest-pin",
            str(pin),
            "--output",
            str(output),
            "--dry-run",
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "offline-harness-pass"
    assert json.loads(output.read_text())["status"] == "offline-harness-pass"


def test_live_cli_rejects_incomplete_authorization_before_droid() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "shadow_mission.feasibility",
            "--fixture",
            "tests/fixtures/feasibility",
            "--fixture-manifest-pin",
            "tests/fixtures/feasibility-manifest.sha256",
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 2
    assert "live execution inputs are incomplete" in completed.stderr
    assert "droid" not in completed.stdout
