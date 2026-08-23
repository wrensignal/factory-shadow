from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from shadow_mission.runtime import MissionExecutionError, PreflightError
from shadow_mission.status import StatusRecord
from tests.integration.test_version_binding import (
    make_fixture,
    run_approved,
    runtime_for,
)


def test_run_stops_without_active_review_controller(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)

    with pytest.raises(PreflightError, match="review controller"):
        runtime_for(fixture).run(fixture.request)

    assert fixture.runner.calls == []
    assert not fixture.state_root.exists()


def test_consumed_authorization_cannot_launch_again(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    runtime = runtime_for(fixture)
    record = run_approved(runtime, fixture.request)
    terminal_status = StatusRecord.model_validate(
        json.loads(
            (
                fixture.state_root
                / "runs"
                / record.run_id
                / "status.json"
            ).read_text(encoding="utf-8")
        )
    )
    shutil.rmtree(fixture.request.factory_mission_root / "factory-orchestrator")

    with pytest.raises(PreflightError, match="live-run ledger"):
        run_approved(runtime, fixture.request)

    assert len(fixture.runner.calls) == 3
    assert sum("--mission" in call[0] for call in fixture.runner.calls) == 1
    assert terminal_status.state == "final"
    assert terminal_status.daemon_health == "stopped"
    assert terminal_status.live_run_count == 3
    assert terminal_status.roles


def test_active_lock_prevents_second_mission(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture.state_root.mkdir(mode=0o700)
    (fixture.state_root / "mission.lock").write_text("active", encoding="utf-8")

    with pytest.raises(PreflightError, match="another Shadow Mission"):
        run_approved(runtime_for(fixture), fixture.request)

    assert len(fixture.runner.calls) == 1


def test_failed_mission_records_increment_and_fails_closed(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture.runner.mission_returncode = 9

    with pytest.raises(MissionExecutionError, match="Droid Mission failed"):
        run_approved(runtime_for(fixture), fixture.request)

    records = list((fixture.state_root / "runs").glob("*/run.json"))
    assert len(records) == 1
    value = json.loads(records[0].read_text())
    assert value["budget_ledger"]["live_run_count_incremented"] is True
    assert value["evaluator_outcome"] == "mission-exit-9"
    assert not (fixture.state_root / "mission.lock").exists()
