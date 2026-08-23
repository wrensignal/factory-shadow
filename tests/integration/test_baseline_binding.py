from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from shadow_mission.runtime import PreflightError
from tests.integration.test_version_binding import (
    bind_baseline_record,
    make_fixture,
    runtime_for,
)


def test_prepare_accepts_exact_bound_host_baseline_record(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    baseline = bind_baseline_record(fixture)

    prepared = runtime_for(fixture).prepare(fixture.request)

    assert prepared.baseline == baseline
    assert fixture.runner.calls == []


def test_prepare_rejects_baseline_with_different_comparison_binding(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)
    bind_baseline_record(fixture, initial_commit="0" * 40)

    with pytest.raises(
        PreflightError,
        match="baseline comparison binding differs: initial_commit",
    ):
        runtime_for(fixture).prepare(fixture.request)


def test_prepare_rejects_symlinked_baseline_record(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    bind_baseline_record(fixture)
    assert fixture.request.baseline_record is not None
    symlink = fixture.request.baseline_record.with_name("baseline-link.json")
    symlink.symlink_to(fixture.request.baseline_record)
    fixture.request = replace(fixture.request, baseline_record=symlink)

    with pytest.raises(PreflightError, match="regular file"):
        runtime_for(fixture).prepare(fixture.request)
