from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from shadow_mission.preflight import (
    PreflightBuildError,
    build_release_preflight,
    release_approval_digest,
)
from shadow_mission.protocol import canonical_json
from tests.integration.test_version_binding import (
    PROJECT_ROOT,
    make_fixture,
    runtime_for,
)


def approval_for(fixture: object) -> dict[str, object]:
    release = fixture.release_value
    value: dict[str, object] = {
        "schema_version": "0.1",
        "preflight_id": "fresh-preflight",
        "authorization_id": "direct-authorization",
        "authorized_by": "Scott",
        "approved_at": 1_000,
        "expires_at": 2_000,
        "paid_run_authorized": True,
        "authorization_scope": "one-shadow-mission",
        "release_gate_verdict": release["release_gate_verdict"],
        "initial_commit": release["initial_commit"],
        "droid_installation_channel": release["droid_installation_channel"],
        "droid_auto_update_control": release["droid_auto_update_control"],
        "models": release["models"],
        "reasoning": release["reasoning"],
        "role_configuration": release["role_configuration"],
        "budget": release["budget"],
        "capabilities": release["capabilities"],
        "record_digest": "0" * 64,
    }
    value["record_digest"] = release_approval_digest(value)
    return value


def write_private(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(canonical_json(value) + b"\n")
    path.chmod(0o600)




def test_build_release_preflight_recomputes_every_runtime_binding(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)
    private = tmp_path / "release-private"
    private.mkdir(mode=0o700)
    approval_path = private / "approval.json"
    output_path = private / "release-preflight.json"
    write_private(approval_path, approval_for(fixture))

    preflight = build_release_preflight(
        project_root=PROJECT_ROOT,
        repo=fixture.request.repo,
        mission_file=fixture.request.mission_file,
        evaluator=fixture.request.evaluator,
        profile_manifest=fixture.request.profile_manifest,
        isolation_manifest=fixture.request.isolation_manifest,
        lima_config=fixture.request.lima_config,
        feasibility_record=fixture.request.feasibility_record,
        droid_path=fixture.request.droid_path,
        approval_path=approval_path,
        output_path=output_path,
        command_runner=fixture.runner,
        clock=lambda: 1_100,
    )

    assert json.loads(output_path.read_bytes()) == preflight.model_dump(mode="json")
    request = replace(fixture.request, release_preflight=output_path)
    prepared = runtime_for(fixture).prepare(request)
    assert prepared.preflight.record_digest == preflight.record_digest




def test_build_release_preflight_rejects_changed_direct_approval(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)
    private = tmp_path / "release-private"
    private.mkdir(mode=0o700)
    approval_path = private / "approval.json"
    output_path = private / "release-preflight.json"
    approval = approval_for(fixture)
    approval["authorization_id"] = "changed-without-resigning"
    write_private(approval_path, approval)

    with pytest.raises(PreflightBuildError, match="approval"):
        build_release_preflight(
            project_root=PROJECT_ROOT,
            repo=fixture.request.repo,
            mission_file=fixture.request.mission_file,
            evaluator=fixture.request.evaluator,
            profile_manifest=fixture.request.profile_manifest,
            isolation_manifest=fixture.request.isolation_manifest,
            lima_config=fixture.request.lima_config,
            feasibility_record=fixture.request.feasibility_record,
            droid_path=fixture.request.droid_path,
            approval_path=approval_path,
            output_path=output_path,
            command_runner=fixture.runner,
            clock=lambda: 1_100,
        )
