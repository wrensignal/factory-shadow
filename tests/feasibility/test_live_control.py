import json
import re
import shutil
from pathlib import Path

import pytest

from shadow_mission.auth import create_descriptor, generate_run_secret, make_alias
from shadow_mission.evidence import FrozenObservation, FrozenObservationRegistry
from shadow_mission.live import CommandResult, ProbeEvidence
from shadow_mission.live_control import LiveGateController


class RecordingCollector:
    def __init__(self) -> None:
        self.pauses: list[float] = []

    def pause_for(self, seconds: float) -> None:
        self.pauses.append(seconds)


def append_transcript(path: Path, *values: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for value in values:
            handle.write(json.dumps(value, sort_keys=True))
            handle.write("\n")


def event(
    event_name: str,
    session_id: str,
    transcript: Path,
    *strings: str,
) -> dict[str, object]:
    return {
        "hook_event_name": event_name,
        "session_id": session_id,
        "transcript_path": str(transcript),
        "cwd": str(transcript.parent),
        "prompt": " ".join(strings),
        "tool_name": "Read",
        "tool_input": {"path": "fixture.txt", "marker": " ".join(strings)},
        "tool_response": " ".join(strings),
    }


def sanitized(
    secret: str,
    session_id: str,
    transcript: Path,
) -> dict[str, str]:
    return {
        "session_alias": make_alias(secret, "session", session_id),
        "transcript_alias": make_alias(secret, "transcript", str(transcript)),
    }

def create_controller(
    tmp_path: Path,
    *,
    include_registry: bool = True,
    decoy_active_during_guidance: bool = True,
    dynamic_registry: bool = False,
    include_probe: bool = True,
) -> tuple[LiveGateController, str, Path, RecordingCollector]:
    fixture = tmp_path / "fixture"
    shutil.copytree(Path("tests/fixtures/feasibility"), fixture)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    secret = generate_run_secret()
    descriptor_path = runtime / "descriptor.json"
    latch_path = runtime / "latch.json"
    descriptor = create_descriptor(
        descriptor_path,
        secret,
        run_id="run-live-observed",
        key_id="key-live-observed",
        collector_url="http://127.0.0.1:43119/events",
        mission_root_digest="a" * 64,
        profile_digest="b" * 64,
        isolation_digest="c" * 64,
        gate_surface_digest="d" * 64,
        installed_artifact_digest="e" * 64,
        latch_path=latch_path,
        ttl_seconds=3_600,
    )
    observations = {}
    for raw_target_id, risk_id in (
        ("worker-a-raw", "worker-conflict"),
        ("run-live-observed", "mission-finalization"),
    ):
        target_id = (
            make_alias(secret, "session", raw_target_id)
            if risk_id == "worker-conflict"
            else raw_target_id
        )
        for suffix, transition, kind, status in (
            ("direct", "blocker_create", "direct_evidence", "observed"),
            ("correction", "blocker_clear", "correction", "corrected"),
        ):
            observation_id = f"{risk_id}-{suffix}"
            observations[observation_id] = FrozenObservation(
                observation_id=observation_id,
                run_id="run-live-observed",
                target_id=target_id,
                risk_id=risk_id,
                transition=transition,
                kind=kind,
                status=status,
                source_class="external_frozen",
            )
        probe_observation_id = f"probe-observed-{risk_id}"
        observations[probe_observation_id] = FrozenObservation(
            observation_id=probe_observation_id,
            run_id="run-live-observed",
            target_id=target_id,
            risk_id=risk_id,
            transition="blocker_create",
            kind="probe_confirmation",
            status="confirmed",
            source_class="external_frozen",
        )
    observation_registry = FrozenObservationRegistry(
        observations,
        source_digest="f" * 64,
    )
    controller = LiveGateController(
        run_id="run-live-observed",
        secret=secret,
        fixture_path=fixture,
        descriptor_path=descriptor_path,
        latch_path=latch_path,
        offline_negative_controls=True,
        profile_status="pass",
        trusted_transcript_root=tmp_path,
        observation_registry=(
            observation_registry
            if include_registry and not dynamic_registry
            else None
        ),
        observation_registry_supplier=(
            (lambda *_: observation_registry) if dynamic_registry else None
        ),
    )
    collector = RecordingCollector()
    controller.bind(descriptor, collector)
    controller.set_control_aliases(
        decoy_alias="decoy-safe-alias",
        inert_alias="inert-safe-alias",
        decoy_active_during_guidance=decoy_active_during_guidance,
    )
    if include_probe:
        controller.set_probe(
            ProbeEvidence(
                probe_result_id="probe-observed",
                authoritative_value="cents",
                citations=("api-schema.json#/properties/amount",),
                attempts=1,
                zero_tools=True,
                activation_stripped=True,
                internal_session_alias="probe-safe-alias",
            )
        )
    return controller, secret, fixture, collector


def send(
    controller: LiveGateController,
    secret: str,
    raw: dict[str, object],
) -> object:
    return controller.handle(
        raw,
        sanitized(
            secret,
            str(raw["session_id"]),
            Path(str(raw["transcript_path"])),
        ),
    )


@pytest.mark.parametrize("dynamic_registry", [False, True])
def test_controller_derives_guidance_blockers_and_capabilities_from_events(
    tmp_path: Path,
    dynamic_registry: bool,
) -> None:
    controller, secret, fixture, collector = create_controller(
        tmp_path,
        dynamic_registry=dynamic_registry,
    )
    transcripts = {
        role: tmp_path / "transcripts" / f"{role}.jsonl"
        for role in ("orchestrator", "worker-a", "worker-b", "validator")
    }
    roles = {
        "orchestrator": "SHADOW-FEASIBILITY-ORCHESTRATOR-7319",
        "worker-a": "SHADOW-FEASIBILITY-WORKER-A-7319",
        "worker-b": "SHADOW-FEASIBILITY-WORKER-B-4826",
        "validator": "SHADOW-FEASIBILITY-VALIDATOR-9054",
    }
    for role, marker in roles.items():
        append_transcript(transcripts[role], {"prompt": marker})
        assert send(
            controller,
            secret,
            event("SessionStart", f"{role}-raw", transcripts[role], marker),
        ) is None

    append_transcript(
        transcripts["worker-a"],
        {
            "assistant": "SHADOW-FEASIBILITY-ASSISTANT-A-7319",
            "tool": "SHADOW-FEASIBILITY-TOOL-A-7319",
        },
    )
    canary_a = event(
        "PostToolUse",
        "worker-a-raw",
        transcripts["worker-a"],
        "SHADOW-FEASIBILITY-TOOL-A-7319",
    )
    canary_a["tool_input"] = {
        "path": "/home/shadow/input/sandbox-input-canary.txt"
    }
    canary_a["tool_response"] = "Access denied"
    guidance_a = send(controller, secret, canary_a)
    assert "[shadow:route-a]" in json.dumps(guidance_a)
    guidance_a_text = json.dumps(guidance_a)
    acknowledgement_a = re.search(r"ACK-[A-Za-z0-9_-]+", guidance_a_text)
    assert acknowledgement_a is not None
    ack_a = acknowledgement_a.group(0)

    append_transcript(
        transcripts["worker-b"],
        {
            "assistant": "SHADOW-FEASIBILITY-ASSISTANT-B-4826",
            "tool": "SHADOW-FEASIBILITY-TOOL-B-4826",
        },
    )
    canary_b = event(
        "PostToolUse",
        "worker-b-raw",
        transcripts["worker-b"],
        "SHADOW-FEASIBILITY-TOOL-B-4826",
    )
    canary_b["tool_input"] = {
        "path": "/home/shadow/credential/sandbox-credential-canary.txt"
    }
    canary_b["tool_response"] = "Access denied"
    guidance_b = send(controller, secret, canary_b)
    assert "[shadow:route-b]" in json.dumps(guidance_b)
    guidance_b_text = json.dumps(guidance_b)
    acknowledgement_b = re.search(r"ACK-[A-Za-z0-9_-]+", guidance_b_text)
    assert acknowledgement_b is not None
    ack_b = acknowledgement_b.group(0)

    for role in ("orchestrator", "validator"):
        append_transcript(transcripts[role], {"tool": "ordinary"})
        assert send(
            controller,
            secret,
            event("PostToolUse", f"{role}-raw", transcripts[role], "ordinary"),
        ) is None

    (fixture / "worker-a.txt").write_text(
        "SHADOW-FEASIBILITY-ASSISTANT-A-7319\namount unit: dollars\n"
    )
    append_transcript(transcripts["worker-a"], {"ack": ack_a})
    worker_block = send(
        controller,
        secret,
        event(
            "SubagentStop",
            "worker-a-raw",
            transcripts["worker-a"],
            ack_a,
        ),
    )
    assert worker_block == {
        "decision": "block",
        "reason": "[shadow:worker-conflict] Confirmed unit conflict remains unresolved.",
    }

    with (fixture / "worker-a.txt").open("a") as handle:
        handle.write("CORRECTION-WORKER-A-7319\nauthoritative unit: cents\n")
    append_transcript(
        transcripts["worker-a"],
        {"tool": "CORRECTION-WORKER-A-7319"},
    )
    assert send(
        controller,
        secret,
        event(
            "PostToolUse",
            "worker-a-raw",
            transcripts["worker-a"],
            "CORRECTION-WORKER-A-7319",
        ),
    ) is None
    assert send(
        controller,
        secret,
        event("SubagentStop", "worker-a-raw", transcripts["worker-a"]),
    ) is None
    assert send(
        controller,
        secret,
        event("SessionEnd", "worker-a-raw", transcripts["worker-a"]),
    ) is None

    (fixture / "worker-b.txt").write_text(
        "SHADOW-FEASIBILITY-ASSISTANT-B-4826\namount unit: dollars\n"
    )
    append_transcript(transcripts["worker-b"], {"ack": ack_b})
    assert send(
        controller,
        secret,
        event(
            "SubagentStop",
            "worker-b-raw",
            transcripts["worker-b"],
            ack_b,
        ),
    ) is None
    assert send(
        controller,
        secret,
        event("SubagentStop", "validator-raw", transcripts["validator"]),
    ) is None

    mission_block = send(
        controller,
        secret,
        event("Stop", "orchestrator-raw", transcripts["orchestrator"]),
    )
    assert mission_block == {
        "decision": "block",
        "reason": "[shadow:mission-finalization] Finalization evidence remains unresolved.",
    }
    assert collector.pauses == [15.0]

    append_transcript(
        transcripts["orchestrator"],
        {
            "outage": (
                "[shadow:collector-outage-fallback] "
                "[shadow:mission-finalization]"
            ),
            "tool": "CORRECTION-MISSION-7319",
        },
    )
    (fixture / "mission-correction.txt").write_text("CORRECTION-MISSION-7319\n")
    assert send(
        controller,
        secret,
        event("Stop", "orchestrator-raw", transcripts["orchestrator"]),
    ) is None

    observations = controller.finalize(
        mission_result=CommandResult(
            0,
            "orchestrator-raw worker-a-raw worker-b-raw",
            "",
        ),
        usage={"pre_run": "captured", "post_run": "captured"},
    )

    assert all(
        record["status"] in {"pass", "fallback"}
        for record in observations["capabilities"].values()
    )
    assert observations["blocker_controls"]["worker"]["completion_released"] is True
    assert observations["blocker_controls"]["mission"]["collector_loss_blocked"] is True
    assert observations["guidance_controls"]["siblings_excluded"] is True
    encoded = json.dumps(observations)
    for forbidden in (
        "worker-a-raw",
        "orchestrator-raw",
        "ROUTE-ALPHA-7319",
        "CORRECTION-MISSION-7319",
    ):
        assert forbidden not in encoded


def test_controller_fails_closed_without_external_blocker_registry(
    tmp_path: Path,
) -> None:
    controller, secret, fixture, _ = create_controller(
        tmp_path,
        include_registry=False,
    )
    transcript = tmp_path / "transcripts/worker-a.jsonl"
    marker = "SHADOW-FEASIBILITY-WORKER-A-7319"
    append_transcript(transcript, {"prompt": marker})
    send(
        controller,
        secret,
        event("SessionStart", "worker-a-raw", transcript, marker),
    )
    (fixture / "worker-a.txt").write_text(
        "SHADOW-FEASIBILITY-ASSISTANT-A-7319\namount unit: dollars\n"
    )

    result = send(
        controller,
        secret,
        event("SubagentStop", "worker-a-raw", transcript),
    )

    assert result == {
        "decision": "block",
        "reason": "[shadow:gate-invalid] Live gate evidence is invalid.",
    }


def test_completed_decoy_cannot_satisfy_guidance_negative_control(
    tmp_path: Path,
) -> None:
    controller, _, _, _ = create_controller(
        tmp_path,
        decoy_active_during_guidance=False,
    )

    observations = controller.finalize(
        mission_result=CommandResult(1, "", ""),
        usage={"pre_run": "captured", "post_run": "captured"},
    )

    assert observations["guidance_controls"]["decoy_excluded"] is False
    assert (
        observations["identity_controls"]["same_project_decoy_excluded"]
        is False
    )
    assert observations["capabilities"]["targeted_guidance_routing"]["status"] == "stop"

def test_guidance_route_marker_in_a_sibling_fails_negative_control(
    tmp_path: Path,
) -> None:
    controller, secret, _, _ = create_controller(tmp_path)
    worker_a = tmp_path / "transcripts/worker-a.jsonl"
    worker_b = tmp_path / "transcripts/worker-b.jsonl"
    append_transcript(
        worker_a,
        {"prompt": "SHADOW-FEASIBILITY-WORKER-A-7319"},
    )
    append_transcript(
        worker_b,
        {"prompt": "SHADOW-FEASIBILITY-WORKER-B-4826"},
    )
    send(
        controller,
        secret,
        event(
            "SessionStart",
            "worker-a-raw",
            worker_a,
            "SHADOW-FEASIBILITY-WORKER-A-7319",
        ),
    )
    send(
        controller,
        secret,
        event(
            "SessionStart",
            "worker-b-raw",
            worker_b,
            "SHADOW-FEASIBILITY-WORKER-B-4826",
        ),
    )
    guidance = send(
        controller,
        secret,
        event("PostToolUse", "worker-a-raw", worker_a),
    )
    assert isinstance(guidance, dict)
    context = str(guidance["hookSpecificOutput"]["additionalContext"])
    route_marker = re.search(r"ROUTE-[A-Za-z0-9_-]+", context)
    assert route_marker is not None
    append_transcript(worker_b, {"tool": route_marker.group(0)})
    send(
        controller,
        secret,
        event("PostToolUse", "worker-b-raw", worker_b),
    )

    observations = controller.finalize(
        mission_result=CommandResult(0, "worker-a-raw worker-b-raw", ""),
        usage={"pre_run": "captured", "post_run": "captured"},
    )

    assert observations["guidance_controls"]["siblings_excluded"] is False
    assert (
        observations["capabilities"]["targeted_guidance_routing"]["status"]
        == "stop"
    )



def test_controller_limits_each_blocker_to_two_attempts(
    tmp_path: Path,
) -> None:
    controller, secret, fixture, _ = create_controller(tmp_path)
    transcript = tmp_path / "transcripts" / "worker-a.jsonl"
    append_transcript(
        transcript,
        {"prompt": "SHADOW-FEASIBILITY-WORKER-A-7319"},
    )
    (fixture / "worker-a.txt").write_text(
        "SHADOW-FEASIBILITY-ASSISTANT-A-7319\namount unit: dollars\n"
    )
    send(
        controller,
        secret,
        event(
            "SessionStart",
            "worker-a-raw",
            transcript,
            "SHADOW-FEASIBILITY-WORKER-A-7319",
        ),
    )

    attempts = [
        send(
            controller,
            secret,
            event("SubagentStop", "worker-a-raw", transcript),
        )
        for _ in range(3)
    ]

    assert [attempt is not None for attempt in attempts] == [True, True, False]
    observations = controller.finalize(
        mission_result=CommandResult(0, "worker-a-raw", ""),
        usage={"pre_run": "captured", "post_run": "captured"},
    )
    assert (
        observations["capabilities"]["run_transport_integrity"]["status"]
        == "stop"
    )


def test_controller_allows_completion_without_direct_blocker_evidence(
    tmp_path: Path,
) -> None:
    controller, secret, _, _ = create_controller(tmp_path)
    transcript = tmp_path / "transcripts" / "worker-a.jsonl"
    append_transcript(
        transcript,
        {"prompt": "SHADOW-FEASIBILITY-WORKER-A-7319"},
    )
    send(
        controller,
        secret,
        event(
            "SessionStart",
            "worker-a-raw",
            transcript,
            "SHADOW-FEASIBILITY-WORKER-A-7319",
        ),
    )

    result = send(
        controller,
        secret,
        event("SubagentStop", "worker-a-raw", transcript),
    )

    assert result is None
    observations = controller.finalize(
        mission_result=CommandResult(0, "worker-a-raw", ""),
        usage={"pre_run": "captured", "post_run": "captured"},
    )
    assert observations["capabilities"]["run_transport_integrity"]["status"] == "pass"
    assert observations["blocker_controls"]["worker"]["direct_evidence"] is False
    assert observations["blocker_controls"]["worker"]["completion_blocked"] is False


def test_direct_blocker_evidence_without_a_probe_fails_closed(
    tmp_path: Path,
) -> None:
    worker_root = tmp_path / "worker"
    worker_root.mkdir()
    worker_controller, worker_secret, worker_fixture, _ = create_controller(
        worker_root,
        include_probe=False,
    )
    worker_transcript = worker_root / "transcripts" / "worker-a.jsonl"
    marker = "SHADOW-FEASIBILITY-WORKER-A-7319"
    append_transcript(worker_transcript, {"prompt": marker})
    send(
        worker_controller,
        worker_secret,
        event(
            "SessionStart",
            "worker-a-raw",
            worker_transcript,
            marker,
        ),
    )
    (worker_fixture / "worker-a.txt").write_text(
        "SHADOW-FEASIBILITY-ASSISTANT-A-7319\namount unit: dollars\n"
    )
    assert send(
        worker_controller,
        worker_secret,
        event("SubagentStop", "worker-a-raw", worker_transcript),
    ) == {
        "decision": "block",
        "reason": "[shadow:gate-invalid] Live gate evidence is invalid.",
    }

    mission_root = tmp_path / "mission"
    mission_root.mkdir()
    mission_controller, mission_secret, mission_fixture, _ = create_controller(
        mission_root,
        include_probe=False,
    )
    mission_transcript = mission_root / "transcripts" / "orchestrator.jsonl"
    append_transcript(mission_transcript, {"prompt": "mission"})
    send(
        mission_controller,
        mission_secret,
        event("SessionStart", "orchestrator-raw", mission_transcript, "startup"),
    )
    (mission_fixture / "worker-a.txt").write_text(
        "SHADOW-FEASIBILITY-ASSISTANT-A-7319\namount unit: cents\n"
    )
    (mission_fixture / "worker-b.txt").write_text(
        "SHADOW-FEASIBILITY-ASSISTANT-B-4826\namount unit: dollars\n"
    )
    assert send(
        mission_controller,
        mission_secret,
        event("Stop", "orchestrator-raw", mission_transcript),
    ) == {
        "decision": "block",
        "reason": "[shadow:gate-invalid] Live gate evidence is invalid.",
    }


def test_inherited_mission_markers_do_not_turn_a_child_into_the_orchestrator(
    tmp_path: Path,
) -> None:
    controller, secret, fixture, collector = create_controller(tmp_path)
    orchestrator = tmp_path / "transcripts" / "orchestrator.jsonl"
    explorer = tmp_path / "transcripts" / "explorer.jsonl"
    inherited_markers = " ".join(
        (
            "SHADOW-FEASIBILITY-ORCHESTRATOR-7319",
            "SHADOW-FEASIBILITY-WORKER-A-7319",
            "SHADOW-FEASIBILITY-WORKER-B-4826",
            "SHADOW-FEASIBILITY-VALIDATOR-9054",
        )
    )
    append_transcript(orchestrator, {"prompt": inherited_markers})
    append_transcript(explorer, {"prompt": inherited_markers})
    assert (
        send(
            controller,
            secret,
            event("SessionStart", "orchestrator-raw", orchestrator, "startup"),
        )
        is None
    )
    assert (
        send(
            controller,
            secret,
            event("SessionStart", "explorer-raw", explorer, inherited_markers),
        )
        is None
    )
    assert (
        send(
            controller,
            secret,
            event("PostToolUse", "explorer-raw", explorer),
        )
        is None
    )
    (fixture / "worker-a.txt").write_text(
        "SHADOW-FEASIBILITY-ASSISTANT-A-7319\namount unit: cents\n"
    )
    (fixture / "worker-b.txt").write_text(
        "SHADOW-FEASIBILITY-ASSISTANT-B-4826\namount unit: dollars\n"
    )

    assert (
        send(
            controller,
            secret,
            event("Stop", "explorer-raw", explorer),
        )
        is None
    )
    assert send(
        controller,
        secret,
        event("Stop", "orchestrator-raw", orchestrator),
    ) == {
        "decision": "block",
        "reason": "[shadow:mission-finalization] Finalization evidence remains unresolved.",
    }
    assert collector.pauses == [15.0]
    observations = controller.finalize(
        mission_result=CommandResult(0, "orchestrator-raw explorer-raw", ""),
        usage={"pre_run": "captured", "post_run": "captured"},
    )
    assert observations["capabilities"]["run_transport_integrity"]["status"] == "pass"
    assert observations["blocker_controls"]["mission"]["direct_evidence"] is True
    assert observations["blocker_controls"]["mission"]["completion_blocked"] is True


def test_role_markers_propagated_to_later_sessions_do_not_duplicate_guidance(
    tmp_path: Path,
) -> None:
    controller, secret, _, _ = create_controller(tmp_path)
    primary = tmp_path / "transcripts" / "worker-a-primary.jsonl"
    propagated = tmp_path / "transcripts" / "worker-a-propagated.jsonl"
    marker = "SHADOW-FEASIBILITY-WORKER-A-7319"
    append_transcript(primary, {"prompt": marker})
    append_transcript(propagated, {"prompt": marker})
    send(
        controller,
        secret,
        event("SessionStart", "worker-a-primary-raw", primary, marker),
    )
    send(
        controller,
        secret,
        event("SessionStart", "worker-a-propagated-raw", propagated, marker),
    )

    guidance = send(
        controller,
        secret,
        event("PostToolUse", "worker-a-primary-raw", primary),
    )
    propagated_guidance = send(
        controller,
        secret,
        event("PostToolUse", "worker-a-propagated-raw", propagated),
    )

    assert isinstance(guidance, dict)
    assert propagated_guidance is None
    assert len(controller._roles()["worker_a"]) == 1
    observations = controller.finalize(
        mission_result=CommandResult(
            0,
            "worker-a-primary-raw worker-a-propagated-raw",
            "",
        ),
        usage={"pre_run": "captured", "post_run": "captured"},
    )
    assert observations["guidance_controls"]["siblings_excluded"] is True


def test_untrusted_tool_markers_and_rejected_duplicates_cannot_claim_roles(
    tmp_path: Path,
) -> None:
    controller, secret, _, _ = create_controller(tmp_path)
    orchestrator = tmp_path / "transcripts" / "orchestrator.jsonl"
    spoof = tmp_path / "transcripts" / "spoof.jsonl"
    worker_a = tmp_path / "transcripts" / "worker-a.jsonl"
    duplicate = tmp_path / "transcripts" / "duplicate.jsonl"
    worker_b = tmp_path / "transcripts" / "worker-b.jsonl"
    marker_a = "SHADOW-FEASIBILITY-WORKER-A-7319"
    marker_b = "SHADOW-FEASIBILITY-WORKER-B-4826"
    for transcript, prompt in (
        (orchestrator, "mission"),
        (spoof, "ordinary"),
        (worker_a, marker_a),
        (duplicate, marker_a),
        (worker_b, marker_b),
    ):
        append_transcript(transcript, {"prompt": prompt})
    send(
        controller,
        secret,
        event("SessionStart", "orchestrator-raw", orchestrator, "startup"),
    )
    send(
        controller,
        secret,
        event("SessionStart", "spoof-raw", spoof, "ordinary"),
    )
    spoof_event = event("PostToolUse", "spoof-raw", spoof)
    spoof_event["tool_response"] = marker_a
    assert send(controller, secret, spoof_event) is None

    send(
        controller,
        secret,
        event("SessionStart", "worker-a-raw", worker_a, marker_a),
    )
    send(
        controller,
        secret,
        event("SessionStart", "duplicate-raw", duplicate, marker_a),
    )
    send(
        controller,
        secret,
        event("UserPromptSubmit", "duplicate-raw", duplicate, marker_b),
    )
    send(
        controller,
        secret,
        event("SessionStart", "worker-b-raw", worker_b, marker_b),
    )

    assert isinstance(
        send(
            controller,
            secret,
            event("PostToolUse", "worker-a-raw", worker_a),
        ),
        dict,
    )
    assert isinstance(
        send(
            controller,
            secret,
            event("PostToolUse", "worker-b-raw", worker_b),
        ),
        dict,
    )
    assert (
        send(
            controller,
            secret,
            event("PostToolUse", "duplicate-raw", duplicate),
        )
        is None
    )
    assert len(controller._roles()["worker_a"]) == 1
    assert len(controller._roles()["worker_b"]) == 1


def test_controller_rejects_symlinked_transcript(tmp_path: Path) -> None:
    controller, secret, _, _ = create_controller(tmp_path)
    target = tmp_path / "transcripts" / "target.jsonl"
    append_transcript(
        target,
        {"prompt": "SHADOW-FEASIBILITY-WORKER-A-7319"},
    )
    transcript = tmp_path / "transcripts" / "worker-a.jsonl"
    transcript.symlink_to(target)

    assert (
        send(
            controller,
            secret,
            event(
                "SessionStart",
                "worker-a-raw",
                transcript,
                "SHADOW-FEASIBILITY-WORKER-A-7319",
            ),
        )
        is None
    )
    observations = controller.finalize(
        mission_result=CommandResult(0, "", ""),
        usage={"pre_run": "captured", "post_run": "captured"},
    )
    assert observations["capabilities"]["live_transcript_access"]["status"] == "stop"


def test_controller_rejects_transcript_outside_factory_state(
    tmp_path: Path,
) -> None:
    controller, secret, _, _ = create_controller(tmp_path)
    trusted = tmp_path / "trusted-factory"
    trusted.mkdir()
    controller.trusted_transcript_root = trusted.resolve()
    transcript = tmp_path / "outside.jsonl"
    append_transcript(transcript, {"prompt": "untrusted"})

    assert (
        send(
            controller,
            secret,
            event("SessionStart", "outside-raw", transcript, "untrusted"),
        )
        is None
    )
    observations = controller.finalize(
        mission_result=CommandResult(0, "", ""),
        usage={"pre_run": "captured", "post_run": "captured"},
    )
    assert observations["capabilities"]["live_transcript_access"]["status"] == "stop"
