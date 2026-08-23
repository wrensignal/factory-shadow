from __future__ import annotations

import hashlib
import json
from pathlib import Path

from shadow_mission.graph import rebuild_graph
from shadow_mission.protocol import HookEnvelope, canonical_json
from shadow_mission.roles import (
    ConfiguredRole,
    FrozenMissionRelations,
    MissionRelation,
    RoleMapper,
)
from shadow_mission.storage import EventLedger, ResponsePlan
from shadow_mission.transcript import TranscriptReader


def envelope(event_id: str, session_alias: str, observed_at: int) -> HookEnvelope:
    return HookEnvelope(provenance_status="hook_authenticated",
    redaction_status="clean",
    event_id=event_id,
    source_fingerprint=hashlib.sha256(event_id.encode()).hexdigest(),
    run_id="run-replay",
    session_alias=session_alias,
    transcript_alias=f"transcript-{session_alias}",
    cwd_alias="cwd-mission",
    hook_event_name="SessionStart", observed_at=observed_at, message_digest=hashlib.sha256(event_id.encode()).hexdigest(),
    payload={"prompt": "start assigned role"},)


def test_ledger_transcript_identity_and_graph_rebuild_are_deterministic(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    ledger = EventLedger(run_dir, run_id="run-replay", clock=lambda: 1_700_000_100)
    accepted = (
        envelope("event-worker", "session-worker", 1_700_000_001),
        envelope("event-validator", "session-validator", 1_700_000_002),
    )
    ledger.start()
    try:
        for value in accepted:
            request_digest = hashlib.sha256(
                canonical_json(value.model_dump(mode="json"))
            ).hexdigest()
            first = ledger.submit(
                value,
                request_digest=request_digest,
                decide=lambda _: ResponsePlan(body={}),
            )
            replay = ledger.submit(
                value,
                request_digest=request_digest,
                decide=lambda _: ResponsePlan(body={"should_not_run": True}),
            )
            assert replay == first
    finally:
        ledger.stop()

    transcripts = tmp_path / "transcripts"
    transcripts.mkdir()
    transcript_paths: dict[str, Path] = {}
    observations = []
    reader = TranscriptReader(
        transcripts,
        run_id="run-replay",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    for value in accepted:
        path = transcripts / f"{value.session_alias}.jsonl"
        transcript_paths[value.session_alias] = path
        path.write_text(
            json.dumps(
                {
                    "kind": "assistant",
                    "observed_at": value.observed_at,
                    "message": f"evidence from {value.session_alias}",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        observations.extend(
            reader.read_primary(
                value.session_alias,
                value.transcript_alias,
                path,
            )
        )
    reader.close()

    roles = (
        ConfiguredRole(role_id="worker-a", kind="worker"),
        ConfiguredRole(role_id="validator", kind="validator"),
    )
    relations = FrozenMissionRelations(
        "mission-1",
        (
            MissionRelation(
                session_alias="session-worker",
                mission_id="mission-1",
                role_id="worker-a",
                assignment_id="assignment-worker",
                source_digest="a" * 64,
                corroborating_role_ids=("worker-a",),
                relation_kind="assignment",
            ),
            MissionRelation(
                session_alias="session-validator",
                mission_id="mission-1",
                role_id="validator",
                assignment_id="assignment-validator",
                source_digest="b" * 64,
                corroborating_role_ids=("validator",),
                relation_kind="mission_relation",
            ),
        ),
    )
    mapper = RoleMapper(roles, relations)
    decisions = tuple(mapper.observe(value) for value in accepted)
    assert all(decision.status == "assigned" for decision in decisions)

    first_graph = rebuild_graph(
        run_id="run-replay",
        ledger_path=ledger.ledger_path,
        sqlite_path=ledger.sqlite_path,
        role_decisions=decisions,
        evidence=(item.evidence for item in observations),
    )
    first_digest = first_graph.digest()
    first_snapshot = first_graph.snapshot()

    recovered = EventLedger(run_dir, run_id="run-replay")
    second_graph = rebuild_graph(
        run_id="run-replay",
        ledger_path=recovered.ledger_path,
        sqlite_path=recovered.sqlite_path,
        role_decisions=decisions,
        evidence=(item.evidence for item in observations),
    )

    assert second_graph.digest() == first_digest
    assert second_graph.snapshot() == first_snapshot
    session_ids = {
        node["node_id"]
        for node in first_snapshot["nodes"]
        if node["kind"] == "session"
    }
    assert session_ids == {"session-worker", "session-validator"}
    assert len(ledger.ledger_path.read_text().splitlines()) == 2
