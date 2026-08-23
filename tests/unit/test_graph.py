from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from shadow_mission.evidence import FrozenEvidenceRegistry
from shadow_mission.graph import GraphError, MissionGraph, rebuild_graph
from shadow_mission.protocol import (
    ClaimRecord,
    ClaimTarget,
    EvidenceRecord,
    HookEnvelope,
    canonical_json,
)
from shadow_mission.roles import RoleDecision
from shadow_mission.storage import EventLedger, ResponsePlan


def make_envelope(event_id: str, session_alias: str) -> HookEnvelope:
    return HookEnvelope(provenance_status="hook_authenticated",
    redaction_status="clean",
    event_id=event_id,
    source_fingerprint=f"source-{session_alias}",
    run_id="run-1",
    session_alias=session_alias,
    transcript_alias=f"transcript-{session_alias}",
    hook_event_name="PostToolUse", observed_at=1, message_digest="d" * 64, payload={"tool_name": "Read"},)


def request_digest(envelope: HookEnvelope) -> str:
    return hashlib.sha256(canonical_json(envelope.model_dump(mode="json"))).hexdigest()


def build_ledger(tmp_path: Path) -> EventLedger:
    ledger = EventLedger(tmp_path / "run", run_id="run-1")
    ledger.start()
    for event_id, session in (("event-a", "session-a"), ("event-b", "session-b")):
        envelope = make_envelope(event_id, session)
        ledger.submit(
            envelope,
            request_digest=request_digest(envelope),
            decide=lambda _: ResponsePlan(),
        )
    ledger.stop()
    return ledger



def evidence(evidence_id: str, session: str, source: str = "worker_output") -> EvidenceRecord:
    return EvidenceRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        evidence_id=evidence_id,
        run_id="run-1",
        session_alias=session,
        kind="claim_source",
        source=source,
        locator=f"src/{session}.py:1",
        digest=hashlib.sha256(evidence_id.encode()).hexdigest(),
        observed_at=2,
    )


def claim(claim_id: str, session: str, evidence_id: str, value: object) -> ClaimRecord:
    return ClaimRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        claim_id=claim_id,
        run_id="run-1",
        session_alias=session,
        subject="amount",
        subject_locator="api-schema.json#/amount",
        property="unit",
        value=value,
        unit="currency",
        confidence=0.9,
        evidence_ids=(evidence_id,),
        observed_at=3,
    )


def assigned(session: str, role_id: str, kind: str) -> RoleDecision:
    return RoleDecision(
        session_alias=session,
        role_id=role_id,
        kind=kind,  # type: ignore[arg-type]
        confidence="high",
        status="assigned",
        reason="test relation",
        evidence_digests=("a" * 64,),
    )


def test_rebuild_is_deterministic_and_materializes_sqlite(tmp_path: Path) -> None:
    ledger = build_ledger(tmp_path)
    first = rebuild_graph(
        run_id="run-1",
        ledger_path=ledger.ledger_path,
        sqlite_path=ledger.sqlite_path,
        role_decisions=(
            assigned("session-a", "worker-a", "worker"),
            assigned("session-b", "validator", "validator"),
        ),
    )
    second = rebuild_graph(
        run_id="run-1",
        ledger_path=ledger.ledger_path,
        sqlite_path=ledger.sqlite_path,
        role_decisions=(
            assigned("session-a", "worker-a", "worker"),
            assigned("session-b", "validator", "validator"),
        ),
    )

    assert first.snapshot() == second.snapshot()
    assert first.digest() == second.digest()
    connection = sqlite3.connect(ledger.sqlite_path)
    try:
        node_count = connection.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
        edge_count = connection.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
    finally:
        connection.close()
    assert node_count == len(first.snapshot()["nodes"])
    assert edge_count == len(first.snapshot()["edges"])


def test_graph_queries_shared_claims_unsupported_matches_and_role_evidence() -> None:
    graph = MissionGraph("run-1")
    graph.add_role_decision(assigned("session-a", "worker-a", "worker"))
    graph.add_role_decision(assigned("session-b", "validator", "validator"))
    evidence_a = evidence("evidence-a", "session-a")
    evidence_b = evidence("evidence-b", "session-b")
    graph.add_evidence(evidence_a)
    graph.add_evidence(evidence_b)
    claim_a = claim("claim-a", "session-a", "evidence-a", "cents")
    claim_b = claim("claim-b", "session-b", "evidence-b", "cents")
    graph.add_claim(claim_a)
    graph.add_claim(claim_b)
    graph.add_milestone("milestone-1", {"name": "payments"})
    graph.connect_claim_to_milestone("claim-a", "milestone-1")
    graph.connect_claim_to_milestone("claim-b", "milestone-1")

    assert graph.claims_sharing(
        "api-schema.json#/amount", "unit", "currency"
    ) == (claim_a, claim_b)
    assert graph.unsupported_matching_claims() == (("claim-a", "claim-b"),)
    assert graph.worker_vs_validator_evidence("milestone-1") == {
        "worker": ("evidence-a",),
        "validator": ("evidence-b",),
    }
    assert graph.claims() == (claim_a, claim_b)
    assert graph.evidence_for_claim("claim-a") == (evidence_a,)
    assert graph.role_for_session("session-a") == "worker"
    assert graph.role_id_for_session("session-a") == "worker-a"
    assert graph.role_id_for_session("unassigned") is None
    assert graph.role_for_session("unassigned") is None
    assert graph.milestones() == ("milestone-1",)
    assert graph.claims_for_milestone("milestone-1") == (claim_a, claim_b)
    assert graph.claim_targets("claim-a") == ()



def test_authoritative_evidence_removes_matching_claim_group() -> None:
    graph = MissionGraph("run-1")
    schema = evidence("evidence-schema", "session-a", "database_schema")
    worker = evidence("evidence-worker", "session-b")
    graph.add_evidence(schema)
    graph.add_evidence(worker)
    graph.add_claim(claim("claim-a", "session-a", schema.evidence_id, "cents"))
    graph.add_claim(claim("claim-b", "session-b", worker.evidence_id, "cents"))

    assert graph.unsupported_matching_claims() == ()


def test_claim_file_feature_dependency_is_explicit() -> None:
    graph = MissionGraph("run-1")
    item = evidence("evidence-a", "session-a")
    graph.add_evidence(item)
    graph.add_claim(claim("claim-a", "session-a", item.evidence_id, "cents"))
    graph.add_feature("feature-payment", {"name": "payment"})
    graph.add_test("test-payment", {"name": "payment contract"})
    graph.connect_claim_to_file("claim-a", "src/payment.py")
    graph.connect_file_to_feature("src/payment.py", "feature-payment")
    graph.connect_claim_to_feature("claim-a", "feature-payment")
    graph.connect_claim_to_test("claim-a", "test-payment")
    assert graph.claim_targets("claim-a") == (
        ("feature", "feature-payment"),
        ("file", "src/payment.py"),
        ("test", "test-payment"),
    )

    edges = graph.snapshot()["edges"]
    assert {
        "source_kind": "claim",
        "source_id": "claim-a",
        "relation": "concerns",
        "target_kind": "file",
        "target_id": "src/payment.py",
    } in edges
    assert {
        "source_kind": "file",
        "source_id": "src/payment.py",
        "relation": "affects",
        "target_kind": "feature",
        "target_id": "feature-payment",
    } in edges


def test_claim_targets_project_material_edges_from_persisted_record() -> None:
    graph = MissionGraph("run-1")
    item = evidence("evidence-a", "session-a").model_copy(
        update={"kind": "changed_file", "locator": "src/payment.py"}
    )
    graph.add_evidence(item)
    record = claim("claim-a", "session-a", item.evidence_id, "cents").model_copy(
        update={
            "targets": (
                ClaimTarget(
                    kind="file",
                    target_id="src/payment.py",
                    evidence_id=item.evidence_id,
                    attributes={},
                ),
            )
        }
    )

    graph.add_claim(record)

    assert graph.claim_targets(record.claim_id) == (("file", "src/payment.py"),)


def test_later_role_quarantine_revokes_prior_assignment() -> None:
    graph = MissionGraph("run-1")
    graph.add_role_decision(assigned("session-a", "worker-a", "worker"))
    graph.add_role_decision(
        RoleDecision(
            session_alias="session-a",
            role_id=None,
            kind="unknown",
            confidence="none",
            status="quarantined",
            reason="conflicting role markers",
            evidence_digests=(),
        )
    )
    graph.add_role_decision(assigned("session-a", "worker-b", "worker"))

    assert graph.role_for_session("session-a") is None
    assert graph.role_id_for_session("session-a") is None
    assert not any(
        edge["source_id"] == "session-a"
        and edge["relation"] == "has_role"
        for edge in graph.snapshot()["edges"]
    )


def test_rebuild_restores_claim_milestone_membership(tmp_path: Path) -> None:
    ledger = build_ledger(tmp_path)
    item = evidence("evidence-a", "session-a")
    record = claim(
        "claim-a", "session-a", item.evidence_id, "cents"
    ).model_copy(update={"milestone_ids": ("milestone-payment",)})

    graph = rebuild_graph(
        run_id="run-1",
        ledger_path=ledger.ledger_path,
        sqlite_path=ledger.sqlite_path,
        role_decisions=(assigned("session-a", "worker-a", "worker"),),
        evidence=(item,),
        claims=(record,),
    )

    assert graph.milestones() == ("milestone-payment",)
    assert graph.claims_for_milestone("milestone-payment") == (record,)


def test_graph_rejects_untrusted_and_cross_session_claim_evidence() -> None:
    graph = MissionGraph("run-1")
    item_a = evidence("evidence-a", "session-a")
    item_b = evidence("evidence-b", "session-b")
    graph.add_evidence(item_a)
    graph.add_evidence(item_b)

    with pytest.raises(GraphError, match="claim provenance"):
        graph.add_claim(
            claim("claim-a", "session-a", item_a.evidence_id, "cents").model_copy(
                update={"provenance_status": "untrusted_provenance"}
            )
        )
    with pytest.raises(GraphError, match="evidence provenance"):
        graph.add_claim(
            claim("claim-b", "session-a", item_b.evidence_id, "cents")
        )


def test_graph_rejects_model_declared_material_target_without_changed_evidence() -> None:
    graph = MissionGraph("run-1")
    item = evidence("evidence-a", "session-a")
    graph.add_evidence(item)
    record = claim(
        "claim-a", "session-a", item.evidence_id, "cents"
    ).model_copy(
        update={
            "targets": (
                ClaimTarget(
                    kind="file",
                    target_id=item.locator,
                    evidence_id=item.evidence_id,
                ),
            )
        }
    )

    with pytest.raises(GraphError, match="material evidence"):
        graph.add_claim(record)


def test_graph_normalizes_material_target_locator_at_ingestion() -> None:
    graph = MissionGraph("run-1")
    item = evidence("evidence-a", "session-a").model_copy(
        update={
            "kind": "changed_file",
            "locator": " ＳＲＣ/Payment.py ",
        }
    )
    graph.add_evidence(item)
    record = claim(
        "claim-a", "session-a", item.evidence_id, "cents"
    ).model_copy(
        update={
            "targets": (
                ClaimTarget(
                    kind="file",
                    target_id="src/payment.py",
                    evidence_id=item.evidence_id,
                ),
            )
        }
    )

    graph.add_claim(record)

    assert graph.claim_targets(record.claim_id) == (("file", "src/payment.py"),)


def test_graph_accepts_sanitized_redacted_authenticated_evidence() -> None:
    graph = MissionGraph("run-1")
    item = evidence("evidence-a", "session-a").model_copy(
        update={"redaction_status": "redacted"}
    )
    graph.add_evidence(item)
    record = claim(
        "claim-a", "session-a", item.evidence_id, "cents"
    ).model_copy(update={"redaction_status": "redacted"})

    graph.add_claim(record)

    assert graph.claims() == (record,)


def test_graph_revalidates_independent_frozen_registry() -> None:
    raw = evidence(
        "evidence-a", "session-a", source="factory_transcript"
    ).model_copy(update={"provenance_status": "independent_frozen"})
    payload = {
        "schema_version": "0.1",
        "evidence": [
            {
                "evidence_id": raw.evidence_id,
                "run_id": raw.run_id,
                "session_alias": raw.session_alias,
                "kind": raw.kind,
                "source": raw.source,
                "locator": raw.locator,
                "digest": raw.digest,
                "redaction_status": raw.redaction_status,
                "observed_at": raw.observed_at,
            }
        ],
    }
    registry = FrozenEvidenceRegistry.from_records(
        (raw,),
        expected_digest=hashlib.sha256(canonical_json(payload)).hexdigest(),
    )
    bound = registry.bind(raw)

    with pytest.raises(GraphError, match="lacks a registry"):
        MissionGraph("run-1").add_evidence(bound)
    graph = MissionGraph("run-1", frozen_evidence_registry=registry)
    with pytest.raises(GraphError, match="binding is invalid"):
        graph.add_evidence(
            bound.model_copy(update={"source": "agent_transcript"})
        )
    graph.add_evidence(bound)
    record = claim(
        "claim-a", "session-a", bound.evidence_id, "cents"
    ).model_copy(update={"provenance_status": "independent_frozen"})
    graph.add_claim(record)

    assert graph.claims() == (record,)
