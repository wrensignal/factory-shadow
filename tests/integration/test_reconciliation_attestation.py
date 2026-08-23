from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from demo.attest_reconciliation import (
    ReconciliationAttestationError,
    attestation_bytes,
    build_reconciliation_attestation,
    _reconcile,
)
from shadow_mission.protocol import (
    EvidenceRecord,
    InterventionRecord,
    InterventionTransition,
    canonical_json,
)
from shadow_mission.review_journal import ReviewJournal
from shadow_mission.router import InterventionRouterDelta, InterventionRouterState


PROJECT_ROOT = Path(__file__).parents[2]
FLAGSHIP_RUN_DIR = Path(
    "/tmp/shadow-phase6-claim/private/shadow-state/runs/"
    "run-b9b18f8af92c3569b65ec0a85db31911"
)
RUN_ID = "run-raw-session-identifier"
SESSION_ALIAS = "session-raw-identifier"
TRANSCRIPT_ALIAS = "transcript-raw-identifier"
INTERVENTION_ID = "intervention-synthetic"
SECRET_MARKER = "private-secret-marker"
STATE_COUNTS = {
    "acknowledged": 0,
    "corrected": 0,
    "delivered": 0,
    "expired": 0,
    "quarantined": 0,
    "queued": 0,
    "repair_assigned": 0,
    "repair_requested": 0,
    "resolved": 0,
    "termination_acknowledged": 0,
}


def _with_record_digest(
    model_type: type[BaseModel], values: dict[str, Any]
) -> dict[str, Any]:
    material = model_type.model_construct(
        record_digest="0" * 64,
        **values,
    ).model_dump(mode="json")
    material.pop("record_digest")
    material["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    return material


def _delivered_intervention() -> InterventionRecord:
    transitions = (
        InterventionTransition(
            transition_id="transition-queued",
            generation=1,
            state="queued",
            action="queued",
            observed_at=10,
        ),
        InterventionTransition(
            transition_id="transition-delivered",
            generation=2,
            state="delivered",
            action="delivered",
            observed_at=11,
        ),
    )
    return InterventionRecord.model_validate(
        _with_record_digest(
            InterventionRecord,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_record",
                "intervention_id": INTERVENTION_ID,
                "run_id": RUN_ID,
                "finding_id": "finding-synthetic",
                "finding_dedup_key": "1" * 64,
                "target_session": SESSION_ALIAS,
                "completion_session_alias": SESSION_ALIAS,
                "rule": "cross_worker_conflict",
                "level": "concern",
                "risk_category": "public_contract",
                "claim_ids": ("claim-a", "claim-b"),
                "direct_evidence_ids": ("evidence-a", "evidence-b"),
                "direct_evidence_digests": ("2" * 64, "3" * 64),
                "generation": 2,
                "state": "delivered",
                "transition_history": transitions,
                "probe_status": "unavailable",
                "blocking_scope": "worker",
            },
        )
    )


def _target_evidence(
    *,
    include_source: bool = True,
    include_test: bool = True,
) -> tuple[EvidenceRecord, ...]:
    common = {
        "schema_version": "0.1",
        "provenance_status": "collector_observed",
        "redaction_status": "redacted",
        "run_id": RUN_ID,
        "session_alias": SESSION_ALIAS,
        "intervention_id": INTERVENTION_ID,
    }
    records = (
        EvidenceRecord(
            **common,
            evidence_id="evidence-acknowledgment",
            kind="target_acknowledgment",
            source="target_assistant_transcript",
            locator=f"transcript:{SECRET_MARKER}:acknowledgment",
            digest="4" * 64,
            observed_at=20,
        ),
        EvidenceRecord(
            **common,
            evidence_id="evidence-source-correction",
            kind="target_correction",
            source="target_diff_transcript",
            locator=f"transcript:{SECRET_MARKER}:source",
            digest="5" * 64,
            observed_at=21,
        ),
        EvidenceRecord(
            **common,
            evidence_id="evidence-test-correction",
            kind="target_correction",
            source="target_test_transcript",
            locator=f"transcript:{SECRET_MARKER}:test",
            digest="6" * 64,
            observed_at=22,
        ),
    )
    return tuple(
        record
        for record in records
        if (include_source or record.source != "target_diff_transcript")
        and (include_test or record.source != "target_test_transcript")
    )


def _synthetic_run(
    tmp_path: Path,
    *,
    include_source: bool = True,
    include_test: bool = True,
) -> Path:
    run_dir = tmp_path / RUN_ID
    run_dir.mkdir()
    journal = ReviewJournal(run_dir / "review.jsonl", run_id=RUN_ID)
    before = InterventionRouterState.empty(RUN_ID)
    intervention = _delivered_intervention()
    final = InterventionRouterState.model_validate(
        _with_record_digest(
            InterventionRouterState,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_state",
                "run_id": RUN_ID,
                "generation": 2,
                "interventions": (intervention,),
            },
        )
    )
    delta = InterventionRouterDelta.model_validate(
        _with_record_digest(
            InterventionRouterDelta,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_delta",
                "run_id": RUN_ID,
                "base_generation": 0,
                "base_digest": before.record_digest,
                "generation": 2,
                "upserts": (intervention,),
                "result_digest": final.record_digest,
            },
        )
    )
    journal.append(
        "intervention_lineage",
        ledger_sequence=1,
        event_id="event-lineage",
        response_digest="7" * 64,
        delta=delta,
    )
    journal.append(
        "transcript_batch",
        ledger_sequence=2,
        event_id="event-transcript",
        session_alias=SESSION_ALIAS,
        transcript_alias=TRANSCRIPT_ALIAS,
        cursor_before=0,
        cursor_after=3,
        status="read",
        evidence=_target_evidence(
            include_source=include_source,
            include_test=include_test,
        ),
    )
    return run_dir


def test_positive_control_reaches_corrected_then_resolved_and_is_idempotent(
    tmp_path: Path,
) -> None:
    run_dir = _synthetic_run(tmp_path)

    attestation = build_reconciliation_attestation(run_dir)

    expected_before_counts = dict(STATE_COUNTS)
    expected_before_counts["delivered"] = 1
    assert attestation["before"] == {
        "generation": 2,
        "intervention_count": 1,
        "state_counts": expected_before_counts,
        "interventions_with_correction_evidence": 0,
    }
    expected_after_counts = dict(STATE_COUNTS)
    expected_after_counts["resolved"] = 1
    assert attestation["after"] == {
        "generation": 5,
        "intervention_count": 1,
        "state_counts": expected_after_counts,
        "interventions_with_correction_evidence": 1,
        "unresolved_count": 0,
    }
    assert attestation["journal"] == {
        "lineage_record_count": 1,
        "outage_reconciliation_record_count": 0,
        "record_count": 2,
        "review_journal_digest": hashlib.sha256(
            (run_dir / "review.jsonl").read_bytes()
        ).hexdigest(),
        "target_evidence_counts": {
            "target_acknowledgment": 1,
            "target_correction": 2,
        },
    }
    reconciliation = attestation["reconciliation"]
    assert reconciliation["applied"] is True
    assert reconciliation["idempotent"] is True
    assert reconciliation["intervention_evidence"] == [
        {
            "intervention_id": INTERVENTION_ID,
            "before_state": "delivered",
            "after_state": "resolved",
            "evidence_profile": "acknowledgment_plus_diff_plus_test",
            "target_evidence_counts": {
                "target_acknowledgment": 1,
                "target_diff_transcript": 1,
                "target_test_transcript": 1,
            },
            "applied_transitions": ["acknowledged", "corrected", "resolved"],
        }
    ]
    assert reconciliation["correction_policy"] == {
        "required_sources": [
            "target_diff_transcript",
            "target_test_transcript",
        ],
        "required_by": "src/shadow_mission/router.py:93-101",
        "withheld_corrections": [],
    }


def test_attestation_folds_outage_reconciliation_into_before_state(
    tmp_path: Path,
) -> None:
    run_dir = _synthetic_run(tmp_path)
    intervention = _delivered_intervention()
    delivered = InterventionRouterState.model_validate(
        _with_record_digest(
            InterventionRouterState,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_state",
                "run_id": RUN_ID,
                "generation": 2,
                "interventions": (intervention,),
            },
        )
    )
    reconciled, applied = _reconcile(delivered, _target_evidence())
    assert applied is True
    delta = InterventionRouterDelta.model_validate(
        _with_record_digest(
            InterventionRouterDelta,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_delta",
                "run_id": RUN_ID,
                "base_generation": delivered.generation,
                "base_digest": delivered.record_digest,
                "generation": reconciled.generation,
                "upserts": reconciled.interventions,
                "result_digest": reconciled.record_digest,
            },
        )
    )
    ReviewJournal(run_dir / "review.jsonl", run_id=RUN_ID).append(
        "outage_reconciliation",
        observed_at=30,
        delta=delta,
    )

    attestation = build_reconciliation_attestation(run_dir)

    assert attestation["journal"]["lineage_record_count"] == 1
    assert attestation["journal"]["outage_reconciliation_record_count"] == 1
    assert attestation["before"]["generation"] == reconciled.generation
    assert attestation["before"]["state_counts"]["resolved"] == 1
    assert attestation["reconciliation"]["applied"] is False


def test_attestation_deduplicates_identical_target_evidence(
    tmp_path: Path,
) -> None:
    run_dir = _synthetic_run(tmp_path)
    ReviewJournal(run_dir / "review.jsonl", run_id=RUN_ID).append(
        "transcript_batch",
        ledger_sequence=3,
        event_id="event-transcript-duplicate",
        session_alias=SESSION_ALIAS,
        transcript_alias=TRANSCRIPT_ALIAS,
        cursor_before=3,
        cursor_after=6,
        status="read",
        evidence=_target_evidence(),
    )

    attestation = build_reconciliation_attestation(run_dir)

    assert attestation["journal"]["target_evidence_counts"] == {
        "target_acknowledgment": 1,
        "target_correction": 2,
    }
    assert attestation["reconciliation"]["intervention_evidence"][0][
        "target_evidence_counts"
    ] == {
        "target_acknowledgment": 1,
        "target_diff_transcript": 1,
        "target_test_transcript": 1,
    }


def test_source_only_evidence_withholds_corrected_by_policy(tmp_path: Path) -> None:
    run_dir = _synthetic_run(tmp_path, include_test=False)

    attestation = build_reconciliation_attestation(run_dir)

    before = attestation["before"]
    after = attestation["after"]
    assert before["interventions_with_correction_evidence"] == 0
    assert after["generation"] == 4
    assert after["state_counts"]["acknowledged"] == 1
    assert after["state_counts"]["corrected"] == before["state_counts"]["corrected"] == 0
    assert after["state_counts"]["resolved"] == before["state_counts"]["resolved"] == 0
    assert after["interventions_with_correction_evidence"] == 1
    assert (
        after["interventions_with_correction_evidence"]
        > before["interventions_with_correction_evidence"]
    )
    assert after["unresolved_count"] == 1
    reconciliation = attestation["reconciliation"]
    assert reconciliation["applied"] is True
    assert reconciliation["idempotent"] is True
    assert reconciliation["intervention_evidence"] == [
        {
            "intervention_id": INTERVENTION_ID,
            "before_state": "delivered",
            "after_state": "acknowledged",
            "evidence_profile": "acknowledgment_plus_diff",
            "target_evidence_counts": {
                "target_acknowledgment": 1,
                "target_diff_transcript": 1,
                "target_test_transcript": 0,
            },
            "applied_transitions": [
                "acknowledged",
                "correction_evidence_bound",
            ],
        }
    ]
    assert reconciliation["correction_policy"]["withheld_corrections"] == [
        {
            "intervention_id": INTERVENTION_ID,
            "missing_precondition": "target_test_transcript",
        }
    ]


def test_test_only_evidence_withholds_corrected_by_policy(tmp_path: Path) -> None:
    run_dir = _synthetic_run(tmp_path, include_source=False)

    attestation = build_reconciliation_attestation(run_dir)

    reconciliation = attestation["reconciliation"]
    intervention = reconciliation["intervention_evidence"][0]
    assert intervention["after_state"] == "acknowledged"
    assert intervention["evidence_profile"] == "acknowledgment_plus_test"
    assert intervention["applied_transitions"] == [
        "acknowledged",
        "correction_evidence_bound",
    ]
    assert reconciliation["correction_policy"]["withheld_corrections"] == [
        {
            "intervention_id": INTERVENTION_ID,
            "missing_precondition": "target_diff_transcript",
        }
    ]


def test_command_is_byte_deterministic_and_emits_no_private_identity(
    tmp_path: Path,
) -> None:
    run_dir = _synthetic_run(tmp_path)
    command = (
        sys.executable,
        str(PROJECT_ROOT / "demo" / "attest_reconciliation.py"),
        "--shadow-run-dir",
        str(run_dir),
    )

    first = subprocess.run(command, cwd=PROJECT_ROOT, capture_output=True, check=False)
    second = subprocess.run(command, cwd=PROJECT_ROOT, capture_output=True, check=False)

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout == attestation_bytes(run_dir)
    assert first.stdout.count(b"\n") == 1
    assert str(tmp_path).encode() not in first.stdout
    assert RUN_ID.encode() not in first.stdout
    assert SESSION_ALIAS.encode() not in first.stdout
    assert SECRET_MARKER.encode() not in first.stdout
    assert TRANSCRIPT_ALIAS.encode() not in first.stdout
    value = json.loads(first.stdout)
    supplied_digest = value.pop("record_digest")
    assert supplied_digest == hashlib.sha256(canonical_json(value)).hexdigest()


def test_attestation_fails_closed_when_journal_does_not_load(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-corrupt"
    run_dir.mkdir()
    (run_dir / "review.jsonl").write_bytes(b"{not-json}\n")

    with pytest.raises(ReconciliationAttestationError, match="could not be loaded"):
        build_reconciliation_attestation(run_dir)


def test_attestation_fails_closed_without_lineage(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-without-lineage"
    run_dir.mkdir()
    ReviewJournal(run_dir / "review.jsonl", run_id=run_dir.name)

    with pytest.raises(ReconciliationAttestationError, match="no intervention lineage"):
        build_reconciliation_attestation(run_dir)


def test_attestation_fails_closed_when_evidence_does_not_validate(
    tmp_path: Path,
) -> None:
    run_dir = _synthetic_run(tmp_path)
    journal_path = run_dir / "review.jsonl"
    records = [json.loads(line) for line in journal_path.read_bytes().splitlines()]
    transcript = records[-1]
    transcript["evidence"][0]["digest"] = "invalid"
    transcript.pop("record_digest")
    transcript["record_digest"] = hashlib.sha256(canonical_json(transcript)).hexdigest()
    records[-1] = transcript
    journal_path.write_bytes(b"".join(canonical_json(item) + b"\n" for item in records))

    with pytest.raises(ReconciliationAttestationError, match="could not be loaded"):
        build_reconciliation_attestation(run_dir)


@pytest.mark.skipif(
    not (FLAGSHIP_RUN_DIR / "review.jsonl").is_file(),
    reason="private flagship run is unavailable",
)
def test_flagship_before_state_matches_frozen_measurement() -> None:
    attestation = build_reconciliation_attestation(FLAGSHIP_RUN_DIR)
    expected_counts = dict(STATE_COUNTS)
    expected_counts.update({"acknowledged": 2, "delivered": 1, "queued": 2})

    assert attestation["before"] == {
        "generation": 20,
        "intervention_count": 5,
        "state_counts": expected_counts,
        "interventions_with_correction_evidence": 0,
    }
    assert attestation["after"] == {
        "generation": 22,
        "intervention_count": 5,
        "state_counts": expected_counts,
        "interventions_with_correction_evidence": 2,
        "unresolved_count": 5,
    }
    assert attestation["after"]["state_counts"] == attestation["before"]["state_counts"]
    assert (
        attestation["after"]["interventions_with_correction_evidence"]
        > attestation["before"]["interventions_with_correction_evidence"]
    )
    assert attestation["after"]["state_counts"]["corrected"] == 0
    assert attestation["after"]["state_counts"]["resolved"] == 0
    reconciliation = attestation["reconciliation"]
    assert reconciliation["applied"] is True
    assert reconciliation["idempotent"] is True
    assert sorted(
        (row["before_state"], row["evidence_profile"])
        for row in reconciliation["intervention_evidence"]
    ) == [
        ("acknowledged", "acknowledgment_only"),
        ("acknowledged", "acknowledgment_plus_diff"),
        ("delivered", "diff_only"),
        ("queued", "no_target_evidence"),
        ("queued", "no_target_evidence"),
    ]
    evidence_binding_rows = [
        row
        for row in reconciliation["intervention_evidence"]
        if row["applied_transitions"] == ["correction_evidence_bound"]
    ]
    assert len(evidence_binding_rows) == 2
    assert all(
        row["after_state"] == row["before_state"] for row in evidence_binding_rows
    )
    assert all(
        row["target_evidence_counts"]["target_diff_transcript"] == 1
        and row["target_evidence_counts"]["target_test_transcript"] == 0
        for row in evidence_binding_rows
    )
    policy = reconciliation["correction_policy"]
    assert policy["required_by"] == "src/shadow_mission/router.py:93-101"
    assert len(policy["withheld_corrections"]) == 2
    assert {
        row["missing_precondition"] for row in policy["withheld_corrections"]
    } == {"target_test_transcript"}
