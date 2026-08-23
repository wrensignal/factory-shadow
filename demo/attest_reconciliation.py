#!/usr/bin/env python3
"""Attest evidence reconciliation against one recorded Shadow review journal."""

from __future__ import annotations

import argparse
import hashlib
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

from shadow_mission.graph import MissionGraph
from shadow_mission.protocol import CapabilityFlags, EvidenceRecord, canonical_json
from shadow_mission.review_journal import (
    InterventionLineageRecord,
    OutageReconciliationRecord,
    JournalRecord,
    ReviewJournal,
    ReviewJournalError,
    TranscriptBatchRecord,
)
from shadow_mission.router import (
    InterventionRouter,
    InterventionRouterDelta,
    InterventionRouterState,
)
from shadow_mission.rules import ProbeVerifier


class ReconciliationAttestationError(RuntimeError):
    """A reconciliation attestation cannot be produced from the supplied run."""


_SCOPE = (
    "This attestation is not a report, not a replay, and not a provenance claim. "
    "The run's correlation.json and report are permanently unrecoverable. "
    "This attestation demonstrates only what the fixed reconciliation does with "
    "that run's own recorded evidence."
)
_TARGET_EVIDENCE_KINDS = ("target_acknowledgment", "target_correction")
_INTERVENTION_STATES = (
    "acknowledged",
    "corrected",
    "delivered",
    "expired",
    "quarantined",
    "queued",
    "repair_assigned",
    "repair_requested",
    "resolved",
    "termination_acknowledged",
)
_NONBLOCKING_STATES = frozenset({"resolved", "termination_acknowledged"})
_ZERO_DIGEST = "0" * 64
_RECONCILIATION_CAPABILITIES = CapabilityFlags(
    core_feasibility_verdict="stop",
    release_gate_verdict="stop",
    droid_version="attestation-only",
    plugin_version="attestation-only",
    droid_sdk_version="attestation-only",
    lima_version="attestation-only",
    vm_image_digest=f"sha256:{_ZERO_DIGEST}",
    factory_profile_digest=_ZERO_DIGEST,
    isolation_digest=_ZERO_DIGEST,
    gate_surface_digest=_ZERO_DIGEST,
    installed_plugin_artifact_digest=_ZERO_DIGEST,
    transport_integrity="stop",
    hook_provenance="stop",
    session_hooks="stop",
    identity="stop",
    transcript="stop",
    guidance="stop",
    worker_block="stop",
    mission_block="stop",
    worker_roles="stop",
    validator_roles="stop",
    self_session_exclusion="stop",
    sandbox_isolation="stop",
    probe_boundary="stop",
    live_validation_overlap="stop",
)
_RECONCILIATION_PROBE_VERIFIER = ProbeVerifier(
    bytes(32),
    boundary_digest=_ZERO_DIGEST,
)


def _load_review_journal(
    run_dir: Path,
) -> tuple[str, tuple[JournalRecord, ...], str]:
    directory = run_dir.expanduser().absolute()
    try:
        directory_metadata = directory.lstat()
    except OSError as error:
        raise ReconciliationAttestationError(
            "Shadow run directory is unavailable"
        ) from error
    if directory.is_symlink() or not stat.S_ISDIR(directory_metadata.st_mode):
        raise ReconciliationAttestationError("Shadow run directory is invalid")
    if not directory.name:
        raise ReconciliationAttestationError("Shadow run identity is unavailable")

    journal_path = directory / "review.jsonl"
    try:
        journal_metadata = journal_path.lstat()
    except OSError as error:
        raise ReconciliationAttestationError("review.jsonl is unavailable") from error
    if journal_path.is_symlink() or not stat.S_ISREG(journal_metadata.st_mode):
        raise ReconciliationAttestationError("review.jsonl is not a regular file")

    try:
        journal = ReviewJournal(journal_path, run_id=directory.name)
        records = journal.records()
    except (OSError, TypeError, ValueError, ReviewJournalError) as error:
        raise ReconciliationAttestationError(
            "review journal could not be loaded"
        ) from error
    payload = b"".join(
        canonical_json(record.model_dump(mode="json")) + b"\n" for record in records
    )
    return directory.name, records, hashlib.sha256(payload).hexdigest()


def _fold_lineage(
    run_id: str,
    records: tuple[JournalRecord, ...],
) -> tuple[InterventionRouterState, int, int]:
    lineage_count = sum(
        isinstance(record, InterventionLineageRecord) for record in records
    )
    outage_count = sum(
        isinstance(record, OutageReconciliationRecord) for record in records
    )
    if not lineage_count:
        raise ReconciliationAttestationError(
            "review journal contains no intervention lineage records"
        )

    try:
        state = InterventionRouterState.empty(run_id)
        for record in records:
            if isinstance(
                record,
                (InterventionLineageRecord, OutageReconciliationRecord),
            ):
                state = record.delta.apply(state)
    except (TypeError, ValueError, RuntimeError) as error:
        raise ReconciliationAttestationError(
            "intervention lineage could not be folded"
        ) from error
    return state, lineage_count, outage_count


def _target_evidence(
    run_id: str,
    records: tuple[JournalRecord, ...],
) -> tuple[tuple[EvidenceRecord, ...], dict[str, int]]:
    evidence: list[EvidenceRecord] = []
    known_by_id: dict[str, EvidenceRecord] = {}
    counts = {kind: 0 for kind in _TARGET_EVIDENCE_KINDS}
    try:
        for record in records:
            if not isinstance(record, TranscriptBatchRecord):
                continue
            for candidate in record.evidence:
                if candidate.kind not in counts:
                    continue
                validated = EvidenceRecord.model_validate(
                    candidate.model_dump(mode="json")
                )
                if validated.run_id != run_id:
                    raise ValueError("target evidence belongs to another run")
                prior = known_by_id.get(validated.evidence_id)
                if prior is not None:
                    if prior != validated:
                        raise ValueError("target evidence identity changed content")
                    continue
                known_by_id[validated.evidence_id] = validated
                evidence.append(validated)
                counts[validated.kind] += 1
    except (TypeError, ValueError, RuntimeError) as error:
        raise ReconciliationAttestationError(
            "target evidence did not validate"
        ) from error
    return tuple(evidence), counts


def _state_summary(
    state: InterventionRouterState,
    *,
    include_unresolved: bool,
) -> dict[str, Any]:
    state_counts = {name: 0 for name in _INTERVENTION_STATES}
    for intervention in state.interventions:
        try:
            state_counts[intervention.state] += 1
        except KeyError as error:
            raise ReconciliationAttestationError(
                "router state contains an unsupported intervention state"
            ) from error
    value: dict[str, Any] = {
        "generation": state.generation,
        "intervention_count": len(state.interventions),
        "state_counts": state_counts,
        "interventions_with_correction_evidence": sum(
            bool(intervention.correction_evidence_ids)
            for intervention in state.interventions
        ),
    }
    if include_unresolved:
        value["unresolved_count"] = sum(
            intervention.state not in _NONBLOCKING_STATES
            for intervention in state.interventions
        )
    return value


def _evidence_profile(
    acknowledgment_count: int,
    diff_count: int,
    test_count: int,
) -> str:
    labels = tuple(
        name
        for name, count in (
            ("acknowledgment", acknowledgment_count),
            ("diff", diff_count),
            ("test", test_count),
        )
        if count
    )
    if not labels:
        return "no_target_evidence"
    if len(labels) == 1:
        return f"{labels[0]}_only"
    return "_plus_".join(labels)


def _intervention_evidence(
    before: InterventionRouterState,
    after: InterventionRouterState,
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    after_by_id = {
        intervention.intervention_id: intervention
        for intervention in after.interventions
    }
    breakdown: list[dict[str, Any]] = []
    withheld: list[dict[str, str]] = []
    for intervention in before.interventions:
        final = after_by_id.get(intervention.intervention_id)
        if final is None or (
            final.transition_history[: len(intervention.transition_history)]
            != intervention.transition_history
        ):
            raise ReconciliationAttestationError(
                "reconciled intervention lineage diverged"
            )
        accepted = InterventionRouter._target_evidence(
            before.run_id,
            evidence,
            intervention,
        )
        acknowledgment_count = sum(
            item.kind == "target_acknowledgment" for item in accepted
        )
        diff_count = sum(
            item.kind == "target_correction"
            and item.source.strip().lower() == "target_diff_transcript"
            for item in accepted
        )
        test_count = sum(
            item.kind == "target_correction"
            and item.source.strip().lower() == "target_test_transcript"
            for item in accepted
        )
        breakdown.append(
            {
                "intervention_id": intervention.intervention_id,
                "before_state": intervention.state,
                "after_state": final.state,
                "evidence_profile": _evidence_profile(
                    acknowledgment_count,
                    diff_count,
                    test_count,
                ),
                "target_evidence_counts": {
                    "target_acknowledgment": acknowledgment_count,
                    "target_diff_transcript": diff_count,
                    "target_test_transcript": test_count,
                },
                "applied_transitions": [
                    transition.action
                    for transition in final.transition_history[
                        len(intervention.transition_history) :
                    ]
                ],
            }
        )
        if bool(diff_count) != bool(test_count):
            withheld.append(
                {
                    "intervention_id": intervention.intervention_id,
                    "missing_precondition": (
                        "target_test_transcript"
                        if diff_count
                        else "target_diff_transcript"
                    ),
                }
            )
    return breakdown, withheld


def _reconcile(
    before: InterventionRouterState,
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[InterventionRouterState, bool]:
    observed_at = max(
        (
            *(item.observed_at for item in evidence),
            *(
                transition.observed_at
                for intervention in before.interventions
                for transition in intervention.transition_history
            ),
        )
    )
    router = InterventionRouter(
        run_id=before.run_id,
        graph=MissionGraph(before.run_id),
        capabilities=_RECONCILIATION_CAPABILITIES,
        probe_verifier=_RECONCILIATION_PROBE_VERIFIER,
        state=before,
    )
    persisted: list[InterventionRouterDelta] = []
    try:
        delta = router.reconcile_evidence(
            evidence,
            persisted.append,
            observed_at=observed_at,
        )
        after = router.snapshot()
        if delta is None:
            if persisted:
                raise ValueError("no-op reconciliation persisted a delta")
        else:
            if persisted != [delta] or delta.apply(before) != after:
                raise ValueError("reconciliation delta was not durable")

        repeated: list[InterventionRouterDelta] = []
        repeated_delta = router.reconcile_evidence(
            evidence,
            repeated.append,
            observed_at=observed_at,
        )
        if repeated_delta is not None or repeated or router.snapshot() != after:
            raise ValueError("evidence reconciliation was not idempotent")
    except (TypeError, ValueError, RuntimeError) as error:
        raise ReconciliationAttestationError(
            "evidence reconciliation failed"
        ) from error
    return after, delta is not None


def build_reconciliation_attestation(run_dir: Path) -> dict[str, Any]:
    """Build one deterministic attestation from a validated review journal."""

    run_id, records, journal_digest = _load_review_journal(run_dir)
    before, lineage_count, outage_count = _fold_lineage(run_id, records)
    evidence, evidence_counts = _target_evidence(run_id, records)
    after, applied = _reconcile(before, evidence)
    intervention_evidence, withheld_corrections = _intervention_evidence(
        before,
        after,
        evidence,
    )
    value: dict[str, Any] = {
        "schema_version": "0.1",
        "record_type": "reconciliation_attestation",
        "scope": _SCOPE,
        "journal": {
            "review_journal_digest": journal_digest,
            "record_count": len(records),
            "lineage_record_count": lineage_count,
            "outage_reconciliation_record_count": outage_count,
            "target_evidence_counts": evidence_counts,
        },
        "before": _state_summary(before, include_unresolved=False),
        "after": _state_summary(after, include_unresolved=True),
        "reconciliation": {
            "applied": applied,
            "idempotent": True,
            "intervention_evidence": intervention_evidence,
            "correction_policy": {
                "required_sources": [
                    "target_diff_transcript",
                    "target_test_transcript",
                ],
                "required_by": "src/shadow_mission/router.py:93-101",
                "withheld_corrections": withheld_corrections,
            },
        },
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def attestation_bytes(run_dir: Path) -> bytes:
    """Return the command's exact one-record stdout payload."""

    return canonical_json(build_reconciliation_attestation(run_dir)) + b"\n"


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--shadow-run-dir", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        payload = attestation_bytes(arguments.shadow_run_dir)
    except ReconciliationAttestationError as error:
        print(f"reconciliation attestation failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
