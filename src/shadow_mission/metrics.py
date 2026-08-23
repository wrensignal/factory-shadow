"""Deterministic Phase 5 metrics derived only from bound replay records."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict

from .protocol import HookExchangeRecord
from .review_journal import (
    ExtractionOutcomeRecord,
    FindingSnapshotRecord,
    JournalRecord,
    project_intervention_router_state,
)

_COMPARISON_BINDINGS = (
    "initial_commit",
    "mission_digest",
    "mission_role_config_digest",
    "factory_profile_digest",
    "mission_relation_source_digest",
    "droid_version",
    "vm_image_digest",
    "isolation_digest",
    "gate_surface_digest",
    "installed_plugin_artifact_digest",
    "approved_evaluator_digest",
    "source_exporter_digest",
)


class MetricValue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["available", "unavailable"]
    value: Any | None = None
    reason: str | None = None


class OutcomeMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    conflict_escape_count: MetricValue
    shared_assumption_escape_count: MetricValue
    validation_overlap_escape_count: MetricValue | None
    intervention_precision: MetricValue
    false_intervention_count: MetricValue
    propagation_radius: MetricValue
    added_usage: MetricValue
    added_cost_cents: MetricValue
    baseline_archive_digest: str | None
    shadow_archive_digest: str | None


def _available(value: Any) -> MetricValue:
    return MetricValue(status="available", value=value)


def _unavailable(reason: str) -> MetricValue:
    return MetricValue(status="unavailable", reason=reason)


def _finding_snapshots(
    records: Sequence[JournalRecord],
) -> tuple[FindingSnapshotRecord, ...]:
    return tuple(record for record in records if isinstance(record, FindingSnapshotRecord))


def _propagation(
    records: Sequence[JournalRecord],
    final_snapshot: FindingSnapshotRecord | None,
) -> dict[str, dict[str, int]]:
    if final_snapshot is None:
        return {
            "detection": {"sessions": 0, "features": 0, "files": 0, "later_decisions": 0},
            "completion": {"sessions": 0, "features": 0, "files": 0, "later_decisions": 0},
        }
    snapshots = _finding_snapshots(records)
    first_by_key: dict[str, tuple[int, Any]] = {}
    final_by_key = {finding.dedup_key: finding for finding in final_snapshot.findings}
    for snapshot in snapshots:
        for finding in snapshot.findings:
            first_by_key.setdefault(
                finding.dedup_key,
                (snapshot.ledger_sequence, finding),
            )
    claims_by_id: dict[str, tuple[int, Any]] = {}
    for record in records:
        if isinstance(record, ExtractionOutcomeRecord) and record.status == "accepted":
            for claim in record.claims:
                claims_by_id[claim.claim_id] = (record.ledger_sequence, claim)

    def radius(findings: Sequence[Any], *, completion: bool) -> dict[str, int]:
        sessions: set[str] = set()
        features: set[str] = set()
        files: set[str] = set()
        later_decisions: set[str] = set()
        for finding in findings:
            sessions.update(finding.target_sessions)
            detection_sequence, detected = first_by_key[finding.dedup_key]
            target_ids: set[str] = set()
            for claim_id in detected.claim_ids:
                claim_entry = claims_by_id.get(claim_id)
                if claim_entry is None:
                    continue
                _, claim = claim_entry
                for target in claim.targets:
                    target_ids.add(target.target_id)
                    if target.kind == "feature":
                        features.add(target.target_id)
                    elif target.kind == "file":
                        files.add(target.target_id)
            if completion:
                current = final_by_key.get(finding.dedup_key, finding)
                for claim_id in current.claim_ids:
                    claim_entry = claims_by_id.get(claim_id)
                    if claim_entry is None:
                        continue
                    _, claim = claim_entry
                    for target in claim.targets:
                        target_ids.add(target.target_id)
                        if target.kind == "feature":
                            features.add(target.target_id)
                        elif target.kind == "file":
                            files.add(target.target_id)
            for claim_id, (sequence, claim) in claims_by_id.items():
                if sequence <= detection_sequence:
                    continue
                if any(target.target_id in target_ids for target in claim.targets):
                    later_decisions.add(claim_id)
        return {
            "sessions": len(sessions),
            "features": len(features),
            "files": len(files),
            "later_decisions": len(later_decisions),
        }

    detected_findings = [value[1] for value in first_by_key.values()]
    return {
        "detection": radius(detected_findings, completion=False),
        "completion": radius(tuple(final_snapshot.findings), completion=True),
    }


def _record_value(record: Mapping[str, Any] | Any, name: str) -> Any:
    if isinstance(record, Mapping):
        return record.get(name)
    return getattr(record, name, None)


def validate_baseline_binding(
    baseline: Mapping[str, Any] | Any,
    shadow: Mapping[str, Any] | Any,
) -> tuple[bool, str | None]:
    for name in _COMPARISON_BINDINGS:
        if _record_value(baseline, name) != _record_value(shadow, name):
            return False, name
    return True, None


def _usage_delta(
    baseline: Mapping[str, Any] | Any,
    shadow: Mapping[str, Any] | Any,
    key: str,
) -> MetricValue:
    baseline_usage = _record_value(baseline, "usage_data")
    shadow_usage = _record_value(shadow, "usage_data")
    if not isinstance(baseline_usage, Mapping) or not isinstance(shadow_usage, Mapping):
        return _unavailable("usage record is unavailable")
    if baseline_usage.get("status") != "available" or shadow_usage.get("status") != "available":
        return _unavailable("attributable usage is unavailable")
    if baseline_usage.get("basis") != shadow_usage.get("basis"):
        return _unavailable("usage bases differ")
    baseline_value = baseline_usage.get(key)
    shadow_value = shadow_usage.get(key)
    if (
        not isinstance(baseline_value, int)
        or isinstance(baseline_value, bool)
        or not isinstance(shadow_value, int)
        or isinstance(shadow_value, bool)
    ):
        return _unavailable(f"{key} is unavailable")
    return _available(shadow_value - baseline_value)


def compute_outcome_metrics(
    *,
    run_id: str,
    journal_records: Sequence[JournalRecord],
    exchanges: Sequence[HookExchangeRecord],
    shadow_record: Mapping[str, Any] | Any,
    baseline_record: Mapping[str, Any] | Any | None = None,
) -> OutcomeMetrics:
    """Compute exact metrics without cached prose, rates, or inferred causality."""
    from .reporting import finding_closed

    snapshots = _finding_snapshots(journal_records)
    final_snapshot = snapshots[-1] if snapshots else None
    findings = final_snapshot.findings if final_snapshot is not None else ()
    interventions = project_intervention_router_state(
        run_id,
        journal_records,
    ).interventions
    unresolved_findings = tuple(
        finding
        for finding in findings
        if not finding_closed(
            finding.dedup_key,
            interventions,
            finding.target_sessions,
        )
    )
    conflict_escape = sum(
        finding.rule == "cross_worker_conflict" for finding in unresolved_findings
    )
    shared_escape = sum(
        finding.rule == "shared_assumption" for finding in unresolved_findings
    )
    overlap_active = (
        final_snapshot is not None
        and final_snapshot.validation_overlap_status == "active"
    )
    overlap_metric = (
        _available(
            sum(
                finding.rule == "validation_overlap"
                for finding in unresolved_findings
            )
        )
        if overlap_active
        else None
    )
    delivered = [
        item
        for item in interventions
        if any(transition.state == "delivered" for transition in item.transition_history)
    ]
    judged = [
        item
        for item in delivered
        if item.probe_status in {"confirmed", "not_confirmed", "rejected"}
    ]
    independently_confirmed = [
        item for item in judged if item.probe_status == "confirmed"
    ]
    false_interventions = [
        item for item in judged if item.probe_status in {"not_confirmed", "rejected"}
    ]
    if not delivered:
        precision = _unavailable("no delivered interventions")
        false_intervention_count = _unavailable("no delivered interventions")
    elif not judged:
        precision = _unavailable("no independent probe verdict")
        false_intervention_count = _unavailable("no independent probe verdict")
    else:
        precision = _available(len(independently_confirmed) / len(judged))
        false_intervention_count = _available(len(false_interventions))

    replayed_guidance = {
        guidance_id
        for exchange in exchanges
        for guidance_id in exchange.response.guidance_ids
    }
    if len(replayed_guidance) > len(delivered):
        precision = _unavailable("guidance lineage is incomplete")

    shadow_archive = _record_value(shadow_record, "final_source_archive_digest")
    baseline_archive = (
        _record_value(baseline_record, "final_source_archive_digest")
        if baseline_record is not None
        else None
    )
    if baseline_record is None:
        added_usage = _unavailable("bound baseline record is unavailable")
        added_cost = _unavailable("bound baseline record is unavailable")
    elif baseline_archive is None or shadow_archive is None:
        added_usage = _unavailable("final source archive binding is unavailable")
        added_cost = _unavailable("final source archive binding is unavailable")
    else:
        matches, mismatch = validate_baseline_binding(baseline_record, shadow_record)
        if not matches:
            added_usage = _unavailable(f"baseline binding differs: {mismatch}")
            added_cost = _unavailable(f"baseline binding differs: {mismatch}")
        else:
            added_usage = _usage_delta(baseline_record, shadow_record, "total_tokens")
            added_cost = _usage_delta(baseline_record, shadow_record, "cost_cents")

    return OutcomeMetrics(
        conflict_escape_count=_available(conflict_escape),
        shared_assumption_escape_count=_available(shared_escape),
        validation_overlap_escape_count=overlap_metric,
        intervention_precision=precision,
        false_intervention_count=false_intervention_count,
        propagation_radius=_available(_propagation(journal_records, final_snapshot)),
        added_usage=added_usage,
        added_cost_cents=added_cost,
        baseline_archive_digest=baseline_archive,
        shadow_archive_digest=shadow_archive,
    )
