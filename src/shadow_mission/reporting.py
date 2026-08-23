"""Deterministic public report rebuild from authoritative run evidence."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any, Collection, Iterable, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .evaluation import EvaluationRecord
from .correlation import (
    FactoryMissionCorrelationRecord,
    FactoryMissionCorrelationWrapper,
)
from .graph import GraphError, load_exchanges_bytes
from .metrics import OutcomeMetrics, compute_outcome_metrics, validate_baseline_binding
from .protocol import (
    RELEASE_REPORTABLE_RUNTIME_OUTCOMES,
    BaselineRunRecord,
    InterventionRecord,
    PreEvaluationRecord,
    RunRecord,
    canonical_json,
)
from .review_journal import (
    ExtractionOutcomeRecord,
    FindingSnapshotRecord,
    ProbeOutcomeRecord,
    ReviewJournalCorruptionError,
    RoleDecisionRecord,
    TranscriptBatchRecord,
    load_journal_records,
    project_intervention_router_state,
)
from .source_export import (
    SourceArchiveError,
    validate_source_archive,
)


class ReportError(RuntimeError):
    """Base failure for deterministic report rebuild."""


class ReportInputError(ReportError):
    """The requested run or baseline binding is unknown or invalid."""


class ReportCorruptionError(ReportError):
    """Authoritative run evidence is corrupt or incomplete."""


class ReportWriteError(ReportError):
    """Both public report outputs could not be published."""


class ReportRecord(BaseModel):
    """One deterministic report rendered identically as JSON and Markdown."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    run_id: str = Field(min_length=1)
    outcome: str = Field(min_length=1)
    provenance_status: str = Field(min_length=1)
    ledger_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    ledger_record_count: int = Field(ge=0)
    review_journal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_record_count: int = Field(ge=0)
    frozen_configuration: dict[str, Any]
    capabilities: dict[str, Any]
    sessions: tuple[dict[str, Any], ...]
    roles: tuple[dict[str, Any], ...]
    detections: tuple[dict[str, Any], ...]
    claims: tuple[dict[str, Any], ...]
    evidence: tuple[dict[str, Any], ...]
    probes: tuple[dict[str, Any], ...]
    interventions: tuple[dict[str, Any], ...]
    changed_files: tuple[str, ...]
    final_source: dict[str, Any]
    evaluator: dict[str, Any]
    unresolved_risks: tuple[str, ...]
    unavailable_fields: tuple[str, ...]
    usage: dict[str, Any]
    budget_ledger: dict[str, Any]
    duration_seconds: float | None
    commits: dict[str, str | None]
    baseline_linkage: dict[str, Any]
    metrics: OutcomeMetrics
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_record_digest(self) -> ReportRecord:
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        if supplied != hashlib.sha256(canonical_json(value)).hexdigest():
            raise ValueError("report record digest differs")
        return self


def _read_regular_bytes(path: Path, description: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReportCorruptionError(f"{description} is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReportCorruptionError(f"{description} is not a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1 << 20):
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as error:
        raise ReportCorruptionError(f"{description} is unreadable") from error
    finally:
        os.close(descriptor)


def _load_json_record(path: Path, model_type, description: str):
    try:
        payload = _read_regular_bytes(path, description)
        value = json.loads(payload)
        if canonical_json(value) + b"\n" != payload:
            raise ReportCorruptionError(f"{description} is not canonical")
        return model_type.model_validate(value)
    except ReportError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ReportCorruptionError(f"{description} is invalid") from error


def _load_mission_relation_record(
    path: Path,
) -> tuple[dict[str, Any], FactoryMissionCorrelationRecord]:
    try:
        payload = _read_regular_bytes(path, "Mission relation record")
        value = json.loads(payload)
        if (
            not isinstance(value, dict)
            or canonical_json(value) + b"\n" != payload
        ):
            raise ReportCorruptionError(
                "Mission relation record is not canonical"
            )
        wrapper = FactoryMissionCorrelationWrapper.model_validate(value)
        return wrapper.model_dump(mode="json"), wrapper.record
    except ReportError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ReportCorruptionError("Mission relation record is invalid") from error


def load_run_record(path: Path) -> RunRecord:
    """Load one digest-bound final or pre-evaluation run record."""

    return _load_json_record(path, RunRecord, "run record")




def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except OSError as error:
        raise ReportCorruptionError("cannot read authoritative report source") from error
    return digest.hexdigest()


def finding_closed(
    dedup_key: str,
    interventions: Iterable[InterventionRecord],
    target_sessions: Collection[str],
) -> bool:
    """Return whether every expected target resolved this finding."""

    group = tuple(
        item for item in interventions if item.finding_dedup_key == dedup_key
    )
    # A finding keeps one identity while its target set grows, so the recorded
    # group may name more sessions than the detection snapshot expected.
    return (
        bool(group)
        and set(target_sessions) <= {item.target_session for item in group}
        and all(item.state == "resolved" for item in group)
    )


def _report_value(
    *,
    run: RunRecord,
    baseline: BaselineRunRecord | None,
    pre_evaluation: PreEvaluationRecord | None,
    evaluation: EvaluationRecord | None,
    exchanges: tuple[Any, ...],
    review_records: tuple[Any, ...],
    ledger_digest: str,
    journal_digest: str,
    mission_role_inventory_complete: bool,
) -> dict[str, Any]:
    role_records = [
        record for record in review_records if isinstance(record, RoleDecisionRecord)
    ]
    assigned_roles = {
        record.role_id: record
        for record in role_records
        if record.status == "assigned"
        and record.confidence == "high"
        and record.role_id is not None
    }
    sessions = sorted(
        {
            exchange.envelope.session_alias
            for exchange in exchanges
        }
        | {record.session_alias for record in role_records}
    )
    claims: dict[str, Any] = {}
    evidence: dict[str, Any] = {}
    snapshots: list[FindingSnapshotRecord] = []
    probes: dict[str, Any] = {}
    for record in review_records:
        if isinstance(record, TranscriptBatchRecord):
            for item in record.evidence:
                evidence[item.evidence_id] = item
        elif isinstance(record, ExtractionOutcomeRecord):
            for item in record.claims:
                claims[item.claim_id] = item
            for item in record.derived_evidence:
                evidence[item.evidence_id] = item
        elif isinstance(record, FindingSnapshotRecord):
            snapshots.append(record)
        elif isinstance(record, ProbeOutcomeRecord):
            probes[record.probe_id] = record
    final_state = project_intervention_router_state(run.run_id, review_records)
    interventions = tuple(final_state.interventions)
    first_detection: dict[str, tuple[int, Any]] = {}
    for snapshot in snapshots:
        for item in snapshot.findings:
            first_detection.setdefault(item.dedup_key, (snapshot.ledger_sequence, item))
    final_findings = (
        {item.dedup_key: item for item in snapshots[-1].findings}
        if snapshots
        else {}
    )
    detection_rows: list[dict[str, Any]] = []
    for dedup_key, (sequence, item) in sorted(first_detection.items()):
        final_state_name = (
            "resolved"
            if finding_closed(dedup_key, interventions, item.target_sessions)
            else "unresolved"
        )
        detection_rows.append(
            {
                "finding": item.model_dump(mode="json"),
                "detected_at_ledger_sequence": sequence,
                "completion_state": final_state_name,
                "present_at_completion": dedup_key in final_findings,
            }
        )
    unresolved = tuple(
        sorted(
            dedup_key
            for dedup_key, finding in final_findings.items()
            if not finding_closed(
                dedup_key,
                interventions,
                finding.target_sessions,
            )
        )
    )
    unavailable: list[str] = []
    if run.usage_data.get("status") != "available":
        unavailable.append("per_run_usage_and_cost")
    if run.final_source_archive_digest is None:
        unavailable.append("final_source_archive")
    if run.final_commit is None:
        unavailable.append("final_commit")
    if not mission_role_inventory_complete:
        unavailable.append("mission_role_inventory")
    baseline_dump = baseline.model_dump(mode="json") if baseline is not None else None
    metrics = compute_outcome_metrics(
        run_id=run.run_id,
        journal_records=review_records,
        exchanges=exchanges,
        shadow_record=run,
        baseline_record=baseline,
    )
    if evaluation is not None and pre_evaluation is not None:
        evaluator = {
            **evaluation.model_dump(mode="json"),
            "evaluator_digest": pre_evaluation.evaluator_digest,
        }
        outcome = evaluation.status
    elif isinstance(run.evaluator_outcome, Mapping):
        evaluator = dict(run.evaluator_outcome)
        outcome = str(evaluator.get("status", "incomplete"))
    else:
        outcome = run.evaluator_outcome or "incomplete"
        evaluator = {"outcome": run.evaluator_outcome}
    value: dict[str, Any] = {
        "schema_version": "0.1",
        "run_id": run.run_id,
        "outcome": outcome,
        "provenance_status": run.provenance_status,
        "ledger_digest": ledger_digest,
        "ledger_record_count": len(exchanges),
        "review_journal_digest": journal_digest,
        "review_record_count": len(review_records),
        "frozen_configuration": {
            "droid_version": run.droid_version,
            "plugin_version": run.plugin_version,
            "droid_sdk_version": run.droid_sdk_version,
            "lima_version": run.lima_version,
            "models": run.models,
            "reasoning": run.reasoning,
            "mission_digest": run.mission_digest,
            "mission_role_config_digest": run.mission_role_config_digest,
            "mission_relation_source_digest": run.mission_relation_source_digest,
            "mission_relation_record_digest": run.mission_relation_record_digest,
            "mission_outcome": run.mission_outcome,
            "runtime_outcome": run.runtime_outcome,
            "factory_profile_digest": run.factory_profile_digest,
            "vm_image_digest": run.vm_image_digest,
            "isolation_digest": run.isolation_digest,
            "gate_surface_digest": run.gate_surface_digest,
            "installed_plugin_artifact_digest": run.installed_plugin_artifact_digest,
            "full_run_artifact_digest": run.full_run_artifact_digest,
            "source_exporter_digest": run.source_exporter_digest,
            "approved_evaluator_digest": run.approved_evaluator_digest,
            "evaluator_digest": run.evaluator_digest,
        },
        "capabilities": run.capabilities.model_dump(mode="json"),
        "sessions": tuple({"session_alias": session} for session in sessions),
        "roles": tuple(
            {
                "role_id": role_id,
                "session_alias": record.session_alias,
                "kind": record.kind,
                "confidence": record.confidence,
                "evidence_digests": record.evidence_digests,
            }
            for role_id, record in sorted(assigned_roles.items())
        ),
        "detections": tuple(detection_rows),
        "claims": tuple(
            claims[key].model_dump(mode="json") for key in sorted(claims)
        ),
        "evidence": tuple(
            evidence[key].model_dump(mode="json") for key in sorted(evidence)
        ),
        "probes": tuple(
            probes[key].model_dump(mode="json") for key in sorted(probes)
        ),
        "interventions": tuple(
            item.model_dump(mode="json")
            for item in sorted(
                final_state.interventions,
                key=lambda item: item.intervention_id,
            )
        ),
        "changed_files": run.changed_files,
        "final_source": {
            "archive_digest": run.final_source_archive_digest,
            "manifest_digest": run.final_source_manifest_digest,
            "working_tree_digest": run.final_source_working_tree_digest,
        },
        "evaluator": evaluator,
        "unresolved_risks": unresolved,
        "unavailable_fields": tuple(sorted(unavailable)),
        "usage": run.usage_data,
        "budget_ledger": run.budget_ledger,
        "duration_seconds": run.duration_seconds,
        "commits": {
            "initial": run.initial_commit,
            "final": run.final_commit,
        },
        "baseline_linkage": {
            "baseline_id": run.baseline_id,
            "baseline_record_digest": run.baseline_record_digest,
            "baseline_record": baseline_dump,
        },
        "metrics": metrics.model_dump(mode="json"),
        "record_digest": "0" * 64,
    }
    material = dict(value)
    material.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    return value


def validate_finalization_provenance(
    run_dir: Path,
    run: RunRecord,
    *,
    ledger_payload: bytes | None = None,
    journal_payload: bytes | None = None,
) -> tuple[
    PreEvaluationRecord,
    EvaluationRecord,
    FactoryMissionCorrelationRecord,
]:
    """Validate the immutable precursor, ledgers, source, and evaluator chain."""

    if not isinstance(run.evaluator_outcome, Mapping):
        raise ReportCorruptionError("run finalization is incomplete")
    pre_run_path = run_dir / "pre-evaluation-run.json"
    pre_evaluation_path = run_dir / "pre-evaluation.json"
    evaluation_path = run_dir / "evaluation.json"
    relation_path = run_dir / "correlation.json"
    if not all(
        path.exists()
        for path in (
            pre_run_path,
            pre_evaluation_path,
            evaluation_path,
            relation_path,
        )
    ):
        raise ReportCorruptionError("evaluation provenance is incomplete")
    preliminary = _load_json_record(
        pre_run_path,
        RunRecord,
        "pre-evaluation run record",
    )
    pre_evaluation = _load_json_record(
        pre_evaluation_path,
        PreEvaluationRecord,
        "pre-evaluation record",
    )
    evaluation = _load_json_record(
        evaluation_path,
        EvaluationRecord,
        "evaluation record",
    )
    relation, correlation_record = _load_mission_relation_record(relation_path)
    try:
        source = validate_source_archive(
            run_dir / "final-source/final-source.tar",
            run_dir / "final-source/final-source-manifest.json",
        )
        if ledger_payload is None:
            ledger_payload = _read_regular_bytes(
                run_dir / "events.jsonl",
                "event ledger",
            )
        if journal_payload is None:
            journal_payload = _read_regular_bytes(
                run_dir / "review.jsonl",
                "review journal",
            )
        event_count = len(load_exchanges_bytes(ledger_payload))
        ledger_digest = hashlib.sha256(ledger_payload).hexdigest()
        journal_digest = hashlib.sha256(journal_payload).hexdigest()
    except (SourceArchiveError, GraphError, OSError, ValueError) as error:
        raise ReportCorruptionError("final provenance artifact is invalid") from error
    allowed_changes = {
        "evaluator_outcome",
        "final_source_archive_digest",
        "pre_evaluation_record_digest",
        "final_source_manifest_digest",
        "final_source_working_tree_digest",
        "evaluator_digest",
        "evaluation_record_digest",
        "evaluator_vm_deleted",
        "record_digest",
    }
    preliminary_value = preliminary.model_dump(mode="json")
    final_value = run.model_dump(mode="json")
    if any(
        preliminary_value[name] != final_value[name]
        for name in preliminary_value
        if name not in allowed_changes
    ):
        raise ReportCorruptionError("final run transform differs")
    if (
        preliminary.run_id != run.run_id
        or preliminary.evaluator_outcome != preliminary.runtime_outcome
        or preliminary.mission_process_stopped is not True
        or pre_evaluation.run_id != run.run_id
        or pre_evaluation.mission_process_stopped is not True
        or pre_evaluation.pre_evaluation_run_record_digest
        != preliminary.record_digest
        or preliminary.final_source_archive_digest is not None
        or preliminary.pre_evaluation_record_digest is not None
        or preliminary.final_source_manifest_digest is not None
        or preliminary.final_source_working_tree_digest is not None
        or preliminary.evaluator_digest is not None
        or preliminary.evaluation_record_digest is not None
        or preliminary.evaluator_vm_deleted is not None
        or run.pre_evaluation_record_digest != pre_evaluation.record_digest
        or run.final_source_manifest_digest != source.manifest_digest
        or run.final_source_working_tree_digest
        != source.manifest.working_tree_digest
        or run.approved_evaluator_digest != pre_evaluation.evaluator_digest
        or run.evaluator_digest != pre_evaluation.evaluator_digest
        or run.evaluation_record_digest != evaluation.record_digest
        or pre_evaluation.event_ledger_digest != ledger_digest
        or pre_evaluation.event_ledger_record_count != event_count
        or pre_evaluation.review_journal_digest != journal_digest
        or pre_evaluation.source_archive_digest != source.archive_digest
        or pre_evaluation.source_manifest_digest != source.manifest_digest
        or pre_evaluation.source_working_tree_digest
        != source.manifest.working_tree_digest
        or run.final_commit != source.manifest.final_commit
        or run.final_source_archive_digest != source.archive_digest
        or evaluation.archive_digest != source.archive_digest
        or evaluation.working_tree_digest
        != source.manifest.working_tree_digest
        or evaluation.model_dump(mode="json") != dict(run.evaluator_outcome)
        or run.mission_process_stopped is not True
        or run.evaluator_vm_deleted is not True
        or (
            run.mission_outcome == "mission-failed"
            and run.runtime_outcome
            not in RELEASE_REPORTABLE_RUNTIME_OUTCOMES
        )
        or relation["source_digest"] != run.mission_relation_source_digest
        or relation["mission_id"] != run.run_id
        or relation["record_digest"] != run.mission_relation_record_digest
    ):
        raise ReportCorruptionError("evaluation provenance binding differs")
    return pre_evaluation, evaluation, correlation_record


def rebuild_report(
    run_dir: Path,
    *,
    baseline_record_path: Path | None = None,
) -> ReportRecord:
    """Replay authoritative JSONL and build one strict in-memory report."""

    if not run_dir.exists():
        raise ReportInputError("unknown run")
    try:
        metadata = run_dir.lstat()
    except OSError as error:
        raise ReportInputError("unknown run") from error
    if run_dir.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ReportCorruptionError("run directory is invalid")
    run_path = run_dir / "run.json"
    if not run_path.exists():
        raise ReportCorruptionError("final run record is missing")
    run = _load_json_record(run_path, RunRecord, "final run record")
    if run.run_id != run_dir.name:
        raise ReportCorruptionError("run directory identity differs")
    ledger_path = run_dir / "events.jsonl"
    journal_path = run_dir / "review.jsonl"
    try:
        ledger_payload = _read_regular_bytes(ledger_path, "event ledger")
        journal_payload = _read_regular_bytes(journal_path, "review journal")
        exchanges = load_exchanges_bytes(ledger_payload)
        review_records = load_journal_records(
            journal_payload,
            run_id=run.run_id,
        )
    except (GraphError, ReviewJournalCorruptionError, ValueError) as error:
        raise ReportCorruptionError("authoritative replay failed") from error
    if any(exchange.envelope.run_id != run.run_id for exchange in exchanges):
        raise ReportCorruptionError("event ledger contains another run")

    baseline: BaselineRunRecord | None = None
    if run.baseline_record_digest is not None:
        if baseline_record_path is None:
            raise ReportInputError("bound baseline record is required")
        try:
            baseline = _load_json_record(
                baseline_record_path,
                BaselineRunRecord,
                "baseline record",
            )
        except ReportCorruptionError as error:
            raise ReportInputError("baseline record is invalid") from error
        if baseline.record_digest != run.baseline_record_digest:
            raise ReportInputError("baseline record binding differs")
        matches, mismatch = validate_baseline_binding(baseline, run)
        if not matches:
            raise ReportInputError(f"baseline comparison binding differs: {mismatch}")
    elif baseline_record_path is not None:
        raise ReportInputError("run is not baseline-bound")
    ledger_digest = hashlib.sha256(ledger_payload).hexdigest()
    journal_digest = hashlib.sha256(journal_payload).hexdigest()
    pre_evaluation, evaluation, correlation_record = validate_finalization_provenance(
        run_dir,
        run,
        ledger_payload=ledger_payload,
        journal_payload=journal_payload,
    )

    try:
        return ReportRecord.model_validate(
            _report_value(
                run=run,
                baseline=baseline,
                pre_evaluation=pre_evaluation,
                evaluation=evaluation,
                exchanges=exchanges,
                review_records=review_records,
                ledger_digest=ledger_digest,
                journal_digest=journal_digest,
                mission_role_inventory_complete=(
                    correlation_record.role_inventory.complete
                ),
            )
        )
    except (ValueError, KeyError, TypeError) as error:
        raise ReportCorruptionError("report reconstruction failed") from error


def render_markdown(report: ReportRecord) -> str:
    """Render Markdown from the rebuilt report record only."""

    def encoded(value: Any) -> str:
        return canonical_json(value).decode("ascii")

    metrics = report.metrics
    lines = [
        f"# Shadow Mission report: `{report.run_id}`",
        "",
        f"Outcome: `{report.outcome}`",
        f"Provenance: `{report.provenance_status}`",
        f"Duration: `{report.duration_seconds}` seconds",
        "",
        "## Outcome metrics",
        "",
        f"- Conflict escapes: `{encoded(metrics.conflict_escape_count.model_dump(mode='json'))}`",
        f"- Shared-assumption escapes: `{encoded(metrics.shared_assumption_escape_count.model_dump(mode='json'))}`",
        "- Validation-overlap escapes: "
        f"`{encoded(metrics.validation_overlap_escape_count.model_dump(mode='json') if metrics.validation_overlap_escape_count is not None else None)}`",
        f"- Intervention precision: `{encoded(metrics.intervention_precision.model_dump(mode='json'))}`",
        f"- False interventions: `{encoded(metrics.false_intervention_count.model_dump(mode='json'))}`",
        f"- Propagation radius: `{encoded(metrics.propagation_radius.model_dump(mode='json'))}`",
        f"- Added usage: `{encoded(metrics.added_usage.model_dump(mode='json'))}`",
        f"- Added cost cents: `{encoded(metrics.added_cost_cents.model_dump(mode='json'))}`",
        f"- Baseline archive: `{metrics.baseline_archive_digest}`",
        f"- Shadow archive: `{metrics.shadow_archive_digest}`",
        "",
        "## Frozen configuration",
        "",
        f"`{encoded(report.frozen_configuration)}`",
        "",
        "## Capability path",
        "",
        f"`{encoded(report.capabilities)}`",
        "",
        "## Mission topology",
        "",
        f"- Sessions: `{encoded(report.sessions)}`",
        f"- Roles: `{encoded(report.roles)}`",
        "",
        "## Review evidence",
        "",
        f"- Detections: `{encoded(report.detections)}`",
        f"- Claims: `{encoded(report.claims)}`",
        f"- Evidence: `{encoded(report.evidence)}`",
        f"- Probes: `{encoded(report.probes)}`",
        f"- Interventions: `{encoded(report.interventions)}`",
        "",
        "## Repository outcome",
        "",
        f"- Changed files: `{encoded(report.changed_files)}`",
        f"- Commits: `{encoded(report.commits)}`",
        f"- Final source: `{encoded(report.final_source)}`",
        f"- Evaluator: `{encoded(report.evaluator)}`",
        "",
        "## Baseline and cost",
        "",
        f"- Baseline linkage: `{encoded(report.baseline_linkage)}`",
        f"- Usage: `{encoded(report.usage)}`",
        f"- Budget ledger: `{encoded(report.budget_ledger)}`",
        "",
        "## Provenance",
        "",
        f"- Ledger records: `{report.ledger_record_count}` (`{report.ledger_digest}`)",
        f"- Review records: `{report.review_record_count}` (`{report.review_journal_digest}`)",
        "",
        "## Unresolved risks",
        "",
    ]
    lines.extend(f"- `{risk}`" for risk in report.unresolved_risks)
    if not report.unresolved_risks:
        lines.append("- None")
    lines.extend(
        [
            "",
            "## Unavailable fields",
            "",
        ]
    )
    lines.extend(f"- `{field}`" for field in report.unavailable_fields)
    if not report.unavailable_fields:
        lines.append("- None")
    lines.extend(["", f"Record digest: `{report.record_digest}`", ""])
    return "\n".join(lines)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_report_outputs(report: ReportRecord, run_dir: Path) -> tuple[Path, Path]:
    """Publish JSON and Markdown from one in-memory record or publish neither."""

    json_path = run_dir / "report.json"
    markdown_path = run_dir / "report.md"
    final_paths = (json_path, markdown_path)
    staged: list[Path] = []
    payloads = (
        canonical_json(report.model_dump(mode="json")) + b"\n",
        render_markdown(report).encode("utf-8"),
    )
    try:
        for final_path, payload in zip(final_paths, payloads, strict=True):
            temporary = run_dir / f".{final_path.name}.{secrets.token_hex(8)}.tmp"
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            staged.append(temporary)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
    except OSError as error:
        for path in staged:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise ReportWriteError("report output publication failed") from error

    backups: dict[Path, Path] = {}
    published: list[Path] = []
    try:
        for final_path in final_paths:
            backup = run_dir / f".{final_path.name}.{secrets.token_hex(8)}.bak"
            try:
                os.link(final_path, backup, follow_symlinks=False)
            except FileNotFoundError:
                continue
            backups[final_path] = backup
        for temporary, final_path in zip(staged, final_paths, strict=True):
            os.replace(temporary, final_path)
            published.append(final_path)
    except OSError as error:
        rollback_failed = False
        for final_path in reversed(published):
            backup = backups.get(final_path)
            try:
                if backup is None:
                    final_path.unlink(missing_ok=True)
                else:
                    os.replace(backup, final_path)
                    backups.pop(final_path)
            except OSError:
                rollback_failed = True
        for path in staged:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        if not rollback_failed:
            for path in backups.values():
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
        try:
            _fsync_directory(run_dir)
        except OSError:
            pass
        raise ReportWriteError("report output publication failed") from error

    for path in backups.values():
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    try:
        _fsync_directory(run_dir)
    except OSError as error:
        raise ReportWriteError("report output publication failed") from error
    return json_path, markdown_path
