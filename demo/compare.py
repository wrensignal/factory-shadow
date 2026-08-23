#!/usr/bin/env python3
"""Compare bound baseline and Shadow outcomes from one pinned evaluator."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

from shadow_mission.metrics import validate_baseline_binding
from shadow_mission.protocol import (
    BaselineRunRecord,
    EvidenceRecord,
    InterventionRecord,
    RunRecord,
    canonical_json,
)
from shadow_mission.reporting import (
    ReportError,
    ReportRecord,
    finding_closed,
    rebuild_report,
)
from shadow_mission.review_journal import JournalFinding
from shadow_mission.source_export import SourceArchiveError, validate_source_archive


class ComparisonError(RuntimeError):
    pass


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_ASSERTION_IDS = frozenset(
    {
        "api_amount_unit_is_integer_cents",
        "api_preserves_integer_cents",
        "database_column_is_amount_cents",
        "ten_dollars_crosses_all_boundaries_as_1000_cents",
    }
)
_SEEDED_CONFLICT_ASSERTION = "ten_dollars_crosses_all_boundaries_as_1000_cents"
_SEEDED_FINDING_LOCATORS = ("docs/stale-guide.md",)
_SEEDED_FINDING_PROPERTIES = ("unit",)
_SEEDED_FINDING_VALUES = (
    canonical_json({"type": "string", "value": "cents"}).decode("ascii"),
    canonical_json({"type": "string", "value": "dollars"}).decode("ascii"),
)
_CORRECTION_EVIDENCE_SOURCES = frozenset(
    {"target_diff_transcript", "target_test_transcript"}
)


def _require_external_absolute(path: Path) -> Path:
    if not path.is_absolute():
        raise ComparisonError("comparison output path must be absolute")
    resolved = path.resolve(strict=False)
    if (
        resolved == _PROJECT_ROOT
        or _PROJECT_ROOT in resolved.parents
        or resolved in _PROJECT_ROOT.parents
    ):
        raise ComparisonError("comparison output must remain outside the project")
    return resolved


def _load_record(path: Path, model: type[BaselineRunRecord] | type[RunRecord]) -> Any:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
        value = json.loads(payload)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or not isinstance(value, Mapping)
            or canonical_json(value) + b"\n" != payload
        ):
            raise ComparisonError(f"{path.name} is not canonical")
        return model.model_validate(value)
    except ComparisonError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ComparisonError(f"{path.name} is invalid") from error


def _evaluation_status(record: BaselineRunRecord | RunRecord) -> str:
    if not isinstance(record.evaluator_outcome, Mapping):
        raise ComparisonError("evaluation outcome is unavailable")
    status = record.evaluator_outcome.get("status")
    if status not in {"pass", "fail"}:
        raise ComparisonError("evaluation outcome status is invalid")
    return str(status)


def _assertion_results(record: BaselineRunRecord | RunRecord) -> dict[str, bool]:
    if not isinstance(record.evaluator_outcome, Mapping):
        raise ComparisonError("evaluation outcome is unavailable")
    assertions = record.evaluator_outcome.get("assertions")
    if not isinstance(assertions, list):
        raise ComparisonError("evaluation assertions are unavailable")
    results: dict[str, bool] = {}
    for assertion in assertions:
        if (
            not isinstance(assertion, Mapping)
            or not isinstance(assertion.get("assertion_id"), str)
            or assertion.get("status") not in {"pass", "fail"}
            or assertion["assertion_id"] in results
        ):
            raise ComparisonError("evaluation assertion is invalid")
        results[str(assertion["assertion_id"])] = assertion["status"] == "pass"
    if not results:
        raise ComparisonError("evaluation assertions are unavailable")
    return dict(sorted(results.items()))


def _failed_assertions(record: BaselineRunRecord | RunRecord) -> int:
    return sum(not passed for passed in _assertion_results(record).values())


def _seeded_findings(
    report: ReportRecord,
) -> tuple[tuple[JournalFinding, ...], bool]:
    matches: dict[str, JournalFinding] = {}
    all_detections_resolved = True
    for detection in report.detections:
        if not isinstance(detection, Mapping):
            raise ComparisonError("report detection is invalid")
        try:
            finding = JournalFinding.model_validate(detection.get("finding"))
        except (TypeError, ValueError) as error:
            raise ComparisonError("report detection is invalid") from error
        if (
            finding.rule == "cross_worker_conflict"
            and finding.normalized_locators == _SEEDED_FINDING_LOCATORS
            and finding.normalized_properties == _SEEDED_FINDING_PROPERTIES
            and finding.normalized_values == _SEEDED_FINDING_VALUES
        ):
            matches.setdefault(finding.dedup_key, finding)
            if detection.get("completion_state") != "resolved":
                all_detections_resolved = False
    if not matches:
        raise ComparisonError("report does not contain the seeded conflict detection")
    return (
        tuple(matches[key] for key in sorted(matches)),
        all_detections_resolved,
    )


def _report_interventions(report: ReportRecord) -> tuple[InterventionRecord, ...]:
    interventions: list[InterventionRecord] = []
    intervention_ids: set[str] = set()
    for value in report.interventions:
        try:
            intervention = InterventionRecord.model_validate(value)
        except (TypeError, ValueError) as error:
            raise ComparisonError("report intervention is invalid") from error
        if intervention.intervention_id in intervention_ids:
            raise ComparisonError("report intervention identities are not unique")
        intervention_ids.add(intervention.intervention_id)
        interventions.append(intervention)
    return tuple(interventions)


def _report_evidence(report: ReportRecord) -> dict[str, EvidenceRecord]:
    evidence: dict[str, EvidenceRecord] = {}
    for value in report.evidence:
        try:
            record = EvidenceRecord.model_validate(value)
        except (TypeError, ValueError) as error:
            raise ComparisonError("report evidence is invalid") from error
        if record.evidence_id in evidence:
            raise ComparisonError("report evidence identities are not unique")
        evidence[record.evidence_id] = record
    return evidence


def _has_seeded_repair_chain(
    intervention: InterventionRecord,
    evidence: Mapping[str, EvidenceRecord],
) -> bool:
    if (
        intervention.state != "resolved"
        or intervention.transition_history[-1].state != "resolved"
        or intervention.transition_history[-1].action != "resolved"
    ):
        return False
    stage = 0
    for transition in intervention.transition_history:
        if stage == 0 and (
            transition.state == "delivered" and transition.action == "delivered"
        ):
            stage = 1
        elif stage == 1 and (
            transition.state == "corrected" and transition.action == "corrected"
        ):
            stage = 2
        elif stage == 2 and (
            transition.state == "resolved" and transition.action == "resolved"
        ):
            stage = 3
    if stage != 3:
        return False
    correction_sources: set[str] = set()
    for evidence_id in intervention.correction_evidence_ids:
        record = evidence.get(evidence_id)
        if (
            record is None
            or record.intervention_id != intervention.intervention_id
            or record.kind != "target_correction"
        ):
            return False
        correction_sources.add(record.source)
    return _CORRECTION_EVIDENCE_SOURCES <= correction_sources


def _seeded_repair_evidence(
    report: ReportRecord,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    findings, all_detections_resolved = _seeded_findings(report)
    finding_keys = tuple(finding.dedup_key for finding in findings)
    interventions = _report_interventions(report)
    closed_finding_keys = tuple(
        finding.dedup_key
        for finding in findings
        if finding_closed(
            finding.dedup_key,
            interventions,
            finding.target_sessions,
        )
    )
    closed_finding_key_set = frozenset(closed_finding_keys)
    closed_interventions = tuple(
        intervention
        for intervention in interventions
        if intervention.finding_dedup_key in closed_finding_key_set
    )
    closed_intervention_ids = tuple(
        sorted(item.intervention_id for item in closed_interventions)
    )

    def chain_error(message: str) -> ComparisonError:
        return ComparisonError(message)

    if not all_detections_resolved or not closed_finding_keys:
        raise chain_error(
            "seeded conflict intervention group is not fully resolved"
        )
    intervention_groups: dict[str, list[InterventionRecord]] = {
        key: [] for key in closed_finding_keys
    }
    for intervention in closed_interventions:
        intervention_groups[intervention.finding_dedup_key].append(intervention)
    try:
        evidence = _report_evidence(report)
    except ComparisonError as error:
        raise chain_error(str(error)) from error
    if not any(
        all(
            _has_seeded_repair_chain(intervention, evidence)
            for intervention in intervention_groups[finding_key]
        )
        for finding_key in closed_finding_keys
    ):
        raise chain_error(
            "seeded conflict lacks delivered source-and-test repair evidence"
        )
    if any(key in report.unresolved_risks for key in finding_keys):
        raise chain_error("seeded conflict remains in unresolved risks")
    return closed_finding_keys, closed_intervention_ids


def _causal_chain_value(
    finding_keys: Sequence[str],
    intervention_ids: Sequence[str],
) -> dict[str, list[str]]:
    return {
        "seeded_finding_dedup_keys": list(finding_keys),
        "matched_intervention_ids": list(intervention_ids),
    }


def _passing_comparison_value(
    *,
    baseline: BaselineRunRecord,
    shadow: RunRecord,
    report: ReportRecord,
    baseline_archive: Path,
    baseline_manifest: Path,
    shadow_archive: Path,
    shadow_manifest: Path,
) -> dict[str, Any]:
    if (
        shadow.baseline_id != baseline.baseline_id
        or shadow.baseline_record_digest != baseline.record_digest
    ):
        raise ComparisonError("Shadow baseline record binding differs")
    if (
        baseline.mission_outcome != "mission-complete"
        or baseline.usage_data.get("failure_classification") is not None
    ):
        raise ComparisonError("baseline completion state is invalid")
    if shadow.runtime_outcome != "mission-terminated":
        raise ComparisonError("Shadow completion state is invalid")
    if (
        shadow.mission_relation_record_digest is None
        or report.frozen_configuration.get("mission_relation_record_digest")
        != shadow.mission_relation_record_digest
    ):
        raise ComparisonError("Shadow Mission relation binding differs")
    matches, mismatch = validate_baseline_binding(baseline, shadow)
    if not matches:
        raise ComparisonError(f"baseline binding differs: {mismatch}")
    if report.baseline_linkage.get("baseline_record_digest") != baseline.record_digest:
        raise ComparisonError("report baseline binding differs")
    baseline_source = validate_source_archive(baseline_archive, baseline_manifest)
    shadow_source = validate_source_archive(shadow_archive, shadow_manifest)
    if (
        baseline.final_source_archive_digest != baseline_source.archive_digest
        or shadow.final_source_archive_digest != shadow_source.archive_digest
    ):
        raise ComparisonError("source archive record binding differs")
    for name, record, source in (
        ("baseline", baseline, baseline_source),
        ("Shadow", shadow, shadow_source),
    ):
        if not isinstance(record.evaluator_outcome, Mapping):
            raise ComparisonError(f"{name} evaluation outcome is unavailable")
        if (
            record.evaluator_outcome.get("archive_digest") != source.archive_digest
            or record.evaluator_outcome.get("working_tree_digest")
            != source.manifest.working_tree_digest
        ):
            raise ComparisonError(f"{name} evaluation source binding differs")

    baseline_status = _evaluation_status(baseline)
    shadow_status = _evaluation_status(shadow)
    baseline_failures = _failed_assertions(baseline)
    shadow_failures = _failed_assertions(shadow)
    if baseline_status != "fail" or baseline_failures == 0:
        raise ComparisonError("baseline did not expose the seeded defect")
    if shadow_status != "pass" or shadow_failures != 0:
        raise ComparisonError("Shadow did not repair the seeded defect")

    baseline_oracle = _assertion_results(baseline)
    shadow_oracle = _assertion_results(shadow)
    if (
        frozenset(baseline_oracle) != _ASSERTION_IDS
        or frozenset(shadow_oracle) != _ASSERTION_IDS
    ):
        raise ComparisonError("evaluation assertion IDs differ from the pinned evaluator")
    if baseline_oracle[_SEEDED_CONFLICT_ASSERTION]:
        raise ComparisonError("baseline did not expose the seeded cross-feature conflict")
    if all(baseline_oracle.values()):
        raise ComparisonError("baseline unexpectedly passed the source oracle")
    expected_baseline_oracle = {
        assertion_id: assertion_id != _SEEDED_CONFLICT_ASSERTION
        for assertion_id in sorted(_ASSERTION_IDS)
    }
    if baseline_oracle != expected_baseline_oracle:
        raise ComparisonError(
            "baseline failed assertions beyond the seeded cross-feature conflict"
        )
    if not all(shadow_oracle.values()):
        failed = [name for name, passed in shadow_oracle.items() if not passed]
        raise ComparisonError(f"Shadow source oracle failed: {', '.join(failed)}")
    seeded_finding_keys, intervention_ids = _seeded_repair_evidence(report)

    value: dict[str, Any] = {
        "schema_version": "0.1",
        "status": "pass",
        "baseline_record_digest": baseline.record_digest,
        "shadow_run_record_digest": shadow.record_digest,
        "shadow_report_digest": report.record_digest,
        "seed_commit": baseline.initial_commit,
        "causal_chain": _causal_chain_value(
            seeded_finding_keys,
            intervention_ids,
        ),
        "evaluation": {
            "baseline_status": baseline_status,
            "shadow_status": shadow_status,
            "baseline_failed_assertions": baseline_failures,
            "shadow_failed_assertions": shadow_failures,
        },
        "source_oracle": {
            "baseline": baseline_oracle,
            "shadow": shadow_oracle,
        },
        "metrics": report.metrics.model_dump(mode="json"),
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def _refusal_reason(error: BaseException) -> str:
    if isinstance(error, ComparisonError):
        return str(error)
    if isinstance(error, ReportError):
        return "Shadow report evidence is invalid"
    if isinstance(error, SourceArchiveError):
        return "source archive evidence is invalid"
    if isinstance(error, OSError):
        return "comparison evidence could not be read"
    return "comparison evidence is invalid"


def _refused_comparison_value(
    baseline: BaselineRunRecord,
    shadow: RunRecord,
    *,
    reason: str,
    shadow_report_digest: str | None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "0.1",
        "status": "refused",
        "refusal_reason": reason,
        "baseline_record_digest": baseline.record_digest,
        "shadow_run_record_digest": shadow.record_digest,
        "shadow_report_digest": shadow_report_digest,
        "seed_commit": baseline.initial_commit,
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def _write_comparison(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_json(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def compare(
    *,
    baseline_record_path: Path,
    shadow_run_dir: Path,
    baseline_archive: Path,
    baseline_manifest: Path,
    shadow_archive: Path,
    shadow_manifest: Path,
    output_path: Path,
) -> dict[str, Any]:
    output_path = _require_external_absolute(output_path)
    if output_path.exists():
        raise ComparisonError("comparison output already exists")
    baseline = _load_record(baseline_record_path, BaselineRunRecord)
    shadow = _load_record(shadow_run_dir / "run.json", RunRecord)
    report: ReportRecord | None = None
    try:
        report = rebuild_report(
            shadow_run_dir,
            baseline_record_path=baseline_record_path,
        )
        value = _passing_comparison_value(
            baseline=baseline,
            shadow=shadow,
            report=report,
            baseline_archive=baseline_archive,
            baseline_manifest=baseline_manifest,
            shadow_archive=shadow_archive,
            shadow_manifest=shadow_manifest,
        )
    except (
        ComparisonError,
        ReportError,
        SourceArchiveError,
        OSError,
        ValueError,
    ) as error:
        value = _refused_comparison_value(
            baseline,
            shadow,
            reason=_refusal_reason(error),
            shadow_report_digest=(
                report.record_digest if report is not None else None
            ),
        )
    _write_comparison(output_path, value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--baseline-record", type=Path, required=True)
    value.add_argument("--shadow-run-dir", type=Path, required=True)
    value.add_argument("--baseline-archive", type=Path, required=True)
    value.add_argument("--baseline-manifest", type=Path, required=True)
    value.add_argument("--shadow-archive", type=Path, required=True)
    value.add_argument("--shadow-manifest", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        value = compare(
            baseline_record_path=arguments.baseline_record,
            shadow_run_dir=arguments.shadow_run_dir,
            baseline_archive=arguments.baseline_archive,
            baseline_manifest=arguments.baseline_manifest,
            shadow_archive=arguments.shadow_archive,
            shadow_manifest=arguments.shadow_manifest,
            output_path=arguments.output,
        )
    except (ComparisonError, ReportError, SourceArchiveError, OSError, ValueError) as error:
        print(f"comparison failed: {error}")
        return 1
    if value["status"] != "pass":
        print(f"comparison failed: {value['refusal_reason']}")
        return 1
    print(canonical_json(value).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
