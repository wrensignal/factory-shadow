#!/usr/bin/env python3
"""Build one aggregate record from frozen pair artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from shadow_mission.evaluation import EvaluationRecord
from shadow_mission.metrics import validate_baseline_binding
from shadow_mission.protocol import (
    BaselineRunRecord,
    PreEvaluationRecord,
    RunRecord,
    canonical_json,
)
from shadow_mission.review_journal import (
    ExtractionOutcomeRecord,
    InterventionLineageRecord,
    MAX_JOURNAL_BYTES,
    OutageReconciliationRecord,
    ReviewJournalCorruptionError,
    load_journal_records,
)
from shadow_mission.router import InterventionRouterState
from shadow_mission.status import intervention_state


class SummaryError(RuntimeError):
    pass


_PAIR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PINNED_ASSERTION_IDS = frozenset(
    {
        "api_amount_unit_is_integer_cents",
        "api_preserves_integer_cents",
        "database_column_is_amount_cents",
        "ten_dollars_crosses_all_boundaries_as_1000_cents",
    }
)


@dataclass(frozen=True)
class PairOutcomeArtifacts:
    pair_id: str
    comparison_record: Path
    baseline_record: Path
    shadow_run_record: Path
    pre_evaluation_record: Path
    review_journal: Path


@dataclass(frozen=True)
class IncompletePair:
    pair_id: str
    reason: str
    consumed_authorizations: int


def _read_regular(
    path: Path,
    description: str,
    *,
    limit: int | None = None,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SummaryError(f"{description} is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SummaryError(f"{description} is not a regular file")
        if limit is not None and metadata.st_size > limit:
            raise SummaryError(f"{description} exceeds its size bound")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(
            descriptor,
            min(1 << 20, limit + 1 - size) if limit is not None else 1 << 20,
        ):
            chunks.append(chunk)
            size += len(chunk)
            if limit is not None and size > limit:
                raise SummaryError(f"{description} exceeds its size bound")
        return b"".join(chunks)
    except OSError as error:
        raise SummaryError(f"{description} is unreadable") from error
    finally:
        os.close(descriptor)


def _load_canonical_object(path: Path, description: str) -> dict[str, Any]:
    try:
        payload = _read_regular(path, description)
        value = json.loads(payload)
    except SummaryError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SummaryError(f"{description} is invalid") from error
    if not isinstance(value, dict) or canonical_json(value) + b"\n" != payload:
        raise SummaryError(f"{description} is not canonical")
    return value


def _load_model(path: Path, model_type, description: str):
    value = _load_canonical_object(path, description)
    try:
        return model_type.model_validate(value)
    except ValueError as error:
        raise SummaryError(f"{description} is invalid") from error


def _validate_comparison(
    value: Mapping[str, Any],
    *,
    baseline: BaselineRunRecord,
    shadow: RunRecord,
) -> str:
    supplied = value.get("record_digest")
    material = dict(value)
    material.pop("record_digest", None)
    if (
        not isinstance(supplied, str)
        or supplied != hashlib.sha256(canonical_json(material)).hexdigest()
    ):
        raise SummaryError("comparison record digest differs")
    if value.get("baseline_record_digest") != baseline.record_digest:
        raise SummaryError("comparison baseline binding differs")
    if value.get("shadow_run_record_digest") != shadow.record_digest:
        raise SummaryError("comparison Shadow binding differs")
    status_value = value.get("status")
    if status_value not in {"pass", "refused"}:
        raise SummaryError("comparison status is invalid")
    refusal_reason = value.get("refusal_reason")
    if status_value == "pass":
        if "refusal_reason" in value:
            raise SummaryError("passing comparison contains a refusal")
    elif (
        not isinstance(refusal_reason, str)
        or not refusal_reason
        or refusal_reason.strip() != refusal_reason
        or "causal_chain" in value
    ):
        raise SummaryError("refused comparison state is invalid")
    return status_value


def _evaluation(record: BaselineRunRecord | RunRecord, side: str) -> EvaluationRecord:
    if not isinstance(record.evaluator_outcome, Mapping):
        raise SummaryError(f"{side} evaluator result is unavailable")
    try:
        return EvaluationRecord.model_validate(record.evaluator_outcome)
    except ValueError as error:
        raise SummaryError(f"{side} evaluator result is invalid") from error


def _failed_assertions(evaluation: EvaluationRecord) -> list[str]:
    return [
        assertion.assertion_id
        for assertion in evaluation.assertions
        if assertion.status == "fail"
    ]


def _duration(record: BaselineRunRecord | RunRecord, side: str) -> float:
    value = record.duration_seconds
    if value is None:
        raise SummaryError(f"{side} duration is unavailable")
    return value


def _usage_field(usage: Mapping[str, Any], field_name: str) -> dict[str, Any]:
    status_value = usage.get("status")
    if status_value == "unavailable":
        return {"status": "unavailable", "value": None}
    if status_value != "available":
        raise SummaryError("usage status is invalid")
    value = usage.get(field_name)
    if type(value) is not int or value < 0:
        raise SummaryError(f"usage {field_name} is invalid")
    return {"status": "available", "value": value}


def _review_counts(
    payload: bytes,
    *,
    run_id: str,
) -> tuple[dict[str, int], dict[str, int]]:
    try:
        records = load_journal_records(payload, run_id=run_id)
    except (ReviewJournalCorruptionError, ValueError) as error:
        raise SummaryError("review journal is invalid") from error

    state = InterventionRouterState.empty(run_id)
    extraction_counts: Counter[str] = Counter()
    for record in records:
        if isinstance(record, ExtractionOutcomeRecord):
            extraction_counts[record.status] += 1
        elif isinstance(record, (InterventionLineageRecord, OutageReconciliationRecord)):
            try:
                state = record.delta.apply(state)
            except ValueError as error:
                raise SummaryError("review intervention lineage is invalid") from error

    interventions = state.interventions
    projection = intervention_state(interventions)
    by_state = projection["by_state"]
    final_counts = {
        "created": len(interventions),
        "delivered": int(by_state.get("delivered", 0)),
        "acknowledged": int(by_state.get("acknowledged", 0)),
        "corrected": int(by_state.get("corrected", 0)),
        "resolved": int(by_state.get("resolved", 0)),
        "unresolved": int(projection["unresolved"]),
    }
    activity_counts = {
        "accepted_extractions": extraction_counts["accepted"],
        "quarantined_extractions": extraction_counts["quarantined"],
        "failed_extractions": extraction_counts["failed"],
        "interventions_created": len(interventions),
        "interventions_delivered": sum(
            any(item.state == "delivered" for item in intervention.transition_history)
            for intervention in interventions
        ),
        "interventions_resolved": sum(
            any(item.state == "resolved" for item in intervention.transition_history)
            for intervention in interventions
        ),
    }
    return final_counts, activity_counts


def _validate_pair_id(pair_id: str) -> None:
    if not isinstance(pair_id, str) or not _PAIR_ID.fullmatch(pair_id):
        raise SummaryError("pair id is invalid")


def _pair_summary(outcome: PairOutcomeArtifacts) -> dict[str, Any]:
    _validate_pair_id(outcome.pair_id)
    baseline = _load_model(
        outcome.baseline_record,
        BaselineRunRecord,
        "baseline record",
    )
    shadow = _load_model(outcome.shadow_run_record, RunRecord, "Shadow run record")
    if (
        shadow.baseline_id != baseline.baseline_id
        or shadow.baseline_record_digest != baseline.record_digest
    ):
        raise SummaryError("pair baseline binding differs")
    matches, mismatch = validate_baseline_binding(baseline, shadow)
    if not matches:
        raise SummaryError(f"pair comparison binding differs: {mismatch}")
    pre_evaluation = _load_model(
        outcome.pre_evaluation_record,
        PreEvaluationRecord,
        "pre-evaluation record",
    )
    review_payload = _read_regular(
        outcome.review_journal,
        "review journal",
        limit=MAX_JOURNAL_BYTES,
    )
    if (
        shadow.pre_evaluation_record_digest != pre_evaluation.record_digest
        or pre_evaluation.run_id != shadow.run_id
        or pre_evaluation.review_journal_digest
        != hashlib.sha256(review_payload).hexdigest()
    ):
        raise SummaryError("review journal binding differs")
    comparison = _load_canonical_object(
        outcome.comparison_record,
        "comparison record",
    )
    comparison_status = _validate_comparison(
        comparison,
        baseline=baseline,
        shadow=shadow,
    )
    baseline_evaluation = _evaluation(baseline, "baseline")
    shadow_evaluation = _evaluation(shadow, "Shadow")
    if comparison_status == "pass" and (
        baseline_evaluation.status != "fail"
        or shadow_evaluation.status != "pass"
    ):
        raise SummaryError("comparison status differs from evaluator results")
    baseline_duration = _duration(baseline, "baseline")
    shadow_duration = _duration(shadow, "Shadow")
    interventions, activity_counts = _review_counts(
        review_payload,
        run_id=shadow.run_id,
    )
    return {
        "pair_id": outcome.pair_id,
        "comparison_status": comparison_status,
        "baseline_evaluator_status": baseline_evaluation.status,
        "shadow_evaluator_status": shadow_evaluation.status,
        "baseline_failed_assertion_ids": _failed_assertions(baseline_evaluation),
        "shadow_failed_assertion_ids": _failed_assertions(shadow_evaluation),
        "intervention_counts": interventions,
        "baseline_duration_seconds": baseline_duration,
        "shadow_duration_seconds": shadow_duration,
        "duration_difference_seconds": shadow_duration - baseline_duration,
        "review_activity_counts": activity_counts,
        "token_counts": {
            "baseline": _usage_field(baseline.usage_data, "total_tokens"),
            "shadow": _usage_field(shadow.usage_data, "total_tokens"),
        },
        "cost_cents": {
            "baseline": _usage_field(baseline.usage_data, "cost_cents"),
            "shadow": _usage_field(shadow.usage_data, "cost_cents"),
        },
    }


def summarize_baseline_corpus(corpus: Path) -> dict[str, Any]:
    try:
        metadata = corpus.lstat()
    except OSError as error:
        raise SummaryError("baseline corpus is unavailable") from error
    if corpus.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise SummaryError("baseline corpus is invalid")
    paths = tuple(
        sorted(
            path
            for path in corpus.iterdir()
            if path.is_file()
            and not path.is_symlink()
            and path.name.startswith("baseline-")
            and path.suffix == ".json"
        )
    )
    if not paths:
        raise SummaryError("baseline corpus has no records")

    identifiers: set[str] = set()
    digests: set[str] = set()
    reference: BaselineRunRecord | None = None
    passed_records = 0
    signatures: Counter[tuple[str, ...]] = Counter()
    for path in paths:
        record = _load_model(path, BaselineRunRecord, "baseline corpus record")
        if record.baseline_id in identifiers or record.record_digest in digests:
            raise SummaryError("baseline corpus repeats a record")
        identifiers.add(record.baseline_id)
        digests.add(record.record_digest)
        if reference is None:
            reference = record
        else:
            matches, mismatch = validate_baseline_binding(reference, record)
            if not matches:
                raise SummaryError(f"baseline corpus binding differs: {mismatch}")
        evaluation = _evaluation(record, "baseline corpus")
        if frozenset(item.assertion_id for item in evaluation.assertions) != (
            _PINNED_ASSERTION_IDS
        ):
            raise SummaryError(
                "baseline corpus assertion IDs differ from the pinned evaluator"
            )
        failures = tuple(_failed_assertions(evaluation))
        if evaluation.status == "pass":
            passed_records += 1
        else:
            signatures[failures] += 1

    failed_records = len(paths) - passed_records
    assert reference is not None
    return {
        "mission_digest": reference.mission_digest,
        "initial_commit": reference.initial_commit,
        "total_records": len(paths),
        "failed_records": failed_records,
        "passed_records": passed_records,
        "failure_signatures": [
            {
                "failed_assertion_ids": list(signature),
                "record_count": count,
            }
            for signature, count in sorted(signatures.items())
        ],
    }


def _validate_incomplete_pair(value: IncompletePair) -> None:
    _validate_pair_id(value.pair_id)
    if (
        not isinstance(value.reason, str)
        or not value.reason
        or value.reason.strip() != value.reason
        or len(value.reason) > 512
        or type(value.consumed_authorizations) is not int
        or value.consumed_authorizations < 0
    ):
        raise SummaryError("incomplete pair record is invalid")


def build_summary(
    *,
    pre_registered_pair_ids: Sequence[str],
    outcomes: Sequence[PairOutcomeArtifacts],
    baseline_corpus: Path,
    incomplete_pairs: Sequence[IncompletePair] = (),
) -> dict[str, Any]:
    pair_ids = tuple(pre_registered_pair_ids)
    for pair_id in pair_ids:
        _validate_pair_id(pair_id)
    if len(pair_ids) != len(set(pair_ids)):
        raise SummaryError("pre-registered pair ids are not unique")

    outcomes_by_id: dict[str, PairOutcomeArtifacts] = {}
    for outcome in outcomes:
        _validate_pair_id(outcome.pair_id)
        if outcome.pair_id in outcomes_by_id:
            raise SummaryError("pair has more than one outcome record")
        outcomes_by_id[outcome.pair_id] = outcome

    incomplete_by_id: dict[str, IncompletePair] = {}
    for incomplete in incomplete_pairs:
        _validate_incomplete_pair(incomplete)
        if incomplete.pair_id in incomplete_by_id:
            raise SummaryError("pair has more than one incomplete record")
        incomplete_by_id[incomplete.pair_id] = incomplete
    if set(outcomes_by_id) & set(incomplete_by_id):
        raise SummaryError("pair cannot be complete and incomplete")
    declared_ids = set(outcomes_by_id) | set(incomplete_by_id)
    missing = [pair_id for pair_id in pair_ids if pair_id not in declared_ids]
    if missing:
        raise SummaryError("pre-registered pair has no outcome record")
    if declared_ids != set(pair_ids):
        raise SummaryError("outcome record is not pre-registered")

    pairs: list[dict[str, Any]] = []
    for pair_id in pair_ids:
        outcome = outcomes_by_id.get(pair_id)
        if outcome is not None:
            pairs.append(
                {
                    "completion_status": "complete",
                    **_pair_summary(outcome),
                }
            )
            continue
        incomplete = incomplete_by_id[pair_id]
        pairs.append(
            {
                "pair_id": pair_id,
                "completion_status": "incomplete",
                "reason": incomplete.reason,
                "consumed_authorizations": incomplete.consumed_authorizations,
            }
        )

    value: dict[str, Any] = {
        "schema_version": "0.1",
        "pair_ids": list(pair_ids),
        "pair_counts": {
            "pre_registered": len(pair_ids),
            "complete": len(outcomes_by_id),
            "incomplete": len(incomplete_by_id),
        },
        "pairs": pairs,
        "baseline_corpus": summarize_baseline_corpus(baseline_corpus),
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def _load_outcome_spec(path: Path) -> PairOutcomeArtifacts:
    value = _load_canonical_object(path, "pair outcome index")
    required = {
        "pair_id",
        "comparison_record",
        "baseline_record",
        "shadow_run_record",
        "pre_evaluation_record",
        "review_journal",
    }
    if set(value) != required or not all(
        isinstance(value[name], str) for name in required
    ):
        raise SummaryError("pair outcome index is invalid")
    root = path.parent

    def resolved(name: str) -> Path:
        candidate = Path(value[name])
        return candidate if candidate.is_absolute() else root / candidate

    return PairOutcomeArtifacts(
        pair_id=value["pair_id"],
        comparison_record=resolved("comparison_record"),
        baseline_record=resolved("baseline_record"),
        shadow_run_record=resolved("shadow_run_record"),
        pre_evaluation_record=resolved("pre_evaluation_record"),
        review_journal=resolved("review_journal"),
    )


def _load_incomplete_spec(path: Path) -> IncompletePair:
    value = _load_canonical_object(path, "incomplete pair index")
    if (
        set(value)
        != {
            "pair_id",
            "completion_status",
            "reason",
            "consumed_authorizations",
        }
        or value.get("completion_status") != "incomplete"
    ):
        raise SummaryError("incomplete pair index is invalid")
    result = IncompletePair(
        pair_id=value.get("pair_id"),
        reason=value.get("reason"),
        consumed_authorizations=value.get("consumed_authorizations"),
    )
    _validate_incomplete_pair(result)
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--baseline-corpus", type=Path, required=True)
    value.add_argument("--pair-id", action="append", default=[])
    value.add_argument("--outcome-record", type=Path, action="append", default=[])
    value.add_argument("--incomplete-record", type=Path, action="append", default=[])
    value.add_argument("--output", type=Path)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        outcomes = tuple(_load_outcome_spec(path) for path in arguments.outcome_record)
        incomplete_pairs = tuple(
            _load_incomplete_spec(path) for path in arguments.incomplete_record
        )
        summary = build_summary(
            pre_registered_pair_ids=tuple(arguments.pair_id),
            outcomes=outcomes,
            baseline_corpus=arguments.baseline_corpus,
            incomplete_pairs=incomplete_pairs,
        )
        payload = canonical_json(summary) + b"\n"
        if arguments.output is None:
            print(payload.decode("ascii"), end="")
        else:
            arguments.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(
                arguments.output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
    except (SummaryError, OSError, ValueError) as error:
        print(f"summary failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
