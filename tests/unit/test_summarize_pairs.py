from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from demo.summarize_pairs import (
    IncompletePair,
    PairOutcomeArtifacts,
    SummaryError,
    build_summary,
    summarize_baseline_corpus,
)
from shadow_mission.evaluation import EvaluationRecord
from shadow_mission.protocol import (
    BaselineRunRecord,
    PreEvaluationRecord,
    RunRecord,
    canonical_json,
)
from shadow_mission.review_journal import ReviewJournal
from tests.unit.test_reporting import append_mixed_finding, final_run


SEEDED_ASSERTION = "ten_dollars_crosses_all_boundaries_as_1000_cents"


def _with_digest(value: dict[str, object]) -> dict[str, object]:
    material = dict(value)
    material.pop("record_digest", None)
    material["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    return material


def _evaluation(*, archive_digest: str, passed: bool) -> dict[str, object]:
    value = _with_digest(
        {
            "schema_version": "0.1",
            "status": "pass" if passed else "fail",
            "archive_digest": archive_digest,
            "working_tree_digest": "e" * 64,
            "assertions": [
                {"assertion_id": "api_amount_unit_is_integer_cents", "status": "pass"},
                {"assertion_id": "api_preserves_integer_cents", "status": "pass"},
                {"assertion_id": "database_column_is_amount_cents", "status": "pass"},
                {
                    "assertion_id": SEEDED_ASSERTION,
                    "status": "pass" if passed else "fail",
                },
            ],
        }
    )
    return EvaluationRecord.model_validate(value).model_dump(mode="json")


def _baseline_from_run(
    run: RunRecord,
    *,
    baseline_id: str,
    duration_seconds: float,
    passed: bool = False,
) -> BaselineRunRecord:
    run_value = run.model_dump(mode="json")
    archive_digest = str(run_value["final_source_archive_digest"])
    value = {
        name: run_value[name]
        for name in BaselineRunRecord.model_fields
        if name not in {"baseline_id", "record_digest"}
    }
    value.update(
        {
            "baseline_id": baseline_id,
            "duration_seconds": duration_seconds,
            "evaluator_outcome": _evaluation(
                archive_digest=archive_digest,
                passed=passed,
            ),
            "usage_data": {
                "factory_mission_id": f"private-{baseline_id}",
                "status": "unavailable",
            },
        }
    )
    return BaselineRunRecord.model_validate(_with_digest(value))


def _shadow_from_run(
    run: RunRecord,
    baseline: BaselineRunRecord,
    *,
    duration_seconds: float,
    passed: bool,
    pre_evaluation_record_digest: str,
) -> RunRecord:
    archive_digest = str(run.final_source_archive_digest)
    evaluation = _evaluation(archive_digest=archive_digest, passed=passed)
    value = run.model_dump(mode="json")
    value.update(
        {
            "baseline_id": baseline.baseline_id,
            "baseline_record_digest": baseline.record_digest,
            "duration_seconds": duration_seconds,
            "evaluator_outcome": evaluation,
            "pre_evaluation_record_digest": pre_evaluation_record_digest,
            "final_source_manifest_digest": "2" * 64,
            "final_source_working_tree_digest": "e" * 64,
            "evaluator_digest": "3" * 64,
            "evaluation_record_digest": evaluation["record_digest"],
            "evaluator_vm_deleted": True,
            "usage_data": {"status": "unavailable"},
        }
    )
    return RunRecord.model_validate(_with_digest(value))


def _write_record(path: Path, value: dict[str, object]) -> Path:
    path.write_bytes(canonical_json(value) + b"\n")
    return path


def _pair_outcome(
    root: Path,
    *,
    pair_id: str,
    shadow_passed: bool,
    baseline_duration: float,
    shadow_duration: float,
) -> PairOutcomeArtifacts:
    root.mkdir()
    base = final_run(f"run-{pair_id}")
    baseline = _baseline_from_run(
        base,
        baseline_id=f"baseline-{pair_id}",
        duration_seconds=baseline_duration,
    )
    baseline_path = _write_record(
        root / "baseline.json",
        baseline.model_dump(mode="json"),
    )

    journal = ReviewJournal(root / "review.jsonl", run_id=base.run_id)
    journal.append(
        "extraction_outcome",
        ledger_sequence=1,
        event_id="event-accepted",
        trigger_kinds=("test_edit",),
        status="accepted",
        quarantine_reason=None,
        claims=(),
        derived_evidence=(),
    )
    journal.append(
        "extraction_outcome",
        ledger_sequence=2,
        event_id="event-quarantined",
        trigger_kinds=("completion_attempt",),
        status="quarantined",
        quarantine_reason="invalid_shape",
        claims=(),
        derived_evidence=(),
    )
    journal.append(
        "extraction_outcome",
        ledger_sequence=3,
        event_id="event-failed",
        trigger_kinds=("failed_command_or_test",),
        status="failed",
        quarantine_reason="extractor_failure",
        claims=(),
        derived_evidence=(),
    )
    append_mixed_finding(journal, base.run_id)
    pre_evaluation = PreEvaluationRecord.model_validate(
        _with_digest(
            {
                "schema_version": "0.1",
                "run_id": base.run_id,
                "pre_evaluation_run_record_digest": "1" * 64,
                "event_ledger_digest": "2" * 64,
                "event_ledger_record_count": 0,
                "review_journal_digest": hashlib.sha256(
                    (root / "review.jsonl").read_bytes()
                ).hexdigest(),
                "source_archive_digest": "3" * 64,
                "source_manifest_digest": "4" * 64,
                "source_working_tree_digest": "e" * 64,
                "evaluator_digest": "3" * 64,
                "mission_process_stopped": True,
            }
        )
    )
    pre_evaluation_path = _write_record(
        root / "pre-evaluation.json",
        pre_evaluation.model_dump(mode="json"),
    )
    shadow = _shadow_from_run(
        base,
        baseline,
        duration_seconds=shadow_duration,
        passed=shadow_passed,
        pre_evaluation_record_digest=pre_evaluation.record_digest,
    )
    shadow_path = _write_record(
        root / "run.json",
        shadow.model_dump(mode="json"),
    )
    comparison = _with_digest(
        {
            "schema_version": "0.1",
            "status": "pass" if shadow_passed else "refused",
            "baseline_record_digest": baseline.record_digest,
            "shadow_run_record_digest": shadow.record_digest,
            "shadow_report_digest": "4" * 64,
            **(
                {}
                if shadow_passed
                else {"refusal_reason": "Shadow did not repair the seeded defect"}
            ),
        }
    )
    comparison_path = _write_record(root / "comparison.json", comparison)
    return PairOutcomeArtifacts(
        pair_id=pair_id,
        comparison_record=comparison_path,
        baseline_record=baseline_path,
        shadow_run_record=shadow_path,
        pre_evaluation_record=pre_evaluation_path,
        review_journal=root / "review.jsonl",
    )


def test_summary_refuses_missing_pre_registered_pair(tmp_path: Path) -> None:
    outcome = _pair_outcome(
        tmp_path / "pair-a",
        pair_id="pair-a",
        shadow_passed=True,
        baseline_duration=12.0,
        shadow_duration=9.0,
    )
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "baseline-a.json").write_bytes(outcome.baseline_record.read_bytes())

    with pytest.raises(SummaryError, match="pre-registered pair has no outcome record"):
        build_summary(
            pre_registered_pair_ids=("pair-a", "pair-b"),
            outcomes=(outcome,),
            baseline_corpus=corpus,
        )


def test_summary_refuses_review_journal_outside_frozen_binding(
    tmp_path: Path,
) -> None:
    outcome = _pair_outcome(
        tmp_path / "pair-a",
        pair_id="pair-a",
        shadow_passed=True,
        baseline_duration=12.0,
        shadow_duration=9.0,
    )
    journal = ReviewJournal(outcome.review_journal, run_id="run-pair-a")
    journal.append(
        "extraction_outcome",
        ledger_sequence=10,
        event_id="event-after-freeze",
        trigger_kinds=(),
        status="not_triggered",
        quarantine_reason=None,
        claims=(),
        derived_evidence=(),
    )
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "baseline-a.json").write_bytes(outcome.baseline_record.read_bytes())

    with pytest.raises(SummaryError, match="review journal binding differs"):
        build_summary(
            pre_registered_pair_ids=("pair-a",),
            outcomes=(outcome,),
            baseline_corpus=corpus,
        )


def test_summary_uses_frozen_fields_and_includes_shadow_failure(
    tmp_path: Path,
) -> None:
    passed = _pair_outcome(
        tmp_path / "pair-a",
        pair_id="pair-a",
        shadow_passed=True,
        baseline_duration=12.5,
        shadow_duration=9.0,
    )
    failed = _pair_outcome(
        tmp_path / "pair-b",
        pair_id="pair-b",
        shadow_passed=False,
        baseline_duration=5.0,
        shadow_duration=8.25,
    )
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "baseline-a.json").write_bytes(passed.baseline_record.read_bytes())
    (corpus / "baseline-b.json").write_bytes(failed.baseline_record.read_bytes())

    summary = build_summary(
        pre_registered_pair_ids=("pair-a", "pair-b"),
        outcomes=(passed, failed),
        baseline_corpus=corpus,
    )

    assert summary["pair_ids"] == ["pair-a", "pair-b"]
    assert summary["pair_counts"] == {
        "pre_registered": 2,
        "complete": 2,
        "incomplete": 0,
    }
    first, second = summary["pairs"]
    assert first["completion_status"] == "complete"
    assert second["completion_status"] == "complete"
    assert first["baseline_evaluator_status"] == "fail"
    assert first["shadow_evaluator_status"] == "pass"
    assert first["baseline_failed_assertion_ids"] == [SEEDED_ASSERTION]
    assert first["shadow_failed_assertion_ids"] == []
    assert first["baseline_duration_seconds"] == 12.5
    assert first["shadow_duration_seconds"] == 9.0
    assert first["duration_difference_seconds"] == -3.5
    assert first["intervention_counts"] == {
        "created": 2,
        "delivered": 0,
        "acknowledged": 0,
        "corrected": 0,
        "resolved": 1,
        "unresolved": 1,
    }
    assert first["review_activity_counts"] == {
        "accepted_extractions": 1,
        "quarantined_extractions": 1,
        "failed_extractions": 1,
        "interventions_created": 2,
        "interventions_delivered": 1,
        "interventions_resolved": 1,
    }
    assert first["token_counts"] == {
        "baseline": {"status": "unavailable", "value": None},
        "shadow": {"status": "unavailable", "value": None},
    }
    assert first["cost_cents"] == {
        "baseline": {"status": "unavailable", "value": None},
        "shadow": {"status": "unavailable", "value": None},
    }
    assert second["shadow_evaluator_status"] == "fail"
    assert second["comparison_status"] == "refused"
    assert second["shadow_failed_assertion_ids"] == [SEEDED_ASSERTION]
    assert second["duration_difference_seconds"] == 3.25

    emitted = canonical_json(summary).decode("ascii").lower()
    for banned in ("overhead", "noise", "precision", "efficiency"):
        assert banned not in emitted


def test_baseline_corpus_groups_exact_failure_signatures(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    base = final_run("run-corpus")
    records = (
        ("baseline-a", False),
        ("baseline-b", False),
        ("baseline-c", True),
    )
    for baseline_id, passed in records:
        record = _baseline_from_run(
            base,
            baseline_id=baseline_id,
            duration_seconds=1.0,
            passed=passed,
        )
        _write_record(
            corpus / f"{baseline_id}.json",
            record.model_dump(mode="json"),
        )

    record = _baseline_from_run(
        base,
        baseline_id="baseline-d",
        duration_seconds=1.0,
        passed=False,
    )
    value = record.model_dump(mode="json")
    evaluation = dict(value["evaluator_outcome"])
    evaluation["assertions"] = [
        {"assertion_id": "api_amount_unit_is_integer_cents", "status": "fail"},
        {"assertion_id": "api_preserves_integer_cents", "status": "pass"},
        {"assertion_id": "database_column_is_amount_cents", "status": "pass"},
        {"assertion_id": SEEDED_ASSERTION, "status": "fail"},
    ]
    evaluation["record_digest"] = _with_digest(evaluation)["record_digest"]
    value["evaluator_outcome"] = EvaluationRecord.model_validate(evaluation).model_dump(
        mode="json"
    )
    record = BaselineRunRecord.model_validate(_with_digest(value))
    _write_record(corpus / "baseline-d.json", record.model_dump(mode="json"))

    summary = summarize_baseline_corpus(corpus)

    assert summary == {
        "mission_digest": base.mission_digest,
        "initial_commit": base.initial_commit,
        "total_records": 4,
        "failed_records": 3,
        "passed_records": 1,
        "failure_signatures": [
            {
                "failed_assertion_ids": ["api_amount_unit_is_integer_cents", SEEDED_ASSERTION],
                "record_count": 1,
            },
            {
                "failed_assertion_ids": [SEEDED_ASSERTION],
                "record_count": 2,
            },
        ],
    }


def test_summary_represents_incomplete_pre_registered_pair(tmp_path: Path) -> None:
    outcome = _pair_outcome(
        tmp_path / "pair-a",
        pair_id="pair-a",
        shadow_passed=True,
        baseline_duration=12.0,
        shadow_duration=9.0,
    )
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "baseline-a.json").write_bytes(outcome.baseline_record.read_bytes())

    summary = build_summary(
        pre_registered_pair_ids=("pair-a", "pair-b"),
        outcomes=(outcome,),
        incomplete_pairs=(
            IncompletePair(
                pair_id="pair-b",
                reason="mission source export failed",
                consumed_authorizations=2,
            ),
        ),
        baseline_corpus=corpus,
    )

    assert summary["pair_ids"] == ["pair-a", "pair-b"]
    assert summary["pair_counts"] == {
        "pre_registered": 2,
        "complete": 1,
        "incomplete": 1,
    }
    assert summary["pairs"][1] == {
        "pair_id": "pair-b",
        "completion_status": "incomplete",
        "reason": "mission source export failed",
        "consumed_authorizations": 2,
    }
    assert "comparison_status" not in summary["pairs"][1]
    assert "baseline_evaluator_status" not in summary["pairs"][1]
    assert "shadow_evaluator_status" not in summary["pairs"][1]


def test_summary_rejects_invalid_comparison_state(tmp_path: Path) -> None:
    outcome = _pair_outcome(
        tmp_path / "pair-a",
        pair_id="pair-a",
        shadow_passed=False,
        baseline_duration=12.0,
        shadow_duration=9.0,
    )
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "baseline-a.json").write_bytes(outcome.baseline_record.read_bytes())
    comparison = json.loads(outcome.comparison_record.read_bytes())
    comparison["causal_chain"] = {
        "seeded_finding_dedup_keys": ["a" * 64],
        "matched_intervention_ids": ["intervention-a"],
    }
    _write_record(outcome.comparison_record, _with_digest(comparison))

    with pytest.raises(SummaryError, match="refused comparison state is invalid"):
        build_summary(
            pre_registered_pair_ids=("pair-a",),
            outcomes=(outcome,),
            baseline_corpus=corpus,
        )

    comparison.pop("causal_chain")
    comparison.pop("refusal_reason")
    comparison["status"] = "unknown"
    _write_record(outcome.comparison_record, _with_digest(comparison))
    with pytest.raises(SummaryError, match="comparison status is invalid"):
        build_summary(
            pre_registered_pair_ids=("pair-a",),
            outcomes=(outcome,),
            baseline_corpus=corpus,
        )


def test_baseline_corpus_rejects_binding_and_assertion_drift(tmp_path: Path) -> None:
    base = final_run("run-corpus-binding")
    first = _baseline_from_run(
        base,
        baseline_id="baseline-a",
        duration_seconds=1.0,
    )

    binding_corpus = tmp_path / "binding-corpus"
    binding_corpus.mkdir()
    _write_record(
        binding_corpus / "baseline-a.json",
        first.model_dump(mode="json"),
    )
    binding_value = first.model_dump(mode="json")
    binding_value["baseline_id"] = "baseline-b"
    binding_value["mission_digest"] = "f" * 64
    binding_record = BaselineRunRecord.model_validate(_with_digest(binding_value))
    _write_record(
        binding_corpus / "baseline-b.json",
        binding_record.model_dump(mode="json"),
    )

    with pytest.raises(SummaryError, match="baseline corpus binding differs: mission_digest"):
        summarize_baseline_corpus(binding_corpus)

    assertion_corpus = tmp_path / "assertion-corpus"
    assertion_corpus.mkdir()
    assertion_value = first.model_dump(mode="json")
    evaluation = dict(assertion_value["evaluator_outcome"])
    evaluation["assertions"] = [
        assertion
        for assertion in evaluation["assertions"]
        if assertion["assertion_id"] != "database_column_is_amount_cents"
    ]
    evaluation["record_digest"] = _with_digest(evaluation)["record_digest"]
    assertion_value["evaluator_outcome"] = EvaluationRecord.model_validate(
        evaluation
    ).model_dump(mode="json")
    assertion_record = BaselineRunRecord.model_validate(
        _with_digest(assertion_value)
    )
    _write_record(
        assertion_corpus / "baseline-a.json",
        assertion_record.model_dump(mode="json"),
    )

    with pytest.raises(SummaryError, match="assertion IDs differ"):
        summarize_baseline_corpus(assertion_corpus)
