from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

import demo.compare as compare_module
from demo.compare import ComparisonError, compare
from demo.summarize_pairs import PairOutcomeArtifacts, build_summary
from shadow_mission.protocol import BaselineRunRecord, RunRecord, canonical_json
from shadow_mission.reporting import ReportRecord, rebuild_report
from shadow_mission.review_journal import ReviewJournal
from shadow_mission.source_export import validate_source_archive
from tests.integration.test_source_export import export
from tests.unit.test_reporting import (
    bind_baseline,
    final_run,
    mission_relation_record,
)


PROJECT_ROOT = Path(__file__).parents[2]

SEEDED_FINDING_KEY = "a" * 64
OTHER_SEEDED_FINDING_KEY = "b" * 64
SEEDED_TARGET_SESSIONS = ("session-a", "session-b")
SEEDED_NORMALIZED_VALUES = (
    canonical_json({"type": "string", "value": "cents"}).decode("ascii"),
    canonical_json({"type": "string", "value": "dollars"}).decode("ascii"),
)


def with_report_values(report: ReportRecord, **changes: object) -> ReportRecord:
    value = report.model_dump(mode="json")
    value.update(changes)
    value["record_digest"] = "0" * 64
    material = dict(value)
    material.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    return ReportRecord.model_validate(value)


def seeded_detection(
    *,
    completion_state: str,
    dedup_key: str = SEEDED_FINDING_KEY,
    present_at_completion: bool = True,
) -> dict:
    return {
        "finding": {
            "finding_id": f"finding-{dedup_key[:24]}",
            "dedup_key": dedup_key,
            "rule": "cross_worker_conflict",
            "level": "concern",
            "target_sessions": SEEDED_TARGET_SESSIONS,
            "claim_ids": ("claim-cents", "claim-dollars"),
            "evidence_ids": ("evidence-cents", "evidence-dollars"),
            "evidence_digests": ("1" * 64, "2" * 64),
            "normalized_locators": ("docs/stale-guide.md",),
            "normalized_properties": ("unit",),
            "normalized_units": (None,),
            "normalized_values": SEEDED_NORMALIZED_VALUES,
            "authority_status": "unresolved_same_authority",
            "authority_level": 0,
            "authority_value": None,
            "risk_category": "none",
            "probe_status": "inconclusive",
            "probe_id": "probe-seeded",
            "milestone_ids": (),
        },
        "detected_at_ledger_sequence": 1,
        "completion_state": completion_state,
        "present_at_completion": present_at_completion,
    }


def resolved_intervention(
    *,
    target_session: str,
    suffix: str,
    finding_dedup_key: str = SEEDED_FINDING_KEY,
    include_test_evidence: bool = True,
) -> tuple[dict, tuple[dict, ...]]:
    intervention_id = f"intervention-{suffix}"
    source_evidence_id = f"correction-{suffix}-source"
    test_evidence_id = f"correction-{suffix}-test"
    all_evidence = tuple(
        {
            "schema_version": "0.1",
            "provenance_status": "collector_observed",
            "redaction_status": "clean",
            "evidence_id": evidence_id,
            "run_id": "run-shadow",
            "session_alias": target_session,
            "kind": "target_correction",
            "source": source,
            "locator": locator,
            "digest": hashlib.sha256(evidence_id.encode("utf-8")).hexdigest(),
            "registry_digest": None,
            "intervention_id": intervention_id,
            "observed_at": observed_at,
        }
        for evidence_id, source, locator, observed_at in (
            (
                source_evidence_id,
                "target_diff_transcript",
                "src/webhook.py",
                4,
            ),
            (
                test_evidence_id,
                "target_test_transcript",
                "tests/test_integration.py",
                5,
            ),
        )
    )
    evidence = all_evidence if include_test_evidence else all_evidence[:1]
    value = {
        "schema_version": "0.1",
        "provenance_status": "collector_observed",
        "redaction_status": "clean",
        "record_type": "intervention_record",
        "intervention_id": intervention_id,
        "run_id": "run-shadow",
        "finding_id": f"finding-{finding_dedup_key[:24]}",
        "finding_dedup_key": finding_dedup_key,
        "target_session": target_session,
        "completion_session_alias": target_session,
        "rule": "cross_worker_conflict",
        "level": "concern",
        "risk_category": "none",
        "claim_ids": ("claim-cents", "claim-dollars"),
        "direct_evidence_ids": ("evidence-cents", "evidence-dollars"),
        "direct_evidence_digests": ("1" * 64, "2" * 64),
        "correction_evidence_ids": tuple(
            sorted(item["evidence_id"] for item in evidence)
        ),
        "correction_evidence_digests": tuple(
            sorted(item["digest"] for item in evidence)
        ),
        "generation": 5,
        "state": "resolved",
        "transition_history": (
            {
                "transition_id": f"transition-{suffix}-queued",
                "generation": 1,
                "state": "queued",
                "action": "queued",
                "observed_at": 1,
            },
            {
                "transition_id": f"transition-{suffix}-delivered",
                "generation": 2,
                "state": "delivered",
                "action": "delivered",
                "observed_at": 2,
            },
            {
                "transition_id": f"transition-{suffix}-acknowledged",
                "generation": 3,
                "state": "acknowledged",
                "action": "acknowledged",
                "observed_at": 3,
            },
            {
                "transition_id": f"transition-{suffix}-corrected",
                "generation": 4,
                "state": "corrected",
                "action": "corrected",
                "observed_at": 5,
            },
            {
                "transition_id": f"transition-{suffix}-resolved",
                "generation": 5,
                "state": "resolved",
                "action": "resolved",
                "observed_at": 5,
            },
        ),
        "probe_id": None,
        "probe_digest": None,
        "probe_status": "inconclusive",
        "probe_snapshot_digest": None,
        "blocking_scope": "worker",
        "original_feature": None,
        "repair_assignment": None,
        "repair_guidance_delivered_at": None,
        "probe_pending_at_completion": None,
        "attempts": 0,
        "deadline": None,
        "terminal_outcome": "corrected",
        "termination_acknowledgment_evidence_id": None,
        "termination_acknowledgment_evidence_digest": None,
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value, evidence


def delivered_intervention(
    *,
    target_session: str,
    suffix: str,
    finding_dedup_key: str,
) -> dict:
    value, _evidence = resolved_intervention(
        target_session=target_session,
        suffix=suffix,
        finding_dedup_key=finding_dedup_key,
    )
    value.update(
        {
            "correction_evidence_ids": (),
            "correction_evidence_digests": (),
            "generation": 2,
            "state": "delivered",
            "transition_history": value["transition_history"][:2],
            "terminal_outcome": None,
        }
    )
    value.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def report_with_seeded_findings(
    report: ReportRecord,
    *,
    finding_keys: tuple[str, ...] = (SEEDED_FINDING_KEY,),
    resolved_chain_keys: tuple[str, ...] = (),
    closed_without_test_keys: tuple[str, ...] = (),
    partially_resolved_keys: tuple[str, ...] = (),
    absent_at_completion_keys: tuple[str, ...] = (),
    unresolved_keys: tuple[str, ...] = (),
) -> ReportRecord:
    interventions: list[dict] = []
    evidence: list[dict] = []
    closed_keys = set(resolved_chain_keys) | set(closed_without_test_keys)
    intervention_keys = closed_keys | set(partially_resolved_keys)
    for finding_index, finding_key in enumerate(finding_keys, start=1):
        if finding_key not in intervention_keys:
            continue
        for target_index, target_session in enumerate(
            SEEDED_TARGET_SESSIONS,
            start=1,
        ):
            suffix = f"{finding_index}-{target_index}"
            if (
                finding_key in partially_resolved_keys
                and target_index == len(SEEDED_TARGET_SESSIONS)
            ):
                interventions.append(
                    delivered_intervention(
                        target_session=target_session,
                        suffix=suffix,
                        finding_dedup_key=finding_key,
                    )
                )
                continue
            intervention, correction_evidence = resolved_intervention(
                target_session=target_session,
                suffix=suffix,
                finding_dedup_key=finding_key,
                include_test_evidence=(
                    finding_key in resolved_chain_keys
                    or finding_key in partially_resolved_keys
                ),
            )
            interventions.append(intervention)
            evidence.extend(correction_evidence)
    return with_report_values(
        report,
        detections=tuple(
            seeded_detection(
                completion_state=(
                    "resolved" if finding_key in closed_keys else "unresolved"
                ),
                dedup_key=finding_key,
                present_at_completion=(
                    finding_key not in absent_at_completion_keys
                ),
            )
            for finding_key in finding_keys
        ),
        interventions=tuple(interventions),
        evidence=tuple(sorted(evidence, key=lambda item: item["evidence_id"])),
        unresolved_risks=tuple(sorted(unresolved_keys)),
    )


def commit_seed(repo: Path) -> None:
    shutil.copytree(PROJECT_ROOT / "demo/seed", repo)
    for arguments in (
        ("git", "init", "-q", str(repo)),
        ("git", "-C", str(repo), "add", "."),
        (
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Shadow Test",
            "-c",
            "user.email=shadow-test@example.invalid",
            "commit",
            "-qm",
            "seed",
        ),
    ):
        subprocess.run(arguments, check=True, capture_output=True, shell=False)


def evaluation_value(archive: Path, manifest: Path, *, status: str) -> dict:
    source = validate_source_archive(archive, manifest)
    assertion_ids = (
        "api_amount_unit_is_integer_cents",
        "api_preserves_integer_cents",
        "database_column_is_amount_cents",
        "ten_dollars_crosses_all_boundaries_as_1000_cents",
    )
    value = {
        "schema_version": "0.1",
        "status": status,
        "archive_digest": source.archive_digest,
        "working_tree_digest": source.manifest.working_tree_digest,
        "assertions": [
            {
                "assertion_id": assertion_id,
                "status": (
                    status
                    if assertion_id
                    == "ten_dollars_crosses_all_boundaries_as_1000_cents"
                    else "pass"
                ),
            }
            for assertion_id in assertion_ids
        ],
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def with_run_values(run: RunRecord, **changes: object) -> RunRecord:
    value = run.model_dump(mode="json")
    value.update(changes)
    value["record_digest"] = "0" * 64
    material = dict(value)
    material.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    return RunRecord.model_validate(value)


def baseline_from(
    run: RunRecord,
    *,
    archive_digest: str,
    evaluation: dict,
) -> BaselineRunRecord:
    run_value = run.model_dump(mode="json")
    value = {
        field: run_value[field]
        for field in BaselineRunRecord.model_fields
        if field not in {"baseline_id", "record_digest"}
    }
    value.update(
        {
            "baseline_id": "baseline-demo",
            "final_source_archive_digest": archive_digest,
            "evaluator_outcome": evaluation,
        }
    )
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return BaselineRunRecord.model_validate(value)


def comparison_pair(tmp_path: Path) -> tuple[dict[str, Path], ReportRecord]:
    repo = tmp_path / "checkout"
    commit_seed(repo)
    baseline_archive, baseline_manifest, baseline_export = export(
        repo, tmp_path / "baseline-source"
    )
    assert baseline_export.returncode == 0
    (repo / "src/webhook.py").write_text(
        """from __future__ import annotations
from decimal import Decimal


def parse_webhook(payload: dict) -> dict:
    amount = payload[\"amount\"]
    cents = amount if type(amount) is int else int(Decimal(str(amount)) * 100)
    return {
        \"payment_id\": str(payload[\"payment_id\"]),
        \"amount_cents\": cents,
        \"currency\": str(payload.get(\"currency\", \"USD\")),
    }
""",
        encoding="utf-8",
    )
    (repo / "docs/stale-guide.md").write_text(
        "Payment amounts use integer cents after webhook ingestion.\n",
        encoding="utf-8",
    )
    shadow_archive, shadow_manifest, shadow_export = export(
        repo, tmp_path / "shadow-source"
    )
    assert shadow_export.returncode == 0
    baseline_source = validate_source_archive(baseline_archive, baseline_manifest)
    shadow_source = validate_source_archive(shadow_archive, shadow_manifest)

    shadow_evaluation = evaluation_value(
        shadow_archive,
        shadow_manifest,
        status="pass",
    )
    evaluator_digest = hashlib.sha256(
        (PROJECT_ROOT / "demo/evaluator/evaluate.py").read_bytes()
    ).hexdigest()
    preliminary = with_run_values(
        final_run("run-shadow"),
        mission_outcome="mission-complete",
        runtime_outcome="mission-terminated",
        evaluator_outcome="mission-terminated",
        initial_commit=baseline_source.manifest.final_commit,
        final_commit=shadow_source.manifest.final_commit,
        final_source_archive_digest=None,
        approved_evaluator_digest=evaluator_digest,
    )
    baseline = baseline_from(
        preliminary,
        archive_digest=baseline_source.archive_digest,
        evaluation=evaluation_value(
            baseline_archive,
            baseline_manifest,
            status="fail",
        ),
    )
    preliminary = bind_baseline(preliminary, baseline)
    manifest_digest = hashlib.sha256(shadow_manifest.read_bytes()).hexdigest()
    pre_evaluation = {
        "schema_version": "0.1",
        "run_id": preliminary.run_id,
        "pre_evaluation_run_record_digest": preliminary.record_digest,
        "event_ledger_digest": hashlib.sha256(b"").hexdigest(),
        "event_ledger_record_count": 0,
        "review_journal_digest": hashlib.sha256(b"").hexdigest(),
        "source_archive_digest": shadow_source.archive_digest,
        "source_manifest_digest": manifest_digest,
        "source_working_tree_digest": shadow_source.manifest.working_tree_digest,
        "evaluator_digest": evaluator_digest,
        "mission_process_stopped": True,
    }
    pre_evaluation["record_digest"] = hashlib.sha256(
        canonical_json(pre_evaluation)
    ).hexdigest()
    run = with_run_values(
        preliminary,
        mission_outcome="mission-complete",
        final_source_archive_digest=shadow_source.archive_digest,
        evaluator_outcome=shadow_evaluation,
        pre_evaluation_record_digest=pre_evaluation["record_digest"],
        final_source_manifest_digest=manifest_digest,
        final_source_working_tree_digest=(
            shadow_source.manifest.working_tree_digest
        ),
        evaluator_digest=evaluator_digest,
        evaluation_record_digest=shadow_evaluation["record_digest"],
        evaluator_vm_deleted=True,
    )
    run_dir = tmp_path / "run-shadow"
    run_dir.mkdir(mode=0o700)
    (run_dir / "run.json").write_bytes(
        canonical_json(run.model_dump(mode="json")) + b"\n"
    )
    (run_dir / "events.jsonl").write_bytes(b"")
    ReviewJournal(run_dir / "review.jsonl", run_id=run.run_id)
    relation = mission_relation_record(run.run_id)
    (run_dir / "correlation.json").write_bytes(
        canonical_json(relation) + b"\n"
    )
    (run_dir / "pre-evaluation-run.json").write_bytes(
        canonical_json(preliminary.model_dump(mode="json")) + b"\n"
    )
    (run_dir / "pre-evaluation.json").write_bytes(
        canonical_json(pre_evaluation) + b"\n"
    )
    (run_dir / "evaluation.json").write_bytes(
        canonical_json(shadow_evaluation) + b"\n"
    )
    final_source = run_dir / "final-source"
    final_source.mkdir()
    shutil.copyfile(shadow_archive, final_source / "final-source.tar")
    shutil.copyfile(
        shadow_manifest,
        final_source / "final-source-manifest.json",
    )
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_bytes(
        canonical_json(baseline.model_dump(mode="json")) + b"\n"
    )

    report = rebuild_report(run_dir, baseline_record_path=baseline_path)
    return (
        {
            "baseline_record_path": baseline_path,
            "shadow_run_dir": run_dir,
            "baseline_archive": baseline_archive,
            "baseline_manifest": baseline_manifest,
            "shadow_archive": shadow_archive,
            "shadow_manifest": shadow_manifest,
            "output_path": tmp_path / "comparison.json",
        },
        report,
    )


def test_comparison_uses_chain_reason_for_multiple_seeded_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    report = report_with_seeded_findings(
        report,
        finding_keys=(SEEDED_FINDING_KEY, OTHER_SEEDED_FINDING_KEY),
    )
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    assert result["status"] == "refused"
    assert (
        result["refusal_reason"]
        == "seeded conflict intervention group is not fully resolved"
    )
    assert "causal_chain" not in result
    assert result["shadow_report_digest"] == report.record_digest
    assert json.loads(arguments["output_path"].read_bytes()) == result
    assert stat.S_IMODE(arguments["output_path"].stat().st_mode) == 0o600


def test_comparison_refuses_when_seeded_finding_set_is_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    report = report_with_seeded_findings(report, finding_keys=())
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    assert result["status"] == "refused"
    assert (
        result["refusal_reason"]
        == "report does not contain the seeded conflict detection"
    )
    assert "causal_chain" not in result


def test_refused_comparison_completes_pre_registered_pair_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    report = report_with_seeded_findings(report)
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )
    comparison = compare(**arguments)
    corpus = tmp_path / "baseline-corpus"
    corpus.mkdir()
    shutil.copyfile(
        arguments["baseline_record_path"],
        corpus / "baseline-pair.json",
    )

    summary = build_summary(
        pre_registered_pair_ids=("pair-refused",),
        outcomes=(
            PairOutcomeArtifacts(
                pair_id="pair-refused",
                comparison_record=arguments["output_path"],
                baseline_record=arguments["baseline_record_path"],
                shadow_run_record=arguments["shadow_run_dir"] / "run.json",
                pre_evaluation_record=(
                    arguments["shadow_run_dir"] / "pre-evaluation.json"
                ),
                review_journal=arguments["shadow_run_dir"] / "review.jsonl",
            ),
        ),
        baseline_corpus=corpus,
    )

    assert comparison["status"] == "refused"
    assert summary["pairs"][0]["comparison_status"] == "refused"


def test_comparison_refuses_when_all_seeded_findings_lack_complete_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    report = report_with_seeded_findings(
        report,
        finding_keys=(SEEDED_FINDING_KEY, OTHER_SEEDED_FINDING_KEY),
        closed_without_test_keys=(
            SEEDED_FINDING_KEY,
            OTHER_SEEDED_FINDING_KEY,
        ),
    )
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    assert result["status"] == "refused"
    assert (
        result["refusal_reason"]
        == "seeded conflict lacks delivered source-and-test repair evidence"
    )
    assert "causal_chain" not in result


def test_comparison_refuses_seeded_finding_in_unresolved_risks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    report = report_with_seeded_findings(
        report,
        finding_keys=(SEEDED_FINDING_KEY, OTHER_SEEDED_FINDING_KEY),
        resolved_chain_keys=(SEEDED_FINDING_KEY,),
        closed_without_test_keys=(OTHER_SEEDED_FINDING_KEY,),
        unresolved_keys=(OTHER_SEEDED_FINDING_KEY,),
    )
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    assert result["status"] == "refused"
    assert (
        result["refusal_reason"]
        == "seeded conflict remains in unresolved risks"
    )
    assert "causal_chain" not in result
    assert result["shadow_report_digest"] == report.record_digest
    assert json.loads(arguments["output_path"].read_bytes()) == result


def test_comparison_refuses_when_any_seeded_finding_group_is_not_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    report = report_with_seeded_findings(
        report,
        finding_keys=(SEEDED_FINDING_KEY, OTHER_SEEDED_FINDING_KEY),
        resolved_chain_keys=(SEEDED_FINDING_KEY,),
        partially_resolved_keys=(OTHER_SEEDED_FINDING_KEY,),
    )
    unclosed_states = {
        intervention["state"]
        for intervention in report.interventions
        if intervention["finding_dedup_key"] == OTHER_SEEDED_FINDING_KEY
    }
    assert unclosed_states == {"delivered", "resolved"}
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    assert report.unresolved_risks == ()
    assert result["status"] == "refused"
    assert (
        result["refusal_reason"]
        == "seeded conflict intervention group is not fully resolved"
    )
    assert "causal_chain" not in result
    assert json.loads(arguments["output_path"].read_bytes()) == result


def test_comparison_refuses_unresolved_completion_for_closed_seeded_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    report = report_with_seeded_findings(
        report,
        finding_keys=(SEEDED_FINDING_KEY, OTHER_SEEDED_FINDING_KEY),
        resolved_chain_keys=(SEEDED_FINDING_KEY, OTHER_SEEDED_FINDING_KEY),
    )
    detections = tuple(
        {
            **detection,
            "completion_state": (
                "unresolved"
                if detection["finding"]["dedup_key"] == OTHER_SEEDED_FINDING_KEY
                else detection["completion_state"]
            ),
        }
        for detection in report.detections
    )
    report = with_report_values(report, detections=detections)
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    assert report.unresolved_risks == ()
    assert result["status"] == "refused"
    assert (
        result["refusal_reason"]
        == "seeded conflict intervention group is not fully resolved"
    )
    assert "causal_chain" not in result


def test_comparison_passes_with_one_closed_seeded_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    report = report_with_seeded_findings(
        report,
        finding_keys=(OTHER_SEEDED_FINDING_KEY,),
        resolved_chain_keys=(OTHER_SEEDED_FINDING_KEY,),
    )
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    assert result["status"] == "pass"
    assert result["evaluation"]["baseline_failed_assertions"] == 1
    assert result["evaluation"]["shadow_failed_assertions"] == 0
    assert result["causal_chain"] == {
        "seeded_finding_dedup_keys": [OTHER_SEEDED_FINDING_KEY],
        "matched_intervention_ids": [
            "intervention-1-1",
            "intervention-1-2",
        ],
    }
    assert result["source_oracle"] == {
        "baseline": {
            "api_amount_unit_is_integer_cents": True,
            "api_preserves_integer_cents": True,
            "database_column_is_amount_cents": True,
            "ten_dollars_crosses_all_boundaries_as_1000_cents": False,
        },
        "shadow": {
            "api_amount_unit_is_integer_cents": True,
            "api_preserves_integer_cents": True,
            "database_column_is_amount_cents": True,
            "ten_dollars_crosses_all_boundaries_as_1000_cents": True,
        },
    }


def test_comparison_refuses_unresolved_seeded_finding_absent_at_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    report = report_with_seeded_findings(
        report,
        finding_keys=(SEEDED_FINDING_KEY, OTHER_SEEDED_FINDING_KEY),
        resolved_chain_keys=(SEEDED_FINDING_KEY,),
        absent_at_completion_keys=(OTHER_SEEDED_FINDING_KEY,),
    )
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    absent_detection = next(
        detection
        for detection in report.detections
        if detection["finding"]["dedup_key"] == OTHER_SEEDED_FINDING_KEY
    )
    assert absent_detection["completion_state"] == "unresolved"
    assert absent_detection["present_at_completion"] is False
    assert report.unresolved_risks == ()
    assert result["status"] == "refused"
    assert (
        result["refusal_reason"]
        == "seeded conflict intervention group is not fully resolved"
    )
    assert "causal_chain" not in result


def test_comparison_refuses_baseline_with_other_assertion_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    baseline_value = json.loads(arguments["baseline_record_path"].read_bytes())
    evaluation = dict(baseline_value["evaluator_outcome"])
    evaluation["assertions"][0]["status"] = "fail"
    evaluation.pop("record_digest")
    evaluation["record_digest"] = hashlib.sha256(
        canonical_json(evaluation)
    ).hexdigest()
    baseline_value["evaluator_outcome"] = evaluation
    baseline_value.pop("record_digest")
    baseline_value["record_digest"] = hashlib.sha256(
        canonical_json(baseline_value)
    ).hexdigest()
    arguments["baseline_record_path"].write_bytes(
        canonical_json(baseline_value) + b"\n"
    )

    run_path = arguments["shadow_run_dir"] / "run.json"
    run = RunRecord.model_validate(json.loads(run_path.read_bytes()))
    run = with_run_values(
        run,
        baseline_record_digest=baseline_value["record_digest"],
    )
    run_path.write_bytes(canonical_json(run.model_dump(mode="json")) + b"\n")
    report = with_report_values(
        report,
        baseline_linkage={
            **report.baseline_linkage,
            "baseline_record_digest": baseline_value["record_digest"],
        },
    )
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    assert result["status"] == "refused"
    assert result["refusal_reason"] == (
        "baseline failed assertions beyond the seeded cross-feature conflict"
    )
    assert "causal_chain" not in result


def test_comparison_requires_shadow_baseline_and_relation_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    run_path = arguments["shadow_run_dir"] / "run.json"
    run = RunRecord.model_validate(json.loads(run_path.read_bytes()))
    run = with_run_values(run, baseline_record_digest="f" * 64)
    run_path.write_bytes(canonical_json(run.model_dump(mode="json")) + b"\n")
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    baseline_refusal = compare(**arguments)

    assert baseline_refusal["status"] == "refused"
    assert baseline_refusal["refusal_reason"] == (
        "Shadow baseline record binding differs"
    )

    arguments["output_path"] = tmp_path / "relation-comparison.json"
    run = with_run_values(
        run,
        baseline_record_digest=json.loads(
            arguments["baseline_record_path"].read_bytes()
        )["record_digest"],
    )
    run_path.write_bytes(canonical_json(run.model_dump(mode="json")) + b"\n")
    frozen_configuration = dict(report.frozen_configuration)
    frozen_configuration["mission_relation_record_digest"] = "f" * 64
    report = with_report_values(
        report,
        frozen_configuration=frozen_configuration,
    )
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    relation_refusal = compare(**arguments)

    assert relation_refusal["status"] == "refused"
    assert relation_refusal["refusal_reason"] == (
        "Shadow Mission relation binding differs"
    )


def test_comparison_rejects_failed_shadow_completion_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, report = comparison_pair(tmp_path)
    run_path = arguments["shadow_run_dir"] / "run.json"
    run = RunRecord.model_validate(json.loads(run_path.read_bytes()))
    run = with_run_values(
        run,
        mission_outcome="mission-failed",
        runtime_outcome="cleanup-failed",
    )
    run_path.write_bytes(canonical_json(run.model_dump(mode="json")) + b"\n")
    monkeypatch.setattr(
        compare_module,
        "rebuild_report",
        lambda *_args, **_kwargs: report,
    )

    result = compare(**arguments)

    assert result["status"] == "refused"
    assert result["refusal_reason"] == "Shadow completion state is invalid"
