from __future__ import annotations

import hashlib
import io
import json
import socket
import stat
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

from demo.attest_cleanup import (
    CleanupAttestationError,
    produce_cleanup_attestation,
)
from demo.compare import compare
from demo.proof_bundle import (
    PairArtifacts,
    ProofBundleError,
    _scan_source_archive,
    _reports_equal,
    _rewrite_structured_aliases,
    _validate_cleanup,
    build_bundle,
    main,
    verify_bundle,
)
from shadow_mission.graph import MissionGraph, load_exchanges_bytes
from shadow_mission.protocol import (
    BaselineRunRecord,
    ClaimRecord,
    EvidenceRecord,
    HookEnvelope,
    HookExchangeRecord,
    HookResponseRecord,
    InterventionRecord,
    PreEvaluationRecord,
    RunRecord,
    canonical_json,
    hook_envelope_digest,
    hook_response_digest,
)
from shadow_mission.reporting import rebuild_report
from shadow_mission.review_journal import (
    ExchangeProjectionRecord,
    ExtractionOutcomeRecord,
    FindingSnapshotRecord,
    InterventionLineageRecord,
    JournalFinding,
    ReviewJournal,
    RoleDecisionRecord,
    load_journal_records,
)
from shadow_mission.roles import (
    FrozenMissionRelations,
    MissionRelation,
    RoleDecision,
)
from shadow_mission.router import InterventionRouterDelta, InterventionRouterState
from shadow_mission.rules import DeliverySelectorState
from shadow_mission.storage import compose_review_state
from tests.integration.test_demo_compare import (
    comparison_pair,
    seeded_detection,
    resolved_intervention,
)
from tests.unit.test_reporting import with_record_digest


def _canonical(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(canonical_json(value) + b"\n")


def _cleanup_value(subject: str, source_record_digest: str) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "0.1",
        "subject": subject,
        "source_record_digest": source_record_digest,
        "mission_process_group_stopped": True,
        "evaluator_vm_deleted": True,
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def _append_seeded_chain(
    run_dir: Path,
    *,
    tool_input: dict[str, object] | None = None,
    response_body_fields: dict[str, object] | None = None,
) -> None:
    correlation = json.loads((run_dir / "correlation.json").read_bytes())
    relations = [
        item
        for item in correlation["record"]["sessions"]
        if item["disposition"] == "mission_role"
    ][:2]
    target_sessions = tuple(item["session_id"] for item in relations)
    assignments = tuple(item["assignment_id"] for item in relations)
    raw_mission_id = correlation["record"]["mission_id"]
    role_relation = MissionRelation(
        session_alias=relations[0]["session_id"],
        mission_id=run_dir.name,
        role_id=relations[0]["role_id"],
        assignment_id=relations[0]["assignment_id"],
        source_digest=relations[0]["source_digest"],
        corroborating_role_ids=tuple(
            relations[0]["corroborating_role_ids"]
        ),
        relation_kind=relations[0]["relation_kind"],
    )
    role_decision = RoleDecision(
        session_alias=role_relation.session_alias,
        role_id=role_relation.role_id,
        kind=relations[0]["role_kind"],
        confidence="high",
        status="assigned",
        reason="authoritative relation",
        evidence_digests=(role_relation.source_digest,),
    )
    relations_digest = FrozenMissionRelations(
        run_dir.name,
        (role_relation,),
    ).digest

    interventions: list[InterventionRecord] = []
    evidence: list[dict] = []
    for index, target_session in enumerate(target_sessions, start=1):
        intervention_value, correction_evidence = resolved_intervention(
            target_session=target_session,
            suffix=str(index),
        )
        interventions.append(InterventionRecord.model_validate(intervention_value))
        evidence.extend(correction_evidence)

    base = InterventionRouterState.empty(run_dir.name)
    final = InterventionRouterState.model_validate(
        with_record_digest(
            InterventionRouterState,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_state",
                "run_id": run_dir.name,
                "generation": 5,
                "interventions": tuple(interventions),
            },
        )
    )
    delta = InterventionRouterDelta.model_validate(
        with_record_digest(
            InterventionRouterDelta,
            {
                "schema_version": "0.1",
                "provenance_status": "collector_observed",
                "redaction_status": "clean",
                "record_type": "intervention_router_delta",
                "run_id": run_dir.name,
                "base_generation": 0,
                "base_digest": base.record_digest,
                "generation": 5,
                "upserts": tuple(interventions),
                "result_digest": final.record_digest,
            },
        )
    )
    selector_state = DeliverySelectorState(
        last_updates=tuple(
            sorted((session, 1) for session in target_sessions)
        ),
        cooldown_remaining=((target_sessions[0], 2),),
        delivered_severity=tuple(
            sorted(
                (session, "a" * 64, 2)
                for session in target_sessions
            )
        ),
    )
    review_state = compose_review_state(
        run_id=run_dir.name,
        components=(
            delta.model_dump(mode="json"),
            selector_state.to_record(run_id=run_dir.name),
        ),
    )
    envelope_payload: dict[str, object] = {
        "tool_name": "Read",
        "tool_response": {
            "mission_id": raw_mission_id,
            "relations": [
                {
                    "session_id": session_id,
                    "assignment_id": assignment_id,
                }
                for session_id, assignment_id
                in zip(target_sessions, assignments)
            ],
        },
    }
    if tool_input is not None:
        envelope_payload["tool_input"] = tool_input

    envelope = HookEnvelope(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        event_id="event-seeded",
        source_fingerprint="source-fingerprint",
        run_id=run_dir.name,
        session_alias=target_sessions[0],
        transcript_alias="transcript-publication-test",
        cwd_alias="cwd-publication-test",
        hook_event_name="PostToolUse",
        observed_at=3,
        message_digest="5" * 64,
        payload=envelope_payload,
    )
    response_body_value: dict[str, object] = {
        "metadata": {
            "mission_id": raw_mission_id,
            "session_id": target_sessions[0],
            "assignment_id": assignments[0],
        }
    }
    if response_body_fields is not None:
        response_body_value.update(response_body_fields)
    response_body = canonical_json(response_body_value).decode("utf-8")
    response = HookResponseRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        response_id="response-seeded",
        run_id=run_dir.name,
        event_id=envelope.event_id,
        request_digest=hook_envelope_digest(envelope),
        response_body=response_body,
        response_digest=hook_response_digest(
            response_body=response_body,
            guidance_ids=(),
            transition_ids=(),
            review_state=review_state,
        ),
        review_state=review_state,
        decided_at=3,
    )
    exchange = HookExchangeRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        ledger_sequence=1,
        exchange_id="exchange-seeded",
        recorded_at=3,
        envelope=envelope,
        response=response,
    )
    (run_dir / "events.jsonl").write_bytes(
        canonical_json(exchange.model_dump(mode="json")) + b"\n"
    )

    claims = (
        {
            "schema_version": "0.1",
            "provenance_status": "collector_observed",
            "redaction_status": "clean",
            "claim_id": "claim-publication-identifiers",
            "run_id": run_dir.name,
            "session_alias": target_sessions[0],
            "subject": "Factory relation",
            "subject_locator": "Factory relation",
            "property": "identifier binding",
            "value": {
                "mission_id": raw_mission_id,
                "sessions": [
                    {
                        "session_id": session_id,
                        "assignment_id": assignment_id,
                    }
                    for session_id, assignment_id
                    in zip(target_sessions, assignments)
                ],
            },
            "unit": None,
            "confidence": 1.0,
            "evidence_ids": (evidence[0]["evidence_id"],),
            "targets": (),
            "milestone_ids": (),
            "observed_at": 5,
        },
    )
    evidence_records = tuple(
        EvidenceRecord.model_validate(item) for item in evidence
    )
    claim_records = tuple(
        ClaimRecord.model_validate(item) for item in claims
    )
    finding_value = seeded_detection(completion_state="resolved")["finding"]
    finding_value["target_sessions"] = target_sessions
    finding = JournalFinding.model_validate(finding_value)
    graph = MissionGraph(run_dir.name)
    graph.add_exchange(exchange)
    graph.add_role_decision(role_decision)
    for item in evidence_records:
        graph.add_evidence(item)
    for claim in claim_records:
        graph.add_claim(claim)

    journal = ReviewJournal(run_dir / "review.jsonl", run_id=run_dir.name)
    journal.append(
        "exchange_projection",
        ledger_sequence=1,
        event_id=envelope.event_id,
        exchange_id=exchange.exchange_id,
        response_digest=response.response_digest,
    )
    journal.append(
        "role_decision",
        ledger_sequence=1,
        event_id=envelope.event_id,
        relations_digest=relations_digest,
        **RoleDecisionRecord.decision_fields(role_decision),
    )
    journal.append(
        "extraction_outcome",
        ledger_sequence=1,
        event_id=envelope.event_id,
        trigger_kinds=("test_edit",),
        status="accepted",
        quarantine_reason=None,
        claims=claim_records,
        derived_evidence=evidence_records,
    )
    journal.append(
        "intervention_lineage",
        ledger_sequence=1,
        event_id=envelope.event_id,
        response_digest=response.response_digest,
        delta=delta,
    )
    journal.append(
        "finding_snapshot",
        ledger_sequence=1,
        event_id=envelope.event_id,
        graph_digest=graph.digest(),
        findings=(finding,),
        validation_overlap_status="active",
    )

    event_payload = (run_dir / "events.jsonl").read_bytes()
    review_payload = (run_dir / "review.jsonl").read_bytes()
    pre_path = run_dir / "pre-evaluation.json"
    pre_value = json.loads(pre_path.read_bytes())
    pre_value.update(
        {
            "event_ledger_digest": hashlib.sha256(event_payload).hexdigest(),
            "event_ledger_record_count": 1,
            "review_journal_digest": hashlib.sha256(review_payload).hexdigest(),
        }
    )
    pre_value.pop("record_digest")
    pre_value["record_digest"] = hashlib.sha256(canonical_json(pre_value)).hexdigest()
    pre_evaluation = PreEvaluationRecord.model_validate(pre_value)
    _canonical(pre_path, pre_evaluation.model_dump(mode="json"))

    run_path = run_dir / "run.json"
    run_value = json.loads(run_path.read_bytes())
    run_value["pre_evaluation_record_digest"] = pre_evaluation.record_digest
    run_value.pop("record_digest")
    run_value["record_digest"] = hashlib.sha256(canonical_json(run_value)).hexdigest()
    run = RunRecord.model_validate(run_value)
    _canonical(run_path, run.model_dump(mode="json"))


def _pair(
    root: Path,
    *,
    include_seeded_chain: bool = True,
    tool_input: dict[str, object] | None = None,
    response_body_fields: dict[str, object] | None = None,
) -> PairArtifacts:
    arguments, _ = comparison_pair(root)
    run_dir = arguments["shadow_run_dir"]
    if include_seeded_chain:
        _append_seeded_chain(
            run_dir,
            tool_input=tool_input,
            response_body_fields=response_body_fields,
        )
    report = rebuild_report(
        run_dir,
        baseline_record_path=arguments["baseline_record_path"],
    )
    report_path = run_dir / "report.json"
    _canonical(report_path, report.model_dump(mode="json"))
    comparison_path = root / "published-comparison.json"
    compare(
        baseline_record_path=arguments["baseline_record_path"],
        shadow_run_dir=run_dir,
        baseline_archive=arguments["baseline_archive"],
        baseline_manifest=arguments["baseline_manifest"],
        shadow_archive=arguments["shadow_archive"],
        shadow_manifest=arguments["shadow_manifest"],
        output_path=comparison_path,
    )
    baseline = json.loads(arguments["baseline_record_path"].read_bytes())
    run = json.loads((run_dir / "run.json").read_bytes())
    baseline_evaluation = root / "baseline-evaluation.json"
    _canonical(baseline_evaluation, baseline["evaluator_outcome"])
    baseline_cleanup = root / "baseline-cleanup.json"
    shadow_cleanup = root / "shadow-cleanup.json"
    _canonical(
        baseline_cleanup,
        _cleanup_value("baseline", baseline["record_digest"]),
    )
    _canonical(
        shadow_cleanup,
        _cleanup_value("shadow", run["record_digest"]),
    )
    return PairArtifacts(
        pair_id="pair-01",
        baseline_record=arguments["baseline_record_path"],
        baseline_archive=arguments["baseline_archive"],
        baseline_manifest=arguments["baseline_manifest"],
        baseline_evaluation=baseline_evaluation,
        shadow_archive=arguments["shadow_archive"],
        shadow_manifest=arguments["shadow_manifest"],
        shadow_run_dir=run_dir,
        report_record=report_path,
        comparison_record=comparison_path,
        baseline_cleanup_attestation=baseline_cleanup,
        shadow_cleanup_attestation=shadow_cleanup,
    )


def test_report_comparison_normalizes_json_containers(tmp_path: Path) -> None:
    pair = _pair(tmp_path)
    report = rebuild_report(
        pair.shadow_run_dir,
        baseline_record_path=pair.baseline_record,
    )
    list_value = report.model_copy(
        update={"frozen_configuration": {"nested": ["value"]}}
    )
    tuple_value = report.model_copy(
        update={"frozen_configuration": {"nested": ("value",)}}
    )

    assert list_value != tuple_value
    assert _reports_equal(list_value, tuple_value)


def test_cleanup_producer_emits_private_digest_bound_attestations(
    tmp_path: Path,
) -> None:
    arguments, _ = comparison_pair(tmp_path / "pair-source")
    baseline_value = json.loads(arguments["baseline_record_path"].read_bytes())
    baseline_value["usage_data"]["cleanup_observations"] = {
        "mission_process_group_stopped": True,
        "evaluator_vm_deleted": True,
    }
    baseline_value.pop("record_digest")
    baseline_value["record_digest"] = hashlib.sha256(
        canonical_json(baseline_value)
    ).hexdigest()
    baseline = BaselineRunRecord.model_validate(baseline_value)
    _canonical(
        arguments["baseline_record_path"],
        baseline.model_dump(mode="json"),
    )
    baseline_cleanup = tmp_path / "baseline-cleanup.json"
    shadow_cleanup = tmp_path / "shadow-cleanup.json"

    baseline_attestation = produce_cleanup_attestation(
        subject="baseline",
        run_record_path=arguments["baseline_record_path"],
        output_path=baseline_cleanup,
    )
    shadow_attestation = produce_cleanup_attestation(
        subject="shadow",
        run_record_path=arguments["shadow_run_dir"] / "run.json",
        output_path=shadow_cleanup,
    )

    _validate_cleanup(
        baseline_cleanup,
        "baseline",
        subject="baseline",
        source_record_digest=baseline.record_digest,
    )
    _validate_cleanup(
        shadow_cleanup,
        "Shadow",
        subject="shadow",
        source_record_digest=json.loads(
            (arguments["shadow_run_dir"] / "run.json").read_bytes()
        )["record_digest"],
    )
    assert baseline_attestation["source_record_digest"] == baseline.record_digest
    assert shadow_attestation["source_record_digest"] == json.loads(
        (arguments["shadow_run_dir"] / "run.json").read_bytes()
    )["record_digest"]
    for path in (baseline_cleanup, shadow_cleanup):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert (
            canonical_json(json.loads(path.read_bytes())) + b"\n"
            == path.read_bytes()
        )


def test_cleanup_producer_refuses_unobserved_cleanup(tmp_path: Path) -> None:
    arguments, _ = comparison_pair(tmp_path / "pair-source")
    output = tmp_path / "cleanup.json"

    with pytest.raises(
        CleanupAttestationError,
        match="cleanup observations are incomplete",
    ):
        produce_cleanup_attestation(
            subject="baseline",
            run_record_path=arguments["baseline_record_path"],
            output_path=output,
        )

    assert not output.exists()


def _tar_payloads(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, mode="r:") as archive:
        return {
            member.name: archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isfile()
        }


def _write_tar(path: Path, payloads: dict[str, bytes]) -> None:
    with tarfile.open(path, mode="w:") as archive:
        for name, payload in sorted(payloads.items()):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o600
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            archive.addfile(info, io.BytesIO(payload))


def _rewrite_manifest(payloads: dict[str, bytes], changed_name: str) -> None:
    manifest = json.loads(payloads["manifest.json"])
    for member in manifest["members"]:
        if member["path"] == changed_name:
            member["sha256"] = hashlib.sha256(payloads[changed_name]).hexdigest()
            member["size"] = len(payloads[changed_name])
            break
    manifest.pop("record_digest")
    manifest["record_digest"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
    payloads["manifest.json"] = canonical_json(manifest) + b"\n"


def test_bundle_builds_and_verifies_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pair = _pair(tmp_path / "pair-source")
    bundle = tmp_path / "proof-bundle.tar"

    manifest = build_bundle(pairs=(pair,), output_path=bundle)
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network used")),
    )
    verified = verify_bundle(bundle)

    assert verified == manifest
    assert main(("verify", "--bundle", str(bundle))) == 0
    assert capsys.readouterr().out == "proof bundle: pass\n"
    payloads = _tar_payloads(bundle)
    combined = b"".join(payloads.values())
    assert b"factory-mission-run-shadow" not in combined
    assert b'"session_id":"session-1"' not in combined
    assert not any("approval" in name for name in payloads)
    assert manifest["exclusions"] == {
        "absolute_host_paths": "excluded",
        "approvals": "excluded",
        "credentials": "excluded",
        "private_path_patterns": "excluded",
        "raw_mission_session_and_assignment_identifiers": "excluded",
    }


def _expected_public_alias(kind: str, raw_value: str) -> str:
    digest = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()[:24]
    return f"public-{kind}-{digest}"


def test_bundle_rewrites_nested_identifiers_and_digest_chains(
    tmp_path: Path,
) -> None:
    pair = _pair(tmp_path / "pair-source")
    source_correlation = json.loads(
        (pair.shadow_run_dir / "correlation.json").read_bytes()
    )
    raw_relations = [
        item
        for item in source_correlation["record"]["sessions"]
        if item["disposition"] == "mission_role"
    ][:2]
    raw_mission_id = source_correlation["record"]["mission_id"]
    raw_identifiers = {
        raw_mission_id,
        *(
            identifier
            for relation in source_correlation["record"]["sessions"]
            for identifier in (
                relation["session_id"],
                relation["assignment_id"],
            )
            if identifier is not None
        ),
    }
    bundle = tmp_path / "identifier-proof-bundle.tar"

    manifest = build_bundle(pairs=(pair,), output_path=bundle)
    assert verify_bundle(bundle) == manifest
    payloads = _tar_payloads(bundle)
    paths = manifest["pairs"][0]
    public_correlation = json.loads(payloads[paths["correlation_record"]])
    public_relations = {
        item["role_id"]: item
        for item in public_correlation["record"]["sessions"]
        if item["disposition"] == "mission_role"
    }
    public_mission_id = _expected_public_alias("mission", raw_mission_id)
    expected_sessions = {
        relation["session_id"]: _expected_public_alias(
            "session",
            relation["session_id"],
        )
        for relation in raw_relations
    }
    expected_assignments = {
        relation["assignment_id"]: _expected_public_alias(
            "assignment",
            relation["assignment_id"],
        )
        for relation in raw_relations
    }
    assert public_correlation["record"]["mission_id"] == public_mission_id
    for relation in raw_relations:
        public_relation = public_relations[relation["role_id"]]
        assert (
            public_relation["session_id"]
            == expected_sessions[relation["session_id"]]
        )
        assert (
            public_relation["assignment_id"]
            == expected_assignments[relation["assignment_id"]]
        )

    event_payload = payloads[paths["event_ledger"]]
    review_payload = payloads[paths["review_journal"]]
    for raw_identifier in raw_identifiers:
        encoded = raw_identifier.encode("utf-8")
        assert encoded not in event_payload
        assert encoded not in review_payload
    exchanges = load_exchanges_bytes(event_payload)
    assert len(exchanges) == 1
    exchange = exchanges[0]
    first_raw_session = raw_relations[0]["session_id"]
    first_raw_assignment = raw_relations[0]["assignment_id"]
    assert exchange.envelope.session_alias == expected_sessions[first_raw_session]
    payload_relations = exchange.envelope.payload["tool_response"]["relations"]
    assert {
        item["session_id"] for item in payload_relations
    } == set(expected_sessions.values())
    assert {
        item["assignment_id"] for item in payload_relations
    } == set(expected_assignments.values())
    assert (
        exchange.envelope.payload["tool_response"]["mission_id"]
        == public_mission_id
    )
    response_body = json.loads(exchange.response.response_body)
    assert response_body["metadata"] == {
        "assignment_id": expected_assignments[first_raw_assignment],
        "mission_id": public_mission_id,
        "session_id": expected_sessions[first_raw_session],
    }
    components = exchange.response.review_state["components"]
    public_delta = InterventionRouterDelta.model_validate(
        components["intervention_router_delta"]
    )
    assert {
        item.target_session for item in public_delta.upserts
    } == set(expected_sessions.values())
    selector = DeliverySelectorState.from_record(
        components["delivery_selector_state"],
        run_id=pair.shadow_run_dir.name,
    )
    assert {
        session for session, _ in selector.last_updates
    } == set(expected_sessions.values())

    review_records = load_journal_records(
        review_payload,
        run_id=pair.shadow_run_dir.name,
    )
    projection = next(
        item
        for item in review_records
        if isinstance(item, ExchangeProjectionRecord)
    )
    role_record = next(
        item
        for item in review_records
        if isinstance(item, RoleDecisionRecord)
    )
    extraction = next(
        item
        for item in review_records
        if isinstance(item, ExtractionOutcomeRecord)
    )
    lineage = next(
        item
        for item in review_records
        if isinstance(item, InterventionLineageRecord)
    )
    snapshot = next(
        item
        for item in review_records
        if isinstance(item, FindingSnapshotRecord)
    )
    assert projection.exchange_id == exchange.exchange_id
    assert projection.response_digest == exchange.response.response_digest
    assert lineage.response_digest == exchange.response.response_digest
    assert lineage.delta == public_delta
    expected_role_relation = MissionRelation(
        session_alias=expected_sessions[first_raw_session],
        mission_id=pair.shadow_run_dir.name,
        role_id=raw_relations[0]["role_id"],
        assignment_id=expected_assignments[first_raw_assignment],
        source_digest=raw_relations[0]["source_digest"],
        corroborating_role_ids=tuple(
            raw_relations[0]["corroborating_role_ids"]
        ),
        relation_kind=raw_relations[0]["relation_kind"],
    )
    assert role_record.session_alias == expected_sessions[first_raw_session]
    assert role_record.relations_digest == FrozenMissionRelations(
        pair.shadow_run_dir.name,
        (expected_role_relation,),
    ).digest
    claim_value = extraction.claims[0].value
    assert claim_value["mission_id"] == public_mission_id
    assert {
        item["session_id"] for item in claim_value["sessions"]
    } == set(expected_sessions.values())
    assert {
        item.session_alias for item in extraction.derived_evidence
    } == set(expected_sessions.values())
    assert set(snapshot.findings[0].target_sessions) == set(
        expected_sessions.values()
    )

    pre_evaluation = PreEvaluationRecord.model_validate(
        json.loads(payloads[paths["shadow_pre_evaluation"]])
    )
    preliminary = RunRecord.model_validate(
        json.loads(payloads[paths["shadow_pre_evaluation_run"]])
    )
    run = RunRecord.model_validate(
        json.loads(payloads[paths["shadow_run_record"]])
    )
    assert pre_evaluation.event_ledger_digest == hashlib.sha256(
        event_payload
    ).hexdigest()
    assert pre_evaluation.event_ledger_record_count == len(exchanges)
    assert pre_evaluation.review_journal_digest == hashlib.sha256(
        review_payload
    ).hexdigest()
    assert (
        pre_evaluation.pre_evaluation_run_record_digest
        == preliminary.record_digest
    )
    assert run.pre_evaluation_record_digest == pre_evaluation.record_digest
    assert (
        run.mission_relation_record_digest
        == public_correlation["record_digest"]
    )
    shadow_cleanup = json.loads(
        payloads[paths["shadow_cleanup_attestation"]]
    )
    assert shadow_cleanup["source_record_digest"] == run.record_digest
    assert (
        payloads[paths["baseline_archive"]]
        == pair.baseline_archive.read_bytes()
    )
    assert (
        payloads[paths["shadow_archive"]]
        == pair.shadow_archive.read_bytes()
    )


def test_bundle_rewrites_nested_tool_paths_and_digest_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_root = "/private/tmp/shadow-proof-private/repository"
    private_directory = f"{private_root}/src"
    private_file = f"{private_directory}/webhook.py"
    text_only_posix = "/private/tmp/shadow proof text-only/patch target.py"
    text_only_windows = r"C:\Users\Shadow Reviewer\proof target.py"
    relative_file = "src/webhook.py"
    pair = _pair(
        tmp_path / "pair-source",
        tool_input={
            "file_path": private_file,
            "directory_path": private_directory,
            "workingDirectory": private_directory,
            "path": private_directory,
            "nested": [
                {"filePath": private_file},
                {"file_path": relative_file},
            ],
        },
        response_body_fields={
            "command": (
                f'python {private_file} --root {private_directory}; '
                f'cat "{text_only_posix}"'
            ),
            "input": (
                "*** Begin Patch\n"
                f"*** Update File: {text_only_posix}\n"
                "*** End Patch"
            ),
            "prompt": f'Review "{text_only_windows}" and {private_file}',
            "tool_response": (
                f"Wrote {private_file} from {private_directory}"
            ),
        },
    )
    source_event_payload = (pair.shadow_run_dir / "events.jsonl").read_bytes()
    source_exchange = load_exchanges_bytes(source_event_payload)[0]
    source_review_payload = (pair.shadow_run_dir / "review.jsonl").read_bytes()
    source_review_records = load_journal_records(
        source_review_payload,
        run_id=pair.shadow_run_dir.name,
    )
    source_pre_evaluation = PreEvaluationRecord.model_validate(
        json.loads(
            (pair.shadow_run_dir / "pre-evaluation.json").read_bytes()
        )
    )
    source_run = RunRecord.model_validate(
        json.loads((pair.shadow_run_dir / "run.json").read_bytes())
    )
    source_report = json.loads(pair.report_record.read_bytes())
    source_comparison = json.loads(pair.comparison_record.read_bytes())
    bundle = tmp_path / "path-proof-bundle.tar"

    manifest = build_bundle(pairs=(pair,), output_path=bundle)
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("network used")
        ),
    )
    assert verify_bundle(bundle) == manifest
    payloads = _tar_payloads(bundle)
    paths = manifest["pairs"][0]
    event_payload = payloads[paths["event_ledger"]]
    review_payload = payloads[paths["review_journal"]]
    assert private_root.encode("utf-8") not in event_payload
    assert private_root.encode("utf-8") not in review_payload
    assert text_only_posix.encode("utf-8") not in event_payload
    assert text_only_posix.encode("utf-8") not in review_payload

    exchange = load_exchanges_bytes(event_payload)[0]
    public_input = exchange.envelope.payload["tool_input"]
    public_directory = _expected_public_alias("path", private_directory)
    public_file = _expected_public_alias("path", private_file)
    public_text_posix = _expected_public_alias("path", text_only_posix)
    public_text_windows = _expected_public_alias("path", text_only_windows)
    assert public_input["file_path"] == public_file
    assert public_input["directory_path"] == public_directory
    assert public_input["workingDirectory"] == public_directory
    assert public_input["path"] == public_directory
    assert public_input["nested"][0]["filePath"] == public_file
    assert public_input["nested"][1]["file_path"] == relative_file
    public_body = json.loads(exchange.response.response_body)
    assert public_body["command"] == (
        f"python {public_file} --root {public_directory}; "
        f'cat "{public_text_posix}"'
    )
    assert public_body["input"] == (
        "*** Begin Patch\n"
        f"*** Update File: {public_text_posix}\n"
        "*** End Patch"
    )
    assert public_body["prompt"] == (
        f'Review "{public_text_windows}" and {public_file}'
    )
    assert public_body["tool_response"] == (
        f"Wrote {public_file} from {public_directory}"
    )
    assert (
        exchange.response.request_digest
        == hook_envelope_digest(exchange.envelope)
    )
    assert (
        exchange.response.request_digest
        != source_exchange.response.request_digest
    )
    assert exchange.response.response_id != source_exchange.response.response_id
    assert (
        exchange.response.response_digest
        != source_exchange.response.response_digest
    )
    assert exchange.exchange_id != source_exchange.exchange_id

    review_records = load_journal_records(
        review_payload,
        run_id=pair.shadow_run_dir.name,
    )
    source_projection = next(
        record
        for record in source_review_records
        if isinstance(record, ExchangeProjectionRecord)
    )
    projection = next(
        record
        for record in review_records
        if isinstance(record, ExchangeProjectionRecord)
    )
    assert projection.exchange_id == exchange.exchange_id
    assert projection.response_digest == exchange.response.response_digest
    assert projection.record_digest != source_projection.record_digest
    assert review_records[-1].record_digest != (
        source_review_records[-1].record_digest
    )

    pre_evaluation = PreEvaluationRecord.model_validate(
        json.loads(payloads[paths["shadow_pre_evaluation"]])
    )
    preliminary = RunRecord.model_validate(
        json.loads(payloads[paths["shadow_pre_evaluation_run"]])
    )
    run = RunRecord.model_validate(
        json.loads(payloads[paths["shadow_run_record"]])
    )
    assert pre_evaluation.event_ledger_digest == hashlib.sha256(
        event_payload
    ).hexdigest()
    assert pre_evaluation.review_journal_digest == hashlib.sha256(
        review_payload
    ).hexdigest()
    assert pre_evaluation.record_digest != source_pre_evaluation.record_digest
    assert (
        pre_evaluation.pre_evaluation_run_record_digest
        == preliminary.record_digest
    )
    assert run.pre_evaluation_record_digest == pre_evaluation.record_digest
    assert run.record_digest != source_run.record_digest
    shadow_cleanup = json.loads(
        payloads[paths["shadow_cleanup_attestation"]]
    )
    assert shadow_cleanup["source_record_digest"] == run.record_digest

    report = json.loads(payloads[paths["report_record"]])
    comparison = json.loads(payloads[paths["comparison_record"]])
    assert report["ledger_digest"] == pre_evaluation.event_ledger_digest
    assert (
        report["review_journal_digest"]
        == pre_evaluation.review_journal_digest
    )
    assert report["record_digest"] != source_report["record_digest"]
    assert comparison["shadow_report_digest"] == report["record_digest"]
    assert comparison["shadow_run_record_digest"] == run.record_digest
    assert comparison["record_digest"] != source_comparison["record_digest"]

    member_digests = {
        member["path"]: member["sha256"]
        for member in manifest["members"]
    }
    for name in (
        paths["event_ledger"],
        paths["review_journal"],
        paths["shadow_pre_evaluation_run"],
        paths["shadow_pre_evaluation"],
        paths["shadow_run_record"],
        paths["shadow_cleanup_attestation"],
        paths["report_record"],
        paths["comparison_record"],
    ):
        assert member_digests[name] == hashlib.sha256(payloads[name]).hexdigest()
    manifest_material = dict(manifest)
    manifest_digest = manifest_material.pop("record_digest")
    assert manifest_digest == hashlib.sha256(
        canonical_json(manifest_material)
    ).hexdigest()
    assert (
        payloads[paths["baseline_archive"]]
        == pair.baseline_archive.read_bytes()
    )
    assert (
        payloads[paths["shadow_archive"]]
        == pair.shadow_archive.read_bytes()
    )


def test_structured_alias_rewrite_fails_closed_for_unknown_locations() -> None:
    raw_session = "session-private-identifier"
    aliases = {
        raw_session: _expected_public_alias("session", raw_session),
    }
    rewritten = _rewrite_structured_aliases(
        {"outer": [{"session_id": raw_session}]},
        aliases,
        description="test record",
    )
    assert rewritten["outer"][0]["session_id"] == aliases[raw_session]

    with pytest.raises(ProofBundleError, match="embedded correlation identifier"):
        _rewrite_structured_aliases(
            {"note": f"session={raw_session}"},
            aliases,
            description="test record",
        )
    with pytest.raises(ProofBundleError, match="structured key"):
        _rewrite_structured_aliases(
            {raw_session: "value"},
            aliases,
            description="test record",
        )


def test_structured_alias_rewrite_handles_paths_and_fails_closed() -> None:
    private_directory = "/private/tmp/shadow-proof-private/src"
    private_file = f"{private_directory}/webhook.py"
    relative_file = "src/webhook.py"
    rewritten = _rewrite_structured_aliases(
        {
            "outer": [
                {
                    "file_path": private_file,
                    "directory_path": private_directory,
                    "workingDirectory": private_directory,
                    "path": private_directory,
                    "nested": [
                        {"filePath": private_file},
                        {"file_path": relative_file},
                    ],
                }
            ]
        },
        {},
        description="test record",
    )
    public_directory = _expected_public_alias("path", private_directory)
    public_file = _expected_public_alias("path", private_file)
    assert rewritten["outer"][0]["file_path"] == public_file
    assert rewritten["outer"][0]["directory_path"] == public_directory
    assert rewritten["outer"][0]["workingDirectory"] == public_directory
    assert rewritten["outer"][0]["path"] == public_directory
    assert rewritten["outer"][0]["nested"][0]["filePath"] == public_file
    assert rewritten["outer"][0]["nested"][1]["file_path"] == relative_file

    with pytest.raises(ProofBundleError, match="absolute host path in free text"):
        _rewrite_structured_aliases(
            {"note": f"read {private_file}"},
            {},
            description="test record",
        )
    with pytest.raises(ProofBundleError, match="unsupported structure"):
        _rewrite_structured_aliases(
            {"file_path": [private_file]},
            {},
            description="test record",
        )
    with pytest.raises(ProofBundleError, match="unsupported structure"):
        _rewrite_structured_aliases(
            {"command": [f"cat {private_file}"]},
            {},
            description="test record",
        )
    with pytest.raises(ProofBundleError, match="unsupported structure"):
        _rewrite_structured_aliases(
            {"tool_response": {"note": f"read {private_file}"}},
            {},
            description="test record",
        )
    with pytest.raises(ProofBundleError, match="structured key"):
        _rewrite_structured_aliases(
            {private_file: "value"},
            {},
            description="test record",
        )


@pytest.mark.parametrize("field_name", ("folder", "missionDir"))
def test_structured_alias_rewrite_handles_observed_path_fields(
    field_name: str,
) -> None:
    private_path = "/private/tmp/shadow-proof-private/repository"
    rewritten = _rewrite_structured_aliases(
        {
            field_name: private_path,
            "nested": [{field_name: private_path}],
        },
        {},
        description="test record",
    )
    public_path = _expected_public_alias("path", private_path)

    assert rewritten[field_name] == public_path
    assert rewritten["nested"][0][field_name] == public_path


def test_structured_alias_rewrite_handles_observed_proposal_text() -> None:
    private_path = "/private/tmp/Shadow Proof/src/webhook.py"
    rewritten = _rewrite_structured_aliases(
        {
            "proposal": (
                "*** Begin Patch\n"
                f"*** Update File: {private_path}\n"
                "*** End Patch"
            )
        },
        {},
        description="test record",
    )
    public_path = _expected_public_alias("path", private_path)

    assert rewritten["proposal"] == (
        "*** Begin Patch\n"
        f"*** Update File: {public_path}\n"
        "*** End Patch"
    )


@pytest.mark.parametrize(
    ("field_name", "free_text"),
    (
        ("missionDirectory", False),
        ("patchProposal", True),
    ),
)
def test_structured_alias_rewrite_rejects_unknown_path_fields(
    field_name: str,
    free_text: bool,
) -> None:
    private_path = "/private/tmp/shadow-proof-private/repository"
    value = f"Read {private_path}" if free_text else private_path

    with pytest.raises(ProofBundleError, match="unsupported structure"):
        _rewrite_structured_aliases(
            {field_name: value},
            {},
            description="test record",
        )


def test_structured_alias_rewrite_discovers_paths_in_allowed_text_fields() -> None:
    private_root = "/private/tmp/shadow-proof-private/repository"
    relative_file = "src/webhook.py"
    rewritten = _rewrite_structured_aliases(
        {
            "command": f"cd {private_root}",
            "input": f"root={private_root}",
            "prompt": f"Compare {private_root} with {relative_file}",
            "tool_response": f"Read {private_root}",
        },
        {},
        description="test record",
    )
    public_root = _expected_public_alias("path", private_root)
    assert rewritten["command"] == f"cd {public_root}"
    assert rewritten["input"] == f"root={public_root}"
    assert rewritten["prompt"] == (
        f"Compare {public_root} with {relative_file}"
    )
    assert rewritten["tool_response"] == f"Read {public_root}"


def test_structured_alias_rewrite_handles_quoted_paths_with_spaces() -> None:
    posix_path = "/private/tmp/Shadow Proof/src/webhook.py"
    windows_path = r"C:\Users\Shadow Reviewer\src\webhook.py"
    unc_path = r"\\proof-server\Shadow Share\src\webhook.py"
    rewritten = _rewrite_structured_aliases(
        {
            "command": (
                f'cat "{posix_path}"; '
                f'type "{windows_path}"; '
                f'type "{unc_path}"'
            )
        },
        {},
        description="test record",
    )
    public_posix = _expected_public_alias("path", posix_path)
    public_windows = _expected_public_alias("path", windows_path)
    public_unc = _expected_public_alias("path", unc_path)

    assert rewritten["command"] == (
        f'cat "{public_posix}"; '
        f'type "{public_windows}"; '
        f'type "{public_unc}"'
    )


def test_structured_alias_rewrite_handles_patch_headers_with_spaces() -> None:
    old_path = "/private/tmp/Shadow Proof/src/old webhook.py"
    new_path = "/private/tmp/Shadow Proof/src/new webhook.py"
    rewritten = _rewrite_structured_aliases(
        {
            "input": (
                "*** Begin Patch\n"
                f"*** Update File: {old_path}\n"
                f"--- {old_path}\told\n"
                f"+++ {new_path}\tnew\n"
                "*** End Patch\n"
                f"*** Begin Patch *** Update File: {new_path} "
                "*** End Patch"
            )
        },
        {},
        description="test record",
    )
    public_old = _expected_public_alias("path", old_path)
    public_new = _expected_public_alias("path", new_path)

    assert rewritten["input"] == (
        "*** Begin Patch\n"
        f"*** Update File: {public_old}\n"
        f"--- {public_old}\told\n"
        f"+++ {public_new}\tnew\n"
        "*** End Patch\n"
        f"*** Begin Patch *** Update File: {public_new} "
        "*** End Patch"
    )


def test_structured_alias_rewrite_preserves_shell_punctuation() -> None:
    private_path = "/private/tmp/shadow-proof-private/src/webhook.py"
    rewritten = _rewrite_structured_aliases(
        {
            "command": (
                f"PATH={private_path}:{private_path};"
                f"cat({private_path});"
                f"cp={private_path}|"
                f"tee>{private_path},"
            )
        },
        {},
        description="test record",
    )
    public_path = _expected_public_alias("path", private_path)

    assert rewritten["command"] == (
        f"PATH={public_path}:{public_path};"
        f"cat({public_path});"
        f"cp={public_path}|"
        f"tee>{public_path},"
    )


def test_structured_alias_rewrite_replaces_exact_overlapping_paths() -> None:
    private_directory = "/private/tmp/shadow-proof-private/src"
    private_file = f"{private_directory}/webhook.py"
    embedded_non_path = f"prefix{private_directory}suffix"
    embedded_quoted_non_path = f'prefix"{private_directory}"suffix'
    rewritten = _rewrite_structured_aliases(
        {
            "command": f"cd {private_directory}; cat {private_file}",
            "prompt": (
                f"Keep {embedded_non_path} and "
                f"{embedded_quoted_non_path} unchanged"
            ),
        },
        {},
        description="test record",
    )
    public_directory = _expected_public_alias("path", private_directory)
    public_file = _expected_public_alias("path", private_file)

    assert rewritten["command"] == (
        f"cd {public_directory}; cat {public_file}"
    )
    assert rewritten["prompt"] == (
        f"Keep {embedded_non_path} and "
        f"{embedded_quoted_non_path} unchanged"
    )


def test_structured_alias_rewrite_bounds_discovered_path_tokens() -> None:
    oversized_path = "/" + ("a" * 4097)

    with pytest.raises(ProofBundleError, match="exceeds its bound"):
        _rewrite_structured_aliases(
            {"command": f"cat {oversized_path}"},
            {},
            description="test record",
        )


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (b"source = '/opt/operator/run.json'\n", "absolute host path"),
        (b"\xff\xfe\xfd", "not decodable"),
    ),
)
def test_source_archive_scan_rejects_absolute_paths_and_undecodable_members(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    source_archive = tmp_path / "source.tar"
    _write_tar(source_archive, {"src/module.py": payload})

    with pytest.raises(ProofBundleError, match=message):
        _scan_source_archive(
            "source.tar",
            source_archive,
            excluded_identifier_hashes=frozenset(),
        )


def test_bundle_preserves_refused_comparison_outcome(tmp_path: Path) -> None:
    pair = _pair(tmp_path / "pair-source", include_seeded_chain=False)
    comparison = json.loads(pair.comparison_record.read_bytes())
    bundle = tmp_path / "refused-proof-bundle.tar"

    manifest = build_bundle(pairs=(pair,), output_path=bundle)
    verified = verify_bundle(bundle)

    assert comparison["status"] == "refused"
    assert comparison["refusal_reason"] == (
        "report does not contain the seeded conflict detection"
    )
    assert verified == manifest


def test_bundle_fails_closed_for_missing_member_and_tampered_digest(
    tmp_path: Path,
) -> None:
    pair = _pair(tmp_path / "pair-source")
    bundle = tmp_path / "proof-bundle.tar"
    build_bundle(pairs=(pair,), output_path=bundle)
    payloads = _tar_payloads(bundle)
    manifest = json.loads(payloads["manifest.json"])
    member_name = manifest["pairs"][0]["baseline_evaluation"]

    missing = tmp_path / "missing.tar"
    missing_payloads = dict(payloads)
    missing_payloads.pop(member_name)
    _write_tar(missing, missing_payloads)
    with pytest.raises(ProofBundleError, match="member set differs"):
        verify_bundle(missing)

    tampered = tmp_path / "tampered.tar"
    tampered_payloads = dict(payloads)
    tampered_payloads[member_name] += b"x"
    _write_tar(tampered, tampered_payloads)
    with pytest.raises(ProofBundleError, match="member digest differs"):
        verify_bundle(tampered)

    absent = tmp_path / "absent.json"
    with pytest.raises(ProofBundleError, match="baseline evaluator result is unavailable"):
        build_bundle(
            pairs=(replace(pair, baseline_evaluation=absent),),
            output_path=tmp_path / "incomplete.tar",
        )
    existing = tmp_path / "existing.tar"
    existing.write_bytes(b"owner data")
    with pytest.raises(ProofBundleError, match="bundle output already exists"):
        build_bundle(pairs=(pair,), output_path=existing)
    assert existing.read_bytes() == b"owner data"


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    (
        ("source", "/opt/operator/run.json"),
        ("api_key", "sk-example-value-that-is-not-real"),
        ("approval_id", "approval-private"),
    ),
)
def test_bundle_rejects_other_cleanup_fields_at_build(
    tmp_path: Path,
    field_name: str,
    field_value: str,
) -> None:
    pair = _pair(tmp_path / "pair-source")
    cleanup = tmp_path / "excluded-cleanup.json"
    _canonical(
        cleanup,
        {
            "schema_version": "0.1",
            "subject": "shadow",
            "deleted": True,
            field_name: field_value,
        },
    )

    with pytest.raises(ProofBundleError, match="cleanup attestation schema differs"):
        build_bundle(
            pairs=(replace(pair, shadow_cleanup_attestation=cleanup),),
            output_path=tmp_path / "excluded-build.tar",
        )


def test_bundle_rejects_invalid_cleanup_at_build_and_private_path_at_verify(
    tmp_path: Path,
) -> None:
    pair = _pair(tmp_path / "pair-source")
    private_cleanup = tmp_path / "private-cleanup.json"
    _canonical(
        private_cleanup,
        {
            "schema_version": "0.1",
            "subject": "shadow",
            "deleted": True,
            "source": "/Users/" "operator/private/run.json",
        },
    )
    with pytest.raises(ProofBundleError, match="cleanup attestation schema differs"):
        build_bundle(
            pairs=(replace(pair, shadow_cleanup_attestation=private_cleanup),),
            output_path=tmp_path / "private-build.tar",
        )

    bundle = tmp_path / "proof-bundle.tar"
    build_bundle(pairs=(pair,), output_path=bundle)
    payloads = _tar_payloads(bundle)
    manifest = json.loads(payloads["manifest.json"])
    cleanup_name = manifest["pairs"][0]["shadow_cleanup_attestation"]
    payloads[cleanup_name] = canonical_json(
        {
            "schema_version": "0.1",
            "subject": "shadow",
            "deleted": True,
            "source": "/Users/" "operator/private/run.json",
        }
    ) + b"\n"
    _rewrite_manifest(payloads, cleanup_name)
    injected = tmp_path / "private-verify.tar"
    _write_tar(injected, payloads)

    with pytest.raises(ProofBundleError, match="private path"):
        verify_bundle(injected)


def test_offline_bundle_verification_binds_cleanup_attestations(
    tmp_path: Path,
) -> None:
    pair = _pair(tmp_path / "pair-source")
    bundle = tmp_path / "proof-bundle.tar"
    build_bundle(pairs=(pair,), output_path=bundle)
    original = _tar_payloads(bundle)
    manifest = json.loads(original["manifest.json"])
    baseline_name = manifest["pairs"][0]["baseline_cleanup_attestation"]
    shadow_name = manifest["pairs"][0]["shadow_cleanup_attestation"]

    missing_digest_payloads = dict(original)
    missing_digest = json.loads(missing_digest_payloads[shadow_name])
    missing_digest.pop("record_digest")
    missing_digest_payloads[shadow_name] = canonical_json(missing_digest) + b"\n"
    _rewrite_manifest(missing_digest_payloads, shadow_name)
    missing_digest_bundle = tmp_path / "cleanup-missing-digest.tar"
    _write_tar(missing_digest_bundle, missing_digest_payloads)
    with pytest.raises(ProofBundleError, match="cleanup attestation schema differs"):
        verify_bundle(missing_digest_bundle)

    false_observation_payloads = dict(original)
    false_observation = json.loads(false_observation_payloads[shadow_name])
    false_observation["evaluator_vm_deleted"] = False
    false_observation.pop("record_digest")
    false_observation["record_digest"] = hashlib.sha256(
        canonical_json(false_observation)
    ).hexdigest()
    false_observation_payloads[shadow_name] = (
        canonical_json(false_observation) + b"\n"
    )
    _rewrite_manifest(false_observation_payloads, shadow_name)
    false_observation_bundle = tmp_path / "cleanup-false-observation.tar"
    _write_tar(false_observation_bundle, false_observation_payloads)
    with pytest.raises(ProofBundleError, match="cleanup attestation binding differs"):
        verify_bundle(false_observation_bundle)

    swapped_payloads = dict(original)
    swapped_payloads[baseline_name], swapped_payloads[shadow_name] = (
        swapped_payloads[shadow_name],
        swapped_payloads[baseline_name],
    )
    _rewrite_manifest(swapped_payloads, baseline_name)
    _rewrite_manifest(swapped_payloads, shadow_name)
    swapped_bundle = tmp_path / "cleanup-swapped.tar"
    _write_tar(swapped_bundle, swapped_payloads)
    with pytest.raises(ProofBundleError, match="cleanup attestation binding differs"):
        verify_bundle(swapped_bundle)


def test_offline_bundle_verification_binds_correlation_wrapper(
    tmp_path: Path,
) -> None:
    pair = _pair(tmp_path / "pair-source")
    bundle = tmp_path / "proof-bundle.tar"
    build_bundle(pairs=(pair,), output_path=bundle)
    original = _tar_payloads(bundle)
    manifest = json.loads(original["manifest.json"])
    correlation_name = manifest["pairs"][0]["correlation_record"]

    missing_digest_payloads = dict(original)
    missing_digest = json.loads(missing_digest_payloads[correlation_name])
    missing_digest.pop("record_digest")
    missing_digest_payloads[correlation_name] = canonical_json(missing_digest) + b"\n"
    _rewrite_manifest(missing_digest_payloads, correlation_name)
    missing_digest_bundle = tmp_path / "correlation-missing-digest.tar"
    _write_tar(missing_digest_bundle, missing_digest_payloads)
    with pytest.raises(ProofBundleError, match="correlation record is invalid"):
        verify_bundle(missing_digest_bundle)

    extra_identifier_payloads = dict(original)
    extra_identifier = json.loads(extra_identifier_payloads[correlation_name])
    extra_identifier["factory_session_id"] = "unlisted-raw-session"
    extra_identifier.pop("record_digest")
    extra_identifier["record_digest"] = hashlib.sha256(
        canonical_json(extra_identifier)
    ).hexdigest()
    extra_identifier_payloads[correlation_name] = (
        canonical_json(extra_identifier) + b"\n"
    )
    _rewrite_manifest(extra_identifier_payloads, correlation_name)
    extra_identifier_bundle = tmp_path / "correlation-extra-identifier.tar"
    _write_tar(extra_identifier_bundle, extra_identifier_payloads)
    with pytest.raises(ProofBundleError, match="correlation record is invalid"):
        verify_bundle(extra_identifier_bundle)


def test_offline_bundle_verification_preserves_working_tree_binding(
    tmp_path: Path,
) -> None:
    pair = _pair(tmp_path / "pair-source")
    bundle = tmp_path / "proof-bundle.tar"
    build_bundle(pairs=(pair,), output_path=bundle)
    payloads = _tar_payloads(bundle)
    manifest = json.loads(payloads["manifest.json"])
    baseline_name = manifest["pairs"][0]["baseline_record"]
    evaluation_name = manifest["pairs"][0]["baseline_evaluation"]

    evaluation = json.loads(payloads[evaluation_name])
    evaluation["working_tree_digest"] = "f" * 64
    evaluation.pop("record_digest")
    evaluation["record_digest"] = hashlib.sha256(
        canonical_json(evaluation)
    ).hexdigest()
    baseline = json.loads(payloads[baseline_name])
    baseline["evaluator_outcome"] = evaluation
    baseline.pop("record_digest")
    baseline["record_digest"] = hashlib.sha256(canonical_json(baseline)).hexdigest()
    payloads[evaluation_name] = canonical_json(evaluation) + b"\n"
    payloads[baseline_name] = canonical_json(baseline) + b"\n"
    _rewrite_manifest(payloads, evaluation_name)
    _rewrite_manifest(payloads, baseline_name)
    tampered = tmp_path / "working-tree-tampered.tar"
    _write_tar(tampered, payloads)

    with pytest.raises(ProofBundleError, match="baseline source binding differs"):
        verify_bundle(tampered)
