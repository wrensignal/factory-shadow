from __future__ import annotations

import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from shadow_mission.evidence import FrozenEvidenceRegistry
from shadow_mission.graph import GraphError, MissionGraph
from shadow_mission.extractor import (
    ApprovedMilestoneLink,
    ApprovedMissionCriterion,
    BoundaryMetadata,
    BrokerAttempt,
    ClaimExtractor,
    RecordedExtractionBroker,
)
from shadow_mission.protocol import (
    CapabilityFlags,
    ClaimRecord,
    EvidenceRecord,
    canonical_json,
    HookEnvelope,
    hook_envelope_digest,
)
from shadow_mission.storage import EventLedger, LedgerError, ResponsePlan
from shadow_mission.roles import RoleDecision
from shadow_mission.rules import (
    DeliverySelector,
    DeliverySelectorState,
    DeterministicRules,
    EvidenceAuthority,
    ProbeAssessment,
    ProbeVerifier,
    classify_evidence_authority,
    normalize_locator,
    normalize_property,
    normalize_unit,
    normalize_value,
    resolve_evidence_authority,
)

_FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "replay"
_PROBE_SIGNING_KEY = b"phase-three-independent-probe-test-key"
_PROBE_BOUNDARY_DIGEST = "9" * 64
_PROBE_SNAPSHOT_DIGEST = "7" * 64
_PROBE_VERIFIER = ProbeVerifier(
    _PROBE_SIGNING_KEY, boundary_digest=_PROBE_BOUNDARY_DIGEST
)
_FIXTURE_NAMES = frozenset(
    {
        "cross-worker-conflict",
        "shared-assumption",
        "validation-overlap",
        "same-value-authoritative",
        "independent-validator",
        "no-material-risk",
    }
)
_POSITIVE_FIXTURES = (
    ("cross-worker-conflict", "cross_worker_conflict"),
    ("shared-assumption", "shared_assumption"),
    ("validation-overlap", "validation_overlap"),
)


def load_replay(name: str) -> dict[str, Any]:
    if name not in _FIXTURE_NAMES:
        raise ValueError("unknown sealed replay fixture")
    root = _FIXTURE_ROOT.resolve()
    path = (root / f"{name}.json").resolve()
    if path.parent != root:
        raise ValueError("replay fixture escaped its sealed root")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("replay fixture must be an object")
    return value


def replay_graph(value: dict[str, Any]) -> MissionGraph:
    graph = MissionGraph(value["run_id"])
    for item in value["roles"]:
        graph.add_role_decision(
            RoleDecision(
                session_alias=item["session_alias"],
                role_id=item["role_id"],
                kind=item["kind"],
                confidence=item["confidence"],
                status="assigned",
                reason="sealed replay relation",
                evidence_digests=("0" * 64,),
            )
        )
    for item in value["evidence"]:
        graph.add_evidence(EvidenceRecord.model_validate(item))
    milestone_ids: dict[str, list[str]] = {}
    for link in value["links"]:
        milestone_ids.setdefault(link["claim_id"], []).append(
            link["milestone_id"]
        )
    for item in value["milestones"]:
        graph.add_milestone(item["milestone_id"], item["attributes"])
    for item in value["claims"]:
        record = ClaimRecord.model_validate(item).model_copy(
            update={
                "milestone_ids": tuple(
                    sorted(milestone_ids.get(item["claim_id"], ()))
                )
            }
        )
        graph.add_claim(record)
    return graph


def fixture_graph(name: str) -> MissionGraph:
    return replay_graph(load_replay(name))


def extracted_replay_graph(name: str) -> MissionGraph:
    value = load_replay(name)
    graph = MissionGraph(value["run_id"])
    for item in value["roles"]:
        graph.add_role_decision(
            RoleDecision(
                session_alias=item["session_alias"],
                role_id=item["role_id"],
                kind=item["kind"],
                confidence=item["confidence"],
                status="assigned",
                reason="sealed replay relation",
                evidence_digests=("0" * 64,),
            )
        )
    evidence_by_session: dict[str, list[EvidenceRecord]] = {}
    for item in value["evidence"]:
        record = EvidenceRecord.model_validate(item)
        graph.add_evidence(record)
        evidence_by_session.setdefault(record.session_alias, []).append(record)
    for item in value["milestones"]:
        graph.add_milestone(item["milestone_id"], item["attributes"])
    milestone_ids: dict[str, list[str]] = {}
    for link in value["links"]:
        milestone_ids.setdefault(link["claim_id"], []).append(
            link["milestone_id"]
        )

    for item in value["claims"]:
        raw = {
            key: item[key]
            for key in (
                "subject",
                "subject_locator",
                "property",
                "value",
                "unit",
                "confidence",
                "evidence_ids",
                "targets",
            )
            if key in item
        }
        session = item["session_alias"]
        broker = RecordedExtractionBroker(
            BrokerAttempt(
                boundary=BoundaryMetadata(
                    factory_home="clean",
                    timeout_seconds=30,
                    shadow_activation_stripped=True,
                    mission_correlation_stripped=True,
                    internal_session_alias=f"extractor-{session}",
                ),
                output=[raw],
            )
        )
        envelope = HookEnvelope(provenance_status="hook_authenticated",
        redaction_status="clean",
        event_id=f"completion-{item['claim_id']}",
        source_fingerprint=f"source-{session}",
        run_id=value["run_id"],
        session_alias=session,
        transcript_alias=f"transcript-{session}",
        hook_event_name="Stop", observed_at=item["observed_at"], message_digest="d" * 64, payload={},)
        linked_ids = tuple(
            sorted(milestone_ids.get(item["claim_id"], ()))
        )
        links = (
            (
                ApprovedMilestoneLink(
                    run_id=value["run_id"],
                    relation_id=f"relation-{item['claim_id']}",
                    locator=item["subject_locator"],
                    milestone_ids=linked_ids,
                ),
            )
            if linked_ids
            else ()
        )
        outcome = ClaimExtractor(broker).extract(
            envelope,
            tuple(evidence_by_session[session]),
            approved_milestone_links=links,
        )
        assert outcome.quarantine is None
        assert len(outcome.claims) == 1
        graph.add_claim(outcome.claims[0])
    return graph


def probe_for(
    finding: Any,
    *,
    status: str = "confirmed",
    risk_category: str = "security",
    recommended_level: str = "blocker",
    run_id: str = "run-replay",
) -> ProbeAssessment:
    return ProbeAssessment.create(
        probe_id=f"probe-{finding.finding_id}",
        run_id=run_id,
        finding_dedup_key=finding.dedup_key,
        claim_ids=finding.claim_ids,
        evidence_digests=finding.evidence_digests,
        risk_category=risk_category,
        recommended_level=recommended_level,
        status=status,
        authoritative_value=(
            normalize_value("authoritative") if status == "confirmed" else None
        ),
        snapshot_digest=_PROBE_SNAPSHOT_DIGEST,
        boundary_digest=_PROBE_BOUNDARY_DIGEST,
        boundary_policy_digest=_PROBE_BOUNDARY_DIGEST,
        signing_key=_PROBE_SIGNING_KEY,
        observed_at=100,
    )


def capabilities(*, overlap: str) -> CapabilityFlags:
    return CapabilityFlags(
        core_feasibility_verdict="pass",
        release_gate_verdict="fallback-pass",
        droid_version="0.197.0",
        plugin_version="0.1.0",
        droid_sdk_version="0.2.0",
        lima_version="2.2.0",
        vm_image_digest="1" * 64,
        factory_profile_digest="2" * 64,
        isolation_digest="3" * 64,
        gate_surface_digest="4" * 64,
        installed_plugin_artifact_digest="5" * 64,
        transport_integrity="pass",
        hook_provenance="fallback",
        session_hooks="pass",
        identity="pass",
        transcript="pass",
        guidance="pass",
        worker_block="pass",
        mission_block="pass",
        worker_roles="pass",
        validator_roles="fallback",
        self_session_exclusion="pass",
        sandbox_isolation="pass",
        probe_boundary="pass",
        live_validation_overlap=overlap,
    )


def fallback_extracted_graph(kind: str) -> MissionGraph:
    run_id = f"run-fallback-{kind}"
    if kind == "validation":
        actors = (("worker-a", "worker"), ("validator-a", "validator"))
        values = ("passed", "passed")
        locator = "tests/test_checkout.py::test_total"
        property_name = "validation result"
        units: tuple[str | None, ...] = (None, None)
    elif kind == "shared":
        actors = (("worker-a", "worker"), ("worker-b", "worker"))
        values = (3, 3)
        locator = "docs/guide.md#retry-limit"
        property_name = "maximum retries"
        units = ("count", "items")
    else:
        actors = (("worker-a", "worker"), ("worker-b", "worker"))
        values = ("cents", "dollars")
        locator = "api-schema.json#/amount"
        property_name = "storage unit"
        units = ("cents", "cents")

    prepared: list[
        tuple[int, str, str, object, str | None, tuple[EvidenceRecord, ...]]
    ] = []
    all_evidence: list[EvidenceRecord] = []
    for position, ((session, role), value, unit) in enumerate(
        zip(actors, values, units, strict=True),
        start=1,
    ):
        source = EvidenceRecord(
            provenance_status="independent_frozen",
            redaction_status="clean",
            evidence_id=f"source-{session}",
            run_id=run_id,
            session_alias=session,
            kind="test_use" if kind == "validation" else "claim_source",
            source="factory_transcript",
            locator=locator,
            digest=f"{position}" * 64,
            observed_at=position,
        )
        evidence_items = [source]
        if kind == "shared":
            evidence_items.append(
                EvidenceRecord(
                    provenance_status="independent_frozen",
                    redaction_status="clean",
                    evidence_id=f"target-{session}",
                    run_id=run_id,
                    session_alias=session,
                    kind="changed_file",
                    source="factory_observation",
                    locator=f"src/{session}.py",
                    digest=f"{position + 2}" * 64,
                    observed_at=position,
                )
            )
        frozen_items = tuple(evidence_items)
        all_evidence.extend(frozen_items)
        prepared.append((position, session, role, value, unit, frozen_items))

    manifest = {
        "schema_version": "0.1",
        "evidence": [
            {
                "evidence_id": item.evidence_id,
                "run_id": item.run_id,
                "session_alias": item.session_alias,
                "kind": item.kind,
                "source": item.source,
                "locator": item.locator,
                "digest": item.digest,
                "redaction_status": item.redaction_status,
                "observed_at": item.observed_at,
            }
            for item in sorted(all_evidence, key=lambda value: value.evidence_id)
        ],
    }
    registry = FrozenEvidenceRegistry.from_records(
        all_evidence,
        expected_digest=hashlib.sha256(canonical_json(manifest)).hexdigest(),
    )
    graph = MissionGraph(run_id, frozen_evidence_registry=registry)
    if kind == "validation":
        graph.add_milestone("milestone-checkout", {"name": "checkout"})

    for position, session, role, value, unit, evidence_items in prepared:
        graph.add_role_decision(
            RoleDecision(
                session_alias=session,
                role_id=f"role-{session}",
                kind=role,
                confidence="high",
                status="assigned",
                reason="frozen Factory observation",
                evidence_digests=("0" * 64,),
            )
        )
        bound_items = tuple(registry.bind(item) for item in evidence_items)
        targets = (
            [
                {
                    "kind": "file",
                    "target_id": bound_items[1].locator,
                    "evidence_id": bound_items[1].evidence_id,
                    "attributes": {},
                }
            ]
            if kind == "shared"
            else []
        )
        raw = {
            "subject": "recorded value",
            "subject_locator": locator,
            "property": property_name,
            "value": value,
            "unit": unit,
            "confidence": 0.95,
            "evidence_ids": [record.evidence_id for record in bound_items],
            "targets": targets,
        }
        broker = RecordedExtractionBroker(
            BrokerAttempt(
                boundary=BoundaryMetadata(
                    factory_home="clean",
                    timeout_seconds=30,
                    shadow_activation_stripped=True,
                    mission_correlation_stripped=True,
                    internal_session_alias=f"extractor-{session}",
                ),
                output=[raw],
            )
        )
        event = HookEnvelope(provenance_status="untrusted_provenance",
        redaction_status="clean",
        event_id=f"event-{session}",
        source_fingerprint=f"source-{session}",
        run_id=run_id,
        session_alias=session,
        transcript_alias=f"transcript-{session}",
        hook_event_name="Stop", observed_at=position + 10, message_digest="d" * 64, payload={},)
        links = (
            ApprovedMilestoneLink(
                run_id=run_id,
                relation_id=f"relation-{session}",
                locator=locator,
                milestone_ids=("milestone-checkout",),
            ),
        ) if kind == "validation" else ()
        outcome = ClaimExtractor(
            broker,
            frozen_evidence_registry=registry,
        ).extract(
            event,
            bound_items,
            approved_milestone_links=links,
        )
        assert outcome.quarantine is None
        for record in bound_items:
            graph.add_evidence(record)
        graph.add_claim(outcome.claims[0])
    return graph


def test_fallback_independent_chain_detects_worker_rules() -> None:
    for kind, expected_rule in (
        ("conflict", "cross_worker_conflict"),
        ("shared", "shared_assumption"),
    ):
        findings = DeterministicRules(
            capabilities=capabilities(overlap="fallback")
        ).detect(fallback_extracted_graph(kind))
        assert tuple(item.rule for item in findings) == (expected_rule,)


def test_fallback_independent_chain_disables_only_live_overlap_delivery() -> None:
    graph = fallback_extracted_graph("validation")
    evaluation = DeterministicRules(
        capabilities=capabilities(overlap="fallback")
    ).evaluate(
        graph,
        updated_session="validator-a",
        stored_update=1,
    )

    assert tuple(item.rule for item in evaluation.matches) == (
        "validation_overlap",
    )
    assert evaluation.deliveries == ()
    assert evaluation.validation_overlap_status == "disabled_by_role_fallback"



def test_redacted_authenticated_evidence_remains_visible_to_rules() -> None:
    value = copy.deepcopy(load_replay("cross-worker-conflict"))
    for item in value["evidence"]:
        item["redaction_status"] = "redacted"
    for item in value["claims"]:
        item["redaction_status"] = "redacted"

    findings = DeterministicRules().detect(replay_graph(value))

    assert tuple(item.rule for item in findings) == ("cross_worker_conflict",)



def test_cross_worker_conflict_targets_the_owning_orchestrator() -> None:
    graph = fixture_graph("cross-worker-conflict")
    graph.add_role_decision(
        RoleDecision(
            session_alias="orchestrator",
            role_id="orchestrator:1",
            kind="orchestrator",
            confidence="high",
            status="assigned",
            reason="sealed replay relation",
            evidence_digests=("0" * 64,),
        )
    )

    finding = DeterministicRules().detect(graph)[0]

    assert finding.target_sessions == ("orchestrator", "worker-a", "worker-b")

def test_validator_new_evidence_at_distinct_locator_is_independent() -> None:
    value = copy.deepcopy(load_replay("validation-overlap"))
    value["evidence"].append(
        {
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "evidence_id": "validator-independent-command",
            "run_id": "run-replay",
            "session_alias": "validator-a",
            "kind": "command",
            "source": "unit_test",
            "locator": "pytest tests/test_refund.py::test_refund",
            "digest": "7" * 64,
            "observed_at": 5,
        }
    )
    value["claims"][1]["evidence_ids"].append(
        "validator-independent-command"
    )

    assert DeterministicRules().detect(replay_graph(value)) == ()


def _shared_assumption_with_second_source() -> dict[str, Any]:
    value = copy.deepcopy(load_replay("shared-assumption"))
    for index, session in enumerate(("worker-a", "worker-b")):
        evidence_id = f"assumption-second-source-{session}"
        value["evidence"].append(
            {
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "evidence_id": evidence_id,
                "run_id": "run-replay",
                "session_alias": session,
                "kind": "claim_source",
                "source": "secondary_guide",
                "locator": "docs/guide.md#retry-limit",
                "digest": str(index + 1) * 64,
                "observed_at": 7 + index,
            }
        )
        value["claims"][index]["evidence_ids"] = sorted(
            (*value["claims"][index]["evidence_ids"], evidence_id)
        )
    return value


def test_shared_assumption_identity_stays_stable_as_evidence_grows() -> None:
    baseline = DeterministicRules().detect(
        replay_graph(load_replay("shared-assumption"))
    )[0]
    findings = DeterministicRules().detect(
        replay_graph(_shared_assumption_with_second_source())
    )
    matching = tuple(
        finding
        for finding in findings
        if finding.dedup_key == baseline.dedup_key
    )

    assert len(matching) == 1
    assert set(baseline.evidence_ids) < set(matching[0].evidence_ids)
    assert set(matching[0].evidence_ids) == {
        *baseline.evidence_ids,
        "assumption-second-source-worker-a",
        "assumption-second-source-worker-b",
    }


def test_shared_assumption_distinct_sources_have_distinct_identities() -> None:
    findings = DeterministicRules().detect(
        replay_graph(_shared_assumption_with_second_source())
    )

    assert len(findings) == 2
    assert {finding.claim_ids for finding in findings} == {
        ("assumption-claim-a", "assumption-claim-b")
    }
    assert len({finding.dedup_key for finding in findings}) == 2


def test_shared_finding_binds_distinct_material_target_evidence() -> None:
    value = load_replay("shared-assumption")
    finding = DeterministicRules().detect(replay_graph(value))[0]
    mutated = copy.deepcopy(value)
    target = next(
        item
        for item in mutated["evidence"]
        if item["evidence_id"] == "assumption-target-b"
    )
    target["locator"] = "src/retry_other.py"
    mutated["claims"][1]["targets"][0]["target_id"] = "src/retry_other.py"
    changed = DeterministicRules().detect(replay_graph(mutated))[0]

    assert finding.evidence_ids == (
        "assumption-source-a",
        "assumption-source-b",
        "assumption-target-a",
        "assumption-target-b",
    )
    assert finding.dedup_key != changed.dedup_key

@pytest.mark.parametrize(
    ("fixture_name", "expected_rule"),
    [
        ("cross-worker-conflict", "cross_worker_conflict"),
        ("shared-assumption", "shared_assumption"),
        ("validation-overlap", "validation_overlap"),
        ("same-value-authoritative", None),
        ("independent-validator", None),
        ("no-material-risk", None),
    ],
)
def test_all_named_replays_exercise_real_graph_rule_chain(
    fixture_name: str, expected_rule: str | None
) -> None:
    findings = DeterministicRules().detect(extracted_replay_graph(fixture_name))

    assert tuple(item.rule for item in findings) == (
        (expected_rule,) if expected_rule else ()
    )


@pytest.mark.parametrize(("fixture_name", "expected_rule"), _POSITIVE_FIXTURES)
def test_each_rule_rejects_claims_without_direct_evidence(
    fixture_name: str, expected_rule: str
) -> None:
    value = copy.deepcopy(load_replay(fixture_name))
    value["evidence"][0]["locator"] = "unrelated/source#value"
    value["claims"][0]["targets"] = []

    findings = DeterministicRules().detect(replay_graph(value))

    assert expected_rule not in {item.rule for item in findings}


@pytest.mark.parametrize(("fixture_name", "expected_rule"), _POSITIVE_FIXTURES)
def test_each_rule_rejects_low_confidence_role_attribution(
    fixture_name: str, expected_rule: str
) -> None:
    value = copy.deepcopy(load_replay(fixture_name))
    value["roles"][0]["confidence"] = "low"

    findings = DeterministicRules().detect(replay_graph(value))

    assert expected_rule not in {item.rule for item in findings}


@pytest.mark.parametrize(("fixture_name", "expected_rule"), _POSITIVE_FIXTURES)
def test_each_rule_rejects_low_confidence_claims(
    fixture_name: str, expected_rule: str
) -> None:
    value = copy.deepcopy(load_replay(fixture_name))
    value["claims"][0]["confidence"] = 0.79

    findings = DeterministicRules().detect(replay_graph(value))

    assert expected_rule not in {item.rule for item in findings}


@pytest.mark.parametrize(("fixture_name", "expected_rule"), _POSITIVE_FIXTURES)
def test_each_rule_accepts_claim_confidence_boundary(
    fixture_name: str, expected_rule: str
) -> None:
    value = copy.deepcopy(load_replay(fixture_name))
    for claim_value in value["claims"]:
        claim_value["confidence"] = 0.8

    findings = DeterministicRules().detect(replay_graph(value))

    assert expected_rule in {item.rule for item in findings}


@pytest.mark.parametrize(
    ("fixture_name", "expected_rule"),
    (
        ("cross-worker-conflict", "cross_worker_conflict"),
        ("shared-assumption", "shared_assumption"),
    ),
)
def test_worker_rules_require_distinct_authoritative_role_ids(
    fixture_name: str, expected_rule: str
) -> None:
    value = copy.deepcopy(load_replay(fixture_name))
    value["roles"][1]["role_id"] = value["roles"][0]["role_id"]

    findings = DeterministicRules().detect(replay_graph(value))

    assert expected_rule not in {item.rule for item in findings}


@pytest.mark.parametrize(("fixture_name", "expected_rule"), _POSITIVE_FIXTURES)
def test_each_rule_has_stable_exact_deduplication(
    fixture_name: str, expected_rule: str
) -> None:
    graph = fixture_graph(fixture_name)
    engine = DeterministicRules(live_validation_overlap=True)
    first = engine.detect(graph)
    second = engine.detect(graph)
    target = first[0].target_sessions[0]

    assert first == second
    assert first[0].rule == expected_rule
    assert len(first[0].dedup_key) == 64
    initial = engine.evaluate(graph, updated_session=target, stored_update=1)
    assert len(initial.deliveries) == 1
    initial.commit()
    for stored_update in range(2, 6):
        evaluation = engine.evaluate(
            graph, updated_session=target, stored_update=stored_update
        )
        assert evaluation.matches == first
        assert evaluation.deliveries == ()
        evaluation.commit()


@pytest.mark.parametrize(("fixture_name", "expected_rule"), _POSITIVE_FIXTURES)
def test_each_rule_suppresses_exactly_three_following_stored_updates(
    fixture_name: str, expected_rule: str
) -> None:
    finding = DeterministicRules().detect(fixture_graph(fixture_name))[0]
    assert finding.rule == expected_rule
    later_key = hashlib.sha256(f"{finding.dedup_key}:later".encode()).hexdigest()
    later = replace(
        finding,
        finding_id=f"finding-{later_key[:24]}",
        dedup_key=later_key,
    )
    selector = DeliverySelector()
    target = finding.target_sessions[0]

    assert len(
        selector.select((finding,), updated_session=target, stored_update=1)
    ) == 1
    for stored_update in range(2, 5):
        assert (
            selector.select(
                (later,),
                updated_session=target,
                stored_update=stored_update,
            )
            == ()
        )
    delivery = selector.select(
        (later,), updated_session=target, stored_update=5
    )

    assert len(delivery) == 1
    assert delivery[0].stored_update == 5


@pytest.mark.parametrize(("fixture_name", "expected_rule"), _POSITIVE_FIXTURES)
def test_each_rule_escalates_only_after_the_full_cooldown(
    fixture_name: str, expected_rule: str
) -> None:
    graph = fixture_graph(fixture_name)
    engine = DeterministicRules(
        live_validation_overlap=True, probe_verifier=_PROBE_VERIFIER
    )
    concern = engine.detect(graph)[0]
    target = concern.target_sessions[0]
    first = engine.evaluate(graph, updated_session=target, stored_update=1)
    assert first.deliveries[0].finding.level == "concern"
    first.commit()
    probe = probe_for(concern)

    for stored_update in range(2, 5):
        suppressed = engine.evaluate(
            graph,
            updated_session=target,
            stored_update=stored_update,
            probes=(probe,),
        )
        assert suppressed.matches[0].level == "blocker"
        assert suppressed.deliveries == ()
        suppressed.commit()
    escalated = engine.evaluate(
        graph, updated_session=target, stored_update=5, probes=(probe,)
    )

    assert escalated.matches[0].rule == expected_rule
    assert escalated.matches[0].level == "blocker"
    assert escalated.matches[0].probe_id == probe.probe_id
    assert escalated.deliveries[0].finding.level == "blocker"
    escalated.commit()
    still_visible = engine.evaluate(
        graph, updated_session=target, stored_update=6, probes=(probe,)
    )
    assert still_visible.matches[0].level == "blocker"
    assert still_visible.deliveries == ()
    still_visible.commit()


@pytest.mark.parametrize("status", ["missing", "pending", "rejected", "inconclusive"])
def test_unconfirmed_probe_status_never_blocks(status: str) -> None:
    graph = fixture_graph("cross-worker-conflict")
    finding = DeterministicRules().detect(graph)[0]
    probe = probe_for(finding, status=status, risk_category="money")

    evaluated = DeterministicRules(
        probe_verifier=_PROBE_VERIFIER
    ).detect(graph, probes=(probe,))

    assert evaluated[0].level == "concern"


def test_confirmed_noncritical_probe_never_blocks() -> None:
    graph = fixture_graph("cross-worker-conflict")
    finding = DeterministicRules().detect(graph)[0]
    probe = probe_for(finding, risk_category="none")

    evaluated = DeterministicRules(
        probe_verifier=_PROBE_VERIFIER
    ).detect(graph, probes=(probe,))

    assert evaluated[0].level == "concern"


def test_confirmed_critical_probe_cannot_exceed_concern_recommendation() -> None:
    graph = fixture_graph("cross-worker-conflict")
    finding = DeterministicRules().detect(graph)[0]
    probe = probe_for(
        finding,
        risk_category="security",
        recommended_level="concern",
    )

    evaluated = DeterministicRules(
        probe_verifier=_PROBE_VERIFIER
    ).detect(graph, probes=(probe,))

    assert evaluated[0].probe_status == "confirmed"
    assert evaluated[0].risk_category == "security"
    assert evaluated[0].level == "concern"


def test_normalization_preserves_case_and_json_type_without_numeric_coercion() -> None:
    assert normalize_locator(" ＳRC/Pay.PY  # Amount ") == "src/pay.py # amount"
    assert normalize_property(" Storage   Unit ") == "storage unit"
    assert normalize_unit("USD   CENTS") == "cents"
    assert normalize_value(" Ｔoken  Value ") == normalize_value("Token Value")
    assert normalize_value("Token") != normalize_value("token")
    assert normalize_value("1") != normalize_value(1)
    assert normalize_value(True) != normalize_value(1)


def test_unknown_unit_spelling_does_not_match() -> None:
    value = copy.deepcopy(load_replay("cross-worker-conflict"))
    for claim in value["claims"]:
        claim["unit"] = "credits"

    assert DeterministicRules().detect(replay_graph(value)) == ()


def test_same_authority_conflict_stays_unresolved() -> None:
    finding = DeterministicRules().detect(
        fixture_graph("cross-worker-conflict")
    )[0]

    assert finding.authority.authority == EvidenceAuthority.AUTHORITATIVE
    assert finding.authority.status == "unresolved_same_authority"
    assert finding.authority.normalized_value is None


def test_evidence_authority_has_explicit_fixed_precedence() -> None:
    value = load_replay("cross-worker-conflict")
    schema = EvidenceRecord.model_validate(value["evidence"][0])
    unit = schema.model_copy(update={"source": "unit_test", "kind": "test"})
    integration = schema.model_copy(
        update={"source": "integration_test", "kind": "test"}
    )
    prose = schema.model_copy(update={"source": "prose_guide", "kind": "code_use"})

    assert classify_evidence_authority(schema) == EvidenceAuthority.AUTHORITATIVE
    assert classify_evidence_authority(integration) == EvidenceAuthority.INTEGRATION_VALIDATION
    assert classify_evidence_authority(unit) == EvidenceAuthority.ISOLATED_VALIDATION
    assert classify_evidence_authority(prose) == EvidenceAuthority.UNKNOWN
    resolved = resolve_evidence_authority(
        (
            (normalize_value("cents"), schema),
            (normalize_value("dollars"), prose),
        )
    )
    assert resolved.status == "resolved"
    assert resolved.normalized_value == normalize_value("cents")


def test_explicit_absent_authority_is_safe_shared_source_marker() -> None:
    value = copy.deepcopy(load_replay("shared-assumption"))
    for evidence in value["evidence"]:
        evidence["source"] = "absent_authority"

    findings = DeterministicRules().detect(replay_graph(value))

    assert tuple(item.rule for item in findings) == ("shared_assumption",)


def test_target_sessions_have_independent_delivery_cooldowns() -> None:
    finding = DeterministicRules().detect(
        fixture_graph("cross-worker-conflict")
    )[0]
    selector = DeliverySelector()

    first = selector.select(
        (finding,), updated_session="worker-a", stored_update=1
    )
    second = selector.select(
        (finding,), updated_session="worker-b", stored_update=1
    )

    assert first[0].target_session == "worker-a"
    assert second[0].target_session == "worker-b"



def test_priority_is_level_then_rule_then_stable_key_and_selects_one() -> None:
    conflict = DeterministicRules().detect(fixture_graph("cross-worker-conflict"))[0]
    shared = DeterministicRules().detect(fixture_graph("shared-assumption"))[0]
    target = "worker-a"
    shared_blocker = replace(
        shared,
        level="blocker",
        risk_category="money",
        probe_status="confirmed",
    )

    blocker_first = DeliverySelector().select(
        (conflict, shared_blocker), updated_session=target, stored_update=1
    )
    rule_first = DeliverySelector().select(
        (shared, conflict), updated_session=target, stored_update=1
    )

    assert len(blocker_first) == 1
    assert blocker_first[0].finding.rule == "shared_assumption"
    assert len(rule_first) == 1
    assert rule_first[0].finding.rule == "cross_worker_conflict"
    note = replace(conflict, level="note")
    concern_before_note = DeliverySelector().select(
        (note, conflict), updated_session=target, stored_update=1
    )
    low_key = replace(
        conflict,
        finding_id="finding-low-key",
        dedup_key="0" * 64,
    )
    high_key = replace(
        conflict,
        finding_id="finding-high-key",
        dedup_key="f" * 64,
    )
    stable_key_first = DeliverySelector().select(
        (high_key, low_key), updated_session=target, stored_update=1
    )
    assert concern_before_note[0].finding.level == "concern"
    assert stable_key_first[0].finding.dedup_key == "0" * 64


def test_priority_ranks_updated_session_dissent_before_coverage_and_key() -> None:
    value = copy.deepcopy(load_replay("cross-worker-conflict"))
    value["evidence"][1]["kind"] = "claim_source"
    value["evidence"][1]["source"] = "worker_note"
    graph = replay_graph(value)
    dissenting = DeterministicRules().detect(graph)[0]
    agreeing_evidence = EvidenceRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        evidence_id="agreeing-evidence-worker-b",
        run_id="run-replay",
        session_alias="worker-b",
        kind="claim_source",
        source="worker_note",
        locator="api-schema.json#/amount",
        digest="c" * 64,
        observed_at=5,
    )
    graph.add_evidence(agreeing_evidence)
    graph.add_claim(
        ClaimRecord(
            provenance_status="hook_authenticated",
            redaction_status="clean",
            claim_id="agreeing-claim-worker-b",
            run_id="run-replay",
            session_alias="worker-b",
            subject="amount",
            subject_locator="api-schema.json#/amount",
            property="storage unit",
            value="cents",
            unit="cents",
            confidence=0.95,
            evidence_ids=(agreeing_evidence.evidence_id,),
            observed_at=6,
        )
    )
    agreeing = replace(
        dissenting,
        finding_id="finding-agreeing",
        dedup_key="0" * 64,
        claim_ids=("agreeing-claim-worker-b", "conflict-claim-a"),
    )
    selector = DeliverySelector()

    started = selector.select(
        (agreeing,),
        updated_session="worker-a",
        stored_update=1,
        graph=graph,
    )
    selected = selector.select(
        (agreeing, dissenting),
        updated_session="worker-b",
        stored_update=1,
        graph=graph,
    )

    assert dissenting.authority.normalized_value == normalize_value("cents")
    assert started[0].finding.dedup_key == agreeing.dedup_key
    assert selected[0].finding.dedup_key == dissenting.dedup_key



def test_capability_fallback_disables_only_live_validation_overlap() -> None:
    flags = capabilities(overlap="fallback")
    graph = fixture_graph("validation-overlap")
    evaluation = DeterministicRules(capabilities=flags).evaluate(
        graph, updated_session="validator-a", stored_update=1
    )

    assert tuple(item.rule for item in evaluation.matches) == ("validation_overlap",)
    assert evaluation.deliveries == ()
    assert evaluation.validation_overlap_status == "disabled_by_role_fallback"
    for fixture_name in ("cross-worker-conflict", "shared-assumption"):
        worker_graph = fixture_graph(fixture_name)
        target = DeterministicRules().detect(worker_graph)[0].target_sessions[0]
        worker_evaluation = DeterministicRules(capabilities=flags).evaluate(
            worker_graph, updated_session=target, stored_update=1
        )
        assert len(worker_evaluation.deliveries) == 1


def test_missing_capability_proof_defaults_live_overlap_off() -> None:
    graph = fixture_graph("validation-overlap")

    evaluation = DeterministicRules().evaluate(
        graph, updated_session="validator-a", stored_update=1
    )

    assert evaluation.matches[0].rule == "validation_overlap"
    assert evaluation.deliveries == ()
    assert evaluation.validation_overlap_status == "disabled_by_role_fallback"


def test_untrusted_hook_provenance_cannot_support_a_direct_concern() -> None:
    value = copy.deepcopy(load_replay("cross-worker-conflict"))
    for record in value["evidence"]:
        record["provenance_status"] = "untrusted_provenance"

    with pytest.raises(GraphError, match="provenance"):
        replay_graph(value)


def test_cross_feature_validator_check_is_independent() -> None:
    graph = fixture_graph("validation-overlap")
    graph.add_feature("feature-refunds", {"name": "refunds"})
    graph.connect_claim_to_feature("overlap-claim-validator", "feature-refunds")

    assert DeterministicRules().detect(graph) == ()


def test_model_output_is_not_direct_evidence() -> None:
    value = copy.deepcopy(load_replay("cross-worker-conflict"))
    for record in value["evidence"]:
        record["kind"] = "model_output"

    assert DeterministicRules().detect(replay_graph(value)) == ()


def test_shared_assumption_requires_file_test_or_feature_target() -> None:
    value = copy.deepcopy(load_replay("shared-assumption"))
    for claim in value["claims"]:
        claim.pop("targets")

    assert DeterministicRules().detect(replay_graph(value)) == ()


def test_authoritative_third_worker_does_not_hide_unsupported_pair() -> None:
    value = copy.deepcopy(load_replay("shared-assumption"))
    value["roles"].append(
        {
            "session_alias": "worker-c",
            "role_id": "role-c",
            "kind": "worker",
            "confidence": "high",
        }
    )
    value["evidence"].append(
        {
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "evidence_id": "assumption-evidence-c",
            "run_id": "run-replay",
            "session_alias": "worker-c",
            "kind": "repository_contract",
            "source": "repository_contract",
            "locator": "docs/guide.md#retry-limit",
            "digest": "7" * 64,
            "observed_at": 3,
        }
    )
    value["claims"].append(
        {
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "claim_id": "assumption-claim-c",
            "run_id": "run-replay",
            "session_alias": "worker-c",
            "subject": "retry limit",
            "subject_locator": "docs/guide.md#retry-limit",
            "property": "maximum retries",
            "value": 3,
            "unit": "count",
            "confidence": 0.95,
            "evidence_ids": ["assumption-evidence-c"],
            "targets": [],
            "observed_at": 3,
        }
    )

    findings = DeterministicRules().detect(replay_graph(value))

    assert len(findings) == 1
    assert findings[0].rule == "shared_assumption"
    assert findings[0].target_sessions == ("worker-a", "worker-b")


def test_unrelated_authoritative_citation_cannot_launder_direct_evidence() -> None:
    value = copy.deepcopy(load_replay("shared-assumption"))
    for index, session in enumerate(("worker-a", "worker-b")):
        evidence_id = f"unrelated-authority-{index}"
        value["evidence"].append(
            {
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "evidence_id": evidence_id,
                "run_id": "run-replay",
                "session_alias": session,
                "kind": "database_schema",
                "source": "database_schema",
                "locator": "db/unrelated.sql#value",
                "digest": str(index + 8) * 64,
                "observed_at": 5 + index,
            }
        )
        value["claims"][index]["evidence_ids"].append(evidence_id)

    findings = DeterministicRules().detect(replay_graph(value))

    assert tuple(item.rule for item in findings) == ("shared_assumption",)
    assert findings[0].authority.authority == EvidenceAuthority.UNKNOWN


def test_extra_model_output_does_not_change_validation_overlap_dedup() -> None:
    original = load_replay("validation-overlap")
    baseline = DeterministicRules().detect(replay_graph(original))[0]
    value = copy.deepcopy(original)
    value["evidence"].append(
        {
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "evidence_id": "validator-model-output",
            "run_id": "run-replay",
            "session_alias": "validator-a",
            "kind": "model_output",
            "source": "model",
            "locator": "model:validator",
            "digest": "7" * 64,
            "observed_at": 5,
        }
    )
    value["claims"][1]["evidence_ids"].append("validator-model-output")

    finding = DeterministicRules().detect(replay_graph(value))[0]

    assert finding.rule == "validation_overlap"
    assert finding.dedup_key == baseline.dedup_key


def test_normalized_feature_target_spelling_cannot_bypass_overlap() -> None:
    value = copy.deepcopy(load_replay("validation-overlap"))
    for index, target_id in enumerate(
        ("feature-checkout", " Feature-Checkout "),
    ):
        evidence_id = f"feature-target-{index}"
        value["evidence"].append(
            {
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "evidence_id": evidence_id,
                "run_id": "run-replay",
                "session_alias": (
                    "worker-a" if index == 0 else "validator-a"
                ),
                "kind": "feature_decision",
                "source": "feature_decision",
                "locator": target_id,
                "digest": str(index + 6) * 64,
                "observed_at": index + 5,
            }
        )
        value["claims"][index]["evidence_ids"] = sorted(
            [*value["claims"][index]["evidence_ids"], evidence_id]
        )
        value["claims"][index]["targets"] = [
            {
                "kind": "feature",
                "target_id": target_id,
                "evidence_id": evidence_id,
                "attributes": {},
            }
        ]

    graph = replay_graph(value)
    findings = DeterministicRules().detect(graph)

    assert graph.claim_targets("overlap-claim-worker") == (
        ("feature", "feature-checkout"),
    )
    assert graph.claim_targets("overlap-claim-validator") == (
        ("feature", "feature-checkout"),
    )
    assert tuple(item.rule for item in findings) == ("validation_overlap",)


def test_validation_overlap_aggregates_multiple_matching_milestones() -> None:
    graph = fixture_graph("validation-overlap")
    graph.add_milestone("milestone-release", {"name": "release"})
    graph.connect_claim_to_milestone(
        "overlap-claim-worker", "milestone-release"
    )
    graph.connect_claim_to_milestone(
        "overlap-claim-validator", "milestone-release"
    )

    findings = DeterministicRules().detect(graph)

    assert len(findings) == 1
    assert findings[0].milestone_ids == (
        "milestone-checkout",
        "milestone-release",
    )


def test_delivery_state_replays_from_authoritative_stored_updates() -> None:
    finding = DeterministicRules().detect(
        fixture_graph("cross-worker-conflict")
    )[0]
    next_key = hashlib.sha256(b"new-risk").hexdigest()
    next_finding = replace(
        finding,
        finding_id=f"finding-{next_key[:24]}",
        dedup_key=next_key,
    )
    selector = DeliverySelector()
    assert selector.select(
        (finding,), updated_session="worker-a", stored_update=10
    )
    restored = DeliverySelector(selector.snapshot())

    assert restored.select(
        (next_finding,), updated_session="worker-a", stored_update=10
    ) == ()
    for stored_update in (11, 12, 13):
        assert restored.select(
            (next_finding,),
            updated_session="worker-a",
            stored_update=stored_update,
        ) == ()
    assert restored.select(
        (next_finding,), updated_session="worker-a", stored_update=14
    )


def test_delivery_state_rejects_noncanonical_and_stale_updates() -> None:
    with pytest.raises(ValueError, match="canonical"):
        DeliverySelectorState(last_updates=(("worker-b", 1), ("worker-a", 1)))
    selector = DeliverySelector()
    finding = DeterministicRules().detect(
        fixture_graph("cross-worker-conflict")
    )[0]
    selector.select((finding,), updated_session="worker-a", stored_update=2)

    with pytest.raises(ValueError, match="backwards"):
        selector.select((finding,), updated_session="worker-a", stored_update=1)


def test_probe_record_rejects_cross_run_and_wrong_evidence_binding() -> None:
    graph = fixture_graph("cross-worker-conflict")
    finding = DeterministicRules().detect(graph)[0]
    cross_run = probe_for(finding, run_id="run-other")
    with pytest.raises(ValueError, match="another run"):
        DeterministicRules(probe_verifier=_PROBE_VERIFIER).detect(
            graph, probes=(cross_run,)
        )
    wrong_evidence = ProbeAssessment.create(
        probe_id="probe-wrong-evidence",
        run_id="run-replay",
        finding_dedup_key=finding.dedup_key,
        claim_ids=finding.claim_ids,
        evidence_digests=("8" * 64,),
        risk_category="security",
        recommended_level="blocker",
        status="confirmed",
        authoritative_value=normalize_value("authoritative"),
        snapshot_digest=_PROBE_SNAPSHOT_DIGEST,
        boundary_digest=_PROBE_BOUNDARY_DIGEST,
        boundary_policy_digest=_PROBE_BOUNDARY_DIGEST,
        signing_key=_PROBE_SIGNING_KEY,
        observed_at=100,
    )
    with pytest.raises(ValueError, match="bind this finding"):
        DeterministicRules(probe_verifier=_PROBE_VERIFIER).detect(
            graph, probes=(wrong_evidence,)
        )


def test_probe_record_digest_rejects_tampering() -> None:
    finding = DeterministicRules().detect(
        fixture_graph("cross-worker-conflict")
    )[0]
    probe = probe_for(finding)

    with pytest.raises(ValueError, match="record digest"):
        replace(probe, authoritative_value=normalize_value("tampered"))
    with pytest.raises(ValueError, match="record digest"):
        replace(probe, recommended_level="concern")
    with pytest.raises(ValueError, match="record digest"):
        replace(probe, boundary_policy_digest="8" * 64)


def test_dedup_identity_is_the_stable_conflict_locus() -> None:
    base_value = load_replay("cross-worker-conflict")
    base = DeterministicRules().detect(replay_graph(base_value))[0]
    reordered = copy.deepcopy(base_value)
    for field in ("roles", "evidence", "claims"):
        reordered[field].reverse()
    assert (
        DeterministicRules().detect(replay_graph(reordered))[0].dedup_key
        == base.dedup_key
    )

    stable = []
    changed = copy.deepcopy(base_value)
    changed["claims"][0]["value"] = "millions"
    stable.append(changed)
    changed = copy.deepcopy(base_value)
    changed["evidence"][0]["digest"] = "0" * 64
    stable.append(changed)
    changed = copy.deepcopy(base_value)
    changed["roles"][0]["session_alias"] = "worker-renamed"
    changed["evidence"][0]["session_alias"] = "worker-renamed"
    changed["claims"][0]["session_alias"] = "worker-renamed"
    stable.append(changed)

    for value in stable:
        finding = DeterministicRules().detect(replay_graph(value))[0]
        assert finding.dedup_key == base.dedup_key

    mutations = []
    changed = copy.deepcopy(base_value)
    for claim in changed["claims"]:
        claim["property"] = "wire unit"
    mutations.append(changed)
    changed = copy.deepcopy(base_value)
    for claim in changed["claims"]:
        claim["unit"] = "count"
    mutations.append(changed)
    changed = copy.deepcopy(base_value)
    for evidence in changed["evidence"]:
        evidence["locator"] = "api-schema.json#/other"
    for claim in changed["claims"]:
        claim["subject_locator"] = "api-schema.json#/other"
    mutations.append(changed)

    for value in mutations:
        finding = DeterministicRules().detect(replay_graph(value))[0]
        assert finding.dedup_key != base.dedup_key
    shared = DeterministicRules().detect(
        fixture_graph("shared-assumption")
    )[0]
    assert shared.dedup_key != base.dedup_key


def _conflict_with_third_worker() -> dict[str, Any]:
    value = copy.deepcopy(load_replay("cross-worker-conflict"))
    value["roles"].append(
        {
            "session_alias": "worker-c",
            "role_id": "role-c",
            "kind": "worker",
            "confidence": "high",
        }
    )
    value["evidence"].append(
        {
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "evidence_id": "conflict-evidence-c",
            "run_id": "run-replay",
            "session_alias": "worker-c",
            "kind": "repository_contract",
            "source": "repository_contract",
            "locator": "api-schema.json#/amount",
            "digest": "c" * 64,
            "observed_at": 5,
        }
    )
    value["claims"].append(
        {
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "claim_id": "conflict-claim-c",
            "run_id": "run-replay",
            "session_alias": "worker-c",
            "subject": "amount",
            "subject_locator": "api-schema.json#/amount",
            "property": "storage unit",
            "value": "millions",
            "unit": "cents",
            "confidence": 0.95,
            "evidence_ids": ["conflict-evidence-c"],
            "observed_at": 6,
        }
    )
    return value


def test_the_selector_finishes_a_started_finding_before_a_fresh_one() -> None:
    base = DeterministicRules().detect(
        replay_graph(load_replay("cross-worker-conflict"))
    )[0]
    sessions = ("worker-a", "worker-b")
    started = replace(
        base,
        finding_id="finding-started",
        dedup_key="f" * 64,
        target_sessions=sessions,
    )
    fresh = replace(
        base,
        finding_id="finding-fresh",
        dedup_key="0" * 64,
        target_sessions=sessions,
    )
    findings = (started, fresh)
    selector = DeliverySelector()

    first = selector.select(
        (started,), updated_session="worker-a", stored_update=1
    )
    assert first[0].finding.dedup_key == started.dedup_key

    second = selector.select(
        findings, updated_session="worker-b", stored_update=1
    )

    assert len(second) == 1
    assert second[0].finding.dedup_key == started.dedup_key
    assert started.dedup_key > fresh.dedup_key


def _conflict_with_a_source_declaration() -> dict[str, Any]:
    value = copy.deepcopy(load_replay("cross-worker-conflict"))
    value["evidence"].append(
        {
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "evidence_id": "conflict-evidence-webhook",
            "run_id": "run-replay",
            "session_alias": "worker-b",
            "kind": "changed_file",
            "source": "changed_file",
            "locator": "src/webhook.py",
            "digest": "d" * 64,
            "observed_at": 7,
        }
    )
    value["claims"].append(
        {
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "claim_id": "conflict-claim-webhook",
            "run_id": "run-replay",
            "session_alias": "worker-b",
            "subject": "amount value",
            "subject_locator": "src/webhook.py",
            "property": "type",
            "value": "float",
            "unit": None,
            "confidence": 0.95,
            "evidence_ids": ["conflict-evidence-webhook"],
            "targets": [
                {
                    "kind": "file",
                    "target_id": "src/webhook.py",
                    "evidence_id": "conflict-evidence-webhook",
                    "attributes": {},
                }
            ],
            "observed_at": 8,
        }
    )
    return value


def test_a_conflict_names_the_source_file_each_session_declared() -> None:
    base = DeterministicRules().detect(
        replay_graph(load_replay("cross-worker-conflict"))
    )[0]
    findings = DeterministicRules().detect(
        replay_graph(_conflict_with_a_source_declaration())
    )
    conflict = next(
        item for item in findings if item.rule == "cross_worker_conflict"
    )

    assert conflict.related_declarations == (
        ("src/webhook.py", "type", normalize_value("float")),
    )
    assert base.related_declarations == ()
    assert conflict.dedup_key == base.dedup_key


def test_one_conflict_keeps_one_identity_while_its_evidence_grows() -> None:
    base = DeterministicRules().detect(
        replay_graph(load_replay("cross-worker-conflict"))
    )[0]
    grown = DeterministicRules().detect(
        replay_graph(_conflict_with_third_worker())
    )[0]

    assert grown.dedup_key == base.dedup_key
    assert grown.finding_id == base.finding_id
    assert set(base.target_sessions) < set(grown.target_sessions)
    assert set(base.claim_ids) < set(grown.claim_ids)
    assert set(base.evidence_digests) < set(grown.evidence_digests)


def test_a_grown_conflict_yields_its_window_to_a_distinct_finding() -> None:
    base = DeterministicRules().detect(
        replay_graph(load_replay("cross-worker-conflict"))
    )[0]
    grown = DeterministicRules().detect(
        replay_graph(_conflict_with_third_worker())
    )[0]
    distinct_key = hashlib.sha256(
        f"{base.dedup_key}:distinct".encode()
    ).hexdigest()
    distinct = replace(
        base,
        finding_id=f"finding-{distinct_key[:24]}",
        dedup_key=distinct_key,
    )
    selector = DeliverySelector()

    assert len(
        selector.select((base,), updated_session="worker-a", stored_update=1)
    ) == 1
    for stored_update in (2, 3, 4):
        assert (
            selector.select(
                (grown,),
                updated_session="worker-a",
                stored_update=stored_update,
            )
            == ()
        )
    assert (
        selector.select((grown,), updated_session="worker-a", stored_update=5)
        == ()
    )
    delivered = selector.select(
        (distinct,), updated_session="worker-a", stored_update=6
    )

    assert len(delivered) == 1
    assert delivered[0].finding.dedup_key == distinct_key


def test_fixture_shaped_test_use_evidence_preserves_authority_order() -> None:
    value = load_replay("validation-overlap")
    record = EvidenceRecord.model_validate(value["evidence"][0])
    integration = record.model_copy(update={"source": "integration_test"})
    isolated = record.model_copy(update={"source": "unit_test"})

    assert (
        classify_evidence_authority(integration)
        == EvidenceAuthority.INTEGRATION_VALIDATION
    )
    assert (
        classify_evidence_authority(isolated)
        == EvidenceAuthority.ISOLATED_VALIDATION
    )


def test_distinct_integration_evidence_makes_validator_independent() -> None:
    value = copy.deepcopy(load_replay("validation-overlap"))
    value["evidence"].append(
        {
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "evidence_id": "zz-validator-integration",
            "run_id": "run-replay",
            "session_alias": "validator-a",
            "kind": "test_use",
            "source": "integration_test",
            "locator": "tests/integration/test_checkout.py#user_flow",
            "digest": "8" * 64,
            "observed_at": 24,
        }
    )
    validator = next(
        item
        for item in value["claims"]
        if item["session_alias"] == "validator-a"
    )
    validator["evidence_ids"] = sorted(
        [*validator["evidence_ids"], "zz-validator-integration"]
    )

    assert DeterministicRules().detect(replay_graph(value)) == ()


def test_semantic_overlap_aggregates_distinct_claim_ids_across_milestones() -> None:
    value = copy.deepcopy(load_replay("validation-overlap"))
    value["milestones"].append(
        {"milestone_id": "milestone-release", "attributes": {"name": "release"}}
    )
    for original in tuple(value["claims"]):
        clone = copy.deepcopy(original)
        clone["claim_id"] = f"{original['claim_id']}-release"
        value["claims"].append(clone)
        value["links"].append(
            {
                "claim_id": clone["claim_id"],
                "milestone_id": "milestone-release",
            }
        )

    findings = DeterministicRules().detect(replay_graph(value))

    assert len(findings) == 1
    assert findings[0].milestone_ids == (
        "milestone-checkout",
        "milestone-release",
    )
    assert len(findings[0].claim_ids) == 4


def test_approved_criterion_reaches_authority_resolution_end_to_end() -> None:
    graph = MissionGraph("run-criterion")
    criterion = ApprovedMissionCriterion(
        run_id="run-criterion",
        criterion_id="acceptance-3",
        locator="mission:acceptance-3",
        property="storage unit",
        value="cents",
        unit="cents",
        observed_at=0,
    )
    for position, (session, value) in enumerate(
        (("worker-a", "cents"), ("worker-b", "dollars")), start=1
    ):
        graph.add_role_decision(
            RoleDecision(
                session_alias=session,
                role_id=f"role-{session}",
                kind="worker",
                confidence="high",
                status="assigned",
                reason="recorded relation",
                evidence_digests=("0" * 64,),
            )
        )
        source = EvidenceRecord(
            provenance_status="hook_authenticated",
            redaction_status="clean",
            evidence_id=f"source-{session}",
            run_id="run-criterion",
            session_alias=session,
            kind="claim_source",
            source="transcript",
            locator=(
                criterion.locator
                if value == "dollars"
                else f"transcript:{session}"
            ),
            digest=hashlib.sha256(session.encode()).hexdigest(),
            observed_at=position,
        )
        broker = RecordedExtractionBroker(
            BrokerAttempt(
                boundary=BoundaryMetadata(
                    factory_home="clean",
                    timeout_seconds=30,
                    shadow_activation_stripped=True,
                    mission_correlation_stripped=True,
                    internal_session_alias=f"extractor-{session}",
                ),
                output=[
                    {
                        "subject": "amount",
                        "subject_locator": criterion.locator,
                        "property": "storage unit",
                        "value": value,
                        "unit": "cents",
                        "confidence": 0.95,
                        "evidence_ids": [source.evidence_id],
                    }
                ],
            )
        )
        outcome = ClaimExtractor(broker).extract(
            HookEnvelope(provenance_status="hook_authenticated",
            redaction_status="clean",
            event_id=f"event-{session}",
            source_fingerprint=f"fingerprint-{session}",
            run_id="run-criterion",
            session_alias=session,
            transcript_alias=f"transcript-{session}",
            hook_event_name="Stop", observed_at=position + 10, message_digest="d" * 64, payload={},),
            (source,),
            approved_criteria=(criterion,),
        )
        graph.add_evidence(source)
        for record in outcome.derived_evidence:
            graph.add_evidence(record)
        graph.add_claim(outcome.claims[0])

    finding = DeterministicRules().detect(graph)[0]

    assert finding.rule == "cross_worker_conflict"
    assert finding.authority.authority == EvidenceAuthority.AUTHORITATIVE
    assert finding.authority.status == "resolved"
    assert finding.authority.normalized_value == normalize_value("cents")

def test_ledger_bound_review_engine_survives_restart_and_counts_updates(
    tmp_path: Path,
) -> None:
    graph = fixture_graph("cross-worker-conflict")
    changed_value = copy.deepcopy(load_replay("cross-worker-conflict"))
    for claim in changed_value["claims"]:
        claim["property"] = "wire unit"
    changed_graph = replay_graph(changed_value)
    ledger = EventLedger(tmp_path / "run", run_id="run-replay", clock=lambda: 100)
    ledger.start()

    def persist(source_graph: MissionGraph, sequence: int) -> tuple[str, ...]:
        engine = DeterministicRules.from_ledger(
            ledger,
            live_validation_overlap=True,
        )
        event = HookEnvelope(provenance_status="hook_authenticated",
        redaction_status="clean",
        event_id=f"review-event-{sequence}",
        source_fingerprint="source-review",
        run_id="run-replay",
        session_alias="worker-a",
        transcript_alias="transcript-worker-a",
        hook_event_name="PostToolUse", observed_at=sequence, message_digest="d" * 64, payload={},)
        response = ledger.submit(
            event,
            request_digest=hook_envelope_digest(event),
            decide=engine.response_decider(source_graph),
        )
        return response.guidance_ids

    try:
        assert persist(graph, 1)
        for sequence in (2, 3, 4):
            assert persist(changed_graph, sequence) == ()
        assert persist(changed_graph, 5)
        assert persist(changed_graph, 6) == ()
    finally:
        ledger.stop()


def test_concurrent_review_submissions_follow_writer_order(tmp_path: Path) -> None:
    graph = fixture_graph("cross-worker-conflict")
    ledger = EventLedger(tmp_path / "run", run_id="run-replay", clock=lambda: 100)
    ledger.start()
    engine = DeterministicRules.from_ledger(ledger)
    events = tuple(
        HookEnvelope(provenance_status="hook_authenticated",
        redaction_status="clean",
        event_id=f"concurrent-review-{index}",
        source_fingerprint="source-review",
        run_id="run-replay",
        session_alias="worker-a",
        transcript_alias="transcript-worker-a",
        hook_event_name="PostToolUse", observed_at=index, message_digest="d" * 64, payload={},)
        for index in (1, 2)
    )

    def submit(event: HookEnvelope) -> tuple[str, ...]:
        return ledger.submit(
            event,
            request_digest=hook_envelope_digest(event),
            decide=engine.response_decider(graph),
        ).guidance_ids

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            guidance = tuple(executor.map(submit, events))
        states = [
            exchange.response.review_state
            for exchange in ledger.exchanges()
        ]
        assert sum(bool(item) for item in guidance) == 1
        assert [dict(item["last_updates"])["worker-a"] for item in states] == [
            1,
            2,
        ]
    finally:
        ledger.stop()


def test_response_decider_rejects_wrong_run_graph_before_append(
    tmp_path: Path,
) -> None:
    ledger = EventLedger(tmp_path / "run", run_id="run-replay")
    ledger.start()
    event = HookEnvelope(provenance_status="hook_authenticated",
    redaction_status="clean",
    event_id="wrong-graph-event",
    source_fingerprint="source-review",
    run_id="run-replay",
    session_alias="worker-a",
    transcript_alias="transcript-worker-a",
    hook_event_name="PostToolUse", observed_at=1, message_digest="d" * 64, payload={},)
    try:
        with pytest.raises(LedgerError, match="persistence failed"):
            ledger.submit(
                event,
                request_digest=hook_envelope_digest(event),
                decide=DeterministicRules().response_decider(
                    MissionGraph("run-other")
                ),
            )
        assert ledger.exchanges() == ()
    finally:
        ledger.stop()


def test_review_state_callback_failure_poison_prevents_replay(
    tmp_path: Path,
) -> None:
    graph = fixture_graph("cross-worker-conflict")
    run_dir = tmp_path / "run"

    def crash_after_append(_exchange: object) -> None:
        raise RuntimeError("injected after-append crash")

    ledger = EventLedger(
        run_dir,
        run_id="run-replay",
        clock=lambda: 100,
        after_append=crash_after_append,
    )
    ledger.start()
    event = HookEnvelope(provenance_status="hook_authenticated",
    redaction_status="clean",
    event_id="crash-review-1",
    source_fingerprint="source-review",
    run_id="run-replay",
    session_alias="worker-a",
    transcript_alias="transcript-worker-a",
    hook_event_name="PostToolUse", observed_at=1, message_digest="d" * 64, payload={},)
    with pytest.raises(LedgerError, match="persistence failed"):
        ledger.submit(
            event,
            request_digest=hook_envelope_digest(event),
            decide=DeterministicRules.from_ledger(ledger).response_decider(graph),
        )
    assert ledger.exchanges() == ()
    with pytest.raises(LedgerError, match="degraded"):
        ledger.submit(
            event,
            request_digest=hook_envelope_digest(event),
            decide=lambda _: ResponsePlan(),
        )
    ledger.stop()

    restored_ledger = EventLedger(run_dir, run_id="run-replay", clock=lambda: 101)
    assert restored_ledger.degraded_reason == "RuntimeError"
    with pytest.raises(LedgerError, match="degraded"):
        restored_ledger.start()
    with pytest.raises(LedgerError, match="degraded"):
        restored_ledger.response_for(
            event.event_id,
            hook_envelope_digest(event),
        )


def test_delivery_state_record_rejects_cross_run_replay() -> None:
    record = DeliverySelectorState().to_record(run_id="run-a")

    with pytest.raises(ValueError, match="binding is invalid"):
        DeliverySelectorState.from_record(record, run_id="run-b")


def test_probe_verifier_rejects_forged_signature_and_boundary() -> None:
    graph = fixture_graph("cross-worker-conflict")
    finding = DeterministicRules().detect(graph)[0]
    forged = ProbeAssessment.create(
        probe_id="probe-forged",
        run_id="run-replay",
        finding_dedup_key=finding.dedup_key,
        claim_ids=finding.claim_ids,
        evidence_digests=finding.evidence_digests,
        risk_category="security",
        recommended_level="blocker",
        status="confirmed",
        authoritative_value=normalize_value("forged"),
        snapshot_digest=_PROBE_SNAPSHOT_DIGEST,
        boundary_digest=_PROBE_BOUNDARY_DIGEST,
        boundary_policy_digest=_PROBE_BOUNDARY_DIGEST,
        signing_key=b"attacker-controlled-probe-signing-key",
        observed_at=100,
    )
    wrong_boundary = ProbeAssessment.create(
        probe_id="probe-wrong-boundary",
        run_id="run-replay",
        finding_dedup_key=finding.dedup_key,
        claim_ids=finding.claim_ids,
        evidence_digests=finding.evidence_digests,
        risk_category="security",
        recommended_level="blocker",
        status="confirmed",
        authoritative_value=normalize_value("forged"),
        snapshot_digest=_PROBE_SNAPSHOT_DIGEST,
        boundary_digest="8" * 64,
        boundary_policy_digest="8" * 64,
        signing_key=_PROBE_SIGNING_KEY,
        observed_at=100,
    )
    rules = DeterministicRules(probe_verifier=_PROBE_VERIFIER)

    with pytest.raises(ValueError, match="not authenticated"):
        rules.detect(graph, probes=(forged,))
    with pytest.raises(ValueError, match="not authenticated"):
        rules.detect(graph, probes=(wrong_boundary,))


def test_selected_delivery_keys_actually_deliver_guidance() -> None:
    """The live decide() path always passes selected_delivery_keys.

    Interventions are created on one event and can only be delivered on a
    later event from the target session. If the selector and the router
    disagree about that window, guidance never leaves the daemon.
    """

    from shadow_mission.protocol import HookEnvelope
    from shadow_mission.router import InterventionRouter

    from unit.test_router import make_capabilities

    graph = fixture_graph("cross-worker-conflict")
    engine = DeterministicRules(probe_verifier=_PROBE_VERIFIER)
    finding = engine.detect(graph)[0]
    target = finding.target_sessions[0]
    router = InterventionRouter(
        run_id="run-replay",
        graph=graph,
        capabilities=make_capabilities(),
        probe_verifier=_PROBE_VERIFIER,
    )

    delivered_bodies = []
    for update in range(1, 5):
        envelope = HookEnvelope(
            provenance_status="untrusted_provenance",
            redaction_status="clean",
            event_id=f"event-delivery-{update}",
            source_fingerprint="source",
            run_id="run-replay",
            session_alias=target,
            transcript_alias="transcript",
            hook_event_name="PostToolUse",
            observed_at=100 + update,
            message_digest="d" * 64,
            payload={},
        )
        evaluation = engine.evaluate(
            graph, updated_session=target, stored_update=update
        )
        selected = tuple(
            (item.finding.dedup_key, item.target_session)
            for item in evaluation.deliveries
        )
        plan = router.plan_response(
            envelope,
            findings=evaluation.matches,
            selected_delivery_keys=selected,
            base_plan=evaluation.response_plan({}),
        )
        if plan.body:
            delivered_bodies.append(plan.body)
        if plan.commit is not None:
            plan.commit()
        evaluation.commit()

    assert delivered_bodies, (
        "no guidance body ever reached a PostToolUse response across four "
        "target-session events"
    )
    context = delivered_bodies[0]["hookSpecificOutput"]["additionalContext"]
    assert "cross_worker_conflict" in context
    assert "do not preserve a per-boundary split" in context
