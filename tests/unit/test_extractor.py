from __future__ import annotations

import hashlib
from pathlib import Path
import pytest
import shadow_mission.extractor as extractor_module

from shadow_mission.evidence import (
    EvidenceRegistryError,
    FrozenEvidenceRegistry,
    load_frozen_evidence_registry,
)
from shadow_mission.extractor import (
    ApprovedMilestoneLink,
    ApprovedMissionCriterion,
    ApprovedRepositoryChange,
    BoundaryMetadata,
    BrokerAttempt,
    ClaimExtractor,
    ExtractedClaim,
    ExtractionRequest,
    RecordedExtractionBroker,
    TriggerClassifier,
    classify_triggers,
)
from shadow_mission.protocol import EvidenceRecord, HookEnvelope, canonical_json


def envelope(
    *,
    event: str = "Stop",
    session: str = "session-a",
    run_id: str = "run-1",
    payload: dict[str, object] | None = None,
    observed_at: int = 10,
    provenance_status: str = "hook_authenticated",
) -> HookEnvelope:
    return HookEnvelope(provenance_status=provenance_status,
    redaction_status="clean",
    event_id=f"event-{session}-{event}-{observed_at}",
    source_fingerprint=f"source-{session}",
    run_id=run_id,
    session_alias=session,
    transcript_alias=f"transcript-{session}",
    hook_event_name=event, observed_at=observed_at, message_digest="d" * 64, payload=payload or {},)


def edit_event(path: str, *, session: str = "session-a") -> HookEnvelope:
    return envelope(
        event="PostToolUse",
        session=session,
        payload={
            "tool_name": "functions.edit",
            "tool_input": {"path": path, "content": "safe"},
            "tool_response": {"status": "ok"},
        },
    )


def evidence(
    evidence_id: str = "evidence-1",
    *,
    run_id: str = "run-1",
    session: str = "session-a",
    locator: str = "src/api/schema.py:12",
    provenance_status: str = "hook_authenticated",
    redaction_status: str = "clean",
    kind: str = "diff",
    source: str = "hook",
    digest: str = "a" * 64,
) -> EvidenceRecord:
    return EvidenceRecord(
        provenance_status=provenance_status,
        redaction_status=redaction_status,
        evidence_id=evidence_id,
        run_id=run_id,
        session_alias=session,
        kind=kind,
        source=source,
        locator=locator,
        digest=digest,
        observed_at=9,
    )


def boundary(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "factory_home": "clean",
        "enabled_tools": [],
        "timeout_seconds": 30,
        "shadow_activation_stripped": True,
        "mission_correlation_stripped": True,
        "internal_session_alias": "session-extractor",
        "environment_keys": ["PATH"],
    }
    value.update(changes)
    return value


def claim(
    *,
    locator: str = "src/api/schema.py:12",
    evidence_ids: list[str] | None = None,
    value: object = 42,
) -> dict[str, object]:
    return {
        "subject": "invoice total",
        "subject_locator": locator,
        "property": "maximum",
        "value": value,
        "unit": "cents",
        "confidence": 0.95,
        "evidence_ids": evidence_ids or ["evidence-1"],
    }

def frozen_registry_for(
    records: tuple[EvidenceRecord, ...],
) -> tuple[FrozenEvidenceRegistry, tuple[EvidenceRecord, ...]]:
    payload = {
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
            for item in sorted(records, key=lambda value: value.evidence_id)
        ],
    }
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    registry = FrozenEvidenceRegistry.from_records(
        records,
        expected_digest=digest,
    )
    return registry, tuple(registry.bind(item) for item in records)


def extract(
    output: object | None,
    *,
    broker_boundary: object | None = None,
    timed_out: bool = False,
    event_value: HookEnvelope | None = None,
    evidence_values: tuple[EvidenceRecord, ...] | None = None,
    criteria: tuple[ApprovedMissionCriterion, ...] = (),
    milestone_links: tuple[ApprovedMilestoneLink, ...] = (),
    repository_changes: tuple[ApprovedRepositoryChange, ...] = (),
    frozen_evidence_registry: FrozenEvidenceRegistry | None = None,
):
    broker = RecordedExtractionBroker(
        BrokerAttempt(
            boundary=boundary() if broker_boundary is None else broker_boundary,
            output=output,
            timed_out=timed_out,
        )
    )
    outcome = ClaimExtractor(
        broker,
        frozen_evidence_registry=frozen_evidence_registry,
    ).extract(
        event_value or envelope(),
        evidence_values if evidence_values is not None else (evidence(),),
        approved_criteria=criteria,
        approved_milestone_links=milestone_links,
        approved_repository_changes=repository_changes,
    )
    return outcome, broker


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/api/schema.py", "contract_or_schema_edit"),
        ("contracts/public-api.json", "contract_or_schema_edit"),
        ("tests/unit/test_invoice.py", "test_edit"),
    ],
)
def test_edit_triggers_are_classified_from_sanitized_payload(
    path: str, expected: str
) -> None:
    assert expected in classify_triggers(edit_event(path))


def test_failed_command_or_test_is_a_trigger() -> None:
    failed = envelope(
        event="PostToolUse",
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": "pytest"},
            "tool_response": {"exit_code": 1, "output": "1 failed"},
        },
    )

    assert classify_triggers(failed) == ("failed_command_or_test",)


@pytest.mark.parametrize("event", ["Stop", "SubagentStop"])
def test_completion_events_are_triggers(event: str) -> None:
    assert classify_triggers(envelope(event=event)) == ("completion_attempt",)


def test_second_session_editing_same_path_is_a_cross_session_trigger() -> None:
    classifier = TriggerClassifier()

    assert classifier.observe(edit_event("src/invoice.py", session="session-a")) == ()
    assert classifier.observe(
        edit_event("src/invoice.py", session="session-b")
    ) == ("cross_session_edit",)


def test_claim_extractor_proxies_idempotent_abort_acknowledgment() -> None:
    broker = RecordedExtractionBroker(
        BrokerAttempt(boundary={}, output=None)
    )
    extractor = ClaimExtractor(broker)

    assert extractor.abort() is True
    assert extractor.abort() is True


def test_quiet_event_does_not_call_broker() -> None:
    broker = RecordedExtractionBroker(
        BrokerAttempt(boundary=boundary(), output=[claim()])
    )
    quiet = envelope(
        event="PostToolUse",
        payload={
            "tool_name": "Read",
            "tool_input": {"path": "src/invoice.py"},
            "tool_response": {"status": "ok"},
        },
    )

    outcome = ClaimExtractor(broker).extract(quiet, (evidence(),))

    assert outcome.trigger_kinds == ()
    assert outcome.claims == ()
    assert outcome.quarantine is None
    assert broker.requests == []


def test_valid_recorded_output_uses_exact_model_and_creates_claim_record() -> None:
    raw = claim(value={"amount": 42, "taxable": True})
    assert ExtractedClaim.model_validate(raw).model_dump(mode="json") == (
        raw | {"targets": []}
    )

    outcome, broker = extract([raw])

    assert outcome.quarantine is None
    assert len(outcome.claims) == 1
    accepted = outcome.claims[0]
    assert accepted.subject == "invoice total"
    assert accepted.value == {"amount": 42, "taxable": True}
    assert accepted.evidence_ids == ("evidence-1",)
    assert accepted.session_alias == "session-a"
    assert broker.requests == [
        ExtractionRequest(
            run_id="run-1",
            event_id="event-session-a-Stop-10",
            source_session_alias="session-a",
            trigger_kinds=("completion_attempt",),
            trigger_payload={},
            evidence=(evidence(),),
            approved_criteria=(),
        )
    ]


def test_structured_output_tuples_normalize_to_json_arrays() -> None:
    raw = claim(value=(("cents",), ()))

    validated = ExtractedClaim.model_validate(raw)

    assert validated.value == [["cents"], []]
    assert validated.model_dump(mode="json")["value"] == [["cents"], []]


def test_claim_value_normalization_uses_the_validation_depth_bound() -> None:
    bounded: object = 0
    too_deep: object = 0
    for _ in range(32):
        bounded = [bounded]
    for _ in range(33):
        too_deep = [too_deep]

    accepted = ExtractedClaim.model_validate(claim(value=bounded))

    assert accepted.value == bounded
    with pytest.raises(ValueError, match="claim value is too deeply nested"):
        ExtractedClaim.model_validate(claim(value=too_deep))


def test_recursive_claim_value_is_quarantined_before_python_recursion() -> None:
    recursive: list[object] = []
    recursive.append(recursive)

    outcome, _ = extract([claim(value=recursive)])

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "malformed_output"


def test_output_validation_recursion_error_is_quarantined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_validation(_value: object) -> tuple[ExtractedClaim, ...]:
        raise RecursionError("injected recursive output")

    monkeypatch.setattr(extractor_module, "_validate_output", fail_validation)

    outcome, _ = extract([claim()])

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "malformed_output"


def test_claim_id_is_deterministic_across_replayed_observation_times() -> None:
    first, _ = extract([claim()], event_value=envelope(observed_at=10))
    second, _ = extract([claim()], event_value=envelope(observed_at=99))

    assert first.claims[0] == second.claims[0]


@pytest.mark.parametrize(
    "bad_output",
    [
        {},
        [claim() | {"unexpected": "field"}],
        [claim() | {"confidence": "high"}],
        [claim(), claim() | {"subject": ""}],
    ],
)
def test_malformed_or_partly_invalid_output_fails_closed(bad_output: object) -> None:
    outcome, _ = extract(bad_output)

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "malformed_output"
    assert outcome.quarantine.model_dump() == {"reason": "malformed_output"}


def test_empty_claim_list_is_accepted_without_quarantine() -> None:
    """Most events assert no contract. Silence is the documented behaviour."""

    outcome, _ = extract([])

    assert outcome.claims == ()
    assert outcome.quarantine is None
    assert outcome.trigger_kinds != ()



def test_missing_output_and_timeout_have_bounded_reasons() -> None:
    missing, _ = extract(None)
    timed_out, _ = extract(None, timed_out=True)

    assert missing.claims == ()
    assert missing.quarantine is not None
    assert missing.quarantine.reason == "missing_output"
    assert timed_out.claims == ()
    assert timed_out.quarantine is not None
    assert timed_out.quarantine.reason == "timeout"


@pytest.mark.parametrize(
    "unsafe_boundary",
    [
        boundary(enabled_tools=["Read"]),
        boundary(factory_home="inherited"),
        boundary(timeout_seconds=31),
        boundary(shadow_activation_stripped=False),
        boundary(mission_correlation_stripped=False),
        boundary(environment_keys=["PATH", "SHADOW_MISSION_RUN_SECRET"]),
        boundary(unexpected="metadata"),
    ],
)
def test_unsafe_tools_home_timeout_or_environment_metadata_is_rejected(
    unsafe_boundary: object,
) -> None:
    outcome, _ = extract([claim()], broker_boundary=unsafe_boundary)

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unsafe_boundary"


def test_boundary_metadata_model_is_the_recorded_contract() -> None:
    metadata = BoundaryMetadata.model_validate(boundary())

    assert metadata.enabled_tools == ()
    assert metadata.timeout_seconds == 30
    assert metadata.internal_session_alias == "session-extractor"


def test_self_observation_is_excluded() -> None:
    outcome, _ = extract(
        [claim()], broker_boundary=boundary(internal_session_alias="session-a")
    )

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "self_observed"


def test_unanchored_locator_and_unknown_evidence_fail_closed() -> None:
    unanchored, _ = extract([claim(locator="src/other.py:7")])
    unknown, _ = extract([claim(evidence_ids=["evidence-missing"])])

    assert unanchored.claims == ()
    assert unanchored.quarantine is not None
    assert unanchored.quarantine.reason == "unanchored_locator"
    assert unknown.claims == ()
    assert unknown.quarantine is not None
    assert unknown.quarantine.reason == "unknown_evidence"


@pytest.mark.parametrize(
    ("foreign_evidence", "reason"),
    [
        (evidence(run_id="run-other"), "cross_run_evidence"),
        (evidence(session="session-other"), "cross_session_evidence"),
    ],
)
def test_cross_run_or_cross_session_evidence_is_rejected(
    foreign_evidence: EvidenceRecord, reason: str
) -> None:
    outcome, _ = extract([claim()], evidence_values=(foreign_evidence,))

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == reason


def test_secret_like_output_is_rejected_without_persisting_it() -> None:
    secret = "sk-this-must-never-persist"
    outcome, _ = extract([claim(value=secret)])

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unredacted_output"
    assert secret not in repr(outcome)
    assert outcome.quarantine.model_dump() == {"reason": "unredacted_output"}


def test_approved_mission_criterion_can_anchor_exact_locator() -> None:
    criterion = ApprovedMissionCriterion(
        run_id="run-1",
        criterion_id="acceptance-3",
        locator="mission:acceptance-3",
        property="maximum",
        value=42,
        unit="cents",
        observed_at=1,
    )

    outcome, broker = extract(
        [claim(locator="mission:acceptance-3")], criteria=(criterion,)
    )

    assert outcome.quarantine is None
    assert outcome.claims[0].subject_locator == "mission:acceptance-3"
    assert len(outcome.derived_evidence) == 1
    criterion_evidence = outcome.derived_evidence[0]
    assert criterion_evidence.provenance_status == "authoritative_input"
    assert criterion_evidence.kind == "mission_criterion"
    assert criterion_evidence.evidence_id in outcome.claims[0].evidence_ids
    assert broker.requests[0].approved_criteria == (criterion,)


def test_criterion_from_another_run_does_not_anchor_claim() -> None:
    criterion = ApprovedMissionCriterion(
        run_id="run-other",
        criterion_id="acceptance-3",
        locator="mission:acceptance-3",
        property="maximum",
        value=42,
        unit="cents",
        observed_at=1,
    )

    outcome, _ = extract(
        [claim(locator="mission:acceptance-3")], criteria=(criterion,)
    )

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unanchored_locator"


def test_material_targets_are_anchored_and_persisted() -> None:
    raw = claim() | {
        "targets": [
            {
                "kind": "file",
                "target_id": "src/api/schema.py:12",
                "evidence_id": "evidence-1",
                "attributes": {},
            }
        ]
    }

    outcome, _ = extract([raw])

    assert outcome.quarantine is None
    assert outcome.claims[0].targets[0].kind == "file"
    assert outcome.claims[0].targets[0].target_id == "src/api/schema.py:12"


def test_untrusted_provenance_cannot_create_a_claim_or_call_broker() -> None:
    event = envelope().model_copy(
        update={"provenance_status": "untrusted_provenance"}
    )
    broker = RecordedExtractionBroker(
        BrokerAttempt(boundary=boundary(), output=[claim()])
    )

    outcome = ClaimExtractor(broker).extract(event, (evidence(),))

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "untrusted_provenance"
    assert broker.requests == []


def test_untrusted_hook_accepts_collector_observed_transcript_evidence() -> None:
    event = edit_event("src/api/schema.py").model_copy(
        update={"provenance_status": "untrusted_provenance"}
    )
    live = evidence(
        provenance_status="collector_observed",
        source="transcript",
    )

    outcome, broker = extract(
        [claim()],
        event_value=event,
        evidence_values=(live,),
    )

    assert outcome.quarantine is None
    assert outcome.claims[0].provenance_status == "collector_observed"
    assert broker.requests


@pytest.mark.parametrize(
    ("kind", "source"),
    [
        ("target_acknowledgment", "target_assistant_transcript"),
        ("target_correction", "target_diff_transcript"),
        ("target_correction", "target_test_transcript"),
    ],
)
def test_untrusted_hook_rejects_intervention_bound_transcript_evidence(
    kind: str,
    source: str,
) -> None:
    event = edit_event("src/api/schema.py").model_copy(
        update={"provenance_status": "untrusted_provenance"}
    )
    bound = evidence(
        provenance_status="collector_observed",
        kind=kind,
        source=source,
    ).model_copy(update={"intervention_id": "intervention-review"})

    outcome, broker = extract(
        [claim()],
        event_value=event,
        evidence_values=(bound,),
    )

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "untrusted_provenance"
    assert broker.requests == []


def test_source_only_evidence_cannot_manufacture_a_material_file_target() -> None:
    source = evidence().model_copy(update={"kind": "code_use"})
    raw = claim() | {
        "targets": [
            {
                "kind": "file",
                "target_id": source.locator,
                "evidence_id": source.evidence_id,
                "attributes": {},
            }
        ]
    }

    outcome, _ = extract([raw], evidence_values=(source,))

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unanchored_locator"


def test_generic_file_evidence_cannot_manufacture_a_changed_file_target() -> None:
    source = evidence(kind="file")
    raw = claim() | {
        "targets": [
            {
                "kind": "file",
                "target_id": source.locator,
                "evidence_id": source.evidence_id,
                "attributes": {},
            }
        ]
    }

    outcome, _ = extract([raw], evidence_values=(source,))

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unanchored_locator"


def test_criterion_requires_exact_property_value_and_unit() -> None:
    criterion = ApprovedMissionCriterion(
        run_id="run-1",
        criterion_id="acceptance-3",
        locator="mission:acceptance-3",
        property="maximum",
        value=42,
        unit="cents",
        observed_at=1,
    )

    outcome, _ = extract(
        [claim(locator=criterion.locator, value=43)],
        criteria=(criterion,),
    )

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "criterion_mismatch"


def test_repeated_criterion_extraction_is_immutable_and_claim_stable() -> None:
    criterion = ApprovedMissionCriterion(
        run_id="run-1",
        criterion_id="acceptance-3",
        locator="mission:acceptance-3",
        property="maximum",
        value=42,
        unit="cents",
        observed_at=1,
    )
    first, _ = extract(
        [claim(locator=criterion.locator)],
        criteria=(criterion,),
        event_value=envelope(observed_at=10),
    )
    second, _ = extract(
        [claim(locator=criterion.locator)],
        criteria=(criterion,),
        event_value=envelope(observed_at=99),
    )

    assert first.derived_evidence == second.derived_evidence
    assert first.claims[0].claim_id == second.claims[0].claim_id
    assert first.claims[0].observed_at == second.claims[0].observed_at == 9


def test_approved_milestone_relation_is_persisted_on_claim() -> None:
    relation = ApprovedMilestoneLink(
        run_id="run-1",
        relation_id="relation-checkout",
        locator="src/api/schema.py:12",
        milestone_ids=("milestone-checkout",),
    )

    outcome, broker = extract([claim()], milestone_links=(relation,))

    assert outcome.claims[0].milestone_ids == ("milestone-checkout",)
    assert broker.requests[0].approved_milestone_links == (relation,)


def test_repository_change_is_bound_to_origin_and_session() -> None:
    event = envelope()
    change = ApprovedRepositoryChange(
        run_id=event.run_id,
        session_alias=event.session_alias,
        event_id="event-session-a-PostToolUse-5",
        change_id="change-payment",
        locator="src/payment.py",
        digest="b" * 64,
        observed_at=5,
    )
    projected_id = "repository-" + hashlib.sha256(
        canonical_json(change.model_dump(mode="json"))
    ).hexdigest()
    raw = claim() | {
        "evidence_ids": ["evidence-1", projected_id],
        "targets": [
            {
                "kind": "file",
                "target_id": "src/payment.py",
                "evidence_id": projected_id,
                "attributes": {},
            }
        ],
    }

    accepted, broker = extract(
        [raw],
        event_value=event,
        repository_changes=(change,),
    )
    wrong_session = change.model_copy(
        update={"session_alias": "session-b", "change_id": "change-other"}
    )
    rejected, _ = extract(
        [raw],
        event_value=event,
        repository_changes=(wrong_session,),
    )

    assert accepted.quarantine is None
    assert accepted.derived_evidence[0].source == "repository_change"
    assert broker.requests[0].approved_repository_changes == (change,)
    assert rejected.claims == ()
    assert rejected.quarantine is not None
    assert rejected.quarantine.reason == "unknown_evidence"


def test_edit_input_alone_does_not_project_repository_change_evidence() -> None:
    event = edit_event("src/payment.py").model_copy(
        update={
            "payload": {
                "tool_name": "functions.edit",
                "tool_input": {"path": "src/payment.py", "content": "safe"},
                "tool_response": {"status": "failed"},
            }
        }
    )
    raw = claim() | {
        "evidence_ids": ["evidence-1", "repository-forged"],
        "targets": [
            {
                "kind": "file",
                "target_id": "src/payment.py",
                "evidence_id": "repository-forged",
                "attributes": {},
            }
        ],
    }

    outcome, broker = extract([raw], event_value=event)

    assert broker.requests[0].approved_repository_changes == ()
    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unknown_evidence"


def test_redacted_authenticated_evidence_remains_reviewable() -> None:
    redacted = evidence(redaction_status="redacted")

    outcome, _ = extract([claim()], evidence_values=(redacted,))

    assert outcome.quarantine is None
    assert outcome.claims[0].provenance_status == "hook_authenticated"


def test_untrusted_hook_accepts_only_independent_factory_evidence() -> None:
    event = envelope(provenance_status="untrusted_provenance")
    frozen = evidence(
        provenance_status="independent_frozen",
        source="factory_transcript",
    )
    registry, (frozen,) = frozen_registry_for((frozen,))

    accepted, _ = extract(
        [claim()],
        event_value=event,
        evidence_values=(frozen,),
        frozen_evidence_registry=registry,
    )
    mixed, mixed_broker = extract(
        [claim(evidence_ids=["evidence-1", "agent-evidence"])],
        event_value=event,
        evidence_values=(frozen, evidence("agent-evidence")),
        frozen_evidence_registry=registry,
    )
    relabeled, relabeled_broker = extract(
        [claim()],
        event_value=event,
        evidence_values=(
            frozen.model_copy(update={"source": "agent_transcript"}),
        ),
        frozen_evidence_registry=registry,
    )

    assert accepted.quarantine is None
    assert accepted.claims[0].provenance_status == "independent_frozen"
    assert mixed.quarantine is not None
    assert mixed.quarantine.reason == "untrusted_provenance"
    assert mixed_broker.requests == []
    assert relabeled.quarantine is not None
    assert relabeled_broker.requests == []


def test_uncited_foreign_evidence_never_crosses_broker_boundary() -> None:
    foreign = evidence(
        "foreign-evidence",
        run_id="run-other",
        session="session-other",
    )

    outcome, broker = extract(
        [claim()],
        evidence_values=(evidence(), foreign),
    )

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "cross_run_evidence"
    assert broker.requests == []


def test_conflicting_approved_criteria_stop_before_broker() -> None:
    first = ApprovedMissionCriterion(
        run_id="run-1",
        criterion_id="criterion-a",
        locator="mission:acceptance-3",
        property="maximum",
        value=42,
        unit="cents",
        observed_at=1,
    )
    second = first.model_copy(
        update={"criterion_id": "criterion-b", "value": 43}
    )

    outcome, broker = extract(
        [claim(locator="mission:acceptance-3")],
        criteria=(first, second),
    )

    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "malformed_output"
    assert broker.requests == []


def test_broker_cannot_mutate_frozen_request_snapshot() -> None:
    class MutatingBroker:
        def extract(self, request: ExtractionRequest) -> BrokerAttempt:
            request.trigger_payload["forged"] = True
            return BrokerAttempt(boundary=boundary(), output=[claim()])

        def abort(self) -> bool:
            return True

    outcome = ClaimExtractor(MutatingBroker()).extract(
        envelope(),
        (evidence(),),
    )

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "malformed_output"



def test_approved_bash_change_triggers_extraction_and_cross_session_history() -> None:
    first_event = envelope(
        event="PostToolUse",
        session="session-a",
        payload={"tool_name": "Bash", "tool_response": {"status": "ok"}},
    )
    first_change = ApprovedRepositoryChange(
        run_id=first_event.run_id,
        session_alias=first_event.session_alias,
        event_id=first_event.event_id,
        change_id="change-a",
        locator="api-schema.json",
        digest="a" * 64,
        observed_at=first_event.observed_at,
    )
    projected_id = "repository-" + hashlib.sha256(
        canonical_json(first_change.model_dump(mode="json"))
    ).hexdigest()
    outcome, _ = extract(
        [
            claim(
                locator="api-schema.json",
                evidence_ids=[projected_id],
            )
            | {
                "targets": [
                    {
                        "kind": "file",
                        "target_id": "api-schema.json",
                        "evidence_id": projected_id,
                        "attributes": {},
                    }
                ]
            }
        ],
        event_value=first_event,
        evidence_values=(),
        repository_changes=(first_change,),
    )
    classifier = TriggerClassifier()
    classifier.observe(first_event, repository_changes=(first_change,))
    second_event = envelope(
        event="PostToolUse",
        session="session-b",
        payload={"tool_name": "Bash", "tool_response": {"status": "ok"}},
    )
    second_change = first_change.model_copy(
        update={
            "session_alias": second_event.session_alias,
            "event_id": second_event.event_id,
            "change_id": "change-b",
        }
    )
    second_triggers = classifier.observe(
        second_event,
        repository_changes=(second_change,),
    )

    assert outcome.quarantine is None
    assert outcome.trigger_kinds == ("contract_or_schema_edit",)
    assert len(outcome.claims) == 1
    assert "cross_session_edit" in second_triggers


def test_frozen_evidence_registry_requires_external_manifest_pin(
    tmp_path: Path,
) -> None:
    raw = evidence(
        provenance_status="independent_frozen",
        source="factory_observation",
    )
    payload = {
        "schema_version": "0.1",
        "evidence": [
            {
                "evidence_id": raw.evidence_id,
                "run_id": raw.run_id,
                "session_alias": raw.session_alias,
                "kind": raw.kind,
                "source": raw.source,
                "locator": raw.locator,
                "digest": raw.digest,
                "redaction_status": raw.redaction_status,
                "observed_at": raw.observed_at,
            }
        ],
    }
    manifest = tmp_path / "frozen-evidence.json"
    encoded = canonical_json(payload)
    manifest.write_bytes(encoded)
    expected_digest = hashlib.sha256(encoded).hexdigest()

    registry = load_frozen_evidence_registry(
        manifest,
        expected_digest=expected_digest,
    )
    bound = registry.bind(raw)
    registry.verify(bound)
    manifest.write_bytes(encoded + b"\n")
    with pytest.raises(EvidenceRegistryError, match="digest mismatch"):
        load_frozen_evidence_registry(
            manifest,
            expected_digest=expected_digest,
        )
