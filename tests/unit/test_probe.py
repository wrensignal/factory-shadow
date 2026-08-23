from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from shadow_mission.graph import MissionGraph
from shadow_mission.probe import (
    MAX_EVIDENCE,
    MAX_OUTPUT_BYTES,
    MAX_TEXT_BYTES,
    DuplicateProbeError,
    FileProbeBoundaryStateStore,
    InMemoryProbeBoundaryStateStore,
    ProbeAttempt,
    ProbeBoundary,
    ProbeBoundaryState,
    ProbeBroker,
    ProbeBusyError,
    ProbeJob,
    ProbeRunner,
    ProbeScheduler,
    ProbeSnapshot,
    ProbeSnapshotError,
    RecordedProbe,
    RecordedProbeBroker,
)
from shadow_mission.protocol import ClaimRecord, EvidenceRecord
from shadow_mission.rules import (
    AuthorityResolution,
    EvidenceAuthority,
    Finding,
    ProbeVerifier,
    normalize_value,
)

_SIGNING_KEY = b"probe-unit-signing-key-material-0001"
_CANARY = "PROBE-SECRET-CANARY-7142"
_EXCERPTS = {"evidence-a": "API excerpt: amount is cents."}
_DIFFS = {"evidence-a": "- dollars\n+ cents"}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def add_claim(
    graph: MissionGraph,
    *,
    claim_id: str,
    evidence_id: str,
    locator: str,
    value: str,
    kind: str = "repository_contract",
    source: str = "repository_contract",
) -> EvidenceRecord:
    evidence = EvidenceRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        evidence_id=evidence_id,
        run_id=graph.run_id,
        session_alias=f"session-{claim_id}",
        kind=kind,
        source=source,
        locator=locator,
        digest=digest(f"{evidence_id}-body"),
        observed_at=10,
    )
    graph.add_evidence(evidence)
    graph.add_claim(
        ClaimRecord(
            provenance_status="hook_authenticated",
            redaction_status="clean",
            claim_id=claim_id,
            run_id=graph.run_id,
            session_alias=f"session-{claim_id}",
            subject="amount",
            subject_locator=locator,
            property="unit",
            value=value,
            unit=None,
            confidence=0.95,
            evidence_ids=(evidence_id,),
            observed_at=10,
        )
    )
    return evidence


def graph_and_finding(repository: Path) -> tuple[MissionGraph, Finding]:
    (repository / "contracts").mkdir(parents=True)
    (repository / "schemas").mkdir(parents=True)
    (repository / "contracts" / "api.json").write_text('{"unit":"cents"}\n')
    (repository / "schemas" / "db.sql").write_text("amount_cents integer\n")
    graph = MissionGraph("run-probe")
    first = add_claim(
        graph,
        claim_id="claim-a",
        evidence_id="evidence-a",
        locator="contracts/api.json#/properties/amount",
        value="dollars",
    )
    second = add_claim(
        graph,
        claim_id="claim-b",
        evidence_id="evidence-b",
        locator="schemas/db.sql:payments.amount_cents",
        value="cents",
        kind="database_schema",
        source="database_schema",
    )
    key = digest("risk-a")
    finding = Finding(
        finding_id=f"finding-{key[:24]}",
        dedup_key=key,
        rule="cross_worker_conflict",
        level="concern",
        target_sessions=("session-claim-a", "session-claim-b"),
        claim_ids=("claim-a", "claim-b"),
        evidence_ids=("evidence-a", "evidence-b"),
        evidence_digests=tuple(sorted({first.digest, second.digest})),
        normalized_locators=("contracts/api.json", "schemas/db.sql"),
        normalized_properties=("unit",),
        normalized_units=(None,),
        normalized_values=("cents", "dollars"),
        authority=AuthorityResolution(
            "unresolved_same_authority", EvidenceAuthority.AUTHORITATIVE
        ),
        risk_category="security",
        probe_status="pending",
    )
    return graph, finding


def snapshot_for(repository: Path) -> tuple[ProbeSnapshot, Finding, MissionGraph]:
    graph, finding = graph_and_finding(repository)
    snapshot = ProbeSnapshot.from_finding(
        finding,
        graph,
        repository,
        excerpts=_EXCERPTS,
        diffs=_DIFFS,
    )
    return snapshot, finding, graph


def boundary(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "0.1",
        "factory_home": "clean",
        "timeout_seconds": 90,
        "shadow_activation_stripped": True,
        "mission_correlation_stripped": True,
        "internal_session_alias": "session-probe-001",
        "environment_keys": ["HOME", "PATH"],
        "list_tools_observed": True,
        "observed_tools": [],
        "enabled_tools": [],
        "collector_event_count": 0,
        "collector_events": [],
    }
    value.update(changes)
    return value


def output_for(
    snapshot: ProbeSnapshot,
    status: str = "confirmed",
    *,
    evidence: tuple[str, ...] | None = None,
    claims: tuple[str, ...] | None = None,
    level: str = "blocker",
) -> dict[str, object]:
    output: dict[str, object] = {
        "status": status,
        "authoritative_evidence": list(
            evidence
            if evidence is not None
            else (() if status == "inconclusive" else ("evidence-a",))
        ),
        "affected_claim_ids": list(
            claims if claims is not None else tuple(item.claim_id for item in snapshot.claims)
        ),
        "recommended_level": level,
        "reason": "Repository-owned evidence resolves the disputed unit.",
        "authoritative_value": "cents" if status == "confirmed" else None,
    }
    return output


def recorded_probe(
    snapshot_digest: str,
    *,
    output: bytes | str | None = None,
    boundary_value: object | None = None,
    timed_out: bool = False,
    usage: object | None = None,
) -> RecordedProbe:
    return RecordedProbe(
        boundary_value if boundary_value is not None else boundary(),
        ProbeAttempt(snapshot_digest, output, timed_out=timed_out, usage=usage),
    )


def runner_for(
    broker: ProbeBroker,
    *,
    state_store: InMemoryProbeBoundaryStateStore | None = None,
) -> ProbeRunner:
    approved_digest = ProbeBoundary.model_validate(boundary()).policy_digest
    store = state_store or InMemoryProbeBoundaryStateStore(
        ProbeBoundaryState.enabled(approved_digest)
    )
    return ProbeRunner(
        broker,
        signing_key=_SIGNING_KEY,
        approved_boundary_digest=approved_digest,
        boundary_state_store=store,
    )


def run_attempt(
    snapshot: ProbeSnapshot,
    finding: Finding,
    graph: MissionGraph,
    repository: Path,
    *,
    output: object | None,
    boundary_value: object | None = None,
    timed_out: bool = False,
    usage: object | None = None,
    attempt_digest: str | None = None,
    secret_canaries: tuple[str, ...] = (),
    include_standard_materials: bool = True,
):
    encoded_output = (
        output
        if output is None or isinstance(output, (bytes, str))
        else json.dumps(output, ensure_ascii=False).encode("utf-8")
    )
    prepared_boundary = boundary_value if boundary_value is not None else boundary()
    broker = RecordedProbeBroker(
        recorded_probe(
            attempt_digest or snapshot.digest,
            output=encoded_output,
            boundary_value=prepared_boundary,
            timed_out=timed_out,
            usage=usage,
        )
    )
    try:
        approved_digest = ProbeBoundary.model_validate(prepared_boundary).policy_digest
    except (TypeError, ValueError):
        approved_digest = ProbeBoundary.model_validate(boundary()).policy_digest
    state_store = InMemoryProbeBoundaryStateStore(
        ProbeBoundaryState.enabled(approved_digest)
    )
    runner = ProbeRunner(
        broker,
        signing_key=_SIGNING_KEY,
        approved_boundary_digest=approved_digest,
        boundary_state_store=state_store,
    )
    return (
        runner.run(
            snapshot,
            finding,
            graph,
            repository,
            probe_id="probe-001",
            observed_at=20,
            excerpts=_EXCERPTS if include_standard_materials else None,
            diffs=_DIFFS if include_standard_materials else None,
            secret_canaries=secret_canaries,
        ),
        broker,
    )


def test_file_probe_boundary_state_store_persists_fail_closed_state(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    path = private_root / "probe-boundary.json"
    enabled = ProbeBoundaryState.enabled("a" * 64)
    store = FileProbeBoundaryStateStore(path, enabled)

    assert store.load() == enabled
    disabled = enabled.stop(stopped_at=25)
    store.save(disabled)
    assert FileProbeBoundaryStateStore(path, enabled).load() == disabled

    with pytest.raises(ValueError, match="immutable"):
        store.save(enabled)

def test_plain_value_error_latches_probe_boundary_fail_closed(
    tmp_path: Path,
) -> None:
    approved_digest = ProbeBoundary.model_validate(boundary()).policy_digest

    class InvalidStore:
        def load(self) -> ProbeBoundaryState:
            raise ValueError("invalid persisted boundary")

        def save(self, state: ProbeBoundaryState) -> None:
            raise AssertionError(f"unexpected save: {state}")

    runner = runner_for(
        RecordedProbeBroker(
            recorded_probe(
                "b" * 64,
                output="{}",
            )
        ),
        state_store=InvalidStore(),
    )

    assert runner._boundary_allows_probes() is False
    assert runner._boundary_disabled is True



def test_plain_value_error_still_persists_probe_boundary_stop(
    tmp_path: Path,
) -> None:
    approved_digest = ProbeBoundary.model_validate(boundary()).policy_digest

    class RecoveringStore:
        def __init__(self) -> None:
            self.saved: ProbeBoundaryState | None = None

        def load(self) -> ProbeBoundaryState:
            raise ValueError("invalid persisted boundary")

        def save(self, state: ProbeBoundaryState) -> None:
            self.saved = state

    store = RecoveringStore()
    runner = runner_for(
        RecordedProbeBroker(
            recorded_probe(
                "b" * 64,
                output="{}",
            )
        ),
        state_store=store,
    )

    runner._disable_boundary(observed_at=25)

    assert runner._boundary_disabled is True
    assert store.saved == ProbeBoundaryState.enabled(approved_digest).stop(
        stopped_at=25
    )


@pytest.mark.parametrize(
    ("status", "expected_value", "level"),
    [
        ("confirmed", normalize_value("cents"), "blocker"),
        ("not_confirmed", None, "concern"),
        ("inconclusive", None, "concern"),
    ],
)
def test_valid_results_map_to_signed_probe_assessments(
    tmp_path: Path, status: str, expected_value: str | None, level: str
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    outcome, _ = run_attempt(
        snapshot,
        finding,
        graph,
        tmp_path,
        output=output_for(snapshot, status, level=level),
    )

    assert outcome.quarantine is None
    assert outcome.assessment is not None
    assert outcome.assessment.status == status
    assert outcome.assessment.authoritative_value == expected_value
    assert outcome.assessment.recommended_level == level
    attempt_boundary = ProbeBoundary.model_validate(boundary())
    assert outcome.assessment.boundary_digest == attempt_boundary.digest
    assert outcome.assessment.boundary_policy_digest == attempt_boundary.policy_digest
    assert outcome.assessment.snapshot_digest == snapshot.digest
    verifier = ProbeVerifier(
        _SIGNING_KEY,
        boundary_digest=ProbeBoundary.model_validate(boundary()).policy_digest,
    )
    assert verifier.verify(outcome.assessment, snapshot_digest=snapshot.digest)


def test_fresh_session_alias_changes_attempt_digest_but_not_approved_policy(
    tmp_path: Path,
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    approved = ProbeBoundary.model_validate(boundary())
    fresh = ProbeBoundary.model_validate(
        boundary(internal_session_alias="session-probe-random-9281")
    )
    broker = RecordedProbeBroker(
        recorded_probe(
            snapshot.digest,
            output=json.dumps(output_for(snapshot, level="concern")),
            boundary_value=fresh,
        )
    )

    outcome = runner_for(broker).run(
        snapshot,
        finding,
        graph,
        tmp_path,
        probe_id="probe-random-alias",
        observed_at=20,
        excerpts=_EXCERPTS,
        diffs=_DIFFS,
    )

    assert approved.digest != fresh.digest
    assert approved.policy_digest == fresh.policy_digest
    changed_policy = ProbeBoundary.model_validate(
        boundary(environment_keys=["HOME"])
    )
    assert approved.policy_digest != changed_policy.policy_digest
    assert outcome.quarantine is None
    assert outcome.assessment is not None
    assert outcome.assessment.boundary_digest == fresh.digest
    assert outcome.assessment.boundary_policy_digest == approved.policy_digest
    verifier = ProbeVerifier(
        _SIGNING_KEY,
        boundary_digest=approved.policy_digest,
    )
    assert verifier.verify(outcome.assessment, snapshot_digest=snapshot.digest)
    assert not verifier.verify(outcome.assessment, snapshot_digest="f" * 64)


def test_scheduler_proxies_idempotent_probe_abort_acknowledgment() -> None:
    broker = RecordedProbeBroker(recorded_probe("0" * 64))
    scheduler = ProbeScheduler(runner_for(broker))
    broker.prepare()

    assert scheduler.abort() is True
    assert scheduler.abort() is True


def test_prepare_completes_before_snapshot_send(tmp_path: Path) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)

    class OrderedBroker:
        def __init__(self) -> None:
            self.events: list[str] = []

        def prepare(self) -> object:
            self.events.append("prepare")
            return boundary()

        def send(self, sent: ProbeSnapshot) -> ProbeAttempt:
            assert self.events == ["prepare"]
            assert sent.digest == snapshot.digest
            self.events.append("send")
            return ProbeAttempt(
                snapshot.digest,
                json.dumps(output_for(snapshot)),
            )

        def abort(self) -> bool:
            return True

    broker = OrderedBroker()
    outcome = runner_for(broker).run(
        snapshot,
        finding,
        graph,
        tmp_path,
        probe_id="probe-ordered",
        observed_at=20,
        excerpts=_EXCERPTS,
        diffs=_DIFFS,
    )

    assert outcome.assessment is not None
    assert broker.events == ["prepare", "send"]


def test_snapshot_has_stable_exact_identity_and_only_direct_repository_files(
    tmp_path: Path,
) -> None:
    graph, finding = graph_and_finding(tmp_path)
    first = ProbeSnapshot.from_finding(
        finding,
        graph,
        tmp_path,
        excerpts={"evidence-b": "DB excerpt", "evidence-a": "API excerpt"},
    )
    second = ProbeSnapshot.from_finding(
        finding,
        graph,
        tmp_path,
        excerpts={"evidence-a": "API excerpt", "evidence-b": "DB excerpt"},
    )

    assert first == second
    assert first.digest == second.digest
    assert tuple(item.claim_id for item in first.claims) == finding.claim_ids
    assert tuple(item.evidence_id for item in first.evidence) == finding.evidence_ids
    assert tuple(item.path for item in first.repository_files) == (
        "contracts/api.json",
        "schemas/db.sql",
    )
    assert first.repository_files[0].content == '{"unit":"cents"}\n'


@pytest.mark.parametrize("reference", ["claim", "evidence", "digest"])
def test_missing_or_changed_finding_references_reject_before_broker(
    tmp_path: Path, reference: str
) -> None:
    graph, finding = graph_and_finding(tmp_path)
    if reference == "claim":
        finding = replace(finding, claim_ids=("claim-missing",))
    elif reference == "evidence":
        finding = replace(finding, evidence_ids=("evidence-missing",))
    else:
        finding = replace(finding, evidence_digests=("0" * 64,))
    broker = RecordedProbeBroker(recorded_probe("0" * 64))
    runner = runner_for(broker)

    with pytest.raises(ProbeSnapshotError):
        runner.run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
        )

    assert broker.requests == []


@pytest.mark.parametrize(
    "unsafe_path",
    ["../outside.txt", "contracts/../outside.txt", "/tmp/outside.txt"],
)
def test_absolute_and_traversal_paths_reject_before_broker(
    tmp_path: Path, unsafe_path: str
) -> None:
    graph, finding = graph_and_finding(tmp_path)
    broker = RecordedProbeBroker(recorded_probe("0" * 64))
    runner = runner_for(broker)

    with pytest.raises(ProbeSnapshotError):
        runner.run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
            repository_paths={"evidence-a": unsafe_path},
        )

    assert broker.requests == []
    assert broker.prepared_count == 0

@pytest.mark.parametrize(
    "protected",
    [
        ".env",
        ".aws/credentials",
        ".git/config",
        ".shadow-mission/run",
        ".ssh/id_ed25519",
        "config/credential.txt",
    ],
)
def test_protected_paths_reject_before_broker(tmp_path: Path, protected: str) -> None:
    protected_path = tmp_path / protected
    protected_path.parent.mkdir(parents=True, exist_ok=True)
    protected_path.write_text("private")
    graph = MissionGraph("run-probe")
    record = add_claim(
        graph,
        claim_id="claim-a",
        evidence_id="evidence-a",
        locator=protected,
        value="x",
    )
    finding = single_finding(record, locator=protected)
    broker = RecordedProbeBroker(recorded_probe("0" * 64))

    with pytest.raises(ProbeSnapshotError):
        runner_for(broker).run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
        )

    assert broker.requests == []
    assert broker.prepared_count == 0


def single_finding(record: EvidenceRecord, *, locator: str) -> Finding:
    key = digest(f"single:{locator}")
    return Finding(
        finding_id=f"finding-{key[:24]}",
        dedup_key=key,
        rule="shared_assumption",
        level="concern",
        target_sessions=("session-claim-a",),
        claim_ids=("claim-a",),
        evidence_ids=(record.evidence_id,),
        evidence_digests=(record.digest,),
        normalized_locators=(locator,),
        normalized_properties=("unit",),
        normalized_units=(None,),
        normalized_values=("x",),
        authority=AuthorityResolution("non_authoritative", EvidenceAuthority.UNKNOWN),
        risk_category="none",
        probe_status="pending",
    )


def test_symlink_escape_rejects_before_broker(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("outside")
    (tmp_path / "escape.txt").symlink_to(outside)
    graph = MissionGraph("run-probe")
    record = add_claim(
        graph,
        claim_id="claim-a",
        evidence_id="evidence-a",
        locator="escape.txt",
        value="x",
    )
    finding = single_finding(record, locator="escape.txt")
    broker = RecordedProbeBroker(recorded_probe("0" * 64))

    with pytest.raises(ProbeSnapshotError):
        runner_for(broker).run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
        )

    assert broker.requests == []
    assert broker.prepared_count == 0


def test_directory_symlink_swap_stays_confined_to_opened_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cited_directory = tmp_path / "safe"
    cited_directory.mkdir()
    (cited_directory / "contract.txt").write_text("approved content")
    outside_directory = tmp_path.parent / f"{tmp_path.name}-outside-dir"
    outside_directory.mkdir()
    (outside_directory / "contract.txt").write_text(_CANARY)
    graph = MissionGraph("run-probe")
    record = add_claim(
        graph,
        claim_id="claim-a",
        evidence_id="evidence-a",
        locator="safe/contract.txt",
        value="x",
    )
    finding = single_finding(record, locator=record.locator)
    original_open = os.open
    swapped = False

    def swap_after_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == "safe" and dir_fd is not None and not swapped:
            swapped = True
            cited_directory.rename(tmp_path / "opened-safe")
            cited_directory.symlink_to(outside_directory, target_is_directory=True)
        return descriptor

    monkeypatch.setattr("shadow_mission.probe.os.open", swap_after_open)

    snapshot = ProbeSnapshot.from_finding(
        finding,
        graph,
        tmp_path,
        secret_canaries=(_CANARY,),
    )

    assert swapped
    assert snapshot.repository_files[0].content == "approved content"


def test_nonregular_file_rejects_before_broker(tmp_path: Path) -> None:
    (tmp_path / "named").mkdir()
    graph = MissionGraph("run-probe")
    record = add_claim(
        graph,
        claim_id="claim-a",
        evidence_id="evidence-a",
        locator="named",
        value="x",
    )
    finding = single_finding(record, locator="named")
    broker = RecordedProbeBroker(recorded_probe("0" * 64))

    with pytest.raises(ProbeSnapshotError):
        runner_for(broker).run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
        )

    assert broker.requests == []
    assert broker.prepared_count == 0


@pytest.mark.parametrize("unsafe_text", [_CANARY, "[shadow:risk-123]"])
def test_secret_canary_and_shadow_marker_reject_before_broker(
    tmp_path: Path, unsafe_text: str
) -> None:
    graph, finding = graph_and_finding(tmp_path)
    broker = RecordedProbeBroker(recorded_probe("0" * 64))

    with pytest.raises(ProbeSnapshotError):
        runner_for(broker).run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
            excerpts={"evidence-a": unsafe_text},
            secret_canaries=(_CANARY,),
        )

    assert broker.requests == []
    assert broker.prepared_count == 0


@pytest.mark.parametrize(
    ("material_name", "unsafe_text"),
    [
        ("excerpts", '"api_key": "raw-value"'),
        ("diffs", "+ AWS_SECRET_ACCESS_KEY=raw-value"),
        ("test_results", "password: raw-value"),
        ("excerpts", "credential = raw-value"),
        ("diffs", "private-key: raw-value"),
    ],
)
def test_structured_credentials_reject_material_before_broker(
    tmp_path: Path,
    material_name: str,
    unsafe_text: str,
) -> None:
    if material_name == "test_results":
        graph = MissionGraph("run-probe")
        record = add_claim(
            graph,
            claim_id="claim-a",
            evidence_id="evidence-a",
            locator="tests/test_contract.py::test_contract",
            value="passed",
            kind="integration_test",
            source="integration_test",
        )
        finding = single_finding(record, locator=record.locator)
    else:
        graph, finding = graph_and_finding(tmp_path)
    broker = RecordedProbeBroker(recorded_probe("0" * 64))
    materials = {material_name: {"evidence-a": unsafe_text}}

    with pytest.raises(ProbeSnapshotError, match="unsafe_material"):
        runner_for(broker).run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
            **materials,
        )

    assert broker.prepared_count == 0
    assert broker.requests == []


def test_structured_credential_in_cited_file_rejects_before_broker(
    tmp_path: Path,
) -> None:
    graph, finding = graph_and_finding(tmp_path)
    (tmp_path / "contracts" / "api.json").write_text(
        '{"api_token": "raw-value"}\n'
    )
    broker = RecordedProbeBroker(recorded_probe("0" * 64))

    with pytest.raises(ProbeSnapshotError, match="unsafe_material"):
        runner_for(broker).run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
        )

    assert broker.prepared_count == 0
    assert broker.requests == []


def test_canary_in_cited_file_rejects_before_broker(tmp_path: Path) -> None:
    graph, finding = graph_and_finding(tmp_path)
    (tmp_path / "contracts" / "api.json").write_text(f"value={_CANARY}\n")
    broker = RecordedProbeBroker(recorded_probe("0" * 64))

    with pytest.raises(ProbeSnapshotError, match="secret_canary"):
        runner_for(broker).run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
            secret_canaries=(_CANARY,),
        )

    assert broker.prepared_count == 0
    assert broker.requests == []


def test_bounded_file_size_rejects_before_broker(tmp_path: Path) -> None:
    graph, finding = graph_and_finding(tmp_path)
    (tmp_path / "contracts" / "api.json").write_text("x" * (MAX_TEXT_BYTES + 1))
    broker = RecordedProbeBroker(recorded_probe("0" * 64))

    with pytest.raises(ProbeSnapshotError):
        runner_for(broker).run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
        )

    assert broker.requests == []
def test_supplied_test_result_is_bound_to_cited_evidence(tmp_path: Path) -> None:
    graph = MissionGraph("run-probe")
    record = add_claim(
        graph,
        claim_id="claim-a",
        evidence_id="evidence-a",
        locator="tests/test_amount.py::test_amount",
        value="passed",
        kind="integration_test",
        source="integration_test",
    )
    finding = single_finding(record, locator=record.locator)

    snapshot = ProbeSnapshot.from_finding(
        finding,
        graph,
        tmp_path,
        test_results={"evidence-a": "1 passed in 0.02s"},
    )

    assert len(snapshot.materials) == 1
    assert snapshot.materials[0].kind == "test_result"
    assert snapshot.materials[0].evidence_id == "evidence-a"


def test_evidence_count_limit_rejects_before_broker(tmp_path: Path) -> None:
    graph = MissionGraph("run-probe")
    records = [
        add_claim(
            graph,
            claim_id=f"claim-{index:03}",
            evidence_id=f"evidence-{index:03}",
            locator=f"contracts/contract-{index:03}.json",
            value=str(index),
        )
        for index in range(MAX_EVIDENCE + 1)
    ]
    claim_ids = tuple(sorted(f"claim-{index:03}" for index in range(MAX_EVIDENCE + 1)))
    evidence_ids = tuple(
        sorted(f"evidence-{index:03}" for index in range(MAX_EVIDENCE + 1))
    )
    key = digest("too-many-evidence-records")
    finding = Finding(
        finding_id=f"finding-{key[:24]}",
        dedup_key=key,
        rule="shared_assumption",
        level="concern",
        target_sessions=("session-target",),
        claim_ids=claim_ids,
        evidence_ids=evidence_ids,
        evidence_digests=tuple(sorted({item.digest for item in records})),
        normalized_locators=("contracts",),
        normalized_properties=("unit",),
        normalized_units=(None,),
        normalized_values=("many",),
        authority=AuthorityResolution("non_authoritative", EvidenceAuthority.UNKNOWN),
        risk_category="none",
        probe_status="pending",
    )
    broker = RecordedProbeBroker(recorded_probe("0" * 64))

    with pytest.raises(ProbeSnapshotError):
        runner_for(broker).run_finding(
            finding,
            graph,
            tmp_path,
            probe_id="probe-rejected",
            observed_at=20,
        )

    assert broker.requests == []




@pytest.mark.parametrize(
    "catalog",
    [[], [{"tool_id": "Read", "allowed": False}, {"tool_id": "Edit", "allowed": False}]],
)
def test_empty_and_all_disabled_tool_catalogs_are_accepted(
    tmp_path: Path, catalog: list[dict[str, object]]
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    outcome, _ = run_attempt(snapshot, finding, graph, tmp_path, output=output_for(snapshot), boundary_value=boundary(observed_tools=catalog),)

    assert outcome.assessment is not None
    assert outcome.quarantine is None


@pytest.mark.parametrize(
    "unsafe_boundary",
    [
        boundary(observed_tools=[{"tool_id": "Read", "allowed": True}]),
        boundary(enabled_tools=["Read"]),
        boundary(list_tools_observed=False),
        boundary(shadow_activation_stripped=False),
        boundary(mission_correlation_stripped=False),
        boundary(environment_keys=["SHADOW_MISSION_RUN_SECRET"]),
    ],
)
def test_enabled_or_unproven_tool_boundary_is_quarantined(
    tmp_path: Path, unsafe_boundary: dict[str, object]
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    outcome, broker = run_attempt(
        snapshot,
        finding,
        graph,
        tmp_path,
        output=output_for(snapshot),
        boundary_value=unsafe_boundary,
    )

    assert outcome.assessment is None
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unsafe_boundary"
    assert broker.requests == []

def test_unsafe_prepare_stops_boundary_across_runner_restart(tmp_path: Path) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    approved_digest = ProbeBoundary.model_validate(boundary()).policy_digest
    state_store = InMemoryProbeBoundaryStateStore(
        ProbeBoundaryState.enabled(approved_digest)
    )
    first_broker = RecordedProbeBroker(
        recorded_probe(
            snapshot.digest,
            output=json.dumps(output_for(snapshot)),
            boundary_value=boundary(enabled_tools=["Read"]),
        )
    )
    first_runner = runner_for(first_broker, state_store=state_store)

    first = first_runner.run(
        snapshot,
        finding,
        graph,
        tmp_path,
        probe_id="probe-a",
        observed_at=20,
        excerpts=_EXCERPTS,
        diffs=_DIFFS,
    )

    second_broker = RecordedProbeBroker(
        recorded_probe(snapshot.digest, output=json.dumps(output_for(snapshot)))
    )
    restarted_runner = runner_for(second_broker, state_store=state_store)
    second = restarted_runner.run(
        snapshot,
        finding,
        graph,
        tmp_path,
        probe_id="probe-b",
        observed_at=21,
        excerpts=_EXCERPTS,
        diffs=_DIFFS,
    )

    assert first.quarantine is not None
    assert first.quarantine.reason == "unsafe_boundary"
    assert second.quarantine is not None
    assert second.quarantine.reason == "unsafe_boundary"
    assert first_broker.requests == []
    assert second_broker.prepared_count == 0
    assert second_broker.requests == []
    assert first_broker.abort() is True
    assert first_broker.abort() is True
    with pytest.raises(RuntimeError, match="not prepared"):
        first_broker.send(snapshot)


def test_prepare_exception_stops_boundary_across_runner_restart(
    tmp_path: Path,
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    approved_digest = ProbeBoundary.model_validate(boundary()).policy_digest
    state_store = InMemoryProbeBoundaryStateStore(
        ProbeBoundaryState.enabled(approved_digest)
    )

    class FailingPrepareBroker:
        def prepare(self) -> object:
            raise RuntimeError("prepare failed")

        def send(self, _snapshot: ProbeSnapshot) -> ProbeAttempt:
            raise AssertionError("send must not follow failed preparation")

        def abort(self) -> bool:
            return True

    first = runner_for(FailingPrepareBroker(), state_store=state_store).run(
        snapshot,
        finding,
        graph,
        tmp_path,
        probe_id="probe-prepare-failure",
        observed_at=20,
        excerpts=_EXCERPTS,
        diffs=_DIFFS,
    )
    second_broker = RecordedProbeBroker(
        recorded_probe(snapshot.digest, output=json.dumps(output_for(snapshot)))
    )
    second = runner_for(second_broker, state_store=state_store).run(
        snapshot,
        finding,
        graph,
        tmp_path,
        probe_id="probe-after-prepare-failure",
        observed_at=21,
        excerpts=_EXCERPTS,
        diffs=_DIFFS,
    )

    assert first.quarantine is not None
    assert first.quarantine.reason == "unsafe_boundary"
    assert second.quarantine is not None
    assert second.quarantine.reason == "unsafe_boundary"
    assert second_broker.prepared_count == 0




@pytest.mark.parametrize(
    "leak",
    [boundary(collector_event_count=1), boundary(collector_events=["event-internal"])],
)
def test_internal_collector_event_leakage_is_quarantined(
    tmp_path: Path, leak: dict[str, object]
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    outcome, _ = run_attempt(snapshot, finding, graph, tmp_path, output=output_for(snapshot), boundary_value=leak,)

    assert outcome.assessment is None
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unsafe_boundary"


@pytest.mark.parametrize(
    ("bad_output", "reason"),
    [
        ({"status": "confirmed"}, "malformed_output"),
        (b"\xff", "malformed_output"),
        ("{", "malformed_output"),
        (None, "missing_output"),
    ],
)
def test_malformed_or_missing_output_is_bounded_quarantine(
    tmp_path: Path, bad_output: object | None, reason: str
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    outcome, _ = run_attempt(
        snapshot,
        finding,
        graph,
        tmp_path,
        output=bad_output,
    )

    assert outcome.assessment is None
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == reason
    assert not hasattr(outcome.quarantine, "output")


def test_uncited_and_wrong_claim_outputs_are_quarantined(tmp_path: Path) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    uncited, _ = run_attempt(snapshot, finding, graph, tmp_path, output=output_for(snapshot, evidence=()), )
    wrong_claim, _ = run_attempt(snapshot, finding, graph, tmp_path, output=output_for(snapshot, claims=("claim-a",)), )

    assert uncited.quarantine is not None
    assert uncited.quarantine.reason == "uncited_output"
    assert wrong_claim.quarantine is not None
    assert wrong_claim.quarantine.reason == "uncited_output"


@pytest.mark.parametrize("forgery", ["claim_value", "authority", "file_content"])
def test_forged_snapshot_content_rejects_before_prepare(
    tmp_path: Path, forgery: str
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    raw = snapshot.model_dump(mode="json")
    if forgery == "claim_value":
        raw["claims"][0]["value"] = "forged"
    elif forgery == "authority":
        raw["evidence"][0]["authoritative"] = False
    else:
        raw["repository_files"][0]["content"] = "forged\n"
        raw["repository_files"][0]["content_digest"] = digest("forged\n")
    changed = ProbeSnapshot.model_validate(raw)

    outcome, broker = run_attempt(
        changed,
        finding,
        graph,
        tmp_path,
        output=output_for(changed),
    )

    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "snapshot_mismatch"
    assert broker.prepared_count == 0
    assert broker.requests == []


def test_over_deterministic_maximum_is_quarantined(tmp_path: Path) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    finding = replace(finding, risk_category="none")
    snapshot = ProbeSnapshot.from_finding(finding, graph, tmp_path)
    outcome, _ = run_attempt(
        snapshot,
        finding,
        graph,
        tmp_path,
        output=output_for(snapshot, level="blocker"),
        include_standard_materials=False,
    )

    assert outcome.assessment is None
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "over_escalated_output"


def test_attempt_must_bind_exact_snapshot_identity(tmp_path: Path) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    outcome, _ = run_attempt(snapshot, finding, graph, tmp_path, output=output_for(snapshot), attempt_digest="f" * 64,)

    assert outcome.assessment is None
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "snapshot_mismatch"


def test_timeout_is_exactly_90_seconds_and_never_assessed(tmp_path: Path) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    timed_out, _ = run_attempt(snapshot, finding, graph, tmp_path, output=output_for(snapshot), timed_out=True,)
    wrong_timeout, _ = run_attempt(snapshot, finding, graph, tmp_path, output=output_for(snapshot), boundary_value=boundary(timeout_seconds=89),)

    assert timed_out.quarantine is not None
    assert timed_out.quarantine.reason == "timeout"
    assert wrong_timeout.quarantine is not None
    assert wrong_timeout.quarantine.reason == "unsafe_boundary"


def test_usage_unavailable_does_not_invent_cost(tmp_path: Path) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    outcome, _ = run_attempt(snapshot, finding, graph, tmp_path, output=output_for(snapshot), usage=None)

    assert outcome.usage.status == "unavailable"
    assert outcome.usage.input_tokens is None
    assert outcome.usage.output_tokens is None
    assert outcome.usage.cost_usd is None


def test_unsafe_raw_output_is_not_copied_to_quarantine(tmp_path: Path) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    unsafe = output_for(snapshot)
    unsafe["reason"] = f"leaked {_CANARY}"
    outcome, _ = run_attempt(snapshot, finding, graph, tmp_path, output=unsafe, secret_canaries=(_CANARY,),)

    assert outcome.assessment is None
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unsafe_output"
    assert _CANARY not in outcome.quarantine.model_dump_json()


@pytest.mark.parametrize(
    "canary",
    [
        "canary-\u2603-\u03bb",
        "quote\"-slash\\/-newline\n-control-\x01",
    ],
)
def test_escaped_canaries_are_rejected_after_json_decode(
    tmp_path: Path, canary: str
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    output = output_for(snapshot)
    output["reason"] = f"nested {canary}"
    escaped = json.dumps(output, ensure_ascii=True).encode("utf-8")

    outcome, _ = run_attempt(
        snapshot,
        finding,
        graph,
        tmp_path,
        output=escaped,
        secret_canaries=(canary,),
    )

    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unsafe_output"


def test_oversized_raw_bytes_reject_before_json_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    decoded = False

    def reject_decode(_: object) -> object:
        nonlocal decoded
        decoded = True
        raise AssertionError("oversized output reached JSON decode")

    monkeypatch.setattr("shadow_mission.probe.json.loads", reject_decode)
    outcome, _ = run_attempt(
        snapshot,
        finding,
        graph,
        tmp_path,
        output=b"x" * (MAX_OUTPUT_BYTES + 1),
    )

    assert not decoded
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unsafe_output"


def second_job(
    tmp_path: Path, snapshot: ProbeSnapshot, finding: Finding
) -> tuple[ProbeSnapshot, Finding]:
    key = digest("risk-b")
    finding_two = replace(
        finding,
        finding_id=f"finding-{key[:24]}",
        dedup_key=key,
    )
    raw = snapshot.model_dump(mode="json")
    raw["finding_id"] = finding_two.finding_id
    raw["finding_dedup_key"] = finding_two.dedup_key
    return ProbeSnapshot.model_validate(raw), finding_two


def test_scheduler_is_fifo_and_rejects_duplicate_risk(tmp_path: Path) -> None:
    first_snapshot, first_finding, graph = snapshot_for(tmp_path)
    second_snapshot, second_finding = second_job(tmp_path, first_snapshot, first_finding)
    broker = RecordedProbeBroker(
        (
            recorded_probe(
                first_snapshot.digest,
                output=json.dumps(
                    output_for(
                        first_snapshot,
                        status="not_confirmed",
                        level="concern",
                    )
                ),
            ),
            recorded_probe(
                second_snapshot.digest,
                output=json.dumps(
                    output_for(
                        second_snapshot,
                        status="inconclusive",
                        level="concern",
                    )
                ),
            ),
        )
    )
    scheduler = ProbeScheduler(runner_for(broker))
    first_job = ProbeJob(
        first_snapshot,
        first_finding,
        "probe-a",
        20,
        graph,
        tmp_path,
        excerpts=_EXCERPTS,
        diffs=_DIFFS,
    )
    scheduler.enqueue(first_job)
    scheduler.enqueue(
        ProbeJob(
            second_snapshot,
            second_finding,
            "probe-b",
            21,
            graph,
            tmp_path,
            excerpts=_EXCERPTS,
            diffs=_DIFFS,
        )
    )

    with pytest.raises(DuplicateProbeError):
        scheduler.enqueue(first_job)

    first = scheduler.run_next()
    second = scheduler.run_next()

    assert first is not None and first.assessment is not None
    assert second is not None and second.assessment is not None
    assert first.assessment.finding_dedup_key == first_finding.dedup_key
    assert second.assessment.finding_dedup_key == second_finding.dedup_key
    assert [item.finding_dedup_key for item in broker.requests] == [
        first_finding.dedup_key,
        second_finding.dedup_key,
    ]


class BlockingRecordedBroker(RecordedProbeBroker):
    def __init__(self, probe: RecordedProbe) -> None:
        super().__init__(probe)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.active = 0
        self.maximum_active = 0

    def send(self, snapshot: ProbeSnapshot) -> ProbeAttempt:
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        self.entered.set()
        assert self.release.wait(timeout=2)
        try:
            return super().send(snapshot)
        finally:
            self.active -= 1


def test_scheduler_allows_at_most_one_concurrent_probe(tmp_path: Path) -> None:
    snapshot, finding, graph = snapshot_for(tmp_path)
    broker = BlockingRecordedBroker(
        recorded_probe(
            snapshot.digest,
            output=json.dumps(output_for(snapshot)),
        )
    )
    scheduler = ProbeScheduler(runner_for(broker))
    scheduler.enqueue(
        ProbeJob(
            snapshot,
            finding,
            "probe-a",
            20,
            graph,
            tmp_path,
            excerpts=_EXCERPTS,
            diffs=_DIFFS,
        )
    )
    outcomes: list[object] = []
    thread = threading.Thread(target=lambda: outcomes.append(scheduler.run_next()))
    thread.start()
    assert broker.entered.wait(timeout=2)

    with pytest.raises(ProbeBusyError):
        scheduler.run_next()

    broker.release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert broker.maximum_active == 1
    assert len(outcomes) == 1
