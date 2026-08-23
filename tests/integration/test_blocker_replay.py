from __future__ import annotations

import hashlib
import os

import pytest

from shadow_mission.auth import AuthenticationError, generate_run_secret
from shadow_mission.protocol import canonical_json, hook_envelope_digest
from shadow_mission.router import InterventionLatchStore, InterventionRouter
from shadow_mission.rules import DeliverySelector, DeliverySelectorState, DeterministicRules
from shadow_mission.storage import EventLedger, LedgerError, ResponsePlan
from tests.unit.test_router import (
    RUN_ID,
    VERIFIER,
    commit,
    event,
    make_capabilities,
    make_finding,
    make_graph,
    make_probe,
)


def request_digest(envelope) -> str:
    return hook_envelope_digest(envelope)


def test_after_append_failure_poison_prevents_partial_state_replay(tmp_path) -> None:
    run_dir = tmp_path / "run"
    private_root = tmp_path / "private"
    secret = generate_run_secret()
    store = InterventionLatchStore(private_root, run_id=RUN_ID, secret=secret)
    graph = make_graph()
    capabilities = make_capabilities()
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    crashed = EventLedger(
        run_dir,
        run_id=RUN_ID,
        after_append=lambda _: (_ for _ in ()).throw(
            RuntimeError("crash after fsync")
        ),
    )
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=graph,
        capabilities=capabilities,
        probe_verifier=VERIFIER,
        latch_store=store,
    )
    envelope = event("worker-target", "Stop", 100)
    crashed.start()
    with pytest.raises(LedgerError):
        crashed.submit(
            envelope,
            request_digest=request_digest(envelope),
            decide=router.response_decider(
                findings=lambda: (finding,), probes=lambda: (probe,)
            ),
        )
    crashed.stop()

    committed = router.snapshot()
    assert committed.generation > 0
    assert store.load(expected_generation=committed.generation) == committed
    with pytest.raises(LedgerError, match="degraded"):
        crashed.response_for(envelope.event_id, request_digest(envelope))

    recovered_ledger = EventLedger(run_dir, run_id=RUN_ID)
    assert recovered_ledger.degraded_reason == "RuntimeError"
    with pytest.raises(LedgerError, match="degraded"):
        recovered_ledger.start()
    with pytest.raises(LedgerError, match="degraded"):
        recovered_ledger.response_for(envelope.event_id, request_digest(envelope))


def test_selector_and_router_delta_compose_and_replay(tmp_path) -> None:
    run_dir = tmp_path / "run"
    ledger = EventLedger(run_dir, run_id=RUN_ID)
    graph = make_graph()
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=graph,
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    finding = make_finding()
    selector_state = DeliverySelectorState(last_updates=(("worker-target", 4),))
    base = ResponsePlan(body={}, review_state=selector_state.to_record(run_id=RUN_ID))
    envelope = event("worker-target", "PostToolUse", 10)
    ledger.start()
    response = ledger.submit(
        envelope,
        request_digest=request_digest(envelope),
        decide=lambda item: router.plan_response(
            item, findings=(finding,), base_plan=base
        ),
    )
    ledger.stop()
    assert response.review_state["record_type"] == "response_review_state"
    assert set(response.review_state["components"]) == {
        "delivery_selector_state",
        "intervention_router_delta",
    }
    restored_selector = DeliverySelector.from_exchanges(ledger.exchanges(), run_id=RUN_ID)
    assert restored_selector.snapshot() == selector_state
    restored_router = InterventionRouter.from_ledger(
        ledger,
        graph=graph,
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
        now=11,
    )
    assert restored_router.snapshot() == router.snapshot()
    DeterministicRules.from_ledger(ledger)


def test_response_review_stores_bounded_changed_record_delta() -> None:
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    first_finding = make_finding(suffix="delta-one")
    first = router.plan_response(
        event("worker-sibling", "PostToolUse", 10), findings=(first_finding,)
    )
    commit(first)
    second_finding = make_finding(suffix="delta-two")
    second = router.plan_response(
        event("worker-sibling", "PostToolUse", 11),
        findings=(first_finding, second_finding),
    )
    component = second.review_state["components"]["intervention_router_delta"]
    assert len(component["upserts"]) == 1
    assert component["upserts"][0]["finding_id"] == second_finding.finding_id
    commit(second)
    assert len(canonical_json(component)) < len(
        canonical_json(router.snapshot().model_dump(mode="json"))
    )


def test_collector_loss_requires_current_generation_and_exact_target(tmp_path) -> None:
    store = InterventionLatchStore(
        tmp_path / "private", run_id=RUN_ID, secret=generate_run_secret()
    )
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
        latch_store=store,
    )
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    plan = router.plan_response(
        event("worker-target", "Stop", 100), findings=(finding,), probes=(probe,)
    )
    commit(plan)
    prior_latch = store.path.read_bytes()
    generation = router.snapshot().generation
    cached = router.cached_response(
        session_alias="worker-target",
        hook_event_name="Stop",
        now=101,
        expected_generation=generation,
    )
    assert set(cached) == {"decision", "reason"}
    assert cached["decision"] == "block"
    assert (
        router.cached_response(
            session_alias="worker-sibling",
            hook_event_name="Stop",
            now=101,
            expected_generation=generation,
        )
        == {}
    )
    with pytest.raises(AuthenticationError, match="stale or replayed"):
        router.cached_response(
            session_alias="worker-target",
            hook_event_name="Stop",
            now=101,
            expected_generation=generation - 1,
        )
    expired = router.cached_response(
        session_alias="worker-target",
        hook_event_name="Stop",
        now=700,
        expected_generation=generation,
    )
    assert "mandatory Mission termination and failure" in expired["reason"]
    later = router.plan_response(
        event("worker-target", "Stop", 102),
        findings=(finding,),
        probes=(probe,),
    )
    commit(later)
    store.path.write_bytes(prior_latch)
    os.chmod(store.path, 0o600)
    with pytest.raises(AuthenticationError, match="head does not match"):
        store.load()


def test_fallback_orchestrator_outage_uses_mission_scope(tmp_path) -> None:
    store = InterventionLatchStore(
        tmp_path / "private", run_id=RUN_ID, secret=generate_run_secret()
    )
    capabilities = make_capabilities(worker_block="fallback", mission_block="pass")
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(repair=True),
        capabilities=capabilities,
        probe_verifier=VERIFIER,
        latch_store=store,
    )
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    plan = router.plan_response(
        event("orchestrator", "Stop", 100),
        findings=(finding,),
        probes=(probe,),
        original_features={finding.finding_id: "feature-checkout"},
    )
    commit(plan)
    state = router.snapshot()
    assert state.interventions[0].blocking_scope == "mission"
    assert router.cached_response(
        session_alias="orchestrator",
        hook_event_name="Stop",
        now=101,
        expected_generation=state.generation,
    )["decision"] == "block"
    assert (
        router.cached_response(
            session_alias="worker-target",
            hook_event_name="SubagentStop",
            now=101,
            expected_generation=state.generation,
        )
        == {}
    )
