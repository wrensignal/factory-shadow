from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from shadow_mission.extractor import (
    BrokerAttempt,
    ClaimExtractor,
    RecordedExtractionBroker,
)
from shadow_mission.protocol import canonical_json
from shadow_mission.review import MissionReviewController
from shadow_mission.review_journal import OutageReconciliationRecord, ReviewJournal
from shadow_mission.roles import FrozenMissionRelations, RoleMapper
from shadow_mission.router import InterventionRouter, InterventionRouterState
from shadow_mission.rules import DeterministicRules
from shadow_mission.transcript import TranscriptReader
from tests.unit.test_intervention_policy import latched_router
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


class _NoProbeScheduler:
    def enqueue(self, _job: object) -> None:
        raise AssertionError("final outage replay must not enqueue a probe")

    def run_next(self) -> None:
        return None


def _review_controller(
    root: Path,
    *,
    router: InterventionRouter,
    journal: ReviewJournal,
) -> MissionReviewController:
    transcript_root = root / "transcripts"
    transcript_root.mkdir(exist_ok=True)
    relations = FrozenMissionRelations("mission-final-outage", ())
    return MissionReviewController(
        run_id=RUN_ID,
        run_dir=root / "controller-run",
        relations=relations,
        role_mapper=RoleMapper((), relations),
        transcript_reader=TranscriptReader(
            transcript_root,
            run_id=RUN_ID,
            mode="fallback",
            provenance_status="hook_authenticated",
            fallback_semantic_equivalence=False,
        ),
        claim_extractor=ClaimExtractor(
            RecordedExtractionBroker(BrokerAttempt(boundary={}, output=None))
        ),
        graph=router.graph,
        rules=DeterministicRules(),
        probe_scheduler=_NoProbeScheduler(),
        router=router,
        journal=journal,
        probe_risk_classifier=lambda finding: finding.risk_category,
        repository_root=root,
    )



def test_final_outage_is_journaled_before_latch_pair_deletion_and_replays(
    tmp_path: Path,
) -> None:
    router, store = latched_router(tmp_path)
    finding = make_finding(
        level="blocker",
        probe_status="confirmed",
        suffix="final-outage",
    )
    probe = make_probe(finding)
    commit(
        router.plan_response(
            event("worker-target", "Stop", 100),
            findings=(finding,),
            probes=(probe,),
        )
    )
    authoritative = router.snapshot()
    before = authoritative.interventions[0]
    blocked_generation = authoritative.generation + 1
    terminal_generation = blocked_generation + 1
    intervention_value = before.model_dump(mode="json")
    intervention_value.update(
        {
            "generation": terminal_generation,
            "state": "expired",
            "attempts": before.attempts + 1,
            "terminal_outcome": "mission_termination_required",
            "transition_history": (
                *intervention_value["transition_history"],
                {
                    "transition_id": f"outage-{blocked_generation}",
                    "generation": blocked_generation,
                    "state": before.state,
                    "action": "blocked_attempt",
                    "observed_at": 101,
                },
                {
                    "transition_id": f"outage-{terminal_generation}",
                    "generation": terminal_generation,
                    "state": "expired",
                    "action": "termination_required",
                    "observed_at": 102,
                },
            ),
        }
    )
    intervention_value.pop("record_digest")
    intervention_value["record_digest"] = hashlib.sha256(
        canonical_json(intervention_value)
    ).hexdigest()
    advanced = type(before).model_validate(intervention_value)
    state_value = {
        "schema_version": "0.1",
        "record_type": "intervention_router_state",
        "provenance_status": "hook_authenticated",
        "redaction_status": "clean",
        "run_id": RUN_ID,
        "generation": terminal_generation,
        "interventions": (advanced.model_dump(mode="json"),),
    }
    state_value["record_digest"] = hashlib.sha256(
        canonical_json(state_value)
    ).hexdigest()
    outage_state = InterventionRouterState.model_validate(state_value)
    store.write(
        outage_state,
        expected_generation=authoritative.generation,
        observed_at=102,
    )
    journal = ReviewJournal(tmp_path / "review.jsonl", run_id=RUN_ID)

    with pytest.raises(RuntimeError, match="injected journal failure"):
        router.reconcile_final_outage(
            lambda _delta: (_ for _ in ()).throw(
                RuntimeError("injected journal failure")
            )
        )
    assert router.snapshot() == authoritative

    controller = _review_controller(
        tmp_path,
        router=router,
        journal=journal,
    )
    delta = controller.reconcile_final_outage()
    assert delta is not None
    assert router.snapshot() == outage_state
    store.path.unlink()
    store.head_path.unlink()
    store.lock_path.unlink(missing_ok=True)

    replay_graph = make_graph()
    replay_router = InterventionRouter(
        run_id=RUN_ID,
        graph=replay_graph,
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
        state=authoritative,
    )
    replayed_records = ReviewJournal(journal.path, run_id=RUN_ID).records()
    assert len(replayed_records) == 1
    record = replayed_records[0]
    assert isinstance(record, OutageReconciliationRecord)
    assert record.delta == delta
    assert record.observed_at >= 102
    replay_controller = _review_controller(
        tmp_path,
        router=replay_router,
        journal=ReviewJournal(journal.path, run_id=RUN_ID),
    )
    replay_controller.replay(())
    replayed = replay_router.snapshot().interventions[0]
    assert tuple(
        transition.action for transition in replayed.transition_history[-2:]
    ) == ("blocked_attempt", "termination_required")
    assert replayed.deadline == before.deadline
    assert replayed.terminal_outcome == "mission_termination_required"
    assert not store.path.exists()
    assert not store.head_path.exists()
