from __future__ import annotations

import os
from pathlib import Path

import pytest

from shadow_mission.auth import AuthenticationError, generate_run_secret
from shadow_mission.router import InterventionLatchStore, InterventionRouter
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


def make_latched_router(
    tmp_path: Path, *, clock: list[float]
) -> tuple[InterventionRouter, InterventionLatchStore]:
    store = InterventionLatchStore(
        tmp_path / "private",
        run_id=RUN_ID,
        secret=generate_run_secret(),
        clock=lambda: clock[0],
    )
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
        latch_store=store,
    )
    return router, store


def add_blocker(router: InterventionRouter, *, observed_at: int) -> None:
    finding = make_finding(level="blocker", probe_status="confirmed")
    commit(
        router.plan_response(
            event("worker-target", "Stop", observed_at),
            findings=(finding,),
            probes=(make_probe(finding),),
        )
    )


def test_elapsed_blocker_deadline_terminates_without_another_hook(
    tmp_path: Path,
) -> None:
    clock = [699.0]
    router, store = make_latched_router(tmp_path, clock=clock)
    add_blocker(router, observed_at=100)

    assert store.completion_blocked is True
    assert store.termination_required is False

    clock[0] = 700.0

    assert store.termination_required is True


def test_in_process_anchor_rejects_signed_pair_rollback(tmp_path: Path) -> None:
    clock = [100.0]
    router, store = make_latched_router(tmp_path, clock=clock)
    add_blocker(router, observed_at=100)
    old_latch = store.path.read_bytes()
    old_head = store.head_path.read_bytes()

    add_blocker(router, observed_at=101)
    assert store.load().generation == router.snapshot().generation

    store.path.write_bytes(old_latch)
    store.head_path.write_bytes(old_head)
    os.chmod(store.path, 0o600)
    os.chmod(store.head_path, 0o600)

    with pytest.raises(AuthenticationError, match="rolled back"):
        store.load()
    assert store.termination_required is True
    assert store.completion_blocked is True
