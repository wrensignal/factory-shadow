from __future__ import annotations

import time
from pathlib import Path

from shadow_mission.protocol import canonical_json
from shadow_mission.status import load_status, status_record
from tests.unit.test_reporting import append_mixed_finding, make_final_run_dir


def test_final_and_active_projections_share_unresolved_risk_identities(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    runs_root = state_root / "runs"
    runs_root.mkdir(parents=True)
    run_id = "run-status-contract"
    run_dir = make_final_run_dir(
        runs_root,
        run_id=run_id,
        journal_setup=lambda journal: append_mixed_finding(journal, run_id),
    )

    final_status = load_status(state_root, run_id)

    (run_dir / "run.json").rename(run_dir / "completed-run.json")
    now = int(time.time())
    active_status = status_record(
        {
            "schema_version": "0.1",
            "run_id": run_id,
            "state": "active",
            "daemon_health": "healthy",
            "queue": {"items": 0, "bytes": 0},
            "spool": {"events": 0, "review": 0},
            "sessions": (),
            "roles": {},
            "capability_path": {},
            "unresolved_risks": (),
            "intervention_state": {
                "unresolved": 0,
                "unresolved_intervention_ids": (),
                "by_state": {},
            },
            "usage": {"status": "unavailable"},
            "started_at": now,
            "duration_seconds": 0.0,
            "live_run_count": 1,
            "budget_ledger": {},
            "updated_at": now,
        }
    )
    (run_dir / "status.json").write_bytes(
        canonical_json(active_status.model_dump(mode="json")) + b"\n"
    )
    (state_root / "mission.lock").write_text("active\n", encoding="utf-8")

    active_status = load_status(state_root, run_id)
    expected = ("a" * 64, "intervention-worker-b")
    assert active_status.unresolved_risks == expected
    assert final_status.unresolved_risks == expected
