"""Validated terminal status view for active and final Shadow runs."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import time
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .graph import GraphError, load_exchanges
from .protocol import (
    RELEASE_REPORTABLE_RUNTIME_OUTCOMES,
    InterventionRecord,
    RunRecord,
    canonical_json,
)
from .reporting import ReportCorruptionError, validate_finalization_provenance
from .review_journal import (
    FindingSnapshotRecord,
    ReviewJournal,
    ReviewJournalError,
    RoleDecisionRecord,
    project_intervention_router_state,
)

_SAFE_RUN_ID = re.compile(r"^run-[A-Za-z0-9._-]{1,128}$")
_HEARTBEAT_STALE_SECONDS = 15
def is_safe_run_id(run_id: str) -> bool:
    return _SAFE_RUN_ID.fullmatch(run_id) is not None




class StatusError(RuntimeError):
    """Base status read failure."""


class StatusInputError(StatusError):
    """The status request is invalid or names an unknown run."""


class StatusCorruptionError(StatusError):
    """The selected run state is unreadable or corrupt."""


class StatusRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    run_id: str = Field(pattern=r"^run-[A-Za-z0-9._-]{1,128}$")
    state: Literal["active", "final", "failed"]
    daemon_health: Literal["starting", "healthy", "degraded", "stopped"]
    queue: dict[str, int]
    spool: dict[str, int]
    sessions: tuple[str, ...]
    roles: dict[str, str]
    capability_path: dict[str, Any]
    unresolved_risks: tuple[str, ...]
    intervention_state: dict[str, Any]
    usage: dict[str, Any]
    started_at: int
    duration_seconds: float | None

    live_run_count: int = Field(ge=0)
    budget_ledger: dict[str, Any]
    updated_at: int
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("intervention_state")
    @classmethod
    def validate_intervention_state(
        cls,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        if set(value) != {
            "unresolved",
            "unresolved_intervention_ids",
            "by_state",
        }:
            raise ValueError("intervention status shape is invalid")
        unresolved = value["unresolved"]
        unresolved_ids = value["unresolved_intervention_ids"]
        by_state = value["by_state"]
        if (
            not isinstance(unresolved, int)
            or isinstance(unresolved, bool)
            or unresolved < 0
            or not isinstance(unresolved_ids, (list, tuple))
            or any(not isinstance(item, str) or not item for item in unresolved_ids)
            or tuple(sorted(set(unresolved_ids))) != tuple(unresolved_ids)
            or unresolved != len(unresolved_ids)
            or not isinstance(by_state, dict)
            or any(
                not isinstance(state, str)
                or not state
                or not isinstance(count, int)
                or isinstance(count, bool)
                or count <= 0
                for state, count in by_state.items()
            )
            or unresolved > sum(by_state.values())
        ):
            raise ValueError("intervention status value is invalid")
        return {
            "unresolved": unresolved,
            "unresolved_intervention_ids": tuple(unresolved_ids),
            "by_state": dict(sorted(by_state.items())),
        }

    @model_validator(mode="after")
    def validate_record_digest(self) -> StatusRecord:
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        if supplied != hashlib.sha256(canonical_json(value)).hexdigest():
            raise ValueError("status record digest differs")
        return self


def status_record(value: Mapping[str, Any]) -> StatusRecord:
    material = dict(value)
    material.pop("record_digest", None)
    material["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    return StatusRecord.model_validate(material)


def intervention_state(
    interventions: Iterable[InterventionRecord],
) -> dict[str, Any]:
    """Build the canonical status projection from one router snapshot."""

    values = tuple(interventions)
    unresolved_ids = tuple(
        sorted(
            item.intervention_id
            for item in values
            if item.state not in {"resolved", "termination_acknowledged"}
        )
    )
    by_state: dict[str, int] = {}
    for item in values:
        by_state[item.state] = by_state.get(item.state, 0) + 1
    return {
        "unresolved": len(unresolved_ids),
        "unresolved_intervention_ids": unresolved_ids,
        "by_state": dict(sorted(by_state.items())),
    }


def terminal_state(
    runtime_outcome: str,
    *,
    evaluation_status: Literal["pass", "fail"] | None = None,
) -> Literal["final", "failed"]:
    """Map one runtime and optional evaluator outcome to a terminal state."""

    if runtime_outcome not in RELEASE_REPORTABLE_RUNTIME_OUTCOMES:
        return "failed"
    if evaluation_status is not None and evaluation_status != "pass":
        return "failed"
    return "final"


def _unresolved_risk_identities(
    records: Iterable[Any],
    unresolved_intervention_ids: Iterable[str],
    *,
    existing: Iterable[str] = (),
) -> tuple[str, ...]:
    latest_snapshot: FindingSnapshotRecord | None = None
    for record in records:
        if isinstance(record, FindingSnapshotRecord):
            latest_snapshot = record
    risks = set(existing)
    risks.update(unresolved_intervention_ids)
    if latest_snapshot is not None:
        risks.update(item.dedup_key for item in latest_snapshot.findings)
    return tuple(sorted(risks))


def _load_final(path: Path) -> RunRecord:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
        value = json.loads(payload)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or canonical_json(value) + b"\n" != payload
        ):
            raise StatusCorruptionError("final run record is not canonical")
        return RunRecord.model_validate(value)
    except StatusError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise StatusCorruptionError("final run record is invalid") from error


def _load_active(path: Path) -> StatusRecord:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
        value = json.loads(payload)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or canonical_json(value) + b"\n" != payload
        ):
            raise StatusCorruptionError("active status record is not canonical")
        return StatusRecord.model_validate(value)
    except StatusError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise StatusCorruptionError("active status record is invalid") from error


def terminal_status(
    run_dir: Path,
    run: RunRecord,
    *,
    interventions: Iterable[InterventionRecord] | None = None,
    known_sessions: Iterable[str] = (),
    role_assignments: Mapping[str, str] | None = None,
    evaluation_status: Literal["pass", "fail"] | None = None,
) -> StatusRecord:
    """Project one stopped Mission from its durable state."""

    try:
        exchanges = load_exchanges(run_dir / "events.jsonl")
        journal = ReviewJournal(run_dir / "review.jsonl", run_id=run.run_id)
        records = journal.records()
    except (GraphError, ReviewJournalError, ValueError) as error:
        raise StatusCorruptionError("run replay state is invalid") from error
    recorded_roles = {
        record.role_id: record.session_alias
        for record in records
        if isinstance(record, RoleDecisionRecord)
        and record.role_id is not None
        and record.status == "assigned"
        and record.confidence == "high"
    }
    projected_roles = dict(role_assignments or {})
    projected_roles.update(recorded_roles)
    if interventions is None:
        current_interventions = project_intervention_router_state(
            run.run_id,
            records,
        ).interventions
    else:
        current_interventions = tuple(interventions)
    current_intervention_state = intervention_state(current_interventions)
    unresolved = _unresolved_risk_identities(
        records,
        current_intervention_state["unresolved_intervention_ids"],
    )
    live_count = run.budget_ledger.get("resulting_live_run_count", 0)
    if not isinstance(live_count, int) or isinstance(live_count, bool) or live_count < 0:
        raise StatusCorruptionError("budget live-run count is invalid")
    return status_record(
        {
            "schema_version": "0.1",
            "run_id": run.run_id,
            "state": terminal_state(
                run.runtime_outcome,
                evaluation_status=evaluation_status,
            ),
            "daemon_health": "stopped",
            "queue": {"items": 0, "bytes": 0},
            "spool": {
                "events": (run_dir / "events.jsonl").stat().st_size,
                "review": (run_dir / "review.jsonl").stat().st_size,
            },
            "sessions": tuple(
                sorted(
                    set(known_sessions)
                    | {exchange.envelope.session_alias for exchange in exchanges}
                )
            ),
            "roles": dict(sorted(projected_roles.items())),
            "capability_path": run.capabilities.model_dump(mode="json"),
            "unresolved_risks": unresolved,
            "intervention_state": current_intervention_state,
            "usage": run.usage_data,
            "started_at": run.started_at,
            "duration_seconds": run.duration_seconds,
            "live_run_count": live_count,
            "budget_ledger": run.budget_ledger,
            "updated_at": run.ended_at or run.started_at,
        }
    )


def _final_status(run_dir: Path, run: RunRecord) -> StatusRecord:
    try:
        _, evaluation, _ = validate_finalization_provenance(run_dir, run)
    except ReportCorruptionError as error:
        raise StatusCorruptionError("finalization provenance is invalid") from error
    return terminal_status(
        run_dir,
        run,
        evaluation_status=evaluation.status,
    )


def load_status(state_root: Path, run_id: str) -> StatusRecord:
    """Load one known active projection or rebuild one final status."""

    if not is_safe_run_id(run_id):
        raise StatusInputError("run ID is invalid")
    run_dir = state_root / "runs" / run_id
    if not run_dir.exists():
        raise StatusInputError("unknown run")
    try:
        metadata = run_dir.lstat()
    except OSError as error:
        raise StatusInputError("unknown run") from error
    if run_dir.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise StatusCorruptionError("run state directory is invalid")
    final_path = run_dir / "run.json"
    if final_path.exists():
        run = _load_final(final_path)
        if run.run_id != run_id:
            raise StatusCorruptionError("run identity differs")
        return _final_status(run_dir, run)
    active_path = run_dir / "status.json"
    if not active_path.exists():
        raise StatusCorruptionError("run status is incomplete")
    status = _load_active(active_path)
    if status.run_id != run_id:
        raise StatusCorruptionError("run identity differs")
    try:
        event_path = run_dir / "events.jsonl"
        review_path = run_dir / "review.jsonl"
        for path in (event_path, review_path):
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise StatusCorruptionError("active spool is invalid")
        lock_path = state_root / "mission.lock"
        lock_healthy = (
            lock_path.exists()
            and not lock_path.is_symlink()
            and stat.S_ISREG(lock_path.lstat().st_mode)
        )
        now = int(time.time())
        heartbeat_stale = now - status.updated_at > _HEARTBEAT_STALE_SECONDS
        value = status.model_dump(mode="json")
        value.pop("record_digest")
        value["spool"] = {
            "events": event_path.stat().st_size,
            "review": review_path.stat().st_size,
        }
        value["duration_seconds"] = float(max(0, now - status.started_at))
        value["updated_at"] = now
        active_risks = set(status.unresolved_risks)
        if not lock_healthy:
            active_risks.add("active lock is missing")
        if heartbeat_stale:
            active_risks.add("active heartbeat is stale")
        if not lock_healthy or heartbeat_stale:
            value["daemon_health"] = "degraded"
        try:
            exchanges = load_exchanges(event_path)
            records = ReviewJournal(review_path, run_id=run_id).records()
        except (GraphError, ReviewJournalError, ValueError) as error:
            raise StatusCorruptionError("active replay state is invalid") from error
        roles = {
            record.role_id: record.session_alias
            for record in records
            if isinstance(record, RoleDecisionRecord)
            and record.role_id is not None
            and record.status == "assigned"
            and record.confidence == "high"
        }
        current_intervention_state = intervention_state(
            project_intervention_router_state(run_id, records).interventions
        )
        value["sessions"] = tuple(
            sorted(
                set(status.sessions)
                | {exchange.envelope.session_alias for exchange in exchanges}
            )
        )
        value["roles"] = dict(sorted({**status.roles, **roles}.items()))
        value["unresolved_risks"] = _unresolved_risk_identities(
            records,
            current_intervention_state["unresolved_intervention_ids"],
            existing=active_risks,
        )
        value["intervention_state"] = current_intervention_state
        return status_record(value)
    except StatusError:
        raise
    except OSError as error:
        raise StatusCorruptionError("active spool is unavailable") from error


def render_status(record: StatusRecord) -> str:
    return canonical_json(record.model_dump(mode="json")).decode("utf-8")
