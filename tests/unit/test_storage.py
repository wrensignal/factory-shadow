from __future__ import annotations

import json
import sqlite3
import os
import stat
import threading
import time
from pathlib import Path

import pytest
import shadow_mission.storage as storage_module

from shadow_mission.protocol import HookEnvelope, QueueCapacityError, canonical_json
from shadow_mission.storage import (
    EventLedger,
    LedgerConflictError,
    LedgerCorruptionError,
    LedgerError,
    ResponsePlan,
)


def envelope(event_id: str = "event-1", *, run_id: str = "run-1") -> HookEnvelope:
    return HookEnvelope(provenance_status="hook_authenticated",
    redaction_status="clean",
    event_id=event_id,
    source_fingerprint="source-a",
    run_id=run_id,
    session_alias="session-a",
    transcript_alias="transcript-a",
    hook_event_name="PostToolUse", observed_at=1_700_000_000, message_digest="d" * 64, payload={"tool_name": "Read"},)


def digest(value: HookEnvelope) -> str:
    import hashlib

    return hashlib.sha256(canonical_json(value.model_dump(mode="json"))).hexdigest()


def test_ledger_persists_one_canonical_exchange_and_rebuilds_sqlite(tmp_path: Path) -> None:
    value = envelope()
    ledger = EventLedger(tmp_path / "run", run_id=value.run_id, clock=lambda: 10)
    ledger.start()
    response = ledger.submit(
        value,
        request_digest=digest(value),
        decide=lambda _: ResponsePlan(body={"hook_output": {"ok": True}}),
    )
    ledger.stop()

    assert json.loads(response.response_body) == {"hook_output": {"ok": True}}
    line = (tmp_path / "run/events.jsonl").read_bytes().splitlines()
    assert len(line) == 1
    assert canonical_json(json.loads(line[0])) == line[0]

    connection = sqlite3.connect(tmp_path / "run/index.sqlite3")
    try:
        row = connection.execute(
            "SELECT ledger_sequence, event_id, response_digest FROM exchanges"
        ).fetchone()
    finally:
        connection.close()
    assert row == (1, "event-1", response.response_digest)

    recovered = EventLedger(tmp_path / "run", run_id=value.run_id)
    assert recovered.response_for(value.event_id, digest(value)) == response



def test_new_event_ledger_fsyncs_its_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory_syncs = 0
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        nonlocal directory_syncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_syncs += 1
        real_fsync(descriptor)

    monkeypatch.setattr(storage_module.os, "fsync", record_fsync)

    EventLedger(tmp_path / "run", run_id="run-1")

    assert directory_syncs >= 1

def test_byte_identical_retry_returns_first_response_once(tmp_path: Path) -> None:
    value = envelope()
    ledger = EventLedger(tmp_path / "run", run_id=value.run_id)
    ledger.start()
    commits = 0

    def decide(_: HookEnvelope) -> ResponsePlan:
        def commit() -> None:
            nonlocal commits
            commits += 1

        return ResponsePlan(
            body={"hook_output": {"message": "first"}},
            guidance_ids=("guidance-1",),
            commit=commit,
        )

    first = ledger.submit(value, request_digest=digest(value), decide=decide)
    second = ledger.submit(
        value,
        request_digest=digest(value),
        decide=lambda _: ResponsePlan(body={"hook_output": {"message": "wrong"}}),
    )
    ledger.stop()

    assert first == second
    assert commits == 1
    assert len(ledger.exchanges()) == 1


def test_changed_body_under_event_id_is_rejected(tmp_path: Path) -> None:
    first = envelope()
    changed = first.model_copy(update={"payload": {"tool_name": "Write"}})
    ledger = EventLedger(tmp_path / "run", run_id=first.run_id)
    ledger.start()
    ledger.submit(first, request_digest=digest(first), decide=lambda _: ResponsePlan())

    with pytest.raises(LedgerConflictError, match="different sanitized content"):
        ledger.submit(
            changed,
            request_digest=digest(changed),
            decide=lambda _: ResponsePlan(),
        )
    ledger.stop()


def test_concurrent_duplicates_wait_for_one_decision(tmp_path: Path) -> None:
    value = envelope()
    ledger = EventLedger(tmp_path / "run", run_id=value.run_id)
    ledger.start()
    barrier = threading.Barrier(9)
    decision_count = 0
    count_lock = threading.Lock()
    responses: list[str] = []

    def decide(_: HookEnvelope) -> ResponsePlan:
        nonlocal decision_count
        with count_lock:
            decision_count += 1
        time.sleep(0.03)
        return ResponsePlan(body={"hook_output": {"delivery": "once"}})

    def submit() -> None:
        barrier.wait()
        result = ledger.submit(value, request_digest=digest(value), decide=decide)
        responses.append(result.response_body)

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    ledger.stop()

    assert decision_count == 1
    assert responses == [responses[0]] * 8


def test_session_event_observation_includes_inflight_and_durable_events(
    tmp_path: Path,
) -> None:
    value = envelope()
    ledger = EventLedger(tmp_path / "run", run_id=value.run_id)
    ledger.start()
    decision_started = threading.Event()
    release_decision = threading.Event()
    failures: list[BaseException] = []

    def decide(_: HookEnvelope) -> ResponsePlan:
        decision_started.set()
        release_decision.wait(timeout=2.0)
        return ResponsePlan()

    def submit() -> None:
        try:
            ledger.submit(value, request_digest=digest(value), decide=decide)
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=submit)
    thread.start()
    assert decision_started.wait(timeout=1.0)
    try:
        assert ledger.event_ids_for_session("session-a") == ("event-1",)
    finally:
        release_decision.set()
        thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert failures == []
    assert ledger.event_ids_for_session("session-a") == ("event-1",)
    assert ledger.event_ids_for_session("session-missing") == ()
    ledger.stop()


def test_post_fsync_commit_precedes_projection_callback(tmp_path: Path) -> None:
    value = envelope()
    order: list[str] = []

    def project(_: object) -> None:
        assert order == ["commit"]
        assert ledger.response_for(value.event_id, digest(value)) is None
        order.append("project")

    ledger = EventLedger(
        tmp_path / "run",
        run_id=value.run_id,
        after_append=project,
    )
    ledger.start()
    response = ledger.submit(
        value,
        request_digest=digest(value),
        decide=lambda _: ResponsePlan(
            body={"hook_output": {"stable": True}},
            commit=lambda: order.append("commit"),
        ),
    )
    ledger.stop()

    assert order == ["commit", "project"]
    assert json.loads(response.response_body) == {"hook_output": {"stable": True}}
    assert not ledger.degraded_path.exists()


@pytest.mark.parametrize("failure_stage", ["commit", "callback", "sqlite"])
def test_post_fsync_failure_poison_rejects_retry_and_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    value = envelope()
    callbacks = 0

    def fail_callback(_: object) -> None:
        nonlocal callbacks
        callbacks += 1
        if failure_stage == "callback":
            raise RuntimeError("injected callback failure")

    def fail_commit() -> None:
        if failure_stage == "commit":
            raise RuntimeError("injected commit failure")

    run_dir = tmp_path / "run"
    failed = EventLedger(
        run_dir,
        run_id=value.run_id,
        after_append=fail_callback,
    )
    if failure_stage == "sqlite":
        def fail_sqlite(*_: object) -> None:
            raise sqlite3.OperationalError("injected SQLite failure")

        monkeypatch.setattr(failed, "_apply_sqlite", fail_sqlite)
    failed.start()
    with pytest.raises(LedgerError, match="persistence failed"):
        failed.submit(
            value,
            request_digest=digest(value),
            decide=lambda _: ResponsePlan(
                body={"hook_output": {"stable": True}},
                commit=fail_commit,
            ),
        )

    with pytest.raises(LedgerError, match="degraded"):
        failed.submit(
            value,
            request_digest=digest(value),
            decide=lambda _: ResponsePlan(body={"hook_output": {"wrong": True}}),
        )
    with pytest.raises(LedgerError, match="degraded"):
        failed.response_for(value.event_id, digest(value))
    failed.stop()

    assert callbacks == (0 if failure_stage == "commit" else 1)
    assert failed.exchanges() == ()
    assert (run_dir / "events.jsonl").read_bytes()
    assert (run_dir / "ledger-degraded.json").is_file()

    recovered = EventLedger(run_dir, run_id=value.run_id)
    expected_reason = (
        "OperationalError" if failure_stage == "sqlite" else "RuntimeError"
    )
    assert recovered.degraded_reason == expected_reason
    with pytest.raises(LedgerError, match="degraded"):
        recovered.start()
    with pytest.raises(LedgerError, match="degraded"):
        recovered.response_for(value.event_id, digest(value))


def test_partial_final_jsonl_record_fails_closed(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    (run_dir / "events.jsonl").write_bytes(b'{"partial":')

    with pytest.raises(LedgerCorruptionError, match="incomplete final record"):
        EventLedger(run_dir, run_id="run-1")


def test_writer_setup_failure_degrades_before_submit_waits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = envelope()
    ledger = EventLedger(tmp_path / "run", run_id=value.run_id)

    def fail_connect(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        raise sqlite3.OperationalError("injected setup failure")

    monkeypatch.setattr(storage_module.sqlite3, "connect", fail_connect)
    with pytest.raises(LedgerError, match="writer setup failed"):
        ledger.start()

    assert ledger.degraded_reason == "OperationalError"
    with pytest.raises(LedgerError, match="degraded"):
        ledger.submit(
            value,
            request_digest=digest(value),
            decide=lambda _: ResponsePlan(),
        )
    ledger.stop()


def test_sanitized_event_limit_rejects_before_enqueue(tmp_path: Path) -> None:
    value = envelope().model_copy(update={"payload": {"tool_response": "x" * (257 << 10)}})
    ledger = EventLedger(tmp_path / "run", run_id=value.run_id)
    ledger.start()
    with pytest.raises(QueueCapacityError, match="256 KiB"):
        ledger.submit(value, request_digest=digest(value), decide=lambda _: ResponsePlan())
    ledger.stop()
