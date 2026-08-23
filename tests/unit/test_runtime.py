from __future__ import annotations

import errno
import json
import sys
import time
from pathlib import Path

import pytest
import shadow_mission.runtime as runtime_module

from shadow_mission.runtime import MissionExecutionError, SubprocessCommandRunner
from tests.integration.test_version_binding import (
    FakeReviewFactory,
    FakeRouter,
    FinalStatusController,
    make_fixture,
    run_approved,
    runtime_for,
    status_router_state,
)



def test_output_capture_treats_pty_eio_as_clean_end() -> None:
    class Stream:
        def __init__(self, error_number: int) -> None:
            self.error_number = error_number
            self.closed = False

        def read(self, _size: int) -> bytes:
            raise OSError(self.error_number, "injected read failure")

        def close(self) -> None:
            self.closed = True

    clean_stream = Stream(errno.EIO)
    clean_capture = runtime_module._BoundedOutputCapture(1024)
    clean_capture.drain(clean_stream, "stdout")

    assert clean_stream.closed is True
    assert clean_capture.failed.is_set() is False

    failed_stream = Stream(errno.EBADF)
    failed_capture = runtime_module._BoundedOutputCapture(1024)
    failed_capture.drain(failed_stream, "stdout")

    assert failed_stream.closed is True
    assert failed_capture.failed.is_set() is True


def test_exclusive_private_write_never_leaves_partial_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "authorization.json"

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("injected write failure")

    monkeypatch.setattr(runtime_module.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match="injected write failure"):
        runtime_module._exclusive_private_json(
            target,
            {"authorization_id": "authorization-1"},
        )

    assert not target.exists()
    assert tuple(tmp_path.glob(".authorization.json.*.tmp")) == ()

def test_interruptible_runner_terminates_noisy_child_at_aggregate_quota(
    tmp_path: Path,
) -> None:
    script = (
        "import os\n"
        "chunk = b'x' * 65536\n"
        "while True:\n"
        "    os.write(1, chunk)\n"
        "    os.write(2, chunk)\n"
    )
    started = time.monotonic()

    with pytest.raises(MissionExecutionError, match="Droid output limit exceeded"):
        SubprocessCommandRunner().run_interruptible(
            (sys.executable, "-c", script),
            environment={},
            cwd=tmp_path,
            timeout_seconds=10,
            termination_required=lambda: False,
            termination_grace_seconds=1.0,
        )

    assert time.monotonic() - started < 3.0

def test_interruptible_runner_terminates_mission_descendants(
    tmp_path: Path,
) -> None:
    heartbeat = tmp_path / "heartbeat"
    child = (
        "import os,time\n"
        f"path={str(heartbeat)!r}\n"
        "while True:\n"
        "    with open(path, 'ab') as handle:\n"
        "        handle.write(b'x')\n"
        "        handle.flush()\n"
        "        os.fsync(handle.fileno())\n"
        "    time.sleep(0.02)\n"
    )
    parent = (
        "import subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
        "while True:\n"
        "    time.sleep(1)\n"
    )

    SubprocessCommandRunner().run_interruptible(
        (sys.executable, "-c", parent),
        environment={},
        cwd=tmp_path,
        timeout_seconds=10,
        termination_required=heartbeat.exists,
        termination_grace_seconds=1.0,
    )
    size_after_return = heartbeat.stat().st_size
    time.sleep(0.2)

    assert heartbeat.stat().st_size == size_after_return


def test_completed_run_persists_terminal_status_after_controller_stop(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)

    def router_factory(run_id: str) -> FakeRouter:
        router = FakeRouter(run_id)
        router.state = status_router_state(run_id, "queued")
        return router

    review_factory = FakeReviewFactory(
        controller_type=FinalStatusController,
        router_factory=router_factory,
    )
    record = run_approved(
        runtime_for(fixture),
        fixture.request,
        review_factory=review_factory,
    )
    assert review_factory.controller is not None
    assert review_factory.controller.lifecycle == [
        "start",
        "drain",
        "reconcile_final_outage",
        "stop",
    ]
    status_path = (
        fixture.state_root / "runs" / record.run_id / "status.json"
    )
    status = json.loads(status_path.read_bytes())

    assert status["state"] == "final"
    assert status["daemon_health"] == "stopped"
    assert status["intervention_state"] == {
        "unresolved": 0,
        "unresolved_intervention_ids": [],
        "by_state": {"resolved": 1},
    }
