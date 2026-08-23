from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from shadow_mission.auth import (
    RUN_FILE_ENV,
    RUN_DESCRIPTOR_ENV,
    RUN_SECRET_ENV,
    create_descriptor,
    generate_run_secret,
    make_alias,
    sign_event_headers,
    write_latch,
    write_signed_private_state,
)
from shadow_mission.collector import HookCollector, MissionCorrelationRegistry
from shadow_mission.evidence import FrozenObservation, FrozenObservationRegistry
from shadow_mission.feasibility import (
    GateClassificationError,
    OfflineCollector,
    run_installed_cache_hook,
)
from shadow_mission.profile import (
    PLUGIN_ARTIFACT_ROOTS,
    compute_plugin_artifact_digest,
)
from shadow_mission.storage import EventLedger, ResponsePlan


def base_event(event: str, session_id: str = "worker-a-raw") -> dict[str, object]:
    return {
        "hook_event_name": event,
        "session_id": session_id,
        "transcript_path": f"/private/transcripts/{session_id}.jsonl",
        "cwd": "/private/mission",
        "tool_name": "Read",
        "tool_input": {"path": "api-schema.json"},
        "tool_response": "amount uses cents",
    }


def post_signed_event(
    url: str, body: bytes, headers: dict[str, str]
) -> tuple[int, dict[str, object]]:
    parsed = urlsplit(url)
    connection = HTTPConnection(parsed.hostname, parsed.port, timeout=2)
    try:
        connection.request("POST", parsed.path, body=body, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read())
        return response.status, payload
    finally:
        connection.close()


def copy_plugin_artifact(destination: Path) -> None:
    for relative_root in PLUGIN_ARTIFACT_ROOTS:
        source = Path(relative_root)
        target = destination / relative_root
        if source.is_dir():
            shutil.copytree(
                source,
                target,
                ignore=shutil.ignore_patterns(
                    "__pycache__", ".pytest_cache", "*.pyc", "*.pyo"
                ),
            )
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def run_hook_against_raw_response(
    tmp_path: Path,
    event: dict[str, object],
    response_value: object,
) -> subprocess.CompletedProcess[str]:
    response_body = json.dumps(
        response_value, sort_keys=True, separators=(",", ":")
    ).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    run_dir = tmp_path / "direct-response-run"
    run_dir.mkdir(parents=True, mode=0o700)
    secret = generate_run_secret()
    descriptor_path = run_dir / "descriptor.json"
    create_descriptor(
        descriptor_path,
        secret,
        run_id="run-direct-response",
        key_id="key-direct-response",
        collector_url=f"http://127.0.0.1:{server.server_port}/events",
        mission_root_digest="a" * 64,
        profile_digest="b" * 64,
        isolation_digest="c" * 64,
        gate_surface_digest="d" * 64,
        installed_artifact_digest="e" * 64,
        latch_path=run_dir / "latch.json",
        ttl_seconds=300,
    )
    try:
        return run_installed_cache_hook(
            Path.cwd(),
            event,
            environment={
                RUN_FILE_ENV: str(descriptor_path),
                RUN_SECRET_ENV: secret,
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

def test_nonfinite_hook_value_fails_closed_without_breaking_factory(
    tmp_path: Path,
) -> None:
    event = base_event("PostToolUse")
    event["tool_response"] = {"duration_seconds": float("nan")}

    completed = run_hook_against_raw_response(tmp_path, event, {})

    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""


def start_status_server(
    status: int,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    response_body = b"{}"

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_hook_subprocess_emits_direct_factory_hook_outputs(tmp_path: Path) -> None:
    context = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "[shadow:direct-context] Use cents.",
        }
    }
    steer = {
        "decision": "block",
        "reason": "[shadow:direct-steer] Pause and resolve the contract conflict.",
    }
    blocker = {
        "decision": "block",
        "reason": "[shadow:direct-blocker] Confirmed risk remains unresolved.",
    }

    post_tool = run_hook_against_raw_response(
        tmp_path / "post-tool",
        base_event("PostToolUse"),
        context,
    )
    post_tool_steer = run_hook_against_raw_response(
        tmp_path / "post-tool-steer",
        base_event("PostToolUse"),
        steer,
    )
    stop = run_hook_against_raw_response(
        tmp_path / "stop",
        base_event("Stop"),
        blocker,
    )

    assert json.loads(post_tool.stdout) == context
    assert post_tool_steer.stdout == ""
    assert json.loads(stop.stdout) == blocker


def test_hook_subprocess_rejects_collector_response_wrapper(
    tmp_path: Path,
) -> None:
    result = run_hook_against_raw_response(
        tmp_path,
        base_event("Stop"),
        {
            "hook_output": {
                "decision": "block",
                "reason": "[shadow:wrapped-blocker] Must not be emitted.",
            }
        },
    )

    output = json.loads(result.stdout)
    assert output["decision"] == "block"
    assert "wrapped-blocker" not in output["reason"]
    assert "signed latch are unavailable" in output["reason"]


def test_installed_cache_hook_is_inert_without_activation(tmp_path: Path) -> None:
    before = set(tmp_path.iterdir())
    result = run_installed_cache_hook(
        Path.cwd(), base_event("SessionStart"), environment={}, cache_parent=tmp_path
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert set(tmp_path.iterdir()) == before


def test_tampered_installed_artifact_is_rejected_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approved_digest = compute_plugin_artifact_digest(Path.cwd())
    project_copy = tmp_path / "tampered"
    copy_plugin_artifact(project_copy)
    hook = project_copy / "hooks/hook_runtime.py"
    hook.write_text(hook.read_text() + "\n# tampered\n")

    def reject_launch(*args: object, **kwargs: object) -> None:
        raise AssertionError("tampered hook must not launch")

    monkeypatch.setattr(subprocess, "run", reject_launch)
    with pytest.raises(GateClassificationError, match="approved source"):
        run_installed_cache_hook(
            project_copy,
            base_event("SessionStart"),
            environment={},
            expected_artifact_digest=approved_digest,
        )


def test_hook_subprocess_has_a_hard_timeout(tmp_path: Path) -> None:
    project_copy = tmp_path / "slow"
    copy_plugin_artifact(project_copy)
    hook = project_copy / "hooks/shadow_hook.py"
    hook.write_text(
        hook.read_text().replace(
            "from hook_runtime import main",
            "import time\ntime.sleep(1)\n\nfrom hook_runtime import main",
        )
    )
    slow_digest = compute_plugin_artifact_digest(project_copy)

    with pytest.raises(subprocess.TimeoutExpired):
        run_installed_cache_hook(
            project_copy,
            base_event("SessionStart"),
            environment={},
            expected_artifact_digest=slow_digest,
            timeout_seconds=0.05,
        )


def test_offline_collector_emits_direct_output_and_sanitizes_event(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    run_id = "run-hook-test"
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    ledger_path = run_dir / "events.jsonl"
    collector = OfflineCollector(run_id, secret, ledger_path)
    collector.start()
    try:
        descriptor_path = run_dir / "descriptor.json"
        descriptor = create_descriptor(
            descriptor_path,
            secret,
            run_id=run_id,
            key_id="key-hook-test",
            collector_url=collector.url,
            mission_root_digest="a" * 64,
            profile_digest="b" * 64,
            isolation_digest="c" * 64,
            gate_surface_digest="d" * 64,
            installed_artifact_digest="e" * 64,
            latch_path=run_dir / "latch.json",
            ttl_seconds=300,
        )
        collector.bind_descriptor(descriptor)
        worker_a = make_alias(secret, "session", "worker-a-raw")
        worker_b = make_alias(secret, "session", "worker-b-raw")
        collector.queue_hook_output(
            worker_a,
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": "[shadow:route-a] ROUTE-ALPHA-7319",
                }
            },
        )
        environment = {
            RUN_FILE_ENV: str(descriptor_path),
            RUN_SECRET_ENV: secret,
        }

        target = run_installed_cache_hook(
            Path.cwd(), base_event("PostToolUse"), environment=environment
        )
        sibling = run_installed_cache_hook(
            Path.cwd(),
            base_event("PostToolUse", "worker-b-raw"),
            environment=environment,
        )

        assert json.loads(target.stdout)["hookSpecificOutput"]["additionalContext"] == (
            "[shadow:route-a] ROUTE-ALPHA-7319"
        )
        assert sibling.stdout == ""
        assert collector.delivered_targets == [worker_a]
        assert worker_b not in collector.delivered_targets
        persisted = ledger_path.read_text()
        assert "worker-a-raw" not in persisted
        collector.queue_hook_output(worker_b, {"unexpected": True})
        invalid_output = run_installed_cache_hook(
            Path.cwd(),
            base_event("PostToolUse", "worker-b-raw"),
            environment=environment,
        )
        assert invalid_output.returncode == 0
        assert invalid_output.stdout == ""
        assert invalid_output.stderr == ""
        assert "/private/" not in persisted
        assert descriptor["signature"] not in persisted
        assert '"provenance_status":"untrusted_provenance"' in persisted
    finally:
        collector.stop()


def test_dynamic_offline_collector_output_is_emitted(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    seen: list[str] = []

    def handle(
        raw: dict[str, object], sanitized: dict[str, object]
    ) -> dict[str, object]:
        seen.append(str(sanitized["session_alias"]))
        return {
            "hookSpecificOutput": {
                "hookEventName": raw["hook_event_name"],
                "additionalContext": "[shadow:dynamic-route] target only",
            }
        }

    collector = OfflineCollector(
        "run-dynamic-output",
        secret,
        run_dir / "events.jsonl",
        event_handler=handle,
    )
    collector.start()
    try:
        descriptor_path = run_dir / "descriptor.json"
        descriptor = create_descriptor(
            descriptor_path,
            secret,
            run_id="run-dynamic-output",
            key_id="key-dynamic-output",
            collector_url=collector.url,
            mission_root_digest="a" * 64,
            profile_digest="b" * 64,
            isolation_digest="c" * 64,
            gate_surface_digest="d" * 64,
            installed_artifact_digest="e" * 64,
            latch_path=run_dir / "latch.json",
            ttl_seconds=300,
        )
        collector.bind_descriptor(descriptor)

        result = run_installed_cache_hook(
            Path.cwd(),
            base_event("PostToolUse"),
            environment={
                RUN_FILE_ENV: str(descriptor_path),
                RUN_SECRET_ENV: secret,
            },
        )

        assert json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"] == (
            "[shadow:dynamic-route] target only"
        )
        assert seen == [make_alias(secret, "session", "worker-a-raw")]
    finally:
        collector.stop()


def test_collector_rejects_key_bootstrap_and_cross_run_packets(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    run_id = "run-bound-descriptor"
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    collector = OfflineCollector(run_id, secret, run_dir / "events.jsonl")
    collector.start()
    try:
        descriptor_path = run_dir / "descriptor.json"
        descriptor = create_descriptor(
            descriptor_path,
            secret,
            run_id=run_id,
            key_id="approved-key",
            collector_url=collector.url,
            mission_root_digest="a" * 64,
            profile_digest="b" * 64,
            isolation_digest="c" * 64,
            gate_surface_digest="d" * 64,
            installed_artifact_digest="e" * 64,
            latch_path=run_dir / "latch.json",
            ttl_seconds=300,
        )
        request_value = {
            "schema_version": "0.1",
            "run_id": run_id,
            "event_id": "event-bound",
            "observed_at": 1_700_000_000,
            "hook": base_event("PostToolUse"),
        }
        body = json.dumps(
            request_value, sort_keys=True, separators=(",", ":")
        ).encode()
        approved_headers = sign_event_headers(
            body,
            secret,
            descriptor,
            event_id="event-bound",
            nonce="nonce-bound",
        )

        status, _ = post_signed_event(collector.url, body, approved_headers)
        assert status == 401

        collector.bind_descriptor(descriptor)
        other_run = dict(descriptor)
        other_run["run_id"] = "run-other"
        cross_run_headers = sign_event_headers(
            body,
            secret,
            other_run,
            event_id="event-bound",
            nonce="nonce-other-run",
        )
        status, _ = post_signed_event(collector.url, body, cross_run_headers)
        assert status == 401

        status, _ = post_signed_event(collector.url, body, approved_headers)
        assert status == 200
    finally:
        collector.stop()


def test_concurrent_duplicate_delivery_persists_exactly_once(tmp_path: Path) -> None:
    secret = generate_run_secret()
    run_id = "run-concurrent"
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    ledger_path = run_dir / "events.jsonl"
    handler_calls: list[str] = []
    expected_output = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "delivered once",
        }
    }

    def handle_duplicate(
        raw: dict[str, object],
        sanitized: dict[str, object],
    ) -> dict[str, object]:
        del raw, sanitized
        handler_calls.append("called")
        return expected_output

    collector = OfflineCollector(
        run_id,
        secret,
        ledger_path,
        max_workers=16,
        event_handler=handle_duplicate,
    )
    collector.start()
    try:
        descriptor = create_descriptor(
            run_dir / "descriptor.json",
            secret,
            run_id=run_id,
            key_id="concurrent-key",
            collector_url=collector.url,
            mission_root_digest="a" * 64,
            profile_digest="b" * 64,
            isolation_digest="c" * 64,
            gate_surface_digest="d" * 64,
            installed_artifact_digest="e" * 64,
            latch_path=run_dir / "latch.json",
            ttl_seconds=300,
        )
        collector.bind_descriptor(descriptor)
        request_value = {
            "schema_version": "0.1",
            "run_id": run_id,
            "event_id": "event-concurrent",
            "observed_at": 1_700_000_000,
            "hook": base_event("PostToolUse"),
        }
        body = json.dumps(
            request_value, sort_keys=True, separators=(",", ":")
        ).encode()

        def send(index: int) -> tuple[int, dict[str, object]]:
            headers = sign_event_headers(
                body,
                secret,
                descriptor,
                event_id="event-concurrent",
                nonce=f"nonce-concurrent-{index}",
            )
            return post_signed_event(collector.url, body, headers)

        with ThreadPoolExecutor(max_workers=8) as executor:
            responses = list(executor.map(send, range(32)))

        assert [status for status, _ in responses] == [200] * 32
        assert all(payload == expected_output for _, payload in responses)
        assert handler_calls == ["called"]
        assert len(ledger_path.read_text().splitlines()) == 1
    finally:
        collector.stop()


def test_writer_failure_never_acknowledges_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = generate_run_secret()
    run_dir = tmp_path / "writer-failure"
    run_dir.mkdir(mode=0o700)
    ledger_path = run_dir / "events.jsonl"
    collector = OfflineCollector("run-writer-failure", secret, ledger_path)

    def fail_write(value: object) -> None:
        raise OSError("simulated durable writer outage")

    monkeypatch.setattr(collector, "_persist", fail_write)
    collector.start()
    try:
        descriptor = create_descriptor(
            run_dir / "descriptor.json",
            secret,
            run_id="run-writer-failure",
            key_id="writer-failure-key",
            collector_url=collector.url,
            mission_root_digest="a" * 64,
            profile_digest="b" * 64,
            isolation_digest="c" * 64,
            gate_surface_digest="d" * 64,
            installed_artifact_digest="e" * 64,
            latch_path=run_dir / "latch.json",
            ttl_seconds=300,
        )
        collector.bind_descriptor(descriptor)
        request_value = {
            "schema_version": "0.1",
            "run_id": "run-writer-failure",
            "event_id": "event-writer-failure",
            "observed_at": 1_700_000_000,
            "hook": base_event("PostToolUse"),
        }
        body = json.dumps(
            request_value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        headers = sign_event_headers(
            body,
            secret,
            descriptor,
            event_id="event-writer-failure",
            nonce="nonce-writer-failure",
        )

        status, payload = post_signed_event(collector.url, body, headers)

        assert status == 503
        assert payload == {"error": "capacity"}
        assert collector.pending_item_count == 0
        assert not ledger_path.exists()
    finally:
        collector.stop()


def test_collector_bounds_request_workers_under_stalled_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = generate_run_secret()
    run_dir = tmp_path / "bounded-workers"
    run_dir.mkdir(mode=0o700)
    collector = OfflineCollector(
        "run-bounded-workers",
        secret,
        run_dir / "events.jsonl",
        max_workers=2,
        durability_timeout_seconds=0.2,
    )
    writer_entered = threading.Event()
    release_writer = threading.Event()
    original_persist = collector._persist

    def stalled_write(value: object) -> None:
        writer_entered.set()
        if not release_writer.wait(timeout=5):
            raise OSError("test did not release writer")
        original_persist(value)

    monkeypatch.setattr(collector, "_persist", stalled_write)
    collector.start()
    try:
        descriptor = create_descriptor(
            run_dir / "descriptor.json",
            secret,
            run_id="run-bounded-workers",
            key_id="bounded-workers-key",
            collector_url=collector.url,
            mission_root_digest="a" * 64,
            profile_digest="b" * 64,
            isolation_digest="c" * 64,
            gate_surface_digest="d" * 64,
            installed_artifact_digest="e" * 64,
            latch_path=run_dir / "latch.json",
            ttl_seconds=300,
        )
        collector.bind_descriptor(descriptor)
        barrier = threading.Barrier(12)

        def send(index: int) -> tuple[int, dict[str, object]]:
            event_id = f"event-bounded-{index}"
            request_value = {
                "schema_version": "0.1",
                "run_id": "run-bounded-workers",
                "event_id": event_id,
                "observed_at": 1_700_000_000,
                "hook": base_event("PostToolUse"),
            }
            body = json.dumps(
                request_value,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            headers = sign_event_headers(
                body,
                secret,
                descriptor,
                event_id=event_id,
                nonce=f"nonce-bounded-{index}",
            )
            barrier.wait()
            return post_signed_event(collector.url, body, headers)

        with ThreadPoolExecutor(max_workers=12) as executor:
            responses = list(executor.map(send, range(12)))

        assert [status for status, _ in responses] == [503] * 12
        assert {"error": "workers"} in [payload for _, payload in responses]
        assert writer_entered.is_set()
        assert collector.max_active_workers <= 2
        assert collector.rejected_requests > 0
        assert collector.pending_item_count <= 1_000
        assert collector.pending_byte_count <= 16 << 20
    finally:
        release_writer.set()
        collector.stop()


def outage_registry(
    target_id: str = "worker-a-raw",
    blocker_id: str = "blocker-outage",
) -> FrozenObservationRegistry:
    records = {
        "evidence-outage": FrozenObservation(
            "evidence-outage",
            "run-outage",
            target_id,
            blocker_id,
            "blocker_create",
            "direct_evidence",
            "observed",
            "external_frozen",
        ),
        "probe-outage": FrozenObservation(
            "probe-outage",
            "run-outage",
            target_id,
            blocker_id,
            "blocker_create",
            "probe_confirmation",
            "confirmed",
            "external_frozen",
        ),
        "evidence-resolution": FrozenObservation(
            "evidence-resolution",
            "run-outage",
            target_id,
            blocker_id,
            "blocker_clear",
            "correction",
            "corrected",
            "external_frozen",
        ),
    }
    return FrozenObservationRegistry(records, source_digest="f" * 64)


def with_record_digest(value: dict[str, object]) -> dict[str, object]:
    unsigned = dict(value)
    unsigned.pop("record_digest", None)
    digest = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    return unsigned | {"record_digest": digest}


def production_intervention(
    *,
    intervention_id: str,
    target_session: str,
    blocking_scope: str,
    completion_session_alias: str | None = None,
    state: str = "delivered",
    generation: int = 1,
    attempts: int = 1,
    deadline: int | None = 4_000_000_000,
    transition_history: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    acknowledged = state == "termination_acknowledged"
    corrected = state in {"corrected", "resolved"}
    transitions = transition_history or [
        {
            "transition_id": f"transition-{generation}",
            "generation": generation,
            "state": state,
            "action": state,
            "observed_at": 1_700_000_000,
        }
    ]
    return with_record_digest(
        {
            "schema_version": "0.1",
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "record_type": "intervention_record",
            "intervention_id": intervention_id,
            "run_id": "run-production-outage",
            "finding_id": f"finding-{intervention_id}",
            "finding_dedup_key": "a" * 64,
            "target_session": target_session,
            "completion_session_alias": (
                target_session
                if completion_session_alias is None
                else completion_session_alias
            ),
            "rule": "shared_assumption",
            "level": "blocker",
            "risk_category": "money",
            "claim_ids": ["claim-a"],
            "direct_evidence_ids": ["evidence-a"],
            "direct_evidence_digests": ["b" * 64],
            "correction_evidence_ids": ["correction-a"] if corrected else [],
            "correction_evidence_digests": ["f" * 64] if corrected else [],
            "generation": generation,
            "state": state,
            "transition_history": transitions,
            "probe_id": "probe-a",
            "probe_digest": "c" * 64,
            "probe_status": "confirmed",
            "probe_snapshot_digest": "d" * 64,
            "blocking_scope": blocking_scope,
            "original_feature": "feature-a",
            "repair_assignment": None,
            "repair_guidance_delivered_at": None,
            "probe_pending_at_completion": None,
            "attempts": attempts,
            "deadline": deadline,
            "terminal_outcome": (
                "mission_termination_required"
                if state in {"expired", "termination_acknowledged"}
                else None
            ),
            "termination_acknowledgment_evidence_id": (
                "termination-ack-a" if acknowledged else None
            ),
            "termination_acknowledgment_evidence_digest": (
                "e" * 64 if acknowledged else None
            ),
        }
    )


def production_latch(
    interventions: list[dict[str, object]],
    *,
    generation: int,
) -> dict[str, object]:
    state = with_record_digest(
        {
            "schema_version": "0.1",
            "provenance_status": "hook_authenticated",
            "redaction_status": "clean",
            "record_type": "intervention_router_state",
            "run_id": "run-production-outage",
            "generation": generation,
            "interventions": interventions,
        }
    )
    return {
        "schema_version": "0.1",
        "record_type": "intervention_latch",
        "run_id": "run-production-outage",
        "generation": generation,
        "state": state,
        "written_at": 1_700_000_000,
    }

def production_head(
    latch: dict[str, object],
    **overrides: object,
) -> dict[str, object]:
    state_digest = hashlib.sha256(
        json.dumps(
            latch["state"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    return {
        "schema_version": "0.1",
        "record_type": "intervention_latch_head",
        "run_id": latch["run_id"],
        "generation": latch["generation"],
        "state_digest": state_digest,
        "updated_at": latch["written_at"],
    } | overrides


def write_production_pair(
    latch_path: Path,
    secret: str,
    latch: dict[str, object],
    *,
    head: dict[str, object] | None = None,
) -> None:
    write_signed_private_state(latch_path, secret, latch)
    write_signed_private_state(
        latch_path.with_name(f"{latch_path.stem}-head{latch_path.suffix}"),
        secret,
        production_head(latch) if head is None else head,
    )


def production_outage_environment(
    tmp_path: Path,
    *,
    collector_url: str = "http://127.0.0.1:1/events",
) -> tuple[str, Path, dict[str, str]]:
    run_dir = tmp_path / "production-outage"
    run_dir.mkdir(parents=True, mode=0o700)
    secret = generate_run_secret()
    descriptor_path = run_dir / "descriptor.json"
    latch_path = run_dir / "latch.json"
    create_descriptor(
        descriptor_path,
        secret,
        run_id="run-production-outage",
        key_id="key-production-outage",
        collector_url=collector_url,
        mission_root_digest="a" * 64,
        profile_digest="b" * 64,
        isolation_digest="c" * 64,
        gate_surface_digest="d" * 64,
        installed_artifact_digest="e" * 64,
        latch_path=latch_path,
        ttl_seconds=300,
    )
    return (
        secret,
        latch_path,
        {RUN_FILE_ENV: str(descriptor_path), RUN_SECRET_ENV: secret},
    )


def test_production_outage_latch_lock_timeout_fails_closed(tmp_path: Path) -> None:
    secret, latch_path, environment = production_outage_environment(tmp_path)
    target_alias = make_alias(secret, "session", "worker-a-raw")
    intervention = production_intervention(
        intervention_id="intervention-lock-timeout",
        target_session=target_alias,
        blocking_scope="mission",
    )
    write_production_pair(
        latch_path,
        secret,
        production_latch([intervention], generation=1),
    )
    lock_path = latch_path.with_name(f".{latch_path.name}.lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    try:
        started = time.monotonic()
        completed = run_installed_cache_hook(
            Path.cwd(),
            base_event("Stop"),
            environment=environment,
        )
        elapsed = time.monotonic() - started
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    assert completed.returncode == 0
    assert elapsed < 1.5
    assert json.loads(completed.stdout) == {
        "decision": "block",
        "reason": (
            "[shadow:runtime-unavailable] "
            "Collector and signed latch are unavailable."
        ),
    }
    assert json.loads(latch_path.read_text(encoding="utf-8"))["generation"] == 1


def test_slow_completion_decision_returns_runtime_block_before_hook_timeout(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "slow-completion"
    run_dir.mkdir(mode=0o700)
    secret = generate_run_secret()
    ledger = EventLedger(run_dir, run_id="run-production-outage")
    correlation = MissionCorrelationRegistry(
        allowed={
            make_alias(secret, "session", "worker-a-raw"): "f" * 64,
        }
    )

    def slow_decision(_: object) -> ResponsePlan:
        time.sleep(1.1)
        return ResponsePlan(
            body={
                "decision": "block",
                "reason": "[shadow:slow-decision] completion is blocked",
            }
        )

    collector = HookCollector(
        ledger,
        provenance_status="hook_authenticated",
        correlation=correlation,
        decide=slow_decision,
    )
    descriptor_path = run_dir / "descriptor.json"
    latch_path = run_dir / "latch.json"
    descriptor = create_descriptor(
        descriptor_path,
        secret,
        run_id="run-production-outage",
        key_id="key-slow-completion",
        collector_url=collector.bind(),
        mission_root_digest="a" * 64,
        profile_digest="b" * 64,
        isolation_digest="c" * 64,
        gate_surface_digest="d" * 64,
        installed_artifact_digest="e" * 64,
        latch_path=latch_path,
        ttl_seconds=300,
    )
    write_production_pair(
        latch_path, secret, production_latch([], generation=0)
    )
    collector.start(secret=secret, descriptor=descriptor)
    try:
        result = run_installed_cache_hook(
            Path.cwd(),
            base_event("Stop"),
            environment={
                RUN_FILE_ENV: str(descriptor_path),
                RUN_SECRET_ENV: secret,
            },
        )
    finally:
        collector.stop()

    output = json.loads(result.stdout)
    assert output["decision"] == "block"
    assert output["reason"] == (
        "[shadow:runtime-unavailable] "
        "Collector unavailable; completion state cannot be verified."
    )


def test_collector_503_uses_exact_target_latch_and_fails_closed_without_one(
    tmp_path: Path,
) -> None:
    server, thread = start_status_server(503)
    try:
        collector_url = f"http://127.0.0.1:{server.server_port}/events"
        secret, latch_path, environment = production_outage_environment(
            tmp_path,
            collector_url=collector_url,
        )
        target_alias = make_alias(secret, "session", "worker-a-raw")

        write_production_pair(
            latch_path, secret, production_latch([], generation=0)
        )
        empty = run_installed_cache_hook(
            Path.cwd(), base_event("SubagentStop"), environment=environment
        )
        non_completion = run_installed_cache_hook(
            Path.cwd(), base_event("PostToolUse"), environment=environment
        )

        active = production_intervention(
            intervention_id="intervention-503-active",
            target_session=target_alias,
            blocking_scope="worker",
            attempts=0,
            deadline=None,
        )
        write_production_pair(
            latch_path, secret, production_latch([active], generation=1)
        )
        active_result = run_installed_cache_hook(
            Path.cwd(), base_event("SubagentStop"), environment=environment
        )
        first_active_state = json.loads(latch_path.read_text())["state"][
            "interventions"
        ][0]
        second_active_result = run_installed_cache_hook(
            Path.cwd(), base_event("SubagentStop"), environment=environment
        )
        second_active_state = json.loads(latch_path.read_text())["state"][
            "interventions"
        ][0]
        terminal_active_result = run_installed_cache_hook(
            Path.cwd(), base_event("SubagentStop"), environment=environment
        )

        resolved = production_intervention(
            intervention_id="intervention-503-resolved",
            target_session=target_alias,
            blocking_scope="worker",
            state="resolved",
        )
        write_production_pair(
            latch_path, secret, production_latch([resolved], generation=1)
        )
        resolved_result = run_installed_cache_hook(
            Path.cwd(), base_event("SubagentStop"), environment=environment
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert "completion state cannot be verified" in json.loads(
        empty.stdout
    )["reason"]
    assert non_completion.stdout == ""
    assert "intervention-503-active" in json.loads(active_result.stdout)["reason"]
    assert "intervention-503-active" in json.loads(
        second_active_result.stdout
    )["reason"]
    assert first_active_state["deadline"] == second_active_state["deadline"]
    assert "mandatory Mission termination" in json.loads(
        terminal_active_result.stdout
    )["reason"]
    assert "completion state cannot be verified" in json.loads(
        resolved_result.stdout
    )["reason"]


@pytest.mark.parametrize("status", [401, 403])
def test_collector_authentication_failure_does_not_consume_latch(
    tmp_path: Path,
    status: int,
) -> None:
    server, thread = start_status_server(status)
    try:
        collector_url = f"http://127.0.0.1:{server.server_port}/events"
        secret, latch_path, environment = production_outage_environment(
            tmp_path,
            collector_url=collector_url,
        )
        intervention = production_intervention(
            intervention_id="intervention-auth",
            target_session=make_alias(secret, "session", "worker-a-raw"),
            blocking_scope="worker",
            attempts=0,
            deadline=None,
        )
        write_production_pair(
            latch_path, secret, production_latch([intervention], generation=1)
        )
        before = latch_path.read_bytes()

        result = run_installed_cache_hook(
            Path.cwd(), base_event("SubagentStop"), environment=environment
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert "Collector authentication failed" in json.loads(result.stdout)["reason"]
    assert latch_path.read_bytes() == before


def test_dependency_free_validator_accepts_independent_evidence_sets() -> None:
    intervention = production_intervention(
        intervention_id="intervention-independent-evidence",
        state="resolved",
        target_session="session-safe",
        blocking_scope="worker",
    )
    intervention["direct_evidence_ids"] = ["evidence-a", "evidence-b"]
    intervention["correction_evidence_ids"] = ["correction-a", "correction-b"]
    intervention = with_record_digest(intervention)
    runtime_path = Path.cwd() / "hooks" / "hook_runtime.py"
    script = """
import importlib.util
import json
import sys

spec = importlib.util.spec_from_file_location("isolated_hook_runtime", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
record = json.loads(sys.stdin.read())
module._validate_intervention(
    record,
    run_id="run-production-outage",
    router_generation=1,
)
"""

    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(runtime_path)],
        input=json.dumps(intervention),
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_production_latch_scopes_worker_and_mission_blocks(
    tmp_path: Path,
) -> None:
    secret, latch_path, environment = production_outage_environment(tmp_path)
    target_alias = make_alias(secret, "session", "worker-a-raw")
    worker = production_intervention(
        intervention_id="intervention-worker",
        target_session=target_alias,
        blocking_scope="worker",
    )
    write_production_pair(
        latch_path, secret, production_latch([worker], generation=1)
    )

    target = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )
    sibling = run_installed_cache_hook(
        Path.cwd(),
        base_event("SubagentStop", "worker-b-raw"),
        environment=environment,
    )
    wrong_event = run_installed_cache_hook(
        Path.cwd(), base_event("Stop"), environment=environment
    )

    assert "intervention-worker" in json.loads(target.stdout)["reason"]
    assert "completion state cannot be verified" in json.loads(
        sibling.stdout
    )["reason"]
    assert "completion state cannot be verified" in json.loads(
        wrong_event.stdout
    )["reason"]

    orchestrator_alias = make_alias(secret, "session", "orchestrator-raw")
    mission = production_intervention(
        intervention_id="intervention-mission",
        target_session=target_alias,
        completion_session_alias=orchestrator_alias,
        blocking_scope="mission",
    )
    write_production_pair(
        latch_path, secret, production_latch([mission], generation=1)
    )
    before_wrong_session = latch_path.read_bytes()
    worker_stop = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )
    wrong_session_stop = run_installed_cache_hook(
        Path.cwd(), base_event("Stop"), environment=environment
    )
    after_wrong_session = latch_path.read_bytes()
    mission_stop = run_installed_cache_hook(
        Path.cwd(),
        base_event("Stop", "orchestrator-raw"),
        environment=environment,
    )

    assert "completion state cannot be verified" in json.loads(
        worker_stop.stdout
    )["reason"]
    assert "completion state cannot be verified" in json.loads(
        wrong_session_stop.stdout
    )["reason"]
    assert after_wrong_session == before_wrong_session
    assert "intervention-mission" in json.loads(mission_stop.stdout)["reason"]


def test_production_outage_cas_advances_only_exact_target_to_terminal(
    tmp_path: Path,
) -> None:
    secret, latch_path, environment = production_outage_environment(tmp_path)
    target_alias = make_alias(secret, "session", "worker-a-raw")
    intervention = production_intervention(
        intervention_id="intervention-attempts",
        target_session=target_alias,
        blocking_scope="worker",
        attempts=0,
        deadline=None,
    )
    write_production_pair(
        latch_path, secret, production_latch([intervention], generation=1)
    )
    original_latch = latch_path.read_bytes()

    sibling = run_installed_cache_hook(
        Path.cwd(),
        base_event("SubagentStop", "worker-b-raw"),
        environment=environment,
    )
    after_sibling = latch_path.read_bytes()
    first = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )
    first_latch = json.loads(latch_path.read_text())
    first_state = first_latch["state"]["interventions"][0]
    second = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )
    second_state = json.loads(latch_path.read_text())["state"]["interventions"][0]
    third = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )
    terminal_latch = json.loads(latch_path.read_text())
    terminal_state = terminal_latch["state"]["interventions"][0]
    terminal_head = json.loads(
        latch_path.with_name(f"{latch_path.stem}-head{latch_path.suffix}").read_text()
    )

    assert "completion state cannot be verified" in json.loads(
        sibling.stdout
    )["reason"]
    assert after_sibling == original_latch
    assert "Confirmed risk remains unresolved" in json.loads(first.stdout)["reason"]
    assert first_state["attempts"] == 1
    assert first_state["deadline"] == first_latch["written_at"] + 600
    assert first_state["transition_history"][-1]["action"] == "blocked_attempt"
    assert "Confirmed risk remains unresolved" in json.loads(second.stdout)["reason"]
    assert second_state["attempts"] == 2
    assert second_state["deadline"] == first_state["deadline"]
    assert second_state["transition_history"][-1]["action"] == "blocked_attempt"
    assert "mandatory Mission termination" in json.loads(third.stdout)["reason"]
    assert terminal_state["state"] == "expired"
    assert terminal_state["attempts"] == 2
    assert terminal_state["terminal_outcome"] == "mission_termination_required"
    assert terminal_state["transition_history"][-1]["action"] == (
        "termination_required"
    )
    assert terminal_head["generation"] == terminal_latch["generation"]
    assert terminal_head["updated_at"] == terminal_latch["written_at"]
    assert terminal_head["state_digest"] == hashlib.sha256(
        json.dumps(
            terminal_latch["state"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


@pytest.mark.parametrize(
    ("deadline", "terminal"),
    [(4_000_000_000, False), (1, True)],
)
def test_production_outage_cas_honors_deadline(
    tmp_path: Path,
    deadline: int,
    terminal: bool,
) -> None:
    secret, latch_path, environment = production_outage_environment(tmp_path)
    intervention = production_intervention(
        intervention_id="intervention-deadline",
        target_session=make_alias(secret, "session", "worker-a-raw"),
        blocking_scope="worker",
        attempts=1,
        deadline=deadline,
    )
    write_production_pair(
        latch_path, secret, production_latch([intervention], generation=1)
    )

    result = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )
    persisted = json.loads(latch_path.read_text())["state"]["interventions"][0]

    assert ("mandatory Mission termination" in json.loads(result.stdout)["reason"]) is terminal
    assert (persisted["state"] == "expired") is terminal
    if not terminal:
        assert persisted["attempts"] == 2
        assert persisted["deadline"] == deadline


def test_production_latch_rejects_forgery_malformed_shape_and_rollback(
    tmp_path: Path,
) -> None:
    secret, latch_path, environment = production_outage_environment(tmp_path)
    target_alias = make_alias(secret, "session", "worker-a-raw")
    forged = production_intervention(
        intervention_id="intervention-forged",
        target_session=target_alias,
        blocking_scope="worker",
    )
    forged["record_digest"] = "0" * 64
    write_production_pair(
        latch_path, secret, production_latch([forged], generation=1)
    )

    forged_result = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )

    forged_output = json.loads(forged_result.stdout)
    assert forged_output["decision"] == "block"
    assert "signed latch are unavailable" in forged_output["reason"]

    malformed = production_intervention(
        intervention_id="intervention-malformed",
        target_session=target_alias,
        blocking_scope="worker",
    )
    malformed["unexpected"] = True
    malformed = with_record_digest(malformed)
    write_production_pair(
        latch_path, secret, production_latch([malformed], generation=1)
    )

    malformed_result = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )

    malformed_output = json.loads(malformed_result.stdout)
    assert malformed_output["decision"] == "block"
    unsafe_alias = production_intervention(
        intervention_id="intervention-unsafe-alias",
        target_session=target_alias,
        completion_session_alias="../orchestrator",
        blocking_scope="mission",
    )
    write_production_pair(
        latch_path, secret, production_latch([unsafe_alias], generation=1)
    )

    unsafe_alias_result = run_installed_cache_hook(
        Path.cwd(), base_event("Stop"), environment=environment
    )

    unsafe_alias_output = json.loads(unsafe_alias_result.stdout)
    assert unsafe_alias_output["decision"] == "block"
    assert "signed latch are unavailable" in unsafe_alias_output["reason"]

    assert "signed latch are unavailable" in malformed_output["reason"]

    rollback = production_intervention(
        intervention_id="intervention-rollback",
        target_session=target_alias,
        blocking_scope="worker",
    )
    write_production_pair(
        latch_path, secret, production_latch([rollback], generation=2)
    )

    rollback_result = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )

    rollback_output = json.loads(rollback_result.stdout)
    assert rollback_output["decision"] == "block"
    assert "signed latch are unavailable" in rollback_output["reason"]

def test_valid_pair_rollback_to_older_empty_state_cannot_allow_completion(
    tmp_path: Path,
) -> None:
    secret, latch_path, environment = production_outage_environment(tmp_path)
    older_empty = production_latch([], generation=0)
    active = production_intervention(
        intervention_id="intervention-before-empty-rollback",
        target_session=make_alias(secret, "session", "worker-a-raw"),
        blocking_scope="worker",
        attempts=0,
        deadline=None,
    )
    write_production_pair(
        latch_path, secret, production_latch([active], generation=1)
    )

    anchored = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )
    write_production_pair(latch_path, secret, older_empty)
    rolled_back = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )

    assert "intervention-before-empty-rollback" in json.loads(anchored.stdout)["reason"]
    assert "completion state cannot be verified" in json.loads(
        rolled_back.stdout
    )["reason"]


@pytest.mark.parametrize(
    "mismatch",
    [
        "missing",
        "forged",
        "older",
        "newer",
        "cross_run",
        "replayed_latch",
        "symlink",
        "non_private",
        "symlink_latch",
        "non_private_latch",
        "malformed_state",
    ],
)
def test_production_outage_requires_exact_current_private_head(
    tmp_path: Path,
    mismatch: str,
) -> None:
    secret, latch_path, environment = production_outage_environment(tmp_path)
    head_path = latch_path.with_name(f"{latch_path.stem}-head{latch_path.suffix}")
    target_alias = make_alias(secret, "session", "worker-a-raw")
    intervention = production_intervention(
        intervention_id="intervention-head-binding",
        target_session=target_alias,
        blocking_scope="worker",
    )
    old_latch = production_latch([intervention], generation=1)
    write_production_pair(latch_path, secret, old_latch)

    if mismatch == "missing":
        head_path.unlink()
    elif mismatch == "forged":
        forged_head = json.loads(head_path.read_text())
        forged_head["state_digest"] = "0" * 64
        head_path.write_text(json.dumps(forged_head))
        os.chmod(head_path, 0o600)
    elif mismatch in {"older", "newer", "cross_run"}:
        overrides: dict[str, object] = {}
        if mismatch == "older":
            overrides["generation"] = 0
        elif mismatch == "newer":
            overrides["generation"] = 2
        else:
            overrides["run_id"] = "run-other"
        write_signed_private_state(
            head_path,
            secret,
            production_head(old_latch, **overrides),
        )
    elif mismatch == "replayed_latch":
        replayed_bytes = latch_path.read_bytes()
        current = production_intervention(
            intervention_id="intervention-head-binding",
            target_session=target_alias,
            blocking_scope="worker",
            generation=2,
        )
        write_production_pair(
            latch_path, secret, production_latch([current], generation=2)
        )
        latch_path.write_bytes(replayed_bytes)
        os.chmod(latch_path, 0o600)
    elif mismatch == "symlink":
        head_path.unlink()
        head_path.symlink_to(latch_path)
    elif mismatch == "non_private":
        os.chmod(head_path, 0o644)
    elif mismatch == "symlink_latch":
        real_latch_path = latch_path.with_name("real-latch.json")
        latch_path.replace(real_latch_path)
        latch_path.symlink_to(real_latch_path)
    elif mismatch == "non_private_latch":
        os.chmod(latch_path, 0o644)
    else:
        malformed = production_latch([intervention], generation=1)
        malformed["state"]["generation"] = "one"
        write_production_pair(latch_path, secret, malformed)

    result = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )

    output = json.loads(result.stdout)
    assert output["decision"] == "block"
    assert output["reason"].startswith("[shadow:runtime-unavailable]")
    assert "signed latch are unavailable" in output["reason"]
    assert "intervention-head-binding" not in output["reason"]


def test_expired_production_latch_and_acknowledged_state_stay_fail_closed(
    tmp_path: Path,
) -> None:
    secret, latch_path, environment = production_outage_environment(tmp_path)
    target_alias = make_alias(secret, "session", "worker-a-raw")
    expired_transition = {
        "transition_id": "transition-expired",
        "generation": 1,
        "state": "expired",
        "action": "expired",
        "observed_at": 1_700_000_000,
    }
    expired = production_intervention(
        intervention_id="intervention-expired",
        target_session=target_alias,
        blocking_scope="mission",
        state="expired",
        attempts=2,
        deadline=1,
        transition_history=[expired_transition],
    )
    write_production_pair(
        latch_path, secret, production_latch([expired], generation=1)
    )

    attempts = [
        run_installed_cache_hook(
            Path.cwd(), base_event("Stop"), environment=environment
        )
        for _ in range(4)
    ]

    for result in attempts:
        output = json.loads(result.stdout)
        assert output["decision"] == "block"
        assert "mandatory Mission termination and failure" in output["reason"]
        assert "intervention-expired" in output["reason"]

    acknowledged_transition = {
        "transition_id": "transition-termination-acknowledged",
        "generation": 2,
        "state": "termination_acknowledged",
        "action": "termination_acknowledged",
        "observed_at": 1_700_000_001,
    }
    acknowledged = production_intervention(
        intervention_id="intervention-expired",
        target_session=target_alias,
        blocking_scope="mission",
        state="termination_acknowledged",
        generation=2,
        attempts=2,
        deadline=1,
        transition_history=[expired_transition, acknowledged_transition],
    )
    write_production_pair(
        latch_path, secret, production_latch([acknowledged], generation=2)
    )

    released = run_installed_cache_hook(
        Path.cwd(), base_event("Stop"), environment=environment
    )
    assert "completion state cannot be verified" in json.loads(
        released.stdout
    )["reason"]


def test_completion_hook_blocks_from_signed_latch_during_collector_outage(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    collector = OfflineCollector("run-outage", secret, run_dir / "events.jsonl")
    collector.start()
    descriptor_path = run_dir / "descriptor.json"
    descriptor = create_descriptor(
        descriptor_path,
        secret,
        run_id="run-outage",
        key_id="key-outage",
        collector_url=collector.url,
        mission_root_digest="a" * 64,
        profile_digest="b" * 64,
        isolation_digest="c" * 64,
        gate_surface_digest="d" * 64,
        installed_artifact_digest="e" * 64,
        latch_path=run_dir / "latch.json",
        ttl_seconds=300,
    )
    registry = outage_registry()
    write_latch(
        run_dir / "latch.json",
        secret,
        descriptor,
        registry=registry,
        scope="worker",
        target_id="worker-a-raw",
        blocker_id="blocker-outage",
        state="active",
        generation=1,
        direct_evidence_ids=["evidence-outage"],
        probe_result_id="probe-outage",
        correction_evidence_ids=[],
        provenance_status="untrusted_provenance",
        ttl_seconds=60,
    )
    collector.stop()
    environment = {RUN_FILE_ENV: str(descriptor_path), RUN_SECRET_ENV: secret}

    first = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )
    retry = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )

    assert json.loads(first.stdout) == json.loads(retry.stdout)
    assert json.loads(first.stdout)["decision"] == "block"
    assert "blocker-outage" in json.loads(first.stdout)["reason"]

    write_latch(
        run_dir / "latch.json",
        secret,
        descriptor,
        registry=registry,
        scope="worker",
        target_id="worker-a-raw",
        blocker_id="blocker-outage",
        state="resolved",
        generation=2,
        direct_evidence_ids=["evidence-outage"],
        probe_result_id="probe-outage",
        correction_evidence_ids=["evidence-resolution"],
        provenance_status="untrusted_provenance",
        ttl_seconds=60,
    )
    released = run_installed_cache_hook(
        Path.cwd(), base_event("SubagentStop"), environment=environment
    )
    assert "completion state cannot be verified" in json.loads(
        released.stdout
    )["reason"]
    non_target = run_installed_cache_hook(
        Path.cwd(),
        base_event("SubagentStop", "worker-b-raw"),
        environment=environment,
    )
    assert json.loads(non_target.stdout)["decision"] == "block"

def test_payload_mode_requires_matching_disk_descriptor_and_uses_latch(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    collector = OfflineCollector("run-outage", secret, run_dir / "events.jsonl")
    collector.start()
    descriptor_path = run_dir / "descriptor.json"
    descriptor = create_descriptor(
        descriptor_path,
        secret,
        run_id="run-outage",
        key_id="key-outage",
        collector_url=collector.url,
        mission_root_digest="a" * 64,
        profile_digest="b" * 64,
        isolation_digest="c" * 64,
        gate_surface_digest="d" * 64,
        installed_artifact_digest="e" * 64,
        latch_path=run_dir / "latch.json",
        ttl_seconds=300,
    )
    registry = outage_registry()
    write_latch(
        run_dir / "latch.json",
        secret,
        descriptor,
        registry=registry,
        scope="worker",
        target_id="worker-a-raw",
        blocker_id="blocker-outage",
        state="active",
        generation=1,
        direct_evidence_ids=["evidence-outage"],
        probe_result_id="probe-outage",
        correction_evidence_ids=[],
        provenance_status="untrusted_provenance",
        ttl_seconds=60,
    )
    payload = json.dumps(descriptor, sort_keys=True, separators=(",", ":"))
    environment = {
        RUN_FILE_ENV: str(descriptor_path),
        RUN_DESCRIPTOR_ENV: payload,
        RUN_SECRET_ENV: secret,
    }
    collector.stop()

    blocked = run_installed_cache_hook(
        Path.cwd(),
        base_event("SubagentStop"),
        environment=environment,
    )
    assert json.loads(blocked.stdout)["decision"] == "block"
    assert "blocker-outage" in json.loads(blocked.stdout)["reason"]

    descriptor_path.unlink()
    missing = run_installed_cache_hook(
        Path.cwd(),
        base_event("SubagentStop"),
        environment=environment,
    )
    assert json.loads(missing.stdout)["decision"] == "block"
    assert "descriptor validation failed" in json.loads(missing.stdout)["reason"]



def test_mission_latch_blocks_every_completion_during_outage(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    collector = OfflineCollector("run-outage", secret, run_dir / "events.jsonl")
    collector.start()
    descriptor_path = run_dir / "descriptor.json"
    descriptor = create_descriptor(
        descriptor_path,
        secret,
        run_id="run-outage",
        key_id="key-outage",
        collector_url=collector.url,
        mission_root_digest="a" * 64,
        profile_digest="b" * 64,
        isolation_digest="c" * 64,
        gate_surface_digest="d" * 64,
        installed_artifact_digest="e" * 64,
        latch_path=run_dir / "latch.json",
        ttl_seconds=300,
    )
    write_latch(
        run_dir / "latch.json",
        secret,
        descriptor,
        registry=outage_registry("run-outage", "mission-outage"),
        scope="mission",
        target_id="run-outage",
        blocker_id="mission-outage",
        state="active",
        generation=1,
        direct_evidence_ids=["evidence-outage"],
        probe_result_id="probe-outage",
        correction_evidence_ids=[],
        provenance_status="untrusted_provenance",
        ttl_seconds=60,
    )
    collector.stop()
    environment = {RUN_FILE_ENV: str(descriptor_path), RUN_SECRET_ENV: secret}

    worker_stop = run_installed_cache_hook(
        Path.cwd(),
        base_event("SubagentStop", "worker-a-raw"),
        environment=environment,
    )
    mission_stop = run_installed_cache_hook(
        Path.cwd(),
        base_event("Stop", "orchestrator-raw"),
        environment=environment,
    )

    assert json.loads(worker_stop.stdout)["decision"] == "block"
    assert json.loads(mission_stop.stdout)["decision"] == "block"
    assert "completion state cannot be verified" in json.loads(
        mission_stop.stdout
    )["reason"]




def test_active_descriptor_without_secret_blocks_only_completion_hooks(
    tmp_path: Path,
) -> None:
    descriptor_path = tmp_path / "descriptor.json"
    descriptor_path.write_text("{}")
    os.chmod(descriptor_path, 0o600)
    environment = {RUN_FILE_ENV: str(descriptor_path)}

    stop = run_installed_cache_hook(
        Path.cwd(), base_event("Stop"), environment=environment
    )
    update = run_installed_cache_hook(
        Path.cwd(), base_event("PostToolUse"), environment=environment
    )

    assert json.loads(stop.stdout)["decision"] == "block"
    assert update.stdout == ""
