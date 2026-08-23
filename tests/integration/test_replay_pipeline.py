from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from pathlib import Path
from typing import Callable
from urllib.request import Request, urlopen

import pytest

from shadow_mission.auth import (
    create_descriptor,
    generate_run_secret,
    make_alias,
    sign_event_headers,
)
from shadow_mission.collector import (
    COLLECTOR_RESPONSE_DEADLINE_SECONDS,
    CollectorRequestError,
    GuidanceQueue,
    HookCollector,
    MissionCorrelationRegistry,
)
from shadow_mission.protocol import (
    HookEnvelope,
    HookExchangeRecord,
    HookRequest,
    canonical_json,
)
from shadow_mission.storage import EventLedger


def start_collector(
    tmp_path: Path,
    *,
    guidance: GuidanceQueue | None = None,
    capture_request: Callable[[HookRequest, HookEnvelope], None] | None = None,
    discard_request: Callable[[str], None] | None = None,
    after_append: Callable[[HookExchangeRecord], None] | None = None,
    correlation_refresh: Callable[[], object] | None = None,
    forbidden_values: tuple[str, ...] = (),
) -> tuple[HookCollector, str, dict[str, object]]:
    run_dir = tmp_path / "run"
    ledger = EventLedger(
        run_dir,
        run_id="run-1",
        after_append=after_append,
    )
    queue = guidance or GuidanceQueue()
    secret = generate_run_secret()
    correlation = MissionCorrelationRegistry(
        allowed={
            make_alias(secret, "session", "raw-session-a"): "f" * 64,
        }
    )
    collector = HookCollector(
        ledger,
        provenance_status="hook_authenticated",
        correlation=correlation,
        correlation_refresh=correlation_refresh,
        decide=queue.decision,
        capture_request=capture_request,
        discard_request=discard_request,
        forbidden_values=forbidden_values,
    )
    url = collector.bind()
    descriptor = create_descriptor(
        run_dir / "descriptor.json",
        secret,
        run_id="run-1",
        key_id="key-1",
        collector_url=url,
        mission_root_digest="a" * 64,
        profile_digest="b" * 64,
        isolation_digest="c" * 64,
        gate_surface_digest="d" * 64,
        installed_artifact_digest="e" * 64,
        latch_path=run_dir / "latch.json",
    )
    collector.start(secret=secret, descriptor=descriptor)
    return collector, secret, descriptor


def event_body(
    event_id: str = "event-1",
    *,
    tool_name: str = "Read",
    tool_response: str = "ok",
) -> bytes:
    return canonical_json(
        {
            "schema_version": "0.1",
            "run_id": "run-1",
            "event_id": event_id,
            "observed_at": int(time.time()),
            "hook": {
                "hook_event_name": "PostToolUse",
                "session_id": "raw-session-a",
                "transcript_path": "/private/transcripts/a.jsonl",
                "cwd": "/private/mission",
                "tool_name": tool_name,
                "tool_response": tool_response,
            },
        }
    )


def headers(
    body: bytes,
    secret: str,
    descriptor: dict[str, object],
    *,
    event_id: str = "event-1",
    nonce: str,
) -> dict[str, str]:
    return sign_event_headers(
        body,
        secret,
        descriptor,
        event_id=event_id,
        nonce=nonce,
    )


def test_guidance_is_consumed_only_once_and_retry_is_byte_identical(
    tmp_path: Path,
) -> None:
    queue = GuidanceQueue()
    collector, secret, descriptor = start_collector(tmp_path, guidance=queue)
    session_alias = collector.ledger.exchanges()
    assert session_alias == ()


    queue.queue(
        session_alias=make_alias(secret, "session", "raw-session-a"),
        guidance_id="guidance-1",
        hook_output={
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "Use cents.",
            }
        },
    )
    body = event_body()
    first = collector.process(
        headers(body, secret, descriptor, nonce="nonce-first"), body
    )
    second = collector.process(
        headers(body, secret, descriptor, nonce="nonce-second"), body
    )
    collector.stop()

    assert first == second
    assert queue.item_count == 0
    assert len(collector.ledger.exchanges()) == 1
    assert json.loads(first)["hookSpecificOutput"]["additionalContext"] == "Use cents."


def test_durable_retry_bypasses_failed_correlation_refresh(tmp_path: Path) -> None:
    refresh_calls = 0

    def refresh() -> None:
        nonlocal refresh_calls
        refresh_calls += 1
        if refresh_calls > 1:
            raise RuntimeError("correlation unavailable")

    collector, secret, descriptor = start_collector(
        tmp_path,
        correlation_refresh=refresh,
    )
    body = event_body()
    first = collector.process(
        headers(body, secret, descriptor, nonce="nonce-first"),
        body,
    )
    second = collector.process(
        headers(body, secret, descriptor, nonce="nonce-retry"),
        body,
    )
    collector.stop()

    assert second == first
    assert refresh_calls == 1
    assert len(collector.ledger.exchanges()) == 1


def test_unseen_event_fails_when_correlation_refresh_is_unavailable(
    tmp_path: Path,
) -> None:
    refresh_calls = 0

    def refresh() -> None:
        nonlocal refresh_calls
        refresh_calls += 1
        raise RuntimeError("correlation unavailable")

    collector, secret, descriptor = start_collector(
        tmp_path,
        correlation_refresh=refresh,
    )
    body = event_body()

    with pytest.raises(CollectorRequestError) as caught:
        collector.process(
            headers(body, secret, descriptor, nonce="nonce-first"),
            body,
        )
    collector.stop()

    assert caught.value.status == 503
    assert refresh_calls == 1
    assert collector.ledger.exchanges() == ()


def test_changed_body_with_same_event_id_is_rejected(tmp_path: Path) -> None:
    collector, secret, descriptor = start_collector(tmp_path)
    first = event_body(tool_name="Read")
    collector.process(headers(first, secret, descriptor, nonce="nonce-a"), first)
    changed = event_body(tool_name="Write")

    with pytest.raises(CollectorRequestError) as caught:
        collector.process(
            headers(changed, secret, descriptor, nonce="nonce-b"), changed
        )
    collector.stop()

    assert caught.value.status == 409
    assert len(collector.ledger.exchanges()) == 1


def test_concurrent_duplicate_delivery_creates_one_exchange(tmp_path: Path) -> None:
    collector, secret, descriptor = start_collector(tmp_path)
    body = event_body()
    barrier = threading.Barrier(17)
    responses: list[bytes] = []

    def deliver(index: int) -> None:
        barrier.wait()
        responses.append(
            collector.process(
                headers(body, secret, descriptor, nonce=f"nonce-{index:04d}"), body
            )
        )

    threads = [threading.Thread(target=deliver, args=(index,)) for index in range(16)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    collector.stop()

    assert responses == [b"{}"] * 16
    assert len(collector.ledger.exchanges()) == 1


def test_http_hook_boundary_persists_before_success(tmp_path: Path) -> None:
    collector, secret, descriptor = start_collector(tmp_path)
    body = event_body()
    request = Request(
        collector.url,
        data=body,
        headers=headers(body, secret, descriptor, nonce="nonce-http"),
        method="POST",
    )
    with urlopen(request, timeout=2) as response:
        assert response.status == 200
        assert response.read() == b"{}"
        assert len(collector.ledger.exchanges()) == 1
    collector.stop()


def test_reference_load_p95_stays_below_hook_budget(tmp_path: Path) -> None:
    collector, secret, descriptor = start_collector(tmp_path)
    barrier = threading.Barrier(17)
    latencies: list[float] = []

    def deliver(index: int) -> None:
        body = event_body(event_id=f"event-{index}")
        request_headers = headers(
            body,
            secret,
            descriptor,
            event_id=f"event-{index}",
            nonce=f"nonce-load-{index}",
        )
        barrier.wait()
        started = time.perf_counter()
        collector.process(request_headers, body)
        latencies.append(time.perf_counter() - started)

    threads = [threading.Thread(target=deliver, args=(index,)) for index in range(16)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    collector.stop()

    ordered = sorted(latencies)
    p95 = ordered[int(len(ordered) * 0.95) - 1]
    assert p95 < COLLECTOR_RESPONSE_DEADLINE_SECONDS
    assert len(collector.ledger.exchanges()) == 16


def test_persisted_exchange_contains_no_raw_identifiers_or_secret(tmp_path: Path) -> None:
    source_canary = "shadow-source-canary-private"
    collector, secret, descriptor = start_collector(
        tmp_path,
        forbidden_values=(source_canary,),
    )
    body = event_body(tool_response=f"bare {secret} {source_canary}")
    collector.process(headers(body, secret, descriptor, nonce="nonce-private"), body)
    collector.stop()

    persisted = (tmp_path / "run/events.jsonl").read_text()
    for forbidden in (
        "raw-session-a",
        "/private/transcripts/a.jsonl",
        "/private/mission",
        secret,
        source_canary,
    ):
        assert forbidden not in persisted
    exchange = collector.ledger.exchanges()[0]
    assert exchange.envelope.message_digest == hmac.new(
        secret.encode("utf-8"),
        b"shadow-raw-hook-v1\0" + body,
        hashlib.sha256,
    ).hexdigest()
    assert exchange.envelope.message_digest != hashlib.sha256(body).hexdigest()


def test_authenticated_ephemeral_handoff_occurs_once_for_the_committed_event(
    tmp_path: Path,
) -> None:
    captured: list[tuple[HookRequest, HookEnvelope]] = []
    committed: list[HookExchangeRecord] = []
    collector, secret, descriptor = start_collector(
        tmp_path,
        capture_request=lambda request, envelope: captured.append(
            (request, envelope)
        ),
        after_append=committed.append,
    )
    body = event_body()

    collector.process(
        headers(body, secret, descriptor, nonce="nonce-handoff-first"),
        body,
    )
    collector.process(
        headers(body, secret, descriptor, nonce="nonce-handoff-retry"),
        body,
    )
    collector.stop()

    assert len(captured) == 1
    assert len(committed) == 1
    request, envelope = captured[0]
    assert request.transcript_path == "/private/transcripts/a.jsonl"
    assert request.event_id == envelope.event_id == committed[0].envelope.event_id


def test_failed_capture_rolls_back_ephemeral_request_context(
    tmp_path: Path,
) -> None:
    captured: set[str] = set()

    def capture(request: HookRequest, envelope: HookEnvelope) -> None:
        assert request.event_id == envelope.event_id
        captured.add(request.event_id)
        raise RuntimeError("capture failed after mutation")

    collector, secret, descriptor = start_collector(
        tmp_path,
        capture_request=capture,
        discard_request=captured.discard,
    )
    body = event_body()

    with pytest.raises(RuntimeError, match="capture failed after mutation"):
        collector.process(
            headers(body, secret, descriptor, nonce="nonce-capture-rollback"),
            body,
        )

    assert captured == set()
    assert collector.ledger.exchanges() == ()
    collector.stop()
