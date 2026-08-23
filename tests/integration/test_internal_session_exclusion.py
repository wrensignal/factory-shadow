from __future__ import annotations

import time
from pathlib import Path

import pytest

from shadow_mission.auth import (
    create_descriptor,
    generate_run_secret,
    make_alias,
    sign_event_headers,
)
from shadow_mission.collector import (
    CollectorRequestError,
    HookCollector,
    MissionCorrelationRegistry,
)
from shadow_mission.protocol import HookEnvelope, canonical_json
from shadow_mission.storage import EventLedger


def body(event_id: str, session_id: str) -> bytes:
    return canonical_json(
        {
            "schema_version": "0.1",
            "run_id": "run-1",
            "event_id": event_id,
            "observed_at": int(time.time()),
            "hook": {
                "hook_event_name": "SessionStart",
                "session_id": session_id,
                "transcript_path": f"/private/{session_id}.jsonl",
                "cwd": "/same/project",
                "prompt": "task",
            },
        }
    )


def test_registry_excludes_shadow_owned_and_same_project_decoy_before_ledger(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    intended = make_alias(secret, "session", "intended-worker")
    internal = make_alias(secret, "session", "shadow-probe")
    correlation = MissionCorrelationRegistry(
        allowed={intended: "a" * 64, internal: "b" * 64},
        excluded=frozenset({internal}),
    )
    with pytest.raises(ValueError, match="excluded session"):
        correlation.allow(internal, "b" * 64)

    ledger = EventLedger(tmp_path / "run", run_id="run-1")
    collector = HookCollector(
        ledger,
        provenance_status="untrusted_provenance",
        correlation=correlation,
    )
    url = collector.bind()
    descriptor = create_descriptor(
        tmp_path / "run/descriptor.json",
        secret,
        run_id="run-1",
        key_id="key-1",
        collector_url=url,
        mission_root_digest="1" * 64,
        profile_digest="2" * 64,
        isolation_digest="3" * 64,
        gate_surface_digest="4" * 64,
        installed_artifact_digest="5" * 64,
        latch_path=tmp_path / "run/latch.json",
    )
    collector.start(secret=secret, descriptor=descriptor)

    intended_body = body("event-intended", "intended-worker")
    assert collector.process(
        sign_event_headers(
            intended_body,
            secret,
            descriptor,
            event_id="event-intended",
            nonce="nonce-intended",
        ),
        intended_body,
    ) == b"{}"

    for event_id, session_id in (
        ("event-internal", "shadow-probe"),
        ("event-decoy", "same-project-decoy"),
    ):
        rejected_body = body(event_id, session_id)
        assert collector.process(
            sign_event_headers(
                rejected_body,
                secret,
                descriptor,
                event_id=event_id,
                nonce=f"nonce-{event_id}",
            ),
            rejected_body,
        ) == b"{}"


    collector.stop()
    exchanges = collector.ledger.exchanges()
    assert len(exchanges) == 1
    assert exchanges[0].envelope.session_alias == intended


def test_unknown_session_refreshes_factory_correlation_before_rejection(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    intended = make_alias(secret, "session", "late-worker")
    correlation = MissionCorrelationRegistry()
    refresh_count = 0

    def refresh() -> None:
        nonlocal refresh_count
        refresh_count += 1
        correlation.allow(intended, "a" * 64)

    ledger = EventLedger(tmp_path / "run", run_id="run-1")
    collector = HookCollector(
        ledger,
        provenance_status="hook_authenticated",
        correlation=correlation,
        correlation_refresh=refresh,
    )
    url = collector.bind()
    descriptor = create_descriptor(
        tmp_path / "run/descriptor.json",
        secret,
        run_id="run-1",
        key_id="key-1",
        collector_url=url,
        mission_root_digest="1" * 64,
        profile_digest="2" * 64,
        isolation_digest="3" * 64,
        gate_surface_digest="4" * 64,
        installed_artifact_digest="5" * 64,
        latch_path=tmp_path / "run/latch.json",
    )
    collector.start(secret=secret, descriptor=descriptor)
    request_body = body("event-late", "late-worker")

    assert collector.process(
        sign_event_headers(
            request_body,
            secret,
            descriptor,
            event_id="event-late",
            nonce="nonce-late",
        ),
        request_body,
    ) == b"{}"
    assert refresh_count == 1
    assert ledger.exchanges()[0].envelope.session_alias == intended
    collector.stop()


def test_dynamic_correlation_requires_independent_digest() -> None:
    registry = MissionCorrelationRegistry()
    envelope = HookEnvelope(provenance_status="untrusted_provenance",
    redaction_status="clean",
    event_id="event-a",
    source_fingerprint="source-a",
    run_id="run-1",
    session_alias="session-a",
    transcript_alias="transcript-a",
    hook_event_name="SessionStart", observed_at=1, message_digest="d" * 64, payload={"prompt": "task"},)

    assert registry.accepts(envelope) is False
    with pytest.raises(ValueError, match="SHA-256"):
        registry.allow("session-a", "not-a-digest")
    registry.allow("session-a", "a" * 64)
    assert registry.accepts(envelope) is True
    registry.exclude("session-a")
    assert registry.accepts(envelope) is False
