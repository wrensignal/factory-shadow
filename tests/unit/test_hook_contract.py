from __future__ import annotations


import fcntl
import os
import threading
import time

import hooks.hook_runtime as hook_runtime
import pytest
from pydantic import ValidationError

from hooks.hook_runtime import HookStateError, _validated_hook_output
from shadow_mission.collector import GuidanceQueue
from shadow_mission.protocol import (
    HookEnvelope,
    HookExchangeRecord,
    HookResponseRecord,
    canonical_json,
    hook_response_digest,
    hook_envelope_digest,
)


def test_unexpected_post_tool_failure_does_not_break_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        hook_runtime,
        "_main",
        lambda: (_ for _ in ()).throw(RuntimeError("synthetic hook failure")),
    )
    monkeypatch.setattr(hook_runtime, "_ACTIVE_HOOK_EVENT_NAME", "PostToolUse")

    assert hook_runtime.main() == 0


def test_unexpected_completion_failure_blocks_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[str] = []
    monkeypatch.setattr(
        hook_runtime,
        "_main",
        lambda: (_ for _ in ()).throw(RuntimeError("synthetic hook failure")),
    )
    monkeypatch.setattr(hook_runtime, "_ACTIVE_HOOK_EVENT_NAME", "Stop")
    monkeypatch.setattr(hook_runtime, "_runtime_block", emitted.append)

    assert hook_runtime.main() == 0
    assert emitted == ["Unexpected hook runtime failure."]

def envelope(session: str, event_id: str = "event-a") -> HookEnvelope:
    return HookEnvelope(provenance_status="untrusted_provenance",
    redaction_status="clean",
    event_id=event_id,
    source_fingerprint=f"source-{session}",
    run_id="run-1",
    session_alias=session,
    transcript_alias=f"transcript-{session}",
    hook_event_name="PostToolUse", observed_at=1, message_digest="d" * 64, payload={"tool_name": "Read"},)


def response(event_id: str = "event-a", body: str = "{}") -> HookResponseRecord:
    return HookResponseRecord(
        provenance_status="untrusted_provenance",
        redaction_status="clean",
        response_id=f"response-{event_id}",
        run_id="run-1",
        event_id=event_id,
        request_digest="a" * 64,
        response_body=body,
        response_digest=hook_response_digest(
            response_body=body,
            guidance_ids=(),
            transition_ids=(),
            review_state=None,
        ),
        decided_at=2,
    )


def test_response_record_requires_canonical_body_and_matching_digest() -> None:
    assert response().response_body == "{}"
    with pytest.raises(ValidationError, match="canonical JSON"):
        response(body='{ "value": 1 }')
    with pytest.raises(ValidationError, match="response_digest"):
        HookResponseRecord(
            provenance_status="untrusted_provenance",
            redaction_status="clean",
            response_id="response-a",
            run_id="run-1",
            event_id="event-a",
            request_digest="a" * 64,
            response_body="{}",
            response_digest="b" * 64,
            decided_at=2,
        )
    with pytest.raises(ValidationError, match="response_digest"):
        HookResponseRecord.model_validate(
            response().model_dump(mode="json")
            | {"guidance_ids": ["forged-guidance"]}
        )


def test_exchange_rejects_cross_event_response_binding() -> None:
    event = envelope("session-a", "event-a")
    with pytest.raises(ValidationError, match="identities differ"):
        HookExchangeRecord(
            provenance_status="untrusted_provenance",
            redaction_status="clean",
            ledger_sequence=1,
            exchange_id="exchange-a",
            recorded_at=2,
            envelope=event,
            response=HookResponseRecord.model_validate(
                response("event-b").model_dump(mode="json")
                | {"request_digest": hook_envelope_digest(event)}
            ),
        )


def test_exchange_rejects_request_digest_not_bound_to_envelope() -> None:
    event = envelope("session-a")
    with pytest.raises(ValidationError, match="request digest differs"):
        HookExchangeRecord(
            provenance_status="untrusted_provenance",
            redaction_status="clean",
            ledger_sequence=1,
            exchange_id="exchange-a",
            recorded_at=2,
            envelope=event,
            response=response(),
        )


def test_guidance_for_target_cannot_be_consumed_by_sibling_shared_output() -> None:
    queue = GuidanceQueue()
    queue.queue(
        session_alias="session-target",
        guidance_id="guidance-a",
        hook_output={
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "Use cents.",
            }
        },
    )

    sibling_plan = queue.decision(envelope("session-sibling", "event-sibling"))
    target_plan = queue.decision(envelope("session-target", "event-target"))

    assert canonical_json(dict(sibling_plan.body)) == b"{}"
    assert sibling_plan.guidance_ids == ()
    assert target_plan.guidance_ids == ("guidance-a",)
    assert target_plan.body == {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "Use cents.",
        }
    }
    assert queue.item_count == 1
    assert target_plan.commit is not None
    target_plan.commit()
    assert queue.item_count == 0


def test_untrusted_hook_envelope_cannot_self_upgrade_provenance() -> None:
    value = envelope("session-a")
    supplied = value.model_dump(mode="json")
    supplied["payload"]["provenance_status"] = "hook_authenticated"

    reconstructed = HookEnvelope.model_validate(supplied)

    assert reconstructed.provenance_status == "untrusted_provenance"
    assert reconstructed.payload["provenance_status"] == "hook_authenticated"


def test_hook_runtime_accepts_only_model_visible_post_tool_output() -> None:
    post_tool_event = {"hook_event_name": "PostToolUse"}
    context = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "[shadow:route-a] Use cents.",
        }
    }
    ignored_post_tool_block = {
        "decision": "block",
        "reason": "[shadow:route-b] Pause and resolve the contract conflict.",
    }
    stop_event = {"hook_event_name": "Stop"}
    blocker = {
        "decision": "block",
        "reason": "[shadow:blocker-a] Confirmed risk remains unresolved.",
    }

    assert _validated_hook_output(post_tool_event, context) == context
    with pytest.raises(HookStateError, match="blocker output is invalid"):
        _validated_hook_output(post_tool_event, ignored_post_tool_block)
    assert _validated_hook_output(stop_event, blocker) == blocker


def test_hook_runtime_rejects_context_on_completion_events() -> None:
    output = {
        "hookSpecificOutput": {
            "hookEventName": "Stop",
            "additionalContext": "[shadow:route-a] This field is ignored on Stop.",
        }
    }

    with pytest.raises(HookStateError, match="context output is invalid"):
        _validated_hook_output({"hook_event_name": "Stop"}, output)


def test_hook_runtime_rejects_legacy_collector_response_wrapper() -> None:
    with pytest.raises(HookStateError, match="shape is not allowed"):
        _validated_hook_output(
            {"hook_event_name": "Stop"},
            {
                "hook_output": {
                    "decision": "block",
                    "reason": "[shadow:blocker-a] Confirmed risk remains unresolved.",
                }
            },
        )


def test_hook_latch_lock_contention_expires_with_typed_error(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    latch_path = tmp_path / "latch.json"
    lock_path = latch_path.with_name(f".{latch_path.name}.lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    monkeypatch.setattr(
        hook_runtime,
        "LATCH_LOCK_TIMEOUT_SECONDS",
        0.05,
    )
    release = threading.Timer(
        0.5,
        lambda: fcntl.flock(descriptor, fcntl.LOCK_UN),
    )
    release.start()
    started = time.monotonic()
    try:
        with pytest.raises(HookStateError, match="latch lock timed out") as captured:
            with hook_runtime._exclusive_latch_lock(latch_path):
                pytest.fail("contended latch lock was acquired")
        elapsed = time.monotonic() - started
    finally:
        release.cancel()
        release.join(timeout=1.0)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    assert isinstance(captured.value, HookStateError)
    assert 0.04 <= elapsed < 0.25
