import json
import pytest

from shadow_mission.auth import generate_run_secret
from shadow_mission.redaction import sanitize_hook_event, sanitize_value


def test_sanitizer_allowlists_fields_redacts_secrets_and_aliases_identifiers() -> None:
    secret = generate_run_secret()
    raw = {
        "hook_event_name": "PostToolUse",
        "session_id": "session-sensitive-alpha",
        "transcript_path": "/Users/scott/private/transcript.jsonl",
        "cwd": "/Users/scott/private/repository",
        "tool_name": "Read",
        "tool_input": {
            "path": "/Users/scott/private/file.py",
            "authorization": "Bearer bearer-secret-123",
            "api_key": "sk-shadow-feasibility-NEVER-PERSIST-7319",
        },
        "tool_response": "password=super-secret-value",
        "unknown_private_field": "must-not-survive",
    }

    first = sanitize_hook_event(
        raw,
        secret=secret,
        run_id="run-alpha",
        event_id="event-alpha",
        observed_at=1_700_000_000,
    )
    second = sanitize_hook_event(
        raw,
        secret=secret,
        run_id="run-alpha",
        event_id="event-beta",
        observed_at=1_700_000_001,
    )
    encoded = json.dumps(first, sort_keys=True)

    assert first["session_alias"] == second["session_alias"]
    assert first["transcript_alias"] == second["transcript_alias"]
    assert first["cwd_alias"] == second["cwd_alias"]
    assert first["redaction_status"] == "redacted"
    assert "unknown_private_field" not in encoded
    for forbidden in (
        "session-sensitive-alpha",
        "/Users/scott",
        "bearer-secret-123",
        "sk-shadow-feasibility",
        "super-secret-value",
        "must-not-survive",
    ):
        assert forbidden not in encoded


def test_sanitizer_redacts_routing_canaries_before_persistence() -> None:
    event = sanitize_hook_event(
        {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "session-a",
            "transcript_path": "/tmp/transcript-a",
            "cwd": "/tmp/repo",
            "prompt": "Acknowledge ROUTE-ALPHA-7319",
        },
        secret=generate_run_secret(),
        run_id="run-alpha",
        event_id="event-alpha",
        observed_at=1_700_000_000,
    )

    assert event["payload"]["prompt"] == "Acknowledge [REDACTED:canary]"


def test_sanitizer_redacts_exact_run_secret_and_private_canary() -> None:
    secret = generate_run_secret()
    source_canary = "shadow-source-canary-exact-private-value"

    event = sanitize_hook_event(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "session-a",
            "tool_response": {
                "first": secret,
                "second": source_canary,
            },
        },
        secret=secret,
        run_id="run-alpha",
        event_id="event-alpha",
        observed_at=1_700_000_000,
        forbidden_values=(source_canary,),
    )
    encoded = json.dumps(event, sort_keys=True)

    assert event["redaction_status"] == "redacted"
    assert secret not in encoded
    assert source_canary not in encoded


def test_value_sanitizer_redacts_exact_forbidden_values() -> None:
    secret = generate_run_secret()
    source_canary = "shadow-source-canary-model-bound"

    value, status = sanitize_value(
        {"response": [secret, source_canary]},
        forbidden_values=(secret, source_canary),
    )

    assert status == "redacted"
    assert secret not in json.dumps(value)
    assert source_canary not in json.dumps(value)


def test_sanitizer_bounds_nested_structures_and_rejects_unknown_events() -> None:
    nested: object = "leaf"
    for _ in range(40):
        nested = {"next": nested}

    event = sanitize_hook_event(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "session-a",
            "tool_response": nested,
        },
        secret=generate_run_secret(),
        run_id="run-alpha",
        event_id="event-alpha",
        observed_at=1_700_000_000,
    )

    assert "[REDACTED:structure-limit]" in json.dumps(event)
    with pytest.raises(ValueError, match="unsupported hook event"):
        sanitize_hook_event(
            {"hook_event_name": "InventedEvent"},
            secret=generate_run_secret(),
            run_id="run-alpha",
            event_id="event-beta",
            observed_at=1_700_000_000,
        )
