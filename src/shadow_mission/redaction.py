"""Allowlist and redact hook data before persistence or model use."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .auth import SCHEMA_VERSION, make_alias

_ALLOWED_PAYLOAD_FIELDS = {
    "prompt",
    "tool_name",
    "tool_input",
    "tool_response",
    "stop_hook_active",
}
_ALLOWED_HOOK_EVENTS = {
    "SessionStart",
    "UserPromptSubmit",
    "PostToolUse",
    "Stop",
    "SubagentStop",
    "SessionEnd",
}
_MAX_CONTAINER_ITEMS = 10_000
_MAX_NESTING_DEPTH = 32
_SENSITIVE_KEYS = re.compile(
    r"(?i)(authorization|api[_-]?key|token|secret|password|credential|private[_-]?key)"
)
_PATTERNS = (
    (
        re.compile(
            r"\b(?:ROUTE|SHADOW-FEASIBILITY|ACK|CORRECTION)-[A-Z0-9-]+\b"
        ),
        "[REDACTED:canary]",
    ),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), "[REDACTED:token]"),
    (
        re.compile(
            r"(?i)\b([A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL))"
            r"\s*=\s*[^\s,;]+"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[^\s,;]+"),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(session[_-]?id|transcript[_-]?path)\s*[:=]\s*[^\s,;]+"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED:private-key]",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_.-])/(?:Users|home)/[^\s'\"<>]+"),
        "$HOME/[REDACTED:private-path]",
    ),
)
_SHADOW_MARKER = re.compile(r"\[shadow:[A-Za-z0-9._:-]{1,160}\]")
_DENIED_PATH_PARTS = {".git", ".shadow-mission", "credential", "credentials"}


def _redact_text(
    value: str,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> tuple[str, bool]:
    result = value
    changed = False
    for forbidden in forbidden_values:
        replaced = result.replace(forbidden, "[REDACTED:forbidden]")
        changed = changed or replaced != result
        result = replaced
    for pattern, replacement in _PATTERNS:
        result, count = pattern.subn(replacement, result)
        changed = changed or count > 0
    return result, changed


def _redact_value(
    value: Any,
    *,
    depth: int = 0,
    remaining: list[int] | None = None,
    forbidden_values: tuple[str, ...] = (),
) -> tuple[Any, bool]:
    if remaining is None:
        remaining = [_MAX_CONTAINER_ITEMS]
    if remaining[0] <= 0 or depth >= _MAX_NESTING_DEPTH:
        return "[REDACTED:structure-limit]", True
    remaining[0] -= 1
    if isinstance(value, str):
        return _redact_text(value, forbidden_values=forbidden_values)
    if isinstance(value, list):
        output: list[Any] = []
        changed = False
        for item in value:
            redacted, item_changed = _redact_value(
                item,
                depth=depth + 1,
                remaining=remaining,
                forbidden_values=forbidden_values,
            )
            output.append(redacted)
            changed = changed or item_changed
        return output, changed
    if isinstance(value, dict):
        output_dict: dict[str, Any] = {}
        changed = False
        for key, item in value.items():
            normalized_key = str(key)
            if _SENSITIVE_KEYS.search(normalized_key):
                output_dict[normalized_key] = "[REDACTED]"
                changed = True
                continue
            redacted, item_changed = _redact_value(
                item,
                depth=depth + 1,
                remaining=remaining,
                forbidden_values=forbidden_values,
            )
            output_dict[normalized_key] = redacted
            changed = changed or item_changed
        return output_dict, changed
    if value is None or isinstance(value, (bool, int)):
        return value, False
    if isinstance(value, float) and math.isfinite(value):
        return value, False
    return "[REDACTED:unsupported-value]", True

def sanitize_value(
    value: Any,
    *,
    forbidden_values: Iterable[str] = (),
) -> tuple[Any, str]:
    """Redact one JSON-compatible value before disk or model use."""
    exact_forbidden_values = tuple(
        sorted(
            {
                item
                for item in forbidden_values
                if isinstance(item, str) and item
            },
            key=len,
            reverse=True,
        )
    )
    redacted, changed = _redact_value(
        value,
        forbidden_values=exact_forbidden_values,
    )
    return redacted, "redacted" if changed else "clean"


def strip_shadow_markers(value: str) -> str:
    """Remove intervention markers before later model input."""
    return " ".join(_SHADOW_MARKER.sub("", value).split())


def resolve_repository_path(repository: Path, relative_path: str) -> Path:
    """Resolve one allowed repository-relative path without escaping private state."""
    candidate = Path(relative_path)
    if candidate.is_absolute() or not relative_path:
        raise ValueError("repository path must be non-empty and relative")
    if any(
        part in _DENIED_PATH_PARTS
        or part.startswith(".env")
        or "credential" in part.lower()
        for part in candidate.parts
    ):
        raise ValueError("repository path enters protected state")
    root = repository.resolve(strict=True)
    resolved = (root / candidate).resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise ValueError("repository path escapes the target repository")
    return resolved


def sanitize_hook_event(
    raw: Mapping[str, Any],
    *,
    secret: str,
    run_id: str,
    event_id: str,
    observed_at: int,
    provenance_status: str = "untrusted_provenance",
    forbidden_values: Iterable[str] = (),
) -> dict[str, Any]:
    """Return the only hook representation permitted on disk."""
    if provenance_status not in {"hook_authenticated", "untrusted_provenance"}:
        raise ValueError("invalid hook provenance status")
    hook_event_name = str(raw.get("hook_event_name", ""))
    if hook_event_name not in _ALLOWED_HOOK_EVENTS:
        raise ValueError("unsupported hook event name")

    session_id = str(raw.get("session_id", ""))
    transcript_path = str(raw.get("transcript_path", ""))
    cwd = str(raw.get("cwd", ""))
    payload: dict[str, Any] = {}
    exact_forbidden_values = tuple(
        sorted(
            {
                secret,
                *(
                    item
                    for item in forbidden_values
                    if isinstance(item, str) and item
                ),
            },
            key=len,
            reverse=True,
        )
    )
    changed = False
    for field in sorted(_ALLOWED_PAYLOAD_FIELDS):
        if field not in raw:
            continue
        redacted, field_changed = _redact_value(
            raw[field],
            forbidden_values=exact_forbidden_values,
        )
        changed = changed or field_changed
        payload[field] = redacted

    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "source_fingerprint": make_alias(
            secret, "source", f"{session_id}\n{transcript_path}"
        ),
        "run_id": run_id,
        "session_alias": make_alias(secret, "session", session_id),
        "transcript_alias": make_alias(secret, "transcript", transcript_path),
        "cwd_alias": make_alias(secret, "cwd", cwd),
        "hook_event_name": hook_event_name,
        "observed_at": int(observed_at),
        "provenance_status": provenance_status,
        "payload": payload,
        "redaction_status": "redacted" if changed else "clean",
    }
