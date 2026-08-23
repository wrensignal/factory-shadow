"""Dependency-free Factory hook runtime.

This file must remain standard-library-only because Factory executes it from the
installed plugin cache before the project package is available.
"""

from __future__ import annotations
from contextlib import contextmanager

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

RUN_FILE_ENV = "SHADOW_MISSION_RUN_FILE"
RUN_DESCRIPTOR_ENV = "SHADOW_MISSION_RUN_DESCRIPTOR"
RUN_SECRET_ENV = "SHADOW_MISSION_RUN_SECRET"
SCHEMA_VERSION = "0.1"
COMPLETION_EVENTS = {"Stop", "SubagentStop"}
CONTEXT_EVENTS = {"PostToolUse", "UserPromptSubmit", "SessionStart"}
MAX_HOOK_INPUT_BYTES = 1 << 20
_ACTIVE_HOOK_EVENT_NAME = ""
LATCH_LOCK_TIMEOUT_SECONDS = 0.5
LATCH_LOCK_POLL_SECONDS = 0.01
PRODUCTION_LATCH_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "run_id",
        "generation",
        "state",
        "written_at",
        "signature",
    }
)
PRODUCTION_LATCH_HEAD_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "run_id",
        "generation",
        "state_digest",
        "updated_at",
        "signature",
    }
)
ROUTER_STATE_FIELDS = frozenset(
    {
        "schema_version",
        "provenance_status",
        "redaction_status",
        "record_type",
        "run_id",
        "generation",
        "interventions",
        "record_digest",
    }
)
INTERVENTION_FIELDS = frozenset(
    {
        "schema_version",
        "provenance_status",
        "redaction_status",
        "record_type",
        "intervention_id",
        "run_id",
        "finding_id",
        "finding_dedup_key",
        "target_session",
        "completion_session_alias",
        "rule",
        "level",
        "risk_category",
        "claim_ids",
        "direct_evidence_ids",
        "direct_evidence_digests",
        "correction_evidence_ids",
        "correction_evidence_digests",
        "generation",
        "state",
        "transition_history",
        "probe_id",
        "probe_digest",
        "probe_status",
        "probe_snapshot_digest",
        "blocking_scope",
        "original_feature",
        "repair_assignment",
        "repair_guidance_delivered_at",
        "probe_pending_at_completion",
        "attempts",
        "deadline",
        "terminal_outcome",
        "termination_acknowledgment_evidence_id",
        "termination_acknowledgment_evidence_digest",
        "record_digest",
    }
)
TRANSITION_FIELDS = frozenset(
    {"transition_id", "generation", "state", "action", "observed_at"}
)
REPAIR_ASSIGNMENT_FIELDS = frozenset(
    {
        "assignment_id",
        "intervention_id",
        "run_id",
        "original_feature",
        "worker_session",
        "worker_role_id",
        "assigned_at",
    }
)
INTERVENTION_STATES = frozenset(
    {
        "queued",
        "delivered",
        "acknowledged",
        "corrected",
        "resolved",
        "expired",
        "quarantined",
        "repair_requested",
        "repair_assigned",
        "termination_acknowledged",
    }
)
TERMINAL_FAILURE_STATES = frozenset({"expired", "quarantined"})
CRITICAL_RISKS = frozenset(
    {"money", "security", "data_loss", "public_contract", "explicit_acceptance"}
)


class HookStateError(ValueError):
    pass


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _decode_secret(encoded: str) -> bytes:
    try:
        padding = "=" * (-len(encoded) % 4)
        value = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise HookStateError("invalid run secret") from error
    if len(value) != 32:
        raise HookStateError("invalid run secret length")
    return value

def _verify_private_directory(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise HookStateError("private state parent is not a directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise HookStateError("private state parent mode is not 0700")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise HookStateError("private state parent owner mismatch")


def _verify_private_file(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise HookStateError("private state is not a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise HookStateError("private state mode is not 0600")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise HookStateError("private state owner mismatch")


def _signature(value: Mapping[str, Any], secret: str) -> str:
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    return hmac.new(
        _decode_secret(secret), _canonical_json(unsigned), hashlib.sha256
    ).hexdigest()


def _load_signed(path: Path, secret: str) -> dict[str, Any]:
    _verify_private_directory(path.parent)
    _verify_private_file(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("signature"), str):
        raise HookStateError("invalid signed state")
    if not hmac.compare_digest(value["signature"], _signature(value, secret)):
        raise HookStateError("signed state mismatch")
    return value

def _signed(value: Mapping[str, Any], secret: str) -> dict[str, Any]:
    result = dict(value)
    result["signature"] = _signature(result, secret)
    return result


def _atomic_private_write(path: Path, value: Mapping[str, Any]) -> None:
    _verify_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(_canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


@contextmanager
def _exclusive_latch_lock(latch_path: Path):
    lock_path = latch_path.with_name(f".{latch_path.name}.lock")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise HookStateError("latch lock is not private")
        deadline = time.monotonic() + LATCH_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HookStateError("latch lock timed out") from error
                time.sleep(min(LATCH_LOCK_POLL_SECONDS, remaining))
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)



def _validate_descriptor(
    descriptor: dict[str, Any],
    secret: str,
    descriptor_parent: Path,
) -> dict[str, Any]:
    if not isinstance(descriptor.get("signature"), str):
        raise HookStateError("invalid signed state")
    if not hmac.compare_digest(
        str(descriptor["signature"]),
        _signature(descriptor, secret),
    ):
        raise HookStateError("signed state mismatch")
    required = {
        "schema_version",
        "run_id",
        "key_id",
        "collector_url",
        "provenance_capability",
        "mission_root_digest",
        "profile_digest",
        "isolation_digest",
        "gate_surface_digest",
        "installed_artifact_digest",
        "latch_path",
        "latch_head_path",
        "created_at",
        "expires_at",
        "descriptor_nonce",
        "signature",
    }
    if set(descriptor) != required:
        raise HookStateError("descriptor fields differ from the contract")
    if descriptor.get("schema_version") != SCHEMA_VERSION:
        raise HookStateError("unsupported descriptor schema")
    if descriptor.get("provenance_capability") != "transport_integrity_only":
        raise HookStateError("descriptor overstates hook provenance")
    for field_name in (
        "mission_root_digest",
        "profile_digest",
        "isolation_digest",
        "gate_surface_digest",
        "installed_artifact_digest",
    ):
        digest = descriptor.get(field_name)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise HookStateError(f"descriptor {field_name} is not a digest")
    if not isinstance(descriptor.get("run_id"), str) or not descriptor["run_id"]:
        raise HookStateError("descriptor run ID is invalid")
    if not isinstance(descriptor.get("key_id"), str) or not descriptor["key_id"]:
        raise HookStateError("descriptor key ID is invalid")
    if int(descriptor.get("expires_at", 0)) < int(time.time()):
        raise HookStateError("descriptor expired")
    latch_path = Path(str(descriptor.get("latch_path", "")))
    latch_head_path = Path(str(descriptor.get("latch_head_path", "")))
    expected_head_path = latch_path.with_name(
        f"{latch_path.stem}-head{latch_path.suffix}"
    )
    if (
        not latch_path.is_absolute()
        or latch_path.parent != descriptor_parent
        or not latch_head_path.is_absolute()
        or latch_head_path.parent != descriptor_parent
        or latch_head_path != expected_head_path
    ):
        raise HookStateError("latch paths leave the private run directory")
    parsed = urlsplit(str(descriptor.get("collector_url", "")))
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.path != "/events"
        or parsed.port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise HookStateError("collector is not loopback")
    return descriptor


def _load_descriptor(path: Path, secret: str) -> dict[str, Any]:
    descriptor = _load_signed(path, secret)
    return _validate_descriptor(descriptor, secret, path.parent.resolve())


def _load_descriptor_payload(
    payload: str,
    secret: str,
    descriptor_path: Path,
) -> dict[str, Any]:
    if len(payload.encode("utf-8")) > 16_384 or not descriptor_path.is_absolute():
        raise HookStateError("run descriptor environment is invalid")
    descriptor = json.loads(payload)
    if not isinstance(descriptor, dict):
        raise HookStateError("run descriptor environment is invalid")
    validated_payload = _validate_descriptor(
        descriptor,
        secret,
        descriptor_path.parent.resolve(),
    )
    disk_descriptor = _load_descriptor(descriptor_path, secret)
    if not hmac.compare_digest(
        _canonical_json(validated_payload),
        _canonical_json(disk_descriptor),
    ):
        raise HookStateError("run descriptor environment differs from disk")
    return disk_descriptor


def _make_alias(secret: str, kind: str, raw_value: str) -> str:
    if not raw_value:
        return f"{kind}-missing"
    digest = hmac.new(
        _decode_secret(secret),
        f"alias\n{kind}\n{raw_value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:20]
    return f"{kind}-{digest}"


def _event_headers(
    body: bytes, secret: str, descriptor: Mapping[str, Any], event_id: str
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    body_digest = hashlib.sha256(body).hexdigest()
    message = "\n".join(
        (
            SCHEMA_VERSION,
            str(descriptor["run_id"]),
            event_id,
            timestamp,
            nonce,
            body_digest,
        )
    ).encode("utf-8")
    signature = hmac.new(_decode_secret(secret), message, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Shadow-Key-Id": str(descriptor["key_id"]),
        "X-Shadow-Timestamp": timestamp,
        "X-Shadow-Nonce": nonce,
        "X-Shadow-Signature": signature,
    }


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")))
    sys.stdout.write("\n")


def _runtime_block(reason: str) -> None:
    _emit(
        {
            "decision": "block",
            "reason": f"[shadow:runtime-unavailable] {reason}",
        }
    )


def _validated_hook_output(
    raw_event: Mapping[str, Any], value: Any
) -> Mapping[str, Any] | None:
    if value in (None, {}):
        return None
    if not isinstance(value, dict):
        raise HookStateError("collector hook output is not an object")
    if set(value) == {"hookSpecificOutput"}:
        specific = value["hookSpecificOutput"]
        if not isinstance(specific, dict) or set(specific) != {
            "hookEventName",
            "additionalContext",
        }:
            raise HookStateError("collector context output fields differ")
        context = specific["additionalContext"]
        event_name = raw_event.get("hook_event_name")
        if (
            event_name not in CONTEXT_EVENTS
            or specific["hookEventName"] != event_name
            or not isinstance(context, str)
            or not context.startswith("[shadow:")
            or len(context.encode("utf-8")) > 8_192
        ):
            raise HookStateError("collector context output is invalid")
        return value
    if set(value) == {"decision", "reason"}:
        reason = value["reason"]
        if (
            raw_event.get("hook_event_name") not in COMPLETION_EVENTS
            or value["decision"] != "block"
            or not isinstance(reason, str)
            or not reason.startswith("[shadow:")
            or len(reason.encode("utf-8")) > 8_192
        ):
            raise HookStateError("collector blocker output is invalid")
        return value
    raise HookStateError("collector hook output shape is not allowed")


def _is_json_int(value: Any, *, minimum: int | None = 0) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (minimum is None or value >= minimum)
    )


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _is_safe_alias(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", value) is not None
    )


def _validate_canonical_strings(
    value: Any,
    *,
    require_nonempty: bool,
    digests: bool = False,
) -> list[str]:
    if (
        not isinstance(value, list)
        or (require_nonempty and not value)
        or not all(
            _is_digest(item) if digests else _is_nonempty_string(item)
            for item in value
        )
        or value != sorted(set(value))
    ):
        raise HookStateError("router string lineage is invalid")
    return value


def _validate_record_digest(value: Mapping[str, Any]) -> None:
    supplied = value.get("record_digest")
    unsigned = {key: item for key, item in value.items() if key != "record_digest"}
    expected = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
        raise HookStateError("router record digest mismatch")


def _validate_transition_history(
    value: Any,
    *,
    intervention_generation: int,
    intervention_state: str,
) -> set[int]:
    if not isinstance(value, list) or not value:
        raise HookStateError("intervention transition history is invalid")
    generations: list[int] = []
    transition_ids: list[str] = []
    for transition in value:
        if not isinstance(transition, dict) or set(transition) != TRANSITION_FIELDS:
            raise HookStateError("intervention transition fields differ")
        generation = transition.get("generation")
        state = transition.get("state")
        if (
            not _is_nonempty_string(transition.get("transition_id"))
            or not _is_json_int(generation, minimum=1)
            or state not in INTERVENTION_STATES
            or not _is_nonempty_string(transition.get("action"))
            or not _is_json_int(transition.get("observed_at"), minimum=None)
        ):
            raise HookStateError("intervention transition is invalid")
        generations.append(generation)
        transition_ids.append(transition["transition_id"])
    if (
        generations != sorted(set(generations))
        or len(transition_ids) != len(set(transition_ids))
        or generations[-1] != intervention_generation
        or value[-1]["state"] != intervention_state
    ):
        raise HookStateError("intervention transition history is ambiguous")
    return set(generations)


def _validate_repair_assignment(
    value: Any,
    *,
    intervention_id: str,
    run_id: str,
    original_feature: Any,
) -> None:
    if not isinstance(value, dict) or set(value) != REPAIR_ASSIGNMENT_FIELDS:
        raise HookStateError("repair assignment fields differ")
    for field_name in (
        "assignment_id",
        "intervention_id",
        "run_id",
        "original_feature",
        "worker_session",
        "worker_role_id",
    ):
        if not _is_nonempty_string(value.get(field_name)):
            raise HookStateError("repair assignment identity is invalid")
    if (
        value["intervention_id"] != intervention_id
        or value["run_id"] != run_id
        or value["original_feature"] != original_feature
        or not _is_safe_alias(value.get("original_feature"))
        or not _is_safe_alias(value.get("worker_session"))
        or not _is_json_int(value.get("assigned_at"), minimum=None)
    ):
        raise HookStateError("repair assignment binding is invalid")


def _validate_intervention(
    value: Any,
    *,
    run_id: str,
    router_generation: int,
) -> tuple[str, set[int]]:
    if not isinstance(value, dict) or set(value) != INTERVENTION_FIELDS:
        raise HookStateError("intervention fields differ")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("provenance_status") != "hook_authenticated"
        or value.get("redaction_status") != "clean"
        or value.get("record_type") != "intervention_record"
        or value.get("run_id") != run_id
    ):
        raise HookStateError("intervention record binding is invalid")
    intervention_id = value.get("intervention_id")
    generation = value.get("generation")
    state = value.get("state")
    level = value.get("level")
    if (
        not _is_nonempty_string(intervention_id)
        or not _is_nonempty_string(value.get("finding_id"))
        or not _is_digest(value.get("finding_dedup_key"))
        or not _is_nonempty_string(value.get("target_session"))
        or not _is_nonempty_string(value.get("rule"))
        or level not in {"concern", "blocker"}
        or not _is_nonempty_string(value.get("risk_category"))
        or not _is_json_int(generation, minimum=1)
        or generation > router_generation
        or state not in INTERVENTION_STATES
        or value.get("blocking_scope") not in {"worker", "mission"}
    ):
        raise HookStateError("intervention identity or state is invalid")
    _validate_canonical_strings(
        value.get("claim_ids"), require_nonempty=False
    )
    _validate_canonical_strings(
        value.get("direct_evidence_ids"), require_nonempty=True
    )
    _validate_canonical_strings(
        value.get("direct_evidence_digests"),
        require_nonempty=True,
        digests=True,
    )
    correction_ids = _validate_canonical_strings(
        value.get("correction_evidence_ids"), require_nonempty=False
    )
    correction_digests = _validate_canonical_strings(
        value.get("correction_evidence_digests"),
        require_nonempty=False,
        digests=True,
    )
    if state in {"corrected", "resolved"} and (
        not correction_ids or not correction_digests
    ):
        raise HookStateError("intervention evidence lineage is invalid")
    probe_id = value.get("probe_id")
    probe_digest = value.get("probe_digest")
    probe_snapshot_digest = value.get("probe_snapshot_digest")
    if probe_id is None:
        if probe_digest is not None or probe_snapshot_digest is not None:
            raise HookStateError("intervention probe binding is incomplete")
    elif (
        not _is_nonempty_string(probe_id)
        or not _is_digest(probe_digest)
        or not _is_digest(probe_snapshot_digest)
    ):
        raise HookStateError("intervention probe binding is invalid")
    if level == "blocker" and (
        value.get("risk_category") not in CRITICAL_RISKS
        or value.get("probe_status") != "confirmed"
        or probe_id is None
    ):
        raise HookStateError("blocker lacks a confirmed critical probe")
    if not _is_nonempty_string(value.get("probe_status")):
        raise HookStateError("intervention probe status is invalid")
    original_feature = value.get("original_feature")
    if original_feature is not None and not _is_safe_alias(original_feature):
        raise HookStateError("intervention original feature is invalid")
    completion_session_alias = value.get("completion_session_alias")
    if not _is_safe_alias(completion_session_alias):
        raise HookStateError("intervention completion session alias is invalid")
    repair_assignment = value.get("repair_assignment")
    if repair_assignment is not None:
        _validate_repair_assignment(
            repair_assignment,
            intervention_id=intervention_id,
            run_id=run_id,
            original_feature=original_feature,
        )
    if (
        (state == "repair_assigned" and repair_assignment is None)
        or (
            value.get("repair_guidance_delivered_at") is not None
            and (
                repair_assignment is None
                or not _is_json_int(
                    value.get("repair_guidance_delivered_at"), minimum=None
                )
            )
        )
        or (
            value.get("probe_pending_at_completion") is not None
            and not _is_json_int(
                value.get("probe_pending_at_completion"), minimum=None
            )
        )
    ):
        raise HookStateError("intervention repair or probe timing is invalid")
    attempts = value.get("attempts")
    deadline = value.get("deadline")
    if (
        not _is_json_int(attempts)
        or attempts > 2
        or (attempts == 0 and deadline is not None)
        or (attempts > 0 and not _is_json_int(deadline, minimum=None))
    ):
        raise HookStateError("intervention attempt deadline is invalid")
    terminal_outcome = value.get("terminal_outcome")
    if terminal_outcome is not None and not _is_nonempty_string(terminal_outcome):
        raise HookStateError("intervention terminal outcome is invalid")
    acknowledgment_id = value.get("termination_acknowledgment_evidence_id")
    acknowledgment_digest = value.get(
        "termination_acknowledgment_evidence_digest"
    )
    acknowledgment_present = acknowledgment_id is not None
    if acknowledgment_present != (acknowledgment_digest is not None) or (
        acknowledgment_present
        and (
            not _is_nonempty_string(acknowledgment_id)
            or not _is_digest(acknowledgment_digest)
        )
    ):
        raise HookStateError("termination acknowledgment binding is invalid")
    if state == "termination_acknowledged" and not acknowledgment_present:
        raise HookStateError("termination acknowledgment state is invalid")
    transition_generations = _validate_transition_history(
        value.get("transition_history"),
        intervention_generation=generation,
        intervention_state=state,
    )
    _validate_record_digest(value)
    return intervention_id, transition_generations


def _validate_router_latch(
    latch: Mapping[str, Any],
    head: Mapping[str, Any],
    descriptor: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if (
        set(latch) != PRODUCTION_LATCH_FIELDS
        or latch.get("schema_version") != SCHEMA_VERSION
        or latch.get("record_type") != "intervention_latch"
        or latch.get("run_id") != descriptor.get("run_id")
        or not _is_json_int(latch.get("generation"))
        or not _is_json_int(latch.get("written_at"), minimum=None)
    ):
        raise HookStateError("production latch fields or binding are invalid")
    state = latch.get("state")
    if (
        not isinstance(state, dict)
        or set(state) != ROUTER_STATE_FIELDS
        or state.get("schema_version") != SCHEMA_VERSION
        or state.get("provenance_status") != "hook_authenticated"
        or state.get("redaction_status") != "clean"
        or state.get("record_type") != "intervention_router_state"
        or state.get("run_id") != descriptor.get("run_id")
        or state.get("generation") != latch.get("generation")
    ):
        raise HookStateError("router state fields or binding are invalid")
    state_digest = hashlib.sha256(_canonical_json(state)).hexdigest()
    if (
        set(head) != PRODUCTION_LATCH_HEAD_FIELDS
        or head.get("schema_version") != SCHEMA_VERSION
        or head.get("record_type") != "intervention_latch_head"
        or head.get("run_id") != descriptor.get("run_id")
        or not _is_json_int(head.get("generation"))
        or not _is_json_int(head.get("updated_at"), minimum=None)
        or not _is_digest(head.get("state_digest"))
        or head.get("generation") != latch.get("generation")
        or head.get("updated_at") != latch.get("written_at")
        or not hmac.compare_digest(str(head["state_digest"]), state_digest)
    ):
        raise HookStateError("production latch head does not match current state")
    interventions = state.get("interventions")
    if not isinstance(interventions, list):
        raise HookStateError("router interventions are invalid")
    identities: list[str] = []
    all_transition_generations: set[int] = set()
    for intervention in interventions:
        intervention_id, transition_generations = _validate_intervention(
            intervention,
            run_id=state["run_id"],
            router_generation=state["generation"],
        )
        if all_transition_generations.intersection(transition_generations):
            raise HookStateError("router transition generations are ambiguous")
        identities.append(intervention_id)
        all_transition_generations.update(transition_generations)
    if identities != sorted(set(identities)):
        raise HookStateError("router intervention identities are ambiguous")
    if (
        (not interventions and state["generation"] != 0)
        or (
            interventions
            and (
                not all_transition_generations
                or max(all_transition_generations) != state["generation"]
            )
        )
    ):
        raise HookStateError("router generation is rollback-ambiguous")
    _validate_record_digest(state)
    return interventions


def _with_record_digest(value: Mapping[str, Any]) -> dict[str, Any]:
    unsigned = {key: item for key, item in value.items() if key != "record_digest"}
    unsigned["record_digest"] = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    return unsigned


def _outage_transition(
    intervention: Mapping[str, Any],
    *,
    generation: int,
    state: str,
    action: str,
    observed_at: int,
    **changes: Any,
) -> dict[str, Any]:
    value = dict(intervention)
    value.update(changes)
    value.update({"generation": generation, "state": state})
    history = list(value["transition_history"])
    identity_digest = hashlib.sha256(
        str(value["intervention_id"]).encode("utf-8")
    ).hexdigest()[:16]
    history.append(
        {
            "transition_id": f"outage-{generation}-{identity_digest}",
            "generation": generation,
            "state": state,
            "action": action,
            "observed_at": observed_at,
        }
    )
    value["transition_history"] = history
    return _with_record_digest(value)


def _advance_outage_state(
    latch: Mapping[str, Any],
    selected: Mapping[str, Any],
    *,
    now: int,
    secret: str,
    descriptor: Mapping[str, Any],
    latch_path: Path,
    head_path: Path,
) -> tuple[dict[str, Any], bool]:
    terminal = selected["state"] in TERMINAL_FAILURE_STATES
    if terminal:
        return dict(selected), True
    generation = int(latch["generation"])
    current = dict(selected)
    if (
        current["deadline"] is not None
        and now >= int(current["deadline"])
    ) or int(current["attempts"]) >= 2:
        generation += 1
        current = _outage_transition(
            current,
            generation=generation,
            state="quarantined" if current["state"] == "corrected" else "expired",
            action="termination_required",
            observed_at=now,
            terminal_outcome="mission_termination_required",
        )
        terminal = True
    else:
        deadline = (
            current["deadline"] if current["deadline"] is not None else now + 600
        )
        generation += 1
        current = _outage_transition(
            current,
            generation=generation,
            state=(
                "delivered"
                if current["state"] == "queued"
                else str(current["state"])
            ),
            action="blocked_attempt",
            observed_at=now,
            attempts=int(current["attempts"]) + 1,
            deadline=deadline,
        )
    state = dict(latch["state"])
    state["generation"] = generation
    state["interventions"] = [
        current if item["intervention_id"] == current["intervention_id"] else item
        for item in state["interventions"]
    ]
    state = _with_record_digest(state)
    next_latch = _signed(
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": "intervention_latch",
            "run_id": descriptor["run_id"],
            "generation": generation,
            "state": state,
            "written_at": now,
        },
        secret,
    )
    next_head = _signed(
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": "intervention_latch_head",
            "run_id": descriptor["run_id"],
            "generation": generation,
            "state_digest": hashlib.sha256(_canonical_json(state)).hexdigest(),
            "updated_at": now,
        },
        secret,
    )
    _validate_router_latch(next_latch, next_head, descriptor)
    _atomic_private_write(latch_path, next_latch)
    _atomic_private_write(head_path, next_head)
    return current, terminal


def _fallback_to_production_latch(
    raw_event: Mapping[str, Any],
    latch_path: Path,
    head_path: Path,
    secret: str,
    descriptor: Mapping[str, Any],
) -> None:
    with _exclusive_latch_lock(latch_path):
        latch = _load_signed(latch_path, secret)
        head = _load_signed(head_path, secret)
        interventions = _validate_router_latch(latch, head, descriptor)
        event_name = str(raw_event.get("hook_event_name", ""))
        session_id = raw_event.get("session_id")
        if not _is_nonempty_string(session_id):
            _runtime_block(
                "Collector unavailable; completion state cannot be verified."
            )
            return
        target_alias = _make_alias(secret, "session", session_id)
        candidates = []
        for intervention in interventions:
            if (
                intervention["level"] != "blocker"
                or intervention["state"] in {"resolved", "termination_acknowledged"}
                or intervention["completion_session_alias"] != target_alias
            ):
                continue
            if intervention["blocking_scope"] == "worker":
                selected = (
                    event_name == "SubagentStop"
                    and intervention["target_session"] == target_alias
                )
            else:
                selected = event_name == "Stop"
            if selected:
                candidates.append(intervention)
        if not candidates:
            _runtime_block(
                "Collector unavailable; completion state cannot be verified."
            )
            return
        now = int(time.time())
        selected = min(
            candidates,
            key=lambda item: (
                0
                if item["state"] in TERMINAL_FAILURE_STATES
                or (item["deadline"] is not None and now >= item["deadline"])
                or item["attempts"] >= 2
                else 1,
                item["intervention_id"],
            ),
        )
        selected, terminal = _advance_outage_state(
            latch,
            selected,
            now=now,
            secret=secret,
            descriptor=descriptor,
            latch_path=latch_path,
            head_path=head_path,
        )
    intervention_id = selected["intervention_id"]
    if terminal:
        _runtime_block(
            f"[shadow:{intervention_id}] [shadow:collector-outage-fallback] "
            "mandatory Mission termination and failure."
        )
    else:
        _runtime_block(
            f"[shadow:{intervention_id}] [shadow:collector-outage-fallback] "
            "Confirmed risk remains unresolved."
        )


def _fallback_to_feasibility_latch(
    raw_event: Mapping[str, Any],
    latch: Mapping[str, Any],
    secret: str,
    descriptor: Mapping[str, Any],
) -> None:
    required = {
        "schema_version",
        "run_id",
        "key_id",
        "scope",
        "target_alias",
        "blocker_id",
        "state",
        "generation",
        "direct_evidence_ids",
        "probe_result_id",
        "correction_evidence_ids",
        "provenance_status",
        "observation_registry_digest",
        "created_at",
        "expires_at",
        "signature",
    }
    if set(latch) != required or latch.get("schema_version") != SCHEMA_VERSION:
        raise HookStateError("latch fields differ from the contract")
    if latch.get("provenance_status") not in {
        "hook_authenticated",
        "untrusted_provenance",
    }:
        raise HookStateError("latch provenance status is invalid")
    direct_ids = latch.get("direct_evidence_ids")
    correction_ids = latch.get("correction_evidence_ids")
    if (
        not isinstance(direct_ids, list)
        or not direct_ids
        or not all(isinstance(value, str) and value for value in direct_ids)
        or not isinstance(latch.get("probe_result_id"), str)
        or not latch["probe_result_id"]
        or not isinstance(correction_ids, list)
        or not all(isinstance(value, str) and value for value in correction_ids)
        or (latch.get("state") == "active" and correction_ids)
        or (latch.get("state") == "resolved" and not correction_ids)
    ):
        raise HookStateError("latch evidence lineage is invalid")
    if not _is_digest(latch.get("observation_registry_digest")):
        raise HookStateError("latch observation registry digest is invalid")
    if latch.get("run_id") != descriptor.get("run_id"):
        raise HookStateError("latch run mismatch")
    if latch.get("key_id") != descriptor.get("key_id"):
        raise HookStateError("latch key mismatch")
    if (
        not _is_json_int(latch.get("generation"))
        or not isinstance(latch.get("expires_at"), int)
        or isinstance(latch.get("expires_at"), bool)
        or int(latch["expires_at"]) < int(time.time())
    ):
        raise HookStateError("latch generation or expiry is invalid")
    event_name = str(raw_event.get("hook_event_name", ""))
    session_id = raw_event.get("session_id")
    if not _is_nonempty_string(session_id):
        _runtime_block(
            "Collector unavailable; completion state cannot be verified."
        )
        return
    target_alias = _make_alias(secret, "session", session_id)
    state = latch.get("state")
    if state not in {"active", "resolved"}:
        raise HookStateError("latch state is invalid")
    scope = latch.get("scope")
    if not _is_safe_alias(latch.get("target_alias")):
        raise HookStateError("latch target alias is invalid")
    if scope == "worker":
        target_matches = (
            event_name == "SubagentStop"
            and latch.get("target_alias") == target_alias
        )
    elif scope == "mission":
        target_matches = (
            event_name == "Stop"
            and latch.get("target_alias") == target_alias
        )
    else:
        raise HookStateError("latch scope is invalid")
    if state == "active" and target_matches:
        blocker_id = str(latch.get("blocker_id", "unknown"))
        _runtime_block(
            f"[shadow:{blocker_id}] [shadow:collector-outage-fallback] "
            "Confirmed risk remains unresolved."
        )
        return
    _runtime_block("Collector unavailable; completion state cannot be verified.")


def _fallback_to_latch(
    raw_event: Mapping[str, Any], secret: str, descriptor: Mapping[str, Any]
) -> None:
    if raw_event.get("hook_event_name") not in COMPLETION_EVENTS:
        return
    latch_path = Path(str(descriptor.get("latch_path", "")))
    latch = _load_signed(latch_path, secret)
    if latch.get("record_type") == "intervention_latch":
        head_path = Path(str(descriptor.get("latch_head_path", "")))
        _fallback_to_production_latch(
            raw_event, latch_path, head_path, secret, descriptor
        )
    else:
        _fallback_to_feasibility_latch(raw_event, latch, secret, descriptor)


def _validate_structure(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    count = 0
    while stack:
        current, depth = stack.pop()
        count += 1
        if count > 100_000 or depth > 64:
            raise HookStateError("hook input structure exceeds limits")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _read_input() -> dict[str, Any]:
    payload = sys.stdin.buffer.read(MAX_HOOK_INPUT_BYTES + 1)
    if len(payload) > MAX_HOOK_INPUT_BYTES:
        raise HookStateError("hook input exceeds 1 MiB")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise HookStateError("hook input must be an object")
    _validate_structure(value)
    return value


def _handle_collector_outage(
    raw_event: Mapping[str, Any],
    secret: str,
    descriptor: Mapping[str, Any],
    *,
    completion: bool,
) -> None:
    if not completion:
        return
    try:
        _fallback_to_latch(raw_event, secret, descriptor)
    except (OSError, ValueError, TypeError, json.JSONDecodeError, HookStateError):
        _runtime_block("Collector and signed latch are unavailable.")


def _main() -> int:
    descriptor_name = os.environ.get(RUN_FILE_ENV)
    descriptor_payload = os.environ.get(RUN_DESCRIPTOR_ENV)
    if not descriptor_name or os.environ.get("SHADOW_MISSION_INTERNAL") == "1":
        return 0

    try:
        raw_event = _read_input()
    except (HookStateError, json.JSONDecodeError, UnicodeError, RecursionError):
        _runtime_block("Hook input validation failed.")
        return 0
    hook_event_name = str(raw_event.get("hook_event_name", ""))
    global _ACTIVE_HOOK_EVENT_NAME
    _ACTIVE_HOOK_EVENT_NAME = hook_event_name
    completion = hook_event_name in COMPLETION_EVENTS
    secret = os.environ.get(RUN_SECRET_ENV)
    if not secret:
        if completion:
            _runtime_block("Run authentication is unavailable.")
        return 0

    try:
        if descriptor_payload:
            descriptor = _load_descriptor_payload(
                descriptor_payload,
                secret,
                Path(descriptor_name),
            )
        else:
            descriptor = _load_descriptor(Path(descriptor_name), secret)
    except (OSError, ValueError, TypeError, json.JSONDecodeError, HookStateError):
        if completion:
            _runtime_block("Run descriptor validation failed.")
        return 0

    try:
        event_id = uuid.uuid4().hex
        request_value = {
            "schema_version": SCHEMA_VERSION,
            "run_id": descriptor["run_id"],
            "event_id": event_id,
            "observed_at": int(time.time()),
            "hook": raw_event,
        }
        body = _canonical_json(request_value)
        request = Request(
            str(descriptor["collector_url"]),
            data=body,
            headers=_event_headers(body, secret, descriptor, event_id),
            method="POST",
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        if completion:
            _runtime_block("Hook input validation failed.")
        return 0
    try:
        with urlopen(request, timeout=1.25) as response:
            if response.status != 200:
                raise HookStateError("collector rejected the event")
            response_body = response.read(65_537)
            if len(response_body) > 65_536:
                raise HookStateError("collector response exceeds 64 KiB")
            result = json.loads(response_body or b"{}")
            hook_output = _validated_hook_output(raw_event, result)
            if hook_output is not None:
                _emit(hook_output)
            return 0
    except HTTPError as error:
        if error.code in {401, 403}:
            if completion:
                _runtime_block("Collector authentication failed.")
        elif 500 <= error.code <= 599:
            _handle_collector_outage(
                raw_event, secret, descriptor, completion=completion
            )
        elif completion:
            _runtime_block("Collector rejected the event.")
        return 0
    except (
        URLError,
        TimeoutError,
        OSError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
        HookStateError,
    ):
        _handle_collector_outage(
            raw_event, secret, descriptor, completion=completion
        )
        return 0


def main() -> int:
    global _ACTIVE_HOOK_EVENT_NAME
    try:
        return _main()
    except BaseException:
        if _ACTIVE_HOOK_EVENT_NAME in COMPLETION_EVENTS:
            try:
                _runtime_block("Unexpected hook runtime failure.")
            except BaseException:
                pass
        return 0
    finally:
        _ACTIVE_HOOK_EVENT_NAME = ""
