"""Fail-closed guest boundary for one host-controlled Phase 1 Mission."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import math
import os
import re
import queue
import select
import stat
import signal
import subprocess
import threading
import time
import tempfile
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .feasibility import CAPABILITY_NAMES, classify_gate
from .auth import make_alias
from .isolation import IsolationError, validate_isolation_manifest
from .profile import FactoryProfileError, validate_factory_profile

SCHEMA_VERSION = "0.1"
AUTO_UPDATE_ENV = "FACTORY_DROID_AUTO_UPDATE_ENABLED"
INITIAL_PROJECT_BUDGET = Decimal("30.00")
HARD_PROJECT_STOP = Decimal("50.00")
_REQUIRED_PREFLIGHT_CHECKS = {
    "offline_dry_run",
    "lima_manifest",
    "guest_droid_installed",
    "guest_droid_checksum",
    "automatic_updates_disabled",
    "guest_authentication",
    "factory_pro",
    "extra_usage",
    "usage_evidence",
    "models_and_reasoning",
    "factory_profile_inventory",
    "plugin_inventory",
    "managed_configuration_measurable",
    "unknown_inherited_surfaces_absent",
    "sealed_fixture_binding",
    "installed_artifact_binding",
    "isolation_binding",
    "same_project_decoy_planned",
    "no_prior_feasibility_mission",
    "teardown_ready",
    "evidence_export_ready",
}
_MODEL_FIELDS = {
    "orchestrator_model",
    "orchestrator_reasoning",
    "worker_model",
    "worker_reasoning",
    "validator_model",
    "validator_reasoning",
    "probe_model",
    "probe_reasoning",
}
_APPROVED_MODEL_REASONING = {
    "gpt-5.4-mini": ("low", "medium", "high", "xhigh"),
    "gpt-5.6-luna": ("none", "low", "medium", "high", "xhigh", "max"),
    "gpt-5.6-terra": ("none", "low", "medium", "high", "xhigh", "max"),
}
_BINDING_FIELDS = {
    "droid_version",
    "droid_installation_channel",
    "droid_binary_digest",
    "droid_auto_update_control",
    "plugin_version",
    "droid_sdk_version",
    "lima_version",
    "vm_image_digest",
    "factory_profile_digest",
    "isolation_digest",
    "gate_surface_digest",
    "installed_plugin_artifact_digest",
}
_AUTHORIZATION_FIELDS = {
    "schema_version",
    "authorized_by",
    "authorized_at",
    "vm_create_and_delete",
    "install_local_plugin",
    "factory_configuration_changes",
    "exactly_one_paid_mission",
    "initial_project_budget",
    "hard_project_stop",
    "maximum_additional_exposure",
    "sanitized_evidence_export",
    "mandatory_vm_disk_deletion",
    "bindings",
    "models",
}
_REQUIRED_IDENTITY_CONTROLS = {
    "independent_mission_correlation",
    "same_project_decoy_excluded",
    "shadow_sdk_sessions_excluded",
}
_REQUIRED_GUIDANCE_CONTROLS = {
    "worker_a_delivered",
    "worker_a_acknowledged",
    "worker_b_delivered",
    "worker_b_acknowledged",
    "siblings_excluded",
    "orchestrator_excluded",
    "decoy_excluded",
    "repeated_markers_filtered",
}
_REQUIRED_BLOCKER_CONTROLS = {
    "direct_evidence",
    "independent_probe",
    "probe_preceded_block",
    "completion_blocked",
    "retry_durable",
    "forgery_rejected",
    "replay_rejected",
    "cross_run_rejected",
    "stale_generation_rejected",
    "expired_state_rejected",
    "collector_loss_blocked",
    "correction_resolved",
    "completion_released",
    "factory_block_observed",
    "factory_release_observed",
}
_REQUIRED_PROBE_CONTROLS = {
    "zero_tools",
    "activation_stripped",
    "watched_events",
    "schema_valid",
    "sdk_process_stable",
    "citations_match_oracle",
    "preceded_blockers",
}
_FORBIDDEN_KEYS = {
    "session_id",
    "transcript_path",
    "run_secret",
    "factory_api_key",
    "api_key",
    "canary",
}
_FORBIDDEN_VALUES = {
    "ROUTE-ALPHA-7319",
    "ROUTE-BRAVO-4826",
    "ROUTE-NEGATIVE-9054",
    "sk-shadow-feasibility-NEVER-PERSIST-7319",
}
_DIGEST_FIELDS = {
    "droid_binary_digest",
    "vm_image_digest",
    "factory_profile_digest",
    "isolation_digest",
    "gate_surface_digest",
    "installed_plugin_artifact_digest",
}
_FALLBACK_BASES = {
    "hook_event_provenance": "complete_independent_observation_path",
    "disposable_isolation": "alternate_disposable_environment",
    "clean_factory_profile": "sealed_managed_settings_only",
    "session_hooks": "worker_only_no_validator_surface",
    "distinct_session_and_mission_identity": "worker_only_no_validator_identity",
    "live_transcript_access": "event_only_equivalent_attribution",
    "targeted_guidance_routing": "observed_session_scoped_channel",
    "stop_blocker_behavior": "mission_repair_worker",
    "role_mapping": "reliable_worker_mapping_only",
}
_CAPABILITY_TRANSITIONS = {
    "run_transport_integrity": "transport_verified",
    "hook_event_provenance": "provenance_reconciled",
    "disposable_isolation": "isolation_observed",
    "clean_factory_profile": "profile_observed",
    "session_hooks": "lifecycle_observed",
    "distinct_session_and_mission_identity": "identity_observed",
    "live_transcript_access": "transcript_observed",
    "targeted_guidance_routing": "guidance_observed",
    "stop_blocker_behavior": "blockers_observed",
    "role_mapping": "roles_observed",
    "independent_probe_boundary": "probe_observed",
}
_EVIDENCE_SOURCES = {
    "factory_process",
    "hook_authenticated",
    "host_preflight",
    "host_teardown",
    "independent_probe",
    "offline_negative_control",
    "transport_authenticated",
    "wrapper_observation",
}
_MINIMUM_CAPABILITY_SOURCES = {
    "run_transport_integrity": {
        "transport_authenticated",
        "offline_negative_control",
    },
    "distinct_session_and_mission_identity": {
        "factory_process",
        "wrapper_observation",
    },
    "stop_blocker_behavior": {
        "independent_probe",
        "offline_negative_control",
        "wrapper_observation",
    },
    "independent_probe_boundary": {"independent_probe"},
}
_VERSION_PATTERN = re.compile(r"(?:droid\s+)?(?P<version>\d+\.\d+\.\d+)", re.IGNORECASE)
_MAX_DROID_OUTPUT_BYTES = 16 << 20
_DROID_PROCESS_TIMEOUT_SECONDS = 3_600



class LiveGateError(ValueError):
    """Raised when a paid action or live verdict is not fully supported."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[[tuple[str, ...], dict[str, str]], CommandResult]
InteractiveCommandRunner = Callable[
    [tuple[str, ...], dict[str, str], str], CommandResult
]


def _run_subprocess(
    arguments: tuple[str, ...],
    environment: dict[str, str],
    *,
    input_text: str | None,
    timeout_seconds: int,
) -> CommandResult:
    try:
        completed = subprocess.run(
            arguments,
            env=environment,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LiveGateError("Droid process boundary failed") from error
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _default_command_runner(
    arguments: tuple[str, ...], environment: dict[str, str]
) -> CommandResult:
    return _run_subprocess(
        arguments,
        environment,
        input_text=None,
        timeout_seconds=_DROID_PROCESS_TIMEOUT_SECONDS,
    )


def _interactive_process_group_alive(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _wait_interactive_process_group(
    process: subprocess.Popen[bytes],
    deadline: float,
) -> bool:
    while True:
        leader_alive = process.poll() is None
        group_alive = _interactive_process_group_alive(process.pid)
        if not leader_alive and not group_alive:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        if leader_alive:
            try:
                process.wait(timeout=min(0.01, remaining))
            except subprocess.TimeoutExpired:
                pass
        else:
            time.sleep(min(0.01, remaining))


def _terminate_interactive_process_group(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float = 5.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass
    term_deadline = time.monotonic() + max(
        0.0,
        (deadline - time.monotonic()) / 2,
    )
    _wait_interactive_process_group(process, term_deadline)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    if not _wait_interactive_process_group(process, deadline):
        raise LiveGateError("interactive Droid process group did not stop")


def _default_interactive_command_runner(
    arguments: tuple[str, ...],
    environment: dict[str, str],
    input_text: str,
) -> CommandResult:
    master, slave = os.openpty()
    process: subprocess.Popen[bytes] | None = None
    output = bytearray()
    deadline = time.monotonic() + 30
    try:
        process = subprocess.Popen(
            arguments,
            env=environment,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
            close_fds=True,
        )
        os.close(slave)
        slave = -1
        os.write(master, input_text.encode("utf-8"))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_interactive_process_group(process)
                return CommandResult(
                    124,
                    output.decode("utf-8", errors="replace"),
                    "interactive Droid command timed out",
                )
            readable, _, _ = select.select([master], [], [], min(remaining, 0.1))
            if readable:
                try:
                    chunk = os.read(master, 65_536)
                except OSError:
                    chunk = b""
                if chunk:
                    output.extend(chunk)
                    if len(output) > _MAX_DROID_OUTPUT_BYTES:
                        _terminate_interactive_process_group(process)
                        return CommandResult(
                            255,
                            "",
                            "interactive Droid output exceeded its byte limit",
                        )
                elif process.poll() is not None:
                    break
            elif process.poll() is not None:
                break
        _terminate_interactive_process_group(process)
        return CommandResult(
            int(process.returncode or 0),
            output.decode("utf-8", errors="replace"),
            "",
        )
    except (OSError, subprocess.SubprocessError) as error:
        if process is not None and (
            process.poll() is None
            or _interactive_process_group_alive(process.pid)
        ):
            try:
                _terminate_interactive_process_group(process)
            except LiveGateError:
                raise LiveGateError(
                    "interactive Droid process boundary and cleanup failed"
                ) from error
        raise LiveGateError("interactive Droid process boundary failed") from error
    finally:
        os.close(master)
        if slave >= 0:
            os.close(slave)



def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()

def _decimal(value: object, field_name: str) -> Decimal:
    if isinstance(value, bool):
        raise LiveGateError(f"{field_name} must be a finite decimal")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise LiveGateError(f"{field_name} must be a finite decimal") from error
    if not result.is_finite() or result < 0:
        raise LiveGateError(f"{field_name} must be a nonnegative finite decimal")
    return result


def _exact_string_mapping(
    value: object, expected_fields: set[str], field_name: str
) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise LiveGateError(f"{field_name} fields differ from the contract")
    result: dict[str, str] = {}
    for key in sorted(expected_fields):
        item = value[key]
        if not isinstance(item, str) or not item:
            raise LiveGateError(f"{field_name}.{key} must be a nonempty string")
        result[key] = item
    return result


def _validate_bindings(value: object) -> dict[str, str]:
    bindings = _exact_string_mapping(value, _BINDING_FIELDS, "bindings")
    for field_name in _DIGEST_FIELDS:
        digest = bindings[field_name]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise LiveGateError(f"bindings.{field_name} is not a SHA-256 digest")
    if bindings["droid_auto_update_control"] != "npm-build-disabled-and-env-false":
        raise LiveGateError("bindings.droid_auto_update_control is not approved")
    return bindings


def _validate_sha256(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise LiveGateError(f"{field_name} is not a SHA-256 digest")
    return value


def validate_model_catalog(
    value: object,
    selected_models: Mapping[str, str],
) -> dict[str, tuple[str, ...]]:
    expected_fields = {
        "schema_version",
        "source",
        "captured_without_model_call",
        "output_digest",
        "available_models",
        "runtime_settings",
        "mcp_servers",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise LiveGateError("model catalog fields differ from the contract")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("source") != "droid-model-selector"
        or value.get("captured_without_model_call") is not True
    ):
        raise LiveGateError("model catalog provenance is not approved")
    _validate_sha256(value.get("output_digest"), "model catalog output digest")
    if value.get("runtime_settings") != {
        "model_id": "gpt-5.4-mini",
        "reasoning_effort": "high",
        "sandbox_enabled": True,
        "sandbox_mode": "whole-process",
        "restrict_tool_ids": [],
    } or value.get("mcp_servers") != []:
        raise LiveGateError("runtime Factory settings differ from the approved set")
    available = value.get("available_models")
    if not isinstance(available, Mapping) or set(available) != set(
        _APPROVED_MODEL_REASONING
    ):
        raise LiveGateError("model catalog inventory differs from the approved set")
    normalized: dict[str, tuple[str, ...]] = {}
    for model_name, reasoning_values in available.items():
        if (
            not isinstance(reasoning_values, list)
            or tuple(reasoning_values)
            != _APPROVED_MODEL_REASONING[str(model_name)]
        ):
            raise LiveGateError("model catalog reasoning settings differ")
        normalized[str(model_name)] = tuple(str(item) for item in reasoning_values)
    models = _exact_string_mapping(selected_models, _MODEL_FIELDS, "models")
    for role in ("orchestrator", "worker", "validator", "probe"):
        model_name = models[f"{role}_model"]
        reasoning = models[f"{role}_reasoning"]
        if model_name not in normalized or reasoning not in normalized[model_name]:
            raise LiveGateError(f"{role} model or reasoning is unavailable")
    return normalized


def build_model_catalog_evidence(
    available_models: Sequence[Mapping[str, object]],
    runtime_settings: Mapping[str, object],
    mcp_servers: Sequence[object],
) -> dict[str, object]:
    observed: list[dict[str, object]] = []
    approved: dict[str, list[str]] = {}
    seen: set[str] = set()
    for raw_model in available_models:
        model_name = raw_model.get("id")
        raw_reasoning = raw_model.get("supported_reasoning_efforts")
        if (
            not isinstance(model_name, str)
            or not model_name
            or model_name in seen
            or not isinstance(raw_reasoning, Sequence)
            or isinstance(raw_reasoning, (str, bytes))
        ):
            raise LiveGateError("measured model catalog is invalid")
        reasoning = [
            str(getattr(value, "value", value))
            for value in raw_reasoning
        ]
        if not reasoning or len(reasoning) != len(set(reasoning)):
            raise LiveGateError("measured model reasoning inventory is invalid")
        seen.add(model_name)
        observed.append({"id": model_name, "reasoning": reasoning})
        if model_name in _APPROVED_MODEL_REASONING:
            expected = list(_APPROVED_MODEL_REASONING[model_name])
            if reasoning != expected:
                raise LiveGateError("approved model reasoning inventory drifted")
            approved[model_name] = reasoning
    if set(approved) != set(_APPROVED_MODEL_REASONING):
        raise LiveGateError("approved model inventory is incomplete")
    expected_runtime = {
        "model_id": "gpt-5.4-mini",
        "reasoning_effort": "high",
        "sandbox_enabled": True,
        "sandbox_mode": "whole-process",
        "restrict_tool_ids": [],
    }
    if dict(runtime_settings) != expected_runtime or list(mcp_servers) != []:
        raise LiveGateError("resolved Factory runtime contains an unknown surface")
    encoded = json.dumps(
        {
            "models": sorted(observed, key=lambda item: str(item["id"])),
            "runtime_settings": expected_runtime,
            "mcp_servers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "droid-model-selector",
        "captured_without_model_call": True,
        "output_digest": hashlib.sha256(encoded).hexdigest(),
        "available_models": approved,
        "runtime_settings": expected_runtime,
        "mcp_servers": [],
    }


def validate_cost_evidence(
    value: object,
    budget: "BudgetLedger",
) -> None:
    expected_fields = {
        "schema_version",
        "source",
        "captured_without_model_call",
        "output_digest",
        "pro_subscription",
        "extra_usage_purchases",
        "prior_shadow_model_charges",
        "remaining_extra_usage",
        "pay_as_you_go_enabled",
        "live_run_count",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise LiveGateError("cost evidence fields differ from the contract")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("source") != "droid-limits-and-project-ledger"
        or value.get("captured_without_model_call") is not True
    ):
        raise LiveGateError("cost evidence provenance is not approved")
    output_digest = _validate_sha256(
        value.get("output_digest"),
        "cost evidence output digest",
    )
    comparable = {
        "pro_subscription": budget.pro_subscription,
        "extra_usage_purchases": budget.extra_usage_purchases,
        "prior_shadow_model_charges": budget.prior_shadow_model_charges,
        "remaining_extra_usage": budget.remaining_extra_usage,
    }
    for field_name, expected in comparable.items():
        if _decimal(value.get(field_name), field_name) != expected:
            raise LiveGateError(f"cost evidence differs: {field_name}")
    if (
        value.get("pay_as_you_go_enabled") is not budget.pay_as_you_go_enabled
        or value.get("live_run_count") != budget.live_run_count
        or budget.cost_evidence_digest != output_digest
    ):
        raise LiveGateError("cost evidence differs from the budget ledger")


def build_cost_and_budget_evidence(
    billing_record: Mapping[str, object],
    usage_observation: Mapping[str, object],
    *,
    live_run_count: int,
) -> tuple[dict[str, object], dict[str, object]]:
    expected_billing_fields = {
        "schema_version",
        "source",
        "captured_without_model_call",
        "output_digest",
        "pro_subscription",
        "extra_usage_purchases",
        "prior_shadow_model_charges",
        "maximum_additional_exposure",
        "pay_as_you_go_enabled",
    }
    if (
        set(billing_record) != expected_billing_fields
        or billing_record.get("schema_version") != SCHEMA_VERSION
        or billing_record.get("source") != "factory-billing-ui"
        or billing_record.get("captured_without_model_call") is not True
    ):
        raise LiveGateError("billing evidence differs from the contract")
    billing_digest = _validate_sha256(
        billing_record.get("output_digest"),
        "billing evidence output digest",
    )
    billing_payload = {
        field_name: billing_record[field_name]
        for field_name in sorted(expected_billing_fields - {"output_digest"})
    }
    expected_billing_digest = hashlib.sha256(
        json.dumps(
            billing_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if billing_digest != expected_billing_digest:
        raise LiveGateError("billing evidence digest does not match its contents")
    expected_usage_fields = {
        "status",
        "evidence_type",
        "output_digest",
        "output_bytes",
        "remaining_extra_usage",
    }
    if (
        set(usage_observation) != expected_usage_fields
        or usage_observation.get("status") != "captured"
        or usage_observation.get("evidence_type") != "droid-limits"
    ):
        raise LiveGateError("usage observation differs from the contract")
    usage_digest = _validate_sha256(
        usage_observation.get("output_digest"),
        "usage observation output digest",
    )
    remaining_extra_usage = usage_observation.get("remaining_extra_usage")
    if remaining_extra_usage is None:
        raise LiveGateError("remaining Extra Usage was not measured")
    if (
        not isinstance(live_run_count, int)
        or isinstance(live_run_count, bool)
        or live_run_count < 0
    ):
        raise LiveGateError("live run count is invalid")
    cost_digest = hashlib.sha256(
        json.dumps(
            {
                "billing_output_digest": billing_digest,
                "usage_output_digest": usage_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    budget = {
        "pro_subscription": str(billing_record["pro_subscription"]),
        "extra_usage_purchases": str(billing_record["extra_usage_purchases"]),
        "prior_shadow_model_charges": str(
            billing_record["prior_shadow_model_charges"]
        ),
        "remaining_extra_usage": str(remaining_extra_usage),
        "maximum_additional_exposure": str(
            billing_record["maximum_additional_exposure"]
        ),
        "pay_as_you_go_enabled": billing_record["pay_as_you_go_enabled"],
        "cost_evidence_digest": cost_digest,
        "live_run_count": live_run_count,
    }
    ledger = BudgetLedger.from_mapping(budget)
    ledger.validate()
    cost_evidence = {
        "schema_version": SCHEMA_VERSION,
        "source": "droid-limits-and-project-ledger",
        "captured_without_model_call": True,
        "output_digest": cost_digest,
        "pro_subscription": budget["pro_subscription"],
        "extra_usage_purchases": budget["extra_usage_purchases"],
        "prior_shadow_model_charges": budget["prior_shadow_model_charges"],
        "remaining_extra_usage": budget["remaining_extra_usage"],
        "pay_as_you_go_enabled": budget["pay_as_you_go_enabled"],
        "live_run_count": live_run_count,
    }
    validate_cost_evidence(cost_evidence, ledger)
    return budget, cost_evidence


@dataclass(frozen=True)
class BudgetLedger:
    pro_subscription: Decimal
    extra_usage_purchases: Decimal
    prior_shadow_model_charges: Decimal
    remaining_extra_usage: Decimal
    maximum_additional_exposure: Decimal
    pay_as_you_go_enabled: bool
    cost_evidence_digest: str
    live_run_count: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "BudgetLedger":
        expected = {
            "pro_subscription",
            "extra_usage_purchases",
            "prior_shadow_model_charges",
            "remaining_extra_usage",
            "maximum_additional_exposure",
            "pay_as_you_go_enabled",
            "cost_evidence_digest",
            "live_run_count",
        }
        if set(value) != expected:
            raise LiveGateError("budget fields differ from the contract")
        count = value["live_run_count"]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise LiveGateError("live_run_count must be a nonnegative integer")
        pay_as_you_go_enabled = value["pay_as_you_go_enabled"]
        if not isinstance(pay_as_you_go_enabled, bool):
            raise LiveGateError("pay_as_you_go_enabled must be boolean")
        evidence_digest = value["cost_evidence_digest"]
        if (
            not isinstance(evidence_digest, str)
            or len(evidence_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in evidence_digest
            )
        ):
            raise LiveGateError("cost evidence digest is invalid")
        return cls(
            pro_subscription=_decimal(value["pro_subscription"], "pro_subscription"),
            extra_usage_purchases=_decimal(
                value["extra_usage_purchases"], "extra_usage_purchases"
            ),
            prior_shadow_model_charges=_decimal(
                value["prior_shadow_model_charges"], "prior_shadow_model_charges"
            ),
            remaining_extra_usage=_decimal(
                value["remaining_extra_usage"], "remaining_extra_usage"
            ),
            maximum_additional_exposure=_decimal(
                value["maximum_additional_exposure"],
                "maximum_additional_exposure",
            ),
            pay_as_you_go_enabled=pay_as_you_go_enabled,
            cost_evidence_digest=evidence_digest,
            live_run_count=count,
        )

    @property
    def committed_spend(self) -> Decimal:
        return (
            self.pro_subscription
            + self.extra_usage_purchases
            + self.prior_shadow_model_charges
        )

    @property
    def maximum_project_exposure(self) -> Decimal:
        return self.committed_spend + self.maximum_additional_exposure

    def validate(self) -> None:
        if self.committed_spend > INITIAL_PROJECT_BUDGET:
            raise LiveGateError("committed project spend exceeds the initial budget")
        if self.maximum_project_exposure >= HARD_PROJECT_STOP:
            raise LiveGateError("maximum project exposure reaches the hard stop")
        if self.pay_as_you_go_enabled:
            raise LiveGateError("pay-as-you-go billing makes exposure unbounded")
        if self.maximum_additional_exposure > self.remaining_extra_usage:
            raise LiveGateError("additional exposure exceeds prepaid Extra Usage")
        if self.remaining_extra_usage > self.extra_usage_purchases:
            raise LiveGateError("remaining Extra Usage exceeds recorded purchases")
        if self.live_run_count != 0:
            raise LiveGateError("the feasibility Mission slot is already consumed")

    def sanitized(self) -> dict[str, object]:
        return {
            "pro_subscription": format(self.pro_subscription, ".2f"),
            "extra_usage_purchases": format(self.extra_usage_purchases, ".2f"),
            "prior_shadow_model_charges": format(
                self.prior_shadow_model_charges, ".2f"
            ),
            "remaining_extra_usage": format(self.remaining_extra_usage, ".2f"),
            "committed_spend": format(self.committed_spend, ".2f"),
            "maximum_additional_exposure": format(
                self.maximum_additional_exposure, ".2f"
            ),
            "maximum_project_exposure": format(
                self.maximum_project_exposure, ".2f"
            ),
            "pay_as_you_go_enabled": self.pay_as_you_go_enabled,
            "cost_evidence_digest": self.cost_evidence_digest,
            "live_run_count": self.live_run_count,
        }


@dataclass(frozen=True)
class AuthorizationRecord:
    authorized_by: str
    authorized_at: str
    factory_configuration_changes: tuple[str, ...]
    maximum_additional_exposure: Decimal
    bindings: dict[str, str]
    models: dict[str, str]

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "AuthorizationRecord":
        if set(value) != _AUTHORIZATION_FIELDS:
            raise LiveGateError("authorization fields differ from the contract")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise LiveGateError("authorization schema is unsupported")
        for field_name in (
            "vm_create_and_delete",
            "install_local_plugin",
            "exactly_one_paid_mission",
            "sanitized_evidence_export",
            "mandatory_vm_disk_deletion",
        ):
            if value.get(field_name) is not True:
                raise LiveGateError(f"authorization does not permit {field_name}")
        if value.get("authorized_by") != "Scott":
            raise LiveGateError("authorization must come directly from Scott")
        authorized_at = value.get("authorized_at")
        if not isinstance(authorized_at, str) or not authorized_at.endswith("Z"):
            raise LiveGateError("authorization time must be an exact UTC timestamp")
        if _decimal(value.get("initial_project_budget"), "initial_project_budget") != INITIAL_PROJECT_BUDGET:
            raise LiveGateError("authorization initial budget differs")
        if _decimal(value.get("hard_project_stop"), "hard_project_stop") != HARD_PROJECT_STOP:
            raise LiveGateError("authorization hard stop differs")
        changes = value.get("factory_configuration_changes")
        if (
            not isinstance(changes, list)
            or not changes
            or not all(isinstance(item, str) and item for item in changes)
        ):
            raise LiveGateError("authorization configuration changes are incomplete")
        return cls(
            authorized_by="Scott",
            authorized_at=authorized_at,
            factory_configuration_changes=tuple(changes),
            maximum_additional_exposure=_decimal(
                value.get("maximum_additional_exposure"),
                "maximum_additional_exposure",
            ),
            bindings=_validate_bindings(value.get("bindings")),
            models=_exact_string_mapping(value.get("models"), _MODEL_FIELDS, "models"),
        )


_MONEY_PATTERN = re.compile(r"\d+\.\d{2}")
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_EXTRA_USAGE_PATTERNS = (
    re.compile(
        r"extra\s+usage[^\r\n$]{0,80}\$\s*(?P<amount>\d+(?:\.\d{1,2})?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\$\s*(?P<amount>\d+(?:\.\d{1,2})?)[^\r\n]{0,80}"
        r"extra\s+usage",
        re.IGNORECASE,
    ),
)


def _parse_extra_usage_remaining(output: bytes) -> str:
    try:
        text = output.decode("utf-8")
    except UnicodeError as error:
        raise LiveGateError("Droid usage evidence is not UTF-8") from error
    normalized = _ANSI_ESCAPE_PATTERN.sub("", text)
    amounts = {
        Decimal(match.group("amount"))
        for pattern in _EXTRA_USAGE_PATTERNS
        for match in pattern.finditer(normalized)
    }
    if len(amounts) != 1:
        raise LiveGateError("Droid usage evidence lacks one Extra Usage balance")
    amount = amounts.pop()
    if not amount.is_finite() or amount < 0:
        raise LiveGateError("Droid Extra Usage balance is invalid")
    return format(amount, ".2f")


def reconcile_usage_observations(
    usage: Mapping[str, object],
) -> dict[str, str]:
    values: dict[str, Decimal] = {}
    for stage in ("pre_run", "post_run"):
        record = usage.get(stage)
        if not isinstance(record, Mapping):
            raise LiveGateError("usage reconciliation evidence is incomplete")
        try:
            values[stage] = Decimal(str(record["remaining_extra_usage"]))
        except (KeyError, InvalidOperation) as error:
            raise LiveGateError("usage reconciliation balance is invalid") from error
    if (
        not all(value.is_finite() and value >= 0 for value in values.values())
        or values["post_run"] > values["pre_run"]
    ):
        raise LiveGateError("post-run usage cannot be reconciled")
    return {
        "status": "reconciled",
        "pre_run_remaining_extra_usage": format(values["pre_run"], ".2f"),
        "post_run_remaining_extra_usage": format(values["post_run"], ".2f"),
        "observed_extra_usage_consumed": format(
            values["pre_run"] - values["post_run"],
            ".2f",
        ),
    }


class DroidCommandBoundary:
    """The only allowed process boundary for the pinned Droid executable."""

    def __init__(
        self,
        executable: Path,
        expected_version: str,
        expected_digest: str,
        installation_channel: str,
        command_runner: CommandRunner | None = None,
        interactive_command_runner: InteractiveCommandRunner | None = None,
        credential_environment: Mapping[str, str] | None = None,
    ) -> None:
        self.executable = executable.resolve()
        self.expected_version = expected_version
        self.expected_digest = expected_digest
        self.installation_channel = installation_channel
        self._command_runner = command_runner or _default_command_runner
        self._interactive_command_runner = (
            interactive_command_runner or _default_interactive_command_runner
        )
        self._credential_environment = dict(credential_environment or {})
        if set(self._credential_environment) not in (set(), {"FACTORY_API_KEY"}):
            raise LiveGateError("Droid credential environment is invalid")
        factory_api_key = self._credential_environment.get("FACTORY_API_KEY")
        if factory_api_key is not None and (
            not factory_api_key
            or len(factory_api_key.encode("utf-8")) > 4096
            or any(character in factory_api_key for character in ("\x00", "\r", "\n"))
        ):
            raise LiveGateError("Droid Factory credential is invalid")
        if installation_channel != "factory-npm-platform-tarball":
            raise LiveGateError("only the approved npm installation channel is supported")
        if len(expected_digest) != 64:
            raise LiveGateError("expected Droid digest is invalid")

    def _verify_binary(self) -> None:
        try:
            metadata = self.executable.stat()
            digest = _sha256_file(self.executable)
        except OSError as error:
            raise LiveGateError("Droid binary is unavailable") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise LiveGateError("Droid binary is not a regular file")
        if digest != self.expected_digest:
            raise LiveGateError("Droid binary digest drift detected")

    @staticmethod
    def _base_environment() -> dict[str, str]:
        allowed = ("HOME", "PATH", "LANG", "LC_ALL", "TERM", "TMPDIR")
        return {key: os.environ[key] for key in allowed if key in os.environ}

    def runtime_environment(
        self, environment: Mapping[str, str] | None = None
    ) -> dict[str, str]:
        supplied = dict(environment or {})
        if supplied.get(AUTO_UPDATE_ENV) not in {None, "false"}:
            raise LiveGateError("Droid automatic updates must remain disabled")
        process_environment = self._base_environment()
        if "FACTORY_API_KEY" in supplied:
            raise LiveGateError("Droid Factory credential cannot be overridden")
        process_environment.update(self._credential_environment)
        process_environment.update(supplied)
        process_environment[AUTO_UPDATE_ENV] = "false"
        return process_environment

    def run(
        self,
        arguments: Sequence[str],
        environment: Mapping[str, str] | None = None,
    ) -> CommandResult:
        self._verify_binary()
        arguments_tuple = tuple(str(item) for item in arguments)
        if "--skip-permissions-unsafe" in arguments_tuple:
            raise LiveGateError("unsafe permission bypass is forbidden")
        process_environment = self.runtime_environment(environment)
        result = self._command_runner(
            (str(self.executable), *arguments_tuple), process_environment
        )
        self._ensure_bounded_output(result)
        return result
    def capture_model_catalog(self, workspace: Path) -> dict[str, object]:
        self._verify_binary()

        async def capture() -> dict[str, object]:
            from droid_sdk.client import DroidClient

            environment = self.runtime_environment(
                {
                    "SHADOW_MISSION_RUN_FILE": "",
                    "SHADOW_MISSION_RUN_DESCRIPTOR": "",
                    "SHADOW_MISSION_RUN_SECRET": "",
                    "SHADOW_MISSION_COLLECTOR_URL": "",
                    "SHADOW_MISSION_CORRELATION_ID": "",
                    "SHADOW_MISSION_LOG_GROUP_ID": "",
                    "SHADOW_MISSION_INTERNAL": "1",
                }
            )
            async with DroidClient(
                exec_path=str(self.executable),
                cwd=str(workspace),
                env=environment,
            ) as client:
                initialized = await client.initialize_session(
                    machine_id="shadow-feasibility-preflight",
                    cwd=str(workspace),
                    model_id="gpt-5.4-mini",
                    reasoning_effort="high",
                    restrict_tool_ids=[],
                    auto_reject_permission_requests=True,
                    disable_builtin_skills=True,
                )
                models = initialized.available_models
                if models is None:
                    raise LiveGateError("Droid returned no model catalog")
                sandbox = initialized.settings.sandbox
                return build_model_catalog_evidence(
                    [
                        {
                            "id": model.id,
                            "supported_reasoning_efforts": (
                                model.supported_reasoning_efforts
                            ),
                        }
                        for model in models
                    ],
                    {
                        "model_id": initialized.settings.model_id,
                        "reasoning_effort": str(
                            initialized.settings.reasoning_effort.value
                        ),
                        "sandbox_enabled": bool(
                            sandbox is not None and sandbox.enabled
                        ),
                        "sandbox_mode": (
                            ""
                            if sandbox is None or sandbox.mode is None
                            else str(sandbox.mode.value)
                        ),
                        "restrict_tool_ids": (
                            initialized.settings.restrict_tool_ids or []
                        ),
                    },
                    initialized.mcp_servers or [],
                )

        try:
            result = asyncio.run(capture())
        except LiveGateError:
            raise
        except Exception as error:
            raise LiveGateError("Droid model catalog capture failed") from error
        self._verify_binary()
        return result


    def validate_model_settings(
        self,
        model_settings: Mapping[str, str],
        model_catalog: object,
    ) -> None:
        validate_model_catalog(model_catalog, model_settings)
    @staticmethod
    def _ensure_bounded_output(result: CommandResult) -> None:
        output_bytes = len(result.stdout.encode()) + len(result.stderr.encode())
        if output_bytes > _MAX_DROID_OUTPUT_BYTES:
            raise LiveGateError("Droid process output exceeded its byte limit")

    def capture_usage(self, stage: str) -> dict[str, object]:
        if stage not in {"pre_run", "post_run"}:
            raise LiveGateError("usage observation stage is invalid")
        self._verify_binary()
        result = self._interactive_command_runner(
            (str(self.executable),),
            self.runtime_environment(),
            "/limits\n/exit\n",
        )
        self._ensure_bounded_output(result)
        output = f"{result.stdout}\n{result.stderr}".strip().encode()
        normalized_output = output.lower()
        if (
            result.returncode != 0
            or not output
            or not any(
                marker in normalized_output
                for marker in (b"usage", b"limit", b"plan", b"extra")
            )
        ):
            raise LiveGateError(f"Droid {stage} usage observation failed")
        return {
            "status": "captured",
            "evidence_type": "droid-limits",
            "output_digest": hashlib.sha256(output).hexdigest(),
            "output_bytes": len(output),
            "remaining_extra_usage": _parse_extra_usage_remaining(output),
        }

    def observe(self, stage: str) -> dict[str, str]:
        if stage not in {"preflight", "pre_mission", "post_mission"}:
            raise LiveGateError("Droid observation stage is invalid")
        result = self.run(("--version",))
        if result.returncode != 0:
            raise LiveGateError(f"Droid {stage} version observation failed")
        match = _VERSION_PATTERN.fullmatch((result.stdout or result.stderr).strip())
        if match is None or match.group("version") != self.expected_version:
            raise LiveGateError(f"Droid version drift detected at {stage}")
        return {
            "version": self.expected_version,
            "binary_digest": self.expected_digest,
            "auto_update_control": "npm-build-disabled-and-env-false",
        }


@dataclass(frozen=True)
class ProbeEvidence:
    probe_result_id: str
    authoritative_value: str
    citations: tuple[str, ...]
    attempts: int
    zero_tools: bool
    activation_stripped: bool


    internal_session_alias: str = ""
    sdk_process_stable: bool = True


class TransientProbeError(RuntimeError):
    """A probe failure that permits one identical fresh-session retry."""


class UnsafeProbeError(RuntimeError):
    """A probe result that must not be retried."""


def run_bounded_probe_attempts(
    attempt: Callable[[], ProbeEvidence],
) -> ProbeEvidence:
    for attempt_number in (1, 2):
        try:
            result = attempt()
            return ProbeEvidence(
                probe_result_id=result.probe_result_id,
                authoritative_value=result.authoritative_value,
                citations=result.citations,
                attempts=attempt_number,
                zero_tools=result.zero_tools,
                activation_stripped=result.activation_stripped,
                internal_session_alias=result.internal_session_alias,
                sdk_process_stable=result.sdk_process_stable,
            )
        except TransientProbeError:
            if attempt_number == 2:
                raise
    raise AssertionError("unreachable probe retry state")

async def _lock_down_session_tools(session: Any) -> bool:
    initial_tools = await session.list_tools()
    disabled_tool_ids = {tool.id for tool in initial_tools}
    if disabled_tool_ids:
        await session.update_settings(
            disabled_tools=disabled_tool_ids,
        )
    tools = await session.list_tools(
        disabled_tools=disabled_tool_ids or None,
    )
    return not any(tool.allowed for tool in tools)


def _build_probe_request(snapshot: str) -> str:
    return json.dumps(
        {
            "task": (
                "Inspect observed_source as well as both schemas. "
                "Independently verify whether an observed source claims "
                "that amount uses dollars while the API and database "
                "schemas establish cents. If that conflict exists, "
                "return risk_confirmed=true, authoritative_value exactly "
                "cents, both allowed citations, and recommendation "
                "exactly block."
            ),
            "constraints": {
                "allowed_citations": [
                    "api-schema.json#/properties/amount",
                    "db-schema.sql:payments.amount_cents",
                ],
                "tools_must_not_be_used": True,
            },
            "evidence": json.loads(snapshot),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


async def _run_probe_session(
    *,
    boundary: DroidCommandBoundary,
    authenticated_guest_home: Path,
    fixture_path: Path,
    model: str,
    reasoning: str,
    snapshot: str,
    alias_secret: str,
) -> ProbeEvidence:
    from droid_sdk import (
        ReasoningEffort,
        Runtime,
        Session,
        SessionConfig,
    )
    from droid_sdk.errors import (
        DroidConnectionError,
        DroidProcessError,
        RunTimeoutError,
    )
    from droid_sdk.transport import ProcessTransport
    from pydantic import BaseModel, ConfigDict

    class ProbeOutput(BaseModel):
        model_config = ConfigDict(extra="forbid")

        risk_confirmed: bool
        authoritative_value: str
        citations: list[str]
        recommendation: str

    boundary._verify_binary()
    authenticated_guest_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(authenticated_guest_home, 0o700)
    runtime_environment = boundary.runtime_environment(
        {
            "HOME": str(authenticated_guest_home),
            "SHADOW_MISSION_RUN_FILE": "",
            "SHADOW_MISSION_RUN_SECRET": "",
            "SHADOW_MISSION_COLLECTOR_URL": "",
            "SHADOW_MISSION_CORRELATION_ID": "",
            "SHADOW_MISSION_LOG_GROUP_ID": "",
            "SHADOW_MISSION_INTERNAL": "1",
        }
    )
    transport = ProcessTransport(
        exec_path=str(boundary.executable),
        cwd=str(fixture_path),
        env=runtime_environment,
    )
    internal_session_alias = ""
    try:
        await transport.connect()
        process_pid = transport.pid
        if process_pid is None:
            raise TransientProbeError(
                "independent probe process identity is unavailable"
            )
        session = Session(
            cwd=fixture_path,
            model=model,
            reasoning_effort=ReasoningEffort(reasoning),
            config=SessionConfig(
                mcp_servers=(),
                auto_reject_permission_requests=True,
                disable_builtin_skills=True,
            ),
            runtime=Runtime(transport=transport),
        )
        async with session:
            internal_session_alias = make_alias(
                alias_secret, "session", session.id
            )
            if not await _lock_down_session_tools(session):
                raise UnsafeProbeError("independent probe has an enabled tool")
            probe_request = _build_probe_request(snapshot)
            stream = session.stream(
                probe_request,
                output=ProbeOutput,
                timeout=90,
            )
            async with stream:
                async for _ in stream:
                    pass
            result = stream.result
            boundary._verify_binary()
            if transport.pid != process_pid:
                raise UnsafeProbeError(
                    "independent probe Droid process restarted"
                )
    except UnsafeProbeError:
        raise
    except TransientProbeError:
        raise
    except (
        DroidConnectionError,
        DroidProcessError,
        RunTimeoutError,
        OSError,
    ) as error:
        raise TransientProbeError("independent probe transport failed") from error
    finally:
        await transport.close()
    if not result.success or result.output is None:
        raise TransientProbeError("independent probe output is missing or invalid")
    output = result.output
    citations = tuple(output.citations)
    if (
        output.risk_confirmed is not True
        or output.authoritative_value != "cents"
        or output.recommendation != "block"
        or not citations
        or not all(
            citation
            in {
                "api-schema.json#/properties/amount",
                "db-schema.sql:payments.amount_cents",
            }
            for citation in citations
        )
    ):
        raise UnsafeProbeError("independent probe conflicts with the sealed oracle")
    encoded = output.model_dump_json()
    if any(forbidden in encoded for forbidden in _FORBIDDEN_VALUES):
        raise UnsafeProbeError("independent probe output contains a protected canary")
    probe_digest = hashlib.sha256(
        json.dumps(
            {
                "authoritative_value": output.authoritative_value,
                "citations": sorted(citations),
                "recommendation": output.recommendation,
                "risk_confirmed": output.risk_confirmed,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return ProbeEvidence(
        probe_result_id=f"probe-{probe_digest[:20]}",
        authoritative_value=output.authoritative_value,
        citations=citations,
        attempts=1,
        zero_tools=True,
        activation_stripped=True,
        internal_session_alias=internal_session_alias,
    )


def run_zero_tool_probe(
    *,
    boundary: DroidCommandBoundary,
    authenticated_guest_home: Path,
    fixture_path: Path,
    model: str,
    reasoning: str,
    snapshot: str,
    alias_secret: str,
) -> ProbeEvidence:
    def attempt() -> ProbeEvidence:
        return asyncio.run(
            _run_probe_session(
                boundary=boundary,
                authenticated_guest_home=authenticated_guest_home,
                fixture_path=fixture_path,
                model=model,
                reasoning=reasoning,
                snapshot=snapshot,
                alias_secret=alias_secret,
            )
        )

    return run_bounded_probe_attempts(attempt)


async def _run_inert_control_session(
    *,
    boundary: DroidCommandBoundary,
    authenticated_guest_home: Path,
    fixture_path: Path,
    model: str,
    reasoning: str,
    alias_secret: str,
    internal: bool,
    ready: Callable[[tuple[str, str]], None] | None = None,
    release: threading.Event | None = None,
) -> str:
    from droid_sdk import ReasoningEffort, Runtime, Session, SessionConfig
    from droid_sdk.errors import DroidConnectionError, DroidProcessError
    from droid_sdk.transport import ProcessTransport

    boundary._verify_binary()
    runtime_environment = boundary.runtime_environment(
        {
            "HOME": str(authenticated_guest_home),
            "SHADOW_MISSION_RUN_FILE": "",
            "SHADOW_MISSION_RUN_SECRET": "",
            "SHADOW_MISSION_COLLECTOR_URL": "",
            "SHADOW_MISSION_CORRELATION_ID": "",
            "SHADOW_MISSION_LOG_GROUP_ID": "",
            "SHADOW_MISSION_INTERNAL": "1" if internal else "",
        }
    )
    transport = ProcessTransport(
        exec_path=str(boundary.executable),
        cwd=str(fixture_path),
        env=runtime_environment,
    )
    try:
        await transport.connect()
        process_pid = transport.pid
        if process_pid is None:
            raise LiveGateError("inert control process identity is unavailable")
        session = Session(
            cwd=fixture_path,
            model=model,
            reasoning_effort=ReasoningEffort(reasoning),
            config=SessionConfig(
                mcp_servers=(),
                auto_reject_permission_requests=True,
                disable_builtin_skills=True,
            ),
            runtime=Runtime(transport=transport),
        )
        async with session:
            if not await _lock_down_session_tools(session):
                raise LiveGateError("inert control session has an enabled tool")
            boundary._verify_binary()
            if transport.pid != process_pid:
                raise LiveGateError("inert control Droid process restarted")
            alias = make_alias(alias_secret, "session", session.id)
            if ready is not None:
                ready((alias, session.id))
            if release is not None:
                await asyncio.to_thread(release.wait)
                boundary._verify_binary()
                if transport.pid != process_pid:
                    raise LiveGateError("inert control Droid process restarted")
            return alias
    except (DroidConnectionError, DroidProcessError, OSError) as error:
        raise LiveGateError("inert control session failed") from error
    finally:
        await transport.close()


async def _inspect_inert_control_context(
    *,
    boundary: DroidCommandBoundary,
    authenticated_guest_home: Path,
    fixture_path: Path,
    session_id: str,
    forbidden_markers: tuple[str, ...],
) -> None:
    from droid_sdk.client import DroidClient
    from droid_sdk.errors import DroidConnectionError, DroidProcessError
    from droid_sdk.transport import ProcessTransport

    boundary._verify_binary()
    transport = ProcessTransport(
        exec_path=str(boundary.executable),
        cwd=str(fixture_path),
        env=boundary.runtime_environment(
            {
                "HOME": str(authenticated_guest_home),
                "SHADOW_MISSION_RUN_FILE": "",
                "SHADOW_MISSION_RUN_SECRET": "",
                "SHADOW_MISSION_COLLECTOR_URL": "",
                "SHADOW_MISSION_CORRELATION_ID": "",
                "SHADOW_MISSION_LOG_GROUP_ID": "",
                "SHADOW_MISSION_INTERNAL": "1",
            }
        ),
    )
    client = DroidClient(transport=transport)
    try:
        await client.connect()
        process_pid = transport.pid
        if process_pid is None:
            raise LiveGateError("decoy context inspector identity is unavailable")
        snapshot = await client.load_session(
            session_id=session_id,
            mcp_servers=[],
            disabled_tool_ids=[],
            auto_reject_permission_requests=True,
            disable_builtin_skills=True,
        )
        encoded = snapshot.session.model_dump_json()
        if any(marker in encoded for marker in forbidden_markers):
            raise LiveGateError("targeted guidance entered the decoy context")
        boundary._verify_binary()
        if transport.pid != process_pid:
            raise LiveGateError("decoy context inspector Droid process restarted")
    except (DroidConnectionError, DroidProcessError, OSError) as error:
        raise LiveGateError("decoy context inspection failed") from error
    finally:
        await client.close()


def run_inert_control_session(
    *,
    boundary: DroidCommandBoundary,
    authenticated_guest_home: Path,
    fixture_path: Path,
    model: str,
    reasoning: str,
    alias_secret: str,
    internal: bool,
) -> str:
    return asyncio.run(
        _run_inert_control_session(
            boundary=boundary,
            authenticated_guest_home=authenticated_guest_home,
            fixture_path=fixture_path,
            model=model,
            reasoning=reasoning,
            alias_secret=alias_secret,
            internal=internal,
        )
    )


@dataclass
class ActiveInertControl:
    alias: str
    session_id: str
    _release: threading.Event
    _thread: threading.Thread
    _errors: queue.Queue[BaseException]
    _inspect: Callable[[], None]

    def close(self) -> None:
        self._release.set()
        self._thread.join(timeout=60)
        if self._thread.is_alive():
            raise LiveGateError("active decoy session did not close")
        if not self._errors.empty():
            error = self._errors.get_nowait()
            raise LiveGateError("active decoy session failed") from error
        self._inspect()


def start_inert_control_session(
    *,
    boundary: DroidCommandBoundary,
    authenticated_guest_home: Path,
    fixture_path: Path,
    model: str,
    reasoning: str,
    alias_secret: str,
    internal: bool,
) -> ActiveInertControl:
    release = threading.Event()
    ready: queue.Queue[tuple[str, str] | BaseException] = queue.Queue(maxsize=1)
    errors: queue.Queue[BaseException] = queue.Queue(maxsize=1)
    started = threading.Event()

    def publish(result: tuple[str, str]) -> None:
        ready.put(result)
        started.set()


    def target() -> None:
        try:
            asyncio.run(
                _run_inert_control_session(
                    boundary=boundary,
                    authenticated_guest_home=authenticated_guest_home,
                    fixture_path=fixture_path,
                    model=model,
                    reasoning=reasoning,
                    alias_secret=alias_secret,
                    internal=internal,
                    ready=publish,
                    release=release,
                )
            )
        except BaseException as error:
            if not started.is_set():
                ready.put(error)
            else:
                errors.put(error)

    thread = threading.Thread(
        target=target,
        name="shadow-active-decoy",
        daemon=True,
    )
    thread.start()
    try:
        result = ready.get(timeout=60)
    except queue.Empty as error:
        release.set()
        thread.join(timeout=5)
        raise LiveGateError("active decoy session did not start") from error
    if isinstance(result, BaseException):
        thread.join(timeout=5)
        raise LiveGateError("active decoy session failed to start") from result
    alias, session_id = result

    def inspect() -> None:
        asyncio.run(
            _inspect_inert_control_context(
                boundary=boundary,
                authenticated_guest_home=authenticated_guest_home,
                fixture_path=fixture_path,
                session_id=session_id,
                forbidden_markers=("[shadow:route-a]", "[shadow:route-b]"),
            )
        )

    return ActiveInertControl(
        alias=alias,
        session_id=session_id,
        _release=release,
        _thread=thread,
        _errors=errors,
        _inspect=inspect,
    )


def build_mission_arguments(
    mission_file: Path, run_id: str, model_settings: Mapping[str, str]
) -> tuple[str, ...]:
    models = _exact_string_mapping(model_settings, _MODEL_FIELDS, "models")
    if not mission_file.is_absolute():
        mission_file = mission_file.resolve()
    if not run_id or any(character.isspace() for character in run_id):
        raise LiveGateError("run ID is invalid")
    return (
        "exec",
        "--mission",
        "--auto",
        "high",
        "--output-format",
        "json",
        "-f",
        str(mission_file),
        "--log-group-id",
        run_id,
        "--model",
        models["orchestrator_model"],
        "--reasoning-effort",
        models["orchestrator_reasoning"],
        "--worker-model",
        models["worker_model"],
        "--worker-reasoning-effort",
        models["worker_reasoning"],
        "--validator-model",
        models["validator_model"],
        "--validator-reasoning-effort",
        models["validator_reasoning"],
        "--cwd",
        str(mission_file.parent),
    )


class LiveRunCounter:
    """An exclusive on-disk claim for the only feasibility Mission slot."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @property
    def count(self) -> int:
        if not self.path.exists():
            return 0
        try:
            metadata = self.path.lstat()
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise LiveGateError("live-run counter is unreadable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or self.path.is_symlink()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or value != {"schema_version": SCHEMA_VERSION, "live_run_count": 1}
        ):
            raise LiveGateError("live-run counter is invalid")
        return 1

    def claim(self) -> None:
        if self.count != 0:
            raise LiveGateError("the feasibility Mission slot is already consumed")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError as error:
            raise LiveGateError("the feasibility Mission slot is already consumed") from error
        try:
            payload = json.dumps(
                {"schema_version": SCHEMA_VERSION, "live_run_count": 1},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory_descriptor = -1
        try:
            directory_descriptor = os.open(self.path.parent, os.O_RDONLY)
            os.fsync(directory_descriptor)
        except OSError as error:
            raise LiveGateError("live-run counter directory sync failed") from error
        finally:
            if directory_descriptor >= 0:
                os.close(directory_descriptor)


class LaunchReservation:
    """A crash-durable one-shot reservation for the authorized live attempt."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def claim(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError as error:
            raise LiveGateError("the authorized live attempt is already reserved") from error
        try:
            payload = json.dumps(
                {"schema_version": SCHEMA_VERSION, "launch_reserved": True},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory_descriptor = -1
        try:
            directory_descriptor = os.open(self.path.parent, os.O_RDONLY)
            os.fsync(directory_descriptor)
        except OSError as error:
            raise LiveGateError("launch reservation directory sync failed") from error
        finally:
            if directory_descriptor >= 0:
                os.close(directory_descriptor)


class PreflightAttemptCounter:
    """A locked, bounded counter for live preflight attempts."""

    def __init__(self, path: Path, limit: int = 5) -> None:
        if limit <= 0:
            raise LiveGateError("preflight attempt limit is invalid")
        self.path = path
        self.limit = limit

    def claim_attempt(self) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise LiveGateError("preflight attempt counter is unavailable") from error
        try:
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or (
                    hasattr(os, "geteuid")
                    and metadata.st_uid != os.geteuid()
                )
            ):
                raise LiveGateError("preflight attempt counter is not private")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            os.lseek(descriptor, 0, os.SEEK_SET)
            payload = os.read(descriptor, 4096)
            if payload:
                try:
                    value = json.loads(payload.decode("ascii"))
                except (UnicodeError, json.JSONDecodeError) as error:
                    raise LiveGateError(
                        "preflight attempt counter is invalid"
                    ) from error
                if (
                    not isinstance(value, dict)
                    or set(value) != {
                        "schema_version",
                        "preflight_attempt_count",
                    }
                    or value.get("schema_version") != SCHEMA_VERSION
                    or not isinstance(
                        value.get("preflight_attempt_count"), int
                    )
                    or isinstance(value.get("preflight_attempt_count"), bool)
                    or not 0 <= int(value["preflight_attempt_count"]) <= self.limit
                ):
                    raise LiveGateError("preflight attempt counter is invalid")
                count = int(value["preflight_attempt_count"])
            else:
                count = 0
            if count >= self.limit:
                raise LiveGateError("preflight attempt limit is exhausted")
            count += 1
            serialized = json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "preflight_attempt_count": count,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.ftruncate(descriptor, 0)
            os.write(descriptor, serialized)
            os.fsync(descriptor)
            return count
        finally:
            os.close(descriptor)


def execute_paid_boundary(
    *,
    preflight: Callable[[], None],
    launch: Callable[[], CommandResult],
    counter: LiveRunCounter,
) -> CommandResult:
    preflight()
    counter.claim()
    return launch()


def validate_live_preflight(
    value: Mapping[str, object],
    authorization: AuthorizationRecord,
    expected_bindings: Mapping[str, str],
    expected_models: Mapping[str, str],
    lima_config: Path,
) -> dict[str, object]:
    required_fields = {
        "schema_version",
        "checks",
        "bindings",
        "models",
        "budget",
        "factory_profile",
        "isolation_manifest",
        "model_catalog",
        "cost_evidence",
    }
    if set(value) != required_fields:
        raise LiveGateError("preflight fields differ from the contract")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise LiveGateError("preflight schema is unsupported")
    checks = value.get("checks")
    if not isinstance(checks, Mapping) or set(checks) != _REQUIRED_PREFLIGHT_CHECKS:
        raise LiveGateError("preflight checks differ from the contract")
    for check_name in sorted(_REQUIRED_PREFLIGHT_CHECKS):
        if checks[check_name] is not True:
            raise LiveGateError(f"preflight check failed: {check_name}")
    bindings = _validate_bindings(value.get("bindings"))
    models = _exact_string_mapping(value.get("models"), _MODEL_FIELDS, "models")
    approved_bindings = _validate_bindings(expected_bindings)
    approved_models = _exact_string_mapping(expected_models, _MODEL_FIELDS, "models")
    if bindings != approved_bindings or authorization.bindings != approved_bindings:
        raise LiveGateError("preflight bindings differ from authorization")
    if models != approved_models or authorization.models != approved_models:
        raise LiveGateError("preflight models differ from authorization")
    validate_model_catalog(value.get("model_catalog"), models)

    profile_value = value.get("factory_profile")
    if not isinstance(profile_value, Mapping):
        raise LiveGateError("running guest Factory profile is missing")
    try:
        profile_result = validate_factory_profile(profile_value)
    except FactoryProfileError as error:
        raise LiveGateError(str(error)) from error
    if (
        profile_result.digest != approved_bindings["factory_profile_digest"]
        or profile_result.activation_enabled is not True
        or profile_value.get("gate_surface_digest")
        != approved_bindings["gate_surface_digest"]
        or profile_value.get("installed_plugin_artifact_digest")
        != approved_bindings["installed_plugin_artifact_digest"]
        or profile_value.get("resolved_plugin_source")
        != f"sha256:{approved_bindings['installed_plugin_artifact_digest']}"
    ):
        raise LiveGateError("running guest Factory profile binding failed")

    isolation_value = value.get("isolation_manifest")
    if not isinstance(isolation_value, Mapping):
        raise LiveGateError("running guest isolation observation is missing")
    try:
        isolation_result = validate_isolation_manifest(
            isolation_value,
            lima_config,
            require_live_canaries=False,
        )
    except IsolationError as error:
        raise LiveGateError(str(error)) from error
    required_live_canaries = {
        "host_read_canary_denied",
        "host_write_canary_unchanged",
        "guest_protected_read_denied",
        "fixture_read_allowed",
    }
    if any(isolation_value.get(field) is not True for field in required_live_canaries):
        raise LiveGateError("running guest isolation canaries failed")
    if isolation_value.get("teardown_confirmed") is not None:
        raise LiveGateError("preflight cannot attest future teardown")
    if (
        isolation_result.config_digest != approved_bindings["isolation_digest"]
        or isolation_result.image_digest.removeprefix("sha256:")
        != approved_bindings["vm_image_digest"]
        or isolation_value.get("lima_version") != approved_bindings["lima_version"]
    ):
        raise LiveGateError("running guest isolation binding failed")

    budget_value = value.get("budget")
    if not isinstance(budget_value, Mapping):
        raise LiveGateError("preflight budget is invalid")
    budget = BudgetLedger.from_mapping(dict(budget_value))
    validate_cost_evidence(value.get("cost_evidence"), budget)
    budget.validate()
    if budget.maximum_additional_exposure != authorization.maximum_additional_exposure:
        raise LiveGateError("preflight exposure differs from authorization")
    return {
        "bindings": bindings,
        "models": models,
        "budget": budget.sanitized(),
        "checks": {name: True for name in sorted(_REQUIRED_PREFLIGHT_CHECKS)},
        "factory_profile_status": profile_result.status,
        "isolation_live_canaries": True,
    }


def _require_true_controls(
    value: object, required_fields: set[str], group_name: str
) -> None:
    if not isinstance(value, Mapping) or set(value) != required_fields:
        raise LiveGateError(f"{group_name} fields differ from the contract")
    for field_name in sorted(required_fields):
        if value[field_name] is not True:
            raise LiveGateError(f"{group_name}.{field_name} is not proven")


def _scan_forbidden(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in _FORBIDDEN_KEYS:
                raise LiveGateError(f"forbidden persisted field: {path}.{key}")
            _scan_forbidden(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _scan_forbidden(item, f"{path}[{index}]")
        return
    if isinstance(value, str):
        if value in _FORBIDDEN_VALUES or value.startswith(("/Users/", "/home/")):
            raise LiveGateError(f"forbidden persisted value: {path}")




def make_live_evidence_record(
    *,
    run_id: str,
    capability: str,
    target_alias: str,
    source_class: str,
    facts: Mapping[str, object],
) -> dict[str, object]:
    if capability not in _CAPABILITY_TRANSITIONS:
        raise LiveGateError("evidence capability is unknown")
    if source_class not in _EVIDENCE_SOURCES:
        raise LiveGateError("evidence source class is not approved")
    if not run_id or not target_alias:
        raise LiveGateError("evidence identity is incomplete")
    payload: dict[str, object] = {
        "run_id": run_id,
        "capability": capability,
        "target_alias": target_alias,
        "transition": _CAPABILITY_TRANSITIONS[capability],
        "source_class": source_class,
        "facts": dict(facts),
    }
    _scan_forbidden(payload)
    digest = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "evidence_id": f"evidence-{digest[:20]}",
        **payload,
        "digest": digest,
    }


def _json_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _live_evidence_binding_values(
    value: Mapping[str, object],
) -> dict[str, str]:
    capabilities = value.get("capabilities")
    if not isinstance(capabilities, Mapping):
        raise LiveGateError("capability observations are missing")
    normalized_capabilities: dict[str, dict[str, object]] = {}
    for name, raw_record in capabilities.items():
        if not isinstance(raw_record, Mapping):
            raise LiveGateError("capability observation is invalid")
        normalized_capabilities[str(name)] = {
            "status": raw_record.get("status"),
            "fallback_basis": raw_record.get("fallback_basis"),
        }
    control_snapshot = {
        "capabilities": normalized_capabilities,
        "identity_controls": value.get("identity_controls"),
        "guidance_controls": value.get("guidance_controls"),
        "blocker_controls": value.get("blocker_controls"),
        "probe_controls": value.get("probe_controls"),
    }
    execution_snapshot = {
        name: value.get(name)
        for name in (
            "run_id",
            "bindings",
            "models",
            "preflight",
            "droid_observations",
            "usage",
            "usage_reconciliation",
            "budget",
            "live_run_count",
            "mission_duration_seconds",
            "evidence_export",
        )
    }
    evidence_export = value.get("evidence_export")
    if not isinstance(evidence_export, Mapping) or not isinstance(
        evidence_export.get("sha256"),
        str,
    ):
        raise LiveGateError("evidence export binding is missing")
    return {
        "control_digest": _json_digest(control_snapshot),
        "execution_digest": _json_digest(execution_snapshot),
        "ledger_digest": str(evidence_export["sha256"]),
    }


def bind_live_evidence_artifacts(
    value: Mapping[str, object],
) -> dict[str, object]:
    result = dict(value)
    binding_values = _live_evidence_binding_values(result)
    raw_registry = result.get("evidence_registry")
    capabilities = result.get("capabilities")
    if not isinstance(raw_registry, list) or not isinstance(capabilities, Mapping):
        raise LiveGateError("live evidence cannot be artifact-bound")
    evidence_id_map: dict[str, str] = {}
    bound_registry: list[dict[str, object]] = []
    for raw_record in raw_registry:
        if not isinstance(raw_record, Mapping):
            raise LiveGateError("live evidence record is invalid")
        facts = raw_record.get("facts")
        if not isinstance(facts, Mapping):
            raise LiveGateError("live evidence facts are invalid")
        bound_record = make_live_evidence_record(
            run_id=str(raw_record.get("run_id", "")),
            capability=str(raw_record.get("capability", "")),
            target_alias=str(raw_record.get("target_alias", "")),
            source_class=str(raw_record.get("source_class", "")),
            facts={**facts, **binding_values},
        )
        evidence_id_map[str(raw_record.get("evidence_id", ""))] = str(
            bound_record["evidence_id"]
        )
        bound_registry.append(bound_record)
    bound_capabilities: dict[str, dict[str, object]] = {}
    for capability, raw_record in capabilities.items():
        if not isinstance(raw_record, Mapping):
            raise LiveGateError("capability observation is invalid")
        raw_ids = raw_record.get("evidence_ids")
        if not isinstance(raw_ids, list):
            raise LiveGateError("capability evidence IDs are invalid")
        try:
            bound_ids = [evidence_id_map[str(item)] for item in raw_ids]
        except KeyError as error:
            raise LiveGateError("capability references unknown evidence") from error
        bound_capabilities[str(capability)] = {
            **raw_record,
            "evidence_ids": bound_ids,
        }
    result["capabilities"] = bound_capabilities
    result["evidence_registry"] = bound_registry
    result["evidence_bindings"] = binding_values
    return result


def load_private_record(path: Path, record_name: str) -> dict[str, object]:
    try:
        parent = path.parent.lstat()
        metadata = path.lstat()
    except OSError as error:
        raise LiveGateError(f"{record_name} record is unavailable") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or path.parent.is_symlink()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (
            hasattr(os, "getuid")
            and (parent.st_uid != os.getuid() or metadata.st_uid != os.getuid())
        )
    ):
        raise LiveGateError(f"{record_name} record is not private")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LiveGateError(f"{record_name} record is invalid JSON") from error
    if not isinstance(value, dict):
        raise LiveGateError(f"{record_name} record is not an object")
    _scan_forbidden(value)
    return value


def _read_private_factory_credential_value(path: Path) -> str:
    try:
        parent = path.parent.lstat()
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise LiveGateError("Factory credential is unavailable") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or path.parent.is_symlink()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (
            hasattr(os, "getuid")
            and (parent.st_uid != os.getuid() or metadata.st_uid != os.getuid())
        )
    ):
        raise LiveGateError("Factory credential is not private")
    if len(raw) > 4097 or b"\x00" in raw:
        raise LiveGateError("Factory credential is invalid")
    try:
        value = raw.decode("utf-8")
    except UnicodeError as error:
        raise LiveGateError("Factory credential is invalid") from error
    if value.endswith("\n"):
        value = value[:-1]
    if not value or "\r" in value or "\n" in value:
        raise LiveGateError("Factory credential is invalid")
    return value


def load_private_factory_credential(path: Path) -> dict[str, str]:
    value = _read_private_factory_credential_value(path)
    if value.startswith("FACTORY_API_KEY="):
        raise LiveGateError("Factory credential is invalid")
    return {"FACTORY_API_KEY": value}


def load_private_factory_environment(path: Path) -> dict[str, str]:
    value = _read_private_factory_credential_value(path)
    prefix = "FACTORY_API_KEY="
    if not value.startswith(prefix) or len(value) == len(prefix):
        raise LiveGateError("Factory credential is invalid")
    return {"FACTORY_API_KEY": value[len(prefix) :]}


def run_authorized_live(
    *,
    preflight_record: Mapping[str, object],
    authorization: AuthorizationRecord,
    expected_bindings: Mapping[str, str],
    model_settings: Mapping[str, str],
    lima_config: Path,
    boundary: DroidCommandBoundary,
    mission_file: Path,
    run_id: str,
    mission_environment: Mapping[str, str],
    counter: LiveRunCounter,
    output_path: Path,
    inert_control: Callable[[], str | ActiveInertControl],
    probe: Callable[[], ProbeEvidence],
    verify_installed_plugin: Callable[[], str],
    observation_supplier: Callable[
        [str, CommandResult, ProbeEvidence, Mapping[str, object]],
        Mapping[str, object],
    ],
) -> dict[str, object]:
    preflight_summary = validate_live_preflight(
        preflight_record,
        authorization,
        expected_bindings,
        model_settings,
        lima_config,
    )
    if counter.count != 0:
        raise LiveGateError("the feasibility Mission slot is already consumed")
    droid_observations = {
        "preflight": boundary.observe("preflight"),
    }
    usage_observations = {
        "pre_run": boundary.capture_usage("pre_run"),
    }
    if (
        usage_observations["pre_run"]["remaining_extra_usage"]
        != preflight_summary["budget"]["remaining_extra_usage"]
    ):
        raise LiveGateError(
            "pre-run Extra Usage differs from the authorized cost ledger"
        )
    probe_evidence = probe()
    if (
        not probe_evidence.zero_tools
        or not probe_evidence.activation_stripped
        or probe_evidence.authoritative_value != "cents"
        or not probe_evidence.internal_session_alias
    ):
        raise LiveGateError("independent probe boundary failed")
    mission_arguments = build_mission_arguments(
        mission_file,
        run_id,
        model_settings,
    )
    droid_observations["pre_mission"] = boundary.observe("pre_mission")
    control_session = inert_control()
    if isinstance(control_session, str):
        inert_alias = control_session
        close_control: Callable[[], None] | None = None
    else:
        inert_alias = control_session.alias
        close_control = control_session.close
    if not inert_alias:
        if close_control is not None:
            close_control()
        raise LiveGateError("the inert SDK control did not produce an alias")
    counter.claim()
    started_at = time.monotonic()
    try:
        mission_result = boundary.run(mission_arguments, mission_environment)
    finally:
        if close_control is not None:
            close_control()
    if (
        verify_installed_plugin()
        != expected_bindings["installed_plugin_artifact_digest"]
    ):
        raise LiveGateError("installed plugin drifted during the Mission")
    duration = time.monotonic() - started_at
    usage_observations["post_run"] = boundary.capture_usage("post_run")
    droid_observations["post_mission"] = boundary.observe("post_mission")
    observations = dict(
        observation_supplier(
            run_id,
            mission_result,
            probe_evidence,
            usage_observations,
        )
    )
    observations["run_id"] = run_id
    observations["bindings"] = dict(expected_bindings)
    observations["models"] = dict(preflight_summary["models"])
    observations["preflight"] = dict(preflight_summary)
    observations["droid_observations"] = droid_observations
    observations["usage"] = usage_observations
    observations["usage_reconciliation"] = reconcile_usage_observations(
        usage_observations
    )
    observations["budget"] = dict(preflight_summary["budget"])
    observations["live_run_count"] = counter.count
    observations["mission_duration_seconds"] = duration
    observations = bind_live_evidence_artifacts(observations)
    candidate = write_candidate_gate(
        output_path,
        observations,
        expected_bindings,
        model_settings,
    )
    if mission_result.returncode != 0 and candidate["candidate_gate_verdict"] != "stop":
        raise LiveGateError("a failed Mission cannot produce a passing gate")
    return candidate


def _validate_live_evidence_registry(
    value: object,
    *,
    run_id: str,
) -> dict[str, dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise LiveGateError("live evidence registry is missing")
    required_fields = {
        "evidence_id",
        "run_id",
        "capability",
        "target_alias",
        "transition",
        "source_class",
        "facts",
        "digest",
    }
    records: dict[str, dict[str, object]] = {}
    for raw_record in value:
        if not isinstance(raw_record, Mapping) or set(raw_record) != required_fields:
            raise LiveGateError("live evidence record fields differ")
        record = dict(raw_record)
        evidence_id = record["evidence_id"]
        capability = record["capability"]
        source_class = record["source_class"]
        facts = record["facts"]
        digest = record["digest"]
        if (
            not isinstance(evidence_id, str)
            or not evidence_id
            or evidence_id in records
            or record["run_id"] != run_id
            or capability not in _CAPABILITY_TRANSITIONS
            or record["transition"] != _CAPABILITY_TRANSITIONS[capability]
            or source_class not in _EVIDENCE_SOURCES
            or not isinstance(record["target_alias"], str)
            or not record["target_alias"]
            or not isinstance(facts, Mapping)
            or not isinstance(digest, str)
        ):
            raise LiveGateError("live evidence record is invalid")
        payload = {
            key: record[key]
            for key in (
                "run_id",
                "capability",
                "target_alias",
                "transition",
                "source_class",
                "facts",
            )
        }
        expected_digest = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        if (
            digest != expected_digest
            or evidence_id != f"evidence-{expected_digest[:20]}"
        ):
            raise LiveGateError("live evidence record digest mismatch")
        records[evidence_id] = record
    return records


def classify_live_observations(
    value: Mapping[str, object],
    expected_bindings: Mapping[str, str],
    expected_models: Mapping[str, str] | None = None,
) -> str:
    _scan_forbidden(value)
    required_root = {
        "schema_version",
        "run_id",
        "bindings",
        "models",
        "preflight",
        "capabilities",
        "evidence_registry",
        "evidence_bindings",
        "identity_controls",
        "guidance_controls",
        "blocker_controls",
        "probe_controls",
        "droid_observations",
        "usage",
        "usage_reconciliation",
        "budget",
        "live_run_count",
        "evidence_export",
        "mission_duration_seconds",
    }
    if set(value) != required_root:
        raise LiveGateError("live observation fields differ from the contract")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise LiveGateError("live observation schema is unsupported")
    if _validate_bindings(value.get("bindings")) != _validate_bindings(expected_bindings):
        raise LiveGateError("live observation bindings differ")
    models = _exact_string_mapping(value.get("models"), _MODEL_FIELDS, "models")
    if expected_models is not None and models != _exact_string_mapping(
        expected_models,
        _MODEL_FIELDS,
        "models",
    ):
        raise LiveGateError("live observation models differ")
    preflight = value.get("preflight")
    if not isinstance(preflight, Mapping) or set(preflight) != {
        "bindings",
        "models",
        "budget",
        "checks",
        "factory_profile_status",
        "isolation_live_canaries",
    }:
        raise LiveGateError("sanitized preflight evidence differs from the contract")
    if (
        _validate_bindings(preflight.get("bindings"))
        != _validate_bindings(expected_bindings)
        or _exact_string_mapping(preflight.get("models"), _MODEL_FIELDS, "models")
        != models
        or preflight.get("budget") != value.get("budget")
        or preflight.get("isolation_live_canaries") is not True
        or preflight.get("factory_profile_status") not in {"pass", "fallback"}
    ):
        raise LiveGateError("sanitized preflight evidence is inconsistent")
    preflight_checks = preflight.get("checks")
    if (
        not isinstance(preflight_checks, Mapping)
        or set(preflight_checks) != _REQUIRED_PREFLIGHT_CHECKS
        or any(preflight_checks[name] is not True for name in preflight_checks)
    ):
        raise LiveGateError("sanitized preflight checks are incomplete")
    run_id = value.get("run_id")
    if not isinstance(run_id, str) or not run_id or any(character.isspace() for character in run_id):
        raise LiveGateError("live observation run ID is invalid")
    evidence_by_id = _validate_live_evidence_registry(
        value.get("evidence_registry"),
        run_id=run_id,
    )
    evidence_bindings = value.get("evidence_bindings")
    expected_evidence_bindings = _live_evidence_binding_values(value)
    if (
        not isinstance(evidence_bindings, Mapping)
        or dict(evidence_bindings) != expected_evidence_bindings
    ):
        raise LiveGateError("live evidence artifact bindings differ")
    for record in evidence_by_id.values():
        facts = record.get("facts")
        if not isinstance(facts, Mapping) or any(
            facts.get(name) != digest
            for name, digest in expected_evidence_bindings.items()
        ):
            raise LiveGateError("capability evidence lacks artifact bindings")
    capabilities_value = value.get("capabilities")
    if (
        not isinstance(capabilities_value, Mapping)
        or set(capabilities_value) != set(CAPABILITY_NAMES)
    ):
        raise LiveGateError("capability observations differ from the gate")
    statuses: dict[str, str] = {}
    referenced_ids: set[str] = set()
    for capability in CAPABILITY_NAMES:
        record = capabilities_value[capability]
        if not isinstance(record, Mapping) or set(record) != {
            "status",
            "fallback_basis",
            "evidence_ids",
        }:
            raise LiveGateError(f"{capability} evidence fields differ")
        status_value = record["status"]
        fallback_basis = record["fallback_basis"]
        evidence_ids = record["evidence_ids"]
        if status_value not in {"pass", "fallback", "stop"}:
            raise LiveGateError(f"{capability} status is invalid")
        expected_basis: str | None
        if status_value == "pass":
            expected_basis = None
        elif status_value == "stop":
            expected_basis = "stop_condition"
        else:
            expected_basis = _FALLBACK_BASES.get(capability)
            if expected_basis is None:
                raise LiveGateError(f"{capability} has no approved fallback")
        if fallback_basis != expected_basis:
            raise LiveGateError(f"{capability} fallback basis is invalid")
        if (
            not isinstance(evidence_ids, list)
            or not evidence_ids
            or len(set(evidence_ids)) != len(evidence_ids)
            or not all(isinstance(item, str) and item for item in evidence_ids)
        ):
            raise LiveGateError(f"{capability} lacks direct evidence IDs")
        try:
            evidence_records = [evidence_by_id[item] for item in evidence_ids]
        except KeyError as error:
            raise LiveGateError(
                f"{capability} references unknown evidence"
            ) from error
        if any(
            evidence["capability"] != capability
            or evidence["transition"] != _CAPABILITY_TRANSITIONS[capability]
            or evidence["run_id"] != run_id
            or evidence["facts"].get("status") != status_value
            for evidence in evidence_records
        ):
            raise LiveGateError(f"{capability} evidence context differs")
        sources = {str(evidence["source_class"]) for evidence in evidence_records}
        minimum_sources = _MINIMUM_CAPABILITY_SOURCES.get(capability, set())
        if status_value != "stop" and not minimum_sources <= sources:
            raise LiveGateError(f"{capability} evidence provenance is incomplete")
        if (
            capability == "hook_event_provenance"
            and status_value == "fallback"
            and not {
                "wrapper_observation",
                "offline_negative_control",
            }
            <= sources
        ):
            raise LiveGateError("hook provenance fallback evidence is incomplete")
        referenced_ids.update(evidence_ids)
        statuses[capability] = str(status_value)
    if referenced_ids != set(evidence_by_id):
        raise LiveGateError("live evidence registry contains unreferenced records")
    identity_controls = value.get("identity_controls")
    if (
        not isinstance(identity_controls, Mapping)
        or set(identity_controls) != _REQUIRED_IDENTITY_CONTROLS
        or not all(
            isinstance(identity_controls[field], bool)
            for field in _REQUIRED_IDENTITY_CONTROLS
        )
    ):
        raise LiveGateError("identity_controls fields differ from the contract")
    for field_name in sorted(_REQUIRED_IDENTITY_CONTROLS):
        if (
            identity_controls[field_name] is not True
            and statuses["distinct_session_and_mission_identity"] != "stop"
        ):
            raise LiveGateError(f"identity_controls.{field_name} is not proven")
    guidance_controls = value.get("guidance_controls")
    if (
        not isinstance(guidance_controls, Mapping)
        or set(guidance_controls) != _REQUIRED_GUIDANCE_CONTROLS
        or not all(
            isinstance(guidance_controls[field], bool)
            for field in _REQUIRED_GUIDANCE_CONTROLS
        )
    ):
        raise LiveGateError("guidance_controls fields differ from the contract")
    for field_name in sorted(_REQUIRED_GUIDANCE_CONTROLS):
        if (
            guidance_controls[field_name] is not True
            and statuses["targeted_guidance_routing"] != "stop"
        ):
            raise LiveGateError(f"guidance_controls.{field_name} is not proven")
    blockers = value.get("blocker_controls")
    if not isinstance(blockers, Mapping) or set(blockers) != {"worker", "mission"}:
        raise LiveGateError("blocker_controls fields differ from the contract")
    for boundary in ("worker", "mission"):
        controls = blockers[boundary]
        if (
            not isinstance(controls, Mapping)
            or set(controls) != _REQUIRED_BLOCKER_CONTROLS
            or not all(
                isinstance(controls[field], bool)
                for field in _REQUIRED_BLOCKER_CONTROLS
            )
        ):
            raise LiveGateError(
                f"blocker_controls.{boundary} fields differ from the contract"
            )
        for field_name in sorted(_REQUIRED_BLOCKER_CONTROLS):
            if (
                controls[field_name] is not True
                and statuses["stop_blocker_behavior"] != "stop"
            ):
                raise LiveGateError(
                    f"blocker_controls.{boundary}.{field_name} is not proven"
                )
    probe = value.get("probe_controls")
    if not isinstance(probe, Mapping) or set(probe) != _REQUIRED_PROBE_CONTROLS:
        raise LiveGateError("probe_controls fields differ from the contract")
    for field_name in sorted(_REQUIRED_PROBE_CONTROLS - {"watched_events"}):
        if (
            not isinstance(probe[field_name], bool)
            or (
                probe[field_name] is not True
                and statuses["independent_probe_boundary"] != "stop"
            )
        ):
            raise LiveGateError(f"probe_controls.{field_name} is not proven")
    if (
        not isinstance(probe["watched_events"], int)
        or isinstance(probe["watched_events"], bool)
        or (
            probe["watched_events"] != 0
            and statuses["independent_probe_boundary"] != "stop"
        )
    ):
        raise LiveGateError("probe_controls.watched_events is not zero")
    observations = value.get("droid_observations")
    if not isinstance(observations, Mapping) or set(observations) != {
        "preflight",
        "pre_mission",
        "post_mission",
    }:
        raise LiveGateError("Droid observations are incomplete")
    expected = _validate_bindings(expected_bindings)
    expected_observation = {
        "version": expected["droid_version"],
        "binary_digest": expected["droid_binary_digest"],
        "auto_update_control": expected["droid_auto_update_control"],
    }
    for stage in ("preflight", "pre_mission", "post_mission"):
        if observations[stage] != expected_observation:
            raise LiveGateError(f"Droid {stage} observation drifted")
    usage = value.get("usage")
    if not isinstance(usage, Mapping) or set(usage) != {"pre_run", "post_run"}:
        raise LiveGateError("pre-run and post-run usage evidence is required")
    for stage in ("pre_run", "post_run"):
        record = usage[stage]
        if (
            not isinstance(record, Mapping)
            or set(record)
            != {
                "status",
                "evidence_type",
                "output_digest",
                "output_bytes",
                "remaining_extra_usage",
            }
            or record.get("status") != "captured"
            or record.get("evidence_type") != "droid-limits"
            or not isinstance(record.get("output_digest"), str)
            or len(str(record["output_digest"])) != 64
            or any(
                character not in "0123456789abcdef"
                for character in str(record["output_digest"])
            )
            or not isinstance(record.get("output_bytes"), int)
            or isinstance(record.get("output_bytes"), bool)
            or int(record["output_bytes"]) <= 0
            or int(record["output_bytes"]) > _MAX_DROID_OUTPUT_BYTES
            or not isinstance(record.get("remaining_extra_usage"), str)
            or not _MONEY_PATTERN.fullmatch(str(record["remaining_extra_usage"]))
        ):
            raise LiveGateError(f"{stage} usage evidence is invalid")
    usage_reconciliation = value.get("usage_reconciliation")
    expected_usage_reconciliation = reconcile_usage_observations(usage)
    if (
        not isinstance(usage_reconciliation, Mapping)
        or dict(usage_reconciliation) != expected_usage_reconciliation
    ):
        raise LiveGateError("post-run usage reconciliation is invalid")
    budget_value = value.get("budget")
    if not isinstance(budget_value, Mapping):
        raise LiveGateError("live budget evidence is invalid")
    base_budget_fields = {
        "pro_subscription",
        "extra_usage_purchases",
        "prior_shadow_model_charges",
        "remaining_extra_usage",
        "maximum_additional_exposure",
        "pay_as_you_go_enabled",
        "cost_evidence_digest",
        "live_run_count",
    }
    if set(budget_value) != base_budget_fields | {
        "committed_spend",
        "maximum_project_exposure",
    }:
        raise LiveGateError("live budget evidence fields differ")
    budget = BudgetLedger.from_mapping(
        {field: budget_value[field] for field in base_budget_fields}
    )
    budget.validate()
    if dict(budget_value) != budget.sanitized():
        raise LiveGateError("live budget evidence is inconsistent")
    if (
        str(usage["pre_run"]["remaining_extra_usage"])
        != format(budget.remaining_extra_usage, ".2f")
    ):
        raise LiveGateError("budget differs from pre-run usage evidence")
    if value.get("live_run_count") != 1:
        raise LiveGateError("live-run count must equal one")
    duration = value.get("mission_duration_seconds")
    if (
        not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or not math.isfinite(duration)
        or duration <= 0
    ):
        raise LiveGateError("Mission duration is invalid")
    evidence_export = value.get("evidence_export")
    if (
        not isinstance(evidence_export, Mapping)
        or set(evidence_export) != {"file_name", "sha256", "record_count"}
        or evidence_export.get("file_name") != "events.jsonl"
        or not isinstance(evidence_export.get("sha256"), str)
        or len(str(evidence_export["sha256"])) != 64
        or any(
            character not in "0123456789abcdef"
            for character in str(evidence_export["sha256"])
        )
        or not isinstance(evidence_export.get("record_count"), int)
        or isinstance(evidence_export.get("record_count"), bool)
        or int(evidence_export["record_count"]) <= 0
    ):
        raise LiveGateError("sanitized evidence export descriptor is invalid")
    return classify_gate(statuses)


def _atomic_private_write(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    if path.is_symlink():
        raise LiveGateError("result path must not be a symlink")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def write_candidate_gate(
    path: Path,
    observations: Mapping[str, object],
    expected_bindings: Mapping[str, str],
    expected_models: Mapping[str, str] | None = None,
) -> dict[str, object]:
    verdict = classify_live_observations(
        observations,
        expected_bindings,
        expected_models,
    )
    candidate = dict(observations)
    candidate["candidate_gate_verdict"] = verdict
    _atomic_private_write(path, candidate)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LiveGateError("candidate gate output is corrupt") from error
    if loaded != candidate:
        raise LiveGateError("candidate gate output verification failed")
    return candidate


def export_sanitized_ledger(
    source_path: Path,
    export_directory: Path,
) -> dict[str, object]:
    try:
        source_metadata = source_path.lstat()
        payload = source_path.read_bytes()
    except OSError as error:
        raise LiveGateError("collector ledger is unavailable for export") from error
    if (
        source_path.is_symlink()
        or not stat.S_ISREG(source_metadata.st_mode)
        or len(payload) > (16 << 20)
    ):
        raise LiveGateError("collector ledger is not exportable")
    export_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(export_directory, 0o700)
    destination = export_directory / "events.jsonl"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".events.jsonl.",
        dir=export_directory,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    export_descriptor: dict[str, object] = {
        "file_name": "events.jsonl",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "record_count": len(payload.splitlines()),
    }
    _verify_exported_ledger(export_directory, export_descriptor)
    return export_descriptor


def _verify_exported_ledger(
    export_directory: Path,
    descriptor: Mapping[str, object],
) -> None:
    ledger_path = export_directory / str(descriptor["file_name"])
    try:
        metadata = ledger_path.lstat()
        payload = ledger_path.read_bytes()
    except OSError as error:
        raise LiveGateError("sanitized evidence ledger is unavailable") from error
    if (
        ledger_path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or len(payload) > (16 << 20)
        or hashlib.sha256(payload).hexdigest() != descriptor["sha256"]
    ):
        raise LiveGateError("sanitized evidence ledger binding failed")
    lines = payload.splitlines()
    if len(lines) != descriptor["record_count"]:
        raise LiveGateError("sanitized evidence ledger record count differs")
    forbidden_fragments = (
        b"ROUTE-",
        b"SHADOW-FEASIBILITY-",
        b"ACK-",
        b"CORRECTION-",
        b"SHADOW_MISSION_RUN_SECRET",
        b"sk-shadow-feasibility",
    )
    if any(fragment in payload for fragment in forbidden_fragments):
        raise LiveGateError("sanitized evidence ledger contains a canary or secret")
    for line in lines:
        try:
            record = json.loads(line)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise LiveGateError("sanitized evidence ledger contains invalid JSON") from error
        if not isinstance(record, dict):
            raise LiveGateError("sanitized evidence ledger record is not an object")
        _scan_forbidden(record)


def _validate_export_directory(export_directory: Path) -> None:
    try:
        directory_metadata = export_directory.lstat()
        entries = list(export_directory.iterdir())
    except OSError as error:
        raise LiveGateError("evidence export directory is unavailable") from error
    if (
        export_directory.is_symlink()
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        or {entry.name for entry in entries} != set(_GUEST_GATE_EXPORT_FILES)
    ):
        raise LiveGateError("evidence export directory differs from the allowlist")
    for entry in entries:
        try:
            metadata = entry.lstat()
        except OSError as error:
            raise LiveGateError("allowlisted evidence file is unavailable") from error
        if (
            entry.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (
                hasattr(os, "getuid")
                and (
                    directory_metadata.st_uid != os.getuid()
                    or metadata.st_uid != os.getuid()
                )
            )
        ):
            raise LiveGateError("allowlisted evidence file is not private")


def finalize_exported_gate(
    export_directory: Path,
    output_path: Path,
    expected_bindings: Mapping[str, str],
    teardown_evidence: Mapping[str, object],
    expected_models: Mapping[str, str] | None = None,
) -> dict[str, object]:
    _validate_export_directory(export_directory)
    candidate_path = export_directory / "gate.candidate.json"
    if not candidate_path.is_file() or candidate_path.is_symlink():
        raise LiveGateError("evidence export is missing the candidate gate")
    try:
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LiveGateError("candidate gate evidence is corrupt") from error
    if not isinstance(candidate, dict):
        raise LiveGateError("candidate gate evidence is not an object")
    recorded_verdict = candidate.pop("candidate_gate_verdict", None)
    candidate_verdict = classify_live_observations(
        candidate,
        expected_bindings,
        expected_models,
    )
    if recorded_verdict != candidate_verdict:
        raise LiveGateError("candidate gate verdict binding failed")
    evidence_export = candidate["evidence_export"]
    assert isinstance(evidence_export, Mapping)
    _verify_exported_ledger(export_directory, evidence_export)
    required_teardown = {"instance_absent", "disk_absent", "credential_removed"}
    if set(teardown_evidence) != required_teardown or not all(
        isinstance(teardown_evidence[field], bool) for field in required_teardown
    ):
        raise LiveGateError("teardown evidence fields differ from the contract")
    teardown_complete = all(
        bool(teardown_evidence[field]) for field in required_teardown
    )
    if not teardown_complete:
        candidate = _reclassify_teardown_failure(candidate, teardown_evidence)
        candidate_verdict = classify_live_observations(
            candidate,
            expected_bindings,
            expected_models,
        )
    live_verdict = candidate_verdict
    complete_success = teardown_complete and live_verdict in {
        "primary-pass",
        "fallback-pass",
    }
    result = dict(candidate)
    result.update(
        {
            "candidate_gate_verdict": candidate_verdict,
            "live_gate_verdict": live_verdict,
            "teardown": dict(teardown_evidence),
            "complete_success": complete_success,
        }
    )
    _scan_forbidden(result)
    _atomic_private_write(output_path, result)
    return result


LimaCommandRunner = Callable[[tuple[str, ...], dict[str, str]], CommandResult]
_GUEST_LIVE_RUN_LEDGER = "/home/shadow/private/live-run.json"
_FEASIBILITY_VM_NAME = "shadow-feasibility"
_GUEST_GATE_EXPORT_PATH = "/home/shadow/output/gate"
_GUEST_GATE_EXPORT_FILES = ("gate.candidate.json", "events.jsonl")
_GUEST_FEASIBILITY_EXECUTABLE = "/home/shadow/venv/bin/shadow-feasibility"
_GUEST_MISSION_TIMEOUT_SECONDS = 1_800


def _default_lima_command_runner(
    arguments: tuple[str, ...],
    environment: dict[str, str],
) -> CommandResult:
    try:
        completed = subprocess.run(
            arguments,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LiveGateError("Lima process boundary failed") from error
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _default_lima_mission_runner(
    arguments: tuple[str, ...],
    environment: dict[str, str],
) -> CommandResult:
    try:
        completed = subprocess.run(
            arguments,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=_GUEST_MISSION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            124,
            "",
            "Lima guest feasibility Mission timed out after 1800 seconds",
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LiveGateError("Lima guest Mission boundary failed") from error
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


class HostLimaFinalizer:
    """Export evidence, destroy the disposable guest, and observe its absence."""
    def __init__(
        self,
        executable: Path,
        expected_version: str,
        command_runner: LimaCommandRunner | None = None,
        instance_directory: Path | None = None,
    ) -> None:
        self.executable = executable.resolve()
        self.expected_version = expected_version
        self._mission_command_runner = (
            command_runner or _default_lima_mission_runner
        )
        self._command_runner = command_runner or _default_lima_command_runner
        self._instance_directory = (
            instance_directory or Path.home() / ".lima" / _FEASIBILITY_VM_NAME
        ).resolve()
        if not _VERSION_PATTERN.fullmatch(expected_version):
            raise LiveGateError("expected Lima version is invalid")
        try:
            metadata = self.executable.stat()
        except OSError as error:
            raise LiveGateError("limactl is unavailable") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise LiveGateError("limactl is not a regular file")

    @staticmethod
    def _environment() -> dict[str, str]:
        allowed = ("HOME", "PATH", "LANG", "LC_ALL", "TERM", "TMPDIR")
        return {key: os.environ[key] for key in allowed if key in os.environ}

    def _run(self, *arguments: str) -> CommandResult:
        try:
            result = self._command_runner(
                (str(self.executable), *arguments),
                self._environment(),
            )
        except Exception:
            return CommandResult(255, "", "Lima command failed")
        output_bytes = len(result.stdout.encode()) + len(result.stderr.encode())
        if output_bytes > _MAX_DROID_OUTPUT_BYTES:
            return CommandResult(255, "", "Lima output exceeded its byte limit")
        return result

    def run_guest_feasibility(
        self,
        arguments: Sequence[str],
    ) -> CommandResult:
        if (
            not arguments
            or arguments[0] != _GUEST_FEASIBILITY_EXECUTABLE
        ):
            raise LiveGateError("guest feasibility command is not approved")
        version_result = self._run("--version")
        version_match = _VERSION_PATTERN.search(
            f"{version_result.stdout}\n{version_result.stderr}"
        )
        if (
            version_result.returncode != 0
            or version_match is None
            or version_match.group("version") != self.expected_version
        ):
            raise LiveGateError("Lima version drift detected before launch")
        try:
            result = self._mission_command_runner(
                (
                    str(self.executable),
                    "shell",
                    _FEASIBILITY_VM_NAME,
                    "--",
                    "env",
                    f"{AUTO_UPDATE_ENV}=false",
                    *arguments,
                ),
                self._environment(),
            )
        except Exception:
            return CommandResult(255, "", "Lima guest Mission command failed")
        output_bytes = len(result.stdout.encode()) + len(result.stderr.encode())
        if output_bytes > _MAX_DROID_OUTPUT_BYTES:
            return CommandResult(
                255,
                "",
                "Lima guest Mission output exceeded its byte limit",
            )
        return result

    def guest_live_run_count(self) -> int:
        result = self._run(
            "shell",
            _FEASIBILITY_VM_NAME,
            "--",
            "cat",
            _GUEST_LIVE_RUN_LEDGER,
        )
        if result.returncode != 0:
            if not result.stdout.strip():
                return 0
            raise LiveGateError("guest live-run counter is unreadable")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise LiveGateError("guest live-run counter is invalid JSON") from error
        if value != {"schema_version": SCHEMA_VERSION, "live_run_count": 1}:
            raise LiveGateError("guest live-run counter is invalid")
        return 1

    @staticmethod
    def _inventory_excludes_instance(payload: str) -> bool:
        if not payload.strip():
            return False
        records: list[object] = []
        try:
            decoded = json.loads(payload)
            records.extend(decoded if isinstance(decoded, list) else [decoded])
        except json.JSONDecodeError:
            try:
                records.extend(
                    json.loads(line)
                    for line in payload.splitlines()
                    if line.strip()
                )
            except json.JSONDecodeError:
                return False
        for record in records:
            if not isinstance(record, Mapping):
                return False
            if record.get("name") == _FEASIBILITY_VM_NAME:
                return False
        return True

    def _capture_guest_disk(self) -> Path | None:
        try:
            instance_metadata = self._instance_directory.lstat()
            disk_path = self._instance_directory / "diffdisk"
            disk_metadata = disk_path.lstat()
        except OSError:
            return None
        if (
            not stat.S_ISDIR(instance_metadata.st_mode)
            or self._instance_directory.is_symlink()
            or not stat.S_ISREG(disk_metadata.st_mode)
            or disk_path.is_symlink()
        ):
            return None
        return disk_path

    def export_and_teardown(
        self,
        host_export_directory: Path,
    ) -> tuple[bool, dict[str, bool], bool]:
        version_result = self._run("--version")
        version_match = _VERSION_PATTERN.search(
            f"{version_result.stdout}\n{version_result.stderr}"
        )
        version_matches = (
            version_result.returncode == 0
            and version_match is not None
            and version_match.group("version") == self.expected_version
        )
        host_export_directory = host_export_directory.resolve()
        export_ready = False
        try:
            parent = host_export_directory.parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            parent_metadata = parent.lstat()
            private_parent = (
                stat.S_ISDIR(parent_metadata.st_mode)
                and not parent.is_symlink()
                and stat.S_IMODE(parent_metadata.st_mode) == 0o700
                and (
                    not hasattr(os, "getuid")
                    or parent_metadata.st_uid == os.getuid()
                )
            )
            if private_parent and not host_export_directory.exists():
                host_export_directory.mkdir(mode=0o700)
                export_ready = True
        except OSError:
            export_ready = False
        copy_results: list[CommandResult] = []
        if export_ready:
            for file_name in _GUEST_GATE_EXPORT_FILES:
                copy_results.append(
                    self._run(
                        "copy",
                        (
                            f"{_FEASIBILITY_VM_NAME}:"
                            f"{_GUEST_GATE_EXPORT_PATH}/{file_name}"
                        ),
                        str(host_export_directory / file_name),
                    )
                )
        export_complete = (
            export_ready
            and len(copy_results) == len(_GUEST_GATE_EXPORT_FILES)
            and all(result.returncode == 0 for result in copy_results)
            and {path.name for path in host_export_directory.iterdir()}
            == set(_GUEST_GATE_EXPORT_FILES)
        )

        guest_disk = self._capture_guest_disk()
        stop_result = self._run("stop", _FEASIBILITY_VM_NAME)
        delete_result = (
            self._run("delete", _FEASIBILITY_VM_NAME)
            if stop_result.returncode == 0
            else CommandResult(1, "", "instance stop failed")
        )
        inventory = self._run("list", "--json")
        instance_absent = (
            stop_result.returncode == 0
            and delete_result.returncode == 0
            and inventory.returncode == 0
            and self._inventory_excludes_instance(inventory.stdout)
        )
        disk_absent = (
            guest_disk is not None
            and not guest_disk.exists()
            and not self._instance_directory.exists()
        )
        teardown = {
            "instance_absent": instance_absent,
            "disk_absent": disk_absent,
            "credential_removed": disk_absent,
        }
        return export_complete, teardown, version_matches


def _write_failed_host_gate(
    output_path: Path,
    expected_bindings: Mapping[str, str],
    teardown_evidence: Mapping[str, bool],
    failure_stage: str,
    expected_models: Mapping[str, str] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "bindings": _validate_bindings(expected_bindings),
        "candidate_gate_verdict": "stop",
        "live_gate_verdict": "stop",
        "teardown": dict(teardown_evidence),
        "complete_success": False,
        "failure_stage": failure_stage,
    }
    if expected_models is not None:
        result["models"] = _exact_string_mapping(
            expected_models,
            _MODEL_FIELDS,
            "models",
        )
    _scan_forbidden(result)
    _atomic_private_write(output_path, result)
    return result


def _reclassify_teardown_failure(
    candidate: Mapping[str, object],
    teardown_evidence: Mapping[str, bool],
) -> dict[str, object]:
    capabilities = candidate.get("capabilities")
    registry = candidate.get("evidence_registry")
    if not isinstance(capabilities, Mapping) or not isinstance(registry, list):
        raise LiveGateError("candidate gate evidence is unavailable for teardown")
    isolation_records = [
        record
        for record in registry
        if isinstance(record, Mapping)
        and record.get("capability") == "disposable_isolation"
    ]
    if not isolation_records:
        raise LiveGateError("candidate isolation evidence is unavailable")
    replacement = make_live_evidence_record(
        run_id=str(candidate.get("run_id", "")),
        capability="disposable_isolation",
        target_alias=str(isolation_records[0].get("target_alias", "")),
        source_class="host_teardown",
        facts={
            "instance_absent": teardown_evidence.get("instance_absent") is True,
            "disk_absent": teardown_evidence.get("disk_absent") is True,
            "credential_removed": teardown_evidence.get("credential_removed") is True,
            "status": "stop",
        },
    )
    updated_capabilities = {
        str(name): dict(record)
        for name, record in capabilities.items()
        if isinstance(record, Mapping)
    }
    updated_capabilities["disposable_isolation"] = {
        "status": "stop",
        "fallback_basis": "stop_condition",
        "evidence_ids": [replacement["evidence_id"]],
    }
    updated = {
        **candidate,
        "capabilities": updated_capabilities,
        "evidence_registry": [
            record
            for record in registry
            if isinstance(record, Mapping)
            and record.get("capability") != "disposable_isolation"
        ]
        + [replacement],
    }
    bound = bind_live_evidence_artifacts(updated)
    verdict = classify_live_observations(
        bound,
        expected_bindings=dict(candidate.get("bindings", {})),
        expected_models=dict(candidate.get("models", {})),
    )
    if verdict != "stop":
        raise LiveGateError("teardown failure did not stop the gate")


    return bound
def finalize_host_gate(
    *,
    finalizer: HostLimaFinalizer,
    host_export_directory: Path,
    output_path: Path,
    expected_bindings: Mapping[str, str],
    expected_models: Mapping[str, str] | None = None,
    host_claim_valid: bool = True,
    guest_execution_valid: bool = True,


    guest_failure_stage: str = "guest_execution",
) -> dict[str, object]:
    export_complete, teardown, version_matches = finalizer.export_and_teardown(
        host_export_directory
    )
    if not version_matches:
        return _write_failed_host_gate(
            output_path,
            expected_bindings,
            teardown,
            "lima_version",
            expected_models,
        )
    if not host_claim_valid:
        return _write_failed_host_gate(
            output_path,
            expected_bindings,
            teardown,
            "host_live_run_claim",
            expected_models,
        )
    if not guest_execution_valid:
        return _write_failed_host_gate(
            output_path,
            expected_bindings,
            teardown,
            guest_failure_stage,
            expected_models,
        )
    if not export_complete:
        return _write_failed_host_gate(
            output_path,
            expected_bindings,
            teardown,
            "evidence_export",
            expected_models,
        )
    try:
        return finalize_exported_gate(
            host_export_directory,
            output_path,
            expected_bindings,
            teardown,
            expected_models,
        )
    except LiveGateError:
        return _write_failed_host_gate(
            output_path,
            expected_bindings,
            teardown,
            "evidence_validation",
            expected_models,
        )
