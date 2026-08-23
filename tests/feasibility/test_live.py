import asyncio
import hashlib
import json
import os
import shutil
from pathlib import Path
import stat
import sys
import time

import pytest
import shadow_mission.feasibility as feasibility_module
import shadow_mission.live as live_module

from shadow_mission.feasibility import (
    CAPABILITY_NAMES,
    build_parser,
    prepare_live_workspace,
    run_host_claim_command,
    run_host_live_gate_command,
    run_capture_isolation_canaries_command,
)
from shadow_mission.evidence import FrozenObservation
from shadow_mission.live import (
    AUTO_UPDATE_ENV,
    AuthorizationRecord,
    BudgetLedger,
    CommandResult,
    DroidCommandBoundary,
    HostLimaFinalizer,
    LiveGateError,
    LiveRunCounter,
    PreflightAttemptCounter,
    build_mission_arguments,
    build_cost_and_budget_evidence,
    build_model_catalog_evidence,
    bind_live_evidence_artifacts,
    classify_live_observations,
    execute_paid_boundary,
    load_private_factory_credential,
    load_private_factory_environment,
    load_private_record,
    finalize_host_gate,
    finalize_exported_gate,
    make_live_evidence_record,
    ProbeEvidence,
    TransientProbeError,
    UnsafeProbeError,
    reconcile_usage_observations,
    run_bounded_probe_attempts,
    run_authorized_live,
    start_inert_control_session,
    validate_live_preflight,
    write_candidate_gate,
)
from shadow_mission.profile import validate_factory_profile


class RecordingRunner:
    def __init__(self, outputs: list[CommandResult] | None = None) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.outputs = list(outputs or [])

    def __call__(
        self, arguments: tuple[str, ...], environment: dict[str, str]
    ) -> CommandResult:
        self.calls.append((arguments, environment))
        if self.outputs:
            return self.outputs.pop(0)
        return CommandResult(0, "", "")
def captured_usage(
    arguments: tuple[str, ...],
    environment: dict[str, str],
    input_text: str,
) -> CommandResult:
    assert arguments[0].endswith("droid")
    assert environment[AUTO_UPDATE_ENV] == "false"
    assert input_text == "/limits\n/exit\n"
    return CommandResult(0, "Extra Usage balance: $10.00", "")




def binary(tmp_path: Path, content: bytes = b"pinned-droid") -> tuple[Path, str]:
    path = tmp_path / "droid"
    path.write_bytes(content)
    path.chmod(0o700)
    return path, hashlib.sha256(content).hexdigest()


def live_factory_profile(
    gate_surface_digest: str = "d" * 64,
    artifact_digest: str = "e" * 64,
) -> dict[str, object]:
    profile = json.loads(
        Path("tests/fixtures/feasibility/factory-profile.json").read_text()
    )
    profile["gate_surface_digest"] = gate_surface_digest
    profile["installed_plugin_artifact_digest"] = artifact_digest
    profile["resolved_plugin_source"] = f"sha256:{artifact_digest}"
    profile["shadow_activation"] = True
    return profile


def live_isolation_manifest() -> dict[str, object]:
    manifest = json.loads(
        Path("tests/fixtures/feasibility/isolation-manifest.json").read_text()
    )
    for field in (
        "host_read_canary_denied",
        "host_write_canary_unchanged",
        "guest_protected_read_denied",
        "fixture_read_allowed",
        "guest_mount_table_clean",
        "guest_visible_paths_allowlisted",
    ):
        manifest[field] = True
    manifest["teardown_confirmed"] = None
    manifest["phase"] = "live-preflight"
    return manifest


def bindings(digest: str = "a" * 64) -> dict[str, str]:
    profile = live_factory_profile()
    return {
        "droid_version": "0.197.0",
        "droid_installation_channel": "factory-npm-platform-tarball",
        "droid_binary_digest": digest,
        "droid_auto_update_control": "npm-build-disabled-and-env-false",
        "plugin_version": "0.1.0",
        "droid_sdk_version": "0.2.0",
        "lima_version": "2.2.0",
        "vm_image_digest": "7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc",
        "factory_profile_digest": validate_factory_profile(profile).digest,
        "isolation_digest": hashlib.sha256(
            Path("ops/lima/shadow-feasibility.yaml").read_bytes()
        ).hexdigest(),
        "gate_surface_digest": "d" * 64,
        "installed_plugin_artifact_digest": "e" * 64,
    }


def models() -> dict[str, str]:
    return {
        "orchestrator_model": "gpt-5.6-terra",
        "orchestrator_reasoning": "high",
        "worker_model": "gpt-5.4-mini",
        "worker_reasoning": "high",
        "validator_model": "gpt-5.4-mini",
        "validator_reasoning": "high",
        "probe_model": "gpt-5.6-luna",
        "probe_reasoning": "medium",
    }


def model_catalog() -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "source": "droid-model-selector",
        "captured_without_model_call": True,
        "output_digest": "a" * 64,
        "available_models": {
            "gpt-5.4-mini": ["low", "medium", "high", "xhigh"],
            "gpt-5.6-luna": [
                "none",
                "low",
                "medium",
                "high",
                "xhigh",
                "max",
            ],
            "gpt-5.6-terra": [
                "none",
                "low",
                "medium",
                "high",
                "xhigh",
                "max",
            ],
        },
        "runtime_settings": {
            "model_id": "gpt-5.4-mini",
            "reasoning_effort": "high",
            "sandbox_enabled": True,
            "sandbox_mode": "whole-process",
            "restrict_tool_ids": [],
        },
        "mcp_servers": [],
    }


def cost_evidence() -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "source": "droid-limits-and-project-ledger",
        "captured_without_model_call": True,
        "output_digest": "f" * 64,
        "pro_subscription": "10.00",
        "extra_usage_purchases": "10.00",
        "prior_shadow_model_charges": "0.00",
        "remaining_extra_usage": "10.00",
        "pay_as_you_go_enabled": False,
        "live_run_count": 0,
    }


def authorization_mapping(
    expected_bindings: dict[str, str],
) -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "authorized_by": "Scott",
        "authorized_at": "2026-08-16T23:00:00Z",
        "vm_create_and_delete": True,
        "install_local_plugin": True,
        "factory_configuration_changes": [
            "install shadow-mission user plugin"
        ],
        "exactly_one_paid_mission": True,
        "initial_project_budget": "30.00",
        "hard_project_stop": "50.00",
        "maximum_additional_exposure": "10.00",
        "sanitized_evidence_export": True,
        "mandatory_vm_disk_deletion": True,
        "bindings": expected_bindings,
        "models": models(),
    }


def authorization(expected_bindings: dict[str, str]) -> AuthorizationRecord:
    return AuthorizationRecord.from_mapping(
        authorization_mapping(expected_bindings)
    )


def live_budget() -> dict[str, object]:
    return {
        "pro_subscription": "10.00",
        "extra_usage_purchases": "10.00",
        "prior_shadow_model_charges": "0.00",
        "remaining_extra_usage": "10.00",
        "maximum_additional_exposure": "10.00",
        "pay_as_you_go_enabled": False,
        "cost_evidence_digest": "f" * 64,
        "live_run_count": 0,
    }


def preflight_record(expected_bindings: dict[str, str]) -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "checks": {
            "offline_dry_run": True,
            "lima_manifest": True,
            "guest_droid_installed": True,
            "guest_droid_checksum": True,
            "automatic_updates_disabled": True,
            "guest_authentication": True,
            "factory_pro": True,
            "extra_usage": True,
            "usage_evidence": True,
            "models_and_reasoning": True,
            "factory_profile_inventory": True,
            "plugin_inventory": True,
            "managed_configuration_measurable": True,
            "unknown_inherited_surfaces_absent": True,
            "sealed_fixture_binding": True,
            "installed_artifact_binding": True,
            "isolation_binding": True,
            "same_project_decoy_planned": True,
            "no_prior_feasibility_mission": True,
            "teardown_ready": True,
            "evidence_export_ready": True,
        },
        "bindings": expected_bindings,
        "models": models(),
        "factory_profile": live_factory_profile(),
        "isolation_manifest": live_isolation_manifest(),
        "budget": live_budget(),
        "model_catalog": model_catalog(),
        "cost_evidence": cost_evidence(),
    }


def passing_observations(expected_bindings: dict[str, str]) -> dict[str, object]:
    run_id = "run-safe-alias"
    sources_by_capability = {
        "run_transport_integrity": (
            "transport_authenticated",
            "offline_negative_control",
        ),
        "hook_event_provenance": ("hook_authenticated",),
        "disposable_isolation": ("host_preflight",),
        "clean_factory_profile": ("host_preflight",),
        "session_hooks": ("hook_authenticated",),
        "distinct_session_and_mission_identity": (
            "factory_process",
            "wrapper_observation",
        ),
        "live_transcript_access": ("wrapper_observation",),
        "targeted_guidance_routing": (
            "hook_authenticated",
            "wrapper_observation",
        ),
        "stop_blocker_behavior": (
            "independent_probe",
            "offline_negative_control",
            "wrapper_observation",
        ),
        "role_mapping": ("wrapper_observation",),
        "independent_probe_boundary": ("independent_probe",),
    }
    evidence_registry = [
        make_live_evidence_record(
            run_id=run_id,
            capability=capability,
            target_alias="target-safe-alias",
            source_class=source,
            facts={"status": "pass"},
        )
        for capability, sources in sources_by_capability.items()
        for source in sources
    ]
    capabilities = {
        name: {
            "status": "pass",
            "fallback_basis": None,
            "evidence_ids": [
                record["evidence_id"]
                for record in evidence_registry
                if record["capability"] == name
            ],
        }
        for name in CAPABILITY_NAMES
    }
    ledger = b'{"event_id":"safe","schema_version":"0.1"}\n'
    budget = BudgetLedger.from_mapping(live_budget()).sanitized()
    sanitized_preflight = {
        "bindings": expected_bindings,
        "models": models(),
        "budget": budget,
        "checks": preflight_record(expected_bindings)["checks"],
        "factory_profile_status": "pass",
        "isolation_live_canaries": True,
    }
    usage = {
        stage: {
            "status": "captured",
            "evidence_type": "droid-limits",
            "output_digest": hashlib.sha256(stage.encode()).hexdigest(),
            "output_bytes": len(stage),
            "remaining_extra_usage": (
                "10.00" if stage == "pre_run" else "9.50"
            ),
        }
        for stage in ("pre_run", "post_run")
    }
    observations = {
        "schema_version": "0.1",
        "run_id": run_id,
        "bindings": expected_bindings,
        "models": models(),
        "preflight": sanitized_preflight,
        "capabilities": capabilities,
        "evidence_registry": evidence_registry,
        "identity_controls": {
            "independent_mission_correlation": True,
            "same_project_decoy_excluded": True,
            "shadow_sdk_sessions_excluded": True,
        },
        "guidance_controls": {
            "worker_a_delivered": True,
            "worker_a_acknowledged": True,
            "worker_b_delivered": True,
            "worker_b_acknowledged": True,
            "siblings_excluded": True,
            "orchestrator_excluded": True,
            "decoy_excluded": True,
            "repeated_markers_filtered": True,
        },
        "blocker_controls": {
            "worker": {
                "direct_evidence": True,
                "independent_probe": True,
                "probe_preceded_block": True,
                "completion_blocked": True,
                "retry_durable": True,
                "forgery_rejected": True,
                "replay_rejected": True,
                "cross_run_rejected": True,
                "stale_generation_rejected": True,
                "expired_state_rejected": True,
                "collector_loss_blocked": True,
                "correction_resolved": True,
                "completion_released": True,
                "factory_block_observed": True,
                "factory_release_observed": True,
            },
            "mission": {
                "direct_evidence": True,
                "independent_probe": True,
                "probe_preceded_block": True,
                "completion_blocked": True,
                "retry_durable": True,
                "forgery_rejected": True,
                "replay_rejected": True,
                "cross_run_rejected": True,
                "stale_generation_rejected": True,
                "expired_state_rejected": True,
                "collector_loss_blocked": True,
                "correction_resolved": True,
                "completion_released": True,
                "factory_block_observed": True,
                "factory_release_observed": True,
            },
        },
        "probe_controls": {
            "zero_tools": True,
            "activation_stripped": True,
            "watched_events": 0,
            "schema_valid": True,
            "sdk_process_stable": True,
            "citations_match_oracle": True,
            "preceded_blockers": True,
        },
        "droid_observations": {
            stage: {
                "version": "0.197.0",
                "binary_digest": expected_bindings["droid_binary_digest"],
                "auto_update_control": "npm-build-disabled-and-env-false",
            }
            for stage in ("preflight", "pre_mission", "post_mission")
        },
        "evidence_export": {
            "file_name": "events.jsonl",
            "sha256": hashlib.sha256(ledger).hexdigest(),
            "record_count": 1,
        },
        "usage": usage,
        "usage_reconciliation": reconcile_usage_observations(usage),
        "budget": budget,
        "live_run_count": 1,
        "mission_duration_seconds": 120,
    }
    return bind_live_evidence_artifacts(observations)


def test_droid_boundary_sets_update_control_for_every_process(tmp_path: Path) -> None:
    executable, digest = binary(tmp_path)
    runner = RecordingRunner(
        [CommandResult(0, "0.197.0\n", ""), CommandResult(0, "ok", "")]
    )
    boundary = DroidCommandBoundary(
        executable=executable,
        expected_version="0.197.0",
        expected_digest=digest,
        installation_channel="factory-npm-platform-tarball",
        command_runner=runner,
    )

    observation = boundary.observe("preflight")
    boundary.run(("plugin", "list"))

    assert observation["version"] == "0.197.0"
    assert len(runner.calls) == 2
    assert all(call[1][AUTO_UPDATE_ENV] == "false" for call in runner.calls)
    assert all(call[0][0] == str(executable.resolve()) for call in runner.calls)


def test_droid_boundary_adds_only_the_private_guest_credential(
    tmp_path: Path,
) -> None:
    executable, digest = binary(tmp_path)
    runner = RecordingRunner([CommandResult(0, "0.197.0\n", "")])
    boundary = DroidCommandBoundary(
        executable=executable,
        expected_version="0.197.0",
        expected_digest=digest,
        installation_channel="factory-npm-platform-tarball",
        command_runner=runner,
        credential_environment={"FACTORY_API_KEY": "guest-key-sentinel"},
    )

    boundary.observe("preflight")

    assert runner.calls[0][1]["FACTORY_API_KEY"] == "guest-key-sentinel"
    with pytest.raises(LiveGateError, match="cannot be overridden"):
        boundary.run(
            ("--version",),
            {"FACTORY_API_KEY": "different-key"},
        )


def test_model_validation_uses_only_a_bound_no_model_observation(
    tmp_path: Path,
) -> None:
    executable, digest = binary(tmp_path)
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def runner(
        arguments: tuple[str, ...],
        environment: dict[str, str],
    ) -> CommandResult:
        calls.append((arguments, environment))
        return CommandResult(0, "Available tools: Read", "")

    boundary = DroidCommandBoundary(
        executable,
        "0.197.0",
        digest,
        "factory-npm-platform-tarball",
        runner,
    )

    boundary.validate_model_settings(models(), model_catalog())
    missing = model_catalog()
    del missing["available_models"]["gpt-5.6-terra"]
    with pytest.raises(LiveGateError, match="catalog inventory"):
        boundary.validate_model_settings(models(), missing)

    assert calls == []




def test_model_catalog_evidence_is_derived_from_sdk_inventory() -> None:
    observed = [
        {
            "id": "gpt-5.4-mini",
            "supported_reasoning_efforts": ["low", "medium", "high", "xhigh"],
        },
        {
            "id": "gpt-5.6-luna",
            "supported_reasoning_efforts": [
                "none",
                "low",
                "medium",
                "high",
                "xhigh",
                "max",
            ],
        },
        {
            "id": "gpt-5.6-terra",
            "supported_reasoning_efforts": [
                "none",
                "low",
                "medium",
                "high",
                "xhigh",
                "max",
            ],
        },
        {
            "id": "unselected-model",
            "supported_reasoning_efforts": ["none"],
        },
    ]

    runtime_settings = {
        "model_id": "gpt-5.4-mini",
        "reasoning_effort": "high",
        "sandbox_enabled": True,
        "sandbox_mode": "whole-process",
        "restrict_tool_ids": [],
    }
    evidence = build_model_catalog_evidence(observed, runtime_settings, [])

    assert evidence["captured_without_model_call"] is True
    assert set(evidence["available_models"]) == {
        "gpt-5.4-mini",
        "gpt-5.6-luna",
        "gpt-5.6-terra",
    }
    assert len(str(evidence["output_digest"])) == 64
    observed[0]["supported_reasoning_efforts"] = ["high"]

    with pytest.raises(LiveGateError, match="reasoning inventory drifted"):
        build_model_catalog_evidence(observed, runtime_settings, [])

def test_active_decoy_close_propagates_post_start_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_after_start(**arguments: object) -> str:
        ready = arguments["ready"]
        release = arguments["release"]
        assert callable(ready)
        ready(("decoy-safe-alias", "raw-decoy-session"))
        while not release.is_set():  # type: ignore[union-attr]
            await asyncio.sleep(0.001)
        raise LiveGateError("pinned Droid process drifted")

    monkeypatch.setattr(
        live_module,
        "_run_inert_control_session",
        fail_after_start,
    )
    control = start_inert_control_session(
        boundary=object(),  # type: ignore[arg-type]
        authenticated_guest_home=tmp_path,
        fixture_path=tmp_path,
        model="probe-model",
        reasoning="low",
        alias_secret="secret",
        internal=False,
    )

    with pytest.raises(LiveGateError, match="active decoy session failed"):
        control.close()


def test_active_decoy_close_fails_when_context_inspection_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run_until_release(**arguments: object) -> str:
        ready = arguments["ready"]
        release = arguments["release"]
        assert callable(ready)
        ready(("decoy-safe-alias", "raw-decoy-session"))
        while not release.is_set():  # type: ignore[union-attr]
            await asyncio.sleep(0.001)
        return "decoy-safe-alias"

    async def reject_context(**_: object) -> None:
        raise LiveGateError("targeted guidance entered the decoy context")

    monkeypatch.setattr(
        live_module,
        "_run_inert_control_session",
        run_until_release,
    )
    monkeypatch.setattr(
        live_module,
        "_inspect_inert_control_context",
        reject_context,
    )
    control = start_inert_control_session(
        boundary=object(),  # type: ignore[arg-type]
        authenticated_guest_home=tmp_path,
        fixture_path=tmp_path,
        model="probe-model",
        reasoning="low",
        alias_secret="secret",
        internal=False,
    )

    with pytest.raises(
        LiveGateError,
        match="targeted guidance entered the decoy context",
    ):
        control.close()

def test_external_blocker_registry_is_frozen_private_and_digest_bound(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "worker-conflict-active.json"
    records = [
        FrozenObservation(
            observation_id="worker-conflict-direct",
            run_id="run-safe",
            target_id="session-safe-alias",
            risk_id="worker-conflict",
            transition="blocker_create",
            kind="direct_evidence",
            status="observed",
            source_class="external_frozen",
        ),
        FrozenObservation(
            observation_id="probe-safe-worker-conflict",
            run_id="run-safe",
            target_id="session-safe-alias",
            risk_id="worker-conflict",
            transition="blocker_create",
            kind="probe_confirmation",
            status="confirmed",
            source_class="external_frozen",
        ),
    ]

    registry = feasibility_module._freeze_observation_registry(path, records)

    registry.authorize(
        provenance_status="untrusted_provenance",
        transition="blocker_create",
        observation_ids=(
            "worker-conflict-direct",
            "probe-safe-worker-conflict",
        ),
        run_id="run-safe",
        target_id="session-safe-alias",
        risk_id="worker-conflict",
    )
    assert path.stat().st_mode & 0o777 == 0o600
    assert "factory-raw-session" not in path.read_text()


@pytest.mark.parametrize("encoded_context", ["{}", '{"text":"[shadow:route-a]"}'])
def test_decoy_context_inspection_uses_session_snapshot_without_a_model_turn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encoded_context: str,
) -> None:
    calls: list[str] = []

    class FakeBoundary:
        executable = tmp_path / "droid"

        def _verify_binary(self) -> None:
            calls.append("verify")

        def runtime_environment(
            self,
            values: dict[str, str],
        ) -> dict[str, str]:
            return values

    class FakeTransport:
        pid = 7319

        def __init__(self, **_: object) -> None:
            pass

    class FakeSessionSnapshot:
        def model_dump_json(self) -> str:
            return encoded_context

    class FakeClient:
        def __init__(self, **_: object) -> None:
            pass

        async def connect(self) -> None:
            calls.append("connect")

        async def load_session(self, **_: object) -> object:
            calls.append("load_session")
            return __import__("types").SimpleNamespace(
                session=FakeSessionSnapshot(),
            )

        async def close(self) -> None:
            calls.append("close")

    monkeypatch.setattr("droid_sdk.transport.ProcessTransport", FakeTransport)
    monkeypatch.setattr("droid_sdk.client.DroidClient", FakeClient)
    invocation = live_module._inspect_inert_control_context(
        boundary=FakeBoundary(),  # type: ignore[arg-type]
        authenticated_guest_home=tmp_path,
        fixture_path=tmp_path,
        session_id="raw-decoy-session",
        forbidden_markers=("[shadow:route-a]", "[shadow:route-b]"),
    )
    if "route-a" in encoded_context:
        with pytest.raises(
            LiveGateError,
            match="targeted guidance entered the decoy context",
        ):
            asyncio.run(invocation)
    else:
        asyncio.run(invocation)
    assert calls == ["verify", "connect", "load_session", "verify", "close"] or (
        calls == ["verify", "connect", "load_session", "close"]
        and "route-a" in encoded_context
    )


def test_host_isolation_canary_capture_persists_only_boolean_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limactl = tmp_path / "limactl"
    limactl.write_text("#!/bin/sh\n")
    limactl.chmod(0o700)
    observed: list[tuple[str, ...]] = []

    def fake_run(
        arguments: tuple[str, ...],
        **_: object,
    ) -> object:
        observed.append(tuple(arguments))
        if arguments[1:] == ("--version",):
            return __import__("subprocess").CompletedProcess(
                arguments,
                0,
                "limactl version 2.2.0\n",
                "",
            )
        if arguments[1:] == ("list", "shadow-feasibility", "--json"):
            return __import__("subprocess").CompletedProcess(
                arguments,
                0,
                json.dumps(
                    {
                        "name": "shadow-feasibility",
                        "status": "Running",
                        "config": {
                            "images": [
                                {
                                    "digest": (
                                        "sha256:7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc"
                                    )
                                }
                            ],
                            "mounts": [],
                            "ssh": {"forwardAgent": False},
                            "propagateProxyEnv": False,
                            "containerd": {"system": False, "user": False},
                        },
                    }
                ),
                "",
            )
        if "findmnt" in arguments:
            return __import__("subprocess").CompletedProcess(
                arguments,
                0,
                json.dumps(
                    {
                        "filesystems": [
                            {
                                "target": "/",
                                "source": "/dev/vda1",
                                "fstype": "ext4",
                                "options": "rw,relatime",
                            }
                        ]
                    }
                ),
                "",
            )
        return __import__("subprocess").CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(feasibility_module.subprocess, "run", fake_run)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    output = private / "isolation-canaries.json"
    options = build_parser().parse_args(
        [
            "--capture-isolation-canaries",
            "--limactl-binary",
            str(limactl),
            "--output",
            str(output),
        ]
    )

    result = run_capture_isolation_canaries_command(options, tmp_path)

    record = json.loads(output.read_text())
    encoded = json.dumps(record, sort_keys=True)
    assert result["status"] == "isolation-canaries-pass"
    assert all(record["canaries"].values())
    assert "shadow-feasibility-host-canary-" not in encoded
    host_canary_argument = next(
        argument
        for command in observed
        for argument in command
        if "shadow-feasibility-host-canary-" in argument
    )
    assert not Path(host_canary_argument).exists()


@pytest.mark.parametrize(
    ("mount", "expected"),
    [
        (
            {
                "target": "/",
                "source": "/dev/vda1",
                "fstype": "ext4",
                "options": "rw,relatime",
            },
            True,
        ),
        (
            {
                "target": "/mnt/host",
                "source": "host:/export",
                "fstype": "nfs4",
                "options": "rw",
            },
            False,
        ),
        (
            {
                "target": "/var/host",
                "source": "/dev/vda1",
                "fstype": "ext4",
                "options": "rw,bind",
            },
            False,
        ),
        (
            {
                "target": "/mnt/extra",
                "source": "/dev/vdb1",
                "fstype": "ext4",
                "options": "rw",
            },
            False,
        ),
    ],
)
def test_active_mount_inventory_matches_only_the_sealed_policy(
    mount: dict[str, str],
    expected: bool,
) -> None:
    assert feasibility_module._mount_matches_sealed_policy(mount) is expected



def test_live_workspace_is_writable_without_mutating_the_sealed_fixture(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "sealed-fixture"
    fixture.mkdir(mode=0o700)
    visible = {
        "mission.md": "sealed mission\n",
        "api-schema.json": "{}\n",
        "db-schema.sql": "select 1;\n",
        "stale-guide.md": "stale\n",
    }
    for name, content in visible.items():
        path = fixture / name
        path.write_text(content)
        path.chmod(0o400)
    (fixture / "oracle.json").write_text('{"answer":"protected"}\n')
    (fixture / "oracle.json").chmod(0o400)
    fixture.chmod(0o500)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)

    workspace = prepare_live_workspace(fixture, runtime)
    (workspace / "mission.md").write_text("working mission\n")
    (workspace / "worker-a.txt").write_text("result\n")

    assert (fixture / "mission.md").read_text() == "sealed mission\n"
    assert (workspace / "worker-a.txt").read_text() == "result\n"
    assert not (workspace / "oracle.json").exists()


def test_usage_capture_is_update_disabled_bounded_and_sanitized(
    tmp_path: Path,
) -> None:
    executable, digest = binary(tmp_path)
    seen: list[tuple[tuple[str, ...], dict[str, str], str]] = []

    def interactive(
        arguments: tuple[str, ...],
        environment: dict[str, str],
        input_text: str,
    ) -> CommandResult:
        seen.append((arguments, environment, input_text))
        return CommandResult(
            0,
            "Extra Usage balance: $9.25\nprivate usage details",
            "",
        )

    boundary = DroidCommandBoundary(
        executable,
        "0.197.0",
        digest,
        "factory-npm-platform-tarball",
        interactive_command_runner=interactive,
    )

    captured = boundary.capture_usage("pre_run")

    assert captured["status"] == "captured"
    assert captured["output_bytes"] == len(
        b"Extra Usage balance: $9.25\nprivate usage details"
    )
    assert "private usage details" not in json.dumps(captured)
    assert captured["remaining_extra_usage"] == "9.25"
    assert seen[0][1][AUTO_UPDATE_ENV] == "false"
    assert seen[0][2] == "/limits\n/exit\n"

    with pytest.raises(LiveGateError, match="cannot be reconciled"):
        reconcile_usage_observations(
            {
                "pre_run": {"remaining_extra_usage": "9.25"},
                "post_run": {"remaining_extra_usage": "9.26"},
            }
        )


def test_default_usage_capture_runs_inside_a_pseudo_terminal(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "droid"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "if not os.isatty(0):\n"
        "    raise SystemExit(3)\n"
        "for line in sys.stdin:\n"
        "    if line.strip() == '/limits':\n"
        "        print('Extra Usage balance: $8.75', flush=True)\n"
        "    if line.strip() == '/exit':\n"
        "        raise SystemExit(0)\n"
    )
    executable.chmod(0o700)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    boundary = DroidCommandBoundary(
        executable,
        "0.197.0",
        digest,
        "factory-npm-platform-tarball",
    )

    captured = boundary.capture_usage("pre_run")

    assert captured["remaining_extra_usage"] == "8.75"

    oversized = DroidCommandBoundary(
        executable,
        "0.197.0",
        digest,
        "factory-npm-platform-tarball",
        command_runner=lambda arguments, environment: CommandResult(
            0,
            "x" * ((16 << 20) + 1),
            "",
        ),
    )
    with pytest.raises(LiveGateError, match="byte limit"):
        oversized.run(("plugin", "list"))


def test_droid_boundary_stops_on_binary_or_version_drift(tmp_path: Path) -> None:
    executable, digest = binary(tmp_path)
    runner = RecordingRunner([CommandResult(0, "0.198.0\n", "")])
    boundary = DroidCommandBoundary(
        executable, "0.197.0", digest, "factory-npm-platform-tarball", runner
    )

    with pytest.raises(LiveGateError, match="version drift"):
        boundary.observe("pre_mission")

    executable.write_bytes(b"changed")
    with pytest.raises(LiveGateError, match="binary digest drift"):
        boundary.run(("--version",))
    assert len(runner.calls) == 1


def test_mission_arguments_are_exact_and_never_unsafe() -> None:
    arguments = build_mission_arguments(Path("/fixture/mission.md"), "run-alias", models())

    assert arguments[:3] == ("exec", "--mission", "--auto")
    assert arguments[3] == "high"
    assert "--skip-permissions-unsafe" not in arguments
    assert arguments.count("--mission") == 1
    assert "--worker-model" in arguments
    assert "--validator-reasoning-effort" in arguments


def test_cost_budget_is_bound_to_billing_and_limits_evidence() -> None:
    billing = {
        "schema_version": "0.1",
        "source": "factory-billing-ui",
        "captured_without_model_call": True,
        "pro_subscription": "10.00",
        "extra_usage_purchases": "10.00",
        "prior_shadow_model_charges": "0.00",
        "maximum_additional_exposure": "10.00",
        "pay_as_you_go_enabled": False,
    }
    billing["output_digest"] = hashlib.sha256(
        json.dumps(
            billing,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    usage = {
        "status": "captured",
        "evidence_type": "droid-limits",
        "output_digest": "b" * 64,
        "output_bytes": 120,
        "remaining_extra_usage": "10.00",
    }

    budget, evidence = build_cost_and_budget_evidence(
        billing,
        usage,
        live_run_count=0,
    )

    assert budget["cost_evidence_digest"] == evidence["output_digest"]
    assert evidence["remaining_extra_usage"] == "10.00"
    unverified = dict(billing)
    unverified["source"] = "operator-authorization"
    unverified["output_digest"] = hashlib.sha256(
        json.dumps(
            {
                key: value
                for key, value in unverified.items()
                if key != "output_digest"
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(LiveGateError, match="billing evidence"):
        build_cost_and_budget_evidence(unverified, usage, live_run_count=0)
    tampered = dict(billing)
    tampered["pro_subscription"] = "9.00"
    with pytest.raises(LiveGateError, match="digest does not match"):
        build_cost_and_budget_evidence(tampered, usage, live_run_count=0)
    billing["extra_usage_purchases"] = "21.00"
    billing["output_digest"] = hashlib.sha256(
        json.dumps(
            {
                key: value
                for key, value in billing.items()
                if key != "output_digest"
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(LiveGateError, match="initial budget"):
        build_cost_and_budget_evidence(billing, usage, live_run_count=0)


def test_budget_and_authorization_fail_closed() -> None:
    safe = BudgetLedger.from_mapping(
        {
            "pro_subscription": "10.00",
            "extra_usage_purchases": "10.00",
            "prior_shadow_model_charges": "0.00",
            "remaining_extra_usage": "10.00",
            "maximum_additional_exposure": "10.00",
            "pay_as_you_go_enabled": False,
            "cost_evidence_digest": "f" * 64,
            "live_run_count": 0,
        }
    )
    safe.validate()

    for field, value in (
        ("prior_shadow_model_charges", "11.00"),
        ("maximum_additional_exposure", "20.00"),
        ("live_run_count", 1),
        ("pay_as_you_go_enabled", True),
    ):
        record = {
            "pro_subscription": "10.00",
            "extra_usage_purchases": "10.00",
            "prior_shadow_model_charges": "0.00",
            "remaining_extra_usage": "10.00",
            "maximum_additional_exposure": "10.00",
            "pay_as_you_go_enabled": False,
            "cost_evidence_digest": "f" * 64,
            "live_run_count": 0,
        }
        record[field] = value
        with pytest.raises(LiveGateError):
            BudgetLedger.from_mapping(record).validate()


def test_every_preflight_check_is_required() -> None:
    expected = bindings()
    record = preflight_record(expected)
    validate_live_preflight(
        record,
        authorization(expected),
        expected,
        models(),
        Path("ops/lima/shadow-feasibility.yaml"),
    )

    for check_name in tuple(record["checks"]):
        changed = json.loads(json.dumps(record))
        changed["checks"][check_name] = False
        with pytest.raises(LiveGateError, match=check_name):
            validate_live_preflight(
                changed,
                authorization(expected),
                expected,
                models(),
                Path("ops/lima/shadow-feasibility.yaml"),
            )


def test_preflight_validates_observed_guest_profile_and_isolation() -> None:
    expected = bindings()
    record = preflight_record(expected)
    lima_config = Path("ops/lima/shadow-feasibility.yaml")

    changed_profile = json.loads(json.dumps(record))
    changed_profile["factory_profile"]["unknown_surfaces"] = ["unknown"]
    with pytest.raises(LiveGateError, match="unknown Factory surfaces"):
        validate_live_preflight(
            changed_profile,
            authorization(expected),
            expected,
            models(),
            lima_config,
        )

    changed_isolation = json.loads(json.dumps(record))
    changed_isolation["isolation_manifest"]["host_mounts"] = ["/host"]
    with pytest.raises(LiveGateError, match="host mounts"):
        validate_live_preflight(
            changed_isolation,
            authorization(expected),
            expected,
            models(),
            lima_config,
        )


def test_failed_preflight_does_not_claim_live_run(tmp_path: Path) -> None:
    counter = LiveRunCounter(tmp_path / "private/live-run.json")

    with pytest.raises(LiveGateError, match="preflight"):
        execute_paid_boundary(
            preflight=lambda: (_ for _ in ()).throw(LiveGateError("preflight")),
            launch=lambda: CommandResult(0, "", ""),
            counter=counter,
        )

    assert counter.count == 0


def test_live_run_is_claimed_once_before_launch(tmp_path: Path) -> None:
    counter = LiveRunCounter(tmp_path / "private/live-run.json")
    launches: list[str] = []

    result = execute_paid_boundary(
        preflight=lambda: None,
        launch=lambda: launches.append("mission") or CommandResult(0, "", ""),
        counter=counter,
    )

    assert result.returncode == 0
    assert counter.count == 1
    assert launches == ["mission"]
    with pytest.raises(LiveGateError, match="already consumed"):
        execute_paid_boundary(
            preflight=lambda: None,
            launch=lambda: CommandResult(0, "", ""),
            counter=counter,
        )


def test_live_run_claim_syncs_file_and_parent_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counter = LiveRunCounter(tmp_path / "private/live-run.json")
    real_fsync = os.fsync
    synchronized_types: list[str] = []

    def recording_fsync(descriptor: int) -> None:
        mode = os.fstat(descriptor).st_mode
        synchronized_types.append("directory" if stat.S_ISDIR(mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    counter.claim()

    assert synchronized_types == ["file", "directory"]
    assert counter.count == 1


def test_preflight_attempt_counter_exhausts_without_claiming_live_run(
    tmp_path: Path,
) -> None:
    counter = PreflightAttemptCounter(
        tmp_path / "private/preflight-attempts.json",
        limit=2,
    )

    assert counter.claim_attempt() == 1
    assert counter.claim_attempt() == 2
    with pytest.raises(LiveGateError, match="limit is exhausted"):
        counter.claim_attempt()


def test_host_live_slot_claim_validates_preflight_and_is_one_time(
    tmp_path: Path,
) -> None:
    expected = bindings()
    private = tmp_path / ".shadow-mission"
    private.mkdir(mode=0o700)
    authorization_path = private / "authorization.json"
    preflight_path = private / "preflight.json"
    authorization_path.write_text(
        json.dumps(authorization_mapping(expected))
    )
    preflight_path.write_text(json.dumps(preflight_record(expected)))
    authorization_path.chmod(0o600)
    preflight_path.chmod(0o600)
    ledger_path = private / "feasibility-live-run.json"
    model_values = models()
    options = build_parser().parse_args(
        [
            "--authorization-record",
            str(authorization_path),
            "--preflight-record",
            str(preflight_path),
            "--lima-config",
            str(Path("ops/lima/shadow-feasibility.yaml").resolve()),
            "--host-live-run-ledger",
            str(ledger_path),
            "--orchestrator-model",
            model_values["orchestrator_model"],
            "--reasoning-effort",
            model_values["orchestrator_reasoning"],
            "--worker-model",
            model_values["worker_model"],
            "--worker-reasoning-effort",
            model_values["worker_reasoning"],
            "--validator-model",
            model_values["validator_model"],
            "--validator-reasoning-effort",
            model_values["validator_reasoning"],
            "--probe-model",
            model_values["probe_model"],
            "--probe-reasoning-effort",
            model_values["probe_reasoning"],
        ]
    )

    result = run_host_claim_command(options, tmp_path)

    assert result == {
        "schema_version": "0.1",
        "status": "host-live-run-slot-claimed",
        "live_run_count": 1,
    }
    with pytest.raises(LiveGateError, match="already consumed"):
        run_host_claim_command(options, tmp_path)



@pytest.mark.parametrize("guest_preflight_passes", [True, False])
def test_atomic_host_gate_claims_once_then_launches_and_tears_down(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    guest_preflight_passes: bool,
) -> None:
    import shadow_mission.live as live_module

    expected = bindings()
    private = tmp_path / ".shadow-mission"
    private.mkdir(mode=0o700)
    authorization_path = private / "authorization.json"
    preflight_path = private / "preflight.json"
    authorization_path.write_text(json.dumps(authorization_mapping(expected)))
    preflight_path.write_text(json.dumps(preflight_record(expected)))
    authorization_path.chmod(0o600)
    preflight_path.chmod(0o600)
    limactl = tmp_path / "limactl"
    limactl.write_bytes(b"pinned-limactl")
    limactl.chmod(0o700)
    guest_calls: list[tuple[str, ...]] = []

    class FakeFinalizer:
        def __init__(
            self,
            executable: Path,
            expected_version: str,
        ) -> None:
            assert executable == limactl.resolve()
            assert expected_version == "2.2.0"

        def run_guest_feasibility(
            self,
            arguments: tuple[str, ...],
        ) -> CommandResult:
            guest_calls.append(arguments)
            if "--live-preflight-only" in arguments:
                if guest_preflight_passes:
                    return CommandResult(
                        0,
                        json.dumps(
                            {
                                "status": "live-preflight-pass",
                                "live_run_count_incremented": False,
                                "model_calls": 0,
                                "factory_calls": 0,
                            }
                        ),
                        "",
                    )
                return CommandResult(1, "", "preflight failed")
            return CommandResult(1, "", "guest failed")
        def guest_live_run_count(self) -> int:
            return 1

        def export_and_teardown(
            self,
            host_export_directory: Path,
        ) -> tuple[bool, dict[str, bool], bool]:
            assert host_export_directory == private / "feasibility-import"
            return (
                False,
                {
                    "instance_absent": True,
                    "disk_absent": True,
                    "credential_removed": True,
                },
                True,
            )

    monkeypatch.setattr(live_module, "HostLimaFinalizer", FakeFinalizer)
    model_values = models()
    options = build_parser().parse_args(
        [
            "--run-host-live-gate",
            "--authorization-record",
            str(authorization_path),
            "--preflight-record",
            str(preflight_path),
            "--host-live-run-ledger",
            str(private / "feasibility-live-run.json"),
            "--lima-config",
            "ops/lima/shadow-feasibility.yaml",
            "--limactl-binary",
            str(limactl),
            "--host-export-directory",
            str(private / "feasibility-import"),
            "--output",
            str(private / "feasibility-gate.json"),
            "--guest-installed-plugin-root",
            "/home/shadow/.factory/plugins/cache/shadow-mission",
            "--orchestrator-model",
            model_values["orchestrator_model"],
            "--reasoning-effort",
            model_values["orchestrator_reasoning"],
            "--worker-model",
            model_values["worker_model"],
            "--worker-reasoning-effort",
            model_values["worker_reasoning"],
            "--validator-model",
            model_values["validator_model"],
            "--validator-reasoning-effort",
            model_values["validator_reasoning"],
            "--probe-model",
            model_values["probe_model"],
            "--probe-reasoning-effort",
            model_values["probe_reasoning"],
        ]
    )

    result = run_host_live_gate_command(options, tmp_path)

    assert result["live_gate_verdict"] == "stop"
    if guest_preflight_passes:
        assert result["failure_stage"] == "guest_execution"
        assert json.loads(
            (private / "feasibility-live-run.json").read_text()
        )["live_run_count"] == 1
        assert len(guest_calls) == 2
        assert guest_calls[1][0] == "/home/shadow/venv/bin/shadow-feasibility"
        assert "/home/shadow/bin/droid" in guest_calls[1]
    else:
        assert result["failure_stage"] == "guest_preflight"
        assert not (private / "feasibility-live-run.json").exists()
        assert len(guest_calls) == 1

def test_live_observation_classifier_requires_direct_independent_controls() -> None:
    expected = bindings()
    observations = passing_observations(expected)
    assert classify_live_observations(observations, expected) == "primary-pass"

    for group, field in (
        ("identity_controls", "same_project_decoy_excluded"),
        ("guidance_controls", "siblings_excluded"),
        ("probe_controls", "zero_tools"),
    ):
        changed = json.loads(json.dumps(observations))
        changed[group][field] = False
        changed = bind_live_evidence_artifacts(changed)
        with pytest.raises(LiveGateError, match=field):
            classify_live_observations(changed, expected)

    for boundary in ("worker", "mission"):
        for field in observations["blocker_controls"][boundary]:
            changed = json.loads(json.dumps(observations))
            changed["blocker_controls"][boundary][field] = False
            changed = bind_live_evidence_artifacts(changed)
            with pytest.raises(LiveGateError, match=field):
                classify_live_observations(changed, expected)


def test_live_observations_reject_raw_identifiers_secrets_and_canaries() -> None:
    expected = bindings()
    observations = passing_observations(expected)

    for field, value in (
        ("session_id", "raw-session"),
        ("transcript_path", "/home/shadow/transcript.jsonl"),
        ("run_secret", "secret-value"),
        ("canary", "ROUTE-ALPHA-7319"),
    ):
        changed = json.loads(json.dumps(observations))
        changed[field] = value
        with pytest.raises(LiveGateError, match="forbidden"):
            classify_live_observations(changed, expected)


def test_probe_retries_only_one_transient_failure() -> None:
    attempts: list[int] = []

    def transient_then_pass() -> ProbeEvidence:
        attempts.append(len(attempts) + 1)
        if len(attempts) == 1:
            raise TransientProbeError("retry")
        return ProbeEvidence(
            probe_result_id="probe-safe",
            authoritative_value="cents",
            citations=("api-schema.json#/properties/amount",),
            attempts=1,
            zero_tools=True,
            activation_stripped=True,
        )

    result = run_bounded_probe_attempts(transient_then_pass)
    assert result.attempts == 2
    assert attempts == [1, 2]

    unsafe_attempts: list[int] = []

    def unsafe() -> ProbeEvidence:
        unsafe_attempts.append(1)
        raise UnsafeProbeError("do not retry")

    with pytest.raises(UnsafeProbeError):
        run_bounded_probe_attempts(unsafe)
    assert unsafe_attempts == [1]


def test_session_tool_lockdown_disables_the_discovered_catalog() -> None:
    class Tool:
        def __init__(self, tool_id: str, allowed: bool) -> None:
            self.id = tool_id
            self.allowed = allowed

    class Session:
        def __init__(self, leak: bool = False) -> None:
            self.leak = leak
            self.disabled: set[str] | None = None

        async def list_tools(
            self,
            *,
            disabled_tools: set[str] | None = None,
        ) -> list[Tool]:
            if disabled_tools is None:
                return [Tool("Read", True), Tool("Execute", False)]
            if self.leak:
                return [Tool("LateTool", True)]
            return [Tool(tool_id, False) for tool_id in disabled_tools]

        async def update_settings(
            self,
            *,
            disabled_tools: set[str],
        ) -> None:
            self.disabled = disabled_tools

    locked = Session()
    assert asyncio.run(live_module._lock_down_session_tools(locked)) is True
    assert locked.disabled == {"Read", "Execute"}
    assert (
        asyncio.run(live_module._lock_down_session_tools(Session(leak=True)))
        is False
    )


def test_probe_request_compares_observed_claims_with_both_schemas() -> None:
    snapshot = {
        "observed_source": {"records": [{"text": "amount uses dollars"}]},
        "api_schema": {"properties": {"amount": {"description": "cents"}}},
        "database_schema": "amount_cents INTEGER",
    }

    request = json.loads(
        live_module._build_probe_request(
            json.dumps(snapshot, sort_keys=True),
        )
    )

    assert request["evidence"] == snapshot
    assert "observed_source" in request["task"]
    assert request["constraints"] == {
        "allowed_citations": [
            "api-schema.json#/properties/amount",
            "db-schema.sql:payments.amount_cents",
        ],
        "tools_must_not_be_used": True,
    }


def test_authorized_runner_claims_immediately_before_mission_launch(
    tmp_path: Path,
) -> None:
    executable, digest = binary(tmp_path)
    expected = bindings(digest)
    runner = RecordingRunner(
        [
            CommandResult(0, "0.197.0\n", ""),
            CommandResult(0, "0.197.0\n", ""),
            CommandResult(0, "mission", ""),
            CommandResult(0, "0.197.0\n", ""),
        ]
    )
    boundary = DroidCommandBoundary(
        executable,
        "0.197.0",
        digest,
        "factory-npm-platform-tarball",
        runner,
        captured_usage,
    )
    counter = LiveRunCounter(tmp_path / "private/live-run.json")

    candidate = run_authorized_live(
        preflight_record=preflight_record(expected),
        authorization=authorization(expected),
        expected_bindings=expected,
        model_settings=models(),
        lima_config=Path("ops/lima/shadow-feasibility.yaml"),
        boundary=boundary,
        mission_file=tmp_path / "mission.md",
        run_id="run-safe-alias",
        mission_environment={"SHADOW_MISSION_INTERNAL": "0"},
        counter=counter,
        output_path=tmp_path / "output/gate.candidate.json",
        inert_control=lambda: "inert-safe-alias",
        probe=lambda: ProbeEvidence(
            probe_result_id="probe-safe",
            authoritative_value="cents",
            citations=("api-schema.json#/properties/amount",),
            attempts=1,
            zero_tools=True,
            activation_stripped=True,
            internal_session_alias="probe-safe-alias",
        ),
        verify_installed_plugin=lambda: expected[
            "installed_plugin_artifact_digest"
        ],
        observation_supplier=lambda run_id, mission, probe, usage: passing_observations(
            expected
        ),
    )

    assert candidate["candidate_gate_verdict"] == "primary-pass"
    assert counter.count == 1
    assert runner.calls[2][0][1:5] == ("exec", "--mission", "--auto", "high")
    assert all(call[1][AUTO_UPDATE_ENV] == "false" for call in runner.calls)


def test_pre_mission_version_drift_does_not_consume_the_mission_slot(
    tmp_path: Path,
) -> None:
    executable, digest = binary(tmp_path)
    expected = bindings(digest)
    runner = RecordingRunner(
        [
            CommandResult(0, "0.197.0\n", ""),
            CommandResult(0, "0.198.0\n", ""),
        ]
    )
    boundary = DroidCommandBoundary(
        executable,
        "0.197.0",
        digest,
        "factory-npm-platform-tarball",
        runner,
        captured_usage,
    )
    counter = LiveRunCounter(tmp_path / "private/live-run.json")

    with pytest.raises(LiveGateError, match="version drift"):
        run_authorized_live(
            preflight_record=preflight_record(expected),
            authorization=authorization(expected),
            expected_bindings=expected,
            model_settings=models(),
            lima_config=Path("ops/lima/shadow-feasibility.yaml"),
            boundary=boundary,
            mission_file=tmp_path / "mission.md",
            run_id="run-safe-alias",
            mission_environment={},
            counter=counter,
            output_path=tmp_path / "output/gate.candidate.json",
            inert_control=lambda: "inert-safe-alias",
            probe=lambda: ProbeEvidence(
                probe_result_id="probe-safe",
                authoritative_value="cents",
                citations=("api-schema.json#/properties/amount",),
                attempts=1,
                zero_tools=True,
                activation_stripped=True,
                internal_session_alias="probe-safe-alias",
            ),
            verify_installed_plugin=lambda: expected[
                "installed_plugin_artifact_digest"
            ],
            observation_supplier=lambda run_id, mission, probe, usage: (
                passing_observations(expected)
            ),
        )

    assert counter.count == 0
    assert len(runner.calls) == 2


def test_probe_failure_does_not_consume_the_mission_slot(tmp_path: Path) -> None:
    executable, digest = binary(tmp_path)
    expected = bindings(digest)
    runner = RecordingRunner(
        [
            CommandResult(0, "0.197.0\n", ""),
        ]
    )
    boundary = DroidCommandBoundary(
        executable,
        "0.197.0",
        digest,
        "factory-npm-platform-tarball",
        runner,
        captured_usage,
    )
    counter = LiveRunCounter(tmp_path / "private/live-run.json")

    with pytest.raises(UnsafeProbeError):
        run_authorized_live(
            preflight_record=preflight_record(expected),
            authorization=authorization(expected),
            expected_bindings=expected,
            model_settings=models(),
            lima_config=Path("ops/lima/shadow-feasibility.yaml"),
            boundary=boundary,
            mission_file=tmp_path / "mission.md",
            run_id="run-safe-alias",
            mission_environment={},
            counter=counter,
            output_path=tmp_path / "output/gate.candidate.json",
            inert_control=lambda: "inert-safe-alias",
            probe=lambda: (_ for _ in ()).throw(
                UnsafeProbeError("unsafe probe")
            ),
            verify_installed_plugin=lambda: expected[
                "installed_plugin_artifact_digest"
            ],
            observation_supplier=lambda run_id, mission, probe, usage: (
                passing_observations(expected)
            ),
        )

    assert counter.count == 0
    assert len(runner.calls) == 1


def test_private_live_records_reject_public_modes_and_symlinks(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    record = private / "preflight.json"
    record.write_text("{}")
    record.chmod(0o600)
    assert load_private_record(record, "preflight") == {}

    record.chmod(0o644)
    with pytest.raises(LiveGateError, match="not private"):
        load_private_record(record, "preflight")

    record.chmod(0o600)
    alias = private / "alias.json"
    alias.symlink_to(record)
    with pytest.raises(LiveGateError, match="not private"):
        load_private_record(alias, "preflight")


def test_private_factory_credential_requires_one_raw_private_line(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    credential = private / "factory-api-key"
    credential.write_text("guest-key-sentinel\n")
    credential.chmod(0o600)

    assert load_private_factory_credential(credential) == {
        "FACTORY_API_KEY": "guest-key-sentinel"
    }

    credential.write_text("FACTORY_API_KEY=guest-key-sentinel\n")
    with pytest.raises(LiveGateError, match="invalid"):
        load_private_factory_credential(credential)


def test_private_factory_environment_requires_one_exact_assignment(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    credential = private / "factory.env"
    credential.write_text("FACTORY_API_KEY=guest-key-sentinel\n")
    credential.chmod(0o600)

    assert load_private_factory_environment(credential) == {
        "FACTORY_API_KEY": "guest-key-sentinel"
    }

    for invalid in (
        "guest-key-sentinel\n",
        "OTHER_KEY=guest-key-sentinel\n",
        "FACTORY_API_KEY=guest-key-sentinel\nOTHER_KEY=value\n",
    ):
        credential.write_text(invalid)
        with pytest.raises(LiveGateError, match="invalid"):
            load_private_factory_environment(credential)


def test_output_corruption_and_export_failure_cannot_report_success(
    tmp_path: Path,
) -> None:
    expected = bindings()
    candidate = passing_observations(expected)
    candidate_path = tmp_path / "guest/gate.candidate.json"
    write_candidate_gate(candidate_path, candidate, expected)
    assert json.loads(candidate_path.read_text())["candidate_gate_verdict"] == "primary-pass"
    ledger_path = tmp_path / "guest/events.jsonl"
    ledger_path.write_bytes(b'{"event_id":"safe","schema_version":"0.1"}\n')
    ledger_path.chmod(0o600)

    candidate_path.write_text("{corrupt")
    with pytest.raises(LiveGateError, match="candidate"):
        finalize_exported_gate(
            tmp_path / "guest",
            tmp_path / "host/gate.json",
            expected,
            {
                "instance_absent": True,
                "disk_absent": True,
                "credential_removed": True,
            },
        )

    with pytest.raises(LiveGateError, match="export"):
        finalize_exported_gate(
            tmp_path / "missing",
            tmp_path / "host/gate.json",
            expected,
            {
                "instance_absent": True,
                "disk_absent": True,
                "credential_removed": True,
            },
        )
    write_candidate_gate(candidate_path, candidate, expected)
    extra_path = tmp_path / "guest/unexpected.txt"
    extra_path.write_text("must not be imported")
    extra_path.chmod(0o600)
    with pytest.raises(LiveGateError, match="allowlist"):
        finalize_exported_gate(
            tmp_path / "guest",
            tmp_path / "host/gate.json",
            expected,
            {
                "instance_absent": True,
                "disk_absent": True,
                "credential_removed": True,
            },
        )


def test_cleanup_failure_forces_stop_and_complete_cleanup_finalizes(
    tmp_path: Path,
) -> None:
    expected = bindings()
    export_dir = tmp_path / "export"
    write_candidate_gate(
        export_dir / "gate.candidate.json", passing_observations(expected), expected
    )

    ledger_path = export_dir / "events.jsonl"
    ledger_path.write_bytes(b'{"event_id":"safe","schema_version":"0.1"}\n')
    ledger_path.chmod(0o600)
    changed_models = models()
    changed_models["worker_model"] = "different-worker-model"
    with pytest.raises(LiveGateError, match="models differ"):
        finalize_exported_gate(
            export_dir,
            tmp_path / "model-drift/gate.json",
            expected,
            {
                "instance_absent": True,
                "disk_absent": True,
                "credential_removed": True,
            },
            changed_models,
        )
    failed_path = tmp_path / "failed/gate.json"

    failed = finalize_exported_gate(
        export_dir,
        failed_path,
        expected,
        {
            "instance_absent": True,
            "disk_absent": False,
            "credential_removed": True,
        },
    )
    assert failed["live_gate_verdict"] == "stop"
    assert failed["complete_success"] is False
    assert failed["candidate_gate_verdict"] == "stop"
    assert failed["capabilities"]["disposable_isolation"] == {
        "status": "stop",
        "fallback_basis": "stop_condition",
        "evidence_ids": failed["capabilities"]["disposable_isolation"][
            "evidence_ids"
        ],
    }
    isolation_records = [
        record
        for record in failed["evidence_registry"]
        if record["capability"] == "disposable_isolation"
    ]
    assert len(isolation_records) == 1
    assert isolation_records[0]["facts"]["disk_absent"] is False

    passed_path = tmp_path / "passed/gate.json"
    passed = finalize_exported_gate(
        export_dir,
        passed_path,
        expected,
        {
            "instance_absent": True,
            "disk_absent": True,
            "credential_removed": True,
        },
    )
    assert passed["live_gate_verdict"] == "primary-pass"
    assert passed["complete_success"] is True
    assert os.stat(passed_path).st_mode & 0o777 == 0o600


def test_host_finalizer_exports_then_tears_down_before_final_verdict(
    tmp_path: Path,
) -> None:
    expected = bindings()
    guest_export = tmp_path / "guest-export"
    write_candidate_gate(
        guest_export / "gate.candidate.json",
        passing_observations(expected),
        expected,
    )
    ledger_path = guest_export / "events.jsonl"
    ledger_path.write_bytes(b'{"event_id":"safe","schema_version":"0.1"}\n')
    ledger_path.chmod(0o600)
    limactl = tmp_path / "limactl"
    limactl.write_bytes(b"pinned-limactl")
    limactl.chmod(0o700)
    instance_directory = tmp_path / ".lima" / "shadow-feasibility"
    instance_directory.mkdir(parents=True)
    (instance_directory / "diffdisk").write_bytes(b"guest-disk")
    calls: list[tuple[str, ...]] = []

    def runner(
        arguments: tuple[str, ...],
        environment: dict[str, str],
    ) -> CommandResult:
        del environment
        calls.append(arguments)
        if arguments[1] == "--version":
            return CommandResult(0, "limactl version 2.2.0", "")
        if arguments[1] == "copy":
            source_name = Path(arguments[2].split(":", 1)[1]).name
            shutil.copy2(guest_export / source_name, Path(arguments[-1]))
        if arguments[1] == "list":
            return CommandResult(0, "[]", "")
        if arguments[1] == "delete":
            shutil.rmtree(instance_directory)
        return CommandResult(0, "", "")

    host_export = tmp_path / "host-import"
    result = finalize_host_gate(
        finalizer=HostLimaFinalizer(
            limactl,
            "2.2.0",
            runner,
            instance_directory,
        ),
        host_export_directory=host_export,
        output_path=tmp_path / "final/gate.json",
        expected_bindings=expected,
    )

    assert result["live_gate_verdict"] == "primary-pass"
    assert result["complete_success"] is True
    assert [call[1] for call in calls] == [
        "--version",
        "copy",
        "copy",
        "stop",
        "delete",
        "list",
    ]
    assert calls[1][1:3] == (
        "copy",
        "shadow-feasibility:/home/shadow/output/gate/gate.candidate.json",
    )

    instance_directory.mkdir(parents=True)
    (instance_directory / "diffdisk").write_bytes(b"guest-disk")
    unclaimed = finalize_host_gate(
        finalizer=HostLimaFinalizer(
            limactl,
            "2.2.0",
            runner,
            instance_directory,
        ),
        host_export_directory=tmp_path / "unclaimed-import",
        output_path=tmp_path / "unclaimed/gate.json",
        expected_bindings=expected,
        host_claim_valid=False,
    )
    assert unclaimed["live_gate_verdict"] == "stop"
    assert unclaimed["failure_stage"] == "host_live_run_claim"
    assert unclaimed["teardown"] == {
        "instance_absent": True,
        "disk_absent": True,
        "credential_removed": True,
    }

    failed_calls: list[tuple[str, ...]] = []
    instance_directory.mkdir(parents=True)
    (instance_directory / "diffdisk").write_bytes(b"guest-disk")

    def export_failure(
        arguments: tuple[str, ...],
        environment: dict[str, str],
    ) -> CommandResult:
        del environment
        failed_calls.append(arguments)
        if arguments[1] == "--version":
            return CommandResult(0, "limactl version 2.2.0", "")
        if arguments[1] == "list":
            return CommandResult(0, "[]", "")
        if arguments[1] == "delete":
            shutil.rmtree(instance_directory)
        return CommandResult(1 if arguments[1] == "copy" else 0, "", "failure")

    failed = finalize_host_gate(
        finalizer=HostLimaFinalizer(
            limactl,
            "2.2.0",
            export_failure,
            instance_directory,
        ),
        host_export_directory=tmp_path / "missing-import",
        output_path=tmp_path / "failed/gate.json",
        expected_bindings=expected,
    )

    assert failed["live_gate_verdict"] == "stop"
    assert failed["failure_stage"] == "evidence_export"
    assert [call[1] for call in failed_calls] == [
        "--version",
        "copy",
        "copy",
        "stop",
        "delete",
        "list",
    ]


def test_host_finalizer_stops_on_lima_version_drift_but_still_tears_down(
    tmp_path: Path,
) -> None:
    limactl = tmp_path / "limactl"
    limactl.write_bytes(b"pinned-limactl")
    limactl.chmod(0o700)
    instance_directory = tmp_path / ".lima" / "shadow-feasibility"
    instance_directory.mkdir(parents=True)
    (instance_directory / "diffdisk").write_bytes(b"guest-disk")
    calls: list[tuple[str, ...]] = []

    def runner(
        arguments: tuple[str, ...],
        environment: dict[str, str],
    ) -> CommandResult:
        del environment
        calls.append(arguments)
        if arguments[1] == "--version":
            return CommandResult(0, "limactl version 2.3.0", "")
        if arguments[1] == "list":
            return CommandResult(0, "[]", "")
        if arguments[1] == "delete":
            shutil.rmtree(instance_directory)
        return CommandResult(1 if arguments[1] == "copy" else 0, "", "")

    result = finalize_host_gate(
        finalizer=HostLimaFinalizer(
            limactl,
            "2.2.0",
            runner,
            instance_directory,
        ),
        host_export_directory=tmp_path / "host-import",
        output_path=tmp_path / "final/gate.json",
        expected_bindings=bindings(),
    )

    assert result["live_gate_verdict"] == "stop"
    assert result["failure_stage"] == "lima_version"
    assert [call[1] for call in calls] == [
        "--version",
        "copy",
        "copy",
        "stop",
        "delete",
        "list",
    ]


def test_host_finalizer_refuses_empty_inventory_and_failed_stop(
    tmp_path: Path,
) -> None:
    limactl = tmp_path / "limactl"
    limactl.write_bytes(b"pinned-limactl")
    limactl.chmod(0o700)
    instance_directory = tmp_path / ".lima/shadow-feasibility"
    instance_directory.mkdir(parents=True)
    (instance_directory / "diffdisk").write_bytes(b"guest-disk")
    commands: list[str] = []

    def runner(
        arguments: tuple[str, ...],
        environment: dict[str, str],
    ) -> CommandResult:
        del environment
        commands.append(arguments[1])
        if arguments[1] == "--version":
            return CommandResult(0, "limactl version 2.2.0", "")
        if arguments[1] == "stop":
            return CommandResult(1, "", "stop failed")
        if arguments[1] == "list":
            return CommandResult(0, "", "")
        return CommandResult(1, "", "not available")

    _exported, teardown, _version_matches = HostLimaFinalizer(
        limactl,
        "2.2.0",
        runner,
        instance_directory,
    ).export_and_teardown(tmp_path / "host-export")

    assert "delete" not in commands
    assert teardown["instance_absent"] is False
    assert teardown["disk_absent"] is False


def test_host_lima_guest_launch_is_pinned_and_update_disabled(
    tmp_path: Path,
) -> None:
    limactl = tmp_path / "limactl"
    limactl.write_bytes(b"pinned-limactl")
    limactl.chmod(0o700)
    calls: list[tuple[str, ...]] = []

    def runner(
        arguments: tuple[str, ...],
        environment: dict[str, str],
    ) -> CommandResult:
        calls.append(arguments)
        assert "PATH" in environment
        assert "FACTORY_API_KEY" not in environment
        if arguments[1] == "--version":
            return CommandResult(0, "limactl version 2.2.0", "")
        return CommandResult(0, "mission complete", "")

    finalizer = HostLimaFinalizer(
        limactl,
        "2.2.0",
        runner,
        tmp_path / ".lima" / "shadow-feasibility",
    )
    result = finalizer.run_guest_feasibility(
        (
            "/home/shadow/venv/bin/shadow-feasibility",
            "--fixture",
            "/home/shadow/input/feasibility",
        )
    )

    assert result.returncode == 0
    assert calls[1] == (
        str(limactl),
        "shell",
        "shadow-feasibility",
        "--",
        "env",
        "FACTORY_DROID_AUTO_UPDATE_ENABLED=false",
        "/home/shadow/venv/bin/shadow-feasibility",
        "--fixture",
        "/home/shadow/input/feasibility",
    )


def test_failed_guest_launch_cannot_report_host_success(
    tmp_path: Path,
) -> None:
    limactl = tmp_path / "limactl"
    limactl.write_bytes(b"pinned-limactl")
    limactl.chmod(0o700)

    def runner(
        arguments: tuple[str, ...],
        environment: dict[str, str],
    ) -> CommandResult:
        del environment
        if arguments[1] == "--version":
            return CommandResult(0, "limactl version 2.2.0", "")
        if arguments[1] == "list":
            return CommandResult(0, "[]", "")
        return CommandResult(1, "", "failed")

    result = finalize_host_gate(
        finalizer=HostLimaFinalizer(
            limactl,
            "2.2.0",
            runner,
            tmp_path / ".lima" / "shadow-feasibility",
        ),
        host_export_directory=tmp_path / "host-import",
        output_path=tmp_path / "final/gate.json",
        expected_bindings=bindings(),
        guest_execution_valid=False,
    )

    assert result["live_gate_verdict"] == "stop"
    assert result["failure_stage"] == "guest_execution"


def test_interactive_runner_stops_descendant_process_group(
    tmp_path: Path,
) -> None:
    heartbeat = tmp_path / "interactive-heartbeat"
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
        "import os,subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
        "time.sleep(0.2)\n"
        f"os.write(1, b'x' * ({live_module._MAX_DROID_OUTPUT_BYTES} + 1))\n"
        "time.sleep(10)\n"
    )

    result = live_module._default_interactive_command_runner(
        (sys.executable, "-c", parent),
        {},
        "\n",
    )

    assert result.returncode == 255
    assert heartbeat.is_file()
    size_after_return = heartbeat.stat().st_size
    time.sleep(0.2)
    assert heartbeat.stat().st_size == size_after_return
