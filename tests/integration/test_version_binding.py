from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

import pytest

import shadow_mission.runtime as runtime_module
from shadow_mission.collector import HookCollector
from shadow_mission.correlation import (
    MissionCorrelationBinding,
    PinnedFactoryMissionRelationProducer,
    factory_relation_source_digest,
)
from shadow_mission.isolation import validate_isolation_manifest
from shadow_mission.profile import (
    PLUGIN_ARTIFACT_ROOTS,
    compute_gate_surface_digest,
    compute_plugin_artifact_digest,
    validate_factory_profile,
)
from shadow_mission.protocol import (
    BaselineRunRecord,
    CapabilityFlags,
    HookEnvelope,
    HookExchangeRecord,
    HookRequest,
    InterventionRecord,
    InterventionTransition,
    RunRecord,
    canonical_json,
)
from shadow_mission.router import InterventionLatchStore, InterventionRouterState
from shadow_mission.runtime import (
    CommandResult,
    MissionExecutionError,
    MissionRequest,
    MissionRuntime,
    PreflightError,
    RunPreparation,
    ReviewControllerBinding,
    compute_full_source_digest,
    release_preflight_digest,
)
from shadow_mission.storage import EventLedger, ResponsePlan

PROJECT_ROOT = Path(__file__).parents[2]
MODEL_ROLES = ("orchestrator", "worker", "validator", "extractor", "probe")


class FakeRunner:
    def __init__(
        self,
        *,
        mission_returncode: int = 0,
        version: str = "0.197.0",
        mission_process_stopped: bool = True,
    ) -> None:
        self.mission_returncode = mission_returncode
        self.version = version
        self.mission_process_stopped = mission_process_stopped
        self.calls: list[tuple[tuple[str, ...], dict[str, str], Path]] = []
        self.mutate_after_version: Path | None = None
        self.mission_mutation: tuple[Path, str] | None = None
        self.interrupt_action: Any | None = None
        self.terminated = False
        self.interrupt_polls = 0
        self.descriptor: dict[str, object] | None = None

    def _write_factory_relations(self, cwd: Path) -> None:
        if self.factory_mission_root is None:
            return
        mission_dir = self.factory_mission_root / "factory-orchestrator"
        mission_dir.mkdir(mode=0o700)
        state = {
            "missionId": "mis_12345678",
            "state": "completed",
            "workingDirectory": str(cwd),
            "createdAt": "2026-08-18T00:00:00Z",
            "updatedAt": "2026-08-18T00:01:00Z",
        }
        assignments = (
            ("feature-a", "factory-worker-a", None),
            ("feature-b", "factory-worker-b", None),
            ("scrutiny-m1", "factory-validator", "scrutiny-validator"),
        )
        features = []
        progress = []
        for feature_id, session_id, skill_name in assignments:
            feature = {
                "id": feature_id,
                "description": feature_id,
                "status": "completed",
                "workerSessionIds": [session_id],
            }
            if skill_name is not None:
                feature["skillName"] = skill_name
            features.append(feature)
            progress.extend(
                (
                    {
                        "timestamp": "2026-08-18T00:00:01Z",
                        "type": "worker_selected_feature",
                        "workerSessionId": session_id,
                        "featureId": feature_id,
                    },
                    {
                        "timestamp": "2026-08-18T00:00:02Z",
                        "type": "worker_started",
                        "workerSessionId": session_id,
                        "featureId": feature_id,
                    },
                )
            )
        files = {
            "state.json": json.dumps(state),
            "features.json": json.dumps({"features": features}),
            "progress_log.jsonl": "".join(
                f"{json.dumps(entry)}\n" for entry in progress
            ),
        }
        for name, content in files.items():
            path = mission_dir / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)

    factory_mission_root: Path | None = None

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        timeout_seconds: int,
        pass_fds: tuple[int, ...] = (),
    ) -> CommandResult:
        self.calls.append((arguments, dict(environment), cwd))
        if arguments[1:] == ("--version",):
            if self.mutate_after_version is not None:
                self.mutate_after_version.write_text("drift", encoding="utf-8")
                self.mutate_after_version.chmod(0o700)
            return CommandResult(0, f"Droid {self.version}\n", "")
        if self.mission_mutation is not None:
            path, content = self.mission_mutation
            path.write_text(content, encoding="utf-8")
        return CommandResult(self.mission_returncode, "Mission complete\n", "")

    def run_interruptible(
        self,
        arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        timeout_seconds: int,
        termination_required: Any,
        termination_grace_seconds: float = 5.0,
        pass_fds: tuple[int, ...] = (),
    ) -> CommandResult:
        del timeout_seconds, termination_grace_seconds, pass_fds
        self.calls.append((arguments, dict(environment), cwd))
        self.descriptor = json.loads(
            Path(environment["SHADOW_MISSION_RUN_FILE"]).read_text(encoding="utf-8")
        )
        self._write_factory_relations(cwd)
        if self.mission_mutation is not None:
            path, content = self.mission_mutation
            path.write_text(content, encoding="utf-8")
        if self.interrupt_action is not None:
            self.interrupt_action()
        self.interrupt_polls += 1
        if termination_required():
            self.terminated = True
            return CommandResult(
                0,
                "Mission interrupted\n",
                "",
                self.mission_process_stopped,
            )
        return CommandResult(
            self.mission_returncode,
            "Mission complete\n",
            "",
            self.mission_process_stopped,
        )


class FakeRouter:
    def __init__(self, run_id: str) -> None:
        self.state = InterventionRouterState.empty(run_id)

    def snapshot(self) -> InterventionRouterState:
        return self.state


class FakeReviewController:
    def __init__(
        self,
        run_id: str,
        run_dir: Path,
        *,
        router: FakeRouter | None = None,
    ) -> None:
        self.run_id = run_id
        self.run_dir = run_dir
        self.releasable = True
        self.non_releasable_reason: str | None = None
        self.termination_required = False
        self.completion_blocked = False
        self.unresolved_intervention_ids: tuple[str, ...] = ()
        self.lifecycle: list[str] = []
        self.router = router or FakeRouter(run_id)

    def capture_request(
        self, request: HookRequest, envelope: HookEnvelope
    ) -> None:
        del request, envelope

    def discard_request(self, event_id: str) -> None:
        del event_id

    def decide(self, envelope: HookEnvelope) -> ResponsePlan:
        del envelope
        return ResponsePlan()

    def after_append(self, exchange: HookExchangeRecord) -> None:
        del exchange

    def start(self) -> None:
        self.lifecycle.append("start")

    def drain(self, *, timeout: float = 5.0) -> bool:
        del timeout
        self.lifecycle.append("drain")
        return True

    def reconcile_final_outage(self) -> None:
        self.lifecycle.append("reconcile_final_outage")

    def stop(self, *, timeout: float = 5.0) -> bool:
        del timeout
        self.lifecycle.append("stop")
        return True




class FakeReviewFactory:
    def __init__(
        self,
        *,
        cross_run: bool = False,
        controller_type: type[FakeReviewController] = FakeReviewController,
        router_factory: Any | None = None,
        additional_forbidden_values: tuple[str, ...] = (),
    ) -> None:
        self.cross_run = cross_run
        self.controller_type = controller_type
        self.router_factory = router_factory
        self.additional_forbidden_values = additional_forbidden_values
        self.controller: FakeReviewController | None = None
        self.latch_store: InterventionLatchStore | None = None
        self.inputs_validated = False

    def __call__(
        self,
        *,
        run_id: str,
        run_dir: Path,
        secret: str,
        descriptor_path: Path,
        latch_path: Path,
        ledger: EventLedger,
        correlation: MissionCorrelationBinding,
        correlation_producer: PinnedFactoryMissionRelationProducer,
        prepared: RunPreparation,
        runtime_forbidden_values: tuple[str, ...],
    ) -> ReviewControllerBinding:
        assert run_dir.is_dir()
        assert secret
        assert len(runtime_forbidden_values) == 2
        assert secret in runtime_forbidden_values
        assert descriptor_path.parent == run_dir
        assert latch_path.parent == run_dir
        assert ledger.run_id == run_id and ledger.run_dir == run_dir.resolve()
        assert isinstance(correlation, MissionCorrelationBinding)
        assert correlation.registry is not None
        assert prepared.repo.is_dir()
        correlation_producer.exclude("shadow-owned-control", "shadow_owned")
        correlation_producer.exclude("same-project-decoy", "same_project_decoy")
        self.inputs_validated = True
        controller_run_id = "run-wrong" if self.cross_run else run_id
        router = (
            self.router_factory(controller_run_id)
            if self.router_factory is not None
            else FakeRouter(controller_run_id)
        )
        self.controller = self.controller_type(
            controller_run_id,
            run_dir,
            router=router,
        )
        self.latch_store = InterventionLatchStore(
            run_dir,
            run_id=run_id,
            secret=secret,
            filename=latch_path.name,
        )
        self.latch_store.initialize(observed_at=1_100)
        return ReviewControllerBinding(
            self.controller,
            self.latch_store,
            forbidden_values=(
                *runtime_forbidden_values,
                *self.additional_forbidden_values,
            ),
        )


@dataclass
class RuntimeFixture:
    request: MissionRequest
    state_root: Path
    release_value: dict[str, Any]
    runner: FakeRunner

    def resign(self) -> None:
        self.release_value["record_digest"] = release_preflight_digest(
            self.release_value
        )
        self.request.release_preflight.write_text(
            json.dumps(self.release_value), encoding="utf-8"
        )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def with_record_digest(model_type: Any, value: dict[str, Any]) -> dict[str, Any]:
    result = model_type.model_construct(
        record_digest="0" * 64,
        **value,
    ).model_dump(mode="json")
    result.pop("record_digest")
    result["record_digest"] = hashlib.sha256(canonical_json(result)).hexdigest()
    return result


def status_intervention(run_id: str, final_state: str) -> InterventionRecord:
    states_by_final = {
        "queued": ("queued",),
        "delivered": ("queued", "delivered"),
        "acknowledged": ("queued", "delivered", "acknowledged"),
        "resolved": (
            "queued",
            "delivered",
            "acknowledged",
            "corrected",
            "resolved",
        ),
    }
    states = states_by_final[final_state]
    corrected = final_state == "resolved"
    transitions = tuple(
        InterventionTransition(
            transition_id=f"transition-status-{state}",
            generation=index,
            state=state,
            action=state,
            observed_at=1_100 + index,
        )
        for index, state in enumerate(states, start=1)
    )
    return InterventionRecord.model_validate(
        with_record_digest(
            InterventionRecord,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_record",
                "intervention_id": "intervention-status",
                "run_id": run_id,
                "finding_id": "finding-status",
                "finding_dedup_key": "a" * 64,
                "target_session": "worker-status",
                "completion_session_alias": "worker-status",
                "rule": "cross_worker_conflict",
                "level": "concern",
                "risk_category": "public_contract",
                "claim_ids": ("claim-a", "claim-b"),
                "direct_evidence_ids": ("evidence-a", "evidence-b"),
                "direct_evidence_digests": ("1" * 64, "2" * 64),
                "correction_evidence_ids": (
                    ("evidence-correction",) if corrected else ()
                ),
                "correction_evidence_digests": (
                    ("3" * 64,) if corrected else ()
                ),
                "generation": len(states),
                "state": final_state,
                "transition_history": transitions,
                "probe_id": "probe-status",
                "probe_digest": "4" * 64,
                "probe_status": "confirmed",
                "probe_snapshot_digest": "5" * 64,
                "blocking_scope": "worker",
                "attempts": 0,
            },
        )
    )


def status_router_state(
    run_id: str,
    final_state: str,
) -> InterventionRouterState:
    item = status_intervention(run_id, final_state)
    return InterventionRouterState.model_validate(
        with_record_digest(
            InterventionRouterState,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_state",
                "run_id": run_id,
                "generation": item.generation,
                "interventions": (item,),
            },
        )
    )


class SequencedRouter(FakeRouter):
    def __init__(
        self,
        run_id: str,
        states: tuple[InterventionRouterState, ...],
    ) -> None:
        super().__init__(run_id)
        self.states = states
        self.snapshot_calls = 0
        self._lock = threading.Lock()

    def snapshot(self) -> InterventionRouterState:
        with self._lock:
            index = min(self.snapshot_calls, len(self.states) - 1)
            self.snapshot_calls += 1
            return self.states[index]


class FinalStatusController(FakeReviewController):
    def drain(self, *, timeout: float = 5.0) -> bool:
        drained = super().drain(timeout=timeout)
        self.router.state = status_router_state(self.run_id, "acknowledged")
        return drained

    def reconcile_final_outage(self) -> None:
        super().reconcile_final_outage()
        self.router.state = status_router_state(self.run_id, "resolved")


def make_fixture(tmp_path: Path) -> RuntimeFixture:
    repo = tmp_path / "mission-repo"
    repo.mkdir(parents=True)
    mission_file = repo / "mission.yaml"
    mission_file.write_text("name: replay-safe-mission\n", encoding="utf-8")
    (repo / "input.txt").write_text("mission-visible\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q", str(repo)), check=True)
    subprocess.run(("git", "-C", str(repo), "add", "."), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Shadow Tests",
            "-c",
            "user.email=shadow-tests@example.invalid",
            "commit",
            "-qm",
            "initial",
        ),
        check=True,
    )
    commit = subprocess.run(
        ("git", "-C", str(repo), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    evaluator = tmp_path / "host-evaluator"
    evaluator.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    evaluator.chmod(0o700)
    droid = tmp_path / "droid"
    droid.write_text("pinned droid binary\n", encoding="utf-8")
    droid.chmod(0o700)

    profile = json.loads(
        (PROJECT_ROOT / "tests/fixtures/feasibility/factory-profile.json").read_text()
    )
    artifact_digest = compute_plugin_artifact_digest(PROJECT_ROOT)
    gate_digest = compute_gate_surface_digest(PROJECT_ROOT)
    profile["gate_surface_digest"] = gate_digest
    profile["installed_plugin_artifact_digest"] = artifact_digest
    profile["resolved_plugin_source"] = f"sha256:{artifact_digest}"
    profile["shadow_activation"] = True
    profile_path = tmp_path / "factory-profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    profile_result = validate_factory_profile(profile)

    isolation_path = tmp_path / "isolation-manifest.json"
    shutil.copyfile(
        PROJECT_ROOT / "tests/fixtures/feasibility/isolation-manifest.json",
        isolation_path,
    )
    lima_config = PROJECT_ROOT / "ops/lima/shadow-feasibility.yaml"
    isolation_result = validate_isolation_manifest(
        isolation_path, lima_config, require_live_canaries=False
    )

    feasibility_record = PROJECT_ROOT / ".shadow-mission/feasibility-gate.json"
    historical = json.loads(feasibility_record.read_text())
    historical_digest = hashlib.sha256(canonical_json(historical)).hexdigest()
    models = {
        "orchestrator": "model-orchestrator",
        "worker": "model-worker",
        "validator": "model-validator",
        "extractor": "model-extractor",
        "probe": "model-probe",
    }
    reasoning = {role: "high" for role in MODEL_ROLES}
    role_configuration = {
        "orchestrator": {"kind": "orchestrator", "count": 1},
        "worker": {"kind": "worker", "minimum": 2},
        "validator": {"kind": "validator", "count": 1},
        "extractor": {"kind": "internal"},
        "probe": {"kind": "internal", "read_only": True},
    }
    role_digest = hashlib.sha256(
        canonical_json(
            {
                "models": models,
                "reasoning": reasoning,
                "role_configuration": role_configuration,
            }
        )
    ).hexdigest()
    capabilities = CapabilityFlags(
        core_feasibility_verdict="pass",
        release_gate_verdict="fallback-pass",
        droid_version="0.197.0",
        plugin_version="0.1.0",
        droid_sdk_version="0.2.0",
        lima_version="2.2.0",
        vm_image_digest=isolation_result.image_digest,
        factory_profile_digest=profile_result.digest,
        isolation_digest=isolation_result.config_digest,
        gate_surface_digest=gate_digest,
        installed_plugin_artifact_digest=artifact_digest,
        transport_integrity="pass",
        hook_provenance="fallback",
        session_hooks="pass",
        identity="pass",
        transcript="pass",
        guidance="pass",
        worker_block="pass",
        mission_block="pass",
        worker_roles="pass",
        validator_roles="pass",
        self_session_exclusion="pass",
        sandbox_isolation="pass",
        probe_boundary="pass",
        live_validation_overlap="fallback",
    )
    factory_home = tmp_path / ".factory"
    factory_mission_root = factory_home / "missions"
    factory_session_root = factory_home / "sessions"
    factory_home.mkdir(mode=0o700)
    factory_mission_root.mkdir(mode=0o700)
    factory_session_root.mkdir(mode=0o700)
    installed_plugin_root = factory_home / "plugins/shadow-mission"
    for relative in PLUGIN_ARTIFACT_ROOTS:
        source = PROJECT_ROOT / relative
        destination = installed_plugin_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            shutil.copy2(source, destination)
    release_value: dict[str, Any] = {
        "schema_version": "0.1",
        "preflight_id": "preflight-approved",
        "approved_at": 1_000,
        "expires_at": 2_000,
        "authorization_id": "authorization-approved",
        "paid_run_authorized": True,
        "authorization_scope": "one-shadow-mission",
        "release_gate_verdict": "fallback-pass",
        "historical_record_digest": historical_digest,
        "historical_launch_artifact_digest": historical["bindings"][
            "launch_installed_plugin_artifact_digest"
        ],
        "droid_version": "0.197.0",
        "droid_installation_channel": "exact-npm",
        "droid_binary_digest": sha256_file(droid),
        "droid_auto_update_control": "npm-build-disabled",
        "plugin_version": "0.1.0",
        "droid_sdk_version": "0.2.0",
        "lima_version": "2.2.0",
        "vm_image_digest": isolation_result.image_digest,
        "factory_profile_digest": profile_result.digest,
        "profile_manifest_digest": sha256_file(profile_path),
        "isolation_digest": isolation_result.config_digest,
        "isolation_manifest_digest": sha256_file(isolation_path),
        "gate_surface_digest": gate_digest,
        "resolved_plugin_source": f"sha256:{artifact_digest}",
        "installed_plugin_artifact_digest": artifact_digest,
        "full_run_artifact_digest": compute_full_source_digest(PROJECT_ROOT),
        "mission_digest": sha256_file(mission_file),
        "mission_role_config_digest": role_digest,
        "mission_relation_source_digest": factory_relation_source_digest(
            sha256_file(droid)
        ),
        "evaluator_digest": sha256_file(evaluator),
        "initial_commit": commit,
        "models": models,
        "reasoning": reasoning,
        "role_configuration": role_configuration,
        "budget": {
            "initial_committed_cents": 3_000,
            "current_project_spend_cents": 3_500,
            "maximum_additional_exposure_cents": 1_000,
            "hard_stop_cents": 5_000,
            "live_run_count": 2,
            "max_live_runs": 6,
        },
        "capabilities": capabilities.model_dump(mode="json"),
        "record_digest": "0" * 64,
    }
    release_path = tmp_path / "release-preflight.json"
    request = MissionRequest(
        repo=repo,
        mission_file=mission_file,
        evaluator=evaluator,
        profile_manifest=profile_path,
        isolation_manifest=isolation_path,
        lima_config=lima_config,
        feasibility_record=feasibility_record,
        release_preflight=release_path,
        factory_mission_root=factory_mission_root,
        droid_path=droid,
        models=models,
        reasoning=reasoning,
    )
    runner = FakeRunner()
    runner.factory_mission_root = factory_mission_root
    fixture = RuntimeFixture(
        request=request,
        state_root=tmp_path / "private-state",
        release_value=release_value,
        runner=runner,
    )
    fixture.resign()
    return fixture


def bind_baseline_record(
    fixture: RuntimeFixture,
    *,
    initial_commit: str | None = None,
) -> BaselineRunRecord:
    release = fixture.release_value
    value = {
        "schema_version": "0.1",
        "provenance_status": "authoritative_input",
        "redaction_status": "clean",
        "droid_version": release["droid_version"],
        "plugin_version": release["plugin_version"],
        "droid_sdk_version": release["droid_sdk_version"],
        "lima_version": release["lima_version"],
        "droid_installation_channel": release["droid_installation_channel"],
        "droid_binary_digest": release["droid_binary_digest"],
        "droid_auto_update_control": release["droid_auto_update_control"],
        "gate_surface_digest": release["gate_surface_digest"],
        "installed_plugin_artifact_digest": release[
            "installed_plugin_artifact_digest"
        ],
        "full_run_artifact_digest": release["full_run_artifact_digest"],
        "historical_launch_artifact_digest": release[
            "historical_launch_artifact_digest"
        ],
        "resolved_plugin_source": release["resolved_plugin_source"],
        "release_preflight_digest": "1" * 64,
        "factory_profile_digest": release["factory_profile_digest"],
        "vm_image_digest": release["vm_image_digest"],
        "isolation_digest": release["isolation_digest"],
        "mission_digest": release["mission_digest"],
        "mission_role_config_digest": release["mission_role_config_digest"],
        "mission_relation_source_digest": release["mission_relation_source_digest"],
        "mission_relation_record_digest": None,
        "mission_outcome": "mission-complete",
        "approved_evaluator_digest": release["evaluator_digest"],
        "source_exporter_digest": sha256_file(
            PROJECT_ROOT / "demo/export_source.py"
        ),
        "initial_commit": initial_commit or release["initial_commit"],
        "final_commit": release["initial_commit"],
        "final_source_archive_digest": "2" * 64,
        "started_at": 900,
        "ended_at": 950,
        "duration_seconds": 50.0,
        "changed_files": (),
        "evaluator_outcome": "fail",
        "usage_data": {"status": "unavailable"},
        "budget_ledger": {"live_run_count": 2},
        "baseline_id": "baseline-demo",
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    baseline = BaselineRunRecord.model_validate(value)
    path = fixture.request.repo.parent / "baseline-run.json"
    path.write_bytes(canonical_json(baseline.model_dump(mode="json")) + b"\n")
    release["baseline_id"] = baseline.baseline_id
    release["baseline_record_digest"] = baseline.record_digest
    fixture.request = replace(fixture.request, baseline_record=path)
    fixture.resign()
    return baseline
def test_prepare_rejects_noncanonical_bound_baseline(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    baseline = bind_baseline_record(fixture)
    assert fixture.request.baseline_record is not None
    fixture.request.baseline_record.write_text(
        json.dumps(baseline.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(PreflightError, match="baseline record is not canonical"):
        runtime_for(fixture).prepare(fixture.request)


def test_relation_setup_drift_is_a_prelaunch_failure(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture.runner.mutate_after_version = (
        fixture.request.factory_mission_root / "unexpected"
    )

    with pytest.raises(
        PreflightError,
        match="Factory Mission relation source is invalid",
    ):
        run_approved(runtime_for(fixture), fixture.request)

    assert len(fixture.runner.calls) == 1
    assert not (fixture.state_root / "mission.lock").exists()


def test_installed_plugin_drift_stops_before_authorization(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)
    installed_hook = (
        fixture.request.factory_mission_root.parent
        / "plugins/shadow-mission/hooks/shadow_hook.py"
    )
    installed_hook.write_text(
        installed_hook.read_text(encoding="utf-8") + "\n# drift\n",
        encoding="utf-8",
    )

    with pytest.raises(
        PreflightError,
        match="installed plugin artifact digest differs",
    ):
        run_approved(runtime_for(fixture), fixture.request)

    assert not (fixture.state_root / "authorizations").exists()
    assert all(
        "--mission" not in arguments
        for arguments, _environment, _cwd in fixture.runner.calls
    )




def runtime_for(fixture: RuntimeFixture) -> MissionRuntime:
    return MissionRuntime(
        PROJECT_ROOT,
        state_root=fixture.state_root,
        command_runner=fixture.runner,
        clock=lambda: 1_100,
    )


def run_approved(
    runtime: MissionRuntime,
    request: MissionRequest,
    *,
    review_factory: FakeReviewFactory | None = None,
):
    return runtime.run(
        request,
        review_controller_factory=review_factory or FakeReviewFactory(),
    )


def test_prepare_validates_complete_approved_binding_without_state(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)

    prepared = runtime_for(fixture).prepare(fixture.request)

    assert prepared.preflight.release_gate_verdict == "fallback-pass"
    assert prepared.initial_commit == fixture.release_value["initial_commit"]
    assert not fixture.state_root.exists()
    assert fixture.runner.calls == []




@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("full_run_artifact_digest", "0" * 64, "full run artifact"),
        ("mission_digest", "0" * 64, "Mission file digest"),
        ("evaluator_digest", "0" * 64, "evaluator digest"),
        ("droid_binary_digest", "0" * 64, "Droid binary digest"),
        ("gate_surface_digest", "0" * 64, "gate-surface digest"),
        (
            "mission_relation_source_digest",
            "0" * 64,
            "Factory relation source binding",
        ),
        ("historical_record_digest", "0" * 64, "historical feasibility"),
        ("initial_commit", "b" * 40, "initial commit"),
    ],
)
def test_prepare_rejects_changed_bound_material(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    fixture = make_fixture(tmp_path)
    fixture.release_value[field] = value
    fixture.resign()

    with pytest.raises(PreflightError, match=message):
        runtime_for(fixture).prepare(fixture.request)

    assert not fixture.state_root.exists()
    assert fixture.runner.calls == []


def test_prepare_rejects_forged_release_preflight(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture.release_value["record_digest"] = "f" * 64
    fixture.request.release_preflight.write_text(
        json.dumps(fixture.release_value), encoding="utf-8"
    )

    with pytest.raises(PreflightError, match="record digest"):
        runtime_for(fixture).prepare(fixture.request)


def test_prepare_rejects_expired_or_over_budget_approval(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture.release_value["expires_at"] = 1_050
    fixture.resign()
    with pytest.raises(PreflightError, match="not currently valid"):
        runtime_for(fixture).prepare(fixture.request)

    fixture = make_fixture(tmp_path / "over-budget")
    fixture.release_value["budget"]["maximum_additional_exposure_cents"] = 1_500
    fixture.resign()
    with pytest.raises(PreflightError, match="contract is invalid"):
        runtime_for(fixture).prepare(fixture.request)


def test_prepare_rejects_model_reasoning_and_role_drift(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    changed_models = dict(fixture.request.models)
    changed_models["worker"] = "unapproved-model"
    fixture.request = MissionRequest(
        **{**fixture.request.__dict__, "models": changed_models}
    )
    with pytest.raises(PreflightError, match="requested models"):
        runtime_for(fixture).prepare(fixture.request)

    fixture = make_fixture(tmp_path / "role-drift")
    fixture.release_value["role_configuration"]["worker"]["minimum"] = 1
    fixture.resign()
    with pytest.raises(PreflightError, match="role configuration"):
        runtime_for(fixture).prepare(fixture.request)

    fixture = make_fixture(tmp_path / "secret-model")
    fixture.release_value["models"]["worker"] = "FACTORY_API_KEY=private"
    fixture.resign()
    with pytest.raises(PreflightError, match="contract is invalid"):
        runtime_for(fixture).prepare(fixture.request)



def test_prepare_rejects_private_state_inside_mission_repository(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)
    runtime = MissionRuntime(
        PROJECT_ROOT,
        state_root=fixture.request.repo / ".shadow-mission",
        command_runner=fixture.runner,
        clock=lambda: 1_100,
    )

    with pytest.raises(PreflightError, match="state root.*outside"):
        runtime.prepare(fixture.request)


def test_prepare_rejects_dirty_repository(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    (fixture.request.repo / "input.txt").write_text("changed\n", encoding="utf-8")

    with pytest.raises(PreflightError, match="must be clean"):
        runtime_for(fixture).prepare(fixture.request)


def test_prepare_rejects_evaluator_inside_mission_tree(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    evaluator = fixture.request.repo / "evaluator"
    evaluator.write_text("#!/bin/sh\n", encoding="utf-8")
    evaluator.chmod(0o700)
    fixture.request = MissionRequest(
        **{**fixture.request.__dict__, "evaluator": evaluator}
    )

    with pytest.raises(PreflightError, match="outside"):
        runtime_for(fixture).prepare(fixture.request)


@pytest.mark.parametrize("timeout_seconds", (0, -1, 1.5, True))
def test_run_rejects_invalid_mission_timeout_before_preflight(
    tmp_path: Path,
    timeout_seconds: Any,
) -> None:
    fixture = make_fixture(tmp_path)

    with pytest.raises(PreflightError, match="positive integer"):
        runtime_for(fixture).run(
            fixture.request,
            review_controller_factory=FakeReviewFactory(),
            timeout_seconds=timeout_seconds,
        )

    assert fixture.runner.calls == []
    assert not fixture.state_root.exists()


def test_run_rejects_missing_or_cross_run_review_before_launch(
    tmp_path: Path,
) -> None:
    missing = make_fixture(tmp_path / "missing")
    with pytest.raises(PreflightError, match="review controller"):
        runtime_for(missing).run(missing.request)
    assert missing.runner.calls == []
    assert not missing.state_root.exists()

    cross_run = make_fixture(tmp_path / "cross-run")
    with pytest.raises(PreflightError, match="another run"):
        run_approved(
            runtime_for(cross_run),
            cross_run.request,
            review_factory=FakeReviewFactory(cross_run=True),
        )
    assert len(cross_run.runner.calls) == 1
    assert "--mission" not in cross_run.runner.calls[0][0]
    assert not (cross_run.state_root / "mission.lock").exists()
    assert not (cross_run.state_root / "authorizations").exists()


def test_terminal_review_interrupts_child_and_persists_failure(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)
    review_factory = FakeReviewFactory()

    def make_terminal() -> None:
        assert review_factory.controller is not None
        review_factory.controller.termination_required = True
        review_factory.controller.unresolved_intervention_ids = ("blocker-1",)

    fixture.runner.interrupt_action = make_terminal
    with pytest.raises(MissionExecutionError, match="unresolved blocker"):
        run_approved(
            runtime_for(fixture),
            fixture.request,
            review_factory=review_factory,
        )

    assert fixture.runner.terminated is True
    assert review_factory.controller is not None
    assert review_factory.controller.lifecycle == [
        "start",
        "drain",
        "reconcile_final_outage",
        "stop",
    ]
    records = tuple((fixture.state_root / "runs").glob("*/run.json"))
    assert len(records) == 1
    assert json.loads(records[0].read_text())["evaluator_outcome"] == (
        "unresolved-blocker"
    )


def test_invalid_latch_interrupts_child(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    review_factory = FakeReviewFactory()

    def fail_latch() -> None:
        assert review_factory.latch_store is not None
        review_factory.latch_store.head_path.write_text(
            "{}\n", encoding="utf-8"
        )

    fixture.runner.interrupt_action = fail_latch
    with pytest.raises(MissionExecutionError, match="unresolved blocker"):
        run_approved(
            runtime_for(fixture),
            fixture.request,
            review_factory=review_factory,
        )

    assert fixture.runner.terminated is True
    records = tuple((fixture.state_root / "runs").glob("*/run.json"))
    assert json.loads(records[0].read_text())["evaluator_outcome"] == (
        "unresolved-blocker"
    )



def test_active_blocker_rejects_zero_exit_without_interrupting_child(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)
    review_factory = FakeReviewFactory()

    def block_completion() -> None:
        assert review_factory.controller is not None
        review_factory.controller.completion_blocked = True
        review_factory.controller.unresolved_intervention_ids = ("blocker-1",)

    fixture.runner.interrupt_action = block_completion
    with pytest.raises(MissionExecutionError, match="prevented Mission completion"):
        run_approved(
            runtime_for(fixture),
            fixture.request,
            review_factory=review_factory,
        )

    assert fixture.runner.terminated is False
    records = tuple((fixture.state_root / "runs").glob("*/run.json"))
    assert len(records) == 1
    assert json.loads(records[0].read_text())["evaluator_outcome"] == (
        "completion-blocked"
    )


def test_collector_degradation_is_persisted_before_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = make_fixture(tmp_path)
    original_stop = HookCollector.stop

    def degraded_stop(self: HookCollector, *, timeout: float = 5.0) -> None:
        self._mark_degraded("test-degradation")
        original_stop(self, timeout=timeout)

    monkeypatch.setattr(HookCollector, "stop", degraded_stop)
    with pytest.raises(MissionExecutionError, match="collector degraded"):
        run_approved(runtime_for(fixture), fixture.request)

    records = tuple((fixture.state_root / "runs").glob("*/run.json"))
    assert len(records) == 1
    assert json.loads(records[0].read_text())["evaluator_outcome"] == (
        "collector-degraded"
    )


def test_cleanup_failure_is_persisted_before_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = make_fixture(tmp_path)
    original_stop = HookCollector.stop

    def failing_stop(self: HookCollector, *, timeout: float = 5.0) -> None:
        original_stop(self, timeout=timeout)
        raise RuntimeError("synthetic cleanup failure")

    monkeypatch.setattr(HookCollector, "stop", failing_stop)
    with pytest.raises(MissionExecutionError, match="Mission cleanup failed"):
        run_approved(runtime_for(fixture), fixture.request)

    records = tuple((fixture.state_root / "runs").glob("*/run.json"))
    assert len(records) == 1
    assert json.loads(records[0].read_text())["evaluator_outcome"] == (
        "cleanup-failed"
    )
    persisted = json.loads(records[0].read_text())
    assert persisted["mission_outcome"] == "mission-failed"
    assert persisted["runtime_outcome"] == "cleanup-failed"


def test_final_git_inspection_failure_still_persists_run_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = make_fixture(tmp_path)
    real_repository_head = runtime_module._repository_head
    calls = 0

    def fail_final_head(repo: Path) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PreflightError("injected final Git failure")
        return real_repository_head(repo)

    monkeypatch.setattr(
        runtime_module,
        "_repository_head",
        fail_final_head,
    )

    with pytest.raises(MissionExecutionError, match="Mission cleanup failed"):
        run_approved(runtime_for(fixture), fixture.request)

    records = tuple((fixture.state_root / "runs").glob("*/run.json"))
    assert len(records) == 1
    persisted = json.loads(records[0].read_bytes())
    assert persisted["runtime_outcome"] == "cleanup-failed"
    assert persisted["final_commit"] is None


def test_review_degradation_interrupts_and_prevents_success(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    review_factory = FakeReviewFactory()

    def degrade_controller() -> None:
        assert review_factory.controller is not None
        review_factory.controller.releasable = False
        review_factory.controller.non_releasable_reason = "projection_failed"

    fixture.runner.interrupt_action = degrade_controller
    with pytest.raises(MissionExecutionError, match="review controller degraded"):
        run_approved(
            runtime_for(fixture),
            fixture.request,
            review_factory=review_factory,
        )

    assert fixture.runner.terminated is True
    records = tuple((fixture.state_root / "runs").glob("*/run.json"))
    assert json.loads(records[0].read_text())["evaluator_outcome"] == (
        "review-controller-degraded"
    )




def test_final_outage_reconciliation_failure_cannot_report_success(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)
    review_factory = FakeReviewFactory()

    def fail_reconciliation() -> None:
        assert review_factory.controller is not None

        def fail() -> None:
            raise RuntimeError("FACTORY_API_KEY=private")

        review_factory.controller.reconcile_final_outage = fail

    fixture.runner.interrupt_action = fail_reconciliation
    with pytest.raises(MissionExecutionError, match="Mission cleanup failed"):
        run_approved(
            runtime_for(fixture),
            fixture.request,
            review_factory=review_factory,
        )

    records = tuple((fixture.state_root / "runs").glob("*/run.json"))
    assert len(records) == 1
    persisted = records[0].read_text(encoding="utf-8")
    assert json.loads(persisted)["evaluator_outcome"] == "cleanup-failed"
    assert "FACTORY_API_KEY" not in persisted


def test_collector_thread_start_failure_releases_runtime_lock_and_threads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = make_fixture(tmp_path)
    review_factory = FakeReviewFactory()
    real_start = threading.Thread.start

    def start_review(controller: FakeReviewController) -> None:
        controller.lifecycle.append("start")
        stop_event = threading.Event()
        worker = threading.Thread(
            target=stop_event.wait,
            name="shadow-review-startup-failure",
            daemon=True,
        )
        controller._test_stop_event = stop_event
        controller._test_worker = worker
        worker.start()

    def stop_review(
        controller: FakeReviewController, *, timeout: float = 5.0
    ) -> bool:
        controller.lifecycle.append("stop")
        controller._test_stop_event.set()
        controller._test_worker.join(timeout)
        return not controller._test_worker.is_alive()

    monkeypatch.setattr(FakeReviewController, "start", start_review)
    monkeypatch.setattr(FakeReviewController, "stop", stop_review)

    def fail_collector_start(thread: threading.Thread) -> None:
        if thread.name == "shadow-hook-collector":
            raise RuntimeError("injected collector start failure")
        real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_collector_start)

    with pytest.raises(RuntimeError, match="injected collector start failure"):
        run_approved(
            runtime_for(fixture),
            fixture.request,
            review_factory=review_factory,
        )

    assert not (fixture.state_root / "mission.lock").exists()
    assert not any(
        thread.name.startswith(
            ("shadow-hook-collector", "shadow-ledger-", "shadow-review-")
        )
        for thread in threading.enumerate()
    )
    assert review_factory.controller is not None
    assert review_factory.controller.lifecycle == [
        "start",
        "drain",
        "reconcile_final_outage",
        "stop",
    ]


def test_status_thread_start_failure_releases_runtime_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = make_fixture(tmp_path)
    review_factory = FakeReviewFactory()
    real_start = threading.Thread.start

    def fail_status_start(thread: threading.Thread) -> None:
        if thread.name.startswith("shadow-status-"):
            raise RuntimeError("injected status start failure")
        real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_status_start)

    with pytest.raises(MissionExecutionError, match="Droid Mission process failed"):
        run_approved(
            runtime_for(fixture),
            fixture.request,
            review_factory=review_factory,
        )

    assert not (fixture.state_root / "mission.lock").exists()
    assert not any(
        thread.name.startswith(
            ("shadow-hook-collector", "shadow-ledger-", "shadow-review-")
        )
        for thread in threading.enumerate()
    )
    assert review_factory.controller is not None
    assert review_factory.controller.lifecycle == [
        "start",
        "drain",
        "reconcile_final_outage",
        "stop",
    ]


def test_run_persists_failed_process_stop_measurement(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture.runner.mission_process_stopped = False
    review_factory = FakeReviewFactory()

    with pytest.raises(
        MissionExecutionError,
        match="process group did not terminate",
    ) as caught:
        run_approved(
            runtime_for(fixture),
            fixture.request,
            review_factory=review_factory,
        )

    record = caught.value.run_record
    assert record is not None
    assert record.mission_process_stopped is False
    assert record.mission_outcome == "mission-failed"
    assert record.runtime_outcome == "cleanup-failed"
    persisted = RunRecord.model_validate(
        json.loads(
            (
                fixture.state_root
                / "runs"
                / record.run_id
                / "run.json"
            ).read_bytes()
        )
    )
    assert persisted == record


def test_run_uses_only_pinned_update_disabled_droid_boundary(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    factory_credential = "factory-credential-for-final-source-exclusion"
    review_factory = FakeReviewFactory(
        additional_forbidden_values=(factory_credential,)
    )
    runtime = runtime_for(fixture)

    record = run_approved(
        runtime,
        fixture.request,
        review_factory=review_factory,
    )

    assert len(fixture.runner.calls) == 2
    version_call, mission_call = fixture.runner.calls
    assert version_call[0][1:] == ("--version",)
    assert mission_call[0][1:6] == ("exec", "--mission", "--auto", "high", "-f")
    assert "--skip-permissions-unsafe" not in mission_call[0]
    for arguments, environment, cwd in fixture.runner.calls:
        if sys.platform.startswith("linux"):
            assert arguments[0].startswith("/proc/self/fd/")
            assert str(cwd).startswith("/proc/self/fd/")
        else:
            assert arguments[0] == str(fixture.request.droid_path.resolve())
            assert cwd == fixture.request.repo.resolve()
        assert environment["FACTORY_DROID_AUTO_UPDATE_ENABLED"] == "false"
        assert str(fixture.request.evaluator) not in " ".join(arguments)
        assert str(fixture.request.evaluator) not in json.dumps(environment)
        assert factory_credential not in " ".join(arguments)
        assert factory_credential not in json.dumps(environment)
    assert "SHADOW_MISSION_RUN_SECRET" not in version_call[1]
    assert "SHADOW_MISSION_RUN_SECRET" in mission_call[1]
    source_canary = mission_call[1]["SHADOW_MISSION_SECRET_CANARY"]
    assert source_canary.startswith("shadow-source-canary-")
    assert source_canary != mission_call[1]["SHADOW_MISSION_RUN_SECRET"]
    assert fixture.runner.descriptor is not None
    assert (
        int(fixture.runner.descriptor["expires_at"])
        - int(fixture.runner.descriptor["created_at"])
        == 7_500
    )
    assert runtime.take_finalization_canaries(record.run_id) == (
        mission_call[1]["SHADOW_MISSION_RUN_SECRET"],
        source_canary,
        factory_credential,
    )
    run_dir = fixture.state_root / "runs" / record.run_id
    for name in ("run.json", "status.json", "correlation.json"):
        payload = (run_dir / name).read_bytes()
        assert payload == canonical_json(json.loads(payload)) + b"\n"
        assert factory_credential.encode("utf-8") not in payload
    for path in run_dir.rglob("*"):
        if path.is_file():
            assert factory_credential.encode("utf-8") not in path.read_bytes()
    with pytest.raises(MissionExecutionError, match="canaries are unavailable"):
        runtime.take_finalization_canaries(record.run_id)
    assert record.mission_outcome == "mission-complete"
    assert record.runtime_outcome == "mission-terminated"
    assert record.mission_process_stopped is True
    assert record.evaluator_outcome == "mission-terminated"
    assert record.capabilities.sandbox_isolation == "fallback"
    assert record.budget_ledger["live_run_count_incremented"] is True
    assert record.budget_ledger["resulting_live_run_count"] == 3
    run_dir = fixture.state_root / "runs" / record.run_id
    assert (run_dir / "run.json").is_file()
    launch = json.loads((run_dir / "launch.json").read_text())
    assert launch["live_run_count_incremented"] is True
    assert launch["resulting_live_run_count"] == 3
    authorizations = tuple((fixture.state_root / "authorizations").iterdir())
    assert len(authorizations) == 1
    assert json.loads(authorizations[0].read_text())["run_id"] == record.run_id
    correlation_artifact = (run_dir / "correlation.json").read_text(encoding="utf-8")
    correlation_value = json.loads(correlation_artifact)
    assert correlation_value["role_counts"] == {
        "orchestrator": 1,
        "validator": 1,
        "worker": 2,
    }
    role_ids = tuple(correlation_value["role_assignments"])
    assert len(role_ids) == 4
    assert role_ids.count("orchestrator") == 1
    assert sum(role_id.startswith("worker:") for role_id in role_ids) == 2
    assert sum(role_id.startswith("validator:") for role_id in role_ids) == 1
    for raw_session_id in (
        "factory-orchestrator",
        "factory-worker-a",
        "factory-worker-b",
        "factory-validator",
        "mis_12345678",
    ):
        assert raw_session_id not in correlation_artifact
    assert not (run_dir / "descriptor.json").exists()
    assert not (run_dir / "latch.json").exists()
    assert not (run_dir / "latch-head.json").exists()
    assert not (run_dir / ".latch.json.lock").exists()
    assert review_factory.controller is not None
    assert review_factory.controller.lifecycle == [
        "start",
        "drain",
        "reconcile_final_outage",
        "stop",
    ]
    assert not (fixture.state_root / "mission.lock").exists()
    persisted = (run_dir / "run.json").read_text(encoding="utf-8")
    assert "SHADOW_MISSION_RUN_SECRET" not in persisted
    assert "pinned droid binary" not in persisted
    assert review_factory.inputs_validated is True
    tampered = record.model_dump(mode="json")
    tampered["plugin_version"] = "0.1.1"
    with pytest.raises(ValueError, match="record_digest"):
        RunRecord.model_validate(tampered)




def test_status_heartbeat_tracks_each_router_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = make_fixture(tmp_path)
    router_holder: dict[str, SequencedRouter] = {}

    def router_factory(run_id: str) -> SequencedRouter:
        router = SequencedRouter(
            run_id,
            tuple(
                status_router_state(run_id, state)
                for state in (
                    "queued",
                    "delivered",
                    "acknowledged",
                    "resolved",
                )
            ),
        )
        router_holder["router"] = router
        return router

    review_factory = FakeReviewFactory(router_factory=router_factory)
    captured_statuses: list[dict[str, Any]] = []
    capture_lock = threading.Lock()
    real_write = runtime_module._atomic_private_json

    def capture_write(path: Path, value: Mapping[str, Any]) -> None:
        real_write(path, value)
        if path.name == "status.json":
            with capture_lock:
                captured_statuses.append(
                    json.loads(canonical_json(dict(value)))
                )

    def wait_for_heartbeat() -> None:
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            with capture_lock:
                if any(
                    status["intervention_state"]["by_state"]
                    == {"delivered": 1}
                    for status in captured_statuses
                ):
                    return
            time.sleep(0.001)
        raise AssertionError("status heartbeat did not publish delivered state")

    monkeypatch.setattr(runtime_module, "_STATUS_HEARTBEAT_SECONDS", 0.001)
    monkeypatch.setattr(runtime_module, "_atomic_private_json", capture_write)
    fixture.runner.interrupt_action = wait_for_heartbeat

    run_approved(
        runtime_for(fixture),
        fixture.request,
        review_factory=review_factory,
    )

    observed = [status["intervention_state"] for status in captured_statuses]
    assert observed[:4] == [
        {
            "unresolved": 1,
            "unresolved_intervention_ids": ["intervention-status"],
            "by_state": {"queued": 1},
        },
        {
            "unresolved": 1,
            "unresolved_intervention_ids": ["intervention-status"],
            "by_state": {"delivered": 1},
        },
        {
            "unresolved": 1,
            "unresolved_intervention_ids": ["intervention-status"],
            "by_state": {"acknowledged": 1},
        },
        {
            "unresolved": 0,
            "unresolved_intervention_ids": [],
            "by_state": {"resolved": 1},
        },
    ]


def test_final_status_write_follows_drain_and_outage_reconciliation(
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
    assert review_factory.controller.router.snapshot().generation == 5
    status_value = json.loads(
        (
            fixture.state_root
            / "runs"
            / record.run_id
            / "status.json"
        ).read_bytes()
    )
    assert status_value["intervention_state"] == {
        "unresolved": 0,
        "unresolved_intervention_ids": [],
        "by_state": {"resolved": 1},
    }


def test_run_records_changed_files_with_redaction(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture.runner.mission_mutation = (
        fixture.request.repo / "FACTORY_API_KEY=private",
        "changed\n",
    )

    record = run_approved(runtime_for(fixture), fixture.request)

    assert record.changed_files == ("FACTORY_API_KEY=[REDACTED]",)


def test_version_or_binary_drift_stops_before_live_launch(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture.runner.version = "0.198.0"
    with pytest.raises(PreflightError, match="version observation"):
        run_approved(runtime_for(fixture), fixture.request)
    assert len(fixture.runner.calls) == 1
    assert not fixture.state_root.exists()

    fixture = make_fixture(tmp_path / "binary-drift")
    fixture.runner.mutate_after_version = fixture.request.droid_path
    with pytest.raises(PreflightError, match="drifted"):
        run_approved(runtime_for(fixture), fixture.request)
    assert len(fixture.runner.calls) == 1
    assert not fixture.state_root.exists()
