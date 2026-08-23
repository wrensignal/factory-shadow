"""Artifact-bound Mission lifecycle for no-spend replay and later approved runs."""

from __future__ import annotations

import errno
import hashlib
import importlib.metadata
import json
import os
import pty
import re
import secrets
import signal
import subprocess
import stat
import threading
import time
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .auth import (
    create_descriptor,
    generate_run_secret,
    production_latch_head_path,
)
from .collector import HookCollector
from .correlation import (
    FactoryMissionCorrelationWrapper,
    MissionCorrelationBinding,
    MissionCorrelationError,
    PinnedFactoryMissionRelationProducer,
    correlation_wrapper_digest,
    factory_relation_source_digest,
    require_host_factory_mission_root,
    snapshot_factory_mission_names,
)
from .internal_session import (
    InternalSessionError,
    sealed_descriptor_path,
    stage_bound_file,
)
from .isolation import IsolationError, validate_isolation_manifest
from .profile import (
    FactoryProfileError,
    PLUGIN_ARTIFACT_ROOTS,
    artifact_manifest,
    compute_gate_surface_digest,
    compute_plugin_artifact_digest,
    resolve_installed_plugin_root,
    validate_factory_profile,
)
from .protocol import (
    BaselineRunRecord,
    CapabilityFlags,
    HookEnvelope,
    HookExchangeRecord,
    HookRequest,
    RunRecord,
    canonical_json,
)
from .metrics import validate_baseline_binding
from .redaction import sanitize_value
from .status import intervention_state, status_record, terminal_status
from .storage import EventLedger, ResponsePlan

MODEL_KEYS = frozenset({"orchestrator", "worker", "validator", "extractor", "probe"})
REASONING_KEYS = MODEL_KEYS
EXPECTED_DROID_VERSION = "0.197.0"
EXPECTED_PLUGIN_VERSION = "0.1.0"
EXPECTED_SDK_VERSION = "0.2.0"
EXPECTED_LIMA_VERSION = "2.2.0"
MAX_INITIAL_BUDGET_CENTS = 3_000
HARD_PROJECT_STOP_CENTS = 5_000
MAX_MISSION_OUTPUT_BYTES = 1 << 20
_OUTPUT_READ_CHUNK_BYTES = 64 << 10
_DESCRIPTOR_CLEANUP_MARGIN_SECONDS = 300
_STATUS_HEARTBEAT_SECONDS = 5.0
_SOURCE_EXPORTER_RELATIVE = "demo/export_source.py"
_SOURCE_ROOTS = (*PLUGIN_ARTIFACT_ROOTS, "ops/lima", _SOURCE_EXPORTER_RELATIVE)


class PreflightError(ValueError):
    """No process may start because a release binding failed."""


class MissionExecutionError(RuntimeError):
    """A launched Mission or mandatory cleanup failed."""

    def __init__(
        self,
        message: str,
        *,
        run_record: RunRecord | None = None,
        mission_process_stopped: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.run_record = run_record
        self.mission_process_stopped = mission_process_stopped



class BudgetApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    initial_committed_cents: int = Field(ge=0)
    current_project_spend_cents: int = Field(ge=0)
    maximum_additional_exposure_cents: int = Field(gt=0)
    hard_stop_cents: int = Field(gt=0)
    live_run_count: int = Field(ge=0)
    max_live_runs: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_limits(self) -> BudgetApproval:
        if self.initial_committed_cents > MAX_INITIAL_BUDGET_CENTS:
            raise ValueError("initial committed budget exceeds $30")
        if self.hard_stop_cents != HARD_PROJECT_STOP_CENTS:
            raise ValueError("hard project stop must equal $50")
        if self.max_live_runs < 6:
            raise ValueError("live Mission cap must be at least six")
        if self.live_run_count >= self.max_live_runs:
            raise ValueError("live Mission cap is exhausted")
        if (
            self.current_project_spend_cents
            + self.maximum_additional_exposure_cents
            >= self.hard_stop_cents
        ):
            raise ValueError("project exposure does not fit below the hard stop")
        return self


class ReleasePreflight(BaseModel):
    """Host-approved immutable bindings required before one live launch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    preflight_id: str = Field(min_length=1)
    approved_at: int
    expires_at: int
    authorization_id: str = Field(min_length=1)
    paid_run_authorized: bool
    authorization_scope: Literal["one-shadow-mission"]
    release_gate_verdict: Literal["primary-pass", "fallback-pass"]
    historical_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    historical_launch_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    droid_version: str
    droid_installation_channel: str = Field(
        min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$"
    )
    droid_binary_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    droid_auto_update_control: Literal["env-false", "npm-build-disabled"]
    plugin_version: str
    droid_sdk_version: str
    lima_version: str
    vm_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    factory_profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    isolation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    isolation_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    gate_surface_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    resolved_plugin_source: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    installed_plugin_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    full_run_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    mission_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    mission_role_config_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    mission_relation_source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluator_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    initial_commit: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    baseline_id: str | None = Field(default=None, min_length=1)
    baseline_record_digest: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    models: dict[str, str]
    reasoning: dict[str, str]
    role_configuration: dict[str, Any]
    budget: BudgetApproval
    capabilities: CapabilityFlags
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_complete_bindings(self) -> ReleasePreflight:
        if not self.paid_run_authorized:
            raise ValueError("paid Mission is not authorized")
        if set(self.models) != MODEL_KEYS or any(not value for value in self.models.values()):
            raise ValueError("five explicit model IDs are required")
        if set(self.reasoning) != REASONING_KEYS or any(
            not value for value in self.reasoning.values()
        ):
            raise ValueError("five explicit reasoning values are required")
        if self.models["extractor"] == self.models["probe"]:
            raise ValueError("extractor and probe models must differ")
        if self.expires_at <= self.approved_at:
            raise ValueError("release preflight expiry is invalid")
        if (self.baseline_id is None) != (self.baseline_record_digest is None):
            raise ValueError("baseline preflight binding is incomplete")
        if self.capabilities.core_feasibility_verdict != "pass":
            raise ValueError("core feasibility did not pass")
        if self.capabilities.release_gate_verdict != self.release_gate_verdict:
            raise ValueError("release verdict binding differs")
        if any(
            not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", value)
            for value in self.models.values()
        ):
            raise ValueError("model IDs contain unsupported characters")
        if any(
            not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", value)
            for value in self.reasoning.values()
        ):
            raise ValueError("reasoning values contain unsupported characters")
        if any(
            sanitize_value(value)[1] != "clean"
            for value in (*self.models.values(), *self.reasoning.values())
        ):
            raise ValueError("model or reasoning values contain secret-like material")
        capability_values = self.capabilities.model_dump(mode="json")
        status_fields = (
            "transport_integrity",
            "hook_provenance",
            "session_hooks",
            "identity",
            "transcript",
            "guidance",
            "worker_block",
            "mission_block",
            "worker_roles",
            "validator_roles",
            "self_session_exclusion",
            "sandbox_isolation",
            "probe_boundary",
            "live_validation_overlap",
        )
        if any(capability_values[field] == "stop" for field in status_fields):
            raise ValueError("release preflight contains a stopped capability")
        return self


@dataclass(frozen=True)
class MissionRequest:
    repo: Path
    mission_file: Path
    evaluator: Path
    profile_manifest: Path
    isolation_manifest: Path
    lima_config: Path
    feasibility_record: Path
    release_preflight: Path
    factory_mission_root: Path
    droid_path: Path
    models: Mapping[str, str]
    reasoning: Mapping[str, str]
    baseline_record: Path | None = None


@dataclass(frozen=True)
class RunPreparation:
    request: MissionRequest
    preflight: ReleasePreflight
    repo: Path
    mission_file: Path
    evaluator: Path
    droid_path: Path
    profile_digest: str
    isolation_digest: str
    mission_root_digest: str
    initial_commit: str
    historical_launch_artifact_digest: str
    source_exporter_digest: str
    factory_mission_root: Path
    factory_mission_snapshot: frozenset[str]
    baseline: BaselineRunRecord | None

@dataclass(frozen=True)
class _PinnedLaunch:
    droid_path: Path
    mission_file: Path
    cwd: Path
    descriptors: tuple[int, ...] = ()

    def close(self) -> None:
        for descriptor in self.descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _pin_launch_boundaries(
    prepared: RunPreparation,
    state_root: Path,
) -> _PinnedLaunch:
    if not sys.platform.startswith("linux"):
        return _PinnedLaunch(
            prepared.droid_path,
            prepared.mission_file,
            prepared.repo,
        )

    descriptors: list[int] = []
    try:
        droid_descriptor = stage_bound_file(
            prepared.droid_path,
            prepared.preflight.droid_binary_digest,
            state_root,
        )
        descriptors.append(droid_descriptor)
        mission_descriptor = stage_bound_file(
            prepared.mission_file,
            prepared.preflight.mission_digest,
            state_root,
            require_executable=False,
            staging_name="mission",
        )
        descriptors.append(mission_descriptor)
        cwd_descriptor = os.open(
            prepared.repo,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        descriptors.append(cwd_descriptor)
        if not stat.S_ISDIR(os.fstat(cwd_descriptor).st_mode):
            raise PreflightError("Mission working directory is invalid")
        return _PinnedLaunch(
            sealed_descriptor_path(
                droid_descriptor,
                os.fstat(droid_descriptor),
            ),
            sealed_descriptor_path(
                mission_descriptor,
                os.fstat(mission_descriptor),
            ),
            Path("/proc/self/fd") / str(cwd_descriptor),
            tuple(descriptors),
        )
    except (InternalSessionError, OSError) as error:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise PreflightError("sealed Mission launch staging failed") from error




@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    mission_process_stopped: bool = True


class _BoundedOutputCapture:
    """Drain two child pipes while retaining one aggregate bounded diagnostic."""

    def __init__(self, quota: int) -> None:
        self._quota = quota
        self._buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self._retained = 0
        self._lock = threading.Lock()
        self.overflow = threading.Event()
        self.failed = threading.Event()

    def drain(self, stream: Any, channel: str) -> None:
        try:
            while True:
                try:
                    chunk = stream.read(_OUTPUT_READ_CHUNK_BYTES)
                except OSError as error:
                    if error.errno == errno.EIO:
                        return
                    raise
                if not chunk:
                    return
                with self._lock:
                    remaining = self._quota - self._retained
                    retained = chunk[:remaining]
                    self._buffers[channel].extend(retained)
                    self._retained += len(retained)
                    if len(chunk) > remaining:
                        self.overflow.set()
        except BaseException:
            self.failed.set()
        finally:
            try:
                stream.close()
            except OSError:
                self.failed.set()

    def result(self) -> tuple[str, str]:
        with self._lock:
            stdout = self._buffers["stdout"].decode("utf-8", errors="replace")
            stderr = self._buffers["stderr"].decode("utf-8", errors="replace")
        return stdout, stderr


class MissionReviewControllerBoundary(Protocol):
    run_id: str
    run_dir: Path
    router: Any

    @property
    def releasable(self) -> bool: ...

    @property
    def non_releasable_reason(self) -> str | None: ...

    @property
    def termination_required(self) -> bool: ...

    @property
    def unresolved_intervention_ids(self) -> tuple[str, ...]: ...

    @property
    def completion_blocked(self) -> bool: ...


    def capture_request(
        self, request: HookRequest, envelope: HookEnvelope
    ) -> None: ...

    def discard_request(self, event_id: str) -> None: ...

    def decide(self, envelope: HookEnvelope) -> ResponsePlan: ...

    def after_append(self, exchange: HookExchangeRecord) -> None: ...

    def start(self) -> None: ...

    def drain(self, *, timeout: float = 5.0) -> bool: ...

    def reconcile_final_outage(self) -> object | None: ...


    def stop(self, *, timeout: float = 5.0) -> bool: ...


class LatchTerminationBoundary(Protocol):
    run_id: str
    path: Path
    head_path: Path
    lock_path: Path

    @property
    def termination_required(self) -> bool: ...

    @property
    def completion_blocked(self) -> bool: ...



@dataclass(frozen=True)
class ReviewControllerBinding:
    controller: MissionReviewControllerBoundary
    latch_store: LatchTerminationBoundary
    forbidden_values: tuple[str, ...] = field(default=(), repr=False)


class ReviewControllerFactory(Protocol):
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
    ) -> ReviewControllerBinding: ...



class CommandRunner(Protocol):
    def run(
        self,
        arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        timeout_seconds: int,
        pass_fds: tuple[int, ...] = (),
    ) -> CommandResult: ...
    def run_interruptible(
        self,
        arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        timeout_seconds: int,
        termination_required: Callable[[], bool],
        termination_grace_seconds: float = 5.0,
        pass_fds: tuple[int, ...] = (),
    ) -> CommandResult: ...



def _process_group_alive(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


class SubprocessCommandRunner:
    """Run a reviewed argument vector without a shell."""

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        timeout_seconds: int,
        pass_fds: tuple[int, ...] = (),
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                arguments,
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                timeout=timeout_seconds,
                pass_fds=pass_fds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise MissionExecutionError("Droid process boundary failed") from error
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)

    def run_interruptible(
        self,
        arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        timeout_seconds: int,
        termination_required: Callable[[], bool],
        termination_grace_seconds: float = 5.0,
        pass_fds: tuple[int, ...] = (),
    ) -> CommandResult:
        if timeout_seconds <= 0 or termination_grace_seconds < 0:
            raise ValueError("process timeouts must be valid")
        master = slave = -1
        try:
            master, slave = pty.openpty()
            process = subprocess.Popen(
                arguments,
                cwd=cwd,
                env=dict(environment),
                stdin=slave,
                stdout=slave,
                stderr=slave,
                text=False,
                shell=False,
                pass_fds=pass_fds,
                start_new_session=True,
            )
        except OSError as error:
            raise MissionExecutionError(
                "Droid process boundary failed",
                mission_process_stopped=True,
            ) from error
        finally:
            if slave >= 0:
                os.close(slave)

        assert process.stdout is None and process.stderr is None
        capture = _BoundedOutputCapture(MAX_MISSION_OUTPUT_BYTES)
        pty_stream = os.fdopen(master, "rb", buffering=0)
        drainers = (
            threading.Thread(
                target=capture.drain,
                args=(pty_stream, "stdout"),
                name="shadow-mission-stdout",
                daemon=True,
            ),
        )
        started_drainers: list[threading.Thread] = []
        try:
            for drainer in drainers:
                drainer.start()
                started_drainers.append(drainer)
        except BaseException as error:
            try:
                pty_stream.close()
            except OSError:
                pass
            stopped = self._terminate_process_group(
                process, tuple(started_drainers), termination_grace_seconds
            )
            raise MissionExecutionError(
                "Droid output capture failed",
                mission_process_stopped=stopped,
            ) from error

        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            if capture.overflow.is_set():
                stopped = self._terminate_process_group(
                    process, drainers, termination_grace_seconds
                )
                raise MissionExecutionError(
                    "Droid output limit exceeded",
                    mission_process_stopped=stopped,
                )
            if capture.failed.is_set():
                stopped = self._terminate_process_group(
                    process, drainers, termination_grace_seconds
                )
                raise MissionExecutionError(
                    "Droid output capture failed",
                    mission_process_stopped=stopped,
                )
            try:
                must_terminate = termination_required()
            except BaseException as error:
                stopped = self._terminate_process_group(
                    process, drainers, termination_grace_seconds
                )
                raise MissionExecutionError(
                    "review termination check failed",
                    mission_process_stopped=stopped,
                ) from error
            if must_terminate:
                stopped = self._terminate_process_group(
                    process, drainers, termination_grace_seconds
                )
                if capture.overflow.is_set():
                    raise MissionExecutionError(
                        "Droid output limit exceeded",
                        mission_process_stopped=stopped,
                    )
                if capture.failed.is_set():
                    raise MissionExecutionError(
                        "Droid output capture failed",
                        mission_process_stopped=stopped,
                    )
                stdout, stderr = capture.result()
                return CommandResult(
                    process.returncode if process.returncode is not None else -1,
                    stdout,
                    stderr,
                    stopped,
                )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stopped = self._terminate_process_group(
                    process, drainers, termination_grace_seconds
                )
                if capture.overflow.is_set():
                    raise MissionExecutionError(
                        "Droid output limit exceeded",
                        mission_process_stopped=stopped,
                    )
                raise MissionExecutionError(
                    "Droid process timed out",
                    mission_process_stopped=stopped,
                )
            try:
                process.wait(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                continue

        stopped = self._terminate_process_group(
            process, drainers, termination_grace_seconds
        )
        if capture.overflow.is_set():
            raise MissionExecutionError(
                "Droid output limit exceeded",
                mission_process_stopped=stopped,
            )
        if capture.failed.is_set():
            raise MissionExecutionError(
                "Droid output capture failed",
                mission_process_stopped=stopped,
            )
        stdout, stderr = capture.result()
        return CommandResult(
            process.returncode if process.returncode is not None else -1,
            stdout,
            stderr,
            stopped,
        )

    @classmethod
    def _terminate_process_group(
        cls,
        process: subprocess.Popen[bytes],
        drainers: tuple[threading.Thread, ...],
        grace_seconds: float,
    ) -> bool:
        deadline = time.monotonic() + grace_seconds
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            pass
        term_deadline = time.monotonic() + max(
            0.0, (deadline - time.monotonic()) / 2
        )
        cls._wait_process_group_exit(process, term_deadline)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        stopped = cls._wait_process_group_exit(process, deadline)
        try:
            cls._join_drainers_until(drainers, deadline)
        except MissionExecutionError as error:
            raise MissionExecutionError(
                str(error),
                mission_process_stopped=stopped,
            ) from error
        return stopped

    @staticmethod
    def _wait_process_group_exit(
        process: subprocess.Popen[bytes], deadline: float
    ) -> bool:
        while True:
            leader_alive = process.poll() is None
            group_alive = _process_group_alive(process.pid)
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

    @classmethod
    def _join_drainers(
        cls, drainers: tuple[threading.Thread, ...], timeout: float
    ) -> None:
        cls._join_drainers_until(drainers, time.monotonic() + timeout)

    @staticmethod
    def _join_drainers_until(
        drainers: tuple[threading.Thread, ...], deadline: float
    ) -> None:
        for drainer in drainers:
            drainer.join(max(0.0, deadline - time.monotonic()))
        if any(drainer.is_alive() for drainer in drainers):
            raise MissionExecutionError("Droid output drain did not stop")


def _sha256_file(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            raise PreflightError(f"required file is not regular: {path.name}")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise PreflightError(f"cannot read required file: {path.name}") from error


def _load_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreflightError(f"{description} is unreadable") from error
    if not isinstance(value, dict):
        raise PreflightError(f"{description} must be an object")
    return value
def _load_canonical_json(path: Path, description: str) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreflightError(f"{description} is unreadable") from error
    if not isinstance(value, dict):
        raise PreflightError(f"{description} must be an object")
    if payload != canonical_json(value) + b"\n":
        raise PreflightError(f"{description} is not canonical")
    return value




def _without_record_digest(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "record_digest"}


def release_preflight_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(_without_record_digest(value))).hexdigest()


def load_release_preflight(path: Path, *, now: int | None = None) -> ReleasePreflight:
    value = _load_json(path, "release preflight")
    expected_digest = release_preflight_digest(value)
    if value.get("record_digest") != expected_digest:
        raise PreflightError("release preflight record digest differs")
    try:
        preflight = ReleasePreflight.model_validate(value)
    except ValueError as error:
        raise PreflightError("release preflight contract is invalid") from error
    current_time = int(time.time()) if now is None else int(now)
    if preflight.approved_at > current_time or preflight.expires_at < current_time:
        raise PreflightError("release preflight is not currently valid")
    return preflight


def compute_full_source_digest(project_root: Path) -> str:
    manifest = artifact_manifest(project_root, _SOURCE_ROOTS)
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def _git_output(repo: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ("/usr/bin/env", "git", "-C", str(repo), *arguments),
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "LC_ALL": "C",
                "GIT_OPTIONAL_LOCKS": "0",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PreflightError("Git repository inspection failed") from error
    if completed.returncode != 0:
        raise PreflightError("Git repository inspection failed")
    return completed.stdout


def _repository_head(repo: Path) -> str:
    head = _git_output(repo, "rev-parse", "--verify", "HEAD").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", head):
        raise PreflightError("repository HEAD is not a commit digest")
    return head


def _require_clean_repository(repo: Path) -> None:
    status = _git_output(
        repo,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status:
        raise PreflightError("Mission repository must be clean")


def _changed_files(repo: Path) -> tuple[str, ...]:
    raw_paths = {
        *(_git_output(repo, "diff", "--name-only", "-z", "HEAD").split("\0")),
        *(
            _git_output(
                repo,
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
            ).split("\0")
        ),
    }
    changed: list[str] = []
    for raw_path in sorted(raw_paths):
        if not raw_path:
            continue
        path = Path(raw_path)
        if path.is_absolute() or ".." in path.parts:
            raise PreflightError("Git returned an unsafe changed path")
        sanitized, _ = sanitize_value(path.as_posix())
        if not isinstance(sanitized, str):
            raise PreflightError("Git returned an invalid changed path")
        changed.append(sanitized)
    return tuple(changed)


def _tree_digest(root: Path, *, excluded: frozenset[str]) -> str:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        if any(part in excluded for part in relative.parts):
            continue
        if path.is_symlink():
            raise PreflightError("Mission tree contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise PreflightError("Mission tree contains a non-regular entry")
        records.append(
            {
                "path": relative.as_posix(),
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return hashlib.sha256(canonical_json({"files": records})).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(dict(value)))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _exclusive_private_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(
        f".{path.name}.{secrets.token_hex(8)}.tmp"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(dict(value)))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise PreflightError(
                "release authorization was already consumed"
            ) from error
        temporary.unlink()
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)

def validate_live_authorization_ledger(
    state_root: Path,
    *,
    live_run_count: int,
) -> Path:
    authorization_directory = state_root / "authorizations"
    if authorization_directory.is_symlink() or (
        authorization_directory.exists() and not authorization_directory.is_dir()
    ):
        raise PreflightError("authorization ledger is invalid")
    prior_authorizations = (
        tuple(authorization_directory.iterdir())
        if authorization_directory.exists()
        else ()
    )
    if any(
        entry.is_symlink() or not entry.is_file()
        for entry in prior_authorizations
    ):
        raise PreflightError("authorization ledger contains an invalid entry")
    expected_authorizations = live_run_count - 2
    if (
        expected_authorizations < 0
        or len(prior_authorizations) != expected_authorizations
    ):
        raise PreflightError("local live-run ledger does not reconcile")
    return authorization_directory


def consume_release_authorization(
    state_root: Path,
    *,
    preflight: ReleasePreflight,
    run_id: str,
    consumed_at: int,
) -> Path:
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_root, 0o700)
    authorization_directory = validate_live_authorization_ledger(
        state_root,
        live_run_count=preflight.budget.live_run_count,
    )
    authorization_path = authorization_directory / (
        hashlib.sha256(preflight.authorization_id.encode("utf-8")).hexdigest()
        + ".json"
    )
    _exclusive_private_json(
        authorization_path,
        {
            "schema_version": "0.1",
            "authorization_id_digest": authorization_path.stem,
            "preflight_record_digest": preflight.record_digest,
            "run_id": run_id,
            "consumed_at": consumed_at,
            "prior_live_run_count": preflight.budget.live_run_count,
            "resulting_live_run_count": preflight.budget.live_run_count + 1,
        },
    )
    return authorization_path




def _require_private_review_file(path: Path, *, run_dir: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PreflightError("review latch boundary is incomplete") from error
    if (
        path.parent.resolve() != run_dir
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise PreflightError("review latch boundary is invalid")


def _validate_review_binding(
    binding: ReviewControllerBinding,
    *,
    run_id: str,
    run_dir: Path,
    latch_path: Path,
) -> None:
    if not isinstance(binding, ReviewControllerBinding):
        raise PreflightError("review controller factory returned an invalid binding")
    controller = binding.controller
    latch_store = binding.latch_store
    try:
        controller_run_dir = Path(controller.run_dir).resolve(strict=True)
        controller_valid = (
            controller.run_id == run_id
            and controller_run_dir == run_dir
            and all(
                callable(getattr(controller, name, None))
                for name in (
                    "capture_request",
                    "discard_request",
                    "decide",
                    "after_append",
                    "start",
                    "drain",
                    "reconcile_final_outage",
                    "stop",
                )
            )
            and callable(getattr(controller.router, "snapshot", None))
            and isinstance(binding.forbidden_values, tuple)
            and all(
                isinstance(value, str) and value
                for value in binding.forbidden_values
            )
            and isinstance(controller.releasable, bool)
            and isinstance(controller.non_releasable_reason, (str, type(None)))
            and isinstance(controller.termination_required, bool)
            and isinstance(controller.completion_blocked, bool)
            and isinstance(controller.unresolved_intervention_ids, tuple)
            and all(
                isinstance(value, str) and value
                for value in controller.unresolved_intervention_ids
            )
        )
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise PreflightError("review controller boundary is invalid") from error
    if not controller_valid:
        raise PreflightError("review controller belongs to another run")

    expected_head = production_latch_head_path(latch_path)
    expected_lock = run_dir / f".{latch_path.name}.lock"
    try:
        latch_valid = (
            latch_store.run_id == run_id
            and Path(latch_store.path).resolve(strict=True) == latch_path
            and Path(latch_store.head_path).resolve(strict=True) == expected_head
            and Path(latch_store.lock_path).resolve(strict=True) == expected_lock
        )
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise PreflightError("review latch boundary is invalid") from error
    if not latch_valid:
        raise PreflightError("review latch belongs to another run")
    for path in (latch_path, expected_head, expected_lock):
        _require_private_review_file(path, run_dir=run_dir)
    try:
        latch_termination_required = latch_store.termination_required
        latch_completion_blocked = latch_store.completion_blocked
        controller_releasable = controller.releasable
        controller_termination_required = controller.termination_required
        controller_completion_blocked = controller.completion_blocked
    except Exception as error:
        raise PreflightError("review supervision boundary is invalid") from error
    if (
        not isinstance(latch_termination_required, bool)
        or not isinstance(latch_completion_blocked, bool)
        or not isinstance(controller_completion_blocked, bool)
    ):
        raise PreflightError("review latch termination state is invalid")
    if latch_termination_required:
        raise PreflightError("review latch is not active")
    if not controller_releasable or controller_termination_required:
        raise PreflightError("review controller is not active")


class MissionRuntime:
    """Validate all bindings, then run at most one approved Mission."""

    def __init__(
        self,
        project_root: Path,
        *,
        state_root: Path | None = None,
        command_runner: CommandRunner | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.project_root = project_root.resolve(strict=True)
        raw_state_root = state_root or self.project_root / ".shadow-mission"
        if raw_state_root.is_symlink() or (
            raw_state_root.exists() and not raw_state_root.is_dir()
        ):
            raise PreflightError("private state root is invalid")
        self.state_root = raw_state_root.resolve()
        self.command_runner = command_runner or SubprocessCommandRunner()
        self.clock = clock
        self._finalization_forbidden_values: dict[str, tuple[str, ...]] = {}

    def take_finalization_canaries(self, run_id: str) -> tuple[str, ...]:
        """Consume exact source-export forbidden values for one completed Mission."""
        try:
            return self._finalization_forbidden_values.pop(run_id)
        except KeyError as error:
            raise MissionExecutionError(
                "Mission finalization canaries are unavailable"
            ) from error

    def prepare(self, request: MissionRequest) -> RunPreparation:
        repo = request.repo.resolve(strict=True)
        if not repo.is_dir() or repo.is_symlink():
            raise PreflightError("Mission repository is invalid")
        mission_file = request.mission_file.resolve(strict=True)
        if repo not in mission_file.parents or not mission_file.is_file() or mission_file.is_symlink():
            raise PreflightError("Mission file must be a regular file inside the repository")
        evaluator = request.evaluator.resolve(strict=True)
        if evaluator == repo or repo in evaluator.parents:
            raise PreflightError("evaluator must remain outside the Mission repository")
        if not evaluator.is_file() or evaluator.is_symlink():
            raise PreflightError("evaluator must be a regular host-held file")
        if not os.access(evaluator, os.X_OK):
            raise PreflightError("evaluator must be executable")
        droid_path = request.droid_path.resolve(strict=True)
        if not droid_path.is_file() or droid_path.is_symlink() or not os.access(droid_path, os.X_OK):
            raise PreflightError("Droid binary is invalid")

        preflight = load_release_preflight(
            request.release_preflight, now=int(self.clock())
        )
        if dict(request.models) != preflight.models:
            raise PreflightError("requested models differ from approved models")
        if dict(request.reasoning) != preflight.reasoning:
            raise PreflightError("requested reasoning differs from approved reasoning")

        historical = _load_json(request.feasibility_record, "feasibility record")
        historical_digest = hashlib.sha256(canonical_json(historical)).hexdigest()
        if historical_digest != preflight.historical_record_digest:
            raise PreflightError("historical feasibility record binding differs")
        if historical.get("core_feasibility_verdict") != "pass":
            raise PreflightError("core feasibility did not pass")
        if historical.get("live_run_count") != 2:
            raise PreflightError("historical live-run count differs")
        bindings = historical.get("bindings")
        if not isinstance(bindings, Mapping):
            raise PreflightError("historical feasibility bindings are missing")
        fixed = {
            "droid_version": EXPECTED_DROID_VERSION,
            "plugin_version": EXPECTED_PLUGIN_VERSION,
            "droid_sdk_version": EXPECTED_SDK_VERSION,
            "lima_version": EXPECTED_LIMA_VERSION,
        }
        for name, expected in fixed.items():
            if bindings.get(name) != expected or getattr(preflight, name) != expected:
                raise PreflightError(f"{name} differs from the feasibility constraint")
        launch_digest = bindings.get("launch_installed_plugin_artifact_digest")
        if launch_digest != preflight.historical_launch_artifact_digest:
            raise PreflightError("historical launch artifact binding differs")

        current_gate_digest = compute_gate_surface_digest(self.project_root)
        if preflight.gate_surface_digest != current_gate_digest:
            raise PreflightError("gate-surface digest differs")
        current_artifact_digest = compute_plugin_artifact_digest(self.project_root)
        if preflight.installed_plugin_artifact_digest != current_artifact_digest:
            raise PreflightError("installed plugin artifact digest differs")
        if preflight.resolved_plugin_source != f"sha256:{current_artifact_digest}":
            raise PreflightError("resolved plugin source differs")
        if preflight.full_run_artifact_digest != compute_full_source_digest(self.project_root):
            raise PreflightError("full run artifact digest differs")

        plugin_manifest = _load_json(
            self.project_root / ".factory-plugin/plugin.json", "plugin manifest"
        )
        if plugin_manifest.get("version") != preflight.plugin_version:
            raise PreflightError("plugin manifest version differs")
        try:
            sdk_version = importlib.metadata.version("droid-sdk")
        except importlib.metadata.PackageNotFoundError as error:
            raise PreflightError("Droid SDK installation is unavailable") from error
        if sdk_version != preflight.droid_sdk_version:
            raise PreflightError("Droid SDK version differs")
        if _sha256_file(droid_path) != preflight.droid_binary_digest:
            raise PreflightError("Droid binary digest differs")

        profile_value = _load_json(request.profile_manifest, "Factory profile")
        try:
            profile_result = validate_factory_profile(profile_value)
        except FactoryProfileError as error:
            raise PreflightError("Factory profile is not approved") from error
        if not profile_result.activation_enabled:
            raise PreflightError("Shadow activation is disabled in the Factory profile")
        if profile_result.digest != preflight.factory_profile_digest:
            raise PreflightError("Factory profile digest differs")
        if _sha256_file(request.profile_manifest) != preflight.profile_manifest_digest:
            raise PreflightError("Factory profile file binding differs")
        if profile_value.get("gate_surface_digest") != current_gate_digest:
            raise PreflightError("Factory profile gate surface differs")
        if profile_value.get("installed_plugin_artifact_digest") != current_artifact_digest:
            raise PreflightError("Factory profile installed artifact differs")

        try:
            isolation_result = validate_isolation_manifest(
                request.isolation_manifest,
                request.lima_config,
                require_live_canaries=False,
            )
        except IsolationError as error:
            raise PreflightError("isolation manifest is not approved") from error
        if isolation_result.config_digest != preflight.isolation_digest:
            raise PreflightError("isolation digest differs")
        if isolation_result.image_digest != preflight.vm_image_digest:
            raise PreflightError("VM image digest differs")
        if _sha256_file(request.isolation_manifest) != preflight.isolation_manifest_digest:
            raise PreflightError("isolation manifest file binding differs")
        if bindings.get("isolation_config_digest") != preflight.isolation_digest:
            raise PreflightError("historical isolation constraint differs")

        mission_digest = _sha256_file(mission_file)
        evaluator_digest = _sha256_file(evaluator)
        if mission_digest != preflight.mission_digest:
            raise PreflightError("Mission file digest differs")
        if evaluator_digest != preflight.evaluator_digest:
            raise PreflightError("evaluator digest differs")
        role_digest = hashlib.sha256(
            canonical_json(
                {
                    "models": dict(request.models),
                    "reasoning": dict(request.reasoning),
                    "role_configuration": preflight.role_configuration,
                }
            )
        ).hexdigest()
        if role_digest != preflight.mission_role_config_digest:
            raise PreflightError("Mission role configuration digest differs")
        expected_relation_source = factory_relation_source_digest(
            preflight.droid_binary_digest
        )
        if expected_relation_source != preflight.mission_relation_source_digest:
            raise PreflightError("Factory relation source binding differs")
        try:
            mission_root_metadata = request.factory_mission_root.lstat()
            factory_mission_root = require_host_factory_mission_root(
                request.factory_mission_root
            )
        except (OSError, MissionCorrelationError) as error:
            raise PreflightError("Factory Mission root is unavailable") from error
        if (
            request.factory_mission_root.is_symlink()
            or not stat.S_ISDIR(mission_root_metadata.st_mode)
            or mission_root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(mission_root_metadata.st_mode) & 0o022
        ):
            raise PreflightError("Factory Mission root is not clean")
        try:
            factory_mission_snapshot = snapshot_factory_mission_names(
                factory_mission_root
            )
        except MissionCorrelationError as error:
            raise PreflightError("Factory Mission root is unavailable") from error
        if factory_mission_root == repo or repo in factory_mission_root.parents:
            raise PreflightError("Factory Mission root must remain outside the repository")
        if (
            self.state_root == repo
            or repo in self.state_root.parents
            or self.state_root in repo.parents
        ):
            raise PreflightError(
                "private state root must remain outside the Mission repository"
            )
        if (
            self.state_root == factory_mission_root
            or factory_mission_root in self.state_root.parents
            or self.state_root in factory_mission_root.parents
        ):
            raise PreflightError(
                "private state root must remain outside the Factory Mission root"
            )
        source_exporter_digest = _sha256_file(
            self.project_root / _SOURCE_EXPORTER_RELATIVE
        )
        baseline: BaselineRunRecord | None = None
        if request.baseline_record is None:
            if preflight.baseline_record_digest is not None:
                raise PreflightError("bound baseline record is missing")
        else:
            try:
                baseline_metadata = request.baseline_record.lstat()
                if (
                    request.baseline_record.is_symlink()
                    or not stat.S_ISREG(baseline_metadata.st_mode)
                ):
                    raise PreflightError("baseline record must be a regular file")
                baseline_path = request.baseline_record.resolve(strict=True)
            except PreflightError:
                raise
            except OSError as error:
                raise PreflightError("baseline record is unavailable") from error
            if baseline_path == repo or repo in baseline_path.parents:
                raise PreflightError("baseline record must remain host-held")
            try:
                baseline = BaselineRunRecord.model_validate(
                    _load_canonical_json(baseline_path, "baseline record")
                )
            except PreflightError:
                raise
            except ValueError as error:
                raise PreflightError("baseline record is invalid") from error
            if (
                baseline.record_digest != preflight.baseline_record_digest
                or baseline.baseline_id != preflight.baseline_id
            ):
                raise PreflightError("baseline record binding differs")
            comparison_bindings = preflight.model_dump(mode="json")
            comparison_bindings["approved_evaluator_digest"] = preflight.evaluator_digest
            comparison_bindings["source_exporter_digest"] = source_exporter_digest
            matches, mismatch = validate_baseline_binding(
                baseline, comparison_bindings
            )
            if not matches:
                raise PreflightError(
                    f"baseline comparison binding differs: {mismatch}"
                )
        initial_commit = _repository_head(repo)
        if initial_commit != preflight.initial_commit:
            raise PreflightError("initial commit differs")
        _require_clean_repository(repo)

        capability_bindings = preflight.capabilities
        for name, observed in (
            ("droid_version", preflight.droid_version),
            ("plugin_version", preflight.plugin_version),
            ("droid_sdk_version", preflight.droid_sdk_version),
            ("lima_version", preflight.lima_version),
            ("vm_image_digest", preflight.vm_image_digest),
            ("factory_profile_digest", preflight.factory_profile_digest),
            ("isolation_digest", preflight.isolation_digest),
            ("gate_surface_digest", preflight.gate_surface_digest),
            ("installed_plugin_artifact_digest", preflight.installed_plugin_artifact_digest),
        ):
            if getattr(capability_bindings, name) != observed:
                raise PreflightError(f"capability {name} binding differs")

        mission_root_digest = _tree_digest(
            repo,
            excluded=frozenset({".git", ".shadow-mission", "__pycache__"}),
        )
        return RunPreparation(
            request=request,
            preflight=preflight,
            repo=repo,
            mission_file=mission_file,
            evaluator=evaluator,
            droid_path=droid_path,
            profile_digest=profile_result.digest,
            isolation_digest=isolation_result.config_digest,
            mission_root_digest=mission_root_digest,
            initial_commit=initial_commit,
            historical_launch_artifact_digest=str(launch_digest),
            source_exporter_digest=source_exporter_digest,
            factory_mission_root=factory_mission_root,
            factory_mission_snapshot=factory_mission_snapshot,
            baseline=baseline,
        )


    def run(
        self,
        request: MissionRequest,
        *,
        review_controller_factory: ReviewControllerFactory | None = None,
        timeout_seconds: int = 7_200,
    ) -> RunRecord:
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise PreflightError("Mission timeout must be a positive integer")
        try:
            prepared = self.prepare(request)
        except PreflightError:
            raise
        except (OSError, ValueError) as error:
            raise PreflightError("preflight input validation failed") from error
        preflight = prepared.preflight
        mission_capabilities = preflight.capabilities.model_dump(mode="json")
        mission_capabilities["sandbox_isolation"] = "fallback"
        if review_controller_factory is None or not callable(
            review_controller_factory
        ):
            raise PreflightError("active Mission review controller is unavailable")
        pinned_launch = _pin_launch_boundaries(prepared, self.state_root)
        try:
            version = self.command_runner.run(
                (str(pinned_launch.droid_path), "--version"),
                environment=self._droid_environment(prepared.droid_path),
                cwd=pinned_launch.cwd,
                timeout_seconds=30,
                pass_fds=pinned_launch.descriptors,
            )
            if version.returncode != 0 or not re.search(
                rf"(?<![0-9.]){re.escape(preflight.droid_version)}(?![0-9.])",
                version.stdout,
            ):
                raise PreflightError("immediate Droid version observation differs")
            if _sha256_file(prepared.droid_path) != preflight.droid_binary_digest:
                raise PreflightError("Droid binary drifted before Mission launch")
        except BaseException:
            pinned_launch.close()
            raise
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_root, 0o700)

        lock_path = self.state_root / "mission.lock"
        lock_acquired = False

        run_id = f"run-{secrets.token_hex(16)}"
        run_dir = self.state_root / "runs" / run_id
        descriptor_path = run_dir / "descriptor.json"
        latch_path = run_dir / "latch.json"
        collector: HookCollector | None = None
        correlation_producer: PinnedFactoryMissionRelationProducer | None = None
        controller: MissionReviewControllerBoundary | None = None
        latch_store: LatchTerminationBoundary | None = None
        mission_process_stopped: bool | None = None
        mission_result: CommandResult | None = None
        execution_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        collector_degraded: str | None = None
        controller_degraded: str | None = None
        review_terminal = False
        unresolved_intervention_ids: tuple[str, ...] = ()
        finalization_forbidden_values: tuple[str, ...] = ()
        completion_blocked = False
        termination_check_errors: list[BaseException] = []
        status_stop = threading.Event()
        status_thread: threading.Thread | None = None
        status_thread_started = False
        launched = False
        mission_relation_record_digest: str | None = None
        started_at = int(self.clock())
        try:
            validate_live_authorization_ledger(
                self.state_root,
                live_run_count=preflight.budget.live_run_count,
            )
            run_dir.mkdir(parents=True, mode=0o700)
            os.chmod(run_dir, 0o700)
            secret = generate_run_secret()
            source_canary = f"shadow-source-canary-{secrets.token_hex(16)}"
            key_id = f"key-{secrets.token_hex(16)}"
            ledger = EventLedger(run_dir, run_id=run_id)
            try:
                correlation_producer = PinnedFactoryMissionRelationProducer(
                    mission_root=prepared.factory_mission_root,
                    project_root=prepared.repo,
                    droid_binary_digest=preflight.droid_binary_digest,
                    expected_source_digest=preflight.mission_relation_source_digest,
                    secret=secret,
                    correlation_id=run_id,
                    role_configuration=preflight.role_configuration,
                    clock=self.clock,
                    historical_names=prepared.factory_mission_snapshot,
                )
            except MissionCorrelationError as error:
                raise PreflightError(
                    "Factory Mission relation source is invalid"
                ) from error
            correlation = correlation_producer.binding
            registry = correlation.registry
            binding = review_controller_factory(
                run_id=run_id,
                run_dir=run_dir,
                secret=secret,
                descriptor_path=descriptor_path,
                latch_path=latch_path,
                ledger=ledger,
                correlation=correlation,
                correlation_producer=correlation_producer,
                prepared=prepared,
                runtime_forbidden_values=(secret, source_canary),
            )
            _validate_review_binding(
                binding,
                run_id=run_id,
                run_dir=run_dir.resolve(strict=True),
                latch_path=latch_path.resolve(strict=True),
            )
            if any(
                value not in binding.forbidden_values
                for value in (secret, source_canary)
            ):
                raise PreflightError(
                    "review controller omitted a runtime forbidden value"
                )
            finalization_forbidden_values = binding.forbidden_values
            controller = binding.controller
            latch_store = binding.latch_store
            ledger.add_after_append(controller.after_append)
            collector = HookCollector(
                ledger,
                provenance_status=(
                    "hook_authenticated"
                    if preflight.capabilities.hook_provenance == "pass"
                    else "untrusted_provenance"
                ),
                correlation=registry,
                correlation_refresh=correlation_producer.refresh,
                decide=controller.decide,
                capture_request=controller.capture_request,
                discard_request=controller.discard_request,
                forbidden_values=binding.forbidden_values,
            )
            try:
                lock_descriptor = os.open(
                    lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
            except FileExistsError as error:
                raise PreflightError("another Shadow Mission is active") from error
            os.close(lock_descriptor)
            lock_acquired = True
            collector_url = collector.bind()
            descriptor = create_descriptor(
                descriptor_path,
                secret,
                run_id=run_id,
                key_id=key_id,
                collector_url=collector_url,
                mission_root_digest=prepared.mission_root_digest,
                profile_digest=prepared.profile_digest,
                isolation_digest=prepared.isolation_digest,
                gate_surface_digest=preflight.gate_surface_digest,
                installed_artifact_digest=preflight.installed_plugin_artifact_digest,
                latch_path=latch_path,
                ttl_seconds=timeout_seconds + _DESCRIPTOR_CLEANUP_MARGIN_SECONDS,
            )
            controller.start()
            collector.start(secret=secret, descriptor=descriptor)

            launch_environment = self._droid_environment(prepared.droid_path)
            launch_environment.update(
                {
                    "SHADOW_MISSION_RUN_FILE": str(descriptor_path),
                    "SHADOW_MISSION_RUN_SECRET": secret,
                    "SHADOW_MISSION_SECRET_CANARY": source_canary,
                }
            )
            launch_arguments = (
                str(pinned_launch.droid_path),
                "exec",
                "--mission",
                "--auto",
                "high",
                "-f",
                str(pinned_launch.mission_file),
                "--log-group-id",
                run_id,
                "--model",
                preflight.models["orchestrator"],
                "--reasoning-effort",
                preflight.reasoning["orchestrator"],
                "--worker-model",
                preflight.models["worker"],
                "--worker-reasoning-effort",
                preflight.reasoning["worker"],
                "--validator-model",
                preflight.models["validator"],
                "--validator-reasoning-effort",
                preflight.reasoning["validator"],
            )
            if "--skip-permissions-unsafe" in launch_arguments:
                raise AssertionError("unsafe permission bypass is forbidden")
            try:
                installed_plugin_root = resolve_installed_plugin_root(
                    prepared.factory_mission_root.parent / "plugins",
                    plugin_name="shadow-mission",
                    plugin_version=preflight.plugin_version,
                    expected_digest=preflight.installed_plugin_artifact_digest,
                )
                installed_plugin_digest = compute_plugin_artifact_digest(
                    installed_plugin_root
                )
            except (FactoryProfileError, OSError) as error:
                raise PreflightError(
                    "installed plugin artifact digest differs"
                ) from error
            if installed_plugin_digest != preflight.installed_plugin_artifact_digest:
                raise PreflightError(
                    "installed plugin artifact digest differs"
                )
            consume_release_authorization(
                self.state_root,
                preflight=preflight,
                run_id=run_id,
                consumed_at=int(self.clock()),
            )
            launched = True
            _atomic_private_json(
                run_dir / "launch.json",
                {
                    "schema_version": "0.1",
                    "run_id": run_id,
                    "launched_at": started_at,
                    "preflight_record_digest": preflight.record_digest,
                    "droid_binary_digest": preflight.droid_binary_digest,
                    "live_run_count_incremented": True,
                    "prior_live_run_count": preflight.budget.live_run_count,
                    "resulting_live_run_count": preflight.budget.live_run_count + 1,
                },
            )
            active_risks = tuple(
                risk
                for risk in (controller.non_releasable_reason,)
                if risk is not None
            )
            active_status = status_record(
                {
                    "schema_version": "0.1",
                    "run_id": run_id,
                    "state": "active",
                    "daemon_health": "healthy",
                    "queue": {
                        "items": ledger.pending_items,
                        "bytes": ledger.pending_bytes,
                    },
                    "spool": {
                        "events": ledger.spool_bytes,
                        "review": (
                            (run_dir / "review.jsonl").stat().st_size
                            if (run_dir / "review.jsonl").is_file()
                            else 0
                        ),
                    },
                    "sessions": tuple(
                        sorted(set(correlation.role_assignments.values()))
                    ),
                    "roles": correlation.role_assignments,
                    "capability_path": mission_capabilities,
                    "unresolved_risks": active_risks,
                    "intervention_state": intervention_state(
                        controller.router.snapshot().interventions
                    ),
                    "usage": {"status": "unavailable"},
                    "duration_seconds": float(max(0, int(self.clock()) - started_at)),
                    "started_at": started_at,
                    "live_run_count": preflight.budget.live_run_count + 1,
                    "budget_ledger": preflight.budget.model_dump(mode="json"),
                    "updated_at": int(self.clock()),
                }
            )
            _atomic_private_json(
                run_dir / "status.json",
                active_status.model_dump(mode="json"),
            )

            def write_active_status() -> None:
                current_time = int(self.clock())
                current_reason = controller.non_releasable_reason
                value = active_status.model_dump(mode="json")
                value.pop("record_digest")
                value["daemon_health"] = (
                    "degraded" if current_reason is not None else "healthy"
                )
                value["queue"] = {
                    "items": ledger.pending_items,
                    "bytes": ledger.pending_bytes,
                }
                value["spool"] = {
                    "events": ledger.spool_bytes,
                    "review": (
                        (run_dir / "review.jsonl").stat().st_size
                        if (run_dir / "review.jsonl").is_file()
                        else 0
                    ),
                }
                value["sessions"] = tuple(
                    sorted(set(correlation.role_assignments.values()))
                )
                value["roles"] = correlation.role_assignments
                value["unresolved_risks"] = (
                    (current_reason,) if current_reason is not None else ()
                )
                value["capability_path"] = {
                    **value["capability_path"],
                    "review_terminal": review_terminal,
                }
                value["intervention_state"] = intervention_state(
                    controller.router.snapshot().interventions
                )
                value["duration_seconds"] = float(max(0, current_time - started_at))
                value["updated_at"] = current_time
                refreshed = status_record(value)
                _atomic_private_json(
                    run_dir / "status.json",
                    refreshed.model_dump(mode="json"),
                )

            def refresh_active_status() -> None:
                while not status_stop.wait(_STATUS_HEARTBEAT_SECONDS):
                    try:
                        write_active_status()
                    except BaseException as error:
                        termination_check_errors.append(error)
                        return

            status_thread = threading.Thread(
                target=refresh_active_status,
                name=f"shadow-status-{run_id[:12]}",
                daemon=True,
            )
            status_thread.start()
            status_thread_started = True

            def termination_required() -> bool:
                assert controller is not None
                assert latch_store is not None
                try:
                    return (
                        controller.termination_required
                        or latch_store.termination_required
                        or not controller.releasable
                    )
                except BaseException as error:
                    termination_check_errors.append(error)
                    return True

            mission_result = self.command_runner.run_interruptible(
                launch_arguments,
                environment=launch_environment,
                cwd=pinned_launch.cwd,
                timeout_seconds=timeout_seconds,
                termination_required=termination_required,
                pass_fds=pinned_launch.descriptors,
            )
            mission_process_stopped = mission_result.mission_process_stopped
            correlation_record = correlation_producer.finalize_record()
            correlation_value: dict[str, Any] = {
                "schema_version": "0.1",
                "source_digest": correlation.source_digest,
                "mission_id": correlation.mission_id,
                "record": correlation_record.model_dump(mode="json"),
                "role_counts": correlation_record.role_inventory.observed.model_dump(
                    mode="json"
                ),
                "role_assignments": dict(correlation.role_assignments),
            }
            correlation_value["record_digest"] = correlation_wrapper_digest(
                correlation_value
            )
            correlation_wrapper = FactoryMissionCorrelationWrapper.model_validate(
                correlation_value
            )
            mission_relation_record_digest = correlation_wrapper.record_digest
            _atomic_private_json(
                run_dir / "correlation.json",
                correlation_wrapper.model_dump(mode="json"),
            )
            write_active_status()
        except BaseException as error:
            execution_error = error
            if (
                isinstance(error, MissionExecutionError)
                and error.mission_process_stopped is not None
            ):
                mission_process_stopped = error.mission_process_stopped
        finally:
            status_stop.set()
            if status_thread is not None and status_thread_started:
                status_thread.join(timeout=2.0)
                if status_thread.is_alive():
                    cleanup_error = cleanup_error or MissionExecutionError(
                        "status heartbeat did not stop"
                    )
            if collector is not None:
                try:
                    collector.stop()
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                collector_degraded = collector.degraded_reason
            if controller is not None:
                drained = False
                try:
                    drained = controller.drain(timeout=30.0)
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                try:
                    controller.reconcile_final_outage()
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                try:
                    stopped = controller.stop(timeout=5.0)
                    if not stopped:
                        cleanup_error = cleanup_error or MissionExecutionError(
                            "review controller did not stop cleanly"
                        )
                    elif not drained and controller.non_releasable_reason is not None:
                        cleanup_error = cleanup_error or MissionExecutionError(
                            "review controller projection drain failed"
                        )
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                try:
                    controller_degraded = controller.non_releasable_reason
                    review_terminal = controller.termination_required
                    completion_blocked = controller.completion_blocked
                    unresolved_intervention_ids = (
                        controller.unresolved_intervention_ids
                    )
                except BaseException as error:
                    termination_check_errors.append(error)
                    review_terminal = True
            if latch_store is not None:
                try:
                    review_terminal = (
                        review_terminal or latch_store.termination_required
                    )
                    completion_blocked = (
                        completion_blocked or latch_store.completion_blocked
                    )
                except BaseException as error:
                    termination_check_errors.append(error)
                    review_terminal = True
            if correlation_producer is not None:
                try:
                    correlation_producer.close()
                except BaseException as error:
                    cleanup_error = cleanup_error or error
            pinned_launch.close()
            private_paths = [
                descriptor_path,
                latch_path,
                production_latch_head_path(latch_path),
                run_dir / f".{latch_path.name}.lock",
            ]
            for private_path in private_paths:
                try:
                    private_path.unlink(missing_ok=True)
                except OSError as error:
                    cleanup_error = cleanup_error or error
            if launched:
                self._finalization_forbidden_values[run_id] = (
                    finalization_forbidden_values
                )
            secret = ""
            source_canary = ""

        if not launched:
            if lock_acquired:
                try:
                    lock_path.unlink(missing_ok=True)
                except OSError as error:
                    cleanup_error = cleanup_error or error
            if cleanup_error is not None:
                raise MissionExecutionError("Mission setup cleanup failed") from cleanup_error
            if execution_error is not None:
                raise execution_error
            raise MissionExecutionError("Mission did not reach the launch boundary")

        ended_at = int(self.clock())
        returncode = mission_result.returncode if mission_result is not None else -1
        if mission_process_stopped is not True:
            run_outcome = "cleanup-failed"
        elif review_terminal:
            run_outcome = "unresolved-blocker"
        elif termination_check_errors:
            run_outcome = "review-termination-check-failed"
        elif cleanup_error is not None:
            run_outcome = "cleanup-failed"
        elif collector_degraded is not None:
            run_outcome = "collector-degraded"
        elif controller_degraded is not None:
            run_outcome = "review-controller-degraded"
        elif returncode == 0 and execution_error is None and completion_blocked:
            run_outcome = "completion-blocked"
        elif returncode == 0 and execution_error is None:
            run_outcome = "mission-terminated"
        elif mission_result is not None:
            run_outcome = f"mission-exit-{returncode}"
        else:
            run_outcome = "mission-process-error"
        final_commit: str | None = None
        changed_files: tuple[str, ...] = ()
        try:
            final_commit = _repository_head(prepared.repo)
        except PreflightError as error:
            cleanup_error = cleanup_error or error
            run_outcome = "cleanup-failed"
        try:
            changed_files = _changed_files(prepared.repo)
        except PreflightError as error:
            cleanup_error = cleanup_error or error
            run_outcome = "cleanup-failed"
        try:
            record_value: dict[str, Any] = {
                "schema_version": "0.1",
                "provenance_status": (
                    "hook_authenticated"
                    if preflight.capabilities.hook_provenance == "pass"
                    else "untrusted_provenance"
                ),
                "redaction_status": "clean",
                "run_id": run_id,
                "droid_version": preflight.droid_version,
                "plugin_version": preflight.plugin_version,
                "droid_sdk_version": preflight.droid_sdk_version,
                "lima_version": preflight.lima_version,
                "droid_installation_channel": preflight.droid_installation_channel,
                "droid_binary_digest": preflight.droid_binary_digest,
                "droid_auto_update_control": preflight.droid_auto_update_control,
                "gate_surface_digest": preflight.gate_surface_digest,
                "installed_plugin_artifact_digest": (
                    preflight.installed_plugin_artifact_digest
                ),
                "full_run_artifact_digest": preflight.full_run_artifact_digest,
                "historical_launch_artifact_digest": (
                    prepared.historical_launch_artifact_digest
                ),
                "resolved_plugin_source": preflight.resolved_plugin_source,
                "release_preflight_digest": preflight.record_digest,
                "factory_profile_digest": preflight.factory_profile_digest,
                "vm_image_digest": preflight.vm_image_digest,
                "isolation_digest": preflight.isolation_digest,
                "mission_digest": preflight.mission_digest,
                "mission_role_config_digest": preflight.mission_role_config_digest,
                "mission_relation_source_digest": preflight.mission_relation_source_digest,
                "mission_relation_record_digest": mission_relation_record_digest,
                "mission_outcome": (
                    "mission-complete"
                    if run_outcome == "mission-terminated"
                    else "mission-failed"
                ),
                "runtime_outcome": run_outcome,
                "mission_process_stopped": mission_process_stopped is True,
                "approved_evaluator_digest": preflight.evaluator_digest,
                "source_exporter_digest": prepared.source_exporter_digest,
                "models": preflight.models,
                "reasoning": preflight.reasoning,
                "budget_ledger": {
                    **preflight.budget.model_dump(mode="json"),
                    "live_run_count_incremented": True,
                    "resulting_live_run_count": preflight.budget.live_run_count + 1,
                },
                "initial_commit": prepared.initial_commit,
                "final_commit": final_commit,
                "final_source_archive_digest": None,
                "started_at": started_at,
                "ended_at": ended_at,
                "duration_seconds": float(max(0, ended_at - started_at)),
                "changed_files": list(changed_files),
                "evaluator_outcome": run_outcome,
                "usage_data": {"status": "unavailable"},
                "baseline_id": (
                    prepared.baseline.baseline_id
                    if prepared.baseline is not None
                    else None
                ),
                "baseline_record_digest": (
                    prepared.baseline.record_digest
                    if prepared.baseline is not None
                    else None
                ),
                "pre_evaluation_record_digest": None,
                "final_source_manifest_digest": None,
                "final_source_working_tree_digest": None,
                "evaluator_digest": None,
                "evaluation_record_digest": None,
                "capabilities": mission_capabilities,
                "evaluator_vm_deleted": None,
                "record_digest": "0" * 64,
            }
            record_value["record_digest"] = hashlib.sha256(
                canonical_json(_without_record_digest(record_value))
            ).hexdigest()
            record = RunRecord.model_validate(record_value)
            try:
                assert controller is not None
                terminal_projection = terminal_status(
                    run_dir,
                    record,
                    interventions=controller.router.snapshot().interventions,
                    known_sessions=correlation.role_assignments.values(),
                    role_assignments=correlation.role_assignments,
                )
                _atomic_private_json(
                    run_dir / "status.json",
                    terminal_projection.model_dump(mode="json"),
                )
            except BaseException as error:
                cleanup_error = cleanup_error or error
                run_outcome = "cleanup-failed"
                record_value.update(
                    {
                        "mission_outcome": "mission-failed",
                        "runtime_outcome": run_outcome,
                        "evaluator_outcome": run_outcome,
                        "record_digest": "0" * 64,
                    }
                )
                record_value["record_digest"] = hashlib.sha256(
                    canonical_json(_without_record_digest(record_value))
                ).hexdigest()
                record = RunRecord.model_validate(record_value)
            _atomic_private_json(run_dir / "run.json", record.model_dump(mode="json"))
        finally:
            if lock_acquired:
                try:
                    lock_path.unlink(missing_ok=True)
                except OSError as error:
                    cleanup_error = cleanup_error or error

        if cleanup_error is not None:
            raise MissionExecutionError("Mission cleanup failed", run_record=record) from cleanup_error
        if termination_check_errors:
            raise MissionExecutionError(
                "review termination check failed",
                run_record=record,
            ) from termination_check_errors[0]
        if execution_error is not None and mission_process_stopped is None:
            raise MissionExecutionError(
                "Droid Mission process failed",
                run_record=record,
            ) from execution_error
        if mission_process_stopped is not True:
            raise MissionExecutionError(
                "Droid process group did not terminate",
                run_record=record,
                mission_process_stopped=False,
            )
        if review_terminal:
            detail = ",".join(unresolved_intervention_ids) or "unknown"
            raise MissionExecutionError(f"unresolved blocker terminated Mission: {detail}", run_record=record)
        if completion_blocked and returncode == 0:
            detail = ",".join(unresolved_intervention_ids) or "unknown"
            raise MissionExecutionError(f"unresolved blocker prevented Mission completion: {detail}", run_record=record)
        if controller_degraded is not None:
            raise MissionExecutionError("review controller degraded during Mission", run_record=record)
        if execution_error is not None:
            raise MissionExecutionError("Droid Mission process failed", run_record=record) from execution_error
        if mission_result is None or mission_result.returncode != 0:
            raise MissionExecutionError("Droid Mission failed", run_record=record)
        if collector_degraded is not None:
            raise MissionExecutionError("collector degraded during Mission", run_record=record)
        return record

    @staticmethod
    def _droid_environment(droid_path: Path) -> dict[str, str]:
        return {
            "HOME": os.environ.get("HOME", "/home/shadow"),
            "PATH": f"{droid_path.parent}:/usr/bin:/bin",
            "FACTORY_DROID_AUTO_UPDATE_ENABLED": "false",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
