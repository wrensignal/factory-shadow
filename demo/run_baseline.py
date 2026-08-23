#!/usr/bin/env python3
"""Run the frozen baseline Mission and persist its bound evaluation record."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
import os
import stat
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from pydantic import ValidationError

from shadow_mission.correlation import (
    MissionCorrelationError,
    require_host_factory_mission_root,
    snapshot_factory_mission_names,
)
from shadow_mission.evaluation import (
    EvaluationRecord,
    LimaVmDriver,
    VmDriver,
    run_isolated_evaluator,
    validate_evaluator_assets,
)
from shadow_mission.finalization import export_final_source
from shadow_mission.redaction import sanitize_value
from shadow_mission.protocol import BaselineRunRecord, canonical_json
from shadow_mission.runtime import (
    PreflightError,
    consume_release_authorization,
    load_release_preflight,
)
from shadow_mission.source_export import (
    SourceArchiveError,
    ValidatedSourceArchive,
    validate_source_archive,
)


class BaselineError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        stdout: str = "",
        stderr: str = "",
        process_group_id: int | None = None,
    ) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr
        self.process_group_id = process_group_id


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_INTENDED_CONFLICT_ASSERTION = "ten_dollars_crosses_all_boundaries_as_1000_cents"
_EXPECTED_ASSERTION_IDS = frozenset(
    {
        "api_amount_unit_is_integer_cents",
        "api_preserves_integer_cents",
        "database_column_is_amount_cents",
        _INTENDED_CONFLICT_ASSERTION,
    }
)
_DYNAMIC_FIELDS = {
    "schema_version",
    "mission_outcome",
    "final_commit",
    "final_source_archive_digest",
    "started_at",
    "ended_at",
    "duration_seconds",
    "changed_files",
    "evaluator_outcome",
    "usage_data",
    "record_digest",
}
_BINDING_FIELDS = set(BaselineRunRecord.model_fields) - _DYNAMIC_FIELDS
_CONTROL_FIELDS = {
    "preparation_record_digest",
    "profile_manifest_digest",
    "role_config_file_digest",
    "source_exporter_digest",
}
_BASELINE_ENVIRONMENT_KEYS = frozenset(
    {
        "FACTORY_API_BASE_URL",
        "FACTORY_DEPLOYMENT_ENV",
        "FACTORY_ENV",
        "HOME",
        "PATH",
        "TMPDIR",
    }
)

# A baseline uses the full worker and validator topology, so it gets the
# production controller's two-hour Mission window. One MiB per stream is ample
# for failure diagnostics while it keeps Mission-selected output bounded.
_GIT_PROBE_TIMEOUT_SECONDS = 30
_BASELINE_MISSION_TIMEOUT_SECONDS = 2 * 60 * 60
_BASELINE_MISSION_STREAM_LIMIT_BYTES = 1 << 20
_MISSION_TERMINATION_GRACE_SECONDS = 5.0
_OUTPUT_READ_CHUNK_BYTES = 64 << 10
_OUTPUT_TRUNCATION_MARKER = "\n[shadow baseline output truncated]\n"
_OUTPUT_TRUNCATION_MARKER_BYTES = _OUTPUT_TRUNCATION_MARKER.encode("ascii")


def _require_external_absolute(path: Path, description: str) -> Path:
    if not path.is_absolute():
        raise BaselineError(f"{description} path must be absolute")
    resolved = path.resolve(strict=False)
    if (
        resolved == _PROJECT_ROOT
        or _PROJECT_ROOT in resolved.parents
        or resolved in _PROJECT_ROOT.parents
    ):
        raise BaselineError(f"{description} must remain outside the project")
    return resolved



def _require_disjoint_host_paths(
    checkout: Path,
    *host_paths: tuple[Path, str],
) -> tuple[Path, ...]:
    resolved: list[Path] = []
    for path, description in host_paths:
        value = _require_external_absolute(path, description)
        if (
            value == checkout
            or checkout in value.parents
            or value in checkout.parents
        ):
            raise BaselineError(f"{description} must remain outside the checkout")
        resolved.append(value)
    for index, left in enumerate(resolved):
        for right in resolved[index + 1 :]:
            if left == right or left in right.parents or right in left.parents:
                raise BaselineError("baseline host-private paths overlap")
    return tuple(resolved)

def _sha256_file(path: Path) -> str:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise BaselineError(f"{path.name} is not a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_canonical(path: Path, description: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
        value = json.loads(payload)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or not isinstance(value, dict)
            or canonical_json(value) + b"\n" != payload
        ):
            raise BaselineError(f"{description} is not canonical")
        material = dict(value)
        supplied = material.pop("record_digest", None)
        expected = hashlib.sha256(canonical_json(material)).hexdigest()
        if supplied != expected:
            raise BaselineError(f"{description} digest differs")
        return dict(value)
    except BaselineError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
        raise BaselineError(f"{description} is invalid") from error


def _baseline_bindings(
    *,
    preflight: Mapping[str, Any],
    preparation: Mapping[str, Any],
    profile_manifest: Path,
    role_config: Path,
    exporter_path: Path,
) -> dict[str, Any]:
    derived_fields = {
        "approved_evaluator_digest",
        "baseline_id",
        "budget_ledger",
        "mission_relation_record_digest",
        "release_preflight_digest",
        "source_exporter_digest",
        "provenance_status",
        "redaction_status",
    }
    required_preflight_fields = _BINDING_FIELDS - derived_fields
    missing = sorted(required_preflight_fields - set(preflight))
    if missing:
        raise BaselineError(
            f"release preflight does not contain baseline bindings: {', '.join(missing)}"
        )
    preflight_id = preflight.get("preflight_id")
    budget = preflight.get("budget")
    if not isinstance(preflight_id, str) or not preflight_id or not isinstance(budget, dict):
        raise BaselineError("release preflight baseline controls are invalid")
    bindings = {name: preflight[name] for name in required_preflight_fields}
    bindings.update(
        {
            "approved_evaluator_digest": preflight.get("evaluator_digest"),
            "baseline_id": f"baseline-{preflight_id}",
            "budget_ledger": budget,
            "mission_relation_record_digest": None,
            "release_preflight_digest": preflight["record_digest"],
            "source_exporter_digest": _sha256_file(exporter_path),
            "preparation_record_digest": preparation.get("record_digest"),
            "provenance_status": "authoritative_input",
            "redaction_status": "clean",
            "profile_manifest_digest": _sha256_file(profile_manifest),
            "role_config_file_digest": _sha256_file(role_config),
        }
    )
    if set(bindings) != _BINDING_FIELDS | _CONTROL_FIELDS:
        raise BaselineError("derived baseline bindings differ from the contract")
    return bindings


def _verify_preparation(
    preparation: Mapping[str, Any],
    bindings: Mapping[str, Any],
    checkout: Path,
) -> None:
    expected = {
        "seed_commit": bindings["initial_commit"],
        "mission_digest": bindings["mission_digest"],
        "mission_role_config_digest": bindings["mission_role_config_digest"],
        "role_config_digest": bindings["role_config_file_digest"],
        "factory_profile_digest": bindings["factory_profile_digest"],
        "gate_surface_digest": bindings["gate_surface_digest"],
        "installed_plugin_artifact_digest": bindings[
            "installed_plugin_artifact_digest"
        ],
        "vm_image_digest": bindings["vm_image_digest"],
        "lima_config_digest": bindings["isolation_digest"],
        "profile_manifest_digest": bindings["profile_manifest_digest"],
        "record_digest": bindings["preparation_record_digest"],
        "baseline_checkout": checkout.name,
    }
    mismatches = [
        name for name, value in expected.items() if preparation.get(name) != value
    ]
    checkout_heads = preparation.get("checkout_heads")
    if (
        not isinstance(checkout_heads, dict)
        or checkout_heads.get(checkout.name) != bindings["initial_commit"]
        or len(checkout_heads) != 2
        or set(checkout_heads.values()) != {bindings["initial_commit"]}
    ):
        mismatches.append("checkout_heads")
    if mismatches:
        raise BaselineError(
            f"baseline preparation binding differs: {', '.join(sorted(set(mismatches)))}"
        )


def _write_record(path: Path, record: BaselineRunRecord) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        raise BaselineError("baseline output already exists")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(record.model_dump(mode="json")) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _authorization_reference(
    authorization_path: Path,
    *,
    preflight_record_digest: str,
    run_id: str,
    consumed_at: int,
) -> dict[str, Any]:
    return {
        "authorization_id_digest": authorization_path.stem,
        "preflight_record_digest": preflight_record_digest,
        "run_id": run_id,
        "consumed_at": consumed_at,
    }


def _recover_source_evidence(
    artifact_root: Path,
    secret_canaries: Sequence[str],
) -> ValidatedSourceArchive | None:
    try:
        canaries = tuple(value.encode("ascii") for value in secret_canaries)
        return validate_source_archive(
            artifact_root / "final-source.tar",
            artifact_root / "final-source-manifest.json",
            secret_canaries=canaries,
        )
    except (OSError, SourceArchiveError, UnicodeEncodeError, ValueError):
        return None


def _recover_evaluator_evidence(
    output_path: Path,
    source: ValidatedSourceArchive | None,
) -> EvaluationRecord | None:
    if source is None:
        return None
    try:
        value = _load_canonical(output_path, "baseline evaluator result")
        evaluation = EvaluationRecord.model_validate(value)
    except (BaselineError, OSError, ValidationError, ValueError):
        return None
    if (
        evaluation.archive_digest != source.archive_digest
        or evaluation.working_tree_digest != source.manifest.working_tree_digest
    ):
        return None
    return evaluation


def _build_outcome_record(
    *,
    bindings: Mapping[str, Any],
    started_at: int,
    ended_at: int,
    mission_outcome: str,
    authorization_reference: Mapping[str, Any],
    source: ValidatedSourceArchive | None,
    evaluation: EvaluationRecord | None,
    factory_mission_id: str | None,
    failure_classification: str | None,
    mission_process_group_stopped: bool | None,
    evaluator_vm_deleted: bool | None,
) -> BaselineRunRecord:
    usage_data: dict[str, Any] = {
        "status": "unavailable",
        "consumed_authorization_reference": dict(authorization_reference),
        "cleanup_observations": {
            "mission_process_group_stopped": mission_process_group_stopped,
            "evaluator_vm_deleted": evaluator_vm_deleted,
        },
    }
    if factory_mission_id is not None:
        usage_data["factory_mission_id"] = factory_mission_id
    if failure_classification is not None:
        usage_data["failure_classification"] = failure_classification
    value = {name: bindings[name] for name in sorted(_BINDING_FIELDS)}
    value.update(
        {
            "schema_version": "0.1",
            "mission_outcome": mission_outcome,
            "final_commit": source.manifest.final_commit if source is not None else None,
            "final_source_archive_digest": (
                source.archive_digest if source is not None else None
            ),
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": float(max(0, ended_at - started_at)),
            "changed_files": (
                _dirty_paths(source.manifest.dirty_state)
                if source is not None
                else ()
            ),
            "evaluator_outcome": (
                evaluation.model_dump(mode="json") if evaluation is not None else None
            ),
            "usage_data": usage_data,
            "record_digest": "0" * 64,
        }
    )
    material = dict(value)
    material.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    try:
        return BaselineRunRecord.model_validate(value)
    except ValidationError as error:
        raise BaselineError("baseline record is invalid") from error


def _dirty_paths(dirty_state: Sequence[str]) -> tuple[str, ...]:
    values: list[str] = []
    for line in dirty_state:
        candidate = line[3:] if len(line) > 3 else line
        if " -> " in candidate:
            candidate = candidate.split(" -> ", maxsplit=1)[1]
        values.append(candidate.strip('"'))
    return tuple(sorted(set(values)))


def _discover_factory_mission_id(
    mission_root: Path,
    *,
    prior_names: frozenset[str],
    checkout: Path,
    started_at: int,
) -> str:
    current_names = snapshot_factory_mission_names(mission_root)
    new_names = current_names - prior_names
    candidate_names = new_names or current_names
    matches: list[str] = []
    for name in candidate_names:
        mission_path = mission_root / name
        state_path = mission_path / "state.json"
        try:
            if mission_path.is_symlink() or not mission_path.is_dir():
                continue
            state = json.loads(state_path.read_bytes())
            created_at = datetime.fromisoformat(
                str(state["createdAt"]).replace("Z", "+00:00")
            ).timestamp()
            working_directory = Path(str(state["workingDirectory"])).resolve(
                strict=True
            )
        except (KeyError, OSError, UnicodeError, ValueError, json.JSONDecodeError):
            continue
        if working_directory == checkout and created_at >= started_at - 5:
            matches.append(name)
    if len(matches) != 1:
        raise BaselineError("baseline did not create one attributable Factory Mission")
    return matches[0]


class _BoundedStreamCapture:
    """Incrementally drain one child stream into a fixed-size byte buffer."""

    def __init__(self, limit: int) -> None:
        if limit <= len(_OUTPUT_TRUNCATION_MARKER_BYTES):
            raise ValueError("Mission stream limit is too small")
        self._limit = limit
        self._buffer = bytearray()
        self._lock = threading.Lock()
        self.overflow = threading.Event()
        self.failed = threading.Event()

    def drain(self, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(_OUTPUT_READ_CHUNK_BYTES)
                if not chunk:
                    return
                if self.overflow.is_set():
                    continue
                with self._lock:
                    if len(self._buffer) + len(chunk) <= self._limit:
                        self._buffer.extend(chunk)
                        continue
                    payload_limit = (
                        self._limit - len(_OUTPUT_TRUNCATION_MARKER_BYTES)
                    )
                    del self._buffer[payload_limit:]
                    remaining = payload_limit - len(self._buffer)
                    self._buffer.extend(chunk[:remaining])
                    self._buffer.extend(_OUTPUT_TRUNCATION_MARKER_BYTES)
                    self.overflow.set()
        except BaseException:
            self.failed.set()
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                self.failed.set()

    def text(self) -> str:
        with self._lock:
            return bytes(self._buffer).decode("utf-8", errors="ignore")


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


def _wait_process_group_exit(
    process: subprocess.Popen[bytes],
    deadline: float,
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


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    drainers: tuple[threading.Thread, ...],
    grace_seconds: float,
) -> tuple[bool, bool]:
    deadline = time.monotonic() + grace_seconds
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass
    term_deadline = time.monotonic() + max(
        0.0,
        (deadline - time.monotonic()) / 2,
    )
    _wait_process_group_exit(process, term_deadline)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    terminated = _wait_process_group_exit(process, deadline)
    for drainer in drainers:
        drainer.join(max(0.0, deadline - time.monotonic()))
    return terminated, not any(drainer.is_alive() for drainer in drainers)


def _run_bounded_mission(
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float = _BASELINE_MISSION_TIMEOUT_SECONDS,
    stream_limit_bytes: int = _BASELINE_MISSION_STREAM_LIMIT_BYTES,
    termination_grace_seconds: float = _MISSION_TERMINATION_GRACE_SECONDS,
    popen_factory: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> subprocess.CompletedProcess[str]:
    """Run one paid Mission with bounded pipes, deadline, and group cleanup."""
    if timeout_seconds <= 0 or termination_grace_seconds <= 0:
        raise ValueError("Mission process timeouts must be positive")
    stdout_capture = _BoundedStreamCapture(stream_limit_bytes)
    stderr_capture = _BoundedStreamCapture(stream_limit_bytes)
    try:
        process = popen_factory(
            arguments,
            cwd=str(cwd),
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            close_fds=True,
            bufsize=0,
            start_new_session=True,
        )
    except (OSError, ValueError) as error:
        raise BaselineError("baseline Mission process boundary failed") from error

    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    drainers = (
        threading.Thread(
            target=stdout_capture.drain,
            args=(process.stdout,),
            name="baseline-mission-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=stderr_capture.drain,
            args=(process.stderr,),
            name="baseline-mission-stderr",
            daemon=True,
        ),
    )
    started_drainers: list[threading.Thread] = []
    try:
        for drainer in drainers:
            drainer.start()
            started_drainers.append(drainer)
    except BaseException as error:
        _terminate_process_group(
            process,
            tuple(started_drainers),
            termination_grace_seconds,
        )
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass
        raise BaselineError(
            "baseline Mission output capture failed",
            process_group_id=process.pid,
        ) from error

    deadline = time.monotonic() + timeout_seconds
    failure_reason: str | None = None
    try:
        while process.poll() is None:
            if stdout_capture.overflow.is_set() or stderr_capture.overflow.is_set():
                failure_reason = "baseline Mission output limit exceeded"
                break
            if stdout_capture.failed.is_set() or stderr_capture.failed.is_set():
                failure_reason = "baseline Mission output capture failed"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure_reason = "baseline Mission timed out"
                break
            try:
                process.wait(timeout=min(0.02, remaining))
            except subprocess.TimeoutExpired:
                pass
    except BaseException:
        _terminate_process_group(
            process,
            drainers,
            termination_grace_seconds,
        )
        raise

    terminated, drainers_stopped = _terminate_process_group(
        process,
        drainers,
        termination_grace_seconds,
    )
    stdout = stdout_capture.text()
    stderr = stderr_capture.text()
    if not terminated:
        failure_reason = "baseline Mission process group did not terminate"
    elif not drainers_stopped:
        failure_reason = "baseline Mission output drain did not stop"
    elif stdout_capture.overflow.is_set() or stderr_capture.overflow.is_set():
        failure_reason = "baseline Mission output limit exceeded"
    elif stdout_capture.failed.is_set() or stderr_capture.failed.is_set():
        failure_reason = "baseline Mission output capture failed"
    if failure_reason is not None:
        raise BaselineError(
            failure_reason,
            stdout=stdout,
            stderr=stderr,
            process_group_id=process.pid,
        )
    return subprocess.CompletedProcess(
        arguments,
        process.returncode if process.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
    )


def _invoke(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return runner(
        arguments,
        cwd=str(cwd),
        env=dict(environment) if environment is not None else None,
        check=False,
        capture_output=True,
        text=True,
        shell=False,
        timeout=_GIT_PROBE_TIMEOUT_SECONDS,
    )


def run_host_baseline(
    *,
    preparation_path: Path,
    preflight_path: Path,
    profile_manifest: Path,
    role_config: Path,
    checkout: Path,
    mission_file: Path,
    exporter_path: Path,
    evaluator_lima_config: Path,
    evaluator_path: Path,
    output_path: Path,
    artifact_root: Path,
    evaluator_vm: str,
    droid_path: Path,
    evaluator_driver: VmDriver,
    secret_canaries: tuple[str, ...],
    factory_mission_root: Path,
    state_root: Path,
    environment: Mapping[str, str] | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    mission_runner: Callable[
        ..., subprocess.CompletedProcess[str]
    ] = _run_bounded_mission,
    clock: Callable[[], float] = time.time,
) -> BaselineRunRecord:
    preparation = _load_canonical(preparation_path, "preparation record")
    preflight = _load_canonical(preflight_path, "release preflight")
    bindings = _baseline_bindings(
        preflight=preflight,
        preparation=preparation,
        profile_manifest=profile_manifest,
        role_config=role_config,
        exporter_path=exporter_path,
    )
    models = preflight.get("models")
    reasoning = preflight.get("reasoning")
    required_model_roles = {"orchestrator", "worker", "validator", "extractor", "probe"}
    if (
        not isinstance(models, dict)
        or set(models) != required_model_roles
        or not isinstance(reasoning, dict)
        or set(reasoning) != required_model_roles
        or any(
            not isinstance(value, str) or not value
            for value in (*models.values(), *reasoning.values())
        )
    ):
        raise BaselineError("baseline model and reasoning bindings are invalid")
    checkout = _require_external_absolute(checkout, "baseline checkout").resolve(
        strict=True
    )
    output_path, artifact_root, state_root = _require_disjoint_host_paths(
        checkout,
        (output_path, "baseline output"),
        (artifact_root, "baseline artifacts"),
        (state_root, "baseline state"),
    )
    mission_file = mission_file.resolve(strict=True)
    droid_path = droid_path.resolve(strict=True)
    _verify_preparation(preparation, bindings, checkout)
    if output_path.exists() or artifact_root.exists():
        raise BaselineError("baseline output already exists")
    if _sha256_file(mission_file) != bindings["mission_digest"]:
        raise BaselineError("baseline Mission digest differs")
    if _sha256_file(droid_path) != bindings["droid_binary_digest"]:
        raise BaselineError("baseline Droid digest differs")
    if _sha256_file(exporter_path) != bindings["source_exporter_digest"]:
        raise BaselineError("baseline source exporter digest differs")
    evaluator_digest = validate_evaluator_assets(evaluator_lima_config, evaluator_path)
    if evaluator_digest != bindings["approved_evaluator_digest"]:
        raise BaselineError("baseline evaluator digest differs")

    head = _invoke(
        runner,
        ("git", "-C", str(checkout), "rev-parse", "HEAD"),
        cwd=checkout,
    )
    if head.returncode != 0 or head.stdout.strip() != bindings["initial_commit"]:
        raise BaselineError("baseline checkout commit differs")
    status = _invoke(
        runner,
        ("git", "-C", str(checkout), "status", "--porcelain"),
        cwd=checkout,
    )
    if status.returncode != 0 or status.stdout.strip():
        raise BaselineError("baseline checkout must be clean")

    try:
        mission_root = require_host_factory_mission_root(factory_mission_root)
        before_missions = snapshot_factory_mission_names(mission_root)
    except MissionCorrelationError as error:
        raise BaselineError("baseline Factory Mission root is invalid") from error
    process_environment = {
        key: value
        for key, value in (environment or os.environ).items()
        if key in _BASELINE_ENVIRONMENT_KEYS
    }
    process_environment["FACTORY_DROID_AUTO_UPDATE_ENABLED"] = "false"
    started_at = int(clock())
    try:
        release_preflight = load_release_preflight(preflight_path)
        authorization_path = consume_release_authorization(
            state_root,
            preflight=release_preflight,
            run_id=str(bindings["baseline_id"]),
            consumed_at=started_at,
        )
    except PreflightError as error:
        raise BaselineError("baseline authorization could not be consumed") from error
    authorization_reference = _authorization_reference(
        authorization_path,
        preflight_record_digest=release_preflight.record_digest,
        run_id=str(bindings["baseline_id"]),
        consumed_at=started_at,
    )
    source: ValidatedSourceArchive | None = None
    evaluation: EvaluationRecord | None = None
    factory_mission_id: str | None = None
    mission_process_group_stopped: bool | None = None
    evaluator_vm_deleted: bool | None = None
    failure_classification = "mission-execution-failed"
    try:
        result = mission_runner(
            (
                str(droid_path),
                "exec",
                "--mission",
                "--auto",
                "high",
                "-f",
                str(mission_file),
                "--model",
                models["orchestrator"],
                "--reasoning-effort",
                reasoning["orchestrator"],
                "--worker-model",
                models["worker"],
                "--worker-reasoning-effort",
                reasoning["worker"],
                "--validator-model",
                models["validator"],
                "--validator-reasoning-effort",
                reasoning["validator"],
            ),
            cwd=checkout,
            environment=process_environment,
            timeout_seconds=_BASELINE_MISSION_TIMEOUT_SECONDS,
            stream_limit_bytes=_BASELINE_MISSION_STREAM_LIMIT_BYTES,
        )
        mission_process_group_stopped = True
        if result.returncode != 0:
            raw_diagnostic = (result.stderr or result.stdout).strip()[:2048]
            diagnostic, _ = sanitize_value(raw_diagnostic)
            raise BaselineError(f"baseline Mission failed: {diagnostic}")

        failure_classification = "mission-correlation-failed"
        try:
            factory_mission_id = _discover_factory_mission_id(
                mission_root,
                prior_names=before_missions,
                checkout=checkout,
                started_at=started_at,
            )
        except MissionCorrelationError as error:
            raise BaselineError(
                "baseline Factory Mission discovery failed"
            ) from error

        failure_classification = "source-export-failed"
        source = export_final_source(
            mission_repo=checkout,
            exporter_path=exporter_path,
            expected_exporter_digest=str(bindings["source_exporter_digest"]),
            artifact_root=artifact_root,
            secret_canaries=secret_canaries,
        )
        failure_classification = "evaluator-failed"
        evaluation = run_isolated_evaluator(
            driver=evaluator_driver,
            vm_name=evaluator_vm,
            lima_config=evaluator_lima_config,
            archive_path=source.archive_path,
            manifest_path=source.manifest_path,
            evaluator_path=evaluator_path,
            output_path=artifact_root / "evaluation.json",
        )
        evaluator_vm_deleted = True
        ended_at = int(clock())
        record = _build_outcome_record(
            bindings=bindings,
            started_at=started_at,
            ended_at=ended_at,
            mission_outcome="mission-complete",
            authorization_reference=authorization_reference,
            source=source,
            evaluation=evaluation,
            factory_mission_id=factory_mission_id,
            failure_classification=None,
            mission_process_group_stopped=mission_process_group_stopped,
            evaluator_vm_deleted=evaluator_vm_deleted,
        )
        if not _is_intended_baseline_failure(record):
            record = _build_outcome_record(
                bindings=bindings,
                started_at=started_at,
                ended_at=ended_at,
                mission_outcome="mission-complete",
                authorization_reference=authorization_reference,
                source=source,
                evaluation=evaluation,
                factory_mission_id=factory_mission_id,
                failure_classification="baseline-qualification-failed",
                mission_process_group_stopped=mission_process_group_stopped,
                evaluator_vm_deleted=evaluator_vm_deleted,
            )
        _write_record(output_path, record)
        return record
    except BaseException as error:
        if output_path.exists():
            raise
        if isinstance(error, BaselineError) and error.process_group_id is not None:
            mission_process_group_stopped = not _process_group_alive(
                error.process_group_id
            )
        if source is None:
            source = _recover_source_evidence(artifact_root, secret_canaries)
        if evaluation is None:
            evaluation = _recover_evaluator_evidence(
                artifact_root / "evaluation.json",
                source,
            )
        ended_at = int(clock())
        failure_record = _build_outcome_record(
            bindings=bindings,
            started_at=started_at,
            ended_at=ended_at,
            mission_outcome="mission-failed",
            authorization_reference=authorization_reference,
            source=source,
            evaluation=evaluation,
            factory_mission_id=factory_mission_id,
            failure_classification=failure_classification,
            mission_process_group_stopped=mission_process_group_stopped,
            evaluator_vm_deleted=evaluator_vm_deleted,
        )
        try:
            _write_record(output_path, failure_record)
        except BaseException as persistence_error:
            raise BaselineError(
                "baseline failure outcome could not be persisted"
            ) from persistence_error
        raise


def _is_intended_baseline_failure(record: BaselineRunRecord) -> bool:
    evaluation = record.evaluator_outcome
    if not isinstance(evaluation, Mapping) or evaluation.get("status") != "fail":
        return False
    assertions = evaluation.get("assertions")
    if not isinstance(assertions, list):
        return False
    results: dict[str, str] = {}
    for assertion in assertions:
        if (
            not isinstance(assertion, Mapping)
            or not isinstance(assertion.get("assertion_id"), str)
            or assertion.get("status") not in {"pass", "fail"}
            or assertion["assertion_id"] in results
        ):
            return False
        results[assertion["assertion_id"]] = assertion["status"]
    return (
        frozenset(results) == _EXPECTED_ASSERTION_IDS
        and {
            assertion_id
            for assertion_id, status_value in results.items()
            if status_value == "fail"
        }
        == {_INTENDED_CONFLICT_ASSERTION}
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--preparation", type=Path, required=True)
    value.add_argument("--release-preflight", type=Path, required=True)
    value.add_argument("--profile-manifest", type=Path, required=True)
    value.add_argument("--role-config", type=Path, required=True)
    value.add_argument("--checkout", type=Path, required=True)
    value.add_argument("--mission-file", type=Path, required=True)
    value.add_argument("--exporter", type=Path, required=True)
    value.add_argument("--evaluator-lima-config", type=Path, required=True)
    value.add_argument("--evaluator", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    value.add_argument("--artifact-root", type=Path, required=True)
    value.add_argument("--evaluator-vm", default="shadow-demo-baseline-evaluator")
    value.add_argument("--droid-path", type=Path, default=Path("/usr/local/bin/droid"))
    value.add_argument("--factory-mission-root", type=Path, required=True)
    value.add_argument("--state-root", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        record = run_host_baseline(
            preparation_path=arguments.preparation,
            preflight_path=arguments.release_preflight,
            profile_manifest=arguments.profile_manifest,
            role_config=arguments.role_config,
            checkout=arguments.checkout,
            mission_file=arguments.mission_file,
            exporter_path=arguments.exporter,
            evaluator_lima_config=arguments.evaluator_lima_config,
            evaluator_path=arguments.evaluator,
            output_path=arguments.output,
            artifact_root=arguments.artifact_root,
            evaluator_vm=arguments.evaluator_vm,
            droid_path=arguments.droid_path,
            evaluator_driver=LimaVmDriver(),
            secret_canaries=tuple(
                f"shadow-baseline-canary-{secrets.token_hex(16)}"
                for _ in range(2)
            ),
            factory_mission_root=arguments.factory_mission_root,
            state_root=arguments.state_root,
        )
        if not _is_intended_baseline_failure(record):
            raise BaselineError(
                "baseline evaluator did not fail for the intended conflict"
            )
    except (BaselineError, OSError, ValueError) as error:
        print(f"baseline stopped: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "baseline_id": record.baseline_id,
                "evaluator_status": record.evaluator_outcome["status"],
                "output": str(arguments.output),
                "record_digest": record.record_digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
