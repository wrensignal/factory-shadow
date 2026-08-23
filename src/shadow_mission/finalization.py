"""Strict mission teardown, source export, and evaluator sequencing."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence
from pydantic import BaseModel, ConfigDict, Field


from .evaluation import (
    EvaluationBoundaryError,
    EvaluationRecord,
    VmDriver,
    run_isolated_evaluator,
    validate_evaluator_assets,
)
from .protocol import PreEvaluationRecord, RunRecord, canonical_json
from .reporting import ReportError, load_run_record
from .source_export import ValidatedSourceArchive, validate_source_archive
from .graph import GraphError, load_exchanges
_DIGEST = r"^[0-9a-f]{64}$"
# The trusted exporter has 30-second Git probes. Two minutes leaves time to
# archive the bounded source tree without stranding post-Mission finalization.
_SOURCE_EXPORT_TIMEOUT_SECONDS = 120


class FinalizationError(RuntimeError):
    """Finalization could not preserve the required isolation and bindings."""





class FinalizationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    run_record: RunRecord
    pre_evaluation_record: PreEvaluationRecord
    source_archive_digest: str = Field(pattern=_DIGEST)
    source_manifest_digest: str = Field(pattern=_DIGEST)
    evaluation_record: EvaluationRecord


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("canonical write made no progress")
        written += count


def _atomic_canonical_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, canonical_json(dict(value)) + b"\n")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass

def _exclusive_canonical_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, canonical_json(dict(value)) + b"\n")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary_name, path, follow_symlinks=False)
        os.unlink(temporary_name)
        temporary_name = ""
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass



def _pre_evaluation_record(values: Mapping[str, Any]) -> PreEvaluationRecord:
    material = dict(values)
    material["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    return PreEvaluationRecord.model_validate(material)


def _complete_run_record(
    path: Path,
    run_record: RunRecord,
    source: ValidatedSourceArchive,
    pre_evaluation: PreEvaluationRecord,
    evaluation: EvaluationRecord,
) -> RunRecord:
    value = run_record.model_dump(mode="json")
    value["final_source_archive_digest"] = source.archive_digest
    value["evaluator_outcome"] = evaluation.model_dump(mode="json")
    value["pre_evaluation_record_digest"] = pre_evaluation.record_digest
    value["final_source_manifest_digest"] = source.manifest_digest
    value["final_source_working_tree_digest"] = (
        source.manifest.working_tree_digest
    )
    value["evaluator_digest"] = pre_evaluation.evaluator_digest
    value["evaluation_record_digest"] = evaluation.record_digest
    value["evaluator_vm_deleted"] = True
    value["record_digest"] = "0" * 64
    material = dict(value)
    material.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    completed = RunRecord.model_validate(value)
    _atomic_canonical_json(path, completed.model_dump(mode="json"))
    return completed


def export_final_source(
    *,
    mission_repo: Path,
    exporter_path: Path,
    expected_exporter_digest: str,
    artifact_root: Path,
    secret_canaries: Sequence[str],
) -> ValidatedSourceArchive:
    try:
        metadata = exporter_path.lstat()
        if exporter_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise FinalizationError("source exporter is not a regular file")
    except OSError as error:
        raise FinalizationError("cannot inspect source exporter") from error
    if _sha256_file(exporter_path) != expected_exporter_digest:
        raise FinalizationError("source exporter digest differs")
    if not secret_canaries:
        raise FinalizationError("source export canaries are unavailable")
    try:
        canary_bytes = tuple(value.encode("utf-8") for value in secret_canaries)
    except UnicodeEncodeError as error:
        raise FinalizationError("source export canary is not UTF-8") from error
    if (
        len(canary_bytes) > 64
        or len(canary_bytes) != len(set(canary_bytes))
        or any(
            not value
            or b"\x00" in value
            or b"\r" in value
            or b"\n" in value
            or len(value) > 4096
            for value in canary_bytes
        )
    ):
        raise FinalizationError("source export canary is invalid")
    try:
        repo_metadata = mission_repo.lstat()
        repo = mission_repo.resolve(strict=True)
    except OSError as error:
        raise FinalizationError("mission checkout is unavailable") from error
    if mission_repo.is_symlink() or not stat.S_ISDIR(repo_metadata.st_mode):
        raise FinalizationError("mission checkout is invalid")
    artifact_root.mkdir(parents=True, exist_ok=False, mode=0o700)
    archive_path = artifact_root / "final-source.tar"
    manifest_path = artifact_root / "final-source-manifest.json"
    export_arguments = [
        sys.executable,
        str(exporter_path),
        "--repo",
        str(repo),
        "--archive",
        str(archive_path),
        "--manifest",
        str(manifest_path),
        "--forbidden-values-stdin",
    ]
    forbidden_value_descriptor = canonical_json(
        {"forbidden_values": list(secret_canaries)}
    ) + b"\n"
    export_environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(artifact_root),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
    }
    if any(
        forbidden in os.fsencode(argument)
        for forbidden in canary_bytes
        for argument in export_arguments
    ):
        raise FinalizationError("source exporter argument boundary is unsafe")
    if any(
        forbidden in value.encode("utf-8")
        for forbidden in canary_bytes
        for value in export_environment.values()
    ):
        raise FinalizationError("source exporter environment boundary is unsafe")
    try:
        exported = subprocess.run(
            export_arguments,
            input=forbidden_value_descriptor,
            close_fds=True,
            shell=False,
            env=export_environment,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_SOURCE_EXPORT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise FinalizationError("mission source export timed out") from None
    except OSError:
        raise FinalizationError("mission source exporter did not start") from None
    if exported.returncode != 0:
        raise FinalizationError(
            f"mission source export exited {exported.returncode}"
        )
    return validate_source_archive(
        archive_path,
        manifest_path,
        secret_canaries=canary_bytes,
    )


def finalize_run(
    *,
    evaluator_driver: VmDriver,
    evaluator_vm_name: str,
    evaluator_lima_config: Path,
    mission_repo: Path,
    exporter_path: Path,
    evaluator_path: Path,
    run_dir: Path,
    mission_process_stopped: bool,
    hooks_stopped: bool,
    secret_canaries: Sequence[str],
    mission_process_succeeded: bool = True,
) -> FinalizationResult:
    """Export the host checkout after process stop, evaluate, then persist."""
    if not mission_process_stopped or not hooks_stopped:
        raise FinalizationError("mission and hooks must stop before source export")

    run_record_path = run_dir / "run.json"
    try:
        run_record = load_run_record(run_record_path)
    except (ReportError, OSError, ValueError) as error:
        raise FinalizationError(
            "run record is unavailable or corrupt"
        ) from error
    if run_record.mission_process_stopped is not True:
        raise FinalizationError("Mission process stop is not attested")
    expected_process_success = run_record.runtime_outcome == "mission-terminated"
    if mission_process_succeeded != expected_process_success:
        raise FinalizationError("Mission process outcome differs from runtime record")
    evaluator_digest = validate_evaluator_assets(
        evaluator_lima_config,
        evaluator_path,
    )
    if evaluator_digest != run_record.approved_evaluator_digest:
        raise FinalizationError("approved evaluator digest differs")
    journal_path = run_dir / "review.jsonl"
    event_path = run_dir / "events.jsonl"
    for path, description in (
        (journal_path, "review journal"),
        (event_path, "event ledger"),
    ):
        if not path.is_file() or path.is_symlink():
            raise FinalizationError(f"{description} is unavailable")
    try:
        event_record_count = len(load_exchanges(event_path))
    except (GraphError, ValueError) as error:
        raise FinalizationError("event ledger is invalid") from error
    source = export_final_source(
        mission_repo=mission_repo,
        exporter_path=exporter_path,
        expected_exporter_digest=run_record.source_exporter_digest,
        artifact_root=run_dir / "final-source",
        secret_canaries=secret_canaries,
    )
    if source.manifest.final_commit != run_record.final_commit:
        raise FinalizationError("final source commit binding differs")
    pre_evaluation = _pre_evaluation_record(
        {
            "schema_version": "0.1",
            "run_id": run_record.run_id,
            "pre_evaluation_run_record_digest": run_record.record_digest,
            "event_ledger_digest": _sha256_file(event_path),
            "event_ledger_record_count": event_record_count,
            "review_journal_digest": _sha256_file(journal_path),
            "source_archive_digest": source.archive_digest,
            "source_manifest_digest": source.manifest_digest,
            "source_working_tree_digest": source.manifest.working_tree_digest,
            "evaluator_digest": evaluator_digest,
            "mission_process_stopped": True,
        }
    )
    _exclusive_canonical_json(
        run_dir / "pre-evaluation-run.json",
        run_record.model_dump(mode="json"),
    )
    _exclusive_canonical_json(
        run_dir / "pre-evaluation.json",
        pre_evaluation.model_dump(mode="json"),
    )
    try:
        evaluation = run_isolated_evaluator(
            driver=evaluator_driver,
            vm_name=evaluator_vm_name,
            lima_config=evaluator_lima_config,
            archive_path=source.archive_path,
            manifest_path=source.manifest_path,
            evaluator_path=evaluator_path,
            output_path=run_dir / "evaluation.json",
        )
    except EvaluationBoundaryError as error:
        raise FinalizationError("isolated evaluator failed") from error
    completed = _complete_run_record(
        run_dir / "run.json",
        run_record,
        source,
        pre_evaluation,
        evaluation,
    )
    if evaluation.status != "pass":
        raise FinalizationError("evaluator reported failure")
    return FinalizationResult(
        run_record=completed,
        pre_evaluation_record=pre_evaluation,
        source_archive_digest=source.archive_digest,
        source_manifest_digest=source.manifest_digest,
        evaluation_record=evaluation,
    )
