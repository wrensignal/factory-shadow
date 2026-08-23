#!/usr/bin/env python3
"""Persist cleanup attestations from frozen baseline or Shadow run records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from shadow_mission.protocol import BaselineRunRecord, RunRecord, canonical_json


class CleanupAttestationError(RuntimeError):
    """The supplied record does not prove both required cleanup facts."""


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SUBJECTS = frozenset({"baseline", "shadow"})


def _require_external_absolute(path: Path) -> Path:
    if not path.is_absolute():
        raise CleanupAttestationError("cleanup output path must be absolute")
    resolved = path.resolve(strict=False)
    if (
        resolved == _PROJECT_ROOT
        or _PROJECT_ROOT in resolved.parents
        or resolved in _PROJECT_ROOT.parents
    ):
        raise CleanupAttestationError("cleanup output must remain outside the project")
    return resolved


def _load_record(
    path: Path,
    model: type[BaselineRunRecord] | type[RunRecord],
) -> BaselineRunRecord | RunRecord:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
        value = json.loads(payload)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or not isinstance(value, Mapping)
            or canonical_json(value) + b"\n" != payload
        ):
            raise CleanupAttestationError("cleanup source record is not canonical")
        return model.model_validate(value)
    except CleanupAttestationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise CleanupAttestationError("cleanup source record is invalid") from error


def _cleanup_observations(
    subject: str,
    record: BaselineRunRecord | RunRecord,
) -> tuple[bool, bool]:
    if subject == "baseline":
        if not isinstance(record, BaselineRunRecord):
            raise CleanupAttestationError("cleanup source record type differs")
        observations = record.usage_data.get("cleanup_observations")
        if not isinstance(observations, Mapping):
            raise CleanupAttestationError("cleanup observations are incomplete")
        mission_stopped = observations.get("mission_process_group_stopped")
        evaluator_deleted = observations.get("evaluator_vm_deleted")
    else:
        if not isinstance(record, RunRecord):
            raise CleanupAttestationError("cleanup source record type differs")
        mission_stopped = record.mission_process_stopped
        evaluator_deleted = record.evaluator_vm_deleted
    if mission_stopped is not True or evaluator_deleted is not True:
        raise CleanupAttestationError("cleanup observations are incomplete")
    return True, True


def _write_private_record(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        raise CleanupAttestationError("cleanup output already exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_json(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def produce_cleanup_attestation(
    *,
    subject: str,
    run_record_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Write one attestation only when the frozen run record proves cleanup."""

    if subject not in _SUBJECTS:
        raise CleanupAttestationError("cleanup subject is invalid")
    output_path = _require_external_absolute(output_path)
    if output_path.exists():
        raise CleanupAttestationError("cleanup output already exists")
    model = BaselineRunRecord if subject == "baseline" else RunRecord
    record = _load_record(run_record_path, model)
    mission_stopped, evaluator_deleted = _cleanup_observations(subject, record)
    value: dict[str, Any] = {
        "schema_version": "0.1",
        "subject": subject,
        "source_record_digest": record.record_digest,
        "mission_process_group_stopped": mission_stopped,
        "evaluator_vm_deleted": evaluator_deleted,
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    _write_private_record(output_path, value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--subject", choices=sorted(_SUBJECTS), required=True)
    value.add_argument("--run-record", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        value = produce_cleanup_attestation(
            subject=arguments.subject,
            run_record_path=arguments.run_record,
            output_path=arguments.output,
        )
    except (CleanupAttestationError, OSError, ValueError) as error:
        print(f"cleanup attestation failed: {error}", file=sys.stderr)
        return 1
    print(canonical_json(value).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
