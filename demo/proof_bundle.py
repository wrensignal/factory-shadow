#!/usr/bin/env python3
"""Build and verify a digest-bound public evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass, fields
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

# `ci` and `demo` are project-root packages, not installed distributions. Direct
# script invocation (`python demo/proof_bundle.py`) puts `demo/` on `sys.path`
# instead of the project root, so make the root importable the way every other
# demo command already resolves. `python -m demo.proof_bundle` is unaffected.
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from ci.verify_release import PRIVATE_PATH_PATTERNS, SECRET_PATTERNS
from demo.compare import ComparisonError, compare
from shadow_mission.correlation import (
    FactoryMissionCorrelationWrapper,
    correlation_record_digest,
    correlation_wrapper_digest,
)
from shadow_mission.evaluation import EvaluationRecord
from shadow_mission.graph import GraphError, MissionGraph, load_exchanges_bytes
from shadow_mission.protocol import (
    BaselineRunRecord,
    DIGEST_PATTERN,
    HookEnvelope,
    HookExchangeRecord,
    HookResponseRecord,
    InterventionRecord,
    PreEvaluationRecord,
    RunRecord,
    canonical_json,
    hook_envelope_digest,
    hook_response_digest,
)
from shadow_mission.reporting import ReportError, ReportRecord, rebuild_report
from shadow_mission.review_journal import (
    ZERO_DIGEST,
    ExchangeProjectionRecord,
    ExtractionOutcomeRecord,
    FindingSnapshotRecord,
    InterventionLineageRecord,
    OutageReconciliationRecord,
    ProbeOutcomeRecord,
    ReviewJournalCorruptionError,
    RoleDecisionRecord,
    TranscriptBatchRecord,
    load_journal_records,
)
from shadow_mission.roles import FrozenMissionRelations, MissionRelation
from shadow_mission.router import InterventionRouterDelta, InterventionRouterState
from shadow_mission.rules import DeliverySelector, DeliverySelectorState
from shadow_mission.source_export import SourceArchiveError, validate_source_archive


class ProofBundleError(RuntimeError):
    pass


_PAIR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TOKEN = re.compile(rb"[A-Za-z0-9][A-Za-z0-9._:-]{0,511}")
_DIGEST = re.compile(DIGEST_PATTERN)
_MAX_MEMBER_BYTES = 64 << 20
_MAX_BUNDLE_BYTES = 512 << 20
_MAX_MEMBERS = 256
_SHADOW_INPUT_NAMES = (
    "run.json",
    "pre-evaluation-run.json",
    "pre-evaluation.json",
    "evaluation.json",
    "correlation.json",
    "events.jsonl",
    "review.jsonl",
)
# Structured path fields hold exact values.
# Only allowlisted redacted text fields allow token discovery.
_MAX_PATH_TEXT_CHARS = _MAX_MEMBER_BYTES
_MAX_PATH_TOKEN_BYTES = 4096
_MAX_PATH_TOKENS = 4096
_MAX_PATH_CANDIDATES = _MAX_PATH_TOKENS * 2
_PATH_QUOTES = frozenset({"'", '"', "`"})
_PATH_STRING_PREFIXES = frozenset("rRbBuUfF")
_PATH_LEFT_BOUNDARIES = frozenset(
    " \t\r\n\"'`=,:;|&!<>()[{}]"
)
_PATH_RIGHT_BOUNDARIES = frozenset(
    " \t\r\n\"'`=,:;|&!<>()[]{}*,?#$"
)
_PATH_TRAILING_PUNCTUATION = frozenset({".", ","})
_PATCH_PATH_HEADERS = (
    "*** Add File:",
    "*** Delete File:",
    "*** Move to:",
    "*** Update File:",
    "---",
    "+++",
)
_PUBLIC_PATH_KEYS = frozenset(
    {
        "directoryPath",
        "directory_path",
        "filePath",
        "file_path",
        "folder",
        "missionDir",
        "path",
        "workingDirectory",
        "working_directory",
    }
)
_PUBLIC_PATH_TEXT_KEYS = frozenset(
    {"command", "input", "prompt", "proposal", "tool_response"}
)
_RAW_IDENTIFIER_KEYS = frozenset(
    {"factory_mission_id", "factory_session_id", "mission_id", "session_id"}
)
_FORBIDDEN_STRUCTURED_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "auth_token",
        "authorization",
        "credential",
        "credentials",
        "factory_api_key",
        "password",
        "secret",
        "token",
    }
)


@dataclass(frozen=True)
class _AbsolutePathToken:
    start: int
    end: int
    value: str


@dataclass(frozen=True)
class PairArtifacts:
    pair_id: str
    baseline_record: Path
    baseline_archive: Path
    baseline_manifest: Path
    baseline_evaluation: Path
    shadow_archive: Path
    shadow_manifest: Path
    shadow_run_dir: Path
    report_record: Path
    comparison_record: Path
    baseline_cleanup_attestation: Path
    shadow_cleanup_attestation: Path


def _read_regular(path: Path, description: str, *, limit: int = _MAX_MEMBER_BYTES) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProofBundleError(f"{description} is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProofBundleError(f"{description} is not a regular file")
        if metadata.st_size > limit:
            raise ProofBundleError(f"{description} exceeds its size bound")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, min(1 << 20, limit + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise ProofBundleError(f"{description} exceeds its size bound")
        return b"".join(chunks)
    except OSError as error:
        raise ProofBundleError(f"{description} is unreadable") from error
    finally:
        os.close(descriptor)





def _load_canonical_object(path: Path, description: str) -> dict[str, Any]:
    payload = _read_regular(path, description)
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProofBundleError(f"{description} is invalid") from error
    if not isinstance(value, dict) or canonical_json(value) + b"\n" != payload:
        raise ProofBundleError(f"{description} is not canonical")
    return value


def _load_model(path: Path, model_type, description: str):
    value = _load_canonical_object(path, description)
    try:
        return model_type.model_validate(value)
    except ValueError as error:
        raise ProofBundleError(f"{description} is invalid") from error


def _write_canonical(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = canonical_json(value) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _replace_canonical(path: Path, value: Mapping[str, Any]) -> None:
    payload = canonical_json(value) + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _copy_regular(source: Path, destination: Path, description: str) -> None:
    payload = _read_regular(source, description)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _record_digest(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("record_digest", None)
    return hashlib.sha256(canonical_json(material)).hexdigest()


def _validate_self_digest(value: Mapping[str, Any], description: str) -> None:
    supplied = value.get("record_digest")
    if not isinstance(supplied, str) or supplied != _record_digest(value):
        raise ProofBundleError(f"{description} digest differs")


def _walk_structured(value: Any) -> Iterable[tuple[str | None, Any]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key), item
            yield from _walk_structured(item)
    elif isinstance(value, list):
        for item in value:
            yield None, item
            yield from _walk_structured(item)


def _is_public_identifier_field(key: str, value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if key.endswith("session_id"):
        return value.startswith("public-session-")
    if key.endswith("mission_id"):
        return value.startswith("public-mission-")
    return False


def _scan_structured(value: Any, name: str) -> None:
    correlation_member = name.endswith("/correlation.json")
    for key, item in _walk_structured(value):
        if key is not None and _has_absolute_path(key):
            raise ProofBundleError(
                f"absolute host path in bundle member key: {name}"
            )
        if isinstance(item, str) and _has_absolute_path(item):
            raise ProofBundleError(f"absolute host path in bundle member: {name}")
        if key is None:
            continue
        normalized = key.lower()
        if (
            not correlation_member
            and normalized in _RAW_IDENTIFIER_KEYS
            and not _is_public_identifier_field(normalized, item)
        ):
            raise ProofBundleError(f"raw identifier field in bundle member: {name}")
        if (
            normalized in _FORBIDDEN_STRUCTURED_KEYS
            or "credential" in normalized
            or "approval" in normalized
        ):
            raise ProofBundleError(f"excluded field in bundle member: {name}")


def _scan_payload(
    name: str,
    payload: bytes,
    *,
    excluded_identifier_hashes: frozenset[str] = frozenset(),
) -> None:
    for pattern in PRIVATE_PATH_PATTERNS:
        if pattern.search(payload):
            raise ProofBundleError(f"private path in bundle member: {name}")
    for pattern in SECRET_PATTERNS:
        if pattern.search(payload):
            raise ProofBundleError(f"credential in bundle member: {name}")
    if excluded_identifier_hashes:
        for match in _TOKEN.finditer(payload):
            if (
                hashlib.sha256(match.group(0)).hexdigest()
                in excluded_identifier_hashes
            ):
                raise ProofBundleError(f"raw identifier in bundle member: {name}")


def _scan_json_payload(name: str, payload: bytes) -> None:
    if name.endswith(".json"):
        try:
            value = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ProofBundleError(f"JSON bundle member is invalid: {name}") from error
        if canonical_json(value) + b"\n" != payload:
            raise ProofBundleError(f"JSON bundle member is not canonical: {name}")
        _scan_structured(value, name)
    elif name.endswith(".jsonl"):
        for line in io.BytesIO(payload):
            if not line.endswith(b"\n"):
                raise ProofBundleError(f"JSONL bundle member is incomplete: {name}")
            try:
                value = json.loads(line[:-1])
            except (UnicodeError, json.JSONDecodeError) as error:
                raise ProofBundleError(f"JSONL bundle member is invalid: {name}") from error
            if canonical_json(value) != line[:-1]:
                raise ProofBundleError(f"JSONL bundle member is not canonical: {name}")
            _scan_structured(value, name)


def _scan_source_archive(
    name: str,
    path: Path,
    *,
    excluded_identifier_hashes: frozenset[str],
) -> None:
    try:
        with tarfile.open(path, mode="r:") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ProofBundleError(f"source member is unreadable: {member.name}")
                payload = extracted.read(_MAX_MEMBER_BYTES + 1)
                if len(payload) > _MAX_MEMBER_BYTES:
                    raise ProofBundleError(f"source member exceeds its size bound: {member.name}")
                try:
                    decoded = payload.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ProofBundleError(
                        f"source member is not decodable: {member.name}"
                    ) from error
                if _has_absolute_path(decoded):
                    raise ProofBundleError(
                        f"absolute host path in source member: {member.name}"
                    )
                _scan_payload(
                    f"{name}:{member.name}",
                    payload,
                    excluded_identifier_hashes=excluded_identifier_hashes,
                )
    except ProofBundleError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ProofBundleError(f"source archive is invalid: {name}") from error


def _validate_cleanup(
    path: Path,
    side: str,
    *,
    subject: str,
    source_record_digest: str,
) -> dict[str, Any]:
    value = _load_canonical_object(path, f"{side} cleanup attestation")
    if set(value) != {
        "schema_version",
        "subject",
        "source_record_digest",
        "mission_process_group_stopped",
        "evaluator_vm_deleted",
        "record_digest",
    }:
        raise ProofBundleError(f"{side} cleanup attestation schema differs")
    _validate_self_digest(value, f"{side} cleanup attestation")
    if (
        value["schema_version"] != "0.1"
        or value["subject"] != subject
        or value["source_record_digest"] != source_record_digest
        or value["mission_process_group_stopped"] is not True
        or value["evaluator_vm_deleted"] is not True
    ):
        raise ProofBundleError(f"{side} cleanup attestation binding differs")
    return value


def _rewrite_cleanup_binding(
    path: Path,
    side: str,
    *,
    subject: str,
    prior_source_digest: str,
    source_record_digest: str,
) -> None:
    value = _validate_cleanup(
        path,
        side,
        subject=subject,
        source_record_digest=prior_source_digest,
    )
    value["source_record_digest"] = source_record_digest
    value["record_digest"] = _record_digest(value)
    _replace_canonical(path, value)


def _comparison_value(
    *,
    baseline_record: Path,
    shadow_run_dir: Path,
    baseline_archive: Path,
    baseline_manifest: Path,
    shadow_archive: Path,
    shadow_manifest: Path,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="shadow-proof-comparison-") as temporary:
        output = Path(temporary) / "comparison.json"
        try:
            return compare(
                baseline_record_path=baseline_record,
                shadow_run_dir=shadow_run_dir,
                baseline_archive=baseline_archive,
                baseline_manifest=baseline_manifest,
                shadow_archive=shadow_archive,
                shadow_manifest=shadow_manifest,
                output_path=output,
            )
        except (ComparisonError, SourceArchiveError, OSError, ValueError) as error:
            raise ProofBundleError("comparison rebuild failed") from error


def _rebuilt_report(run_dir: Path, baseline_record: Path) -> ReportRecord:
    try:
        return rebuild_report(
            run_dir,
            baseline_record_path=baseline_record,
        )
    except (ReportError, SourceArchiveError, OSError, ValueError) as error:
        raise ProofBundleError("report rebuild failed") from error

def _reports_equal(left: ReportRecord, right: ReportRecord) -> bool:
    return left.model_dump(mode="json") == right.model_dump(mode="json")


def _validate_source_pair(pair: PairArtifacts) -> RunRecord:
    if not _PAIR_ID.fullmatch(pair.pair_id):
        raise ProofBundleError("pair id is invalid")
    baseline = _load_model(pair.baseline_record, BaselineRunRecord, "baseline record")
    baseline_evaluation = _load_model(
        pair.baseline_evaluation,
        EvaluationRecord,
        "baseline evaluator result",
    )
    if baseline_evaluation.model_dump(mode="json") != baseline.evaluator_outcome:
        raise ProofBundleError("baseline evaluator binding differs")
    baseline_source = validate_source_archive(pair.baseline_archive, pair.baseline_manifest)
    if (
        baseline.final_source_archive_digest != baseline_source.archive_digest
        or baseline_evaluation.archive_digest != baseline_source.archive_digest
        or baseline_evaluation.working_tree_digest
        != baseline_source.manifest.working_tree_digest
    ):
        raise ProofBundleError("baseline source binding differs")

    run = _load_model(pair.shadow_run_dir / "run.json", RunRecord, "Shadow run record")
    if run.run_id != pair.shadow_run_dir.name:
        raise ProofBundleError("Shadow run directory identity differs")
    shadow_evaluation = _load_model(
        pair.shadow_run_dir / "evaluation.json",
        EvaluationRecord,
        "Shadow evaluator result",
    )
    if shadow_evaluation.model_dump(mode="json") != run.evaluator_outcome:
        raise ProofBundleError("Shadow evaluator binding differs")
    shadow_source = validate_source_archive(
        pair.shadow_run_dir / "final-source/final-source.tar",
        pair.shadow_run_dir / "final-source/final-source-manifest.json",
    )
    if (
        run.final_source_archive_digest != shadow_source.archive_digest
        or shadow_evaluation.archive_digest != shadow_source.archive_digest
        or shadow_evaluation.working_tree_digest
        != shadow_source.manifest.working_tree_digest
    ):
        raise ProofBundleError("Shadow source binding differs")
    if pair.shadow_archive != pair.shadow_run_dir / "final-source/final-source.tar":
        supplied_shadow = validate_source_archive(pair.shadow_archive, pair.shadow_manifest)
        if (
            supplied_shadow.archive_digest != shadow_source.archive_digest
            or supplied_shadow.manifest_digest != shadow_source.manifest_digest
        ):
            raise ProofBundleError("Shadow source inputs differ")

    rebuilt_report = _rebuilt_report(
        pair.shadow_run_dir,
        pair.baseline_record,
    )
    supplied_report = _load_model(pair.report_record, ReportRecord, "report record")
    if not _reports_equal(supplied_report, rebuilt_report):
        raise ProofBundleError("report record differs from rebuild")
    supplied_comparison = _load_canonical_object(
        pair.comparison_record,
        "comparison record",
    )
    _validate_self_digest(supplied_comparison, "comparison record")
    rebuilt_comparison = _comparison_value(
        baseline_record=pair.baseline_record,
        shadow_run_dir=pair.shadow_run_dir,
        baseline_archive=pair.baseline_archive,
        baseline_manifest=pair.baseline_manifest,
        shadow_archive=pair.shadow_archive,
        shadow_manifest=pair.shadow_manifest,
    )
    if supplied_comparison != rebuilt_comparison:
        raise ProofBundleError("comparison record differs from rebuild")
    _validate_cleanup(
        pair.baseline_cleanup_attestation,
        "baseline",
        subject="baseline",
        source_record_digest=baseline.record_digest,
    )
    _validate_cleanup(
        pair.shadow_cleanup_attestation,
        "Shadow",
        subject="shadow",
        source_record_digest=run.record_digest,
    )
    return run


def _public_alias(kind: str, value: str) -> str:
    return f"public-{kind}-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:24]}"


def _require_identifier_token(value: str, description: str) -> None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise ProofBundleError(f"{description} is invalid") from error
    if _TOKEN.fullmatch(encoded) is None:
        raise ProofBundleError(f"{description} is not a bounded token")


def _public_alias_map(
    wrapper: FactoryMissionCorrelationWrapper,
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    kinds: dict[str, str] = {}

    def add(kind: str, raw_value: str) -> None:
        _require_identifier_token(raw_value, f"correlation {kind} identifier")
        prior_kind = kinds.get(raw_value)
        if prior_kind is not None and prior_kind != kind:
            raise ProofBundleError("correlation identifier kinds overlap")
        kinds[raw_value] = kind
        aliases[raw_value] = _public_alias(kind, raw_value)

    add("mission", wrapper.record.mission_id)
    for relation in wrapper.record.sessions:
        add("session", relation.session_id)
        if relation.assignment_id is not None:
            add("assignment", relation.assignment_id)
    if wrapper.mission_id in aliases:
        raise ProofBundleError("run identity overlaps a correlation identifier")
    public_values = tuple(aliases.values())
    if (
        len(public_values) != len(set(public_values))
        or set(public_values) & set(aliases)
    ):
        raise ProofBundleError("public correlation aliases collide")
    return aliases


def _require_bounded_path(value: str, description: str) -> None:
    if len(value) > _MAX_PATH_TOKEN_BYTES:
        raise ProofBundleError(f"{description} exceeds its bound")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise ProofBundleError(f"{description} is invalid") from error
    if len(encoded) > _MAX_PATH_TOKEN_BYTES:
        raise ProofBundleError(f"{description} exceeds its bound")


def _is_absolute_path_value(value: str) -> bool:
    if (
        not value
        or len(value) > _MAX_PATH_TOKEN_BYTES
        or any(character in value for character in "\x00\r\n")
    ):
        return False
    if value.startswith("/"):
        return True
    if (
        len(value) >= 3
        and value[0].isascii()
        and value[0].isalpha()
        and value[1] == ":"
        and value[2] in "\\/"
    ):
        return True
    if not value.startswith("\\\\"):
        return False
    remainder = value[2:]
    separator = next(
        (
            index
            for index, character in enumerate(remainder)
            if character in "\\/"
        ),
        -1,
    )
    if separator <= 0 or separator == len(remainder) - 1:
        return False
    server = remainder[:separator]
    share_and_tail = remainder[separator + 1 :]
    share = re.split(r"[\\/]", share_and_tail, maxsplit=1)[0]
    return not any(character.isspace() for character in server) and bool(
        share and not share.isspace()
    )


def _absolute_path_kind_at(value: str, start: int) -> str | None:
    remaining = len(value) - start
    if (
        remaining >= 1
        and value[start] == "/"
        and (
            remaining == 1
            or value[start + 1] not in {"/", "\x00", "\r", "\n"}
        )
    ):
        return "posix"
    if (
        remaining >= 3
        and value[start].isascii()
        and value[start].isalpha()
        and value[start + 1] == ":"
        and value[start + 2] in "\\/"
    ):
        return "windows"
    if (
        remaining >= 5
        and value.startswith("\\\\", start)
        and value[start + 2] not in "\\/ \t\r\n\x00"
    ):
        return "windows"
    return None


def _path_has_left_boundary(value: str, start: int) -> bool:
    return start == 0 or value[start - 1] in _PATH_LEFT_BOUNDARIES


def _path_quote_has_left_boundary(value: str, quote_start: int) -> bool:
    if _path_has_left_boundary(value, quote_start):
        return True
    prefix_start = quote_start
    while (
        prefix_start > 0
        and quote_start - prefix_start < 2
        and value[prefix_start - 1] in _PATH_STRING_PREFIXES
    ):
        prefix_start -= 1
    return (
        prefix_start < quote_start
        and _path_has_left_boundary(value, prefix_start)
    )


def _closing_path_quote(value: str, start: int, quote: str) -> int:
    cursor = start
    while cursor < len(value):
        if cursor - start > _MAX_PATH_TOKEN_BYTES:
            raise ProofBundleError("absolute path token exceeds its bound")
        character = value[cursor]
        if character in "\r\n":
            break
        if character == quote:
            if quote == "'":
                return cursor
            backslashes = 0
            prior = cursor - 1
            while prior >= start and value[prior] == "\\":
                backslashes += 1
                prior -= 1
            if backslashes % 2 == 0:
                return cursor
        cursor += 1
    raise ProofBundleError("quoted absolute path is not terminated")


def _append_path_candidate(
    candidates: list[_AbsolutePathToken],
    value: str,
    start: int,
    end: int,
    *,
    trim_trailing_punctuation: bool = False,
) -> None:
    while end > start and value[end - 1] in " \t\r":
        end -= 1
    if trim_trailing_punctuation:
        while end > start and value[end - 1] in _PATH_TRAILING_PUNCTUATION:
            end -= 1
    if end <= start:
        return
    if end - start > _MAX_PATH_TOKEN_BYTES:
        raise ProofBundleError("absolute path token exceeds its bound")
    raw_path = value[start:end]
    if not _is_absolute_path_value(raw_path):
        return
    _require_bounded_path(raw_path, "absolute path token")
    candidates.append(_AbsolutePathToken(start, end, raw_path))
    if len(candidates) > _MAX_PATH_CANDIDATES:
        raise ProofBundleError("absolute path candidate count exceeds its bound")


# Patch header boundaries preserve spaces after newline redaction.
def _collect_patch_path_candidates(
    value: str,
    candidates: list[_AbsolutePathToken],
) -> None:
    search_start = 0
    boundary_markers = (
        *_PATCH_PATH_HEADERS,
        "*** Begin Patch",
        "*** End Patch",
    )
    while search_start < len(value):
        matches = tuple(
            (position, header)
            for header in _PATCH_PATH_HEADERS
            if (position := value.find(header, search_start)) >= 0
        )
        if not matches:
            return
        header_start, header = min(
            matches,
            key=lambda item: (item[0], -len(item[1]), item[1]),
        )
        search_start = header_start + 1
        if header_start > 0 and not value[header_start - 1].isspace():
            continue
        cursor = header_start + len(header)
        if cursor >= len(value) or value[cursor] not in " \t":
            continue
        while cursor < len(value) and value[cursor] in " \t":
            cursor += 1
        if cursor >= len(value) or value[cursor] in "\r\n":
            continue
        path_start = cursor + 1 if value[cursor] in _PATH_QUOTES else cursor
        if _absolute_path_kind_at(value, path_start) is None:
            continue
        if path_start != cursor:
            path_end = _closing_path_quote(
                value,
                path_start,
                value[cursor],
            )
            _append_path_candidate(
                candidates,
                value,
                path_start,
                path_end,
            )
            search_start = path_end + 1
            continue
        path_end = len(value)
        for delimiter in ("\r", "\n", "\t"):
            position = value.find(delimiter, path_start)
            if position >= 0:
                path_end = min(path_end, position)
        for marker in boundary_markers:
            for separator in (" ", "\t"):
                position = value.find(
                    f"{separator}{marker}",
                    path_start,
                )
                if position >= 0:
                    path_end = min(path_end, position)
        _append_path_candidate(
            candidates,
            value,
            path_start,
            path_end,
        )
        search_start = max(path_end, header_start + 1)


def _collect_general_path_candidates(
    value: str,
    candidates: list[_AbsolutePathToken],
) -> None:
    cursor = 0
    while cursor < len(value):
        kind = _absolute_path_kind_at(value, cursor)
        if kind is None or not _path_has_left_boundary(value, cursor):
            cursor += 1
            continue
        start = cursor
        if start > 0 and value[start - 1] in _PATH_QUOTES:
            quote_start = start - 1
            if not _path_quote_has_left_boundary(value, quote_start):
                cursor += 1
                continue
            path_end = _closing_path_quote(value, start, value[quote_start])
            _append_path_candidate(candidates, value, start, path_end)
            cursor = path_end + 1
            continue
        path_end = start
        while path_end < len(value):
            character = value[path_end]
            if character == "\x00":
                break
            if (
                path_end > start
                and character in _PATH_RIGHT_BOUNDARIES
                and not (
                    kind == "windows"
                    and path_end == start + 1
                    and character == ":"
                )
            ):
                break
            if (
                kind == "posix"
                and character == "\\"
                and path_end + 1 < len(value)
            ):
                path_end += 2
            else:
                path_end += 1
            if path_end - start > _MAX_PATH_TOKEN_BYTES:
                raise ProofBundleError("absolute path token exceeds its bound")
        _append_path_candidate(
            candidates,
            value,
            start,
            path_end,
            trim_trailing_punctuation=True,
        )
        cursor = max(path_end, start + 1)


def _absolute_path_tokens(value: str) -> tuple[_AbsolutePathToken, ...]:
    if len(value) > _MAX_PATH_TEXT_CHARS:
        raise ProofBundleError("redacted path text exceeds its bound")
    candidates: list[_AbsolutePathToken] = []
    _collect_patch_path_candidates(value, candidates)
    _collect_general_path_candidates(value, candidates)
    unique = {
        (candidate.start, candidate.end, candidate.value): candidate
        for candidate in candidates
    }
    # Longest candidates win, so patch paths retain space-delimited segments.
    selected: list[_AbsolutePathToken] = []
    for candidate in sorted(
        unique.values(),
        key=lambda item: (
            -(item.end - item.start),
            item.start,
            item.end,
            item.value,
        ),
    ):
        if any(
            candidate.start < prior.end and prior.start < candidate.end
            for prior in selected
        ):
            continue
        selected.append(candidate)
        if len(selected) > _MAX_PATH_TOKENS:
            raise ProofBundleError("absolute path token count exceeds its bound")
    return tuple(sorted(selected, key=lambda item: (item.start, item.end)))


def _has_absolute_path(value: str) -> bool:
    return _is_absolute_path_value(value) or bool(_absolute_path_tokens(value))


def _public_path_map(values: Iterable[Any]) -> dict[str, str]:
    raw_paths: set[str] = set()

    def collect(
        item: Any,
        *,
        path_field: bool = False,
        path_text_field: bool = False,
    ) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                collect(
                    child,
                    path_field=(
                        isinstance(key, str) and key in _PUBLIC_PATH_KEYS
                    ),
                    path_text_field=(
                        isinstance(key, str)
                        and key in _PUBLIC_PATH_TEXT_KEYS
                    ),
                )
            return
        if isinstance(item, (list, tuple)):
            for child in item:
                collect(child)
            return
        if not isinstance(item, str):
            return
        if path_field and _is_absolute_path_value(item):
            _require_bounded_path(item, "absolute path value")
            raw_paths.add(item)
        if path_text_field:
            raw_paths.update(
                token.value for token in _absolute_path_tokens(item)
            )

    for value in values:
        collect(value)
    aliases = {
        raw_path: _public_alias("path", raw_path)
        for raw_path in sorted(raw_paths)
    }
    public_values = tuple(aliases.values())
    if (
        len(public_values) != len(set(public_values))
        or set(public_values) & set(aliases)
    ):
        raise ProofBundleError("public path aliases collide")
    return aliases


def _merge_public_path_maps(
    *path_maps: Mapping[str, str],
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for path_map in path_maps:
        for raw_path in sorted(path_map):
            public_path = path_map[raw_path]
            prior = aliases.get(raw_path)
            if prior is not None and prior != public_path:
                raise ProofBundleError("public path maps differ")
            aliases[raw_path] = public_path
    aliases = dict(sorted(aliases.items()))
    public_values = tuple(aliases.values())
    if (
        len(public_values) != len(set(public_values))
        or set(public_values) & set(aliases)
    ):
        raise ProofBundleError("public path aliases collide")
    return aliases


def _rewrite_path_text(
    value: str,
    path_aliases: Mapping[str, str],
    *,
    description: str,
) -> str:
    tokens = _absolute_path_tokens(value)
    if not tokens:
        return value
    replacements: list[tuple[_AbsolutePathToken, str]] = []
    for token in sorted(
        tokens,
        key=lambda item: (-len(item.value), item.start, item.end),
    ):
        public_path = path_aliases.get(token.value)
        if public_path is None:
            raise ProofBundleError(
                f"{description} has an unmapped absolute host path"
            )
        replacements.append((token, public_path))
    pieces: list[str] = []
    cursor = 0
    for token, public_path in sorted(
        replacements,
        key=lambda item: (item[0].start, item[0].end),
    ):
        pieces.extend((value[cursor : token.start], public_path))
        cursor = token.end
    pieces.append(value[cursor:])
    return "".join(pieces)


def _rewrite_structured_aliases(
    value: Any,
    aliases: Mapping[str, str],
    *,
    description: str,
    path_aliases: Mapping[str, str] | None = None,
    _path_field: bool = False,
    _path_text_field: bool = False,
) -> Any:
    if path_aliases is None:
        path_aliases = _public_path_map((value,))
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProofBundleError(f"{description} has a non-string key")
            if any(raw_value in key for raw_value in aliases):
                raise ProofBundleError(
                    f"{description} has an identifier in a structured key"
                )
            if _has_absolute_path(key):
                raise ProofBundleError(
                    f"{description} has an absolute host path in a structured key"
                )
            result[key] = _rewrite_structured_aliases(
                item,
                aliases,
                description=description,
                path_aliases=path_aliases,
                _path_field=key in _PUBLIC_PATH_KEYS,
                _path_text_field=key in _PUBLIC_PATH_TEXT_KEYS,
            )
        return result
    if isinstance(value, list):
        return [
            _rewrite_structured_aliases(
                item,
                aliases,
                description=description,
                path_aliases=path_aliases,
            )
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            _rewrite_structured_aliases(
                item,
                aliases,
                description=description,
                path_aliases=path_aliases,
            )
            for item in value
        )
    if isinstance(value, str):
        if _path_field and _is_absolute_path_value(value):
            _require_bounded_path(value, "absolute path value")
            public_path = path_aliases.get(value)
            if public_path is None:
                raise ProofBundleError(
                    f"{description} has an unmapped absolute host path"
                )
            return public_path
        if _path_text_field:
            value = _rewrite_path_text(
                value,
                path_aliases,
                description=description,
            )
        if _has_absolute_path(value):
            raise ProofBundleError(
                f"{description} has an absolute host path in free text "
                "or an unsupported structure"
            )
        public_value = aliases.get(value)
        if public_value is not None:
            return public_value
        if any(raw_value in value for raw_value in aliases):
            raise ProofBundleError(
                f"{description} has an embedded correlation identifier"
            )
    return value


def _sanitize_usage(value: Any) -> tuple[dict[str, Any], set[str]]:
    if not isinstance(value, Mapping):
        raise ProofBundleError("usage record is invalid")
    result: dict[str, Any] = {}
    raw_identifiers: set[str] = set()
    for key, item in value.items():
        normalized = str(key).lower()
        if normalized.endswith("mission_id") or normalized.endswith("session_id"):
            if not isinstance(item, str) or not item:
                raise ProofBundleError("usage identifier is invalid")
            _require_identifier_token(item, "usage identifier")
            raw_identifiers.add(item)
            continue
        result[str(key)] = item
    if result.get("status") not in {"available", "unavailable"}:
        raise ProofBundleError("usage status is invalid")
    return result, raw_identifiers


def _sanitize_correlation(
    value: dict[str, Any],
) -> tuple[FactoryMissionCorrelationWrapper, dict[str, str]]:
    try:
        wrapper = FactoryMissionCorrelationWrapper.model_validate(value)
    except (TypeError, ValueError) as error:
        raise ProofBundleError("correlation record is invalid") from error
    aliases = _public_alias_map(wrapper)
    record_value = wrapper.record.model_dump(mode="json")
    record_value["mission_id"] = aliases[wrapper.record.mission_id]
    for relation in record_value["sessions"]:
        relation["session_id"] = aliases[relation["session_id"]]
        assignment_id = relation.get("assignment_id")
        if assignment_id is not None:
            relation["assignment_id"] = aliases[assignment_id]
    record_value["record_digest"] = correlation_record_digest(record_value)

    result = wrapper.model_dump(mode="json")
    result["record"] = record_value
    result["role_assignments"] = {
        role_id: aliases[session_id]
        for role_id, session_id in wrapper.role_assignments.items()
    }
    result["record_digest"] = correlation_wrapper_digest(result)
    try:
        public_wrapper = FactoryMissionCorrelationWrapper.model_validate(result)
    except ValueError as error:
        raise ProofBundleError("public correlation record is invalid") from error
    return public_wrapper, aliases


def _replace_jsonl(path: Path, values: Sequence[Mapping[str, Any]]) -> None:
    payload = b"".join(canonical_json(value) + b"\n" for value in values)
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _stable_id(prefix: str, *values: str) -> str:
    digest = hashlib.sha256(
        "\0".join((prefix, *values)).encode("utf-8")
    ).hexdigest()
    return f"{prefix}-{digest}"


def _public_router_state(
    run_id: str,
    generation: int,
    interventions: Iterable[InterventionRecord],
) -> InterventionRouterState:
    value: dict[str, Any] = {
        "schema_version": "0.1",
        "provenance_status": "hook_authenticated",
        "redaction_status": "clean",
        "record_type": "intervention_router_state",
        "run_id": run_id,
        "generation": generation,
        "interventions": tuple(
            item.model_dump(mode="json")
            for item in sorted(
                interventions,
                key=lambda item: item.intervention_id,
            )
        ),
    }
    value["record_digest"] = _record_digest(value)
    return InterventionRouterState.model_validate(value)


def _rewrite_router_delta(
    delta: InterventionRouterDelta,
    *,
    original_state: InterventionRouterState,
    public_state: InterventionRouterState,
    aliases: Mapping[str, str],
    path_aliases: Mapping[str, str],
) -> tuple[
    InterventionRouterDelta,
    InterventionRouterState,
    InterventionRouterState,
]:
    try:
        original_result = delta.apply(original_state)
    except ValueError as error:
        raise ProofBundleError("router delta source chain diverges") from error
    public_upserts: list[InterventionRecord] = []
    for item in delta.upserts:
        item_value = _rewrite_structured_aliases(
            item.model_dump(mode="json"),
            aliases,
            description="intervention record",
            path_aliases=path_aliases,
        )
        item_value["record_digest"] = _record_digest(item_value)
        try:
            public_upserts.append(InterventionRecord.model_validate(item_value))
        except ValueError as error:
            raise ProofBundleError("public intervention record is invalid") from error
    records = {
        item.intervention_id: item for item in public_state.interventions
    }
    records.update({item.intervention_id: item for item in public_upserts})
    public_result = _public_router_state(
        delta.run_id,
        delta.generation,
        records.values(),
    )
    delta_value = delta.model_dump(mode="json")
    delta_value.update(
        {
            "base_digest": public_state.record_digest,
            "upserts": tuple(
                item.model_dump(mode="json")
                for item in sorted(
                    public_upserts,
                    key=lambda item: item.intervention_id,
                )
            ),
            "result_digest": public_result.record_digest,
        }
    )
    delta_value["record_digest"] = _record_digest(delta_value)
    try:
        public_delta = InterventionRouterDelta.model_validate(delta_value)
        applied = public_delta.apply(public_state)
    except ValueError as error:
        raise ProofBundleError("public router delta is invalid") from error
    if applied != public_result:
        raise ProofBundleError("public router delta result differs")
    return public_delta, original_result, public_result


def _rewrite_delivery_state(
    value: Mapping[str, Any],
    *,
    run_id: str,
    aliases: Mapping[str, str],
    path_aliases: Mapping[str, str],
) -> dict[str, Any]:
    try:
        state = DeliverySelectorState.from_record(value, run_id=run_id)
        public_state = DeliverySelectorState(
            last_updates=tuple(
                sorted(
                    (
                        _rewrite_structured_aliases(
                            session,
                            aliases,
                            description="delivery selector state",
                            path_aliases=path_aliases,
                        ),
                        update,
                    )
                    for session, update in state.last_updates
                )
            ),
            cooldown_remaining=tuple(
                sorted(
                    (
                        _rewrite_structured_aliases(
                            session,
                            aliases,
                            description="delivery selector state",
                            path_aliases=path_aliases,
                        ),
                        remaining,
                    )
                    for session, remaining in state.cooldown_remaining
                )
            ),
            delivered_severity=tuple(
                sorted(
                    (
                        _rewrite_structured_aliases(
                            session,
                            aliases,
                            description="delivery selector state",
                            path_aliases=path_aliases,
                        ),
                        _rewrite_structured_aliases(
                            dedup_key,
                            aliases,
                            description="delivery selector state",
                            path_aliases=path_aliases,
                        ),
                        severity,
                    )
                    for session, dedup_key, severity
                    in state.delivered_severity
                )
            ),
        )
    except (TypeError, ValueError) as error:
        raise ProofBundleError("delivery selector state is invalid") from error
    return public_state.to_record(run_id=run_id)


def _rewrite_review_state(
    value: Mapping[str, Any] | None,
    *,
    run_id: str,
    aliases: Mapping[str, str],
    path_aliases: Mapping[str, str],
    original_router: InterventionRouterState,
    public_router: InterventionRouterState,
) -> tuple[
    dict[str, Any] | None,
    InterventionRouterState,
    InterventionRouterState,
    tuple[InterventionRouterDelta, InterventionRouterDelta] | None,
]:
    if value is None:
        return None, original_router, public_router, None

    def rewrite_component(
        name: str,
        component: Mapping[str, Any],
    ) -> tuple[
        dict[str, Any],
        tuple[InterventionRouterDelta, InterventionRouterDelta] | None,
    ]:
        nonlocal original_router, public_router
        if component.get("record_type") != name:
            raise ProofBundleError("response review component name differs")
        if name == "delivery_selector_state":
            return (
                _rewrite_delivery_state(
                    component,
                    run_id=run_id,
                    aliases=aliases,
                    path_aliases=path_aliases,
                ),
                None,
            )
        if name != "intervention_router_delta":
            raise ProofBundleError("response review component is unknown")
        try:
            original_delta = InterventionRouterDelta.model_validate(component)
        except ValueError as error:
            raise ProofBundleError("response router delta is invalid") from error
        public_delta, original_router, public_router = _rewrite_router_delta(
            original_delta,
            original_state=original_router,
            public_state=public_router,
            aliases=aliases,
            path_aliases=path_aliases,
        )
        return (
            public_delta.model_dump(mode="json"),
            (original_delta, public_delta),
        )

    if value.get("record_type") == "response_review_state":
        expected = {
            "schema_version",
            "record_type",
            "run_id",
            "components",
        }
        components = value.get("components")
        if (
            set(value) != expected
            or value.get("schema_version") != "0.1"
            or value.get("run_id") != run_id
            or not isinstance(components, Mapping)
            or tuple(components) != tuple(sorted(components))
        ):
            raise ProofBundleError("response review state is invalid")
        public_components: dict[str, Any] = {}
        delta_pair = None
        for name, component in components.items():
            if not isinstance(name, str) or not isinstance(component, Mapping):
                raise ProofBundleError("response review component is invalid")
            public_component, candidate = rewrite_component(name, component)
            if candidate is not None:
                if delta_pair is not None:
                    raise ProofBundleError("response repeats a router delta")
                delta_pair = candidate
            public_components[name] = public_component
        return (
            {
                "schema_version": "0.1",
                "record_type": "response_review_state",
                "run_id": run_id,
                "components": dict(sorted(public_components.items())),
            },
            original_router,
            public_router,
            delta_pair,
        )
    name = value.get("record_type")
    if not isinstance(name, str):
        raise ProofBundleError("response review state is invalid")
    public_component, delta_pair = rewrite_component(name, value)
    return (
        public_component,
        original_router,
        public_router,
        delta_pair,
    )


def _rewrite_event_ledger(
    path: Path,
    *,
    run_id: str,
    aliases: Mapping[str, str],
    path_aliases: Mapping[str, str],
) -> tuple[
    tuple[HookExchangeRecord, ...],
    tuple[HookExchangeRecord, ...],
    dict[int, tuple[InterventionRouterDelta, InterventionRouterDelta]],
    dict[str, str],
]:
    payload = _read_regular(path, "staged event ledger")
    try:
        original_exchanges = load_exchanges_bytes(payload)
    except (GraphError, ValueError) as error:
        raise ProofBundleError("staged event ledger is invalid") from error
    response_bodies: dict[int, Mapping[str, Any]] = {}
    path_sources: list[Any] = []
    for exchange in original_exchanges:
        response_value = exchange.response.model_dump(mode="json")
        try:
            response_body_value = json.loads(response_value["response_body"])
        except (TypeError, json.JSONDecodeError) as error:
            raise ProofBundleError("event response body is invalid") from error
        if not isinstance(response_body_value, Mapping):
            raise ProofBundleError("event response body is invalid")
        response_bodies[exchange.ledger_sequence] = response_body_value
        path_sources.extend(
            (exchange.model_dump(mode="json"), response_body_value)
        )
    path_aliases = _merge_public_path_maps(
        path_aliases,
        _public_path_map(path_sources),
    )
    original_router = InterventionRouterState.empty(run_id)
    public_router = InterventionRouterState.empty(run_id)
    public_exchanges: list[HookExchangeRecord] = []
    delta_pairs: dict[
        int,
        tuple[InterventionRouterDelta, InterventionRouterDelta],
    ] = {}
    preserved_envelope_fields = (
        "source_fingerprint",
        "transcript_alias",
        "cwd_alias",
        "message_digest",
    )
    for exchange in original_exchanges:
        envelope_value = exchange.envelope.model_dump(mode="json")
        public_envelope_value = _rewrite_structured_aliases(
            envelope_value,
            aliases,
            description="event envelope",
            path_aliases=path_aliases,
        )
        if any(
            public_envelope_value[name] != envelope_value[name]
            for name in preserved_envelope_fields
        ):
            raise ProofBundleError("event source evidence contains an identifier")
        try:
            public_envelope = HookEnvelope.model_validate(public_envelope_value)
        except ValueError as error:
            raise ProofBundleError("public event envelope is invalid") from error

        response_value = exchange.response.model_dump(mode="json")
        response_body_value = response_bodies[exchange.ledger_sequence]
        public_body_value = _rewrite_structured_aliases(
            response_body_value,
            aliases,
            description="event response body",
            path_aliases=path_aliases,
        )
        (
            public_review_state,
            original_router,
            public_router,
            delta_pair,
        ) = _rewrite_review_state(
            exchange.response.review_state,
            run_id=run_id,
            aliases=aliases,
            path_aliases=path_aliases,
            original_router=original_router,
            public_router=public_router,
        )
        if delta_pair is not None:
            delta_pairs[exchange.ledger_sequence] = delta_pair
        public_response_value = {
            name: _rewrite_structured_aliases(
                item,
                aliases,
                description="event response",
                path_aliases=path_aliases,
            )
            for name, item in response_value.items()
            if name
            not in {
                "request_digest",
                "response_body",
                "response_digest",
                "response_id",
                "review_state",
            }
        }
        request_digest = hook_envelope_digest(public_envelope)
        response_body = canonical_json(public_body_value).decode("utf-8")
        public_response_value.update(
            {
                "request_digest": request_digest,
                "response_body": response_body,
                "response_id": _stable_id(
                    "response",
                    run_id,
                    public_envelope.event_id,
                    request_digest,
                ),
                "review_state": public_review_state,
            }
        )
        public_response_value["response_digest"] = hook_response_digest(
            response_body=response_body,
            guidance_ids=tuple(public_response_value["guidance_ids"]),
            transition_ids=tuple(public_response_value["transition_ids"]),
            review_state=public_review_state,
        )
        try:
            public_response = HookResponseRecord.model_validate(
                public_response_value
            )
        except ValueError as error:
            raise ProofBundleError("public event response is invalid") from error
        public_exchange_value = {
            name: _rewrite_structured_aliases(
                item,
                aliases,
                description="event exchange",
                path_aliases=path_aliases,
            )
            for name, item in exchange.model_dump(mode="json").items()
            if name not in {"envelope", "exchange_id", "response"}
        }
        public_exchange_value.update(
            {
                "envelope": public_envelope.model_dump(mode="json"),
                "exchange_id": _stable_id(
                    "exchange",
                    run_id,
                    public_envelope.event_id,
                    request_digest,
                ),
                "response": public_response.model_dump(mode="json"),
            }
        )
        try:
            public_exchanges.append(
                HookExchangeRecord.model_validate(public_exchange_value)
            )
        except ValueError as error:
            raise ProofBundleError("public event exchange is invalid") from error
    public_values = tuple(
        exchange.model_dump(mode="json") for exchange in public_exchanges
    )
    _replace_jsonl(path, public_values)
    try:
        rebuilt = load_exchanges_bytes(
            b"".join(canonical_json(value) + b"\n" for value in public_values)
        )
        DeliverySelector.from_exchanges(rebuilt, run_id=run_id)
    except (GraphError, ValueError) as error:
        raise ProofBundleError("public event ledger replay failed") from error
    return original_exchanges, rebuilt, delta_pairs, path_aliases


def _public_mission_relations(
    wrapper: FactoryMissionCorrelationWrapper,
) -> dict[str, MissionRelation]:
    relations: dict[str, MissionRelation] = {}
    for item in wrapper.record.sessions:
        if item.disposition != "mission_role":
            continue
        if (
            item.role_id is None
            or item.assignment_id is None
        ):
            raise ProofBundleError("public Mission relation is incomplete")
        relation = MissionRelation(
            session_alias=item.session_id,
            mission_id=wrapper.mission_id,
            role_id=item.role_id,
            assignment_id=item.assignment_id,
            source_digest=item.source_digest,
            corroborating_role_ids=item.corroborating_role_ids,
            relation_kind=item.relation_kind,
        )
        relations[relation.session_alias] = relation
    return relations


def _journal_draft(record, value: Mapping[str, Any]):
    material = dict(value)
    material["record_digest"] = _record_digest(material)
    try:
        return type(record).model_validate(material)
    except ValueError as error:
        raise ProofBundleError("public review journal record is invalid") from error


def _load_review_records(
    path: Path,
    *,
    run_id: str,
) -> tuple[Any, ...]:
    payload = _read_regular(path, "staged review journal")
    try:
        return load_journal_records(payload, run_id=run_id)
    except ReviewJournalCorruptionError as error:
        raise ProofBundleError("staged review journal is invalid") from error


def _rewrite_review_journal(
    path: Path,
    *,
    run_id: str,
    aliases: Mapping[str, str],
    path_aliases: Mapping[str, str],
    original_records: tuple[Any, ...],
    public_correlation: FactoryMissionCorrelationWrapper,
    original_exchanges: tuple[HookExchangeRecord, ...],
    public_exchanges: tuple[HookExchangeRecord, ...],
    event_delta_pairs: Mapping[
        int,
        tuple[InterventionRouterDelta, InterventionRouterDelta],
    ],
) -> tuple[Any, ...]:
    original_by_sequence = {
        exchange.ledger_sequence: exchange for exchange in original_exchanges
    }
    public_by_sequence = {
        exchange.ledger_sequence: exchange for exchange in public_exchanges
    }
    original_graph = MissionGraph(run_id)
    public_graph = MissionGraph(run_id)
    original_router = InterventionRouterState.empty(run_id)
    public_router = InterventionRouterState.empty(run_id)
    public_relations = _public_mission_relations(public_correlation)
    seen_relations: dict[str, MissionRelation] = {}
    drafts: list[tuple[Any, dict[str, Any]]] = []

    try:
        for record in original_records:
            value = _rewrite_structured_aliases(
                record.model_dump(mode="json"),
                aliases,
                description="review journal record",
                path_aliases=path_aliases,
            )
            if (
                isinstance(record, ProbeOutcomeRecord)
                and record.assessment is not None
                and value["assessment"]
                != record.assessment.model_dump(mode="json")
            ):
                raise ProofBundleError(
                    "signed probe evidence contains a correlation identifier"
                )
            ledger_sequence = getattr(record, "ledger_sequence", None)
            event_id = getattr(record, "event_id", None)
            original_exchange = None
            public_exchange = None
            if ledger_sequence is not None or event_id is not None:
                original_exchange = original_by_sequence.get(ledger_sequence)
                public_exchange = public_by_sequence.get(ledger_sequence)
                if (
                    original_exchange is None
                    or public_exchange is None
                    or original_exchange.envelope.event_id != event_id
                ):
                    raise ProofBundleError(
                        "review journal event binding differs"
                    )
                value["event_id"] = public_exchange.envelope.event_id

            if isinstance(
                record,
                (InterventionLineageRecord, OutageReconciliationRecord),
            ):
                public_delta, original_router, public_router = (
                    _rewrite_router_delta(
                        record.delta,
                        original_state=original_router,
                        public_state=public_router,
                        aliases=aliases,
                        path_aliases=path_aliases,
                    )
                )
                value["delta"] = public_delta.model_dump(mode="json")
                if isinstance(record, InterventionLineageRecord):
                    assert original_exchange is not None
                    assert public_exchange is not None
                    event_pair = event_delta_pairs.get(record.ledger_sequence)
                    if (
                        event_pair is None
                        or event_pair[0] != record.delta
                        or event_pair[1] != public_delta
                        or record.response_digest
                        != original_exchange.response.response_digest
                    ):
                        raise ProofBundleError(
                            "review router lineage binding differs"
                        )
                    value["response_digest"] = (
                        public_exchange.response.response_digest
                    )

            if isinstance(record, ExchangeProjectionRecord):
                assert original_exchange is not None
                assert public_exchange is not None
                if (
                    record.exchange_id != original_exchange.exchange_id
                    or record.response_digest
                    != original_exchange.response.response_digest
                ):
                    raise ProofBundleError(
                        "review exchange projection binding differs"
                    )
                value.update(
                    {
                        "exchange_id": public_exchange.exchange_id,
                        "response_digest": (
                            public_exchange.response.response_digest
                        ),
                    }
                )

            if isinstance(record, RoleDecisionRecord):
                relation = public_relations.get(value["session_alias"])
                if relation is not None:
                    seen_relations.setdefault(relation.session_alias, relation)
                value["relations_digest"] = FrozenMissionRelations(
                    public_correlation.mission_id,
                    tuple(seen_relations.values()),
                ).digest

            if isinstance(record, FindingSnapshotRecord):
                if record.graph_digest != original_graph.digest():
                    raise ProofBundleError(
                        "review source graph digest differs"
                    )
                value["graph_digest"] = public_graph.digest()

            draft = _journal_draft(record, value)
            if isinstance(record, ExchangeProjectionRecord):
                assert original_exchange is not None
                assert public_exchange is not None
                original_graph.add_exchange(original_exchange)
                public_graph.add_exchange(public_exchange)
            elif isinstance(record, RoleDecisionRecord):
                original_graph.add_role_decision(record.to_decision())
                public_graph.add_role_decision(draft.to_decision())
            elif isinstance(record, TranscriptBatchRecord):
                for evidence in record.evidence:
                    original_graph.add_evidence(evidence)
                for evidence in draft.evidence:
                    public_graph.add_evidence(evidence)
            elif isinstance(record, ExtractionOutcomeRecord):
                for evidence in record.derived_evidence:
                    original_graph.add_evidence(evidence)
                for claim in record.claims:
                    original_graph.add_claim(claim)
                for evidence in draft.derived_evidence:
                    public_graph.add_evidence(evidence)
                for claim in draft.claims:
                    public_graph.add_claim(claim)
            drafts.append((record, draft.model_dump(mode="json")))
    except ProofBundleError:
        raise
    except (GraphError, TypeError, ValueError) as error:
        raise ProofBundleError("review journal rewrite failed") from error

    public_values: list[dict[str, Any]] = []
    previous_digest = ZERO_DIGEST
    for original_record, value in drafts:
        value["previous_digest"] = previous_digest
        final_record = _journal_draft(original_record, value)
        public_value = final_record.model_dump(mode="json")
        public_values.append(public_value)
        previous_digest = final_record.record_digest
    _replace_jsonl(path, public_values)
    public_payload = b"".join(
        canonical_json(value) + b"\n" for value in public_values
    )
    try:
        public_records = load_journal_records(public_payload, run_id=run_id)
        _validate_public_derivation_bindings(
            run_id=run_id,
            correlation=public_correlation,
            exchanges=public_exchanges,
            review_records=public_records,
        )
        return public_records
    except ReviewJournalCorruptionError as error:
        raise ProofBundleError("public review journal replay failed") from error


def _response_router_delta(
    exchange: HookExchangeRecord,
) -> InterventionRouterDelta | None:
    review_state = exchange.response.review_state
    if review_state is None:
        return None
    if review_state.get("record_type") == "response_review_state":
        expected = {
            "schema_version",
            "record_type",
            "run_id",
            "components",
        }
        components = review_state.get("components")
        if (
            set(review_state) != expected
            or review_state.get("schema_version") != "0.1"
            or review_state.get("run_id") != exchange.envelope.run_id
            or not isinstance(components, Mapping)
            or tuple(components) != tuple(sorted(components))
            or set(components)
            - {"delivery_selector_state", "intervention_router_delta"}
        ):
            raise ProofBundleError("public response review state is invalid")
        component = components.get("intervention_router_delta")
    else:
        if review_state.get("record_type") not in {
            "delivery_selector_state",
            "intervention_router_delta",
        }:
            raise ProofBundleError("public response review state is unknown")
        component = (
            review_state
            if review_state.get("record_type") == "intervention_router_delta"
            else None
        )
    if component is None:
        return None
    try:
        return InterventionRouterDelta.model_validate(component)
    except ValueError as error:
        raise ProofBundleError("public response router delta is invalid") from error


def _validate_public_derivation_bindings(
    *,
    run_id: str,
    correlation: FactoryMissionCorrelationWrapper,
    exchanges: Sequence[HookExchangeRecord],
    review_records: Sequence[Any],
) -> None:
    exchange_by_sequence = {
        exchange.ledger_sequence: exchange for exchange in exchanges
    }
    event_deltas: dict[int, InterventionRouterDelta] = {}
    event_router = InterventionRouterState.empty(run_id)
    try:
        DeliverySelector.from_exchanges(exchanges, run_id=run_id)
        for exchange in exchanges:
            request_digest = exchange.response.request_digest
            if (
                exchange.response.response_id
                != _stable_id(
                    "response",
                    run_id,
                    exchange.envelope.event_id,
                    request_digest,
                )
                or exchange.exchange_id
                != _stable_id(
                    "exchange",
                    run_id,
                    exchange.envelope.event_id,
                    request_digest,
                )
            ):
                raise ProofBundleError("public exchange identity differs")
            delta = _response_router_delta(exchange)
            if delta is not None:
                event_router = delta.apply(event_router)
                event_deltas[exchange.ledger_sequence] = delta

        graph = MissionGraph(run_id)
        journal_router = InterventionRouterState.empty(run_id)
        relations = _public_mission_relations(correlation)
        seen_relations: dict[str, MissionRelation] = {}
        projected_sequences: list[int] = []
        for record in review_records:
            ledger_sequence = getattr(record, "ledger_sequence", None)
            event_id = getattr(record, "event_id", None)
            exchange = None
            if ledger_sequence is not None or event_id is not None:
                exchange = exchange_by_sequence.get(ledger_sequence)
                if (
                    exchange is None
                    or exchange.envelope.event_id != event_id
                ):
                    raise ProofBundleError(
                        "public review event binding differs"
                    )
            if isinstance(record, ExchangeProjectionRecord):
                assert exchange is not None
                if (
                    record.exchange_id != exchange.exchange_id
                    or record.response_digest
                    != exchange.response.response_digest
                ):
                    raise ProofBundleError(
                        "public exchange projection binding differs"
                    )
                projected_sequences.append(record.ledger_sequence)
                graph.add_exchange(exchange)
            elif isinstance(record, RoleDecisionRecord):
                relation = relations.get(record.session_alias)
                if relation is not None:
                    seen_relations.setdefault(relation.session_alias, relation)
                expected_digest = FrozenMissionRelations(
                    correlation.mission_id,
                    tuple(seen_relations.values()),
                ).digest
                if record.relations_digest != expected_digest:
                    raise ProofBundleError(
                        "public role relation digest differs"
                    )
                graph.add_role_decision(record.to_decision())
            elif isinstance(record, TranscriptBatchRecord):
                for evidence in record.evidence:
                    graph.add_evidence(evidence)
            elif isinstance(record, ExtractionOutcomeRecord):
                for evidence in record.derived_evidence:
                    graph.add_evidence(evidence)
                for claim in record.claims:
                    graph.add_claim(claim)
            elif isinstance(record, FindingSnapshotRecord):
                if record.graph_digest != graph.digest():
                    raise ProofBundleError(
                        "public finding graph digest differs"
                    )
            if isinstance(
                record,
                (InterventionLineageRecord, OutageReconciliationRecord),
            ):
                journal_router = record.delta.apply(journal_router)
                if isinstance(record, InterventionLineageRecord):
                    assert exchange is not None
                    if (
                        event_deltas.get(record.ledger_sequence)
                        != record.delta
                        or record.response_digest
                        != exchange.response.response_digest
                    ):
                        raise ProofBundleError(
                            "public intervention lineage differs"
                        )
        if projected_sequences != list(
            range(1, len(projected_sequences) + 1)
        ):
            raise ProofBundleError(
                "public exchange projections are not contiguous"
            )
    except ProofBundleError:
        raise
    except (GraphError, TypeError, ValueError) as error:
        raise ProofBundleError(
            "public derivation binding validation failed"
        ) from error


def _sanitize_staged_pair(
    *,
    baseline_record: Path,
    baseline_cleanup_attestation: Path,
    shadow_run_dir: Path,
    shadow_cleanup_attestation: Path,
) -> set[str]:
    correlation_path = shadow_run_dir / "correlation.json"
    correlation_value = _load_canonical_object(
        correlation_path,
        "staged correlation record",
    )
    public_correlation, aliases = _sanitize_correlation(correlation_value)
    raw_identifiers = set(aliases)

    baseline_value = _load_canonical_object(
        baseline_record,
        "staged baseline record",
    )
    prior_baseline_digest = baseline_value.get("record_digest")
    if not isinstance(prior_baseline_digest, str):
        raise ProofBundleError("staged baseline record digest is invalid")
    baseline_evaluator = baseline_value.get("evaluator_outcome")
    baseline_usage, baseline_identifiers = _sanitize_usage(
        baseline_value.get("usage_data")
    )
    raw_identifiers.update(baseline_identifiers)
    baseline_value["usage_data"] = baseline_usage
    baseline_value = _rewrite_structured_aliases(
        baseline_value,
        aliases,
        description="staged baseline record",
    )
    if baseline_value.get("evaluator_outcome") != baseline_evaluator:
        raise ProofBundleError(
            "baseline evaluator evidence contains a correlation identifier"
        )
    baseline_value["record_digest"] = _record_digest(baseline_value)
    baseline = BaselineRunRecord.model_validate(baseline_value)
    _replace_canonical(baseline_record, baseline.model_dump(mode="json"))
    _replace_canonical(
        correlation_path,
        public_correlation.model_dump(mode="json"),
    )
    journal_path = shadow_run_dir / "review.jsonl"
    original_review_records = _load_review_records(
        journal_path,
        run_id=shadow_run_dir.name,
    )
    journal_path_aliases = _public_path_map(
        record.model_dump(mode="json") for record in original_review_records
    )

    events_path = shadow_run_dir / "events.jsonl"
    (
        original_exchanges,
        public_exchanges,
        event_delta_pairs,
        event_path_aliases,
    ) = _rewrite_event_ledger(
        events_path,
        run_id=shadow_run_dir.name,
        aliases=aliases,
        path_aliases=journal_path_aliases,
    )
    _rewrite_review_journal(
        journal_path,
        run_id=shadow_run_dir.name,
        aliases=aliases,
        path_aliases=event_path_aliases,
        original_records=original_review_records,
        public_correlation=public_correlation,
        original_exchanges=original_exchanges,
        public_exchanges=public_exchanges,
        event_delta_pairs=event_delta_pairs,
    )

    preliminary_path = shadow_run_dir / "pre-evaluation-run.json"
    preliminary_value = _load_canonical_object(
        preliminary_path,
        "staged pre-evaluation run record",
    )
    preliminary_usage, preliminary_identifiers = _sanitize_usage(
        preliminary_value.get("usage_data")
    )
    raw_identifiers.update(preliminary_identifiers)
    preliminary_value.update(
        {
            "usage_data": preliminary_usage,
            "baseline_record_digest": baseline.record_digest,
            "mission_relation_record_digest": (
                public_correlation.record_digest
            ),
        }
    )
    preliminary_value = _rewrite_structured_aliases(
        preliminary_value,
        aliases,
        description="staged pre-evaluation run record",
    )
    preliminary_value["record_digest"] = _record_digest(preliminary_value)
    preliminary = RunRecord.model_validate(preliminary_value)
    _replace_canonical(preliminary_path, preliminary.model_dump(mode="json"))

    event_payload = _read_regular(events_path, "public event ledger")
    journal_payload = _read_regular(journal_path, "public review journal")
    pre_evaluation_path = shadow_run_dir / "pre-evaluation.json"
    pre_evaluation_value = _load_canonical_object(
        pre_evaluation_path,
        "staged pre-evaluation record",
    )
    pre_evaluation_value.update(
        {
            "pre_evaluation_run_record_digest": preliminary.record_digest,
            "event_ledger_digest": hashlib.sha256(event_payload).hexdigest(),
            "event_ledger_record_count": len(public_exchanges),
            "review_journal_digest": (
                hashlib.sha256(journal_payload).hexdigest()
            ),
        }
    )
    pre_evaluation_value = _rewrite_structured_aliases(
        pre_evaluation_value,
        aliases,
        description="staged pre-evaluation record",
    )
    pre_evaluation_value["record_digest"] = _record_digest(
        pre_evaluation_value
    )
    pre_evaluation = PreEvaluationRecord.model_validate(pre_evaluation_value)
    _replace_canonical(
        pre_evaluation_path,
        pre_evaluation.model_dump(mode="json"),
    )

    run_path = shadow_run_dir / "run.json"
    run_value = _load_canonical_object(run_path, "staged Shadow run record")
    prior_run_digest = run_value.get("record_digest")
    if not isinstance(prior_run_digest, str):
        raise ProofBundleError("staged Shadow run record digest is invalid")
    evaluator_outcome = run_value.get("evaluator_outcome")
    run_usage, run_identifiers = _sanitize_usage(run_value.get("usage_data"))
    raw_identifiers.update(run_identifiers)
    run_value.update(
        {
            "usage_data": run_usage,
            "baseline_record_digest": baseline.record_digest,
            "mission_relation_record_digest": (
                public_correlation.record_digest
            ),
            "pre_evaluation_record_digest": pre_evaluation.record_digest,
        }
    )
    run_value = _rewrite_structured_aliases(
        run_value,
        aliases,
        description="staged Shadow run record",
    )
    if run_value.get("evaluator_outcome") != evaluator_outcome:
        raise ProofBundleError(
            "Shadow evaluator evidence contains a correlation identifier"
        )
    run_value["record_digest"] = _record_digest(run_value)
    run = RunRecord.model_validate(run_value)
    _replace_canonical(run_path, run.model_dump(mode="json"))
    _rewrite_cleanup_binding(
        baseline_cleanup_attestation,
        "staged baseline",
        subject="baseline",
        prior_source_digest=prior_baseline_digest,
        source_record_digest=baseline.record_digest,
    )
    _rewrite_cleanup_binding(
        shadow_cleanup_attestation,
        "staged Shadow",
        subject="shadow",
        prior_source_digest=prior_run_digest,
        source_record_digest=run.record_digest,
    )
    return raw_identifiers


def _pair_member_paths(pair_id: str, run_id: str) -> dict[str, Any]:
    root = f"pairs/{pair_id}"
    shadow_root = f"{root}/shadow/{run_id}"
    return {
        "pair_id": pair_id,
        "baseline_record": f"{root}/baseline/record.json",
        "baseline_archive": f"{root}/baseline/final-source/final-source.tar",
        "baseline_manifest": (
            f"{root}/baseline/final-source/final-source-manifest.json"
        ),
        "baseline_evaluation": f"{root}/baseline/evaluation.json",
        "baseline_cleanup_attestation": f"{root}/baseline/cleanup.json",
        "shadow_run_root": shadow_root,
        "shadow_run_record": f"{shadow_root}/run.json",
        "shadow_pre_evaluation_run": f"{shadow_root}/pre-evaluation-run.json",
        "shadow_pre_evaluation": f"{shadow_root}/pre-evaluation.json",
        "shadow_evaluation": f"{shadow_root}/evaluation.json",
        "correlation_record": f"{shadow_root}/correlation.json",
        "event_ledger": f"{shadow_root}/events.jsonl",
        "review_journal": f"{shadow_root}/review.jsonl",
        "shadow_archive": f"{shadow_root}/final-source/final-source.tar",
        "shadow_manifest": (
            f"{shadow_root}/final-source/final-source-manifest.json"
        ),
        "report_record": f"{shadow_root}/report.json",
        "shadow_cleanup_attestation": f"{root}/shadow/cleanup.json",
        "comparison_record": f"{root}/comparison.json",
    }


def _copy_pair_to_stage(
    pair: PairArtifacts,
    *,
    stage: Path,
    paths: Mapping[str, Any],
) -> set[str]:
    copies = (
        (pair.baseline_record, paths["baseline_record"], "baseline record"),
        (pair.baseline_archive, paths["baseline_archive"], "baseline source archive"),
        (pair.baseline_manifest, paths["baseline_manifest"], "baseline source manifest"),
        (pair.baseline_evaluation, paths["baseline_evaluation"], "baseline evaluator result"),
        (
            pair.baseline_cleanup_attestation,
            paths["baseline_cleanup_attestation"],
            "baseline cleanup attestation",
        ),
        (
            pair.shadow_cleanup_attestation,
            paths["shadow_cleanup_attestation"],
            "Shadow cleanup attestation",
        ),
    )
    for source, member_name, description in copies:
        _copy_regular(source, stage / member_name, description)

    shadow_run_dir = stage / paths["shadow_run_root"]
    for name in _SHADOW_INPUT_NAMES:
        _copy_regular(
            pair.shadow_run_dir / name,
            shadow_run_dir / name,
            f"Shadow {name}",
        )
    for source, name in (
        (pair.shadow_archive, "final-source.tar"),
        (pair.shadow_manifest, "final-source-manifest.json"),
    ):
        _copy_regular(
            source,
            shadow_run_dir / "final-source" / name,
            f"Shadow {name}",
        )

    raw_identifiers = _sanitize_staged_pair(
        baseline_record=stage / paths["baseline_record"],
        baseline_cleanup_attestation=stage / paths["baseline_cleanup_attestation"],
        shadow_run_dir=shadow_run_dir,
        shadow_cleanup_attestation=stage / paths["shadow_cleanup_attestation"],
    )
    report = _rebuilt_report(
        shadow_run_dir,
        stage / paths["baseline_record"],
    )
    _write_canonical(stage / paths["report_record"], report.model_dump(mode="json"))
    comparison = _comparison_value(
        baseline_record=stage / paths["baseline_record"],
        shadow_run_dir=shadow_run_dir,
        baseline_archive=stage / paths["baseline_archive"],
        baseline_manifest=stage / paths["baseline_manifest"],
        shadow_archive=stage / paths["shadow_archive"],
        shadow_manifest=stage / paths["shadow_manifest"],
    )
    _write_canonical(stage / paths["comparison_record"], comparison)
    return raw_identifiers


def _stage_files(stage: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in stage.rglob("*") if path.is_file()))


def _scan_stage(
    stage: Path,
    files: Sequence[Path],
    raw_identifiers: set[str],
) -> tuple[frozenset[str], list[dict[str, Any]]]:
    identifier_hashes = frozenset(
        hashlib.sha256(value.encode("utf-8")).hexdigest()
        for value in raw_identifiers
    )
    raw_payloads = tuple(value.encode("utf-8") for value in raw_identifiers)
    members: list[dict[str, Any]] = []
    for path in files:
        name = path.relative_to(stage).as_posix()
        payload = _read_regular(path, f"bundle member {name}")
        _scan_payload(
            name,
            payload,
            excluded_identifier_hashes=identifier_hashes,
        )
        if any(value and value in payload for value in raw_payloads):
            raise ProofBundleError(f"raw identifier in bundle member: {name}")
        _scan_json_payload(name, payload)
        if name.endswith("final-source.tar"):
            _scan_source_archive(
                name,
                path,
                excluded_identifier_hashes=identifier_hashes,
            )
        members.append(
            {
                "path": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    return identifier_hashes, members


def _manifest(
    pairs: list[dict[str, Any]],
    hashes: frozenset[str],
    members: list[dict[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "0.1",
        "pairs": pairs,
        "members": members,
        "exclusions": {
            "absolute_host_paths": "excluded",
            "approvals": "excluded",
            "credentials": "excluded",
            "private_path_patterns": "excluded",
            "raw_mission_session_and_assignment_identifiers": "excluded",
        },
        "excluded_identifier_hashes": sorted(hashes),
    }
    value["record_digest"] = _record_digest(value)
    return value


def _write_bundle_tar(stage: Path, output: Path, files: Sequence[Path]) -> None:
    with tarfile.open(output, mode="w:") as archive:
        for path in sorted(files):
            name = path.relative_to(stage).as_posix()
            payload = _read_regular(path, f"bundle member {name}")
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o600
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            archive.addfile(info, io.BytesIO(payload))


def build_bundle(
    *,
    pairs: Sequence[PairArtifacts],
    output_path: Path,
) -> dict[str, Any]:
    values = tuple(pairs)
    if not values:
        raise ProofBundleError("bundle has no pairs")
    if len(values) > 8:
        raise ProofBundleError("bundle pair count exceeds its bound")
    pair_ids = [pair.pair_id for pair in values]
    if len(pair_ids) != len(set(pair_ids)):
        raise ProofBundleError("bundle pair ids are not unique")
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    with tempfile.TemporaryDirectory(prefix="shadow-proof-stage-") as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir(mode=0o700)
        manifest_pairs: list[dict[str, Any]] = []
        raw_identifiers: set[str] = set()
        for pair in values:
            run = _validate_source_pair(pair)
            paths = _pair_member_paths(pair.pair_id, run.run_id)
            raw_identifiers.update(
                _copy_pair_to_stage(pair, stage=stage, paths=paths)
            )
            manifest_pairs.append(dict(paths))
        stage_files = _stage_files(stage)
        hashes, members = _scan_stage(stage, stage_files, raw_identifiers)
        manifest = _manifest(manifest_pairs, hashes, members)
        manifest_path = stage / "manifest.json"
        _write_canonical(manifest_path, manifest)
        _scan_payload(
            "manifest.json",
            _read_regular(manifest_path, "bundle manifest"),
        )
        bundle_files = (*stage_files, manifest_path)

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output_path.name}.",
            dir=output_path.parent,
        )
        os.close(descriptor)
        temporary_output = Path(temporary_name)
        try:
            _write_bundle_tar(stage, temporary_output, bundle_files)
            os.chmod(temporary_output, 0o600)
            verify_bundle(temporary_output)
            try:
                os.link(temporary_output, output_path)
            except FileExistsError as error:
                raise ProofBundleError("bundle output already exists") from error
            except OSError as error:
                raise ProofBundleError("bundle output cannot be published") from error
        finally:
            temporary_output.unlink(missing_ok=True)
    return manifest


def _safe_member_name(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise ProofBundleError("bundle member name is invalid")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ProofBundleError("bundle member path is unsafe")
    return path


def _extract_member(source, destination: Path, size: int) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    digest = hashlib.sha256()
    observed_size = 0
    try:
        with os.fdopen(descriptor, "wb") as handle:
            while observed_size < size:
                chunk = source.read(min(1 << 20, size - observed_size))
                if not chunk:
                    raise ProofBundleError(
                        f"bundle member size differs: {destination.name}"
                    )
                handle.write(chunk)
                digest.update(chunk)
                observed_size += len(chunk)
            if source.read(1):
                raise ProofBundleError(
                    f"bundle member size differs: {destination.name}"
                )
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return {"sha256": digest.hexdigest(), "size": observed_size}


def _extract_bundle(path: Path, root: Path) -> dict[str, dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProofBundleError("proof bundle is unavailable") from error
    observed: dict[str, dict[str, Any]] = {}
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProofBundleError("proof bundle is not a regular file")
        if metadata.st_size > _MAX_BUNDLE_BYTES:
            raise ProofBundleError("proof bundle exceeds its size bound")
        initial_size = metadata.st_size
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            with tarfile.open(fileobj=handle, mode="r:") as archive:
                total = 0
                member_count = 0
                previous_name: str | None = None
                for member in archive:
                    member_count += 1
                    if member_count > _MAX_MEMBERS:
                        raise ProofBundleError(
                            "bundle member count exceeds its bound"
                        )
                    if (
                        previous_name is not None
                        and member.name <= previous_name
                    ):
                        raise ProofBundleError(
                            "bundle members are not sorted and unique"
                        )
                    previous_name = member.name
                    relative = _safe_member_name(member.name)
                    if (
                        not member.isfile()
                        or member.linkname
                        or member.size > _MAX_MEMBER_BYTES
                        or stat.S_IMODE(member.mode) != 0o600
                        or member.uid != 0
                        or member.gid != 0
                        or member.mtime != 0
                    ):
                        raise ProofBundleError(
                            f"bundle member metadata is invalid: {member.name}"
                        )
                    total += member.size
                    if total > _MAX_BUNDLE_BYTES:
                        raise ProofBundleError(
                            "bundle contents exceed their size bound"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ProofBundleError(
                            f"bundle member is unreadable: {member.name}"
                        )
                    with extracted:
                        observed[member.name] = _extract_member(
                            extracted,
                            root.joinpath(*relative.parts),
                            member.size,
                        )
        final_size = os.fstat(descriptor).st_size
        if final_size != initial_size or final_size > _MAX_BUNDLE_BYTES:
            raise ProofBundleError("proof bundle changed during verification")
    except ProofBundleError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ProofBundleError("proof bundle is invalid") from error
    finally:
        os.close(descriptor)
    return observed


def _load_manifest(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProofBundleError("bundle manifest is invalid") from error
    if not isinstance(value, dict) or canonical_json(value) + b"\n" != payload:
        raise ProofBundleError("bundle manifest is not canonical")
    required = {
        "schema_version",
        "pairs",
        "members",
        "exclusions",
        "excluded_identifier_hashes",
        "record_digest",
    }
    if set(value) != required or value.get("schema_version") != "0.1":
        raise ProofBundleError("bundle manifest shape is invalid")
    if value.get("record_digest") != _record_digest(value):
        raise ProofBundleError("bundle manifest digest differs")
    return value


def _validate_member_manifest(
    observed: Mapping[str, Mapping[str, Any]],
    manifest: Mapping[str, Any],
) -> None:
    members = manifest.get("members")
    if not isinstance(members, list):
        raise ProofBundleError("bundle member manifest is invalid")
    names: list[str] = []
    for member in members:
        if not isinstance(member, Mapping) or set(member) != {"path", "sha256", "size"}:
            raise ProofBundleError("bundle member manifest is invalid")
        name = member["path"]
        digest = member["sha256"]
        size = member["size"]
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
            or type(size) is not int
            or size < 0
        ):
            raise ProofBundleError("bundle member manifest is invalid")
        _safe_member_name(name)
        names.append(name)
    if names != sorted(set(names)):
        raise ProofBundleError("bundle member manifest is not canonical")
    if set(observed) != {"manifest.json", *names}:
        raise ProofBundleError("bundle member set differs")
    for member in members:
        actual = observed[member["path"]]
        if actual["sha256"] != member["sha256"]:
            raise ProofBundleError(f"bundle member digest differs: {member['path']}")
        if actual["size"] != member["size"]:
            raise ProofBundleError(f"bundle member size differs: {member['path']}")


def _expected_pair_paths(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(_pair_member_paths("pair", "run"))
    if set(value) != required:
        raise ProofBundleError("bundle pair index is invalid")
    pair_id = value.get("pair_id")
    shadow_root = value.get("shadow_run_root")
    if not isinstance(pair_id, str) or not _PAIR_ID.fullmatch(pair_id):
        raise ProofBundleError("bundle pair id is invalid")
    if not isinstance(shadow_root, str):
        raise ProofBundleError("bundle Shadow root is invalid")
    root_path = _safe_member_name(shadow_root)
    if len(root_path.parts) != 4 or root_path.parts[:3] != ("pairs", pair_id, "shadow"):
        raise ProofBundleError("bundle Shadow root is invalid")
    run_id = root_path.parts[3]
    expected = _pair_member_paths(pair_id, run_id)
    if dict(value) != expected:
        raise ProofBundleError("bundle pair index differs")
    return expected



def _verify_pair(root: Path, paths: Mapping[str, Any]) -> None:
    baseline_path = root / paths["baseline_record"]
    baseline = _load_model(baseline_path, BaselineRunRecord, "bundled baseline record")
    baseline_evaluation = _load_model(
        root / paths["baseline_evaluation"],
        EvaluationRecord,
        "bundled baseline evaluator result",
    )
    if baseline_evaluation.model_dump(mode="json") != baseline.evaluator_outcome:
        raise ProofBundleError("bundled baseline evaluator binding differs")
    baseline_source = validate_source_archive(
        root / paths["baseline_archive"],
        root / paths["baseline_manifest"],
    )
    if (
        baseline.final_source_archive_digest != baseline_source.archive_digest
        or baseline_evaluation.archive_digest != baseline_source.archive_digest
        or baseline_evaluation.working_tree_digest
        != baseline_source.manifest.working_tree_digest
    ):
        raise ProofBundleError("bundled baseline source binding differs")

    shadow_run_dir = root / paths["shadow_run_root"]
    run = _load_model(
        root / paths["shadow_run_record"],
        RunRecord,
        "bundled Shadow run record",
    )
    if run.run_id != shadow_run_dir.name:
        raise ProofBundleError("bundled Shadow run identity differs")
    shadow_evaluation = _load_model(
        root / paths["shadow_evaluation"],
        EvaluationRecord,
        "bundled Shadow evaluator result",
    )
    if shadow_evaluation.model_dump(mode="json") != run.evaluator_outcome:
        raise ProofBundleError("bundled Shadow evaluator binding differs")
    shadow_source = validate_source_archive(
        root / paths["shadow_archive"],
        root / paths["shadow_manifest"],
    )
    if (
        run.final_source_archive_digest != shadow_source.archive_digest
        or run.final_source_manifest_digest != shadow_source.manifest_digest
        or run.final_source_working_tree_digest
        != shadow_source.manifest.working_tree_digest
        or shadow_evaluation.archive_digest != shadow_source.archive_digest
        or shadow_evaluation.working_tree_digest
        != shadow_source.manifest.working_tree_digest
    ):
        raise ProofBundleError("bundled Shadow source binding differs")
    correlation = _load_canonical_object(
        root / paths["correlation_record"],
        "bundled correlation record",
    )
    try:
        public_wrapper = FactoryMissionCorrelationWrapper.model_validate(correlation)
    except (TypeError, ValueError) as error:
        raise ProofBundleError("bundled correlation record is invalid") from error
    public_record = public_wrapper.record
    if (
        public_wrapper.mission_id != run.run_id
        or public_wrapper.source_digest != run.mission_relation_source_digest
        or public_wrapper.record_digest != run.mission_relation_record_digest
    ):
        raise ProofBundleError("bundled correlation wrapper binding differs")
    if not public_record.mission_id.startswith("public-mission-") or any(
        not relation.session_id.startswith("public-session-")
        or (
            relation.assignment_id is not None
            and not relation.assignment_id.startswith("public-assignment-")
        )
        for relation in public_record.sessions
    ):
        raise ProofBundleError("bundled correlation identifiers are not public aliases")
    try:
        public_exchanges = load_exchanges_bytes(
            _read_regular(
                root / paths["event_ledger"],
                "bundled event ledger",
            )
        )
        public_review_records = load_journal_records(
            _read_regular(
                root / paths["review_journal"],
                "bundled review journal",
            ),
            run_id=run.run_id,
        )
    except (GraphError, ReviewJournalCorruptionError, ValueError) as error:
        raise ProofBundleError("bundled derivation ledger is invalid") from error
    _validate_public_derivation_bindings(
        run_id=run.run_id,
        correlation=public_wrapper,
        exchanges=public_exchanges,
        review_records=public_review_records,
    )

    report = _rebuilt_report(shadow_run_dir, baseline_path)
    bundled_report = _load_model(
        root / paths["report_record"],
        ReportRecord,
        "bundled report record",
    )
    if not _reports_equal(bundled_report, report):
        raise ProofBundleError("bundled report differs from rebuild")
    comparison = _comparison_value(
        baseline_record=baseline_path,
        shadow_run_dir=shadow_run_dir,
        baseline_archive=root / paths["baseline_archive"],
        baseline_manifest=root / paths["baseline_manifest"],
        shadow_archive=root / paths["shadow_archive"],
        shadow_manifest=root / paths["shadow_manifest"],
    )
    bundled_comparison = _load_canonical_object(
        root / paths["comparison_record"],
        "bundled comparison record",
    )
    if bundled_comparison != comparison:
        raise ProofBundleError("bundled comparison differs from rebuild")
    _validate_cleanup(
        root / paths["baseline_cleanup_attestation"],
        "bundled baseline",
        subject="baseline",
        source_record_digest=baseline.record_digest,
    )
    _validate_cleanup(
        root / paths["shadow_cleanup_attestation"],
        "bundled Shadow",
        subject="shadow",
        source_record_digest=run.record_digest,
    )


def verify_bundle(bundle_path: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="shadow-proof-verify-") as temporary:
        root = Path(temporary)
        observed = _extract_bundle(bundle_path, root)
        if "manifest.json" not in observed:
            raise ProofBundleError("bundle manifest is missing")
        manifest = _load_manifest(
            _read_regular(root / "manifest.json", "bundle manifest")
        )
        _validate_member_manifest(observed, manifest)
        expected_exclusions = {
            "absolute_host_paths": "excluded",
            "approvals": "excluded",
            "credentials": "excluded",
            "private_path_patterns": "excluded",
            "raw_mission_session_and_assignment_identifiers": "excluded",
        }
        if manifest.get("exclusions") != expected_exclusions:
            raise ProofBundleError("bundle exclusion attestation differs")
        hashes = manifest.get("excluded_identifier_hashes")
        if (
            not isinstance(hashes, list)
            or hashes != sorted(set(hashes))
            or not all(
                isinstance(value, str) and _DIGEST.fullmatch(value)
                for value in hashes
            )
        ):
            raise ProofBundleError("bundle identifier exclusion set is invalid")
        hash_set = frozenset(hashes)

        pairs = manifest.get("pairs")
        if not isinstance(pairs, list) or not pairs:
            raise ProofBundleError("bundle pair index is empty")
        indexed_paths: set[str] = set()
        validated_pairs: list[dict[str, Any]] = []
        pair_ids: set[str] = set()
        for value in pairs:
            if not isinstance(value, Mapping):
                raise ProofBundleError("bundle pair index is invalid")
            paths = _expected_pair_paths(value)
            if paths["pair_id"] in pair_ids:
                raise ProofBundleError("bundle pair ids are not unique")
            pair_ids.add(paths["pair_id"])
            validated_pairs.append(paths)
            indexed_paths.update(
                item
                for key, item in paths.items()
                if key not in {"pair_id", "shadow_run_root"}
            )
        if indexed_paths != set(observed) - {"manifest.json"}:
            raise ProofBundleError("bundle allowlist differs")

        for name in observed:
            member_path = root.joinpath(*PurePosixPath(name).parts)
            payload = _read_regular(member_path, f"bundle member {name}")
            _scan_payload(
                name,
                payload,
                excluded_identifier_hashes=hash_set,
            )
            if name != "manifest.json":
                _scan_json_payload(name, payload)
        for paths in validated_pairs:
            _scan_source_archive(
                paths["baseline_archive"],
                root / paths["baseline_archive"],
                excluded_identifier_hashes=hash_set,
            )
            _scan_source_archive(
                paths["shadow_archive"],
                root / paths["shadow_archive"],
                excluded_identifier_hashes=hash_set,
            )
            _verify_pair(root, paths)
        return manifest


def _load_build_spec(path: Path) -> tuple[PairArtifacts, ...]:
    value = _load_canonical_object(path, "bundle build specification")
    if set(value) != {"schema_version", "pairs"} or value.get("schema_version") != "0.1":
        raise ProofBundleError("bundle build specification is invalid")
    pairs = value.get("pairs")
    field_names = {field.name for field in fields(PairArtifacts)}
    if not isinstance(pairs, list) or not pairs:
        raise ProofBundleError("bundle build specification has no pairs")
    result: list[PairArtifacts] = []
    for pair in pairs:
        if not isinstance(pair, Mapping) or set(pair) != field_names:
            raise ProofBundleError("bundle pair specification is invalid")
        if not all(isinstance(pair[name], str) for name in field_names):
            raise ProofBundleError("bundle pair specification is invalid")
        root = path.parent

        def artifact(name: str) -> Path:
            candidate = Path(pair[name])
            return candidate if candidate.is_absolute() else root / candidate

        result.append(
            PairArtifacts(
                pair_id=pair["pair_id"],
                baseline_record=artifact("baseline_record"),
                baseline_archive=artifact("baseline_archive"),
                baseline_manifest=artifact("baseline_manifest"),
                baseline_evaluation=artifact("baseline_evaluation"),
                shadow_archive=artifact("shadow_archive"),
                shadow_manifest=artifact("shadow_manifest"),
                shadow_run_dir=artifact("shadow_run_dir"),
                report_record=artifact("report_record"),
                comparison_record=artifact("comparison_record"),
                baseline_cleanup_attestation=artifact(
                    "baseline_cleanup_attestation"
                ),
                shadow_cleanup_attestation=artifact("shadow_cleanup_attestation"),
            )
        )
    return tuple(result)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    commands = value.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--spec", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "build":
            build_bundle(
                pairs=_load_build_spec(arguments.spec),
                output_path=arguments.output,
            )
            print("proof bundle build: pass")
        else:
            verify_bundle(arguments.bundle)
            print("proof bundle: pass")
    except (ProofBundleError, SourceArchiveError, OSError, ValueError) as error:
        print(f"proof bundle: fail: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
