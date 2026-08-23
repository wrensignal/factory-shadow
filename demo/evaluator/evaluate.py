#!/usr/bin/env python3
"""Hidden cross-feature evaluator for the Shadow Mission demonstration."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, NamedTuple, Sequence

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_SOURCE_FILES = 10_000
MAX_SOURCE_BYTES = 256 << 20
CHILD_OUTPUT_LIMIT_BYTES = 64 << 10
CHILD_RESULT_LIMIT_BYTES = 4 << 10
CHILD_REQUEST_LIMIT_BYTES = 4 << 10
CHILD_WALL_TIMEOUT_SECONDS = 2.0
OUTPUT_TRUNCATION_MARKER = b"\n...[truncated]\n"
_CHILD_READ_BYTES = 16 << 10
_CHILD_ADDRESS_SPACE_BYTES = 512 << 20
_CHILD_DATA_BYTES = 256 << 20
# Darwin reserves a large virtual range before `exec`; the release guest uses
# the tighter Linux address-space and data bounds above.
_CHILD_DARWIN_MEMORY_BYTES = 1 << 40
_CHILD_CPU_SECONDS = 3
_CHILD_OPEN_FILES = 32
# The runner needs no descendants. This prevents a child from escaping cleanup.
_CHILD_PROCESSES = 0
_FUNCTION_RUNNER_NAME = "function_runner.py"
_FUNCTION_RUNNER_SHA256 = (
    "c89538a2d6dfaed17e3e0c78a9ae770f5c72ec25e4259f0c38490ffe00144d56"
)
_FUNCTION_RUNNER_LIMIT_BYTES = 64 << 10
_SECURE_ISOLATION_FLAG = "--secure-isolation"
_PR_GET_DUMPABLE = 3
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_PR_SET_DUMPABLE = 4
_FUNCTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_MANIFEST_KEYS = {
    "schema_version",
    "final_commit",
    "dirty_state",
    "working_tree_digest",
    "files",
    "record_digest",
}
_FILE_KEYS = {"path", "mode", "size", "sha256"}


class EvaluationError(ValueError):
    pass


class FunctionOutcome(NamedTuple):
    ok: bool
    value: object | None
    stdout: bytes
    stderr: bytes
    returncode: int | None
    timed_out: bool
    output_exceeded: bool


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def file_records(root: Path) -> list[dict]:
    records: list[dict] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        if "__pycache__" in names:
            raise EvaluationError("evaluator source tree contains __pycache__")
        names[:] = sorted(names)
        for name in names:
            directory_path = Path(directory) / name
            metadata = directory_path.lstat()
            if directory_path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise EvaluationError("evaluator source tree contains an invalid directory")
        for name in sorted(files):
            path = Path(directory) / name
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise EvaluationError("evaluator source tree contains a non-regular file")
            relative = path.relative_to(root).as_posix()
            digest = _file_sha256(path)
            records.append(
                {
                    "path": relative,
                    "mode": stat.S_IMODE(metadata.st_mode) & 0o777,
                    "size": metadata.st_size,
                    "sha256": digest,
                }
            )
    return sorted(records, key=lambda item: item["path"])

def make_tree_read_only(root: Path) -> dict[Path, int]:
    modes: dict[Path, int] = {}
    paths = sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True)
    paths.append(root)
    for path in paths:
        metadata = path.lstat()
        if path.is_symlink() or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        ):
            raise EvaluationError("evaluator source tree contains a non-regular entry")
        mode = stat.S_IMODE(metadata.st_mode)
        modes[path] = mode
        path.chmod(mode & ~0o222)
    return modes


def restore_tree_modes(modes: Mapping[Path, int]) -> None:
    for path, mode in sorted(modes.items(), key=lambda item: len(item[0].parts)):
        path.chmod(mode)


def safe_member_name(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise EvaluationError("source member name is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise EvaluationError("source member path escapes the checkout")
    if any(part in {".git", ".shadow-mission"} for part in path.parts):
        raise EvaluationError("source member enters private state")
    return path


def load_manifest(path: Path) -> dict:
    payload = path.read_bytes()
    value = json.loads(payload)
    if (
        not isinstance(value, Mapping)
        or set(value) != _MANIFEST_KEYS
        or canonical_json(value) + b"\n" != payload
    ):
        raise EvaluationError("source manifest is not canonical")
    material = dict(value)
    supplied_digest = material.pop("record_digest", None)
    if (
        not isinstance(supplied_digest, str)
        or not _DIGEST.fullmatch(supplied_digest)
        or hashlib.sha256(canonical_json(material)).hexdigest() != supplied_digest
    ):
        raise EvaluationError("source manifest record digest differs")
    files = value["files"]
    if not isinstance(files, list) or len(files) > MAX_SOURCE_FILES:
        raise EvaluationError("source manifest file bound is invalid")
    paths: list[str] = []
    total_bytes = 0
    for item in files:
        if not isinstance(item, Mapping) or set(item) != _FILE_KEYS:
            raise EvaluationError("source manifest file record is invalid")
        path_value = str(safe_member_name(item["path"]))
        if (
            path_value != item["path"]
            or isinstance(item["mode"], bool)
            or not isinstance(item["mode"], int)
            or not 0 <= item["mode"] <= 0o777
            or isinstance(item["size"], bool)
            or not isinstance(item["size"], int)
            or not 0 <= item["size"] <= MAX_SOURCE_BYTES
            or not isinstance(item["sha256"], str)
            or not _DIGEST.fullmatch(item["sha256"])
        ):
            raise EvaluationError("source manifest file record is invalid")
        paths.append(path_value)
        total_bytes += item["size"]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise EvaluationError("source manifest paths are not sorted and unique")
    if total_bytes > MAX_SOURCE_BYTES:
        raise EvaluationError("source manifest byte bound is invalid")
    expected_tree_digest = hashlib.sha256(
        canonical_json({"files": files})
    ).hexdigest()
    if (
        not isinstance(value["working_tree_digest"], str)
        or value["working_tree_digest"] != expected_tree_digest
    ):
        raise EvaluationError("source manifest tree digest differs")
    return dict(value)


def extract_archive(archive_path: Path, manifest_path: Path, work_root: Path) -> tuple[Path, str, str]:
    if work_root.exists():
        raise EvaluationError("evaluator work root already exists")
    manifest = load_manifest(manifest_path)
    archive_digest = _file_sha256(archive_path)
    expected = {item["path"]: item for item in manifest["files"]}
    work_root.mkdir(mode=0o700)
    checkout = work_root / "checkout"
    checkout.mkdir(mode=0o700)
    observed: set[str] = set()
    total_bytes = 0
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            previous_name: str | None = None
            member_count = 0
            for member in archive:
                member_count += 1
                if member_count > MAX_SOURCE_FILES:
                    raise EvaluationError("source archive exceeds its file bound")
                if previous_name is not None and member.name <= previous_name:
                    raise EvaluationError(
                        "source archive members are not sorted and unique"
                    )
                previous_name = member.name
            members = archive.members
            for member in members:
                relative = safe_member_name(member.name)
                record = expected.get(member.name)
                if (
                    record is None
                    or not member.isfile()
                    or member.linkname
                    or member.size != record["size"]
                    or member.mode & 0o777 != record["mode"]
                ):
                    raise EvaluationError("source archive differs from its manifest")
                total_bytes += member.size
                if total_bytes > MAX_SOURCE_BYTES:
                    raise EvaluationError("source archive exceeds its byte bound")
                stream = archive.extractfile(member)
                if stream is None:
                    raise EvaluationError("source archive member cannot be read")
                target = checkout.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                digest = hashlib.sha256()
                with target.open("xb") as handle:
                    while True:
                        chunk = stream.read(1 << 20)
                        if not chunk:
                            break
                        digest.update(chunk)
                        handle.write(chunk)
                os.chmod(target, record["mode"])
                if digest.hexdigest() != record["sha256"]:
                    raise EvaluationError("source archive content differs from manifest")
                observed.add(member.name)
    except tarfile.TarError as error:
        raise EvaluationError("source archive is invalid") from error
    if observed != set(expected):
        raise EvaluationError("source archive omits a manifest member")
    return checkout, archive_digest, manifest["working_tree_digest"]


def _set_child_resource_limits() -> None:
    address_space_bytes = (
        _CHILD_DARWIN_MEMORY_BYTES
        if sys.platform == "darwin"
        else _CHILD_ADDRESS_SPACE_BYTES
    )
    data_bytes = (
        _CHILD_DARWIN_MEMORY_BYTES if sys.platform == "darwin" else _CHILD_DATA_BYTES
    )
    limits = (
        (resource.RLIMIT_AS, address_space_bytes),
        (resource.RLIMIT_DATA, data_bytes),
        (resource.RLIMIT_CPU, _CHILD_CPU_SECONDS),
        (resource.RLIMIT_NOFILE, _CHILD_OPEN_FILES),
        (resource.RLIMIT_NPROC, _CHILD_PROCESSES),
    )
    for kind, requested in limits:
        current_soft, current_hard = resource.getrlimit(kind)
        finite_limits = [
            value
            for value in (requested, current_soft, current_hard)
            if value != resource.RLIM_INFINITY
        ]
        applied = min(finite_limits)
        # Darwin requires the inherited soft limit to fall before the hard limit.
        resource.setrlimit(kind, (applied, current_hard))
        resource.setrlimit(kind, (applied, applied))


def _append_bounded(buffer: bytearray, chunk: bytes, limit: int) -> bool:
    if len(buffer) + len(chunk) <= limit:
        buffer.extend(chunk)
        return False
    payload_limit = max(0, limit - len(OUTPUT_TRUNCATION_MARKER))
    if len(buffer) > payload_limit:
        del buffer[payload_limit:]
    remaining = payload_limit - len(buffer)
    if remaining > 0:
        buffer.extend(chunk[:remaining])
    buffer.extend(OUTPUT_TRUNCATION_MARKER[:limit])
    return True


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except OSError:
            pass
    process.wait()


def _capture_untrusted_process(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
) -> FunctionOutcome:
    if process.stdout is None or process.stderr is None:
        raise EvaluationError("function runner output pipes are unavailable")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    truncated: set[str] = set()
    selector = selectors.DefaultSelector()
    for label, stream in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    output_exceeded = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(remaining)
            if not events:
                timed_out = True
                break
            for key, _ in events:
                label = key.data
                try:
                    chunk = os.read(key.fd, _CHILD_READ_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if label in truncated:
                    continue
                if _append_bounded(
                    buffers[label],
                    chunk,
                    CHILD_OUTPUT_LIMIT_BYTES,
                ):
                    truncated.add(label)
                    output_exceeded = True
            if output_exceeded:
                break

        if timed_out or output_exceeded:
            _kill_process_group(process)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(process)

        for key in list(selector.get_map().values()):
            label = key.data
            while True:
                try:
                    chunk = os.read(key.fd, _CHILD_READ_BYTES)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                if label in truncated:
                    continue
                if _append_bounded(
                    buffers[label],
                    chunk,
                    CHILD_OUTPUT_LIMIT_BYTES,
                ):
                    truncated.add(label)
                    output_exceeded = True
    finally:
        selector.close()
        for stream in streams.values():
            if not stream.closed:
                stream.close()

    return FunctionOutcome(
        ok=False,
        value=None,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        returncode=process.returncode,
        timed_out=timed_out,
        output_exceeded=output_exceeded,
    )


def _is_bounded_function_value(value: object, *, depth: int = 0) -> bool:
    if depth > 3:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -(1 << 63) <= value < (1 << 63)
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, str):
        return len(value.encode("utf-8")) <= 1024
    if isinstance(value, list):
        return len(value) <= 16 and all(
            _is_bounded_function_value(item, depth=depth + 1) for item in value
        )
    if isinstance(value, dict):
        return len(value) <= 16 and all(
            isinstance(key, str)
            and 0 < len(key.encode("utf-8")) <= 128
            and _is_bounded_function_value(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def _decode_function_payload(payload: bytes) -> tuple[bool, object | None]:
    if len(payload) > CHILD_RESULT_LIMIT_BYTES:
        return False, None
    try:
        value = json.loads(payload)
        if not isinstance(value, Mapping) or canonical_json(value) + b"\n" != payload:
            return False, None
        if value == {"ok": False}:
            return False, None
        if (
            set(value) != {"ok", "value"}
            or value["ok"] is not True
            or not _is_bounded_function_value(value["value"])
        ):
            return False, None
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return False, None
    return True, value["value"]


def _validated_function_runner_bytes(payload: bytes | None = None) -> bytes:
    if payload is None:
        path = Path(__file__).with_name(_FUNCTION_RUNNER_NAME)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise EvaluationError("function runner is unavailable") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or metadata.st_size <= 0
                or metadata.st_size > _FUNCTION_RUNNER_LIMIT_BYTES
            ):
                raise EvaluationError("function runner boundary is invalid")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                payload = handle.read(_FUNCTION_RUNNER_LIMIT_BYTES + 1)
            final_metadata = os.fstat(descriptor)
            if (
                len(payload) != metadata.st_size
                or (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                )
                != (
                    final_metadata.st_dev,
                    final_metadata.st_ino,
                    final_metadata.st_size,
                    final_metadata.st_mtime_ns,
                )
            ):
                raise EvaluationError("function runner changed during inspection")
        finally:
            os.close(descriptor)
    if (
        not payload
        or len(payload) > _FUNCTION_RUNNER_LIMIT_BYTES
        or hashlib.sha256(payload).hexdigest() != _FUNCTION_RUNNER_SHA256
    ):
        raise EvaluationError("function runner digest differs")
    return payload


def _linux_prctl() -> Callable[..., int]:
    if not sys.platform.startswith("linux"):
        raise EvaluationError("secure evaluator isolation requires Linux")
    try:
        function = ctypes.CDLL(None, use_errno=True).prctl
        function.argtypes = (
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        )
        function.restype = ctypes.c_int
    except (AttributeError, OSError) as error:
        raise EvaluationError("parent memory protection is unavailable") from error
    return function


def _protect_parent_memory() -> None:
    prctl = _linux_prctl()
    if prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise EvaluationError("child privilege protection failed")
    if prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise EvaluationError("parent memory protection failed")
    if prctl(_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
        raise EvaluationError("child privilege protection is incomplete")
    if prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise EvaluationError("parent memory protection is incomplete")


def _require_parent_memory_protection() -> None:
    prctl = _linux_prctl()
    if prctl(_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
        raise EvaluationError("child privilege protection was lost")
    if prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise EvaluationError("parent memory protection was lost")


def _hide_evaluator_source(path: Path) -> None:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
        ):
            raise EvaluationError("hidden evaluator source boundary is invalid")
        path.unlink()
    except EvaluationError:
        raise
    except OSError as error:
        raise EvaluationError("hidden evaluator source cannot be removed") from error
    if path.exists() or path.is_symlink():
        raise EvaluationError("hidden evaluator source remains available")


def run_untrusted_function(
    module_path: Path,
    function_name: str,
    arguments: Sequence[object],
    *,
    source_root: Path | None = None,
    timeout_seconds: float = CHILD_WALL_TIMEOUT_SECONDS,
    function_runner_bytes: bytes | None = None,
    require_parent_memory_protection: bool = False,
) -> FunctionOutcome:
    if timeout_seconds <= 0 or not _FUNCTION_NAME.fullmatch(function_name):
        raise EvaluationError("function runner configuration is invalid")
    runner_payload = _validated_function_runner_bytes(function_runner_bytes)
    if require_parent_memory_protection:
        _require_parent_memory_protection()
    workspace = Path(tempfile.mkdtemp(prefix="shadow-evaluator-function-"))
    try:
        runner_copy = workspace / _FUNCTION_RUNNER_NAME
        runner_copy.write_bytes(runner_payload)
        runner_copy.chmod(0o400)
        if source_root is None:
            execution_root = workspace
            module_copy = execution_root / "mission_module.py"
            module_copy.write_bytes(module_path.read_bytes())
        else:
            # Each call gets a writable full-tree copy. A module can use local
            # imports without mutating the parent tree or a later call.
            relative_module = module_path.relative_to(source_root)
            execution_root = workspace / "checkout"
            shutil.copytree(
                source_root,
                execution_root,
                copy_function=shutil.copyfile,
            )
            for path in execution_root.rglob("*"):
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    path.chmod(stat.S_IMODE(metadata.st_mode) | 0o700)
                elif stat.S_ISREG(metadata.st_mode):
                    path.chmod(stat.S_IMODE(metadata.st_mode) | 0o200)
            execution_root.chmod(0o700)
            module_copy = execution_root / relative_module
        request = canonical_json({"args": list(arguments)}) + b"\n"
        if len(request) > CHILD_REQUEST_LIMIT_BYTES:
            raise EvaluationError("function runner request exceeds its byte limit")
        try:
            process = subprocess.Popen(
                (
                    sys.executable,
                    "-I",
                    "-B",
                    str(runner_copy),
                    str(module_copy),
                    function_name,
                    str(execution_root),
                ),
                cwd=execution_root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
                shell=False,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(workspace),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
                preexec_fn=_set_child_resource_limits,
            )
        except (OSError, subprocess.SubprocessError):
            return FunctionOutcome(False, None, b"", b"", None, False, False)
        if process.stdin is None:
            _kill_process_group(process)
            return FunctionOutcome(
                False,
                None,
                b"",
                b"",
                process.returncode,
                False,
                False,
            )
        try:
            process.stdin.write(request)
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()
        outcome = _capture_untrusted_process(
            process,
            timeout_seconds=timeout_seconds,
        )
        if (
            outcome.timed_out
            or outcome.output_exceeded
            or outcome.returncode != 0
        ):
            return outcome
        ok, value = _decode_function_payload(outcome.stdout)
        return outcome._replace(ok=ok, value=value)
    except (OSError, UnicodeError, ValueError, TypeError):
        return FunctionOutcome(False, None, b"", b"", None, False, False)
    finally:
        try:
            workspace.chmod(0o700)
        except OSError:
            pass
        shutil.rmtree(workspace, ignore_errors=True)


def evaluate(
    repo: Path,
    archive_digest: str,
    expected_tree_digest: str,
    *,
    function_runner_bytes: bytes | None = None,
    require_parent_memory_protection: bool = False,
) -> dict:
    if not _DIGEST.fullmatch(archive_digest) or not _DIGEST.fullmatch(
        expected_tree_digest
    ):
        raise EvaluationError("evaluator digest binding is invalid")
    records = file_records(repo)
    pre_evaluation_tree_digest = hashlib.sha256(
        canonical_json({"files": records})
    ).hexdigest()
    if pre_evaluation_tree_digest != expected_tree_digest:
        raise EvaluationError("evaluator working-tree digest differs")

    schema = json.loads((repo / "api-schema.json").read_text(encoding="utf-8"))
    database = (repo / "db-schema.sql").read_text(encoding="utf-8")
    original_modes = make_tree_read_only(repo)
    read_only_records = file_records(repo)

    def require_unchanged_tree() -> None:
        if file_records(repo) != read_only_records:
            raise EvaluationError(
                "evaluated source changed during hidden assertions"
            )

    try:
        checks = {
            "api_amount_unit_is_integer_cents": (
                schema.get("payment", {}).get("amount", {}).get("unit") == "cents"
                and schema.get("payment", {}).get("amount", {}).get("type") == "integer"
            ),
            "database_column_is_amount_cents": "amount_cents INTEGER" in database,
        }
        payment = run_untrusted_function(
            repo / "src/payment_api.py",
            "payment_response",
            ("payment-10", 1000, "USD"),
            source_root=repo,
            function_runner_bytes=function_runner_bytes,
            require_parent_memory_protection=require_parent_memory_protection,
        )
        require_unchanged_tree()
        response = payment.value
        checks["api_preserves_integer_cents"] = (
            payment.ok
            and isinstance(response, Mapping)
            and response.get("amount") == 1000
            and isinstance(response.get("amount"), int)
            and not isinstance(response.get("amount"), bool)
        )

        webhook = run_untrusted_function(
            repo / "src/webhook.py",
            "parse_webhook",
            (
                {
                    "payment_id": "payment-10",
                    "amount": "10.00",
                    "currency": "USD",
                },
            ),
            source_root=repo,
            function_runner_bytes=function_runner_bytes,
            require_parent_memory_protection=require_parent_memory_protection,
        )
        require_unchanged_tree()
        parsed = webhook.value
        invoice = (
            run_untrusted_function(
                repo / "src/invoice_export.py",
                "invoice_row",
                (parsed,),
                source_root=repo,
                function_runner_bytes=function_runner_bytes,
                require_parent_memory_protection=require_parent_memory_protection,
            )
            if webhook.ok and isinstance(parsed, Mapping)
            else FunctionOutcome(False, None, b"", b"", None, False, False)
        )
        require_unchanged_tree()
        row = invoice.value
        checks["ten_dollars_crosses_all_boundaries_as_1000_cents"] = (
            webhook.ok
            and invoice.ok
            and isinstance(row, list)
            and row == ["payment-10", 1000, "USD"]
            and isinstance(row[1], int)
            and not isinstance(row[1], bool)
        )
    finally:
        restore_tree_modes(original_modes)
    post_evaluation_tree_digest = hashlib.sha256(
        canonical_json({"files": file_records(repo)})
    ).hexdigest()
    if (
        post_evaluation_tree_digest != pre_evaluation_tree_digest
        or post_evaluation_tree_digest != expected_tree_digest
    ):
        raise EvaluationError("evaluated source changed during hidden assertions")
    assertions = [
        {"assertion_id": name, "status": "pass" if passed else "fail"}
        for name, passed in sorted(checks.items())
    ]
    result = {
        "schema_version": "0.1",
        "status": "pass" if all(checks.values()) else "fail",
        "archive_digest": archive_digest,
        "working_tree_digest": post_evaluation_tree_digest,
        "assertions": assertions,
    }
    result["record_digest"] = hashlib.sha256(canonical_json(result)).hexdigest()
    return result


def write_result(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(result) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--archive", type=Path, required=True)
    value.add_argument("--manifest", type=Path, required=True)
    value.add_argument("--work-root", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    value.add_argument(
        _SECURE_ISOLATION_FLAG,
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return value


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = tuple(sys.argv[1:] if argv is None else argv)
    arguments = parser().parse_args(raw_arguments)
    try:
        runner_bytes = _validated_function_runner_bytes()
        secure_isolation = bool(arguments.secure_isolation)
        if secure_isolation:
            evaluator_source = Path(__file__).resolve(strict=True)
            _protect_parent_memory()
            _hide_evaluator_source(evaluator_source)
        repo, archive_digest, working_tree_digest = extract_archive(
            arguments.archive.resolve(strict=True),
            arguments.manifest.resolve(strict=True),
            arguments.work_root,
        )
        result = evaluate(
            repo,
            archive_digest,
            working_tree_digest,
            function_runner_bytes=runner_bytes,
            require_parent_memory_protection=secure_isolation,
        )
        write_result(arguments.output, result)
    except (
        EvaluationError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        print(f"evaluation failed: {error}")
        return 1
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
