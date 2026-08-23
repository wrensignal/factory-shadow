"""Fresh-VM execution boundary for the hidden final evaluator."""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import time
from pathlib import Path
from typing import Literal, Mapping, Protocol, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .protocol import canonical_json
from .source_export import ValidatedSourceArchive, validate_source_archive

_DIGEST = r"^[0-9a-f]{64}$"
_GUEST_INPUT_ROOT = "/home/shadow/evaluator-input"
_GUEST_OUTPUT = "/home/shadow/evaluator-output/result.json"
_GUEST_WORK_ROOT = "/home/shadow/evaluator-work"
_GUEST_FUNCTION_RUNNER = f"{_GUEST_INPUT_ROOT}/function_runner.py"
MAX_EVALUATION_RESULT_BYTES = 64 << 10
_FUNCTION_RUNNER_NAME = "function_runner.py"
_MAX_FUNCTION_RUNNER_BYTES = 64 << 10
VM_OUTPUT_LIMIT_BYTES = 1 << 20
OUTPUT_TRUNCATION_MARKER = b"\n...[truncated]\n"
_OUTPUT_READ_BYTES = 64 << 10
_CLEAN_STATE_ATTESTATION_FIELDS = frozenset(
    {
        "factory_profile_absent",
        "shadow_state_absent",
        "prior_inputs_absent",
        "credential_environment_absent",
        "host_mount_absent",
        "passwordless_sudo_absent",
    }
)

# One host-share detector, evaluated inside the guest against /proc/mounts.
# Lima always attaches its read-only cloud-init image at /mnt/lima-cidata, and
# that iso9660 device shares nothing with the host. Host directory sharing
# always appears as 9p, virtiofs, or reverse-sshfs (fuse.lima).
HOST_SHARE_MOUNT_TEST = (
    "(' 9p ' in line or ' virtiofs ' in line or 'fuse.lima' in line"
    " or ('/mnt/lima-' in line and ' iso9660 ' not in line))"
)


_PINNED_EVALUATOR_CONFIG_DIGEST = (
    "665f2f96aba8d3e926ebd533d00f574a535091a0a50b7625e415c191c53cbd8d"
)

class EvaluationBoundaryError(RuntimeError):
    """The isolated evaluator lifecycle did not complete safely."""


class EvaluationCleanupError(EvaluationBoundaryError):
    """A disposable evaluator VM was not deleted."""


class EvaluationAssertion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    assertion_id: str = Field(min_length=1)
    status: Literal["pass", "fail"]


class EvaluationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    status: Literal["pass", "fail"]
    archive_digest: str = Field(pattern=_DIGEST)
    working_tree_digest: str = Field(pattern=_DIGEST)
    assertions: tuple[EvaluationAssertion, ...]
    record_digest: str = Field(pattern=_DIGEST)

    @model_validator(mode="after")
    def validate_record(self) -> EvaluationRecord:
        identifiers = [item.assertion_id for item in self.assertions]
        if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
            raise ValueError("evaluation assertion IDs are not sorted and unique")
        expected_status = (
            "pass" if self.assertions and all(item.status == "pass" for item in self.assertions) else "fail"
        )
        if self.status != expected_status:
            raise ValueError("evaluation status differs from assertions")
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        if hashlib.sha256(canonical_json(value)).hexdigest() != supplied:
            raise ValueError("evaluation record digest differs")
        return self


class VmCommandResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


class VmDriver(Protocol):
    """Minimal shell-free driver used by the evaluator lifecycle."""

    def start(self, name: str, config: Path) -> None: ...
    def instance_exists(self, name: str) -> bool: ...

    def attest_clean(self, name: str) -> Mapping[str, bool]: ...

    def copy_to(self, name: str, source: Path, destination: str) -> None: ...

    def copy_from(self, name: str, source: str, destination: Path) -> None: ...

    def run(self, name: str, arguments: tuple[str, ...]) -> VmCommandResult: ...

    def delete(self, name: str) -> bool: ...


class ProcessFactory(Protocol):
    def __call__(
        self,
        arguments: Sequence[str],
        *,
        stdin: int,
        stdout: int,
        stderr: int,
        shell: bool,
        close_fds: bool,
        start_new_session: bool,
        env: Mapping[str, str],
    ) -> subprocess.Popen[bytes]: ...


def _append_bounded_output(buffer: bytearray, chunk: bytes, limit: int) -> bool:
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


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except OSError:
            pass
    process.wait()


def _capture_bounded_output(
    process: subprocess.Popen[bytes],
    *,
    arguments: tuple[str, ...],
    timeout_seconds: int,
    output_limit_bytes: int,
) -> tuple[int, str, str]:
    if process.stdout is None or process.stderr is None:
        _terminate_process(process)
        raise EvaluationBoundaryError("Lima output pipes are unavailable")
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
                    chunk = os.read(key.fd, _OUTPUT_READ_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if label in truncated:
                    continue
                if _append_bounded_output(
                    buffers[label],
                    chunk,
                    output_limit_bytes,
                ):
                    truncated.add(label)
                    output_exceeded = True
            if output_exceeded:
                break

        if timed_out or output_exceeded:
            _terminate_process(process)
        else:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process(process)

        for key in list(selector.get_map().values()):
            label = key.data
            while True:
                try:
                    chunk = os.read(key.fd, _OUTPUT_READ_BYTES)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                if label in truncated:
                    continue
                if _append_bounded_output(
                    buffers[label],
                    chunk,
                    output_limit_bytes,
                ):
                    truncated.add(label)
                    output_exceeded = True
    finally:
        selector.close()
        for stream in streams.values():
            if not stream.closed:
                stream.close()

    stdout = bytes(buffers["stdout"]).decode("utf-8", errors="replace")
    stderr = bytes(buffers["stderr"]).decode("utf-8", errors="replace")
    if timed_out:
        raise subprocess.TimeoutExpired(
            arguments,
            timeout_seconds,
            output=stdout,
            stderr=stderr,
        )
    return (255 if output_exceeded else int(process.returncode), stdout, stderr)


class LimaVmDriver:
    """Exact `limactl` transport for one no-mount disposable VM."""

    def __init__(
        self,
        *,
        process_factory: ProcessFactory = subprocess.Popen,
        timeout_seconds: int = 600,
        output_limit_bytes: int = VM_OUTPUT_LIMIT_BYTES,
    ) -> None:
        if timeout_seconds <= 0 or output_limit_bytes < len(OUTPUT_TRUNCATION_MARKER):
            raise ValueError("Lima process bounds are invalid")
        self._process_factory = process_factory
        self._timeout_seconds = timeout_seconds
        self._output_limit_bytes = output_limit_bytes

    def _invoke(self, arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        process = self._process_factory(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", "/tmp"),
            },
        )
        returncode, stdout, stderr = _capture_bounded_output(
            process,
            arguments=arguments,
            timeout_seconds=self._timeout_seconds,
            output_limit_bytes=self._output_limit_bytes,
        )
        return subprocess.CompletedProcess(
            arguments,
            returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def _checked(self, arguments: tuple[str, ...], action: str) -> None:
        result = self._invoke(arguments)
        if result.returncode != 0:
            diagnostic = (result.stderr or result.stdout).strip()[:2048]
            raise EvaluationBoundaryError(f"{action} failed: {diagnostic}")

    def instance_exists(self, name: str) -> bool:
        result = self._invoke(("limactl", "list", "--json"))
        if result.returncode != 0:
            raise EvaluationBoundaryError("evaluator VM inventory failed")
        payload = result.stdout.strip()
        if not payload:
            return False
        try:
            decoded = json.loads(payload)
            records = decoded if isinstance(decoded, list) else [decoded]
        except json.JSONDecodeError:
            try:
                records = [
                    json.loads(line)
                    for line in payload.splitlines()
                    if line.strip()
                ]
            except json.JSONDecodeError as error:
                raise EvaluationBoundaryError(
                    "evaluator VM inventory is invalid"
                ) from error
        if any(
            not isinstance(record, Mapping)
            or type(record.get("name")) is not str
            for record in records
        ):
            raise EvaluationBoundaryError("evaluator VM inventory is invalid")
        return any(record["name"] == name for record in records)

    def start(self, name: str, config: Path) -> None:
        self._checked(("limactl", "start", "--name", name, str(config)), "evaluator VM start")

    def attest_clean(self, name: str) -> Mapping[str, bool]:
        program = (
            "import json,os,pathlib,subprocess;"
            "forbidden=(pathlib.Path('/home/shadow/.factory'),"
            "pathlib.Path('/home/shadow/.shadow-mission'),"
            "pathlib.Path('/home/shadow/evaluator-input'));"
            "keys=tuple(k for k in os.environ if any(x in k.upper() for x in "
            "('FACTORY','DROID','TOKEN','SECRET','CREDENTIAL')));"
            "mounts=pathlib.Path('/proc/mounts').read_text();"
            f"host_mount=any({HOST_SHARE_MOUNT_TEST} "
            "for line in mounts.splitlines());"
            "sudo_absent=subprocess.run(('/usr/bin/sudo','-n','true'),"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0;"
            "print(json.dumps({'factory_profile_absent':not forbidden[0].exists(),"
            "'shadow_state_absent':not forbidden[1].exists(),"
            "'prior_inputs_absent':not forbidden[2].exists(),"
            "'credential_environment_absent':not keys,"
            "'host_mount_absent':not host_mount,"
            "'passwordless_sudo_absent':sudo_absent},"
            "sort_keys=True,separators=(',',':')))"
        )
        result = self.run(name, ("/usr/bin/python3", "-c", program))
        if result.returncode != 0:
            raise EvaluationBoundaryError("evaluator clean-state attestation failed")
        try:
            value = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError) as error:
            raise EvaluationBoundaryError("evaluator clean-state attestation is invalid") from error
        if (
            not isinstance(value, dict)
            or set(value) != _CLEAN_STATE_ATTESTATION_FIELDS
            or any(value[name] is not True for name in _CLEAN_STATE_ATTESTATION_FIELDS)
        ):
            raise EvaluationBoundaryError("evaluator VM is not clean")
        return value

    def copy_to(self, name: str, source: Path, destination: str) -> None:
        self._checked(("limactl", "copy", str(source), f"{name}:{destination}"), "evaluator input copy")

    def copy_from(self, name: str, source: str, destination: Path) -> None:
        self._checked(("limactl", "copy", f"{name}:{source}", str(destination)), "evaluator result copy")

    def run(self, name: str, arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        return self._invoke(("limactl", "shell", name, "--", *arguments))

    def delete(self, name: str) -> bool:
        stopped = False
        deleted = False
        try:
            stopped = self._invoke(("limactl", "stop", name)).returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            deleted = self._invoke(("limactl", "delete", name)).returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
        return stopped and deleted


def _load_evaluation_record(path: Path) -> EvaluationRecord:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise EvaluationBoundaryError("evaluation result is not canonical")
        if metadata.st_size > MAX_EVALUATION_RESULT_BYTES:
            raise EvaluationBoundaryError("evaluation result exceeds its byte limit")
        payload = path.read_bytes()
        if len(payload) > MAX_EVALUATION_RESULT_BYTES:
            raise EvaluationBoundaryError("evaluation result exceeds its byte limit")
        value = json.loads(payload)
        if not isinstance(value, Mapping) or canonical_json(value) + b"\n" != payload:
            raise EvaluationBoundaryError("evaluation result is not canonical")
        return EvaluationRecord.model_validate(value)
    except EvaluationBoundaryError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as error:
        raise EvaluationBoundaryError("evaluation result is invalid") from error


def validate_evaluator_assets(lima_config: Path, evaluator_path: Path) -> str:
    """Validate the exact VM template and return the hidden evaluator digest."""

    try:
        config_metadata = lima_config.lstat()
        config_digest = hashlib.sha256(lima_config.read_bytes()).hexdigest()
        if (
            lima_config.is_symlink()
            or not stat.S_ISREG(config_metadata.st_mode)
            or config_digest != _PINNED_EVALUATOR_CONFIG_DIGEST
        ):
            raise EvaluationBoundaryError(
                "evaluator Lima configuration differs from the pinned template"
            )
        evaluator_metadata = evaluator_path.lstat()
        evaluator_bytes = evaluator_path.read_bytes()
        if evaluator_path.is_symlink() or not stat.S_ISREG(evaluator_metadata.st_mode):
            raise EvaluationBoundaryError("evaluator is not a regular file")
        _function_runner_asset(evaluator_path)
        return hashlib.sha256(evaluator_bytes).hexdigest()
    except EvaluationBoundaryError:
        raise
    except OSError as error:
        raise EvaluationBoundaryError("cannot inspect evaluator assets") from error


def _function_runner_asset(evaluator_path: Path) -> Path:
    path = evaluator_path.with_name(_FUNCTION_RUNNER_NAME)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvaluationBoundaryError("function runner is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > _MAX_FUNCTION_RUNNER_BYTES
    ):
        raise EvaluationBoundaryError("function runner boundary is invalid")
    return path


def run_isolated_evaluator(
    *,
    driver: VmDriver,
    vm_name: str,
    lima_config: Path,
    archive_path: Path,
    manifest_path: Path,
    evaluator_path: Path,
    output_path: Path,
) -> EvaluationRecord:
    """Validate source, run the hidden evaluator in one fresh VM, then delete it."""

    validate_evaluator_assets(lima_config, evaluator_path)
    function_runner_path = _function_runner_asset(evaluator_path)
    validated: ValidatedSourceArchive = validate_source_archive(
        archive_path, manifest_path
    )
    if output_path.exists():
        raise EvaluationBoundaryError("evaluation output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_path.parent, 0o700)

    if driver.instance_exists(vm_name):
        raise EvaluationBoundaryError("evaluator VM name is already in use")

    start_attempted = False
    started = False
    ownership_error: BaseException | None = None
    lifecycle_error: BaseException | None = None
    record: EvaluationRecord | None = None
    try:
        start_attempted = True
        driver.start(vm_name, lima_config)
        started = True
        attestation = driver.attest_clean(vm_name)
        if (
            not isinstance(attestation, Mapping)
            or set(attestation) != _CLEAN_STATE_ATTESTATION_FIELDS
            or any(
                attestation[name] is not True
                for name in _CLEAN_STATE_ATTESTATION_FIELDS
            )
        ):
            raise EvaluationBoundaryError("evaluator VM clean-state proof is incomplete")
        prepared = driver.run(
            vm_name,
            (
                "/usr/bin/mkdir",
                "-p",
                _GUEST_INPUT_ROOT,
                "/home/shadow/evaluator-output",
            ),
        )
        if prepared.returncode != 0:
            raise EvaluationBoundaryError("evaluator guest directories cannot be created")
        driver.copy_to(vm_name, archive_path, f"{_GUEST_INPUT_ROOT}/final-source.tar")
        driver.copy_to(vm_name, manifest_path, f"{_GUEST_INPUT_ROOT}/final-source-manifest.json")
        driver.copy_to(vm_name, evaluator_path, f"{_GUEST_INPUT_ROOT}/evaluate.py")
        driver.copy_to(
            vm_name,
            function_runner_path,
            _GUEST_FUNCTION_RUNNER,
        )
        result = driver.run(
            vm_name,
            (
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                "HOME=/home/shadow",
                "PYTHONDONTWRITEBYTECODE=1",
                "/usr/bin/python3",
                f"{_GUEST_INPUT_ROOT}/evaluate.py",
                "--archive",
                f"{_GUEST_INPUT_ROOT}/final-source.tar",
                "--manifest",
                f"{_GUEST_INPUT_ROOT}/final-source-manifest.json",
                "--work-root",
                _GUEST_WORK_ROOT,
                "--output",
                _GUEST_OUTPUT,
                "--secure-isolation",
            ),
        )
        if result.returncode not in {0, 1}:
            raise EvaluationBoundaryError("evaluator process failed before an outcome")
        driver.copy_from(vm_name, _GUEST_OUTPUT, output_path)
        record = _load_evaluation_record(output_path)
        if record.archive_digest != validated.archive_digest:
            raise EvaluationBoundaryError("evaluator archive binding differs")
        if record.working_tree_digest != validated.manifest.working_tree_digest:
            raise EvaluationBoundaryError("evaluator tree binding differs")
        if (result.returncode == 0) != (record.status == "pass"):
            raise EvaluationBoundaryError("evaluator exit status differs from its record")
    except BaseException as error:
        lifecycle_error = error
        if start_attempted and not started:
            try:
                started = driver.instance_exists(vm_name)
            except BaseException as inspection_error:
                ownership_error = inspection_error
    finally:
        if ownership_error is not None:
            cleanup_error = EvaluationCleanupError(
                "evaluator VM ownership check failed"
            )
            if lifecycle_error is not None:
                raise cleanup_error from lifecycle_error
            raise cleanup_error from ownership_error
        if started and not driver.delete(vm_name):
            cleanup_error = EvaluationCleanupError("evaluator VM cleanup failed")
            if lifecycle_error is not None:
                raise cleanup_error from lifecycle_error
            raise cleanup_error
    if lifecycle_error is not None:
        raise lifecycle_error
    if record is None:
        raise EvaluationBoundaryError("evaluator produced no result")
    return record
