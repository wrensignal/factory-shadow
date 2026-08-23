"""Isolated live Droid SDK boundaries for extraction and independent probes.

The brokers in this module never inherit the host process environment. Each call
uses a fresh Droid process, a clean HOME, an empty tool allowlist, and one
schema-bound turn. Raw model output is returned only through the existing
attempt objects.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import hmac
import json
import os
import signal
import stat
import sys
import tempfile
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Mapping, Protocol

try:
    import fcntl
except ImportError:  # pragma: no cover - unsupported non-POSIX host
    fcntl = None  # type: ignore[assignment]

_DARWIN_STAGED_EXECUTABLES: dict[tuple[int, int], Path] = {}


from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .extractor import (
    BoundaryMetadata,
    BrokerAttempt,
    ExtractedClaim,
    ExtractionRequest,
)
from .probe import (
    MAX_OUTPUT_BYTES,
    ProbeAttempt,
    ProbeBoundary,
    ProbeResult,
    ProbeSnapshot,
    ToolCatalogEntry,
)
from .redaction import sanitize_value

_EXTRACTION_TIMEOUT_SECONDS = 30
MAX_EXTRACTION_CLAIMS = 8
_PROBE_TIMEOUT_SECONDS = 90
_PREWARM_MAX_IDLE_SECONDS = 120
_STDOUT_LIMIT = 2 * 1024 * 1024
_CLOSE_TIMEOUT_SECONDS = 3.0
_EXTRACTION_CLEANUP_BUDGET_SECONDS = _CLOSE_TIMEOUT_SECONDS * 4


class InternalSessionError(RuntimeError):
    """A bounded live-boundary failure which contains no external data."""

class _InternalSessionTimeout(InternalSessionError):
    pass


@dataclass(frozen=True)
class InternalSessionConfig:
    """The exact restrictive configuration applied before a session opens."""

    mcp_servers: tuple[object, ...] = ()
    restrict_tools: tuple[str, ...] = ()
    auto_reject_permission_requests: bool = True
    disable_builtin_skills: bool = True


class _Transport(Protocol):
    @property
    def is_connected(self) -> bool: ...

    @property
    def process_alive(self) -> bool: ...

    async def connect(self) -> None: ...

    async def send(self, message: str) -> None: ...

    def read_messages(self) -> AsyncIterator[dict[str, Any]]: ...

    async def close(self) -> None: ...


class _Session(Protocol):
    @property
    def id(self) -> str: ...

    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def list_tools(self, **options: object) -> list[object]: ...

    async def update_settings(self, **settings: object) -> object: ...

    def stream(self, prompt: str, **options: object) -> object: ...


class SdkBoundary(Protocol):
    """Injectable adapter around the small droid-sdk surface used here."""

    def create_session(
        self,
        *,
        cwd: Path,
        model: str,
        reasoning: str,
        config: InternalSessionConfig,
        transport: _Transport,
    ) -> _Session: ...


TransportFactory = Callable[[int, Path, Mapping[str, str]], "_Transport"]
CollectorEventCount = Callable[[str], tuple[str, tuple[str, ...]]]
ExecutableDigestReader = Callable[[Path], str]
SecureExecutableStager = Callable[[Path, str, Path], int]


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


class ReplacementEnvironmentTransport:
    """Droid JSONL transport which passes a replacement child environment.

    Unlike droid-sdk 0.2.0 ``ProcessTransport``, this transport never merges
    ``os.environ`` into the child environment.
    """

    def __init__(
        self,
        executable_descriptor: int,
        cwd: Path,
        environment: Mapping[str, str],
        *,
        grace_period: float = 1.0,
    ) -> None:
        self._executable_descriptor: int | None = executable_descriptor
        self._cwd = cwd
        self._environment = dict(environment)
        self._grace_period = grace_period
        self._process: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._write_lock: asyncio.Lock | None = None
        self._closing = False

    @property
    def is_connected(self) -> bool:
        return self.process_alive and not self._closing

    @property
    def process_alive(self) -> bool:
        process = self._process
        return process is not None and (
            process.returncode is None or _process_group_alive(process.pid)
        )

    async def connect(self) -> None:
        if self.is_connected:
            raise InternalSessionError("internal transport is already connected")
        descriptor = self._executable_descriptor
        if descriptor is None:
            raise InternalSessionError("internal executable descriptor is closed")
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o111 == 0
            ):
                raise InternalSessionError("staged Droid executable is invalid")
            executable = sealed_descriptor_path(descriptor, metadata)
            self._process = await asyncio.create_subprocess_exec(
                str(executable),
                "exec",
                "--input-format",
                "stream-jsonrpc",
                "--output-format",
                "stream-jsonrpc",
                cwd=str(self._cwd),
                env=dict(self._environment),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=_STDOUT_LIMIT,
                pass_fds=(descriptor,),
                start_new_session=True,
            )
        except InternalSessionError:
            raise
        except (OSError, ValueError) as error:
            raise InternalSessionError("internal transport failed to start") from error
        finally:
            self._close_executable_descriptor()
        self._write_lock = asyncio.Lock()
        if self._process.stderr is not None:
            self._stderr_task = asyncio.create_task(
                self._discard_stderr(self._process.stderr)
            )

    async def send(self, message: str) -> None:
        process = self._process
        if (
            process is None
            or process.returncode is not None
            or process.stdin is None
            or self._write_lock is None
        ):
            raise InternalSessionError("internal process is not alive")
        async with self._write_lock:
            try:
                process.stdin.write((message + "\n").encode("utf-8"))
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionError, OSError) as error:
                raise InternalSessionError("internal transport write failed") from error

    async def read_messages(self) -> AsyncIterator[dict[str, Any]]:
        process = self._process
        if process is None or process.stdout is None:
            raise InternalSessionError("internal transport is not connected")
        while True:
            try:
                raw_line = await process.stdout.readline()
            except (OSError, ValueError) as error:
                raise InternalSessionError("internal transport read failed") from error
            if not raw_line:
                break
            try:
                message = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise InternalSessionError("internal transport returned invalid JSON") from error
            if not isinstance(message, dict):
                raise InternalSessionError("internal transport returned invalid protocol data")
            yield message
        if not self._closing:
            raise InternalSessionError("internal process exited")

    async def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        process = self._process
        try:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except OSError:
                    pass
                await self._wait_process_group_exit(
                    process,
                    time.monotonic() + self._grace_period,
                )
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                terminated = await self._wait_process_group_exit(
                    process,
                    time.monotonic() + 1.0,
                )
                if not terminated:
                    raise InternalSessionError(
                        "internal process group did not terminate"
                    )
            if process is not None and process.stdin is not None:
                process.stdin.close()
            task = self._stderr_task
            self._stderr_task = None
            if task is not None and not task.done():
                task.cancel()
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)
            self._process = None
        finally:
            try:
                self._close_executable_descriptor()
            finally:
                self._closing = False
    @staticmethod
    async def _wait_process_group_exit(
        process: asyncio.subprocess.Process,
        deadline: float,
    ) -> bool:
        while True:
            leader_alive = process.returncode is None
            group_alive = _process_group_alive(process.pid)
            if not leader_alive and not group_alive:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            await asyncio.sleep(min(0.01, remaining))


    @staticmethod
    async def _discard_stderr(stderr: asyncio.StreamReader) -> None:
        while await stderr.read(8192):
            pass

    def _close_executable_descriptor(self) -> None:
        descriptor = self._executable_descriptor
        if descriptor is None:
            return
        self._executable_descriptor = None
        try:
            os.close(descriptor)
        except OSError as error:
            raise InternalSessionError(
                "internal executable descriptor cleanup failed"
            ) from error


def _required_linux_seals() -> tuple[int, int, int]:
    names = (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_WRITE",
        "F_SEAL_GROW",
        "F_SEAL_SHRINK",
        "F_SEAL_SEAL",
    )
    values = tuple(getattr(fcntl, name, None) for name in names)
    if any(type(value) is not int for value in values):
        raise InternalSessionError("sealed executable staging is unavailable")
    add_seals, get_seals, *seal_values = values
    required = 0
    for value in seal_values:
        required |= value
    return add_seals, get_seals, required


def _verify_linux_descriptor_seals(descriptor: int) -> None:
    if not sys.platform.startswith("linux"):
        raise InternalSessionError("sealed executable launch is unavailable")
    _, get_seals, required = _required_linux_seals()
    try:
        observed = fcntl.fcntl(descriptor, get_seals)
    except OSError as error:
        raise InternalSessionError("sealed executable launch is unavailable") from error
    if observed & required != required:
        raise InternalSessionError("staged Droid executable is not sealed")


def sealed_descriptor_path(
    descriptor: int, descriptor_metadata: os.stat_result
) -> Path:
    if sys.platform.startswith("linux"):
        _verify_linux_descriptor_seals(descriptor)
        executable = Path("/proc/self/fd") / str(descriptor)
    elif sys.platform == "darwin":
        key = (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
        mapped = _DARWIN_STAGED_EXECUTABLES.get(key)
        if mapped is None:
            raise InternalSessionError(
                "descriptor-backed executable launch is unavailable"
            )
        executable = mapped
    else:
        raise InternalSessionError(
            "descriptor-backed executable launch is unavailable"
        )
    try:
        executable_metadata = os.stat(executable)
    except OSError as error:
        raise InternalSessionError(
            "descriptor-backed executable launch is unavailable"
        ) from error
    same_inode = executable_metadata.st_ino == descriptor_metadata.st_ino
    same_device = executable_metadata.st_dev == descriptor_metadata.st_dev
    if not same_inode or (
        sys.platform.startswith("linux") and not same_device
    ):
        raise InternalSessionError(
            "descriptor-backed executable launch is unavailable"
        )
    return executable


class _DroidSdkBoundary:
    def create_session(
        self,
        *,
        cwd: Path,
        model: str,
        reasoning: str,
        config: InternalSessionConfig,
        transport: _Transport,
    ) -> _Session:
        from droid_sdk import ReasoningEffort, Runtime, Session, SessionConfig

        session_config = SessionConfig(
            mcp_servers=config.mcp_servers,
            restrict_tools=config.restrict_tools,
            auto_reject_permission_requests=config.auto_reject_permission_requests,
            disable_builtin_skills=config.disable_builtin_skills,
        )
        return Session(
            cwd=cwd,
            model=model,
            reasoning_effort=ReasoningEffort(reasoning),
            config=session_config,
            runtime=Runtime(transport=transport),
        )


class _ExtractionOutput(BaseModel):
    """The droid-sdk requires a top-level object, never a bare array."""

    model_config = ConfigDict(extra="forbid")

    claims: list[ExtractedClaim]


@dataclass
class _PreparedProbe:
    temporary_home: tempfile.TemporaryDirectory[str]
    transport: _Transport
    session: _Session
    worker: "_LoopWorker"
    preparation_cleanup: "_PreparationCleanup" = field(repr=False)
    boundary: ProbeBoundary
    closing: bool = False
    closed: bool = False
    close_complete: threading.Event = field(default_factory=threading.Event)
    close_succeeded: bool = False



@dataclass
class _PreparedExtraction:
    """One fresh confined extraction session built before its request exists."""

    temporary_home: tempfile.TemporaryDirectory[str]
    transport: _Transport
    session: _Session
    worker: "_LoopWorker"
    boundary: BoundaryMetadata
    preparation_cleanup: "_PreparationCleanup" = field(repr=False)
    prepared_at: float = field(default_factory=time.monotonic)
    closing: bool = False
    closed: bool = False
    close_complete: threading.Event = field(default_factory=threading.Event)
    close_succeeded: bool = False


@dataclass
class _PreparationCleanup:
    """Boundary resources owned until prepared-session handoff."""

    temporary_home: tempfile.TemporaryDirectory[str]
    transport: _Transport | None
    staged_descriptor: int | None
    session: _Session | None
    worker: "_LoopWorker"
    boundary_closed: bool = False
    home_cleaned: bool = False
    cleanup_owner: str | None = None
    cleanup_complete: threading.Event = field(default_factory=threading.Event)


class _LoopWorker:
    def __init__(self, name: str) -> None:
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._future_lock = threading.RLock()
        self._future_condition = threading.Condition(self._future_lock)
        self._active_future: concurrent.futures.Future[Any] | None = None
        self._active_generation: int | None = None
        self._submission_generation = 0
        self._completed_generation = 0
        self._started_generations: set[int] = set()
        self._cancel_requested = False
        self._thread = threading.Thread(
            target=self._serve,
            name=name,
            daemon=True,
        )
        self._thread.start()
        self._ready.wait()

    def _serve(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        try:
            self._loop.run_forever()
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
        finally:
            self._loop.close()
            self._stopped.set()
            with self._future_condition:
                self._future_condition.notify_all()

    async def _tracked_run(self, coroutine: object, generation: int) -> Any:
        with self._future_condition:
            self._started_generations.add(generation)
        try:
            return await coroutine  # type: ignore[misc]
        finally:
            with self._future_condition:
                self._mark_completed_locked(generation)

    def _mark_completed_locked(self, generation: int) -> None:
        self._completed_generation = max(self._completed_generation, generation)
        if self._active_generation == generation:
            self._active_future = None
            self._active_generation = None
        self._future_condition.notify_all()

    def run(self, coroutine: object, *, timeout: float) -> Any:
        with self._future_condition:
            generation = self._submission_generation + 1
            self._submission_generation = generation
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self._tracked_run(coroutine, generation),
                    self._loop,
                )
            except BaseException:
                close = getattr(coroutine, "close", None)
                if callable(close):
                    close()
                self._mark_completed_locked(generation)
                raise
            self._active_future = future
            self._active_generation = generation

            def complete_if_never_started(
                _future: concurrent.futures.Future[Any],
            ) -> None:
                with self._future_condition:
                    if generation not in self._started_generations:
                        close = getattr(coroutine, "close", None)
                        if callable(close):
                            close()
                        self._mark_completed_locked(generation)

            future.add_done_callback(complete_if_never_started)
            if self._cancel_requested:
                self._cancel_requested = False
                future.cancel()
            self._future_condition.notify_all()
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise _InternalSessionTimeout("internal session wall timeout") from None

    def cancel_active(
        self,
        *,
        timeout: float = _CLOSE_TIMEOUT_SECONDS,
        completed_is_stopped: bool = False,
    ) -> bool:
        """Cancel the current or next submitted turn and await its completion."""

        deadline = time.monotonic() + timeout
        with self._future_condition:
            if (
                self._active_future is None
                and completed_is_stopped
                and self._submission_generation > 0
                and self._completed_generation == self._submission_generation
            ):
                return True
            if self._active_future is not None:
                target_generation = self._active_generation
            else:
                target_generation = self._submission_generation + 1
                self._cancel_requested = True
            assert target_generation is not None
            while (
                self._submission_generation < target_generation
                and not self._stopped.is_set()
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._future_condition.wait(remaining)
            if self._completed_generation >= target_generation:
                return True
            future = (
                self._active_future
                if self._active_generation == target_generation
                else None
            )
            if future is not None:
                self._cancel_requested = False
                future.cancel()
            while (
                self._completed_generation < target_generation
                and not self._stopped.is_set()
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._future_condition.wait(remaining)
            return self._completed_generation >= target_generation

    def stop(self, *, timeout: float = _CLOSE_TIMEOUT_SECONDS) -> bool:
        if not self._loop.is_closed():
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except RuntimeError:
                pass
        self._thread.join(timeout=timeout)
        return self._stopped.is_set() and not self._thread.is_alive()

    @property
    def alive(self) -> bool:
        return self._thread.is_alive() and not self._stopped.is_set()


def _default_transport_factory(
    executable_descriptor: int,
    cwd: Path,
    environment: Mapping[str, str],
) -> _Transport:
    return ReplacementEnvironmentTransport(
        executable_descriptor, cwd, environment
    )



def _open_executable_source(path: Path) -> int:
    if not path.is_absolute():
        raise InternalSessionError("internal Droid executable path is not absolute")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise InternalSessionError("secure executable staging is unavailable")
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise InternalSessionError("internal Droid executable is unreadable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o111 == 0
        ):
            raise InternalSessionError("internal Droid executable is invalid")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor
def _open_regular_source(path: Path) -> int:
    if not path.is_absolute():
        raise InternalSessionError("bound file path is not absolute")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise InternalSessionError("secure file staging is unavailable")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | nofollow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise InternalSessionError("bound file is unreadable") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InternalSessionError("bound file is invalid")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor




def _read_descriptor_digest(descriptor: int) -> str:
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1 << 20):
        digest.update(chunk)
    return digest.hexdigest()


def _valid_sha256_digest(value: str) -> bool:
    return type(value) is str and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _sha256_executable(path: Path) -> str:
    descriptor = _open_executable_source(path)
    try:
        return _read_descriptor_digest(descriptor)
    except OSError as error:
        raise InternalSessionError("internal Droid executable is unreadable") from error
    finally:
        os.close(descriptor)


def _source_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _create_staging_descriptor(
    private_home: Path,
    staging_name: str,
) -> tuple[int, Path | None]:
    if sys.platform.startswith("linux"):
        memfd_create = getattr(os, "memfd_create", None)
        allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
        if not callable(memfd_create) or type(allow_sealing) is not int:
            raise InternalSessionError("sealed file staging is unavailable")
        flags = allow_sealing | getattr(os, "MFD_CLOEXEC", 0)
        return memfd_create(f"shadow-{staging_name}", flags), None
    staged_path = private_home / staging_name
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    return os.open(staged_path, flags, 0o600), staged_path


def _seal_linux_staging_descriptor(descriptor: int) -> int:
    add_seals, _, required = _required_linux_seals()
    try:
        fcntl.fcntl(descriptor, add_seals, required)
        _verify_linux_descriptor_seals(descriptor)
        metadata = os.fstat(descriptor)
        readonly = os.open(
            Path("/proc/self/fd") / str(descriptor),
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        readonly_metadata = os.fstat(readonly)
        if (
            readonly_metadata.st_dev != metadata.st_dev
            or readonly_metadata.st_ino != metadata.st_ino
        ):
            raise InternalSessionError("sealed executable descriptor changed")
        _verify_linux_descriptor_seals(readonly)
    except BaseException:
        if "readonly" in locals():
            os.close(readonly)
        raise
    os.close(descriptor)
    return readonly


def stage_bound_file(
    source: Path,
    expected_digest: str,
    private_home: Path,
    *,
    require_executable: bool = True,
    staging_name: str = "droid",
) -> int:
    if not _valid_sha256_digest(expected_digest):
        raise InternalSessionError("bound file digest is invalid")
    source_descriptor: int | None = None
    staged_descriptor: int | None = None
    staged_path: Path | None = None
    try:
        source_descriptor = (
            _open_executable_source(source)
            if require_executable
            else _open_regular_source(source)
        )
        source_before = os.fstat(source_descriptor)
        staged_descriptor, staged_path = _create_staging_descriptor(
            private_home,
            staging_name,
        )
        source_digest = hashlib.sha256()
        while chunk := os.read(source_descriptor, 1 << 20):
            source_digest.update(chunk)
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(staged_descriptor, remaining)
                if written <= 0:
                    raise OSError("short executable staging write")
                remaining = remaining[written:]
        source_after = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_after.st_mode)
            or _source_identity(source_after) != _source_identity(source_before)
        ):
            raise InternalSessionError("bound file identity changed")
        if not hmac.compare_digest(source_digest.hexdigest(), expected_digest):
            raise InternalSessionError("bound file binding changed")
        os.fsync(staged_descriptor)
        os.fchmod(staged_descriptor, 0o500 if require_executable else 0o400)
        os.lseek(staged_descriptor, 0, os.SEEK_SET)
        staged_digest = _read_descriptor_digest(staged_descriptor)
        if not hmac.compare_digest(staged_digest, expected_digest):
            raise InternalSessionError("staged file binding changed")
        os.lseek(staged_descriptor, 0, os.SEEK_SET)
        if sys.platform.startswith("linux"):
            staged_descriptor = _seal_linux_staging_descriptor(staged_descriptor)
        retained_descriptor = staged_descriptor
        staged_descriptor = None
        if sys.platform == "darwin" and staged_path is not None:
            metadata = os.fstat(retained_descriptor)
            _DARWIN_STAGED_EXECUTABLES[(metadata.st_dev, metadata.st_ino)] = (
                staged_path
            )
            staged_path = None
        return retained_descriptor
    except InternalSessionError:
        raise
    except OSError as error:
        raise InternalSessionError("internal Droid executable staging failed") from error
    finally:
        if staged_descriptor is not None:
            os.close(staged_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)
        if staged_path is not None:
            try:
                staged_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _require_executable_digest(
    executable: str,
    expected_digest: str,
    digest_reader: ExecutableDigestReader,
) -> None:
    source = Path(executable)
    if (
        not source.is_absolute()
        or not _valid_sha256_digest(expected_digest)
        or not hmac.compare_digest(digest_reader(source), expected_digest)
    ):
        raise InternalSessionError("internal Droid executable binding changed")

def _is_forbidden_environment_key(key: str) -> bool:
    normalized = key.upper()
    return (
        "SHADOW" in normalized
        or "MISSION" in normalized
        or "CORRELATION" in normalized
        or "COLLECTOR" in normalized
    )

def _is_unapproved_secret_key(key: str) -> bool:
    normalized = key.upper()
    if normalized == "FACTORY_API_KEY":
        return False
    return (
        normalized.startswith(("AWS_", "AZURE_", "GITHUB_", "GITLAB_"))
        or any(
            marker in normalized
            for marker in (
                "API_KEY",
                "AUTH",
                "CREDENTIAL",
                "PASSWORD",
                "PRIVATE_KEY",
                "SECRET",
                "TOKEN",
            )
        )
    )


def _replacement_environment(
    supplied: Mapping[str, str], home: Path
) -> dict[str, str]:
    replacement: dict[str, str] = {}
    for key, value in supplied.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise InternalSessionError("internal environment is invalid")
        if not key or "=" in key or "\x00" in key or "\x00" in value:
            raise InternalSessionError("internal environment is invalid")
        if (
            not _is_forbidden_environment_key(key)
            and not _is_unapproved_secret_key(key)
            and key.upper() != "HOME"
        ):
            replacement[key] = value
    replacement["HOME"] = str(home)
    replacement["FACTORY_DROID_AUTO_UPDATE_ENABLED"] = "false"
    return replacement


def _transport_alive(transport: _Transport) -> bool:
    try:
        return transport.is_connected and transport.process_alive
    except Exception:
        return False


def _tool_id(tool: object) -> str:
    value = getattr(tool, "id", None)
    if not isinstance(value, str) or not value:
        raise InternalSessionError("internal tool catalog is invalid")
    return value


def _tool_allowed(tool: object) -> bool:
    value = getattr(tool, "allowed", None)
    if type(value) is not bool:
        raise InternalSessionError("internal tool catalog is invalid")
    return value


async def _lock_down_tools(
    session: _Session,
) -> tuple[ToolCatalogEntry, ...]:
    initial = await session.list_tools()
    tool_ids = tuple(sorted(_tool_id(tool) for tool in initial))
    if len(set(tool_ids)) != len(tool_ids):
        raise InternalSessionError("internal tool catalog is invalid")
    await session.update_settings(disabled_tools=tool_ids, restrict_tools=())
    observed = await session.list_tools(
        disabled_tools=tool_ids or None,
        restrict_tools=(),
    )
    observed_entries = tuple(
        sorted(
            (
                ToolCatalogEntry(
                    tool_id=_tool_id(tool),
                    allowed=_tool_allowed(tool),
                )
                for tool in observed
            ),
            key=lambda entry: entry.tool_id,
        )
    )
    observed_ids = tuple(entry.tool_id for entry in observed_entries)
    if (
        len(set(observed_ids)) != len(observed_ids)
        or observed_ids != tool_ids
        or any(entry.allowed for entry in observed_entries)
    ):
        raise InternalSessionError("internal session retained native tools")
    return observed_entries


def _repository_disjoint_cwd(home: Path, repository: Path) -> Path:
    """Create one private cwd which cannot resolve into the target repository."""

    try:
        repository_root = repository.resolve(strict=True)
        workspace = home / "workspace"
        workspace.mkdir(mode=0o700)
        workspace_root = workspace.resolve(strict=True)
    except OSError as error:
        raise InternalSessionError("internal session cwd is unavailable") from error
    if (
        workspace_root == repository_root
        or workspace_root.is_relative_to(repository_root)
        or repository_root.is_relative_to(workspace_root)
    ):
        raise InternalSessionError("internal session cwd overlaps the repository")
    return workspace_root


def _collector_observation(
    observer: CollectorEventCount,
    session: _Session,
) -> tuple[str, tuple[str, ...]]:
    """Measure collector events for this exact internal Droid session."""

    session_id = getattr(session, "id", None)
    if type(session_id) is not str or not session_id:
        raise InternalSessionError("internal session collector identity is unavailable")
    try:
        observation = observer(session_id)
    except Exception as error:
        raise InternalSessionError(
            "internal session collector observation is unavailable"
        ) from error
    if type(observation) is not tuple or len(observation) != 2:
        raise InternalSessionError("internal session collector observation is invalid")
    session_alias, event_ids = observation
    if (
        type(session_alias) is not str
        or not session_alias
        or type(event_ids) is not tuple
        or any(type(event_id) is not str or not event_id for event_id in event_ids)
        or event_ids != tuple(sorted(set(event_ids)))
    ):
        raise InternalSessionError("internal session collector observation is invalid")
    return session_alias, event_ids


async def _close_boundary(session: _Session | None, transport: _Transport) -> None:
    cleanup_errors: list[BaseException] = []
    if session is not None:
        try:
            await asyncio.wait_for(session.close(), timeout=_CLOSE_TIMEOUT_SECONDS)
        except BaseException as error:
            cleanup_errors.append(error)
    try:
        await asyncio.wait_for(transport.close(), timeout=_CLOSE_TIMEOUT_SECONDS)
    except BaseException as error:
        cleanup_errors.append(error)
    try:
        if transport.is_connected or transport.process_alive:
            cleanup_errors.append(
                InternalSessionError("internal process remained alive")
            )
    except BaseException as error:
        cleanup_errors.append(error)
    if cleanup_errors:
        raise InternalSessionError("internal session cleanup failed") from cleanup_errors[0]


def _stream_result_usage(result: object) -> dict[str, object] | None:
    usage = getattr(result, "usage", None)
    if usage is None:
        return None
    input_tokens = getattr(usage, "input_tokens", None)
    output_tokens = getattr(usage, "output_tokens", None)
    if type(input_tokens) is not int or type(output_tokens) is not int:
        return None
    if input_tokens < 0 or output_tokens < 0:
        return None
    return {
        "status": "reported",
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


async def _one_turn(
    session: _Session,
    prompt: str,
    *,
    output_schema: type[object],
    timeout_seconds: int,
) -> object:
    async def _consume() -> object:
        stream = session.stream(
            prompt,
            output=output_schema,
            timeout=timeout_seconds,
        )
        async with stream:  # type: ignore[attr-defined]
            async for _ in stream:  # type: ignore[attr-defined]
                pass
        return stream.result  # type: ignore[attr-defined]

    return await asyncio.wait_for(_consume(), timeout=timeout_seconds)


def _extraction_prompt(request: ExtractionRequest) -> str:
    """Build the exact sealed extraction prompt for one request."""

    return json.dumps(
        {
            "task": (
                "Extract every explicit locator-anchored contract assertion "
                "from every evidence item and the complete trigger payload in "
                "the sealed request. Return one JSON object with a 'claims' "
                "array. Do not use tools."
            ),
            "claim_contract": {
                "subject": (
                    "the contract element asserted, for example "
                    "'payment amount'"
                ),
                "subject_locator": (
                    "copy verbatim from one request.evidence[].locator"
                ),
                "property": (
                    "one short normalized attribute another session "
                    "could contradict, for example 'unit', 'type', or "
                    "'column'. Never describe an edit."
                ),
                "value": (
                    "the asserted value only, for example 'cents', "
                    "'dollars', or 'integer'. Never prose."
                ),
                "unit": "the unit when the value is a quantity, else null",
                "evidence_ids": (
                    "copy verbatim from request.evidence[].evidence_id"
                ),
            },
            "rules": [
                "Assert the resulting contract, never the diff.",
                "Inspect every evidence item; do not stop after the first claim.",
                "Inspect request.trigger_payload.tool_input and tool_response. "
                "For changed-file claims, use the matching repository-change "
                "evidence locator and evidence ID.",
                "Extract explicit contract declarations from patch text and "
                "file content, including declarations added to documentation.",
                f"Return at most {MAX_EXTRACTION_CLAIMS} claims. Prioritize "
                "units, types, schemas, and cross-boundary contracts; omit "
                "identifiers, digests, ordinary test data, and implementation "
                "trivia.",
                "Return a separate claim for every explicit value of a property.",
                "Preserve contradictions. Never merge, reconcile, or omit one "
                "explicit value because another value looks more plausible.",
                "An explicit unit statement in prose is a contract claim. "
                "Do not replace it with a unit inferred from an identifier.",
                'Return {"claims": []} only when no evidence item asserts a '
                "contract value.",
            ],
            "request": request.model_dump(mode="json"),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


class LiveExtractionBroker:
    """One fresh, tool-free droid-sdk extraction session per request."""

    timeout_seconds = _EXTRACTION_TIMEOUT_SECONDS

    def __init__(
        self,
        *,
        executable: str,
        expected_executable_digest: str,
        cwd: Path,
        environment: Mapping[str, str],
        model: str,
        reasoning: str,
        collector_event_count: CollectorEventCount,
        transport_factory: TransportFactory = _default_transport_factory,
        sdk_boundary: SdkBoundary | None = None,
        executable_digest_reader: ExecutableDigestReader = _sha256_executable,
        secure_executable_stager: SecureExecutableStager = stage_bound_file,
        failure_log: Path | None = None,
        forbidden_values: tuple[str, ...] = (),
    ) -> None:
        self._executable = executable
        self._expected_executable_digest = expected_executable_digest
        self._executable_digest_reader = executable_digest_reader
        self._secure_executable_stager = secure_executable_stager
        self._cwd = Path(cwd)
        self._environment = dict(environment)
        self._model = model
        self._reasoning = reasoning
        self._collector_event_count = collector_event_count
        self._transport_factory = transport_factory
        self._sdk_boundary = sdk_boundary or _DroidSdkBoundary()
        self._condition = threading.Condition()
        self._active_worker: _LoopWorker | None = None
        self._active_extraction_started: threading.Event | None = None
        self._active_cleanup_complete: threading.Event | None = None
        self._active_cleanup_succeeded: threading.Event | None = None
        self._request_in_progress = False
        self._aborted = False
        self._prepared: _PreparedExtraction | None = None
        self._preparing = False
        self._preparing_worker: _LoopWorker | None = None
        self._preparing_thread: threading.Thread | None = None
        self._failed_workers: set[_LoopWorker] = set()
        self._cleanup_failed = False
        self._failed_cleanups: list[_PreparationCleanup] = []
        self._inflight_cleanups: list[_PreparationCleanup] = []
        self._prewarm_thread: threading.Thread | None = None
        self._failure_log = Path(failure_log) if failure_log is not None else None
        if any(type(item) is not str or not item for item in forbidden_values):
            raise ValueError("forbidden redaction values must be non-empty strings")
        self._forbidden_values = tuple(dict.fromkeys(forbidden_values))

    def _record_failure(self, stage: str, detail: str) -> None:
        """Persist why one extraction produced no claims. Never raises."""

        try:
            redacted, _ = sanitize_value(
                {"stage": stage, "detail": detail},
                forbidden_values=self._forbidden_values,
            )
            if not isinstance(redacted, Mapping):
                raise TypeError("failure detail did not remain an object")
            safe_stage = str(redacted.get("stage", "unknown"))[:128]
            safe_detail = str(redacted.get("detail", "unavailable"))[:2048]
        except (TypeError, ValueError):
            safe_stage = "unknown"
            safe_detail = "[REDACTED:failure-detail]"
        message = f"shadow-extractor: {safe_stage}: {safe_detail}"
        print(message, file=sys.stderr, flush=True)
        path = self._failure_log
        if path is None:
            return
        try:
            line = json.dumps(
                {
                    "observed_at": int(time.time()),
                    "stage": safe_stage,
                    "detail": safe_detail,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8") + b"\n"
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                os.write(descriptor, line)
            finally:
                os.close(descriptor)
        except (OSError, TypeError, ValueError):
            return

    def _verify_executable(self) -> None:
        _require_executable_digest(
            self._executable,
            self._expected_executable_digest,
            self._executable_digest_reader,
        )

    def _register_inflight_cleanup(
        self,
        *,
        temporary_home: tempfile.TemporaryDirectory[str],
        staged_descriptor: int | None,
        worker: _LoopWorker,
    ) -> _PreparationCleanup:
        cleanup = _PreparationCleanup(
            temporary_home=temporary_home,
            transport=None,
            staged_descriptor=staged_descriptor,
            session=None,
            worker=worker,
        )
        with self._condition:
            self._inflight_cleanups.append(cleanup)
            self._condition.notify_all()
        return cleanup

    def _claim_inflight_cleanup(
        self,
        cleanup: _PreparationCleanup,
        owner: str,
    ) -> bool:
        with self._condition:
            registered = any(
                item is cleanup for item in self._inflight_cleanups
            )
            if not registered or cleanup.cleanup_owner is not None:
                return False
            cleanup.cleanup_owner = owner
            self._condition.notify_all()
            return True

    def _wait_for_inflight_cleanup(
        self,
        worker: _LoopWorker,
        *,
        deadline: float,
    ) -> bool:
        with self._condition:
            completions = tuple(
                cleanup.cleanup_complete
                for cleanup in self._inflight_cleanups
                if cleanup.worker is worker
                and cleanup.cleanup_owner == "coroutine"
            )
        completed = True
        for completion in completions:
            completed = (
                completion.wait(max(0.0, deadline - time.monotonic()))
                and completed
            )
        return completed

    def _release_inflight_cleanup(
        self,
        cleanup: _PreparationCleanup,
    ) -> None:
        with self._condition:
            self._inflight_cleanups = [
                item for item in self._inflight_cleanups if item is not cleanup
            ]
            self._cleanup_failed = bool(
                self._failed_cleanups or self._inflight_cleanups
            )
            cleanup.cleanup_complete.set()
            self._condition.notify_all()

    def _retain_inflight_cleanup(
        self,
        cleanup: _PreparationCleanup,
    ) -> None:
        with self._condition:
            self._inflight_cleanups = [
                item for item in self._inflight_cleanups if item is not cleanup
            ]
            if not any(
                item.temporary_home is cleanup.temporary_home
                for item in self._failed_cleanups
            ):
                self._failed_cleanups.append(cleanup)
            self._cleanup_failed = True
            cleanup.cleanup_owner = None
            cleanup.cleanup_complete.set()
            self._condition.notify_all()

    def _promote_inflight_cleanups(
        self,
        worker: _LoopWorker | None = None,
    ) -> None:
        with self._condition:
            retained = [
                cleanup
                for cleanup in self._inflight_cleanups
                if (worker is None or cleanup.worker is worker)
                and cleanup.cleanup_owner is None
            ]
            if not retained:
                return
            self._inflight_cleanups = [
                cleanup
                for cleanup in self._inflight_cleanups
                if not any(cleanup is item for item in retained)
            ]
            for cleanup in retained:
                cleanup.cleanup_owner = None
                cleanup.cleanup_complete.set()
                if not any(
                    item.temporary_home is cleanup.temporary_home
                    for item in self._failed_cleanups
                ):
                    self._failed_cleanups.append(cleanup)
            self._cleanup_failed = True
            self._condition.notify_all()

    def _retain_failed_cleanup(
        self,
        *,
        temporary_home: tempfile.TemporaryDirectory[str],
        transport: _Transport | None,
        staged_descriptor: int | None,
        session: _Session | None,
        worker: _LoopWorker,
        boundary_closed: bool,
        home_cleaned: bool,
    ) -> None:
        cleanup = _PreparationCleanup(
            temporary_home=temporary_home,
            transport=transport,
            staged_descriptor=staged_descriptor,
            session=session,
            worker=worker,
            boundary_closed=boundary_closed,
            home_cleaned=home_cleaned,
        )
        with self._condition:
            if not any(
                item.temporary_home is temporary_home
                for item in self._failed_cleanups
            ):
                self._failed_cleanups.append(cleanup)
            self._cleanup_failed = True
            self._condition.notify_all()

    def _retry_failed_cleanup(
        self,
        cleanup: _PreparationCleanup,
        *,
        deadline: float,
    ) -> bool:
        with self._condition:
            if not any(item is cleanup for item in self._failed_cleanups):
                return True
            cleanup_complete = cleanup.cleanup_complete
            if cleanup.cleanup_owner is None:
                cleanup.cleanup_owner = "broker"
                cleanup.cleanup_complete.clear()
                owns_cleanup = True
            else:
                owns_cleanup = False
        if not owns_cleanup:
            if not cleanup_complete.wait(
                max(0.0, deadline - time.monotonic())
            ):
                return False
            with self._condition:
                return not any(
                    item is cleanup for item in self._failed_cleanups
                )
        try:
            if not cleanup.boundary_closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                if (
                    cleanup.transport is not None
                    and not _transport_alive(cleanup.transport)
                ):
                    cleanup.boundary_closed = True
                else:
                    try:
                        if cleanup.transport is not None:
                            if not cleanup.worker.alive:
                                return False
                            cleanup.worker.run(
                                _close_boundary(
                                    cleanup.session,
                                    cleanup.transport,
                                ),
                                timeout=remaining,
                            )
                        elif cleanup.staged_descriptor is not None:
                            os.close(cleanup.staged_descriptor)
                    except Exception:
                        if (
                            cleanup.transport is None
                            or _transport_alive(cleanup.transport)
                        ):
                            return False
                    cleanup.boundary_closed = True
            if not cleanup.home_cleaned:
                try:
                    cleanup.temporary_home.cleanup()
                except OSError:
                    return False
                cleanup.home_cleaned = True
            stopped = cleanup.worker.stop(
                timeout=max(0.0, deadline - time.monotonic())
            )
            with self._condition:
                if stopped:
                    self._failed_cleanups = [
                        item
                        for item in self._failed_cleanups
                        if item is not cleanup
                    ]
                    self._failed_workers.discard(cleanup.worker)
                else:
                    self._failed_workers.add(cleanup.worker)
                self._cleanup_failed = bool(
                    self._failed_cleanups or self._inflight_cleanups
                )
                self._condition.notify_all()
            return stopped
        finally:
            with self._condition:
                if cleanup.cleanup_owner == "broker":
                    cleanup.cleanup_owner = None
                cleanup.cleanup_complete.set()
                self._condition.notify_all()

    def prewarm(self) -> bool:
        """Build the next fresh confined session before its request arrives."""

        with self._condition:
            if (
                self._aborted
                or self._cleanup_failed
                or self._failed_workers
                or self._inflight_cleanups
                or self._prepared is not None
                or self._preparing
            ):
                return False
            self._preparing = True
            self._preparing_thread = threading.current_thread()
        try:
            worker = _LoopWorker("shadow-extraction-prewarm")
        except Exception as error:
            with self._condition:
                if self._preparing_thread is threading.current_thread():
                    self._preparing_thread = None
                self._preparing = False
                self._condition.notify_all()
            self._record_failure(
                "prewarm",
                f"{type(error).__name__}: {error}",
            )
            return False
        with self._condition:
            self._preparing_worker = worker
            aborted = self._aborted
            self._condition.notify_all()
        prepared: _PreparedExtraction | None = None
        retained = False
        try:
            if not aborted:
                try:
                    self._verify_executable()
                    prepared = worker.run(
                        asyncio.wait_for(
                            self._prepare_once(worker), timeout=self.timeout_seconds
                        ),
                        timeout=self.timeout_seconds + _CLOSE_TIMEOUT_SECONDS,
                    )
                except Exception as error:
                    self._record_failure(
                        "prewarm", f"{type(error).__name__}: {error}"
                    )
            if prepared is None:
                self._wait_for_inflight_cleanup(
                    worker,
                    deadline=time.monotonic() + _CLOSE_TIMEOUT_SECONDS * 2,
                )
                self._promote_inflight_cleanups(worker)
            else:
                self._release_inflight_cleanup(prepared.preparation_cleanup)
            with self._condition:
                if prepared is not None and not self._aborted:
                    self._prepared = prepared
                    retained = True
            if prepared is None:
                with self._condition:
                    cleanup_retained = any(
                        item.worker is worker
                        for item in (
                            *self._failed_cleanups,
                            *self._inflight_cleanups,
                        )
                    )
                if not cleanup_retained:
                    stopped = worker.stop()
                    with self._condition:
                        if not stopped:
                            self._failed_workers.add(worker)
                return False
            if not retained:
                self._finish_prepared(prepared)
                return False
            return True
        finally:
            with self._condition:
                if self._preparing_worker is worker:
                    self._preparing_worker = None
                if self._preparing_thread is threading.current_thread():
                    self._preparing_thread = None
                self._cleanup_failed = bool(
                    self._failed_cleanups or self._inflight_cleanups
                )
                self._preparing = False
                self._condition.notify_all()

    def _schedule_prewarm(self) -> None:
        """Rebuild the spare session off the request path. Never raises."""

        with self._condition:
            if (
                self._aborted
                or self._cleanup_failed
                or self._failed_workers
                or self._inflight_cleanups
                or self._prepared is not None
                or self._preparing
            ):
                return
            thread = self._prewarm_thread
            if thread is not None and thread.is_alive():
                return
            thread = threading.Thread(
                target=self.prewarm,
                name="shadow-extraction-prewarm",
                daemon=True,
            )
            self._prewarm_thread = thread
            try:
                thread.start()
            except RuntimeError:
                self._prewarm_thread = None

    async def _prepare_once(self, worker: _LoopWorker) -> _PreparedExtraction:
        """Build one confined session on the caller's loop worker."""

        temporary_home = tempfile.TemporaryDirectory(prefix="shadow-extractor-")
        transport: _Transport | None = None
        session: _Session | None = None
        staged_descriptor: int | None = None
        cleanup = self._register_inflight_cleanup(
            temporary_home=temporary_home,
            staged_descriptor=None,
            worker=worker,
        )
        try:
            self._verify_executable()
            home = Path(temporary_home.name)
            home.chmod(0o700)
            workspace = _repository_disjoint_cwd(home, self._cwd)
            staged_descriptor = self._secure_executable_stager(
                Path(self._executable),
                self._expected_executable_digest,
                home,
            )
            with self._condition:
                cleanup.staged_descriptor = staged_descriptor
                self._condition.notify_all()
            environment = _replacement_environment(self._environment, home)
            transport = self._transport_factory(
                staged_descriptor,
                workspace,
                environment,
            )
            with self._condition:
                cleanup.transport = transport
                cleanup.staged_descriptor = None
                self._condition.notify_all()
            staged_descriptor = None
            await transport.connect()
            if not _transport_alive(transport):
                raise InternalSessionError("internal process is not alive")
            session = self._sdk_boundary.create_session(
                cwd=workspace,
                model=self._model,
                reasoning=self._reasoning,
                config=InternalSessionConfig(),
                transport=transport,
            )
            with self._condition:
                cleanup.session = session
                self._condition.notify_all()
            await session.open()
            await _lock_down_tools(session)
            observation = _collector_observation(
                self._collector_event_count,
                session,
            )
            if not _transport_alive(transport) or observation[1]:
                raise InternalSessionError("internal extraction boundary is unsafe")
            return _PreparedExtraction(
                temporary_home=temporary_home,
                transport=transport,
                session=session,
                worker=worker,
                boundary=BoundaryMetadata(
                    factory_home="clean",
                    enabled_tools=(),
                    timeout_seconds=self.timeout_seconds,
                    shadow_activation_stripped=True,
                    mission_correlation_stripped=True,
                    internal_session_alias=observation[0],
                    environment_keys=tuple(sorted(environment)),
                ),
                preparation_cleanup=cleanup,
            )
        except BaseException as error:
            if isinstance(error, asyncio.CancelledError):
                raise
            if not self._claim_inflight_cleanup(cleanup, "coroutine"):
                raise
            boundary_closed = transport is None and staged_descriptor is None
            home_cleaned = False
            try:
                if transport is not None:
                    await _close_boundary(session, transport)
                    boundary_closed = True
                elif staged_descriptor is not None:
                    os.close(staged_descriptor)
                    boundary_closed = True
            finally:
                if transport is not None and not _transport_alive(transport):
                    boundary_closed = True
                with self._condition:
                    cleanup.boundary_closed = boundary_closed
                    self._condition.notify_all()
                try:
                    temporary_home.cleanup()
                    home_cleaned = True
                finally:
                    with self._condition:
                        cleanup.boundary_closed = boundary_closed
                        cleanup.home_cleaned = home_cleaned
                        self._condition.notify_all()
                    if boundary_closed and home_cleaned:
                        self._release_inflight_cleanup(cleanup)
                    else:
                        self._retain_inflight_cleanup(cleanup)
            raise

    def extract(self, request: ExtractionRequest) -> BrokerAttempt:
        with self._condition:
            if (
                self._aborted
                or self._cleanup_failed
                or self._failed_workers
                or self._request_in_progress
                or self._active_worker is not None
            ):
                return BrokerAttempt(boundary={}, output=None)
            self._request_in_progress = True
        try:
            try:
                self._verify_executable()
            except Exception as error:
                self._record_failure(
                    "verify_executable", f"{type(error).__name__}: {error}"
                )
                return BrokerAttempt(boundary={}, output=None)
            prepared = self._take_prepared()
            self._schedule_prewarm()
            with self._condition:
                blocked = (
                    self._cleanup_failed
                    or bool(self._failed_workers)
                    or self._aborted
                )
            if blocked:
                if prepared is not None:
                    self._finish_prepared(prepared)
                return BrokerAttempt(boundary={}, output=None)
            attempt = self._run_request(request, prepared)
            with self._condition:
                cleanup_failed = (
                    self._cleanup_failed or bool(self._failed_workers)
                )
            if cleanup_failed:
                return BrokerAttempt(boundary={}, output=None)
            if (
                prepared is not None
                and attempt.output is None
                and not attempt.timed_out
            ):
                with self._condition:
                    aborted = self._aborted
                if not aborted:
                    # A spare session can expire while it waits for a request.
                    # Never let that lose the claims a fresh session would find.
                    self._record_failure(
                        "prewarm_retry", "prepared session returned no claims"
                    )
                    attempt = self._run_request(request, None)
            result = attempt
        finally:
            with self._condition:
                self._request_in_progress = False
                self._condition.notify_all()
        return result

    def _take_prepared(self) -> _PreparedExtraction | None:
        """Claim the spare session when it is alive and recent enough to use."""

        stale: _PreparedExtraction | None = None
        prepared: _PreparedExtraction | None = None
        with self._condition:
            candidate = self._prepared
            self._prepared = None
            if candidate is not None:
                expired = (
                    time.monotonic() - candidate.prepared_at
                    > _PREWARM_MAX_IDLE_SECONDS
                )
                if expired or not _transport_alive(candidate.transport):
                    stale = candidate
                else:
                    prepared = candidate
        if stale is not None:
            self._finish_prepared(stale)
        return prepared

    def _run_request(
        self,
        request: ExtractionRequest,
        prepared: _PreparedExtraction | None,
    ) -> BrokerAttempt:
        worker = (
            prepared.worker
            if prepared is not None
            else _LoopWorker("shadow-extraction-session")
        )
        extraction_started = threading.Event()
        cleanup_complete = threading.Event()
        cleanup_succeeded = threading.Event()
        model_complete = threading.Event()
        released = False
        with self._condition:
            if self._aborted or self._active_worker is not None:
                released = True
            else:
                self._active_worker = worker
                self._active_extraction_started = extraction_started
                self._active_cleanup_complete = cleanup_complete
                self._active_cleanup_succeeded = cleanup_succeeded
            self._condition.notify_all()
        if released:
            if prepared is None:
                stopped = worker.stop()
                with self._condition:
                    if not stopped:
                        self._failed_workers.add(worker)
            else:
                self._finish_prepared(prepared)
            return BrokerAttempt(boundary={}, output=None)
        attempt = BrokerAttempt(boundary={}, output=None)
        try:
            try:
                coroutine = (
                    self._send_prepared(
                        prepared,
                        request,
                        extraction_started=extraction_started,
                        model_complete=model_complete,
                        cleanup_complete=cleanup_complete,
                        cleanup_succeeded=cleanup_succeeded,
                    )
                    if prepared is not None
                    else self._extract_once(
                        request,
                        worker=worker,
                        extraction_started=extraction_started,
                        model_complete=model_complete,
                        cleanup_complete=cleanup_complete,
                        cleanup_succeeded=cleanup_succeeded,
                    )
                )
                attempt = worker.run(
                    asyncio.wait_for(
                        coroutine,
                        timeout=self.timeout_seconds
                        + _EXTRACTION_CLEANUP_BUDGET_SECONDS,
                    ),
                    timeout=self.timeout_seconds
                    + _EXTRACTION_CLEANUP_BUDGET_SECONDS
                    + _CLOSE_TIMEOUT_SECONDS,
                )
            except (asyncio.TimeoutError, _InternalSessionTimeout):
                if model_complete.is_set():
                    self._record_failure(
                        "cleanup_timeout",
                        "extraction cleanup exceeded its bounded deadline "
                        "after the model turn completed",
                    )
                else:
                    self._record_failure(
                        "timeout",
                        "no confined session completed within the extraction budget",
                    )
                attempt = BrokerAttempt(boundary={}, output=None, timed_out=True)
            except (concurrent.futures.CancelledError, InternalSessionError) as error:
                with self._condition:
                    deliberate = self._aborted
                if not deliberate:
                    self._record_failure(
                        "cleanup_failed"
                        if model_complete.is_set()
                        else "session_boundary",
                        f"{type(error).__name__}: {error}",
                    )
                attempt = BrokerAttempt(boundary={}, output=None)
            except Exception as error:
                self._record_failure(
                    "unexpected", f"{type(error).__name__}: {error}"
                )
                attempt = BrokerAttempt(boundary={}, output=None)
        finally:
            cleanup_confirmed = (
                not extraction_started.is_set() or cleanup_succeeded.is_set()
            )
            with self._condition:
                cleanup_retained = any(
                    item.worker is worker for item in self._failed_cleanups
                )
            stop_attempted = not cleanup_retained
            stopped = worker.stop() if stop_attempted else False
            with self._condition:
                if not cleanup_confirmed and not cleanup_retained:
                    self._cleanup_failed = True
                if stop_attempted and not stopped:
                    self._failed_workers.add(worker)
                elif stopped and self._active_worker is worker:
                    self._active_worker = None
                if stopped and self._active_extraction_started is extraction_started:
                    self._active_extraction_started = None
                if stopped and self._active_cleanup_complete is cleanup_complete:
                    self._active_cleanup_complete = None
                if stopped and self._active_cleanup_succeeded is cleanup_succeeded:
                    self._active_cleanup_succeeded = None
                aborted = self._aborted
                self._condition.notify_all()
        if aborted:
            return BrokerAttempt(boundary={}, output=None)
        return attempt

    async def _send_prepared(
        self,
        prepared: _PreparedExtraction,
        request: ExtractionRequest,
        *,
        extraction_started: threading.Event,
        model_complete: threading.Event,
        cleanup_complete: threading.Event,
        cleanup_succeeded: threading.Event,
    ) -> BrokerAttempt:
        """Send one request on an already-confined session, then close it."""

        extraction_started.set()
        try:
            prompt = _extraction_prompt(request)
            self._verify_executable()
            observation = _collector_observation(
                self._collector_event_count,
                prepared.session,
            )
            if (
                not _transport_alive(prepared.transport)
                or observation != (prepared.boundary.internal_session_alias, ())
            ):
                raise InternalSessionError("internal extraction boundary changed")
            result = await _one_turn(
                prepared.session,
                prompt,
                output_schema=_ExtractionOutput,
                timeout_seconds=self.timeout_seconds,
            )
            model_complete.set()
            self._verify_executable()
            observation = _collector_observation(
                self._collector_event_count,
                prepared.session,
            )
            if observation != (prepared.boundary.internal_session_alias, ()):
                raise InternalSessionError("internal extraction boundary changed")
            return self._decode_turn(result, prepared.transport, prepared.boundary)
        finally:
            boundary_closed = False
            home_cleaned = False
            try:
                await _close_boundary(prepared.session, prepared.transport)
                boundary_closed = True
            finally:
                if not _transport_alive(prepared.transport):
                    boundary_closed = True
                try:
                    prepared.temporary_home.cleanup()
                    home_cleaned = True
                finally:
                    succeeded = boundary_closed and home_cleaned
                    with self._condition:
                        prepared.closing = True
                        prepared.closed = True
                        prepared.close_succeeded = succeeded
                        if self._prepared is prepared:
                            self._prepared = None
                        prepared.close_complete.set()
                        self._condition.notify_all()
                    if not succeeded:
                        self._retain_failed_cleanup(
                            temporary_home=prepared.temporary_home,
                            transport=prepared.transport,
                            staged_descriptor=None,
                            session=prepared.session,
                            worker=prepared.worker,
                            boundary_closed=boundary_closed,
                            home_cleaned=home_cleaned,
                        )
                    if succeeded:
                        cleanup_succeeded.set()
                    cleanup_complete.set()

    def _finish_prepared(self, prepared: _PreparedExtraction) -> bool:
        """Close one unused prepared session exactly once."""

        with self._condition:
            if prepared.closed:
                return prepared.close_succeeded
            if prepared.closing:
                owner = False
            else:
                prepared.closing = True
                owner = True
        if not owner:
            if not prepared.close_complete.wait(_CLOSE_TIMEOUT_SECONDS * 2):
                return False
            return prepared.close_succeeded
        boundary_closed = False
        try:
            prepared.worker.run(
                _close_boundary(prepared.session, prepared.transport),
                timeout=_CLOSE_TIMEOUT_SECONDS * 2,
            )
            boundary_closed = True
        except Exception:
            boundary_closed = not _transport_alive(prepared.transport)
        home_cleaned = False
        try:
            prepared.temporary_home.cleanup()
            home_cleaned = True
        except OSError:
            pass
        cleanup_succeeded = boundary_closed and home_cleaned
        stopped = False
        if cleanup_succeeded:
            stopped = prepared.worker.stop()
        else:
            self._retain_failed_cleanup(
                temporary_home=prepared.temporary_home,
                transport=prepared.transport,
                staged_descriptor=None,
                session=prepared.session,
                worker=prepared.worker,
                boundary_closed=boundary_closed,
                home_cleaned=home_cleaned,
            )
        with self._condition:
            prepared.close_succeeded = cleanup_succeeded and stopped
            prepared.closed = True
            if cleanup_succeeded and not stopped:
                self._failed_workers.add(prepared.worker)
            if self._prepared is prepared:
                self._prepared = None
            prepared.close_complete.set()
            self._condition.notify_all()
            return prepared.close_succeeded

    def _decode_turn(
        self,
        result: object,
        transport: _Transport,
        boundary: BoundaryMetadata | None,
    ) -> BrokerAttempt:
        """Accept only one validated, bounded claim array from one turn."""

        if not _transport_alive(transport) or not getattr(result, "success", False):
            self._record_failure(
                "turn_failed",
                f"error={getattr(result, 'error', None)!r} "
                f"output_validation_error="
                f"{getattr(result, 'output_validation_error', None)!r}",
            )
            return BrokerAttempt(boundary=boundary, output=None)
        try:
            validated = _ExtractionOutput.model_validate(
                getattr(result, "output", None)
            )
            output = [
                item.model_dump(mode="json")
                for item in validated.claims[:MAX_EXTRACTION_CLAIMS]
            ]
            encoded = json.dumps(
                output,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, ValidationError) as error:
            self._record_failure(
                "output_rejected", f"{type(error).__name__}: {error}"
            )
            return BrokerAttempt(boundary=boundary, output=None)
        if len(encoded) > MAX_OUTPUT_BYTES:
            return BrokerAttempt(boundary=boundary, output=None)
        return BrokerAttempt(boundary=boundary, output=output)

    def abort(self) -> bool:
        """Cancel all extraction work and acknowledge only proven cleanup."""

        deadline = time.monotonic() + _CLOSE_TIMEOUT_SECONDS * 3
        with self._condition:
            self._aborted = True
            self._condition.notify_all()
            while (
                (self._preparing and self._preparing_worker is None)
                or (self._request_in_progress and self._active_worker is None)
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            preparing_worker = self._preparing_worker
            preparing_thread = self._preparing_thread
            scheduled_thread = self._prewarm_thread
            worker = self._active_worker
            extraction_started = self._active_extraction_started
            cleanup_complete = self._active_cleanup_complete
            cleanup_succeeded = self._active_cleanup_succeeded
            spare = self._prepared
            self._prepared = None

        if spare is not None:
            self._finish_prepared(spare)

        if preparing_worker is not None:
            preparing_worker.cancel_active(
                timeout=max(0.0, deadline - time.monotonic()),
                completed_is_stopped=True,
            )
        with self._condition:
            while self._preparing:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)

        prewarm_threads = {
            thread
            for thread in (preparing_thread, scheduled_thread)
            if thread is not None and thread is not threading.current_thread()
        }
        for thread in prewarm_threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        prewarm_threads_stopped = all(
            not thread.is_alive() for thread in prewarm_threads
        )
        with self._condition:
            inflight_workers = tuple(
                dict.fromkeys(
                    cleanup.worker for cleanup in self._inflight_cleanups
                )
            )
        for inflight_worker in inflight_workers:
            self._wait_for_inflight_cleanup(
                inflight_worker,
                deadline=deadline,
            )
        self._promote_inflight_cleanups()

        completed = True
        cleanup_finished = (
            extraction_started is None or not extraction_started.is_set()
        )
        if worker is not None:
            completed = worker.cancel_active(
                timeout=max(0.0, deadline - time.monotonic()),
                completed_is_stopped=True,
            )
            if extraction_started is not None and extraction_started.is_set():
                cleanup_finished = bool(
                    cleanup_complete is not None
                    and cleanup_complete.wait(
                        max(0.0, deadline - time.monotonic())
                    )
                )

        with self._condition:
            failed_cleanups = tuple(self._failed_cleanups)
        for failed_cleanup in failed_cleanups:
            self._retry_failed_cleanup(
                failed_cleanup,
                deadline=deadline,
            )

        stopped = worker is None
        cleanup_acknowledged = cleanup_finished
        if worker is not None:
            with self._condition:
                cleanup_remaining = any(
                    item.worker is worker for item in self._failed_cleanups
                )
            cleanup_acknowledged = cleanup_finished and not cleanup_remaining
            if completed and cleanup_acknowledged:
                stopped = worker.stop(
                    timeout=max(0.0, deadline - time.monotonic())
                )
            else:
                stopped = False
            with self._condition:
                if stopped and self._active_worker is worker:
                    self._active_worker = None
                if stopped and self._active_extraction_started is extraction_started:
                    self._active_extraction_started = None
                if stopped and self._active_cleanup_complete is cleanup_complete:
                    self._active_cleanup_complete = None
                if stopped and self._active_cleanup_succeeded is cleanup_succeeded:
                    self._active_cleanup_succeeded = None
                if stopped:
                    self._failed_workers.discard(worker)
                elif not cleanup_remaining:
                    self._failed_workers.add(worker)
                self._condition.notify_all()

        with self._condition:
            failed_workers = tuple(self._failed_workers)
        for failed_worker in failed_workers:
            if failed_worker.stop(
                timeout=max(0.0, deadline - time.monotonic())
            ):
                with self._condition:
                    self._failed_workers.discard(failed_worker)
                    if self._active_worker is failed_worker:
                        self._active_worker = None
                        self._active_extraction_started = None
                        self._active_cleanup_complete = None
                        self._active_cleanup_succeeded = None

        with self._condition:
            while self._request_in_progress:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)

        with self._condition:
            if (
                self._prewarm_thread is not None
                and not self._prewarm_thread.is_alive()
            ):
                self._prewarm_thread = None
            all_stopped = (
                not self._preparing
                and self._preparing_worker is None
                and self._preparing_thread is None
                and not self._request_in_progress
                and self._active_worker is None
                and not self._failed_workers
                and not self._failed_cleanups
                and not self._inflight_cleanups
                and (
                    self._prewarm_thread is None
                    or not self._prewarm_thread.is_alive()
                )
            )
            self._cleanup_failed = bool(
                self._failed_cleanups or self._inflight_cleanups
            )
            cleanup_failed = self._cleanup_failed
        return (
            prewarm_threads_stopped
            and completed
            and cleanup_acknowledged
            and stopped
            and all_stopped
            and not cleanup_failed
        )

    async def _extract_once(
        self,
        request: ExtractionRequest,
        worker: _LoopWorker,
        *,
        extraction_started: threading.Event,
        model_complete: threading.Event,
        cleanup_complete: threading.Event,
        cleanup_succeeded: threading.Event,
    ) -> BrokerAttempt:
        extraction_started.set()
        temporary_home = tempfile.TemporaryDirectory(prefix="shadow-extractor-")
        transport: _Transport | None = None
        session: _Session | None = None
        boundary: BoundaryMetadata | None = None
        staged_descriptor: int | None = None
        try:
            self._verify_executable()
            home = Path(temporary_home.name)
            home.chmod(0o700)
            workspace = _repository_disjoint_cwd(home, self._cwd)
            staged_descriptor = self._secure_executable_stager(
                Path(self._executable),
                self._expected_executable_digest,
                home,
            )
            environment = _replacement_environment(self._environment, home)
            transport = self._transport_factory(
                staged_descriptor,
                workspace,
                environment,
            )
            staged_descriptor = None
            await transport.connect()
            if not _transport_alive(transport):
                raise InternalSessionError("internal process is not alive")
            config = InternalSessionConfig()
            session = self._sdk_boundary.create_session(
                cwd=workspace,
                model=self._model,
                reasoning=self._reasoning,
                config=config,
                transport=transport,
            )
            await session.open()
            await _lock_down_tools(session)
            observation = _collector_observation(
                self._collector_event_count,
                session,
            )
            if not _transport_alive(transport) or observation[1]:
                raise InternalSessionError("internal extraction boundary is unsafe")
            boundary = BoundaryMetadata(
                factory_home="clean",
                enabled_tools=(),
                timeout_seconds=self.timeout_seconds,
                shadow_activation_stripped=True,
                mission_correlation_stripped=True,
                internal_session_alias=observation[0],
                environment_keys=tuple(sorted(environment)),
            )
            prompt = _extraction_prompt(request)
            self._verify_executable()
            observation = _collector_observation(
                self._collector_event_count,
                session,
            )
            if (
                not _transport_alive(transport)
                or observation != (boundary.internal_session_alias, ())
            ):
                raise InternalSessionError("internal extraction boundary changed")
            result = await _one_turn(
                session,
                prompt,
                output_schema=_ExtractionOutput,
                timeout_seconds=self.timeout_seconds,
            )
            model_complete.set()
            self._verify_executable()
            observation = _collector_observation(
                self._collector_event_count,
                session,
            )
            if observation != (boundary.internal_session_alias, ()):
                raise InternalSessionError("internal extraction boundary changed")
            return self._decode_turn(result, transport, boundary)
        finally:
            boundary_closed = transport is None and staged_descriptor is None
            home_cleaned = False
            try:
                if transport is not None:
                    await _close_boundary(session, transport)
                    boundary_closed = True
                elif staged_descriptor is not None:
                    os.close(staged_descriptor)
                    boundary_closed = True
            finally:
                if transport is not None and not _transport_alive(transport):
                    boundary_closed = True
                try:
                    temporary_home.cleanup()
                    home_cleaned = True
                finally:
                    if boundary_closed and home_cleaned:
                        cleanup_succeeded.set()
                    else:
                        self._retain_failed_cleanup(
                            temporary_home=temporary_home,
                            transport=transport,
                            staged_descriptor=staged_descriptor,
                            session=session,
                            worker=worker,
                            boundary_closed=boundary_closed,
                            home_cleaned=home_cleaned,
                        )
                    cleanup_complete.set()


class LiveProbeBroker:
    """Two-step fresh Droid probe with mandatory prepared-session cleanup."""

    timeout_seconds = _PROBE_TIMEOUT_SECONDS

    def __init__(
        self,
        *,
        executable: str,
        expected_executable_digest: str,
        cwd: Path,
        environment: Mapping[str, str],
        model: str,
        reasoning: str,
        collector_event_count: CollectorEventCount,
        transport_factory: TransportFactory = _default_transport_factory,
        sdk_boundary: SdkBoundary | None = None,
        executable_digest_reader: ExecutableDigestReader = _sha256_executable,
        secure_executable_stager: SecureExecutableStager = stage_bound_file,
    ) -> None:
        self._executable = executable
        self._expected_executable_digest = expected_executable_digest
        self._executable_digest_reader = executable_digest_reader
        self._secure_executable_stager = secure_executable_stager
        self._cwd = Path(cwd)
        self._environment = dict(environment)
        self._model = model
        self._reasoning = reasoning
        self._collector_event_count = collector_event_count
        self._transport_factory = transport_factory
        self._sdk_boundary = sdk_boundary or _DroidSdkBoundary()
        self._condition = threading.Condition()
        self._preparing_worker: _LoopWorker | None = None
        self._prepared: _PreparedProbe | None = None
        self._active: _PreparedProbe | None = None
        self._aborted = False
        self._inflight_cleanups: list[_PreparationCleanup] = []

    def _verify_executable(self) -> None:
        _require_executable_digest(
            self._executable,
            self._expected_executable_digest,
            self._executable_digest_reader,
        )


    def _register_inflight_cleanup(
        self,
        *,
        temporary_home: tempfile.TemporaryDirectory[str],
        staged_descriptor: int | None,
        worker: _LoopWorker,
    ) -> _PreparationCleanup:
        cleanup = _PreparationCleanup(
            temporary_home=temporary_home,
            transport=None,
            staged_descriptor=staged_descriptor,
            session=None,
            worker=worker,
        )
        with self._condition:
            self._inflight_cleanups.append(cleanup)
            self._condition.notify_all()
        return cleanup

    def _claim_inflight_cleanup(
        self,
        cleanup: _PreparationCleanup,
        owner: str,
    ) -> bool:
        with self._condition:
            registered = any(
                item is cleanup for item in self._inflight_cleanups
            )
            if not registered or cleanup.cleanup_owner is not None:
                return False
            cleanup.cleanup_owner = owner
            self._condition.notify_all()
            return True

    def _wait_for_inflight_cleanup(
        self,
        worker: _LoopWorker,
        *,
        deadline: float,
    ) -> bool:
        with self._condition:
            completions = tuple(
                cleanup.cleanup_complete
                for cleanup in self._inflight_cleanups
                if cleanup.worker is worker
                and cleanup.cleanup_owner == "coroutine"
            )
        completed = True
        for completion in completions:
            completed = (
                completion.wait(max(0.0, deadline - time.monotonic()))
                and completed
            )
        return completed

    def _release_inflight_cleanup(
        self,
        cleanup: _PreparationCleanup,
    ) -> None:
        with self._condition:
            self._inflight_cleanups = [
                item for item in self._inflight_cleanups if item is not cleanup
            ]
            cleanup.cleanup_complete.set()
            self._condition.notify_all()

    def _retry_inflight_cleanup(
        self,
        cleanup: _PreparationCleanup,
        *,
        deadline: float,
    ) -> bool:
        with self._condition:
            registered = any(
                item is cleanup for item in self._inflight_cleanups
            )
            owner = cleanup.cleanup_owner
        if not registered:
            return True
        if owner == "coroutine":
            if not cleanup.cleanup_complete.wait(
                max(0.0, deadline - time.monotonic())
            ):
                return False
            with self._condition:
                if not any(
                    item is cleanup for item in self._inflight_cleanups
                ):
                    return True
                cleanup.cleanup_owner = None
        if not self._claim_inflight_cleanup(cleanup, "broker"):
            return False
        succeeded = False
        try:
            if not cleanup.boundary_closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                if (
                    cleanup.transport is not None
                    and not _transport_alive(cleanup.transport)
                ):
                    cleanup.boundary_closed = True
                else:
                    try:
                        if cleanup.transport is not None:
                            if not cleanup.worker.alive:
                                return False
                            cleanup.worker.run(
                                _close_boundary(
                                    cleanup.session,
                                    cleanup.transport,
                                ),
                                timeout=remaining,
                            )
                        elif cleanup.staged_descriptor is not None:
                            os.close(cleanup.staged_descriptor)
                    except Exception:
                        if (
                            cleanup.transport is None
                            or _transport_alive(cleanup.transport)
                        ):
                            return False
                    cleanup.boundary_closed = True
            if not cleanup.home_cleaned:
                try:
                    cleanup.temporary_home.cleanup()
                except OSError:
                    return False
                cleanup.home_cleaned = True
            stopped = cleanup.worker.stop(
                timeout=max(0.0, deadline - time.monotonic())
            )
            if stopped:
                self._release_inflight_cleanup(cleanup)
                succeeded = True
            return stopped
        finally:
            if not succeeded:
                with self._condition:
                    if cleanup.cleanup_owner == "broker":
                        cleanup.cleanup_owner = None
                    self._condition.notify_all()

    def prepare(self) -> ProbeBoundary:
        self._verify_executable()
        worker = _LoopWorker("shadow-probe-session")
        with self._condition:
            if (
                self._aborted
                or self._preparing_worker is not None
                or self._inflight_cleanups
                or self._prepared is not None
                or self._active is not None
            ):
                worker.stop()
                raise InternalSessionError("an internal probe is already prepared")
            self._preparing_worker = worker
            self._condition.notify_all()
        try:
            prepared = worker.run(
                asyncio.wait_for(
                    self._prepare_once(worker), timeout=self.timeout_seconds
                ),
                timeout=self.timeout_seconds + _CLOSE_TIMEOUT_SECONDS,
            )
        except BaseException as error:
            with self._condition:
                cleanups = tuple(
                    cleanup
                    for cleanup in self._inflight_cleanups
                    if cleanup.worker is worker
                )
            cleanup_deadline = time.monotonic() + _CLOSE_TIMEOUT_SECONDS * 2
            self._wait_for_inflight_cleanup(
                worker,
                deadline=cleanup_deadline,
            )
            if cleanups:
                for cleanup in cleanups:
                    self._retry_inflight_cleanup(
                        cleanup,
                        deadline=cleanup_deadline,
                    )
            else:
                worker.stop()
            with self._condition:
                if self._preparing_worker is worker:
                    self._preparing_worker = None
                self._condition.notify_all()
            raise InternalSessionError("internal probe preparation failed") from error
        self._release_inflight_cleanup(prepared.preparation_cleanup)
        with self._condition:
            aborted = self._aborted
            if not aborted:
                self._prepared = prepared
                self._preparing_worker = None
                self._condition.notify_all()
        if aborted:
            self._finish_prepared(prepared)
            with self._condition:
                if self._preparing_worker is worker:
                    self._preparing_worker = None
                self._condition.notify_all()
            raise InternalSessionError("internal probe preparation was aborted")
        return prepared.boundary

    async def _prepare_once(self, worker: _LoopWorker) -> _PreparedProbe:
        temporary_home = tempfile.TemporaryDirectory(prefix="shadow-probe-")
        transport: _Transport | None = None
        session: _Session | None = None
        staged_descriptor: int | None = None
        cleanup = self._register_inflight_cleanup(
            temporary_home=temporary_home,
            staged_descriptor=None,
            worker=worker,
        )
        try:
            self._verify_executable()
            home = Path(temporary_home.name)
            home.chmod(0o700)
            workspace = _repository_disjoint_cwd(home, self._cwd)
            staged_descriptor = self._secure_executable_stager(
                Path(self._executable),
                self._expected_executable_digest,
                home,
            )
            with self._condition:
                cleanup.staged_descriptor = staged_descriptor
                self._condition.notify_all()
            environment = _replacement_environment(self._environment, home)
            transport = self._transport_factory(
                staged_descriptor,
                workspace,
                environment,
            )
            with self._condition:
                cleanup.transport = transport
                cleanup.staged_descriptor = None
                self._condition.notify_all()
            staged_descriptor = None
            await transport.connect()
            if not _transport_alive(transport):
                raise InternalSessionError("internal process is not alive")
            config = InternalSessionConfig()
            session = self._sdk_boundary.create_session(
                cwd=workspace,
                model=self._model,
                reasoning=self._reasoning,
                config=config,
                transport=transport,
            )
            with self._condition:
                cleanup.session = session
                self._condition.notify_all()
            await session.open()
            observed_tools = await _lock_down_tools(session)
            observation = _collector_observation(
                self._collector_event_count,
                session,
            )
            if not _transport_alive(transport) or observation[1]:
                raise InternalSessionError("internal probe boundary is unsafe")
            boundary = ProbeBoundary(
                factory_home="clean",
                timeout_seconds=self.timeout_seconds,
                shadow_activation_stripped=True,
                mission_correlation_stripped=True,
                internal_session_alias=observation[0],
                environment_keys=tuple(sorted(environment)),
                list_tools_observed=True,
                observed_tools=observed_tools,
                enabled_tools=(),
                collector_event_count=len(observation[1]),
                collector_events=observation[1],
            )
            return _PreparedProbe(
                temporary_home=temporary_home,
                transport=transport,
                session=session,
                worker=worker,
                boundary=boundary,
                preparation_cleanup=cleanup,
            )
        except BaseException as error:
            if isinstance(error, asyncio.CancelledError):
                raise
            if not self._claim_inflight_cleanup(cleanup, "coroutine"):
                raise
            boundary_closed = transport is None and staged_descriptor is None
            home_cleaned = False
            try:
                if transport is not None:
                    await _close_boundary(session, transport)
                    boundary_closed = True
                elif staged_descriptor is not None:
                    os.close(staged_descriptor)
                    boundary_closed = True
            finally:
                if transport is not None and not _transport_alive(transport):
                    boundary_closed = True
                with self._condition:
                    cleanup.boundary_closed = boundary_closed
                    self._condition.notify_all()
                try:
                    temporary_home.cleanup()
                    home_cleaned = True
                finally:
                    with self._condition:
                        cleanup.boundary_closed = boundary_closed
                        cleanup.home_cleaned = home_cleaned
                        cleanup.cleanup_complete.set()
                        self._condition.notify_all()
            raise

    def send(self, snapshot: ProbeSnapshot) -> ProbeAttempt:
        with self._condition:
            prepared = self._prepared
            if self._aborted or prepared is None:
                raise InternalSessionError("internal probe was not prepared")
            self._prepared = None
            self._active = prepared
        attempt = ProbeAttempt(snapshot_digest=snapshot.digest, output=None)
        cleanup_succeeded = False
        try:
            try:
                attempt = prepared.worker.run(
                    asyncio.wait_for(
                        self._send_once(prepared, snapshot),
                        timeout=self.timeout_seconds,
                    ),
                    timeout=self.timeout_seconds + _CLOSE_TIMEOUT_SECONDS,
                )
            except (asyncio.TimeoutError, _InternalSessionTimeout):
                attempt = ProbeAttempt(
                    snapshot_digest=snapshot.digest,
                    output=None,
                    timed_out=True,
                )
            except concurrent.futures.CancelledError:
                attempt = ProbeAttempt(snapshot_digest=snapshot.digest, output=None)
            except InternalSessionError:
                raise
            except Exception:
                attempt = ProbeAttempt(snapshot_digest=snapshot.digest, output=None)
        finally:
            cleanup_succeeded = self._finish_prepared(prepared)
        if not cleanup_succeeded:
            raise InternalSessionError("internal probe cleanup failed")
        with self._condition:
            if self._aborted:
                return ProbeAttempt(snapshot_digest=snapshot.digest, output=None)
        return attempt

    async def _send_once(
        self, prepared: _PreparedProbe, snapshot: ProbeSnapshot
    ) -> ProbeAttempt:
        self._verify_executable()
        observation = _collector_observation(
            self._collector_event_count,
            prepared.session,
        )
        if (
            not _transport_alive(prepared.transport)
            or observation != (prepared.boundary.internal_session_alias, ())
        ):
            raise InternalSessionError("internal probe boundary changed")
        prompt = json.dumps(
            {
                "task": (
                    "Independently assess the sealed risk snapshot. Cite only "
                    "authoritative evidence in the snapshot and do not use tools."
                ),
                "snapshot": snapshot.model_dump(mode="json"),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        observation = _collector_observation(
            self._collector_event_count,
            prepared.session,
        )
        if (
            not _transport_alive(prepared.transport)
            or observation != (prepared.boundary.internal_session_alias, ())
        ):
            raise InternalSessionError("internal probe boundary changed")
        result = await _one_turn(
            prepared.session,
            prompt,
            output_schema=ProbeResult,
            timeout_seconds=self.timeout_seconds,
        )
        self._verify_executable()
        observation = _collector_observation(
            self._collector_event_count,
            prepared.session,
        )
        if observation != (prepared.boundary.internal_session_alias, ()):
            raise InternalSessionError("internal probe boundary changed")
        usage = _stream_result_usage(result)
        if not _transport_alive(prepared.transport) or not getattr(
            result, "success", False
        ):
            return ProbeAttempt(
                snapshot_digest=snapshot.digest,
                output=None,
                usage=usage,
            )
        try:
            output = ProbeResult.model_validate(
                getattr(result, "output", None)
            ).model_dump_json()
        except (TypeError, ValueError, ValidationError):
            return ProbeAttempt(
                snapshot_digest=snapshot.digest,
                output=None,
                usage=usage,
            )
        if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
            return ProbeAttempt(
                snapshot_digest=snapshot.digest,
                output=None,
                usage=usage,
            )
        return ProbeAttempt(
            snapshot_digest=snapshot.digest,
            output=output,
            usage=usage,
        )

    def abort(self) -> bool:
        """Stop preparation or a prepared/active turn and acknowledge cleanup."""

        deadline = time.monotonic() + _CLOSE_TIMEOUT_SECONDS * 3
        with self._condition:
            self._aborted = True
            preparing_worker = self._preparing_worker
            prepared = self._prepared
            active = self._active
            self._prepared = None
        acknowledged = True
        if active is not None:
            acknowledged = active.worker.cancel_active(
                timeout=max(0.0, deadline - time.monotonic())
            )
            if not acknowledged:
                return False
            acknowledged = self._finish_prepared(active)
        elif prepared is not None:
            acknowledged = self._finish_prepared(prepared)
        elif preparing_worker is not None:
            acknowledged = preparing_worker.cancel_active(
                timeout=max(0.0, deadline - time.monotonic()),
                completed_is_stopped=True,
            )
            with self._condition:
                while self._preparing_worker is preparing_worker:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._condition.wait(remaining)
        with self._condition:
            inflight_cleanups = tuple(self._inflight_cleanups)
        inflight_results = tuple(
            self._retry_inflight_cleanup(cleanup, deadline=deadline)
            for cleanup in inflight_cleanups
        )
        inflight_acknowledged = all(inflight_results)
        with self._condition:
            stopped = (
                self._preparing_worker is None
                and self._prepared is None
                and self._active is None
                and not self._inflight_cleanups
            )
        return acknowledged and inflight_acknowledged and stopped

    def _finish_prepared(self, prepared: _PreparedProbe) -> bool:
        with self._condition:
            if prepared.closed:
                return prepared.close_succeeded
            if prepared.closing:
                owner = False
            else:
                prepared.closing = True
                owner = True
        if not owner:
            if not prepared.close_complete.wait(_CLOSE_TIMEOUT_SECONDS * 2):
                return False
            return prepared.close_succeeded
        close_succeeded = True
        try:
            prepared.worker.run(
                _close_boundary(prepared.session, prepared.transport),
                timeout=_CLOSE_TIMEOUT_SECONDS * 2,
            )
        except Exception:
            close_succeeded = False
        try:
            prepared.temporary_home.cleanup()
        except OSError:
            close_succeeded = False
        stopped = prepared.worker.stop()
        with self._condition:
            prepared.close_succeeded = close_succeeded and stopped
            prepared.closed = True
            if self._prepared is prepared:
                self._prepared = None
            if self._active is prepared:
                self._active = None
            prepared.close_complete.set()
            self._condition.notify_all()
            return prepared.close_succeeded



__all__ = [
    "InternalSessionConfig",
    "InternalSessionError",
    "LiveExtractionBroker",
    "LiveProbeBroker",
    "ReplacementEnvironmentTransport",
    "SdkBoundary",
    "sealed_descriptor_path",
    "stage_bound_file",
]
