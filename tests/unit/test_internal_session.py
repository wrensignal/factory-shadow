from __future__ import annotations

import asyncio
import concurrent.futures
import errno
import hashlib
import os
import stat
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from shadow_mission import internal_session
from shadow_mission.extractor import BoundaryMetadata, BrokerAttempt, ExtractionRequest
from shadow_mission.internal_session import (
    InternalSessionConfig,
    InternalSessionError,
    LiveExtractionBroker,
    LiveProbeBroker,
    ReplacementEnvironmentTransport,
    sealed_descriptor_path,
    _LoopWorker,
    stage_bound_file,
)
from shadow_mission.probe import (
    ProbeBoundary,
    InMemoryProbeBoundaryStateStore,
    ProbeClaim,
    ProbeEvidenceMetadata,
    ProbeResult,
    ProbeSnapshot,
    ProbeBoundaryState,
    ProbeRunner,
)


class FakeTransport:
    def __init__(
        self, *, fail_connect: bool = False, connect_action: object = None
    ) -> None:
        self.connected = False
        self.alive = False
        self.fail_connect = fail_connect
        self.connect_action = connect_action
        self.close_count = 0
        self.executable_path: Path | None = None
        self.executable_existed_at_close: bool | None = None
        self.executable_descriptor: int | None = None

    @property
    def is_connected(self) -> bool:
        return self.connected and self.alive

    @property
    def process_alive(self) -> bool:
        return self.alive

    async def connect(self) -> None:
        if self.fail_connect:
            raise OSError("sealed transport detail")
        try:
            if callable(self.connect_action):
                self.connect_action()
            self.connected = True
            self.alive = True
        finally:
            self._close_executable_descriptor()

    async def send(self, message: str) -> None:
        del message

    async def read_messages(self) -> Any:
        if False:
            yield {}

    async def close(self) -> None:
        if self.executable_path is not None:
            self.executable_existed_at_close = self.executable_path.exists()
        self._close_executable_descriptor()
        self.close_count += 1
        self.connected = False
        self.alive = False

    def _close_executable_descriptor(self) -> None:
        descriptor = self.executable_descriptor
        if descriptor is None:
            return
        self.executable_descriptor = None
        os.close(descriptor)


class FakeStream:
    def __init__(self, result: object, *, timeout: bool = False) -> None:
        self.result = result
        self._timeout = timeout

    async def __aenter__(self) -> "FakeStream":
        if self._timeout:
            raise asyncio.TimeoutError
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    def __aiter__(self) -> "FakeStream":
        return self

    async def __anext__(self) -> object:
        raise StopAsyncIteration


class BlockingCancellableStream:
    def __init__(self, result: object) -> None:
        self.result = result
        self.entered = threading.Event()
        self.cancelled = threading.Event()

    async def __aenter__(self) -> "BlockingCancellableStream":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    def __aiter__(self) -> "BlockingCancellableStream":
        return self

    async def __anext__(self) -> object:
        self.entered.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        raise StopAsyncIteration



class FakeSession:
    def __init__(
        self,
        *,
        session_id: str = "internal-session-test",
        initial_tools: tuple[str, ...] = (),
        remaining_tools: tuple[str, ...] = (),
        remaining_allowed: bool = True,
        output: object = None,
        success: bool = True,
        timeout: bool = False,
        die_after_lockdown: bool = False,
    ) -> None:
        self.id = session_id
        self.initial_tools = initial_tools
        self.remaining_tools = remaining_tools
        self.remaining_allowed = remaining_allowed
        self.result = SimpleNamespace(success=success, output=output, usage=None)
        self.timeout = timeout
        self.die_after_lockdown = die_after_lockdown
        self.transport: FakeTransport | None = None
        self.events: list[object] = []
        self.prompts: list[str] = []
        self.stream_options: list[dict[str, object]] = []
        self.close_count = 0
        self._list_count = 0

    async def open(self) -> None:
        self.events.append("open")

    async def close(self) -> None:
        self.close_count += 1
        self.events.append("close")

    async def list_tools(self, **options: object) -> list[object]:
        self._list_count += 1
        self.events.append(("list", dict(options)))
        names = self.initial_tools if self._list_count == 1 else self.remaining_tools
        if self._list_count == 2 and self.die_after_lockdown:
            assert self.transport is not None
            self.transport.alive = False
        allowed = True if self._list_count == 1 else self.remaining_allowed
        return [SimpleNamespace(id=name, allowed=allowed) for name in names]

    async def update_settings(self, **settings: object) -> object:
        self.events.append(("update", dict(settings)))
        return object()

    def stream(self, prompt: str, **options: object) -> FakeStream:
        self.events.append("stream")
        self.prompts.append(prompt)
        self.stream_options.append(dict(options))
        return FakeStream(self.result, timeout=self.timeout)


class BlockingSession(FakeSession):
    def __init__(self, *, output: object) -> None:
        super().__init__(output=output)
        self.blocking_stream = BlockingCancellableStream(self.result)

    def stream(
        self, prompt: str, **options: object
    ) -> BlockingCancellableStream:
        self.events.append("stream")
        self.prompts.append(prompt)
        self.stream_options.append(dict(options))
        return self.blocking_stream


class BlockingOpenSession(FakeSession):
    def __init__(self, *, output: object) -> None:
        super().__init__(output=output)
        self.open_entered = threading.Event()
        self.open_cancelled = threading.Event()

    async def open(self) -> None:
        self.events.append("open")
        self.open_entered.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.open_cancelled.set()
            raise


class FakeSdkBoundary:
    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.calls: list[dict[str, object]] = []

    def create_session(self, **values: object) -> FakeSession:
        self.calls.append(dict(values))
        transport = values["transport"]
        assert isinstance(transport, FakeTransport)
        self.session.transport = transport
        self.session.events.append(("create", values["config"]))
        return self.session


class FakeSecureStager:
    def __init__(self, payload: bytes = b"fake approved Droid") -> None:
        self.payload = payload
        self.calls: list[tuple[Path, str, Path]] = []

    def __call__(
        self, source: Path, expected_digest: str, private_home: Path
    ) -> int:
        self.calls.append((source, expected_digest, private_home))
        staged = private_home / "droid"
        staged.write_bytes(self.payload)
        staged.chmod(0o500)
        return os.open(
            staged,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )


class FakeTransportFactory:
    def __init__(
        self, *, fail_connect: bool = False, connect_action: object = None
    ) -> None:
        self.fail_connect = fail_connect
        self.connect_action = connect_action
        self.environments: list[dict[str, str]] = []
        self.cwds: list[Path] = []
        self.executables: list[Path] = []
        self.executable_bytes: list[bytes] = []
        self.executable_modes: list[int] = []
        self.transports: list[FakeTransport] = []

    def __call__(
        self,
        executable_descriptor: int,
        cwd: Path,
        environment: object,
    ) -> FakeTransport:
        assert cwd.is_absolute()
        self.cwds.append(cwd)
        assert isinstance(environment, dict)
        staged = Path(environment["HOME"]) / "droid"
        assert staged.is_absolute()
        assert staged.parent == Path(environment["HOME"])
        metadata = os.fstat(executable_descriptor)
        self.environments.append(dict(environment))
        self.executables.append(
            Path("/proc/self/fd") / str(executable_descriptor)
            if sys.platform.startswith("linux")
            else staged
        )
        self.executable_bytes.append(
            os.pread(executable_descriptor, metadata.st_size, 0)
        )
        self.executable_modes.append(stat.S_IMODE(metadata.st_mode))
        transport = FakeTransport(
            fail_connect=self.fail_connect,
            connect_action=self.connect_action,
        )
        transport.executable_path = staged if staged.exists() else None
        transport.executable_descriptor = executable_descriptor
        self.transports.append(transport)
        return transport


class RetainedDescriptorTransport(FakeTransport):
    def __init__(self, *, close_failures: int) -> None:
        super().__init__()
        self.close_failures = close_failures

    async def connect(self) -> None:
        self.connected = True
        self.alive = True

    async def close(self) -> None:
        if self.close_failures:
            self.close_failures -= 1
            raise OSError("sealed cleanup detail")
        await super().close()


class RetainedDescriptorFactory(FakeTransportFactory):
    def __init__(self, *, close_failures: int) -> None:
        super().__init__()
        self.close_failures = close_failures

    def __call__(
        self,
        executable_descriptor: int,
        cwd: Path,
        environment: object,
    ) -> FakeTransport:
        original = super().__call__(
            executable_descriptor,
            cwd,
            environment,
        )
        transport = RetainedDescriptorTransport(
            close_failures=self.close_failures
        )
        transport.executable_path = original.executable_path
        transport.executable_descriptor = original.executable_descriptor
        original.executable_descriptor = None
        self.transports[-1] = transport
        return transport


def abandonment_worker_type() -> tuple[
    type[_LoopWorker],
    list[_LoopWorker],
]:
    instances: list[_LoopWorker] = []

    class AbandonBeforeCleanupWorker(_LoopWorker):
        def __init__(self, name: str) -> None:
            self._abandon_requested = False
            self._replacement_ready = threading.Event()
            self._replacement_stop = threading.Event()
            self._abandoned: list[
                tuple[
                    asyncio.AbstractEventLoop,
                    tuple[asyncio.Task[Any], ...],
                ]
            ] = []
            super().__init__(name)
            instances.append(self)

        def _serve(self) -> None:
            asyncio.set_event_loop(self._loop)
            self._ready.set()
            try:
                self._loop.run_forever()
                if self._abandon_requested:
                    abandoned_loop = self._loop
                    self._abandoned.append(
                        (
                            abandoned_loop,
                            tuple(asyncio.all_tasks(abandoned_loop)),
                        )
                    )
                    self._replacement_ready.set()
                    self._replacement_stop.wait()
                else:
                    pending = asyncio.all_tasks(self._loop)
                    for task in pending:
                        task.cancel()
                    if pending:
                        self._loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                    self._loop.close()
            finally:
                self._stopped.set()
                with self._future_condition:
                    self._future_condition.notify_all()

        def run(self, coroutine: object, *, timeout: float) -> Any:
            if not self._replacement_ready.is_set():
                return super().run(coroutine, timeout=timeout)
            del timeout
            return asyncio.run(coroutine)

        def cancel_active(
            self,
            *,
            timeout: float = internal_session._CLOSE_TIMEOUT_SECONDS,
            completed_is_stopped: bool = False,
        ) -> bool:
            del completed_is_stopped
            with self._future_condition:
                future = self._active_future
            if future is None:
                return False

            def abandon() -> None:
                self._abandon_requested = True
                self._loop.stop()
                future.cancel()

            self._loop.call_soon_threadsafe(abandon)
            return self._replacement_ready.wait(timeout)

        def stop(
            self,
            *,
            timeout: float = internal_session._CLOSE_TIMEOUT_SECONDS,
        ) -> bool:
            if not self._replacement_ready.is_set():
                return super().stop(timeout=timeout)
            self._replacement_stop.set()
            self._thread.join(timeout=timeout)
            return self._stopped.is_set() and not self._thread.is_alive()

        def dispose_abandoned(self) -> None:
            if self.alive:
                self.stop()
            for loop, tasks in self._abandoned:
                if loop.is_closed():
                    continue
                asyncio.set_event_loop(loop)
                for task in tasks:
                    task.cancel()
                if tasks:
                    loop.run_until_complete(
                        asyncio.gather(*tasks, return_exceptions=True)
                    )
                loop.close()
            self._abandoned.clear()
            asyncio.set_event_loop(None)

    return AbandonBeforeCleanupWorker, instances


def quiet_collector_observation(
    session_id: str,
) -> tuple[str, tuple[str, ...]]:
    return (f"session-{session_id}", ())


def extraction_request() -> ExtractionRequest:
    return ExtractionRequest(
        run_id="run-a",
        event_id="event-a",
        source_session_alias="worker-a",
        trigger_kinds=("test_edit",),
        trigger_payload={"tool": "Edit", "path": "tests/test_amount.py"},
        evidence=(),
        approved_criteria=(),
    )


def test_extraction_prompt_preserves_explicit_conflicts() -> None:
    prompt = internal_session.json.loads(
        internal_session._extraction_prompt(extraction_request())
    )

    assert "complete trigger payload" in prompt["task"]
    assert "every evidence item" in prompt["task"]
    rules = " ".join(prompt["rules"])
    assert "separate claim for every explicit value" in rules
    assert "trigger_payload.tool_input and tool_response" in rules
    assert "matching repository-change evidence" in rules
    assert "contract declarations from patch text" in rules
    assert "Return at most 8 claims" in rules
    assert "omit identifiers, digests" in rules
    assert 'Return {"claims": []}' in rules
    assert "Preserve contradictions" in rules
    assert "explicit unit statement in prose" in rules
    assert "unit inferred from an identifier" in rules


def extraction_output() -> list[dict[str, object]]:
    return [
        {
            "subject": "amount",
            "subject_locator": "contracts/api.json#/properties/amount",
            "property": "unit",
            "value": "cents",
            "unit": None,
            "confidence": 0.9,
            "evidence_ids": ["evidence-a"],
            "targets": [],
        }
    ]

def extraction_sdk_output() -> dict[str, object]:
    """The droid-sdk returns a top-level object, never a bare array."""

    return {"claims": extraction_output()}



def probe_snapshot() -> ProbeSnapshot:
    evidence_digest = hashlib.sha256(b"evidence").hexdigest()
    finding_digest = hashlib.sha256(b"finding").hexdigest()
    return ProbeSnapshot(
        run_id="run-a",
        finding_id="finding-a",
        finding_dedup_key=finding_digest,
        rule="cross_worker_conflict",
        risk_category="security",
        maximum_level="blocker",
        claims=(
            ProbeClaim(
                claim_id="claim-a",
                subject="amount",
                subject_locator="contracts/api.json#/properties/amount",
                property="unit",
                value="cents",
                confidence=0.9,
                evidence_ids=("evidence-a",),
            ),
        ),
        evidence=(
            ProbeEvidenceMetadata(
                evidence_id="evidence-a",
                kind="repository_contract",
                source="repository_contract",
                locator="contracts/api.json#/properties/amount",
                digest=evidence_digest,
                provenance_status="hook_authenticated",
                redaction_status="clean",
                observed_at=10,
                authoritative=True,
            ),
        ),
    )


def probe_output() -> dict[str, object]:
    return {
        "status": "confirmed",
        "authoritative_evidence": ["evidence-a"],
        "affected_claim_ids": ["claim-a"],
        "recommended_level": "blocker",
        "reason": "The repository contract establishes cents.",
        "authoritative_value": "cents",
    }


def extraction_broker(
    tmp_path: Path,
    session: FakeSession,
    factory: FakeTransportFactory,
    *,
    executable_digest_reader: object = None,
    secure_executable_stager: object = None,
    failure_log: Path | None = None,
    forbidden_values: tuple[str, ...] = (),
) -> tuple[LiveExtractionBroker, FakeSdkBoundary]:
    sdk = FakeSdkBoundary(session)
    digest_reader = executable_digest_reader or (lambda path: "a" * 64)
    assert callable(digest_reader)
    stager = secure_executable_stager or FakeSecureStager()
    assert callable(stager)
    return (
        LiveExtractionBroker(
            executable="/approved/droid",
            expected_executable_digest="a" * 64,
            cwd=tmp_path.resolve(),
            environment={
                "PATH": "/approved/bin",
                "HOME": "/ambient/home",
                "FACTORY_API_KEY": "supplied-key",
                "OPENAI_API_KEY": "ambient-openai-key",
                "AWS_SECRET_ACCESS_KEY": "ambient-aws-key",
                "SHADOW_MISSION_RUN_FILE": "/private/run",
                "MISSION_ID": "mission-a",
                "FACTORY_MISSION_CORRELATION": "correlation-a",
                "SHADOW_COLLECTOR_URL": "http://collector",
            },
            model="extractor-model",
            reasoning="low",
            collector_event_count=quiet_collector_observation,
            executable_digest_reader=digest_reader,
            secure_executable_stager=stager,
            transport_factory=factory,
            sdk_boundary=sdk,
            failure_log=failure_log,
            forbidden_values=forbidden_values,
        ),
        sdk,
    )


def probe_broker(
    tmp_path: Path,
    session: FakeSession,
    factory: FakeTransportFactory,
    *,
    collector_event_count: object = None,
    executable_digest_reader: object = None,
    secure_executable_stager: object = None,
) -> tuple[LiveProbeBroker, FakeSdkBoundary]:
    sdk = FakeSdkBoundary(session)
    observer = collector_event_count or quiet_collector_observation
    assert callable(observer)
    digest_reader = executable_digest_reader or (lambda path: "a" * 64)
    assert callable(digest_reader)
    stager = secure_executable_stager or FakeSecureStager()
    assert callable(stager)
    return (
        LiveProbeBroker(
            executable="/approved/droid",
            expected_executable_digest="a" * 64,
            cwd=tmp_path.resolve(),
            environment={"PATH": "/approved/bin"},
            model="probe-model",
            reasoning="high",
            collector_event_count=observer,
            executable_digest_reader=digest_reader,
            secure_executable_stager=stager,
            transport_factory=factory,
            sdk_boundary=sdk,
        ),
        sdk,
    )


def assert_exact_config(sdk: FakeSdkBoundary) -> None:
    config = sdk.calls[0]["config"]
    assert config == InternalSessionConfig(
        mcp_servers=(),
        restrict_tools=(),
        auto_reject_permission_requests=True,
        disable_builtin_skills=True,
    )
    assert sdk.session.events[0] == ("create", config)
    assert sdk.session.events[1] == "open"


def test_extraction_uses_replacement_environment_and_locks_tools_before_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AMBIENT_SECRET", "must-not-reach-child")
    session = FakeSession(
        initial_tools=("Read", "Execute"),
        remaining_tools=("Read", "Execute"),
        remaining_allowed=False,
        output=extraction_sdk_output(),
    )
    factory = FakeTransportFactory()
    broker, sdk = extraction_broker(tmp_path, session, factory)
    monkeypatch.setattr(broker, "_schedule_prewarm", lambda: None)

    attempt = broker.extract(extraction_request())

    boundary = BoundaryMetadata.model_validate(attempt.boundary)
    environment = factory.environments[0]
    assert "AMBIENT_SECRET" not in environment
    assert "OPENAI_API_KEY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert not any(
        marker in key.upper()
        for key in environment
        for marker in ("SHADOW", "MISSION", "CORRELATION", "COLLECTOR")
    )
    assert environment["PATH"] == "/approved/bin"
    assert environment["FACTORY_API_KEY"] == "supplied-key"
    assert environment["FACTORY_DROID_AUTO_UPDATE_ENABLED"] == "false"
    assert environment["HOME"] != os.environ.get("HOME")
    assert not Path(environment["HOME"]).exists()
    assert_exact_config(sdk)
    assert session.events[2:] == [
        ("list", {}),
        (
            "update",
            {"disabled_tools": ("Execute", "Read"), "restrict_tools": ()},
        ),
        (
            "list",
            {"disabled_tools": ("Execute", "Read"), "restrict_tools": ()},
        ),
        "stream",
        "close",
    ]
    assert session.stream_options[0]["timeout"] == 30
    assert attempt.output == extraction_output()
    assert not attempt.timed_out
    assert boundary.internal_session_alias == "session-internal-session-test"
    assert factory.transports[0].close_count >= 1


def test_production_stager_executes_only_private_immutable_approved_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved_bytes = b"#!/bin/sh\nexit 0\n"
    source = tmp_path / "approved-droid"
    source.write_bytes(approved_bytes)
    source.chmod(0o700)
    expected_digest = hashlib.sha256(approved_bytes).hexdigest()
    session = FakeSession(output=extraction_sdk_output())
    sdk = FakeSdkBoundary(session)
    factory = FakeTransportFactory()
    broker = LiveExtractionBroker(
        executable=str(source),
        expected_executable_digest=expected_digest,
        cwd=tmp_path,
        environment={"PATH": "/approved/bin"},
        model="extractor-model",
        reasoning="low",
        collector_event_count=quiet_collector_observation,
        transport_factory=factory,
        sdk_boundary=sdk,
    )
    monkeypatch.setattr(broker, "_schedule_prewarm", lambda: None)

    attempt = broker.extract(extraction_request())

    executed_path = factory.executables[0]
    assert attempt.output == extraction_output()
    assert executed_path != source
    assert factory.executable_bytes == [approved_bytes]
    assert hashlib.sha256(factory.executable_bytes[0]).hexdigest() == expected_digest
    assert factory.executable_modes == [0o500]
    assert not executed_path.exists()
    assert source.read_bytes() == approved_bytes


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="sealed memfd execution is Linux-only",
)
def test_sealed_memfd_executes_approved_bytes_after_same_inode_mutation(
    tmp_path: Path,
) -> None:
    approved_bytes = (
        b'#!/bin/sh\nprintf approved > "$HOME/executed-byte-source"\n'
    )
    source = tmp_path / "approved-droid"
    source.write_bytes(approved_bytes)
    source.chmod(0o700)
    source_inode = source.stat().st_ino
    private_home = tmp_path / "private-home"
    private_home.mkdir(mode=0o700)
    descriptor = stage_bound_file(
        source, hashlib.sha256(approved_bytes).hexdigest(), private_home
    )
    executable = sealed_descriptor_path(descriptor, os.fstat(descriptor))

    os.fchmod(descriptor, 0o700)
    attacker_descriptor = os.open(executable, os.O_RDWR)
    try:
        with pytest.raises(OSError) as write_error:
            os.write(attacker_descriptor, b"replacement")
        assert write_error.value.errno == errno.EPERM
        with pytest.raises(OSError) as truncate_error:
            os.ftruncate(attacker_descriptor, 0)
        assert truncate_error.value.errno == errno.EPERM
    finally:
        os.close(attacker_descriptor)
        os.fchmod(descriptor, 0o500)

    malicious = b'#!/bin/sh\nprintf replacement > "$HOME/executed-byte-source"\n'
    with source.open("r+b", buffering=0) as same_inode:
        same_inode.write(malicious)
        same_inode.truncate()
    assert source.stat().st_ino == source_inode

    transport = ReplacementEnvironmentTransport(
        descriptor,
        tmp_path,
        {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
    )

    async def exercise() -> None:
        await transport.connect()
        with pytest.raises(OSError):
            os.fstat(descriptor)
        process = transport._process
        assert process is not None
        assert await process.wait() == 0
        await transport.close()

    asyncio.run(exercise())

    assert (tmp_path / "executed-byte-source").read_text() == "approved"


def test_transport_hands_pinned_descriptor_to_spawn_and_closes_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = tmp_path / "droid"
    staged.write_bytes(b"#!/bin/sh\nexit 0\n")
    staged.chmod(0o500)
    descriptor = os.open(
        staged,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    monkeypatch.setattr(
        "shadow_mission.internal_session.sealed_descriptor_path",
        lambda received_descriptor, _: Path(
            f"/proc/self/fd/{received_descriptor}"
        ),
    )

    async def fail_spawn(
        *args: object, **kwargs: object
    ) -> asyncio.subprocess.Process:
        assert args[0] == f"/proc/self/fd/{descriptor}"
        assert kwargs["pass_fds"] == (descriptor,)
        raise OSError("sealed spawn failure")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_spawn)
    transport = ReplacementEnvironmentTransport(
        descriptor,
        tmp_path,
        {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
    )

    with pytest.raises(InternalSessionError, match="failed to start"):
        asyncio.run(transport.connect())
    with pytest.raises(OSError):
        os.fstat(descriptor)
    asyncio.run(transport.close())


def test_darwin_descriptor_handoff_uses_dev_fd_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approved = b"#!/bin/sh\nexit 0\n"
    source = tmp_path / "approved-droid"
    source.write_bytes(approved)
    source.chmod(0o700)
    private_home = tmp_path / "private-home"
    private_home.mkdir(mode=0o700)
    descriptor = stage_bound_file(
        source, hashlib.sha256(approved).hexdigest(), private_home
    )
    spawn_paths: list[str] = []

    async def fail_spawn(*args: object, **kwargs: object) -> object:
        spawn_paths.append(str(args[0]))
        assert kwargs["pass_fds"] == (descriptor,)
        raise OSError("darwin spawn failure")

    monkeypatch.setattr("shadow_mission.internal_session.sys.platform", "darwin")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_spawn)
    transport = ReplacementEnvironmentTransport(
        descriptor,
        tmp_path,
        {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
    )

    with pytest.raises(InternalSessionError, match="failed to start"):
        asyncio.run(transport.connect())
    assert len(spawn_paths) == 1
    assert spawn_paths[0].startswith(str(private_home))
    with pytest.raises(OSError):
        os.fstat(descriptor)




@pytest.mark.parametrize("kind", ["relative", "symlink", "nonregular"])
def test_unapproved_source_path_fails_before_model_input(
    tmp_path: Path, kind: str
) -> None:
    approved_bytes = b"#!/bin/sh\nexit 0\n"
    target = tmp_path / "approved-droid"
    target.write_bytes(approved_bytes)
    target.chmod(0o700)
    if kind == "relative":
        source = Path("approved-droid")
    elif kind == "symlink":
        source = tmp_path / "droid-link"
        source.symlink_to(target)
    else:
        source = tmp_path / "droid-directory"
        source.mkdir()
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker = LiveExtractionBroker(
        executable=str(source),
        expected_executable_digest=hashlib.sha256(approved_bytes).hexdigest(),
        cwd=tmp_path,
        environment={"PATH": "/approved/bin"},
        model="extractor-model",
        reasoning="low",
        collector_event_count=quiet_collector_observation,
        transport_factory=factory,
        sdk_boundary=FakeSdkBoundary(session),
    )

    attempt = broker.extract(extraction_request())

    assert attempt.output is None
    assert factory.transports == []
    assert session.prompts == []


def test_source_replacement_after_staging_fails_before_model_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved_bytes = b"#!/bin/sh\nexit 0\n"
    source = tmp_path / "approved-droid"
    source.write_bytes(approved_bytes)
    source.chmod(0o700)
    replacement = tmp_path / "replacement-droid"
    replacement.write_bytes(b"#!/bin/sh\nexit 9\n")
    replacement.chmod(0o700)

    def replace_source() -> None:
        os.replace(replacement, source)

    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory(connect_action=replace_source)
    broker = LiveExtractionBroker(
        executable=str(source),
        expected_executable_digest=hashlib.sha256(approved_bytes).hexdigest(),
        cwd=tmp_path,
        environment={"PATH": "/approved/bin"},
        model="extractor-model",
        reasoning="low",
        collector_event_count=quiet_collector_observation,
        transport_factory=factory,
        sdk_boundary=FakeSdkBoundary(session),
    )
    monkeypatch.setattr(broker, "_schedule_prewarm", lambda: None)

    attempt = broker.extract(extraction_request())

    assert attempt.output is None
    assert factory.executable_bytes == [approved_bytes]
    assert session.prompts == []
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


def test_extraction_executable_drift_discards_output_and_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_digests = iter(("a" * 64, "a" * 64, "a" * 64, "b" * 64))
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(
        tmp_path,
        session,
        factory,
        executable_digest_reader=lambda path: next(observed_digests),
    )
    monkeypatch.setattr(broker, "_schedule_prewarm", lambda: None)

    attempt = broker.extract(extraction_request())

    assert attempt.output is None
    assert attempt.boundary == {}
    assert session.prompts
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


def test_probe_empty_catalog_passes_and_uses_distinct_alias_and_timeout(
    tmp_path: Path,
) -> None:
    session = FakeSession(output=probe_output())
    factory = FakeTransportFactory()
    broker, sdk = probe_broker(tmp_path, session, factory)

    boundary = broker.prepare()
    assert isinstance(boundary, ProbeBoundary)
    assert session.prompts == []
    attempt = broker.send(probe_snapshot())

    assert_exact_config(sdk)
    assert session.events[2:5] == [
        ("list", {}),
        ("update", {"disabled_tools": (), "restrict_tools": ()}),
        ("list", {"disabled_tools": None, "restrict_tools": ()}),
    ]
    assert session.stream_options[0]["timeout"] == 90
    assert ProbeResult.model_validate_json(attempt.output).status == "confirmed"
    assert boundary.internal_session_alias == "session-internal-session-test"
    assert factory.transports[0].close_count >= 1
    assert session.close_count == 1


def test_nonempty_post_disable_catalog_rejects_before_snapshot_and_closes(
    tmp_path: Path,
) -> None:
    session = FakeSession(initial_tools=("Read",), remaining_tools=("Read",))
    factory = FakeTransportFactory()
    broker, _ = probe_broker(tmp_path, session, factory)

    with pytest.raises(InternalSessionError, match="preparation failed"):
        broker.prepare()

    assert session.prompts == []
    assert session.events[4] == (
        "list",
        {"disabled_tools": ("Read",), "restrict_tools": ()},
    )
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


@pytest.mark.parametrize(
    "remaining_tools",
    [(), ("Read",), ("Execute", "Read", "Write")],
)
def test_mismatched_post_disable_catalog_rejects_before_snapshot(
    tmp_path: Path, remaining_tools: tuple[str, ...]
) -> None:
    session = FakeSession(
        initial_tools=("Execute", "Read"),
        remaining_tools=remaining_tools,
        remaining_allowed=False,
    )
    factory = FakeTransportFactory()
    broker, _ = probe_broker(tmp_path, session, factory)

    with pytest.raises(InternalSessionError, match="preparation failed"):
        broker.prepare()

    assert session.prompts == []
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


def test_nonempty_disallowed_catalog_passes_before_snapshot(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        initial_tools=("Read",),
        remaining_tools=("Read",),
        remaining_allowed=False,
        output=probe_output(),
    )
    factory = FakeTransportFactory()
    broker, _ = probe_broker(tmp_path, session, factory)

    boundary = broker.prepare()
    attempt = broker.send(probe_snapshot())

    assert tuple(
        (item.tool_id, item.allowed) for item in boundary.observed_tools
    ) == (("Read", False),)
    assert attempt.output is not None


def test_probe_post_send_executable_drift_disables_boundary_and_closes(
    tmp_path: Path,
) -> None:
    observed_digests = iter(("a" * 64, "a" * 64, "a" * 64, "b" * 64))
    session = FakeSession(output=probe_output())
    factory = FakeTransportFactory()
    broker, _ = probe_broker(
        tmp_path,
        session,
        factory,
        executable_digest_reader=lambda path: next(observed_digests),
    )
    boundary = broker.prepare()
    propagated_errors: list[InternalSessionError] = []

    class PreparedBroker:
        def prepare(self) -> ProbeBoundary:
            return boundary

        def send(self, snapshot: ProbeSnapshot) -> object:
            try:
                return broker.send(snapshot)
            except InternalSessionError as error:
                propagated_errors.append(error)
                raise

        def abort(self) -> bool:
            return broker.abort()

    state_store = InMemoryProbeBoundaryStateStore(
        ProbeBoundaryState.enabled(boundary.policy_digest)
    )
    runner = ProbeRunner(
        PreparedBroker(),
        signing_key=b"k" * 32,
        approved_boundary_digest=boundary.policy_digest,
        boundary_state_store=state_store,
    )

    outcome = runner._run_canonical(
        probe_snapshot(),
        probe_id="probe-drift",
        observed_at=100,
        secret_canaries=(),
    )

    assert propagated_errors
    assert "binding changed" in str(propagated_errors[0])
    assert outcome.assessment is None
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unsafe_boundary"
    assert state_store.load().status == "disabled"
    assert session.prompts
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


def test_process_death_before_send_closes_without_transmitting_snapshot(
    tmp_path: Path,
) -> None:
    session = FakeSession(die_after_lockdown=True)
    factory = FakeTransportFactory()
    broker, _ = probe_broker(tmp_path, session, factory)

    with pytest.raises(InternalSessionError):
        broker.prepare()

    assert session.prompts == []
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


def test_post_prepare_collector_activity_disables_without_transmitting_snapshot(
    tmp_path: Path,
) -> None:
    collector_count = [0]
    session = FakeSession(output=probe_output())
    factory = FakeTransportFactory()
    broker, _ = probe_broker(
        tmp_path,
        session,
        factory,
        collector_event_count=lambda session_id: (
            f"session-{session_id}",
            () if collector_count[0] == 0 else ("event-internal",),
        ),
    )
    boundary = broker.prepare()
    collector_count[0] = 1

    class PreparedBroker:
        def prepare(self) -> ProbeBoundary:
            return boundary

        def send(self, snapshot: ProbeSnapshot) -> object:
            return broker.send(snapshot)

        def abort(self) -> bool:
            return broker.abort()

    state_store = InMemoryProbeBoundaryStateStore(
        ProbeBoundaryState.enabled(boundary.policy_digest)
    )
    runner = ProbeRunner(
        PreparedBroker(),
        signing_key=b"k" * 32,
        approved_boundary_digest=boundary.policy_digest,
        boundary_state_store=state_store,
    )

    outcome = runner._run_canonical(
        probe_snapshot(),
        probe_id="probe-collector-activity",
        observed_at=100,
        secret_canaries=(),
    )

    assert outcome.assessment is None
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "unsafe_boundary"
    assert state_store.load().status == "disabled"
    assert session.prompts == []
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


def test_transport_failure_is_bounded_and_closes_extraction_attempt(
    tmp_path: Path,
) -> None:
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory(fail_connect=True)
    broker, _ = extraction_broker(tmp_path, session, factory)

    attempt = broker.extract(extraction_request())

    assert attempt.output is None
    assert not attempt.timed_out
    assert attempt.boundary == {}
    assert "sealed transport detail" not in repr(attempt)


@pytest.mark.parametrize("kind", ["timeout", "malformed"])
def test_extraction_timeout_and_malformed_output_are_bounded_and_close(
    tmp_path: Path,
    kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(
        output=object() if kind == "malformed" else extraction_sdk_output(),
        timeout=kind == "timeout",
    )
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)
    monkeypatch.setattr(broker, "_schedule_prewarm", lambda: None)

    attempt = broker.extract(extraction_request())

    assert attempt.output is None
    assert attempt.timed_out is (kind == "timeout")
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


class SlowClosingSession(FakeSession):
    """One session whose mandatory cleanup outlives the model deadline."""

    def __init__(self, *, output: object, close_delay: float) -> None:
        super().__init__(output=output)
        self._close_delay = close_delay

    async def close(self) -> None:
        await asyncio.sleep(self._close_delay)
        await super().close()


def test_cleanup_slower_than_model_deadline_still_returns_claims(
    tmp_path: Path,
) -> None:
    session = SlowClosingSession(output=extraction_sdk_output(), close_delay=0.9)
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)
    assert broker.prewarm() is True
    # The prepared boundary already records the pinned model deadline, so the
    # request can use a short model deadline and a slower mandatory cleanup.
    broker.timeout_seconds = 0.5

    attempt = broker.extract(extraction_request())
    broker.abort()

    assert attempt.output == extraction_output()
    assert attempt.timed_out is False
    assert session.close_count == 1


def test_cleanup_overrun_is_recorded_apart_from_model_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        internal_session, "_EXTRACTION_CLEANUP_BUDGET_SECONDS", 0.2
    )
    failure_log = tmp_path / "extract-failures.jsonl"
    session = SlowClosingSession(output=extraction_sdk_output(), close_delay=1.0)
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(
        tmp_path, session, factory, failure_log=failure_log
    )
    monkeypatch.setattr(broker, "_schedule_prewarm", lambda: None)
    assert broker.prewarm() is True
    broker.timeout_seconds = 0.3

    attempt = broker.extract(extraction_request())
    broker.abort()

    assert attempt.output is None
    stages = [
        internal_session.json.loads(line)["stage"]
        for line in failure_log.read_text().splitlines()
    ]
    assert stages[0] == "cleanup_failed"
    assert "timeout" not in stages


def test_oversized_claim_set_is_truncated_instead_of_rejected(
    tmp_path: Path,
) -> None:
    claim = extraction_output()[0]
    oversized = [
        {**claim, "subject": f"amount-{index}"}
        for index in range(internal_session.MAX_EXTRACTION_CLAIMS + 4)
    ]
    session = FakeSession(output={"claims": oversized})
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)

    attempt = broker.extract(extraction_request())

    assert attempt.output is not None
    assert len(attempt.output) == internal_session.MAX_EXTRACTION_CLAIMS
    assert attempt.output[0]["subject"] == "amount-0"


@pytest.mark.parametrize(
    ("output", "expected"),
    [({}, None), ({"claims": []}, [])],
)
def test_missing_claims_member_fails_closed_and_empty_claims_pass(
    tmp_path: Path, output: object, expected: object
) -> None:
    session = FakeSession(output=output)
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)

    attempt = broker.extract(extraction_request())

    assert attempt.output == expected

@pytest.mark.parametrize("kind", ["timeout", "malformed"])
def test_probe_timeout_and_malformed_output_are_bounded_and_close(
    tmp_path: Path, kind: str
) -> None:
    session = FakeSession(
        output=object() if kind == "malformed" else probe_output(),
        timeout=kind == "timeout",
    )
    factory = FakeTransportFactory()
    broker, _ = probe_broker(tmp_path, session, factory)
    broker.prepare()

    attempt = broker.send(probe_snapshot())

    assert attempt.output is None
    assert attempt.timed_out is (kind == "timeout")
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


def test_probe_cleanup_failure_cannot_return_success(tmp_path: Path) -> None:
    session = FakeSession(output=probe_output())
    factory = FakeTransportFactory()
    broker, _ = probe_broker(tmp_path, session, factory)
    broker.prepare()
    transport = factory.transports[0]

    async def fail_close() -> None:
        transport.close_count += 1
        raise OSError("sealed cleanup detail")

    transport.close = fail_close  # type: ignore[method-assign]

    with pytest.raises(InternalSessionError, match="cleanup failed"):
        broker.send(probe_snapshot())

    assert transport.process_alive is True


def test_abort_is_idempotent_and_never_sends_snapshot(
    tmp_path: Path,
) -> None:
    session = FakeSession(output=probe_output())
    factory = FakeTransportFactory()
    broker, _ = probe_broker(tmp_path, session, factory)

    broker.prepare()
    assert broker.abort() is True
    assert broker.abort() is True

    assert session.prompts == []
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


def test_abort_cancels_active_stream_and_never_returns_success(
    tmp_path: Path,
) -> None:
    session = BlockingSession(output=probe_output())
    factory = FakeTransportFactory()
    broker, _ = probe_broker(tmp_path, session, factory)
    broker.prepare()
    attempts: list[object] = []
    errors: list[BaseException] = []

    def send_snapshot() -> None:
        try:
            attempts.append(broker.send(probe_snapshot()))
        except BaseException as error:
            errors.append(error)

    send_thread = threading.Thread(target=send_snapshot, daemon=True)
    send_thread.start()
    assert session.blocking_stream.entered.wait(timeout=2)

    assert broker.abort() is True
    send_thread.join(timeout=2)

    assert not send_thread.is_alive()
    assert session.blocking_stream.cancelled.is_set()
    assert errors == []
    assert len(attempts) == 1
    assert getattr(attempts[0], "output", None) is None
    assert session.close_count == 1
    assert factory.transports[0].close_count >= 1


def test_abort_cancels_blocked_probe_prepare_and_awaits_cleanup(
    tmp_path: Path,
) -> None:
    session = BlockingOpenSession(output=probe_output())
    factory = FakeTransportFactory()
    broker, _ = probe_broker(tmp_path, session, factory)
    errors: list[BaseException] = []

    def prepare_probe() -> None:
        try:
            broker.prepare()
        except BaseException as error:
            errors.append(error)

    prepare_thread = threading.Thread(target=prepare_probe, daemon=True)
    prepare_thread.start()
    assert session.open_entered.wait(timeout=2)

    assert broker.abort() is True
    prepare_thread.join(timeout=2)

    assert not prepare_thread.is_alive()
    assert session.open_cancelled.is_set()
    assert errors
    assert session.close_count == 1
    assert factory.transports[0].close_count == 1
    assert broker._preparing_worker is None


def test_probe_abort_owns_abandoned_prepare_resources_until_cleanup_proven(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    AbandonBeforeCleanupWorker, workers = abandonment_worker_type()
    monkeypatch.setattr(
        internal_session,
        "_LoopWorker",
        AbandonBeforeCleanupWorker,
    )
    session = BlockingOpenSession(output=probe_output())
    factory = RetainedDescriptorFactory(close_failures=0)
    broker, _ = probe_broker(tmp_path, session, factory)
    errors: list[BaseException] = []

    def prepare_probe() -> None:
        try:
            broker.prepare()
        except BaseException as error:
            errors.append(error)

    prepare_thread = threading.Thread(target=prepare_probe, daemon=True)
    prepare_thread.start()
    assert session.open_entered.wait(timeout=2)
    transport = factory.transports[0]
    assert isinstance(transport, RetainedDescriptorTransport)
    descriptor = transport.executable_descriptor
    assert descriptor is not None

    try:
        cleanup_acknowledged = broker.abort()
        prepare_thread.join(timeout=2)

        assert not prepare_thread.is_alive()
        assert errors
        descriptor_is_open = True
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
            descriptor_is_open = False
        something_unclean = (
            transport.process_alive
            or descriptor_is_open
            or bool(broker._inflight_cleanups)
        )
        assert cleanup_acknowledged is (not something_unclean)

        for worker in workers:
            worker.dispose_abandoned()  # type: ignore[attr-defined]
        assert all(
            not created_transport.process_alive
            for created_transport in factory.transports
        )
        assert all(
            created_transport.close_count == 1
            for created_transport in factory.transports
        )
        assert broker._inflight_cleanups == []
        with pytest.raises(OSError) as closed_descriptor:
            os.fstat(descriptor)
        assert closed_descriptor.value.errno == errno.EBADF
    finally:
        for worker in workers:
            worker.dispose_abandoned()  # type: ignore[attr-defined]
        if transport.process_alive:
            transport.close_failures = 0
            asyncio.run(transport.close())


def test_probe_abort_retains_home_after_early_preparation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allow_home_cleanup = threading.Event()
    real_temporary_directory = internal_session.tempfile.TemporaryDirectory
    home_paths: list[Path] = []

    class FailUntilReleasedTemporaryDirectory:
        def __init__(self, *, prefix: str) -> None:
            self._directory = real_temporary_directory(prefix=prefix)
            self.name = self._directory.name
            home_paths.append(Path(self.name))

        def cleanup(self) -> None:
            if not allow_home_cleanup.is_set():
                raise OSError("sealed home cleanup detail")
            self._directory.cleanup()

    monkeypatch.setattr(
        internal_session.tempfile,
        "TemporaryDirectory",
        FailUntilReleasedTemporaryDirectory,
    )
    factory = FakeTransportFactory()
    digest_reads = 0

    def drift_after_entry(_: Path) -> str:
        nonlocal digest_reads
        digest_reads += 1
        return ("a" if digest_reads == 1 else "b") * 64

    broker, _ = probe_broker(
        tmp_path,
        FakeSession(output=probe_output()),
        factory,
        executable_digest_reader=drift_after_entry,
    )

    try:
        with pytest.raises(InternalSessionError, match="preparation failed"):
            broker.prepare()

        assert factory.transports == []
        assert len(broker._inflight_cleanups) == 1
        assert broker.abort() is False
        allow_home_cleanup.set()
        assert broker.abort() is True
        assert broker._inflight_cleanups == []
        assert home_paths and not home_paths[0].exists()
    finally:
        allow_home_cleanup.set()
        broker.abort()


def test_abort_cancels_blocked_extraction_and_prevents_success(
    tmp_path: Path,
) -> None:
    session = BlockingSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)
    attempts: list[object] = []

    extraction_thread = threading.Thread(
        target=lambda: attempts.append(broker.extract(extraction_request())),
        daemon=True,
    )
    extraction_thread.start()
    assert session.blocking_stream.entered.wait(timeout=2)

    assert broker.abort() is True
    extraction_thread.join(timeout=2)

    assert not extraction_thread.is_alive()
    assert session.blocking_stream.cancelled.is_set()
    assert len(attempts) == 1
    assert getattr(attempts[0], "output", None) is None
    # Replenishment is now scheduled before the served request, so the factory
    # can hold both the request transport and a prewarm transport. abort() must
    # leave none of them alive, whatever order they were created in.
    assert factory.transports
    assert all(not transport.process_alive for transport in factory.transports)
    assert all(transport.close_count == 1 for transport in factory.transports)
    assert broker._active_worker is None


def test_abort_cancels_blocked_extraction_prewarm_and_awaits_cleanup(
    tmp_path: Path,
) -> None:
    session = BlockingOpenSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)
    results: list[bool] = []
    errors: list[BaseException] = []

    def prewarm_extraction() -> None:
        try:
            results.append(broker.prewarm())
        except BaseException as error:
            errors.append(error)

    prepare_thread = threading.Thread(target=prewarm_extraction, daemon=True)
    prepare_thread.start()
    assert session.open_entered.wait(timeout=2)

    assert broker.abort() is True
    assert not prepare_thread.is_alive()
    prepare_thread.join(timeout=2)
    assert session.open_cancelled.is_set()
    assert results == [False]
    assert errors == []
    assert factory.transports[0].process_alive is False
    assert factory.transports[0].close_count == 1
    assert broker._preparing_worker is None


def test_prewarm_worker_creation_failure_releases_bookkeeping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)

    def fail_worker_creation(name: str) -> _LoopWorker:
        assert name == "shadow-extraction-prewarm"
        raise RuntimeError("sealed worker construction detail")

    monkeypatch.setattr(
        internal_session,
        "_LoopWorker",
        fail_worker_creation,
    )

    assert broker.prewarm() is False
    assert broker._preparing is False
    assert broker._preparing_thread is None
    assert broker._preparing_worker is None
    assert factory.transports == []
    assert broker.abort() is True


@pytest.mark.parametrize("fail_first_close", [False, True])
def test_abort_owns_abandoned_prewarm_resources_until_cleanup_proven(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_first_close: bool,
) -> None:
    AbandonBeforeCleanupWorker, workers = abandonment_worker_type()

    monkeypatch.setattr(
        internal_session,
        "_LoopWorker",
        AbandonBeforeCleanupWorker,
    )
    session = BlockingOpenSession(output=extraction_sdk_output())
    factory = RetainedDescriptorFactory(
        close_failures=int(fail_first_close)
    )
    broker, _ = extraction_broker(tmp_path, session, factory)
    prewarm_results: list[bool] = []
    prewarm_thread = threading.Thread(
        target=lambda: prewarm_results.append(broker.prewarm()),
        daemon=True,
    )
    prewarm_thread.start()
    assert session.open_entered.wait(timeout=2)
    transport = factory.transports[0]
    assert isinstance(transport, RetainedDescriptorTransport)
    descriptor = transport.executable_descriptor
    assert descriptor is not None

    try:
        cleanup_acknowledged = broker.abort()
        prewarm_thread.join(timeout=2)

        assert not prewarm_thread.is_alive()
        assert prewarm_results == [False]
        descriptor_is_open = True
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
            descriptor_is_open = False
        something_unclean = transport.process_alive or descriptor_is_open
        assert cleanup_acknowledged is (not something_unclean)
        if fail_first_close:
            assert cleanup_acknowledged is False
            assert something_unclean is True
            assert broker.abort() is True

        for worker in workers:
            worker.dispose_abandoned()  # type: ignore[attr-defined]
        assert all(
            not created_transport.process_alive
            for created_transport in factory.transports
        )
        assert all(
            created_transport.close_count == 1
            for created_transport in factory.transports
        )
        assert broker._inflight_cleanups == []
        assert broker._failed_cleanups == []
        with pytest.raises(OSError) as closed_descriptor:
            os.fstat(descriptor)
        assert closed_descriptor.value.errno == errno.EBADF
    finally:
        for worker in workers:
            worker.dispose_abandoned()  # type: ignore[attr-defined]
        if transport.process_alive:
            transport.close_failures = 0
            asyncio.run(transport.close())



def test_abort_waits_for_prepared_session_claim_handoff(
    tmp_path: Path,
) -> None:
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)
    assert broker.prewarm() is True
    claimed = threading.Event()
    release_claim = threading.Event()
    real_take_prepared = broker._take_prepared

    def take_prepared() -> object:
        prepared = real_take_prepared()
        claimed.set()
        assert release_claim.wait(timeout=2)
        return prepared

    broker._take_prepared = take_prepared  # type: ignore[method-assign]
    attempts: list[object] = []
    abort_results: list[bool] = []
    extraction_thread = threading.Thread(
        target=lambda: attempts.append(broker.extract(extraction_request())),
        daemon=True,
    )
    extraction_thread.start()
    assert claimed.wait(timeout=2)
    abort_thread = threading.Thread(
        target=lambda: abort_results.append(broker.abort()),
        daemon=True,
    )
    abort_thread.start()
    with broker._condition:
        assert broker._condition.wait_for(lambda: broker._aborted, timeout=2)
    assert abort_thread.is_alive()

    release_claim.set()
    extraction_thread.join(timeout=2)
    abort_thread.join(timeout=2)

    assert not extraction_thread.is_alive()
    assert not abort_thread.is_alive()
    assert abort_results == [True]
    assert len(attempts) == 1
    assert getattr(attempts[0], "output", None) is None
    assert factory.transports[0].process_alive is False


def test_abort_waits_for_fresh_worker_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)
    constructor_entered = threading.Event()
    release_constructor = threading.Event()
    real_loop_worker = internal_session._LoopWorker

    def blocking_loop_worker(name: str) -> _LoopWorker:
        if name == "shadow-extraction-session":
            constructor_entered.set()
            assert release_constructor.wait(timeout=2)
        return real_loop_worker(name)

    monkeypatch.setattr(internal_session, "_LoopWorker", blocking_loop_worker)
    attempts: list[object] = []
    abort_results: list[bool] = []
    extraction_thread = threading.Thread(
        target=lambda: attempts.append(broker.extract(extraction_request())),
        daemon=True,
    )
    extraction_thread.start()
    assert constructor_entered.wait(timeout=2)
    abort_thread = threading.Thread(
        target=lambda: abort_results.append(broker.abort()),
        daemon=True,
    )
    abort_thread.start()
    with broker._condition:
        assert broker._condition.wait_for(lambda: broker._aborted, timeout=2)
    assert abort_thread.is_alive()

    release_constructor.set()
    extraction_thread.join(timeout=2)
    abort_thread.join(timeout=2)

    assert not extraction_thread.is_alive()
    assert not abort_thread.is_alive()
    assert abort_results == [True]
    assert len(attempts) == 1
    assert getattr(attempts[0], "output", None) is None
    assert broker._active_worker is None

def test_extraction_cleanup_failure_remains_non_releasable(
    tmp_path: Path,
) -> None:
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)
    assert broker.prewarm() is True
    transport = factory.transports[0]
    real_close = transport.close

    async def fail_close() -> None:
        transport.close_count += 1
        raise OSError("sealed cleanup detail")

    transport.close = fail_close  # type: ignore[method-assign]

    attempt = broker.extract(extraction_request())

    assert attempt.output is None
    assert transport.process_alive is True
    assert broker.abort() is False
    transport.close = real_close  # type: ignore[method-assign]
    assert broker.abort() is True
    assert transport.process_alive is False



def test_failed_prewarm_cleanup_remains_non_releasable(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        initial_tools=("read",),
        remaining_tools=("read",),
        output=extraction_sdk_output(),
    )

    class CleanupFailingFactory(FakeTransportFactory):
        def __call__(
            self,
            executable_descriptor: int,
            cwd: Path,
            environment: object,
        ) -> FakeTransport:
            transport = super().__call__(
                executable_descriptor,
                cwd,
                environment,
            )

            async def fail_close() -> None:
                transport.close_count += 1
                raise OSError("sealed cleanup detail")

            transport.close = fail_close  # type: ignore[method-assign]
            return transport

    factory = CleanupFailingFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)

    assert broker.prewarm() is False
    assert factory.transports[0].process_alive is True
    assert broker.abort() is False
    transport = factory.transports[0]
    transport.close = FakeTransport.close.__get__(  # type: ignore[method-assign]
        transport,
        FakeTransport,
    )
    assert broker.abort() is True
    assert transport.process_alive is False


def test_concurrent_abort_serializes_retained_extraction_cleanup(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        initial_tools=("read",),
        remaining_tools=("read",),
        output=extraction_sdk_output(),
    )
    factory = FakeTransportFactory()

    def install_failing_close() -> None:
        transport = factory.transports[-1]

        async def fail_close() -> None:
            raise OSError("sealed cleanup detail")

        transport.close = fail_close  # type: ignore[method-assign]

    factory.connect_action = install_failing_close
    broker, _ = extraction_broker(tmp_path, session, factory)
    assert broker.prewarm() is False
    transport = factory.transports[0]
    assert transport.process_alive is True

    close_entered = threading.Event()
    release_close = threading.Event()
    second_retry_entered = threading.Event()
    close_calls = 0

    async def blocking_close() -> None:
        nonlocal close_calls
        close_calls += 1
        close_entered.set()
        await asyncio.to_thread(release_close.wait)
        await FakeTransport.close(transport)

    transport.close = blocking_close  # type: ignore[method-assign]
    real_retry = broker._retry_failed_cleanup

    def track_retry(
        cleanup: object,
        *,
        deadline: float,
    ) -> bool:
        if threading.current_thread().name == "second-extraction-abort":
            second_retry_entered.set()
        return real_retry(cleanup, deadline=deadline)  # type: ignore[arg-type]

    broker._retry_failed_cleanup = track_retry  # type: ignore[method-assign]
    abort_results: list[bool] = []
    first_abort = threading.Thread(
        target=lambda: abort_results.append(broker.abort()),
        name="first-extraction-abort",
        daemon=True,
    )
    second_abort = threading.Thread(
        target=lambda: abort_results.append(broker.abort()),
        name="second-extraction-abort",
        daemon=True,
    )

    try:
        first_abort.start()
        assert close_entered.wait(timeout=2)
        second_abort.start()
        assert second_retry_entered.wait(timeout=2)
        assert close_calls == 1
    finally:
        release_close.set()
        first_abort.join(timeout=2)
        second_abort.join(timeout=2)

    assert not first_abort.is_alive()
    assert not second_abort.is_alive()
    assert abort_results == [True, True]
    assert close_calls == 1
    assert transport.close_count == 1
    assert transport.process_alive is False
    assert broker._failed_cleanups == []


def test_abort_joins_scheduled_extraction_prewarm(tmp_path: Path) -> None:
    session = BlockingOpenSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)

    broker._schedule_prewarm()
    assert session.open_entered.wait(timeout=2)

    assert broker.abort() is True
    thread = broker._prewarm_thread
    assert thread is None or not thread.is_alive()


def test_abort_retries_failed_extraction_worker_stop(tmp_path: Path) -> None:
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)
    assert broker.prewarm() is True
    prepared = broker._prepared
    assert prepared is not None
    real_stop = prepared.worker.stop
    stop_calls = 0

    def fail_twice(*, timeout: float = internal_session._CLOSE_TIMEOUT_SECONDS) -> bool:
        nonlocal stop_calls
        stop_calls += 1
        if stop_calls <= 2:
            return False
        return real_stop(timeout=timeout)

    prepared.worker.stop = fail_twice  # type: ignore[method-assign]

    assert broker.abort() is False
    assert broker.abort() is True
    assert stop_calls >= 3

def test_loop_worker_cancellation_is_sticky_until_future_registration() -> None:
    worker = _LoopWorker("sticky-cancel-test")
    cancellation_started = threading.Event()
    acknowledgments: list[bool] = []

    def cancel_before_submit() -> None:
        cancellation_started.set()
        acknowledgments.append(worker.cancel_active(timeout=1.0))

    cancellation_thread = threading.Thread(target=cancel_before_submit)
    cancellation_thread.start()
    assert cancellation_started.wait(timeout=1)

    async def blocked_turn() -> None:
        await asyncio.Future()

    with pytest.raises(concurrent.futures.CancelledError):
        worker.run(blocked_turn(), timeout=1.0)
    cancellation_thread.join(timeout=1)

    assert acknowledgments == [True]
    assert worker.stop() is True


def test_back_to_back_extractions_schedule_spare_before_first_turn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker, _ = extraction_broker(
        tmp_path,
        FakeSession(output=extraction_sdk_output()),
        FakeTransportFactory(),
    )
    first_spare = object()
    replacement_spare = object()
    spares = [first_spare]
    request_path: list[tuple[str, object | None]] = []

    monkeypatch.setattr(broker, "_verify_executable", lambda: None)
    monkeypatch.setattr(
        broker,
        "_take_prepared",
        lambda: spares.pop(0) if spares else None,
    )

    def schedule() -> None:
        request_path.append(("schedule", None))
        if broker._request_in_progress and replacement_spare not in spares:
            spares.append(replacement_spare)

    def run_request(
        _request: ExtractionRequest, prepared: object | None
    ) -> BrokerAttempt:
        request_path.append(("run", prepared))
        return BrokerAttempt(boundary={}, output=[])

    monkeypatch.setattr(broker, "_schedule_prewarm", schedule)
    monkeypatch.setattr(broker, "_run_request", run_request)

    broker.extract(extraction_request())
    broker.extract(extraction_request())

    assert request_path[:2] == [("schedule", None), ("run", first_spare)]
    assert ("run", replacement_spare) in request_path


def test_extractor_and_probe_use_repository_disjoint_temporary_cwds(
    tmp_path: Path,
) -> None:
    extraction_factory = FakeTransportFactory()
    extraction, extraction_sdk = extraction_broker(
        tmp_path,
        FakeSession(output=extraction_sdk_output()),
        extraction_factory,
    )
    probe_factory = FakeTransportFactory()
    probe, probe_sdk = probe_broker(
        tmp_path,
        FakeSession(output=probe_output()),
        probe_factory,
    )

    extraction.extract(extraction_request())
    probe.prepare()

    repository = tmp_path.resolve()
    launched_cwds = (*extraction_factory.cwds, *probe_factory.cwds)
    assert len(launched_cwds) >= 2
    assert len(set(launched_cwds)) == len(launched_cwds)
    assert all(
        cwd != repository
        and not cwd.is_relative_to(repository)
        and not repository.is_relative_to(cwd)
        for cwd in launched_cwds
    )
    # Replenishment is scheduled before the served request, so factory creation
    # order no longer tracks call order. Bind each call to a factory workspace.
    assert extraction_sdk.calls[0]["cwd"] in set(extraction_factory.cwds)
    assert probe_sdk.calls[0]["cwd"] in set(probe_factory.cwds)

    assert extraction.abort()
    assert probe.abort()


def test_probe_boundary_uses_measured_per_session_collector_observation(
    tmp_path: Path,
) -> None:
    observed_session_ids: list[str] = []

    def observe(session_id: str) -> tuple[str, tuple[str, ...]]:
        observed_session_ids.append(session_id)
        return ("session-measured-internal", ())

    broker, _ = probe_broker(
        tmp_path,
        FakeSession(session_id="raw-internal-session", output=probe_output()),
        FakeTransportFactory(),
        collector_event_count=observe,
    )

    boundary = broker.prepare()

    assert observed_session_ids == ["raw-internal-session"]
    assert boundary.internal_session_alias == "session-measured-internal"
    assert boundary.collector_event_count == 0
    assert boundary.collector_events == ()
    assert broker.abort()


def test_extraction_failure_log_redacts_exact_factory_credential(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    credential = "factory-credential-value-that-must-not-persist"
    failure_log = tmp_path / "extract-failures.jsonl"
    broker, _ = extraction_broker(
        tmp_path,
        FakeSession(output=extraction_sdk_output()),
        FakeTransportFactory(),
        failure_log=failure_log,
        forbidden_values=(credential,),
    )

    broker._record_failure("turn_failed", f"credential={credential}")

    assert credential not in capsys.readouterr().err
    assert credential not in failure_log.read_text(encoding="utf-8")


def test_broker_schemas_satisfy_the_sdk_top_level_object_contract() -> None:
    """The sdk rejects a bare array. A RootModel[list] silently broke extraction."""

    from droid_sdk._high_level.output import prepare_output_adapter
    from pydantic import RootModel

    from shadow_mission.internal_session import _ExtractionOutput
    from shadow_mission.probe import ProbeResult

    for schema in (_ExtractionOutput, ProbeResult):
        assert schema.model_json_schema(mode="validation")["type"] == "object"
        prepare_output_adapter(schema)

    class _BareArray(RootModel[list[int]]):
        pass

    with pytest.raises(TypeError, match="top-level object"):
        prepare_output_adapter(_BareArray)


def test_prewarmed_session_leaves_only_the_model_turn_on_the_request_path(
    tmp_path: Path,
) -> None:
    """Session setup costs about six seconds and delays every finding.

    A worker finishes about twelve seconds after the edit that creates a
    conflict, so process spawn, handshake, and tool lockdown must happen before
    the request exists, not inside it.
    """

    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, sdk = extraction_broker(tmp_path, session, factory)

    assert broker.prewarm() is True
    warm = list(session.events)
    assert "open" in warm
    assert "stream" not in warm
    assert len(factory.transports) == 1
    assert len(sdk.calls) == 1
    assert session.close_count == 0

    attempt = broker.extract(extraction_request())

    assert attempt.output == extraction_output()
    assert session.events[len(warm) : len(warm) + 2] == ["stream", "close"]
    assert factory.transports[0].close_count == 1
    assert attempt.boundary.factory_home == "clean"
    assert attempt.boundary.enabled_tools == ()
    assert attempt.boundary.shadow_activation_stripped is True
    assert (
        attempt.boundary.internal_session_alias
        == "session-internal-session-test"
    )
    broker.abort()


def test_dead_prewarmed_session_falls_back_to_a_fresh_session(
    tmp_path: Path,
) -> None:
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)

    assert broker.prewarm() is True
    factory.transports[0].alive = False

    attempt = broker.extract(extraction_request())

    assert attempt.output == extraction_output()
    assert len(factory.transports) >= 2
    assert factory.transports[0].close_count == 1
    broker.abort()


def test_abort_closes_an_unused_prewarmed_session(tmp_path: Path) -> None:
    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)

    assert broker.prewarm() is True
    assert session.close_count == 0

    assert broker.abort() is True

    assert session.close_count == 1
    assert factory.transports[0].close_count == 1
    assert broker.prewarm() is False


def test_expired_prewarmed_session_never_loses_an_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spare session can go stale while it waits for a request.

    A stale spare must cost one fresh retry, never the claims themselves.
    """

    session = FakeSession(output=extraction_sdk_output())
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)

    assert broker.prewarm() is True
    monkeypatch.setattr(
        internal_session, "_PREWARM_MAX_IDLE_SECONDS", -1.0, raising=True
    )

    attempt = broker.extract(extraction_request())

    assert attempt.output == extraction_output()
    assert len(factory.transports) >= 2
    assert factory.transports[0].close_count == 1
    broker.abort()


def test_failed_prewarmed_turn_retries_once_on_a_fresh_session(
    tmp_path: Path,
) -> None:
    class OnceFailingSession(FakeSession):
        def __init__(self) -> None:
            super().__init__(output=extraction_sdk_output())
            self.turns = 0

        def stream(self, prompt: str, **options: object):
            self.turns += 1
            self.result = SimpleNamespace(
                success=self.turns > 1,
                output=extraction_sdk_output() if self.turns > 1 else None,
                usage=None,
            )
            return super().stream(prompt, **options)

    session = OnceFailingSession()
    factory = FakeTransportFactory()
    broker, _ = extraction_broker(tmp_path, session, factory)

    assert broker.prewarm() is True
    attempt = broker.extract(extraction_request())

    assert session.turns == 2
    assert attempt.output == extraction_output()
    broker.abort()
