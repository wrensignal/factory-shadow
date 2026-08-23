"""No-spend feasibility harness.

The dry run exercises local hook, authentication, redaction, routing, latch,
fixture, profile, and isolation contracts. It never starts Droid or a model.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

from .auth import (
    RUN_DESCRIPTOR_ENV,
    RUN_FILE_ENV,
    RUN_SECRET_ENV,
    AuthenticationError,
    EventAuthenticator,
    create_descriptor,
    generate_run_secret,
    make_alias,
    write_latch,
)
from .evidence import (
    PROTECTED_TRANSITIONS,
    EvidenceRegistryError,
    FrozenObservation,
    FrozenObservationRegistry,
    authorize_protected_transition,
    load_frozen_observation_registry,
)
from .isolation import capture_live_isolation_manifest, validate_isolation_manifest
from .profile import (
    capture_factory_profile,
    PLUGIN_ARTIFACT_ROOTS,
    compute_gate_surface_digest,
    compute_plugin_artifact_digest,
    resolve_installed_plugin_root,
    validate_factory_profile,
)
from .protocol import ByteBoundedQueue, QueueCapacityError
from .redaction import sanitize_hook_event

CAPABILITY_NAMES = (
    "run_transport_integrity",
    "hook_event_provenance",
    "disposable_isolation",
    "clean_factory_profile",
    "session_hooks",
    "distinct_session_and_mission_identity",
    "live_transcript_access",
    "targeted_guidance_routing",
    "stop_blocker_behavior",
    "role_mapping",
    "independent_probe_boundary",
)
_NO_FALLBACK_CAPABILITIES = {
    "run_transport_integrity",
    "independent_probe_boundary",
}
_ALLOWED_FALLBACKS = set(CAPABILITY_NAMES) - _NO_FALLBACK_CAPABILITIES
_INTERNAL_ENV_KEYS = {
    RUN_DESCRIPTOR_ENV,
    RUN_FILE_ENV,
    RUN_SECRET_ENV,
    "SHADOW_MISSION_COLLECTOR_URL",
    "SHADOW_MISSION_CORRELATION_ID",
    "SHADOW_MISSION_LOG_GROUP_ID",
}


class GateClassificationError(ValueError):
    """Raised when capability evidence does not cover the exact gate."""


@dataclass(frozen=True)
class HookProcessResult:
    returncode: int
    stdout: str
    stderr: str
    installed_artifact_digest: str


def classify_gate(results: Mapping[str, str]) -> str:
    if set(results) != set(CAPABILITY_NAMES):
        raise GateClassificationError("results must contain the exact capability set")
    if any(status not in {"pass", "fallback", "stop"} for status in results.values()):
        raise GateClassificationError("capability status must be pass, fallback, or stop")
    if any(status == "stop" for status in results.values()):
        return "stop"
    if all(status == "pass" for status in results.values()):
        return "primary-pass"
    fallback_names = {name for name, status in results.items() if status == "fallback"}
    if fallback_names and fallback_names <= _ALLOWED_FALLBACKS:
        return "fallback-pass"
    return "stop"




def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_pinned_manifest_digest(path: Path) -> str:
    try:
        digest = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise GateClassificationError("cannot read fixture manifest pin") from error
    if (
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise GateClassificationError("fixture manifest pin is not a SHA-256 digest")
    return digest


def verify_sealed_fixture(
    fixture_path: Path, *, expected_manifest_digest: str
) -> dict[str, Any]:
    manifest_path = fixture_path / "manifest.json"
    manifest_digest = _sha256(manifest_path)
    if manifest_digest != expected_manifest_digest:
        raise GateClassificationError("fixture manifest does not match the external pin")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_files = manifest["files"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise GateClassificationError("invalid sealed fixture manifest") from error
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "files"}
        or manifest["schema_version"] != "0.1"
        or not isinstance(expected_files, dict)
    ):
        raise GateClassificationError("unsupported sealed fixture manifest")
    actual_names = {
        path.name for path in fixture_path.iterdir() if path.name != "manifest.json"
    }
    if actual_names != set(expected_files):
        raise GateClassificationError("fixture file set differs from sealed manifest")
    for name, expected_digest in expected_files.items():
        if (
            not isinstance(name, str)
            or not isinstance(expected_digest, str)
            or _sha256(fixture_path / name) != expected_digest
        ):
            raise GateClassificationError(f"fixture digest mismatch: {name}")
    oracle = json.loads((fixture_path / "oracle.json").read_text(encoding="utf-8"))
    observed = json.loads(
        (fixture_path / "observed-source.json").read_text(encoding="utf-8")
    )
    if (
        not isinstance(observed, dict)
        or set(observed) != {"schema_version", "records"}
        or observed["schema_version"] != "0.1"
    ):
        raise GateClassificationError("observed source fields differ")
    records = observed["records"]
    allowed_roles = {"worker-a", "worker-b"}
    if not isinstance(records, list) or not records or not all(
        isinstance(record, dict)
        and set(record) == {"role", "record_boundary", "text"}
        and record["record_boundary"] is True
        and record["role"] in allowed_roles
        and isinstance(record["text"], str)
        for record in records
    ):
        raise GateClassificationError("observed source attribution is incomplete")
    normalized_records = [
        (record["role"], record["text"].casefold()) for record in records
    ]
    controls = oracle["controls"]
    conflict = oracle["conflict"]
    shared = oracle["shared_assumption"]
    marker_for = {
        "worker-a": str(controls["worker_a_marker"]).casefold(),
        "worker-b": str(controls["worker_b_marker"]).casefold(),
    }

    def role_has(role: str, *values: str) -> bool:
        expected = tuple(value.casefold() for value in values)
        return any(
            record_role == role and all(value in text for value in expected)
            for record_role, text in normalized_records
        )

    conflict_observed = role_has(
        "worker-a",
        str(conflict["worker_a_value"]),
        marker_for["worker-a"],
    ) and role_has(
        "worker-b",
        str(conflict["worker_b_value"]),
        marker_for["worker-b"],
    )
    affected_workers = shared["affected_workers"]
    shared_observed = (
        affected_workers == ["worker-a", "worker-b"]
        and all(
            role_has(
                role,
                str(shared["value"]),
                marker_for[role],
            )
            for role in affected_workers
        )
    )
    all_text = "\n".join(text for _, text in normalized_records)
    negative_marker_absent = (
        str(controls["negative_marker"]).casefold() not in all_text
    )
    secret_canary_absent = (
        str(controls["secret_canary"]).casefold() not in all_text
    )
    if (
        not conflict_observed
        or not shared_observed
        or not negative_marker_absent
        or not secret_canary_absent
    ):
        raise GateClassificationError("sealed source is not semantically sufficient")
    return {
        "sealed": True,
        "manifest_digest": manifest_digest,
        "observation_registry_digest": expected_files[
            "external-observations.json"
        ],
        "cross_worker_conflict_observed": True,
        "shared_assumption_observed": True,
        "negative_control_absent": True,
        "secret_canary_absent": True,
        "production_rules_called": False,
    }


@dataclass
class _PendingWrite:
    event_id: str
    value: dict[str, Any]
    serialized: bytes
    done: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None


class _BoundedHTTPServer(HTTPServer):
    request_queue_size = 128

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        max_workers: int,
    ) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="shadow-collector-request",
        )
        self._slots = threading.BoundedSemaphore(max_workers)
        self._activity_lock = threading.Lock()
        self._active_workers = 0
        self.max_active_workers = 0
        self.rejected_requests = 0
        super().__init__(server_address, handler_class)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            with self._activity_lock:
                self.rejected_requests += 1
            try:
                self._reject_overload(request)
            finally:
                self.shutdown_request(request)
            return
        try:
            self._executor.submit(self._run_request, request, client_address)
        except BaseException:
            self._slots.release()
            self.shutdown_request(request)
            raise

    @staticmethod
    def _reject_overload(request: Any) -> None:
        payload = b'{"error":"workers"}'
        try:
            request.settimeout(0.25)
            received = bytearray()
            while b"\r\n\r\n" not in received and len(received) <= 64 << 10:
                chunk = request.recv(4 << 10)
                if not chunk:
                    break
                received.extend(chunk)
            if b"\r\n\r\n" in received:
                raw_headers, body = bytes(received).split(b"\r\n\r\n", 1)
                content_length = 0
                for header in raw_headers.split(b"\r\n")[1:]:
                    name, separator, value = header.partition(b":")
                    if separator and name.strip().lower() == b"content-length":
                        content_length = int(value.strip())
                        break
                if 0 <= content_length <= 1 << 20:
                    remaining = max(0, content_length - len(body))
                    while remaining:
                        chunk = request.recv(min(remaining, 64 << 10))
                        if not chunk:
                            break
                        remaining -= len(chunk)
            request.sendall(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + payload
            )
        except (OSError, ValueError):
            pass
        finally:
            request.settimeout(None)


    def _run_request(self, request: Any, client_address: Any) -> None:
        with self._activity_lock:
            self._active_workers += 1
            self.max_active_workers = max(
                self.max_active_workers,
                self._active_workers,
            )
        try:
            self.finish_request(request, client_address)
        except BaseException:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            with self._activity_lock:
                self._active_workers -= 1
            self._slots.release()

    def server_close(self) -> None:
        super().server_close()
        self._executor.shutdown(wait=True, cancel_futures=False)


class OfflineCollector:
    """Authenticated offline collector with bounded requests and durable writes."""

    MAX_RAW_BYTES = 1 << 20
    MAX_SANITIZED_BYTES = 1 << 18

    def __init__(
        self,
        run_id: str,
        secret: str,
        ledger_path: Path,
        *,
        provenance_status: str = "untrusted_provenance",
        max_items: int = 1_000,
        max_pending_bytes: int = 16 << 20,
        max_workers: int = 8,
        durability_timeout_seconds: float = 1.5,
        event_handler: (
            Callable[
                [Mapping[str, Any], Mapping[str, Any]],
                Mapping[str, Any] | None,
            ]
            | None
        ) = None,
    ) -> None:
        if max_workers <= 0 or durability_timeout_seconds <= 0:
            raise ValueError("collector limits must be positive")
        self.run_id = run_id
        self.secret = secret
        self.ledger_path = ledger_path
        self._queue = ByteBoundedQueue[_PendingWrite](
            max_items=max_items,
            max_bytes=max_pending_bytes,
        )
        self._guidance: dict[str, list[dict[str, Any]]] = {}
        self._delivered_targets: list[str] = []
        self._server: _BoundedHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._writer_thread: threading.Thread | None = None
        self._writer_stop = threading.Event()
        self._max_workers = max_workers
        self._durability_timeout_seconds = durability_timeout_seconds
        self._authenticator: EventAuthenticator | None = None
        self._descriptor: Mapping[str, Any] | None = None
        self._provenance_status = provenance_status
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._event_handler_lock = threading.Lock()
        self._seen_events: dict[str, bytes] = {}
        self._pending_events: dict[str, _PendingWrite] = {}
        self._responded_events: set[str] = set()
        self._hook_outputs: dict[str, dict[str, Any]] = {}
        self._max_active_observed = 0
        self._rejected_observed = 0
        self._event_handler = event_handler
        self._pause_lock = threading.Lock()
        self._pause_abort = threading.Event()
        self._pause_thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("collector is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/events"

    @property
    def delivered_targets(self) -> list[str]:
        with self._state_lock:
            return list(self._delivered_targets)

    @property
    def max_active_workers(self) -> int:
        server = self._server
        return (
            self._max_active_observed
            if server is None
            else server.max_active_workers
        )

    @property
    def rejected_requests(self) -> int:
        server = self._server
        return (
            self._rejected_observed
            if server is None
            else server.rejected_requests
        )

    @property
    def pending_item_count(self) -> int:
        return self._queue.item_count

    @property
    def pending_byte_count(self) -> int:
        return self._queue.byte_count

    def bind_descriptor(self, descriptor: Mapping[str, Any]) -> None:
        if self._server is None:
            raise RuntimeError("collector must be started before descriptor binding")
        if descriptor.get("run_id") != self.run_id:
            raise AuthenticationError("descriptor run ID does not match collector")
        if descriptor.get("collector_url") != self.url:
            raise AuthenticationError("descriptor collector URL does not match collector")
        self._descriptor = dict(descriptor)
        self._authenticator = EventAuthenticator(self.secret, self._descriptor)

    def queue_hook_output(self, session_alias: str, output: dict[str, Any]) -> None:
        with self._state_lock:
            self._guidance.setdefault(session_alias, []).append(output)

    def start(self) -> None:
        if self._server is not None:
            raise RuntimeError("collector already started")
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                collector._handle(self)

            def log_message(self, format: str, *args: object) -> None:
                return

        self.ledger_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.ledger_path.parent, 0o700)
        self._server = _BoundedHTTPServer(
            ("127.0.0.1", 0),
            Handler,
            max_workers=self._max_workers,
        )
        self._writer_stop.clear()
        self._writer_thread = threading.Thread(
            target=self._write_loop,
            name=f"shadow-offline-writer-{self.run_id}",
            daemon=True,
        )
        self._writer_thread.start()
        self._server_thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"shadow-offline-collector-{self.run_id}",
            daemon=True,
        )
        self._server_thread.start()
        self._pause_abort.clear()

    def pause_for(self, seconds: float) -> None:
        if seconds <= 0:
            raise ValueError("collector pause must be positive")
        with self._pause_lock:
            if self._server is None:
                raise RuntimeError("collector is not running")
            if self._pause_thread is not None and self._pause_thread.is_alive():
                raise RuntimeError("collector is already scheduled to pause")
            server = self._server

            def cycle() -> None:
                time.sleep(0.1)
                server.shutdown()
                current_thread = self._server_thread
                if current_thread is not None:
                    current_thread.join(timeout=2)
                self._pause_abort.wait(seconds)
                with self._pause_lock:
                    if self._server is not server:
                        return
                    resumed = threading.Thread(
                        target=server.serve_forever,
                        name=f"shadow-offline-collector-{self.run_id}-resumed",
                        daemon=True,
                    )
                    self._server_thread = resumed
                    resumed.start()

            self._pause_thread = threading.Thread(
                target=cycle,
                name=f"shadow-offline-collector-{self.run_id}-pause",
                daemon=True,
            )
            self._pause_thread.start()

    def stop(self) -> None:
        server = self._server
        if server is None:
            return
        self._pause_abort.set()
        pause_thread = self._pause_thread
        if pause_thread is not None:
            pause_thread.join(timeout=3)
            if pause_thread.is_alive():
                raise RuntimeError("collector pause did not stop")
        server_thread = self._server_thread
        writer_thread = self._writer_thread
        server.shutdown()
        server.server_close()
        self._max_active_observed = server.max_active_workers
        self._rejected_observed = server.rejected_requests
        if server_thread is not None:
            server_thread.join(timeout=2)
        self._writer_stop.set()
        if writer_thread is not None:
            writer_thread.join(timeout=5)
            if writer_thread.is_alive():
                raise RuntimeError("collector writer did not stop")
        self._server = None
        self._server_thread = None
        self._writer_thread = None
        self._pause_thread = None

    def _respond(
        self,
        handler: BaseHTTPRequestHandler,
        status: HTTPStatus,
        value: Mapping[str, Any],
    ) -> None:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        handler.send_response(int(status))
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        if handler.path != "/events":
            self._respond(handler, HTTPStatus.NOT_FOUND, {"error": "not-found"})
            return
        try:
            content_length = int(handler.headers.get("Content-Length", "-1"))
        except ValueError:
            content_length = -1
        if content_length < 0 or content_length > self.MAX_RAW_BYTES:
            self._respond(
                handler,
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "raw-size"},
            )
            return
        body = handler.rfile.read(content_length)
        headers = {key: value for key, value in handler.headers.items()}
        if self._authenticator is None or self._descriptor is None:
            self._respond(handler, HTTPStatus.UNAUTHORIZED, {"error": "auth"})
            return
        if headers.get("X-Shadow-Key-Id") != self._descriptor["key_id"]:
            self._respond(handler, HTTPStatus.UNAUTHORIZED, {"error": "key"})
            return
        try:
            event_id = self._authenticator.verify(headers, body)
            request_value = json.loads(body)
            if (
                request_value.get("schema_version") != "0.1"
                or request_value.get("run_id") != self.run_id
                or request_value.get("event_id") != event_id
            ):
                raise ValueError("event envelope differs from authenticated headers")
            raw_hook = request_value["hook"]
            if not isinstance(raw_hook, dict):
                raise ValueError("hook must be an object")
            sanitized = sanitize_hook_event(
                raw_hook,
                secret=self.secret,
                run_id=self.run_id,
                event_id=event_id,
                observed_at=int(request_value["observed_at"]),
                provenance_status=self._provenance_status,
            )
            serialized = json.dumps(
                sanitized,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            if len(serialized) > self.MAX_SANITIZED_BYTES:
                raise QueueCapacityError("sanitized payload exceeds 256 KiB")
            with self._state_lock:
                prior = self._seen_events.get(event_id)
                if prior is not None and prior != serialized:
                    raise AuthenticationError("event content changed during retry")
                pending = self._pending_events.get(event_id)
                if pending is not None and pending.serialized != serialized:
                    raise AuthenticationError("pending event content changed")
                if prior is None and pending is None:
                    pending = _PendingWrite(event_id, sanitized, serialized)
                    self._queue.put(pending, serialized)
                    self._pending_events[event_id] = pending
            if pending is not None:
                if not pending.done.wait(self._durability_timeout_seconds):
                    raise QueueCapacityError("durability acknowledgement timed out")
                if pending.error is not None:
                    raise QueueCapacityError("durable writer failed")
            with self._event_handler_lock:
                with self._state_lock:
                    response_cached = event_id in self._responded_events
                    hook_output = (
                        dict(self._hook_outputs[event_id])
                        if response_cached
                        else {}
                    )
                if not response_cached:
                    dynamic_output = (
                        self._event_handler(raw_hook, sanitized)
                        if self._event_handler is not None
                        else None
                    )
                    with self._state_lock:
                        if dynamic_output is not None:
                            hook_output = dict(dynamic_output)
                        else:
                            alias = sanitized["session_alias"]
                            outputs = self._guidance.get(alias, [])
                            hook_output = outputs.pop(0) if outputs else {}
                        if hook_output:
                            self._delivered_targets.append(
                                sanitized["session_alias"]
                            )
                        self._hook_outputs[event_id] = dict(hook_output)
                        self._responded_events.add(event_id)
            self._respond(handler, HTTPStatus.OK, hook_output)
        except AuthenticationError:
            self._respond(handler, HTTPStatus.UNAUTHORIZED, {"error": "auth"})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._respond(handler, HTTPStatus.BAD_REQUEST, {"error": "payload"})
        except QueueCapacityError:
            self._respond(
                handler,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "capacity"},
            )

    def _write_loop(self) -> None:
        while not self._writer_stop.is_set() or self._queue.item_count:
            try:
                pending = self._queue.get(timeout=0.1)
            except TimeoutError:
                continue
            try:
                self._persist(pending.value)
            except BaseException as error:
                pending.error = error
            with self._state_lock:
                if pending.error is None:
                    self._seen_events[pending.event_id] = pending.serialized
                if self._pending_events.get(pending.event_id) is pending:
                    del self._pending_events[pending.event_id]
            pending.done.set()

    def _persist(self, value: Mapping[str, Any]) -> None:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        with self._write_lock:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.ledger_path, flags, 0o600)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise OSError("ledger is not a regular file")
                os.fchmod(descriptor, 0o600)
                with os.fdopen(
                    descriptor,
                    "a",
                    encoding="utf-8",
                    closefd=True,
                ) as handle:
                    handle.write(payload)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise


def run_installed_cache_hook(
    project_root: Path,
    payload: Mapping[str, Any],
    *,
    environment: Mapping[str, str],
    cache_parent: Path | None = None,
    expected_artifact_digest: str | None = None,
    timeout_seconds: float = 2.0,
) -> HookProcessResult:
    with tempfile.TemporaryDirectory(dir=cache_parent) as temporary_name:
        cache_root = Path(temporary_name)
        for relative_root in PLUGIN_ARTIFACT_ROOTS:
            source = project_root / relative_root
            target = cache_root / relative_root
            if source.is_dir():
                shutil.copytree(
                    source,
                    target,
                    ignore=shutil.ignore_patterns(
                        "__pycache__", ".pytest_cache", "*.pyc", "*.pyo"
                    ),
                )
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        artifact_digest = compute_plugin_artifact_digest(cache_root)
        if (
            expected_artifact_digest is not None
            and artifact_digest != expected_artifact_digest
        ):
            raise GateClassificationError(
                "installed plugin artifact differs from the approved source"
            )
        child_environment = dict(os.environ)
        for key in _INTERNAL_ENV_KEYS | {"SHADOW_MISSION_INTERNAL"}:
            child_environment.pop(key, None)
        child_environment.update(environment)
        child_environment["DROID_PLUGIN_ROOT"] = str(cache_root)
        child_environment["PYTHONNOUSERSITE"] = "1"
        child_environment.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [sys.executable, str(cache_root / "hooks" / "shadow_hook.py")],

            input=json.dumps(payload),
            text=True,
            capture_output=True,
            cwd=cache_root,
            env=child_environment,
            timeout=timeout_seconds,
            check=False,
        )
        return HookProcessResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            installed_artifact_digest=artifact_digest,
        )


def _freeze_observation_registry(
    path: Path,
    records: list[FrozenObservation],
) -> FrozenObservationRegistry:
    _write_private_result(
        path,
        {
            "schema_version": "0.1",
            "observations": [record.__dict__ for record in records],
        },
    )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return load_frozen_observation_registry(path, expected_digest=digest)

def internal_session_environment(parent: Mapping[str, str]) -> dict[str, str]:
    child = dict(parent)
    for key in _INTERNAL_ENV_KEYS:
        child.pop(key, None)
    child["SHADOW_MISSION_INTERNAL"] = "1"
    return child


def _hook_event(name: str, session: str) -> dict[str, Any]:
    return {
        "hook_event_name": name,
        "session_id": session,
        "transcript_path": f"/private/transcripts/{session}.jsonl",
        "cwd": "/private/mission",
        "tool_name": "Read",
        "tool_input": {"path": "api-schema.json"},
        "tool_response": "amount uses cents",
    }


def _write_private_result(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved_parent = path.parent.resolve(strict=True)
    parent_metadata = resolved_parent.stat()
    private_directory = (
        parent_metadata.st_mode & 0o077 == 0
        and (
            not hasattr(os, "getuid")
            or parent_metadata.st_uid == os.getuid()
        )
    )
    sticky_shared_directory = bool(
        parent_metadata.st_mode & stat.S_ISVTX
        and parent_metadata.st_mode & stat.S_IWOTH
    )
    if (
        not resolved_parent.is_dir()
        or not (private_directory or sticky_shared_directory)
    ):
        raise GateClassificationError(
            "result directory is neither private nor sticky"
        )
    resolved_path = resolved_parent / path.name
    if resolved_path.is_symlink():
        raise GateClassificationError("result path must not be a symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=resolved_parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, resolved_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def run_dry_run(
    *,
    fixture_path: Path,
    fixture_manifest_pin: Path,
    output_path: Path | None,
    project_root: Path,
) -> dict[str, Any]:
    expected_manifest_digest = load_pinned_manifest_digest(fixture_manifest_pin)
    fixture_result = verify_sealed_fixture(
        fixture_path,
        expected_manifest_digest=expected_manifest_digest,
    )
    observation_registry = load_frozen_observation_registry(
        fixture_path / "external-observations.json",
        expected_digest=fixture_result["observation_registry_digest"],
    )
    gate_surface_digest = compute_gate_surface_digest(project_root)
    installed_artifact_digest = compute_plugin_artifact_digest(project_root)
    profile = json.loads(
        (fixture_path / "factory-profile.json").read_text(encoding="utf-8")
    )
    if profile.get("gate_surface_digest") != gate_surface_digest:
        raise GateClassificationError("profile gate surface digest is stale")
    if profile.get("installed_plugin_artifact_digest") != installed_artifact_digest:
        raise GateClassificationError("profile installed artifact digest is stale")
    profile_result = validate_factory_profile(profile)
    isolation_result = validate_isolation_manifest(
        fixture_path / "isolation-manifest.json",
        project_root / "ops/lima/shadow-feasibility.yaml",
        require_live_canaries=False,
    )
    oracle = json.loads((fixture_path / "oracle.json").read_text(encoding="utf-8"))
    worker_a_marker = str(oracle["controls"]["worker_a_marker"])
    secret_canary = str(oracle["controls"]["secret_canary"])
    run_id = "offline-fixture-run"

    checks: dict[str, str] = {}
    inert = run_installed_cache_hook(
        project_root,
        _hook_event("SessionStart", "inert"),
        environment={},
        expected_artifact_digest=installed_artifact_digest,
    )
    if (
        inert.returncode != 0
        or inert.stdout
        or inert.stderr
        or inert.installed_artifact_digest != installed_artifact_digest
    ):
        raise RuntimeError("installed-cache hook is not inert or is not source-equivalent")
    checks["inert_cached_hook"] = "pass"

    internal = run_installed_cache_hook(
        project_root,
        _hook_event("SessionStart", "internal-probe"),
        environment=internal_session_environment(
            {RUN_FILE_ENV: "/unreachable", RUN_SECRET_ENV: "removed"}
        ),
        expected_artifact_digest=installed_artifact_digest,
    )
    if (
        internal.returncode != 0
        or internal.stdout
        or internal.stderr
        or internal.installed_artifact_digest != installed_artifact_digest
    ):
        raise RuntimeError("internal SDK session hook or installed artifact is invalid")
    checks["self_session_exclusion"] = "pass"

    with tempfile.TemporaryDirectory() as temporary_name:
        run_dir = Path(temporary_name) / "run"
        run_dir.mkdir(mode=0o700)
        secret = generate_run_secret()
        collector = OfflineCollector(run_id, secret, run_dir / "events.jsonl")
        collector.start()
        descriptor_path = run_dir / "descriptor.json"
        descriptor = create_descriptor(
            descriptor_path,
            secret,
            run_id=run_id,
            key_id="offline-key",
            collector_url=collector.url,
            mission_root_digest="a" * 64,
            profile_digest=profile_result.digest,
            isolation_digest=isolation_result.config_digest,
            gate_surface_digest=gate_surface_digest,
            installed_artifact_digest=installed_artifact_digest,
            latch_path=run_dir / "latch.json",
            ttl_seconds=300,
        )
        collector.bind_descriptor(descriptor)
        environment = {RUN_FILE_ENV: str(descriptor_path), RUN_SECRET_ENV: secret}
        worker_a_alias = make_alias(secret, "session", "worker-a-raw")
        worker_b_alias = make_alias(secret, "session", "worker-b-raw")
        collector.queue_hook_output(
            worker_a_alias,
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": f"[shadow:offline-route-a] {worker_a_marker}",
                }
            },
        )
        target = run_installed_cache_hook(
            project_root,
            _hook_event("PostToolUse", "worker-a-raw"),
            environment=environment,
            expected_artifact_digest=installed_artifact_digest,
        )
        sibling = run_installed_cache_hook(
            project_root,
            _hook_event("PostToolUse", "worker-b-raw"),
            environment=environment,
            expected_artifact_digest=installed_artifact_digest,
        )
        if (
            worker_a_marker not in target.stdout
            or sibling.stdout
            or target.installed_artifact_digest != installed_artifact_digest
            or sibling.installed_artifact_digest != installed_artifact_digest
        ):
            raise RuntimeError("target-only hook routing failed")
        if collector.delivered_targets != [worker_a_alias]:
            raise RuntimeError("collector delivered guidance to the wrong target")
        if worker_b_alias in collector.delivered_targets:
            raise RuntimeError("sibling received target guidance")
        checks["target_only_guidance"] = "pass"

        write_latch(
            run_dir / "latch.json",
            secret,
            descriptor,
            registry=observation_registry,
            scope="worker",
            target_id="worker-a-raw",
            blocker_id="offline-blocker",
            state="active",
            generation=1,
            direct_evidence_ids=["obs-block-direct"],
            probe_result_id="obs-block-probe",
            correction_evidence_ids=[],
            provenance_status="untrusted_provenance",
            ttl_seconds=60,
        )
        collector.stop()
        first_stop = run_installed_cache_hook(
            project_root,
            _hook_event("SubagentStop", "worker-a-raw"),
            expected_artifact_digest=installed_artifact_digest,
            environment=environment,
        )
        retry_stop = run_installed_cache_hook(
            project_root,
            _hook_event("SubagentStop", "worker-a-raw"),
            expected_artifact_digest=installed_artifact_digest,
            environment=environment,
        )
        if not first_stop.stdout or json.loads(first_stop.stdout) != json.loads(
            retry_stop.stdout
        ):
            raise RuntimeError("signed latch did not survive collector outage")
        write_latch(
            run_dir / "latch.json",
            secret,
            descriptor,
            registry=observation_registry,
            scope="worker",
            target_id="worker-a-raw",
            blocker_id="offline-blocker",
            state="resolved",
            generation=2,
            direct_evidence_ids=["obs-block-direct"],
            probe_result_id="obs-block-probe",
            correction_evidence_ids=["obs-block-clear"],
            provenance_status="untrusted_provenance",
            ttl_seconds=60,
        )
        released = run_installed_cache_hook(
            project_root,
            _hook_event("SubagentStop", "worker-a-raw"),
            environment=environment,
            expected_artifact_digest=installed_artifact_digest,
        )
        if (
            not released.stdout
            or json.loads(released.stdout).get("decision") != "block"
            or "completion state cannot be verified"
            not in json.loads(released.stdout).get("reason", "")
        ):
            raise RuntimeError("resolved outage latch did not fail closed")
        checks["collector_outage_latch"] = "pass"

        persisted = (run_dir / "events.jsonl").read_text(encoding="utf-8")
        for forbidden in (
            "worker-a-raw",
            "worker-b-raw",
            "/private/",
            secret,
            secret_canary,
        ):
            if forbidden in persisted:
                raise RuntimeError("private data survived in the offline ledger")
        checks["pre_persistence_redaction"] = "pass"
        if '"provenance_status":"untrusted_provenance"' not in persisted:
            raise RuntimeError("offline hook provenance was not marked untrusted")
        checks["untrusted_provenance_marking"] = "pass"

    for transition in PROTECTED_TRANSITIONS:
        try:
            authorize_protected_transition(
                registry=observation_registry,
                provenance_status="untrusted_provenance",
                transition=transition,
                observation_ids=(),
                run_id=run_id,
                target_id="worker-a-raw",
                risk_id="offline-blocker",
            )
        except EvidenceRegistryError:
            pass
        else:
            raise RuntimeError(f"untrusted {transition} transition was accepted")
        authorize_protected_transition(
            registry=observation_registry,
            provenance_status="untrusted_provenance",
            transition=transition,
            observation_ids=observation_registry.observation_ids_for(transition),
            run_id=run_id,
            target_id="worker-a-raw",
            risk_id="offline-blocker",
        )
    checks["provenance_policy"] = "pass"

    primary = {name: "pass" for name in CAPABILITY_NAMES}
    fallback = dict(primary)
    fallback["live_transcript_access"] = "fallback"
    fallback["hook_event_provenance"] = "fallback"
    stopped = dict(primary)
    stopped["session_hooks"] = "stop"
    classifications = {
        "primary": classify_gate(primary),
        "fallback": classify_gate(fallback),
        "stop": classify_gate(stopped),
    }
    if classifications != {
        "primary": "primary-pass",
        "fallback": "fallback-pass",
        "stop": "stop",
    }:
        raise RuntimeError("gate classifier is not deterministic")
    checks["gate_classifier"] = "pass"
    checks["sealed_source_oracle"] = "pass"
    checks["factory_profile_schema"] = "pass"
    checks["isolation_manifest_schema"] = "pass"
    checks["transport_integrity_and_latch"] = "pass"
    checks["byte_bounded_queue"] = "pass"

    result: dict[str, Any] = {
        "schema_version": "0.1",
        "status": "offline-harness-pass",
        "live_gate_verdict": "unverified",
        "live_run_count_incremented": False,
        "factory_calls": 0,
        "model_calls": 0,
        "external_network_calls": 0,
        "loopback_hook_requests": 2,
        "fixture_manifest_digest": fixture_result["manifest_digest"],
        "factory_profile_digest": profile_result.digest,
        "isolation_config_digest": isolation_result.config_digest,
        "gate_surface_digest": gate_surface_digest,
        "installed_plugin_artifact_digest": installed_artifact_digest,
        "factory_profile_status": profile_result.status,
        "hook_provenance_status": "untrusted_provenance",
        "classification_examples": classifications,
        "checks": dict(sorted(checks.items())),
    }
    if output_path is not None:
        _write_private_result(output_path, result)
    return result


_MISSION_VISIBLE_FIXTURE_FILES = (
    "mission.md",
    "api-schema.json",
    "db-schema.sql",
    "stale-guide.md",
)


def prepare_live_workspace(fixture_path: Path, runtime_path: Path) -> Path:
    source = fixture_path.resolve(strict=True)
    runtime = runtime_path.resolve(strict=True)
    if not source.is_dir() or fixture_path.is_symlink():
        raise GateClassificationError("sealed fixture directory is invalid")
    if source == runtime or source in runtime.parents or runtime in source.parents:
        raise GateClassificationError("live workspace overlaps sealed fixture state")
    for path in source.rglob("*"):
        if path.is_symlink():
            raise GateClassificationError("sealed fixture contains a symlink")
        if not path.is_file() and not path.is_dir():
            raise GateClassificationError("sealed fixture contains an irregular path")
    workspace = runtime / "workspace"
    try:
        workspace.mkdir(mode=0o700)
        for file_name in _MISSION_VISIBLE_FIXTURE_FILES:
            source_file = source / file_name
            if not source_file.is_file() or source_file.is_symlink():
                raise GateClassificationError(
                    f"Mission-visible fixture file is invalid: {file_name}"
                )
            destination = workspace / file_name
            shutil.copy2(source_file, destination)
            os.chmod(destination, 0o600)
    except OSError as error:
        raise GateClassificationError("writable live workspace is unavailable") from error
    mission_file = workspace / "mission.md"
    if not mission_file.is_file() or mission_file.is_symlink():
        raise GateClassificationError("live workspace Mission file is unavailable")
    return workspace


def run_live_command(options: argparse.Namespace, project_root: Path) -> dict[str, Any]:
    import importlib.metadata
    import secrets

    from .live import (
        AuthorizationRecord,
        DroidCommandBoundary,
        LiveGateError,
        LiveRunCounter,
        PreflightAttemptCounter,
        export_sanitized_ledger,
        load_private_factory_credential,
        load_private_record,
        run_authorized_live,
        run_inert_control_session,
        start_inert_control_session,
        run_zero_tool_probe,
        validate_live_preflight,
    )
    from .live_control import LiveGateController

    required_paths = {
        "fixture": options.fixture,
        "fixture_manifest_pin": options.fixture_manifest_pin,
        "authorization_record": options.authorization_record,
        "workspace_dir": options.workspace_dir,
        "preflight_record": options.preflight_record,
        "factory_credential_file": options.factory_credential_file,
        "droid_binary": options.droid_binary,
        "installed_plugin_root": options.installed_plugin_root,
        "mission_file": options.mission_file,
        "live_run_ledger": options.live_run_ledger,
        "preflight_attempt_ledger": options.preflight_attempt_ledger,
        "runtime_dir": options.runtime_dir,
        "lima_config": options.lima_config,
        "output": options.output,
    }
    missing_paths = sorted(
        name for name, value in required_paths.items() if value is None
    )
    model_settings = {
        "orchestrator_model": options.orchestrator_model,
        "orchestrator_reasoning": options.reasoning_effort,
        "worker_model": options.worker_model,
        "worker_reasoning": options.worker_reasoning_effort,
        "validator_model": options.validator_model,
        "validator_reasoning": options.validator_reasoning_effort,
        "probe_model": options.probe_model,
        "probe_reasoning": options.probe_reasoning_effort,
    }
    missing_models = sorted(
        name for name, value in model_settings.items() if not value
    )
    if missing_paths or missing_models:
        missing = ", ".join(missing_paths + missing_models)
        raise LiveGateError(f"live execution inputs are incomplete: {missing}")
    PreflightAttemptCounter(
        options.preflight_attempt_ledger.resolve()
    ).claim_attempt()

    fixture_path = options.fixture.resolve()
    mission_file = options.mission_file.resolve()
    lima_config = options.lima_config.resolve()
    if mission_file.parent != fixture_path or mission_file.name != "mission.md":
        raise LiveGateError("the Mission file must be the sealed fixture mission")
    offline = run_dry_run(
        fixture_path=fixture_path,
        fixture_manifest_pin=options.fixture_manifest_pin.resolve(),
        output_path=None,
        project_root=project_root,
    )
    if (
        offline.get("status") != "offline-harness-pass"
        or any(value != "pass" for value in offline.get("checks", {}).values())
    ):
        raise LiveGateError("the no-spend gate is not fully passing")
    preflight_record = load_private_record(
        options.preflight_record.resolve(), "preflight"
    )
    authorization = AuthorizationRecord.from_mapping(
        load_private_record(
            options.authorization_record.resolve(), "authorization"
        )
    )
    credential_environment = load_private_factory_credential(
        options.factory_credential_file.resolve()
    )
    expected_bindings = preflight_record.get("bindings")
    if not isinstance(expected_bindings, dict):
        raise LiveGateError("preflight bindings are missing")
    installed_plugin_root = resolve_installed_plugin_root(
        Path.home() / ".factory" / "plugins",
        plugin_name="shadow-mission",
        plugin_version=str(expected_bindings.get("plugin_version", "")),
        expected_digest=str(
            expected_bindings.get("installed_plugin_artifact_digest", "")
        ),
    )
    if options.installed_plugin_root.resolve() != installed_plugin_root:
        raise LiveGateError(
            "installed plugin path differs from measured Factory state"
        )
    actual_bindings = {
        "plugin_version": json.loads(
            (project_root / ".factory-plugin/plugin.json").read_text(
                encoding="utf-8"
            )
        )["version"],
        "droid_sdk_version": importlib.metadata.version("droid-sdk"),
        "gate_surface_digest": offline["gate_surface_digest"],
        "installed_plugin_artifact_digest": compute_plugin_artifact_digest(
            installed_plugin_root
        ),
    }
    for field_name, observed in actual_bindings.items():
        if expected_bindings.get(field_name) != observed:
            raise LiveGateError(f"live binding drift: {field_name}")

    preflight_summary = validate_live_preflight(
        preflight_record,
        authorization,
        expected_bindings,
        model_settings,
        lima_config,
    )

    boundary = DroidCommandBoundary(
        executable=options.droid_binary.resolve(),
        expected_version=str(expected_bindings.get("droid_version", "")),
        expected_digest=str(
            expected_bindings.get("droid_binary_digest", "")
        ),
        installation_channel=str(
            expected_bindings.get("droid_installation_channel", "")
        ),
        credential_environment=credential_environment,
    )
    boundary.validate_model_settings(
        model_settings,
        preflight_record.get("model_catalog"),
    )
    if options.live_preflight_only:
        return {
            "schema_version": "0.1",
            "status": "live-preflight-pass",
            "live_run_count_incremented": False,
            "model_calls": 0,
            "factory_calls": 0,
        }
    run_id = f"shadow-feasibility-{secrets.token_hex(16)}"
    workspace_parent = options.workspace_dir.resolve()
    runtime_parent = options.runtime_dir.resolve()
    output_directory = options.output.resolve()
    private_paths = (runtime_parent, output_directory, workspace_parent)
    if len(set(private_paths)) != len(private_paths) or any(
        left in right.parents or right in left.parents
        for index, left in enumerate(private_paths)
        for right in private_paths[index + 1 :]
    ):
        raise LiveGateError(
            "private runtime, Mission workspace, and evidence export must be separate"
        )
    runtime_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(runtime_parent, 0o700)
    workspace_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(workspace_parent, 0o700)
    output_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_directory, 0o700)
    runtime_path = runtime_parent / run_id
    runtime_path.mkdir(mode=0o700)
    workspace_run_path = workspace_parent / run_id
    workspace_run_path.mkdir(mode=0o700)
    workspace_path = prepare_live_workspace(fixture_path, workspace_run_path)
    workspace_mission_file = workspace_path / "mission.md"
    descriptor_path = runtime_path / "descriptor.json"
    latch_path = runtime_path / "latch.json"
    ledger_path = runtime_path / "events.jsonl"
    registry_root = runtime_path / "observation-registries"
    registry_root.mkdir(mode=0o700)

    def frozen_blocker_registry(
        target_id: str,
        risk_id: str,
        correction: bool,
        probe_evidence: Any,
    ) -> FrozenObservationRegistry:
        if (
            probe_evidence.authoritative_value != "cents"
            or not probe_evidence.zero_tools
            or not probe_evidence.activation_stripped
            or not probe_evidence.probe_result_id
        ):
            raise LiveGateError("external blocker probe evidence is invalid")

        def contains(name: str, *values: str) -> bool:
            path = workspace_path / name
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags)
            except OSError:
                return False
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > (1 << 20):
                    return False
                payload = os.pread(descriptor, metadata.st_size, 0)
                if (
                    len(payload) != metadata.st_size
                    or os.fstat(descriptor).st_size != metadata.st_size
                ):
                    return False
                text = payload.decode("utf-8")
            except (OSError, UnicodeError):
                return False
            finally:
                os.close(descriptor)
            return all(value in text for value in values)

        if risk_id == "worker-conflict":
            direct = contains(
                "worker-a.txt",
                "SHADOW-FEASIBILITY-ASSISTANT-A-7319",
                "dollars",
            )
            corrected = contains(
                "worker-a.txt",
                "CORRECTION-WORKER-A-7319",
                "cents",
            )
            target_valid = target_id.startswith("session-")
        elif risk_id == "mission-finalization":
            direct = contains(
                "worker-a.txt",
                "SHADOW-FEASIBILITY-ASSISTANT-A-7319",
                "cents",
            ) and contains(
                "worker-b.txt",
                "SHADOW-FEASIBILITY-ASSISTANT-B-4826",
                "dollars",
            )
            corrected = contains(
                "mission-correction.txt",
                "CORRECTION-MISSION-7319",
            )
            target_valid = target_id == run_id
        else:
            raise LiveGateError("external blocker risk is unknown")
        if not target_valid or not direct or (correction and not corrected):
            raise LiveGateError("external blocker observation is incomplete")

        records = [
            FrozenObservation(
                observation_id=f"{risk_id}-direct",
                run_id=run_id,
                target_id=target_id,
                risk_id=risk_id,
                transition="blocker_create",
                kind="direct_evidence",
                status="observed",
                source_class="external_frozen",
            ),
            FrozenObservation(
                observation_id=f"{probe_evidence.probe_result_id}-{risk_id}",
                run_id=run_id,
                target_id=target_id,
                risk_id=risk_id,
                transition="blocker_create",
                kind="probe_confirmation",
                status="confirmed",
                source_class="external_frozen",
            ),
        ]
        if correction:
            records.append(
                FrozenObservation(
                    observation_id=f"{risk_id}-correction",
                    run_id=run_id,
                    target_id=target_id,
                    risk_id=risk_id,
                    transition="blocker_clear",
                    kind="correction",
                    status="corrected",
                    source_class="external_frozen",
                )
            )
        registry_path = registry_root / (
            f"{risk_id}-{'resolved' if correction else 'active'}.json"
        )
        return _freeze_observation_registry(registry_path, records)

    secret = generate_run_secret()
    controller = LiveGateController(
        run_id=run_id,
        secret=secret,
        fixture_path=workspace_path,
        descriptor_path=descriptor_path,
        latch_path=latch_path,
        offline_negative_controls=True,
        profile_status=str(preflight_summary["factory_profile_status"]),
        trusted_transcript_root=(Path.home() / ".factory"),
        observation_registry_supplier=frozen_blocker_registry,
    )
    collector = OfflineCollector(
        run_id,
        secret,
        ledger_path,
        event_handler=controller.handle,
    )
    collector.start()
    result: dict[str, Any] | None = None
    try:
        descriptor = create_descriptor(
            descriptor_path,
            secret,
            run_id=run_id,
            key_id=secrets.token_hex(16),
            collector_url=collector.url,
            mission_root_digest=_sha256(workspace_mission_file),
            profile_digest=str(expected_bindings["factory_profile_digest"]),
            isolation_digest=str(expected_bindings["isolation_digest"]),
            gate_surface_digest=str(expected_bindings["gate_surface_digest"]),
            installed_artifact_digest=str(
                expected_bindings["installed_plugin_artifact_digest"]
            ),
            latch_path=latch_path,
            ttl_seconds=3_600,
        )
        collector.bind_descriptor(descriptor)
        controller.bind(descriptor, collector)
        probe_snapshot = json.dumps(
            {
                "schema_version": "0.1",
                "observed_source": json.loads(
                    (fixture_path / "observed-source.json").read_text(
                        encoding="utf-8"
                    )
                ),
                "api_schema": json.loads(
                    (fixture_path / "api-schema.json").read_text(
                        encoding="utf-8"
                    )
                ),
                "database_schema": (
                    fixture_path / "db-schema.sql"
                ).read_text(encoding="utf-8"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        def start_internal_controls() -> Any:
            decoy_control = start_inert_control_session(
                boundary=boundary,
                authenticated_guest_home=Path.home().resolve(),
                fixture_path=workspace_path,
                model=str(model_settings["probe_model"]),
                reasoning=str(model_settings["probe_reasoning"]),
                alias_secret=secret,
                internal=False,
            )
            try:
                inert_alias = run_inert_control_session(
                    boundary=boundary,
                    authenticated_guest_home=Path.home().resolve(),
                    fixture_path=workspace_path,
                    model=str(model_settings["probe_model"]),
                    reasoning=str(model_settings["probe_reasoning"]),
                    alias_secret=secret,
                    internal=True,
                )
                controller.set_control_aliases(
                    decoy_alias=decoy_control.alias,
                    inert_alias=inert_alias,
                    decoy_active_during_guidance=True,
                )
            except BaseException:
                decoy_control.close()
                raise
            return decoy_control

        def run_probe() -> Any:
            probe_evidence = run_zero_tool_probe(
                boundary=boundary,
                authenticated_guest_home=Path.home().resolve(),
                fixture_path=workspace_path,
                model=str(model_settings["probe_model"]),
                reasoning=str(model_settings["probe_reasoning"]),
                snapshot=probe_snapshot,
                alias_secret=secret,
            )
            controller.set_probe(probe_evidence)
            return probe_evidence

        def supply_observations(
            expected_run_id: str,
            mission_result: Any,
            probe_evidence: Any,
            usage_observations: Mapping[str, object],
        ) -> Mapping[str, object]:
            if (
                expected_run_id != run_id
                or probe_evidence.internal_session_alias
                != controller.probe_session_alias
            ):
                raise LiveGateError("live evidence uses a different run")
            collector.stop()
            export_descriptor = export_sanitized_ledger(
                ledger_path,
                output_directory,
            )
            observations = controller.finalize(
                mission_result=mission_result,
                usage=usage_observations,
            )
            observations["evidence_export"] = export_descriptor
            return observations

        candidate = run_authorized_live(
            preflight_record=preflight_record,
            authorization=authorization,
            expected_bindings=expected_bindings,
            model_settings=model_settings,
            lima_config=lima_config,
            boundary=boundary,
            mission_file=workspace_mission_file,
            run_id=run_id,
            mission_environment={
                RUN_FILE_ENV: str(descriptor_path),
                RUN_DESCRIPTOR_ENV: json.dumps(
                    descriptor,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                RUN_SECRET_ENV: secret,
                "SHADOW_MISSION_COLLECTOR_URL": collector.url,
                "SHADOW_MISSION_CORRELATION_ID": run_id,
                "SHADOW_MISSION_LOG_GROUP_ID": run_id,
            },
            counter=LiveRunCounter(options.live_run_ledger.resolve()),
            output_path=output_directory / "gate.candidate.json",
            inert_control=start_internal_controls,
            probe=run_probe,
            verify_installed_plugin=lambda: compute_plugin_artifact_digest(
                installed_plugin_root
            ),
            observation_supplier=supply_observations,
        )
        result = dict(candidate)
    finally:
        collector.stop()
        secret = ""
        shutil.rmtree(workspace_run_path)
        shutil.rmtree(runtime_path)
    if result is None:
        raise LiveGateError("live execution produced no candidate gate")
    return result
def run_capture_live_preflight_command(
    options: argparse.Namespace,
    project_root: Path,
) -> dict[str, Any]:
    import importlib.metadata
    from decimal import Decimal

    from .live import (
        BudgetLedger,
        DroidCommandBoundary,
        LiveGateError,
        LiveRunCounter,
        build_cost_and_budget_evidence,
        load_private_factory_credential,
        load_private_record,
    )

    required = {
        "fixture": options.fixture,
        "fixture_manifest_pin": options.fixture_manifest_pin,
        "output": options.output,
        "factory_credential_file": options.factory_credential_file,
        "droid_binary": options.droid_binary,
        "installed_plugin_root": options.installed_plugin_root,
        "workspace_dir": options.workspace_dir,
        "live_run_ledger": options.live_run_ledger,
        "lima_config": options.lima_config,
        "factory_root": options.factory_root,
        "marketplace_root": options.marketplace_root,
        "system_settings_path": options.system_settings_path,
        "private_root": options.private_root,
        "protected_root": options.protected_root,
        "billing_record": options.billing_record,
        "isolation_canary_record": options.isolation_canary_record,
    }
    missing = sorted(name for name, value in required.items() if value is None)
    models = {
        "orchestrator_model": options.orchestrator_model,
        "orchestrator_reasoning": options.reasoning_effort,
        "worker_model": options.worker_model,
        "worker_reasoning": options.worker_reasoning_effort,
        "validator_model": options.validator_model,
        "validator_reasoning": options.validator_reasoning_effort,
        "probe_model": options.probe_model,
        "probe_reasoning": options.probe_reasoning_effort,
    }
    missing.extend(sorted(name for name, value in models.items() if not value))
    if missing:
        raise LiveGateError(
            "preflight capture inputs are incomplete: " + ", ".join(missing)
        )

    fixture_path = options.fixture.resolve()
    lima_config = options.lima_config.resolve()
    offline = run_dry_run(
        fixture_path=fixture_path,
        fixture_manifest_pin=options.fixture_manifest_pin.resolve(),
        output_path=None,
        project_root=project_root,
    )
    if (
        offline.get("status") != "offline-harness-pass"
        or any(value != "pass" for value in offline.get("checks", {}).values())
    ):
        raise LiveGateError("the no-spend gate is not fully passing")

    try:
        artifacts = json.loads(
            (
                project_root / "ops/lima/shadow-feasibility-artifacts.json"
            ).read_text(encoding="utf-8")
        )
        droid_artifact = artifacts["droid"]
        lima_artifact = artifacts["lima"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise LiveGateError("approved guest artifact inventory is unavailable") from error
    if not isinstance(droid_artifact, Mapping) or not isinstance(
        lima_artifact, Mapping
    ):
        raise LiveGateError("approved guest artifact inventory is invalid")

    installed_digest = compute_plugin_artifact_digest(
        options.installed_plugin_root.resolve()
    )
    resolved_installed = resolve_installed_plugin_root(
        options.factory_root.resolve() / "plugins",
        plugin_name="shadow-mission",
        plugin_version="0.1.0",
        expected_digest=installed_digest,
    )
    if resolved_installed != options.installed_plugin_root.resolve():
        raise LiveGateError("installed plugin resolution differs from the capture input")

    profile = capture_factory_profile(
        factory_root=options.factory_root.resolve(),
        project_root=project_root,
        installed_plugin_root=resolved_installed,
        trusted_root=options.workspace_dir.resolve(),
        credential_root=options.factory_credential_file.resolve().parent,
        input_root=project_root,
        private_root=options.private_root.resolve(),
        protected_root=options.protected_root.resolve(),
        marketplace_root=options.marketplace_root.resolve(),
        system_settings_path=options.system_settings_path.resolve(),
        shadow_activation=True,
    )
    profile_result = validate_factory_profile(profile)

    isolation_record = load_private_record(
        options.isolation_canary_record.resolve(),
        "isolation canary",
    )
    if (
        set(isolation_record)
        != {
            "schema_version",
            "source",
            "captured_without_model_call",
            "output_digest",
            "canaries",
            "runtime",
        }
        or isolation_record.get("schema_version") != "0.1"
        or isolation_record.get("source") != "host-and-guest-canary-probe"
        or isolation_record.get("captured_without_model_call") is not True
        or not isinstance(isolation_record.get("output_digest"), str)
        or len(str(isolation_record["output_digest"])) != 64
        or not isinstance(isolation_record.get("canaries"), Mapping)
        or not isinstance(isolation_record.get("runtime"), Mapping)
    ):
        raise LiveGateError("isolation canary evidence differs from the contract")
    isolation_canaries = dict(isolation_record["canaries"])
    isolation_runtime = dict(isolation_record["runtime"])
    if set(isolation_runtime) != {
        "vm_name",
        "image_digest",
        "host_mounts",
        "ssh_agent_forwarding",
        "proxy_environment_propagation",
        "containerd_enabled",
    }:
        raise LiveGateError("active Lima evidence differs from the contract")
    expected_isolation_output_digest = hashlib.sha256(
        json.dumps(
            {
                "canaries": isolation_canaries,
                "runtime": isolation_runtime,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    if isolation_record["output_digest"] != expected_isolation_output_digest:
        raise LiveGateError("isolation canary evidence digest does not match")
    profile_settings = profile.get("settings")
    if not isinstance(profile_settings, Mapping):
        raise LiveGateError("measured Factory settings are missing")
    profile_sandbox = profile_settings.get("sandbox")
    if not isinstance(profile_sandbox, Mapping):
        raise LiveGateError("measured Factory sandbox settings are missing")
    isolation = capture_live_isolation_manifest(
        lima_config=lima_config,
        lima_version=str(lima_artifact.get("version", "")),
        canaries=isolation_canaries,
        vm_name=str(isolation_runtime.get("vm_name", "")),
        image_digest=str(isolation_runtime.get("image_digest", "")),
        host_mounts=list(isolation_runtime.get("host_mounts", [])),
        ssh_agent_forwarding=bool(
            isolation_runtime.get("ssh_agent_forwarding")
        ),
        proxy_environment_propagation=bool(
            isolation_runtime.get("proxy_environment_propagation")
        ),
        containerd_enabled=bool(isolation_runtime.get("containerd_enabled")),
        factory_sandbox_enabled=bool(profile_sandbox.get("enabled")),
        factory_sandbox_mode=str(profile_sandbox.get("mode", "")),
    )

    credential_environment = load_private_factory_credential(
        options.factory_credential_file.resolve()
    )
    boundary = DroidCommandBoundary(
        executable=options.droid_binary.resolve(),
        expected_version=str(droid_artifact.get("version", "")),
        expected_digest=str(droid_artifact.get("binary_sha256", "")),
        installation_channel=str(droid_artifact.get("installation_channel", "")),
        credential_environment=credential_environment,
    )
    droid_observation = boundary.observe("preflight")
    model_catalog = boundary.capture_model_catalog(options.workspace_dir.resolve())
    boundary.validate_model_settings(models, model_catalog)
    usage_observation = boundary.capture_usage("pre_run")

    live_run_count = LiveRunCounter(options.live_run_ledger.resolve()).count
    billing = load_private_record(options.billing_record.resolve(), "billing")
    budget, cost_evidence = build_cost_and_budget_evidence(
        billing,
        usage_observation,
        live_run_count=live_run_count,
    )
    budget_ledger = BudgetLedger.from_mapping(budget)
    if (
        budget_ledger.pro_subscription <= Decimal("0")
        or budget_ledger.extra_usage_purchases <= Decimal("0")
        or budget_ledger.remaining_extra_usage <= Decimal("0")
    ):
        raise LiveGateError("Factory Pro or Extra Usage is unavailable")

    plugin_metadata = json.loads(
        (project_root / ".factory-plugin/plugin.json").read_text(encoding="utf-8")
    )
    bindings = {
        "droid_version": droid_observation["version"],
        "droid_installation_channel": str(
            droid_artifact["installation_channel"]
        ),
        "droid_binary_digest": droid_observation["binary_digest"],
        "droid_auto_update_control": droid_observation["auto_update_control"],
        "plugin_version": str(plugin_metadata["version"]),
        "droid_sdk_version": importlib.metadata.version("droid-sdk"),
        "lima_version": str(lima_artifact["version"]),
        "vm_image_digest": str(lima_artifact["image_digest"]).removeprefix(
            "sha256:"
        ),
        "factory_profile_digest": profile_result.digest,
        "isolation_digest": hashlib.sha256(lima_config.read_bytes()).hexdigest(),
        "gate_surface_digest": compute_gate_surface_digest(project_root),
        "installed_plugin_artifact_digest": installed_digest,
    }
    if (
        profile.get("gate_surface_digest") != bindings["gate_surface_digest"]
        or profile.get("installed_plugin_artifact_digest") != installed_digest
    ):
        raise LiveGateError("measured Factory profile binding failed")

    checks = {
        "offline_dry_run": True,
        "lima_manifest": True,
        "guest_droid_installed": True,
        "guest_droid_checksum": True,
        "automatic_updates_disabled": True,
        "guest_authentication": True,
        "factory_pro": True,
        "extra_usage": True,
        "usage_evidence": True,
        "models_and_reasoning": True,
        "factory_profile_inventory": True,
        "plugin_inventory": True,
        "managed_configuration_measurable": True,
        "unknown_inherited_surfaces_absent": True,
        "sealed_fixture_binding": True,
        "installed_artifact_binding": True,
        "isolation_binding": True,
        "same_project_decoy_planned": True,
        "no_prior_feasibility_mission": live_run_count == 0,
        "teardown_ready": True,
        "evidence_export_ready": True,
    }
    if not all(checks.values()):
        raise LiveGateError("one or more live preflight checks failed")
    preflight = {
        "schema_version": "0.1",
        "checks": checks,
        "bindings": bindings,
        "models": models,
        "budget": budget,
        "factory_profile": profile,
        "isolation_manifest": isolation,
        "model_catalog": model_catalog,
        "cost_evidence": cost_evidence,
    }
    _write_private_result(options.output.resolve(), preflight)
    return {
        "schema_version": "0.1",
        "status": "live-preflight-captured",
        "model_calls": 0,
        "live_run_count_incremented": False,
        "checks": checks,
        "bindings": bindings,
        "models": models,
        "budget": budget_ledger.sanitized(),
    }


_ALLOWED_PSEUDO_MOUNTS = {
    "autofs": ("/proc", "/sys"),
    "binfmt_misc": ("/proc/sys/fs/binfmt_misc",),
    "cgroup": ("/sys/fs/cgroup",),
    "cgroup2": ("/sys/fs/cgroup",),
    "configfs": ("/sys/kernel/config",),
    "debugfs": ("/sys/kernel/debug",),
    "devpts": ("/dev/pts",),
    "devtmpfs": ("/dev",),
    "efivarfs": ("/sys/firmware/efi/efivars",),
    "fusectl": ("/sys/fs/fuse/connections",),
    "hugetlbfs": ("/dev/hugepages",),
    "mqueue": ("/dev/mqueue",),
    "proc": ("/proc",),
    "pstore": ("/sys/fs/pstore",),
    "ramfs": ("/run",),
    "rpc_pipefs": ("/run/rpc_pipefs",),
    "securityfs": ("/sys/kernel/security",),
    "sysfs": ("/sys",),
    "tmpfs": ("/dev", "/run", "/sys", "/tmp"),
    "tracefs": ("/sys/kernel/tracing",),
}


def _mount_matches_sealed_policy(item: Mapping[str, Any]) -> bool:
    target_value = item.get("target")
    source_value = item.get("source")
    fstype_value = item.get("fstype")
    options_value = item.get("options")
    if not all(
        isinstance(value, str) and value
        for value in (target_value, source_value, fstype_value, options_value)
    ):
        return False
    target = str(target_value)
    source = str(source_value)
    fstype = str(fstype_value).lower()
    options = {value.strip() for value in str(options_value).split(",")}
    if (
        ".." in target.split("/")
        or {"bind", "rbind"} & options
        or source.startswith(("//", "/Users/", "/Volumes/"))
        or ":" in source
    ):
        return False
    if target == "/" and fstype == "ext4":
        return source.startswith("/dev/vda1")
    if target == "/boot/efi" and fstype == "vfat":
        return source.startswith("/dev/vda15")
    roots = _ALLOWED_PSEUDO_MOUNTS.get(fstype)
    return roots is not None and any(
        target == root or target.startswith(f"{root}/") for root in roots
    )


def run_capture_isolation_canaries_command(
    options: argparse.Namespace,
    project_root: Path,
) -> dict[str, Any]:
    from .live import LiveGateError

    if options.limactl_binary is None or options.output is None:
        raise LiveGateError("isolation canary capture inputs are incomplete")
    executable = options.limactl_binary.resolve()
    try:
        metadata = executable.stat()
    except OSError as error:
        raise LiveGateError("limactl is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise LiveGateError("limactl is not a regular file")
    environment = {
        key: os.environ[key]
        for key in ("HOME", "PATH", "LANG", "LC_ALL", "TERM", "TMPDIR")
        if key in os.environ
    }

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                (str(executable), *arguments),
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise LiveGateError("Lima isolation canary command failed") from error
        if len(result.stdout.encode()) + len(result.stderr.encode()) > (1 << 20):
            raise LiveGateError("Lima isolation canary output exceeded its limit")
        return result

    version = run("--version")
    if (
        version.returncode != 0
        or "2.2.0" not in f"{version.stdout}\n{version.stderr}"
    ):
        raise LiveGateError("Lima version drifted before isolation capture")
    inventory_result = run("list", "shadow-feasibility", "--json")
    try:
        inventory = json.loads(inventory_result.stdout)
        config = inventory["config"]
        images = config["images"]
        ssh_config = config["ssh"]
        containerd_config = config["containerd"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise LiveGateError("active Lima inventory is invalid") from error
    if (
        inventory_result.returncode != 0
        or not isinstance(inventory, Mapping)
        or inventory.get("status") != "Running"
        or inventory.get("name") != "shadow-feasibility"
        or not isinstance(config, Mapping)
        or not isinstance(images, list)
        or len(images) != 1
        or not isinstance(images[0], Mapping)
        or config.get("mounts") != []
        or not isinstance(ssh_config, Mapping)
        or ssh_config.get("forwardAgent") is not False
        or config.get("propagateProxyEnv") is not False
        or not isinstance(containerd_config, Mapping)
        or containerd_config.get("system") is not False
        or containerd_config.get("user") is not False
    ):
        raise LiveGateError("active Lima isolation differs from the contract")
    runtime = {
        "vm_name": str(inventory["name"]),
        "image_digest": str(images[0].get("digest", "")),
        "host_mounts": [],
        "ssh_agent_forwarding": bool(ssh_config["forwardAgent"]),
        "proxy_environment_propagation": bool(config["propagateProxyEnv"]),
        "containerd_enabled": bool(
            containerd_config["system"] or containerd_config["user"]
        ),
    }
    mount_table_result = run(
        "shell",
        "shadow-feasibility",
        "--",
        "findmnt",
        "--json",
        "--output",
        "TARGET,SOURCE,FSTYPE,OPTIONS",
    )
    try:
        mount_table = json.loads(mount_table_result.stdout)
        filesystems = mount_table["filesystems"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise LiveGateError("active guest mount inventory is invalid") from error
    if mount_table_result.returncode != 0 or not isinstance(filesystems, list):
        raise LiveGateError("active guest mount inventory is invalid")
    mount_entries: list[Mapping[str, Any]] = []
    pending_mounts: list[Any] = list(filesystems)
    while pending_mounts:
        item = pending_mounts.pop()
        if not isinstance(item, Mapping):
            raise LiveGateError("active guest mount inventory is invalid")
        children = item.get("children", [])
        if not isinstance(children, list):
            raise LiveGateError("active guest mount inventory is invalid")
        mount_entries.append(item)
        pending_mounts.extend(children)
    canary_mount_table_clean = bool(mount_entries) and all(
        _mount_matches_sealed_policy(item) for item in mount_entries
    )
    visible_paths_result = run(
        "shell",
        "shadow-feasibility",
        "--",
        "sh",
        "-c",
        (
            "for path in /home/shadow/.[!.]* /home/shadow/..?* "
            "/home/shadow/*; do [ -e \"$path\" ] || continue; "
            "case \"${path##*/}\" in "
            ".factory|credential|input|output|private|protected|venv|workspace) ;; "
            "*) exit 1 ;; esac; done"
        ),
    )
    canary_visible_paths_allowlisted = visible_paths_result.returncode == 0

    host_descriptor = -1
    host_canary: Path | None = None
    canaries: dict[str, bool] = {}
    try:
        host_descriptor, host_name = tempfile.mkstemp(
            prefix="shadow-feasibility-host-canary-"
        )
        host_canary = Path(host_name)
        os.fchmod(host_descriptor, 0o600)
        os.write(host_descriptor, os.urandom(32))
        os.fsync(host_descriptor)
        os.close(host_descriptor)
        host_descriptor = -1
        before_digest = hashlib.sha256(host_canary.read_bytes()).hexdigest()
        commands = (
            (
                "host_read_canary_denied",
                (
                    "shell",
                    "shadow-feasibility",
                    "--",
                    "sh",
                    "-c",
                    'test ! -e "$1"',
                    "sh",
                    str(host_canary),
                ),
            ),
            (
                "host_write_canary_unchanged",
                (
                    "shell",
                    "shadow-feasibility",
                    "--",
                    "sh",
                    "-c",
                    'test ! -e "$1" && ! touch "$1"',
                    "sh",
                    str(host_canary),
                ),
            ),
            (
                "guest_protected_read_denied",
                (
                    "shell",
                    "shadow-feasibility",
                    "--",
                    "sh",
                    "-c",
                    "test ! -r /home/shadow/protected/read-canary",
                ),
            ),
            (
                "fixture_read_allowed",
                (
                    "shell",
                    "shadow-feasibility",
                    "--",
                    "test",
                    "-r",
                    "/home/shadow/input/feasibility/mission.md",
                ),
            ),
        )
        canaries = {
            name: run(*arguments).returncode == 0
            for name, arguments in commands
        }
        canaries["guest_mount_table_clean"] = canary_mount_table_clean
        canaries["guest_visible_paths_allowlisted"] = (
            canary_visible_paths_allowlisted
        )
        after_digest = hashlib.sha256(host_canary.read_bytes()).hexdigest()
        canaries["host_write_canary_unchanged"] = (
            canaries["host_write_canary_unchanged"]
            and before_digest == after_digest
        )
    finally:
        if host_descriptor >= 0:
            os.close(host_descriptor)
        if host_canary is not None:
            host_canary.unlink(missing_ok=True)
    if set(canaries) != {
        "host_read_canary_denied",
        "host_write_canary_unchanged",
        "guest_protected_read_denied",
        "fixture_read_allowed",
        "guest_mount_table_clean",
        "guest_visible_paths_allowlisted",
    } or any(value is not True for value in canaries.values()):
        raise LiveGateError("one or more isolation canaries failed")
    evidence = {
        "canaries": canaries,
        "runtime": runtime,
    }
    encoded = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    record = {
        "schema_version": "0.1",
        "source": "host-and-guest-canary-probe",
        "captured_without_model_call": True,
        "output_digest": hashlib.sha256(encoded).hexdigest(),
        **evidence,
    }
    _write_private_result(options.output.resolve(), record)
    return {
        "schema_version": "0.1",
        "status": "isolation-canaries-pass",
        "model_calls": 0,
        "factory_calls": 0,
        "live_run_count_incremented": False,
        "checks": canaries,
    }




def run_host_claim_command(
    options: argparse.Namespace,
    project_root: Path,
) -> dict[str, Any]:
    from .live import (
        AuthorizationRecord,
        LiveGateError,
        LiveRunCounter,
        load_private_record,
        validate_live_preflight,
    )

    required = {
        "authorization_record": options.authorization_record,
        "preflight_record": options.preflight_record,
        "lima_config": options.lima_config,
        "host_live_run_ledger": options.host_live_run_ledger,
        "orchestrator_model": options.orchestrator_model,
        "reasoning_effort": options.reasoning_effort,
        "worker_model": options.worker_model,
        "worker_reasoning_effort": options.worker_reasoning_effort,
        "validator_model": options.validator_model,
        "validator_reasoning_effort": options.validator_reasoning_effort,
        "probe_model": options.probe_model,
        "probe_reasoning_effort": options.probe_reasoning_effort,
    }
    missing = sorted(name for name, value in required.items() if value is None)
    if missing:
        raise LiveGateError(
            "host live-run claim inputs are incomplete: " + ", ".join(missing)
        )
    expected_ledger = (
        project_root / ".shadow-mission" / "feasibility-live-run.json"
    ).resolve()
    if options.host_live_run_ledger.resolve() != expected_ledger:
        raise LiveGateError("host live-run ledger path differs from the contract")
    preflight = load_private_record(
        options.preflight_record.resolve(),
        "preflight",
    )
    authorization = AuthorizationRecord.from_mapping(
        load_private_record(
            options.authorization_record.resolve(),
            "authorization",
        )
    )
    expected_bindings = preflight.get("bindings")
    if not isinstance(expected_bindings, dict):
        raise LiveGateError("preflight bindings are missing")
    model_settings = {
        "orchestrator_model": options.orchestrator_model,
        "orchestrator_reasoning": options.reasoning_effort,
        "worker_model": options.worker_model,
        "worker_reasoning": options.worker_reasoning_effort,
        "validator_model": options.validator_model,
        "validator_reasoning": options.validator_reasoning_effort,
        "probe_model": options.probe_model,
        "probe_reasoning": options.probe_reasoning_effort,
    }
    validate_live_preflight(
        authorization=authorization,
        value=preflight,
        expected_bindings=expected_bindings,
        expected_models=model_settings,
        lima_config=options.lima_config.resolve(),
    )
    counter = LiveRunCounter(expected_ledger)
    counter.claim()
    return {
        "schema_version": "0.1",
        "status": "host-live-run-slot-claimed",
        "live_run_count": counter.count,
    }


def run_host_live_gate_command(
    options: argparse.Namespace,
    project_root: Path,
) -> dict[str, Any]:
    from .live import (
        HostLimaFinalizer,
        LaunchReservation,
        LiveGateError,
        finalize_host_gate,
        load_private_record,
    )

    required = {
        "limactl_binary": options.limactl_binary,
        "host_export_directory": options.host_export_directory,
        "output": options.output,
        "guest_installed_plugin_root": options.guest_installed_plugin_root,
    }
    missing = sorted(name for name, value in required.items() if value is None)
    if missing:
        raise LiveGateError(
            "host live gate inputs are incomplete: " + ", ".join(missing)
        )
    guest_plugin_root = str(options.guest_installed_plugin_root)
    if (
        not guest_plugin_root.startswith("/home/shadow/")
        or ".." in Path(guest_plugin_root).parts
    ):
        raise LiveGateError("guest installed plugin path is invalid")
    private_root = (project_root / ".shadow-mission").resolve()
    export_directory = options.host_export_directory.resolve()
    output_path = options.output.resolve()
    if export_directory != private_root / "feasibility-import":
        raise LiveGateError("host evidence export path differs from the contract")
    if output_path != private_root / "feasibility-gate.json":
        raise LiveGateError("host final gate path differs from the contract")
    preflight = load_private_record(
        options.preflight_record.resolve(),
        "preflight",
    )
    expected_bindings = preflight.get("bindings")
    expected_models = preflight.get("models")
    if not isinstance(expected_bindings, dict) or not isinstance(
        expected_models, dict
    ):
        raise LiveGateError("preflight bindings or models are missing")
    finalizer = HostLimaFinalizer(
        options.limactl_binary.resolve(),
        str(expected_bindings.get("lima_version", "")),
    )
    guest_arguments = (
        "/home/shadow/venv/bin/shadow-feasibility",
        "--fixture",
        "/home/shadow/input/feasibility",
        "--fixture-manifest-pin",
        "/home/shadow/input/feasibility-manifest.sha256",
        "--authorization-record",
        "/home/shadow/private/authorization.json",
        "--preflight-record",
        "/home/shadow/private/preflight.json",
        "--factory-credential-file",
        "/home/shadow/credential/factory-api-key",
        "--project-root",
        "/home/shadow/input",
        "--droid-binary",
        "/home/shadow/bin/droid",
        "--installed-plugin-root",
        guest_plugin_root,
        "--workspace-dir",
        "/home/shadow/workspace",
        "--mission-file",
        "/home/shadow/input/feasibility/mission.md",
        "--live-run-ledger",
        "/home/shadow/private/live-run.json",
        "--preflight-attempt-ledger",
        "/home/shadow/private/preflight-attempts.json",
        "--runtime-dir",
        "/home/shadow/private/runtime",
        "--lima-config",
        "/home/shadow/input/shadow-feasibility.yaml",
        "--output",
        "/home/shadow/output/gate",
        "--orchestrator-model",
        str(options.orchestrator_model),
        "--reasoning-effort",
        str(options.reasoning_effort),
        "--worker-model",
        str(options.worker_model),
        "--worker-reasoning-effort",
        str(options.worker_reasoning_effort),
        "--validator-model",
        str(options.validator_model),
        "--validator-reasoning-effort",
        str(options.validator_reasoning_effort),
        "--probe-model",
        str(options.probe_model),
        "--probe-reasoning-effort",
        str(options.probe_reasoning_effort),
    )
    try:
        guest_preflight = finalizer.run_guest_feasibility(
            (*guest_arguments, "--live-preflight-only")
        )
    except LiveGateError:
        guest_preflight = None
    guest_preflight_valid = False
    if guest_preflight is not None and guest_preflight.returncode == 0:
        try:
            guest_preflight_value = json.loads(guest_preflight.stdout)
        except (TypeError, json.JSONDecodeError):
            guest_preflight_value = None
        guest_preflight_valid = (
            isinstance(guest_preflight_value, dict)
            and guest_preflight_value.get("status") == "live-preflight-pass"
            and guest_preflight_value.get("live_run_count_incremented") is False
            and guest_preflight_value.get("model_calls") == 0
            and guest_preflight_value.get("factory_calls") == 0
        )
    if not guest_preflight_valid:
        return finalize_host_gate(
            finalizer=finalizer,
            host_export_directory=export_directory,
            output_path=output_path,
            expected_bindings=expected_bindings,
            expected_models=expected_models,
            host_claim_valid=True,
            guest_execution_valid=False,
            guest_failure_stage="guest_preflight",
        )
    launch_reservation = LaunchReservation(
        private_root / "feasibility-launch-reservation.json"
    )
    try:
        launch_reservation.claim()
    except LiveGateError:
        return finalize_host_gate(
            finalizer=finalizer,
            host_export_directory=export_directory,
            output_path=output_path,
            expected_bindings=expected_bindings,
            expected_models=expected_models,
            host_claim_valid=False,
            guest_execution_valid=False,
        )
    try:
        guest_result = finalizer.run_guest_feasibility(guest_arguments)
        guest_execution_valid = guest_result.returncode == 0
    except LiveGateError:
        guest_execution_valid = False
    try:
        guest_live_run_count = finalizer.guest_live_run_count()
        host_claim_valid = False
        if guest_live_run_count == 1:
            claim = run_host_claim_command(options, project_root)
            host_claim_valid = claim.get("live_run_count") == 1
    except LiveGateError:
        host_claim_valid = False
    return finalize_host_gate(
        finalizer=finalizer,
        host_export_directory=export_directory,
        output_path=output_path,
        expected_bindings=expected_bindings,
        expected_models=expected_models,
        host_claim_valid=host_claim_valid,
        guest_execution_valid=guest_execution_valid,
    )


def run_host_finalize_command(
    options: argparse.Namespace,
    project_root: Path,
) -> dict[str, Any]:
    from .live import (
        HostLimaFinalizer,
        LiveGateError,
        LiveRunCounter,
        finalize_host_gate,
        load_private_record,
    )

    required = {
        "preflight_record": options.preflight_record,
        "limactl_binary": options.limactl_binary,
        "host_export_directory": options.host_export_directory,
        "output": options.output,
        "host_live_run_ledger": options.host_live_run_ledger,
    }
    missing = sorted(name for name, value in required.items() if value is None)
    if missing:
        raise LiveGateError(
            "host finalization inputs are incomplete: " + ", ".join(missing)
        )
    private_root = (project_root / ".shadow-mission").resolve()
    export_directory = options.host_export_directory.resolve()
    output_path = options.output.resolve()
    if export_directory != private_root / "feasibility-import":
        raise LiveGateError("host evidence export path differs from the contract")
    if output_path != private_root / "feasibility-gate.json":
        raise LiveGateError("host final gate path differs from the contract")
    host_ledger_path = options.host_live_run_ledger.resolve()
    if host_ledger_path != private_root / "feasibility-live-run.json":
        raise LiveGateError("host live-run ledger path differs from the contract")
    try:
        host_claim_valid = LiveRunCounter(host_ledger_path).count == 1
    except LiveGateError:
        host_claim_valid = False
    preflight = load_private_record(
        options.preflight_record.resolve(),
        "preflight",
    )
    expected_bindings = preflight.get("bindings")
    if not isinstance(expected_bindings, dict):
        raise LiveGateError("preflight bindings are missing")
    expected_models = preflight.get("models")
    if not isinstance(expected_models, dict):
        raise LiveGateError("preflight models are missing")
    return finalize_host_gate(
        finalizer=HostLimaFinalizer(
            options.limactl_binary.resolve(),
            str(expected_bindings.get("lima_version", "")),
        ),
        host_export_directory=export_directory,
        output_path=output_path,
        expected_bindings=expected_bindings,
        expected_models=expected_models,
        host_claim_valid=host_claim_valid,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Shadow Mission feasibility harness")
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--fixture-manifest-pin", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--authorization-record", type=Path)
    parser.add_argument("--factory-root", type=Path)
    parser.add_argument("--marketplace-root", type=Path)
    parser.add_argument("--system-settings-path", type=Path)
    parser.add_argument("--private-root", type=Path)
    parser.add_argument("--protected-root", type=Path)
    parser.add_argument("--billing-record", type=Path)
    parser.add_argument("--isolation-canary-record", type=Path)
    parser.add_argument("--preflight-record", type=Path)
    parser.add_argument("--factory-credential-file", type=Path)
    parser.add_argument("--workspace-dir", type=Path)
    parser.add_argument("--droid-binary", type=Path)
    parser.add_argument("--installed-plugin-root", type=Path)
    parser.add_argument("--guest-installed-plugin-root")
    parser.add_argument("--mission-file", type=Path)
    parser.add_argument("--live-run-ledger", type=Path)
    parser.add_argument("--preflight-attempt-ledger", type=Path)
    parser.add_argument("--host-live-run-ledger", type=Path)
    parser.add_argument("--runtime-dir", type=Path)
    parser.add_argument("--host-export-directory", type=Path)
    parser.add_argument("--limactl-binary", type=Path)
    parser.add_argument("--lima-config", type=Path)
    parser.add_argument("--orchestrator-model")
    parser.add_argument("--reasoning-effort")
    parser.add_argument("--worker-model")
    parser.add_argument("--worker-reasoning-effort")
    parser.add_argument("--validator-model")
    parser.add_argument("--validator-reasoning-effort")
    parser.add_argument("--probe-model")
    parser.add_argument("--probe-reasoning-effort")
    parser.add_argument(
        "--capture-live-preflight",
        action="store_true",
        help="Capture the measured no-model guest preflight record.",
    )
    parser.add_argument(
        "--capture-isolation-canaries",
        action="store_true",
        help="Capture no-model host and guest isolation canaries.",
    )
    parser.add_argument(
        "--live-preflight-only",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--run-host-live-gate",
        action="store_true",
        help="Claim, launch, export, destroy, and classify one live gate.",
    )
    parser.add_argument(
        "--finalize-host-gate",
        action="store_true",
        help="Export guest evidence, destroy the VM, and write the final gate.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run only the no-spend offline harness.",
    )
    return parser


def main(arguments: list[str] | None = None) -> int:
    parser = build_parser()
    options = parser.parse_args(arguments)
    project_root = (
        options.project_root.resolve()
        if options.project_root is not None
        else Path.cwd().resolve()
    )
    try:
        mode_count = sum(
            (
                options.dry_run,
                options.finalize_host_gate,
                options.capture_live_preflight,
                options.capture_isolation_canaries,
                options.run_host_live_gate,
            )
        )
        if mode_count > 1:
            raise GateClassificationError("execution modes are mutually exclusive")
        if options.capture_isolation_canaries:
            result = run_capture_isolation_canaries_command(options, project_root)
        elif options.capture_live_preflight:
            result = run_capture_live_preflight_command(options, project_root)
        elif options.finalize_host_gate:
            result = run_host_finalize_command(options, project_root)
        elif options.run_host_live_gate:
            result = run_host_live_gate_command(options, project_root)
        elif options.dry_run:
            if options.fixture is None or options.fixture_manifest_pin is None:
                raise GateClassificationError(
                    "dry-run fixture inputs are incomplete"
                )
            result = run_dry_run(
                fixture_path=options.fixture.resolve(),
                fixture_manifest_pin=options.fixture_manifest_pin.resolve(),
                output_path=options.output.resolve() if options.output else None,
                project_root=project_root,
            )
        else:
            result = run_live_command(options, project_root)
    except (GateClassificationError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
