"""Authenticated loopback hook collector with durable response replay."""

from __future__ import annotations

import hmac
import hashlib
import json
import socket
import sys
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping

from .auth import AuthenticationError, EventAuthenticator
from .protocol import HookEnvelope, HookRequest, QueueCapacityError, canonical_json
from .redaction import sanitize_hook_event, sanitize_value
from .storage import (
    EventLedger,
    LedgerConflictError,
    LedgerError,
    ResponsePlan,
)

MAX_RAW_INPUT_BYTES = 1 << 20
MAX_RESPONSE_BYTES = 64 << 10
COLLECTOR_RESPONSE_DEADLINE_SECONDS = 1.0
COLLECTOR_SOCKET_TIMEOUT_SECONDS = 1.5
MAX_CONCURRENT_HANDLERS = 32
_ALLOWED_REQUEST_FIELDS = {
    "schema_version",
    "run_id",
    "event_id",
    "observed_at",
    "hook",
}


class CollectorRequestError(ValueError):
    """A request failed before a successful durable acknowledgment."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status

class MissionCorrelationRegistry:
    """Factory-side allowlist for actual Mission child sessions."""

    def __init__(
        self,
        *,
        allowed: Mapping[str, str] | None = None,
        excluded: frozenset[str] = frozenset(),
    ) -> None:
        self._allowed = dict(allowed or {})
        self._excluded = set(excluded)
        self._lock = threading.Lock()
        for session_alias, evidence_digest in self._allowed.items():
            self._validate_entry(session_alias, evidence_digest)

    def allow(self, session_alias: str, evidence_digest: str) -> None:
        self._validate_entry(session_alias, evidence_digest)
        with self._lock:
            if session_alias in self._excluded:
                raise ValueError("excluded session cannot enter Mission correlation set")
            prior = self._allowed.get(session_alias)
            if prior is not None and prior != evidence_digest:
                raise ValueError("session correlation evidence changed")
            self._allowed[session_alias] = evidence_digest

    def exclude(self, session_alias: str) -> None:
        if not session_alias:
            raise ValueError("excluded session alias must not be empty")
        with self._lock:
            self._excluded.add(session_alias)
            self._allowed.pop(session_alias, None)

    def accepts(self, envelope: HookEnvelope) -> bool:
        with self._lock:
            return (
                envelope.session_alias in self._allowed
                and envelope.session_alias not in self._excluded
            )

    @staticmethod
    def _validate_entry(session_alias: str, evidence_digest: str) -> None:
        if not session_alias:
            raise ValueError("session correlation alias must not be empty")
        if len(evidence_digest) != 64 or any(
            character not in "0123456789abcdef" for character in evidence_digest
        ):
            raise ValueError("session correlation evidence must be a SHA-256 digest")


class GuidanceQueue:
    """Hold target-only responses until the ledger commits their delivery."""

    def __init__(self, *, max_items: int = 1_000, max_bytes: int = 1 << 20) -> None:
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._items: dict[
            str, deque[tuple[str, Mapping[str, Any], int, tuple[str, ...]]]
        ] = {}
        self._ids: set[str] = set()
        self._item_count = 0
        self._byte_count = 0
        self._lock = threading.Lock()

    def queue(
        self,
        *,
        session_alias: str,
        guidance_id: str,
        hook_output: Mapping[str, Any],
        transition_ids: tuple[str, ...] = (),
    ) -> None:
        if not session_alias or not guidance_id:
            raise ValueError("guidance identity must not be empty")
        redacted, _ = sanitize_value(dict(hook_output))
        if not isinstance(redacted, Mapping):
            raise ValueError("hook output must remain an object")
        size = len(canonical_json(redacted))
        with self._lock:
            if guidance_id in self._ids:
                raise ValueError("guidance ID already exists")
            if self._item_count >= self._max_items:
                raise QueueCapacityError("guidance item limit exceeded")
            if size > self._max_bytes or self._byte_count + size > self._max_bytes:
                raise QueueCapacityError("guidance byte limit exceeded")
            self._items.setdefault(session_alias, deque()).append(
                (guidance_id, dict(redacted), size, transition_ids)
            )
            self._ids.add(guidance_id)
            self._item_count += 1
            self._byte_count += size

    def decision(self, envelope: HookEnvelope) -> ResponsePlan:
        with self._lock:
            queue = self._items.get(envelope.session_alias)
            item = queue[0] if queue else None
        if item is None:
            return ResponsePlan(body={})
        guidance_id, hook_output, _, transition_ids = item

        def commit() -> None:
            with self._lock:
                current = self._items.get(envelope.session_alias)
                if not current or current[0][0] != guidance_id:
                    raise RuntimeError("guidance reservation changed before commit")
                removed_id, _, size, _ = current.popleft()
                self._ids.remove(removed_id)
                self._item_count -= 1
                self._byte_count -= size
                if not current:
                    self._items.pop(envelope.session_alias, None)

        return ResponsePlan(
            body=hook_output,
            guidance_ids=(guidance_id,),
            transition_ids=transition_ids,
            commit=commit,
        )

    @property
    def item_count(self) -> int:
        with self._lock:
            return self._item_count


class _CollectorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, collector: HookCollector) -> None:
        self.collector = collector
        self._handler_condition = threading.Condition()
        self._active_handlers = 0
        self._accepting = False
        self._shutdown_requested = threading.Event()
        super().__init__(("127.0.0.1", 0), _CollectorHandler)
        self.timeout = 0.01

    def serve_bounded(self) -> None:
        while not self._shutdown_requested.is_set():
            self.handle_request()

    def request_shutdown(self) -> None:
        self._shutdown_requested.set()


    def process_request(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        request.settimeout(COLLECTOR_SOCKET_TIMEOUT_SECONDS)
        with self._handler_condition:
            if not self._accepting:
                self.shutdown_request(request)
                return
            if self._active_handlers >= MAX_CONCURRENT_HANDLERS:
                self.collector._mark_degraded("handler-capacity")
                self.shutdown_request(request)
                return
            self._active_handlers += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.collector._mark_degraded("handler-start")
            self._handler_finished()
            self.shutdown_request(request)
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._handler_finished()

    def start_accepting(self) -> None:
        with self._handler_condition:
            self._accepting = True

    def stop_accepting(self) -> None:
        with self._handler_condition:
            self._accepting = False

    def drain_handlers(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._handler_condition:
            while self._active_handlers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._handler_condition.wait(remaining)
        return True

    def _handler_finished(self) -> None:
        with self._handler_condition:
            self._active_handlers -= 1
            self._handler_condition.notify_all()


class _CollectorHandler(BaseHTTPRequestHandler):
    server: _CollectorHTTPServer

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path != "/events":
            self._respond(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                raise CollectorRequestError(
                    HTTPStatus.LENGTH_REQUIRED, "content length is required"
                )
            length = int(length_header)
            if length < 0 or length > MAX_RAW_INPUT_BYTES:
                raise CollectorRequestError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request exceeds 1 MiB"
                )
            body = self.rfile.read(length)
            if len(body) != length:
                raise CollectorRequestError(
                    HTTPStatus.BAD_REQUEST, "request body is incomplete"
                )
            response = self.server.collector.process(self.headers, body)
            self._respond_bytes(HTTPStatus.OK, response)
        except TimeoutError:
            try:
                self._respond(
                    HTTPStatus.REQUEST_TIMEOUT, {"error": "request body timed out"}
                )
            except OSError:
                return
        except ValueError as error:
            if isinstance(error, CollectorRequestError):
                self._respond(error.status, {"error": str(error)})
            else:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "invalid request"})
        except OSError:
            return

    def _respond(self, status: HTTPStatus, value: Mapping[str, Any]) -> None:
        self._respond_bytes(status, canonical_json(value))

    def _respond_bytes(self, status: HTTPStatus, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class HookCollector:
    """Accept authenticated hook events and acknowledge only durable responses."""

    def __init__(
        self,
        ledger: EventLedger,
        *,
        provenance_status: str,
        correlation: MissionCorrelationRegistry,
        correlation_refresh: Callable[[], object] | None = None,
        decide: Callable[[HookEnvelope], ResponsePlan] | None = None,
        capture_request: Callable[[HookRequest, HookEnvelope], None] | None = None,
        discard_request: Callable[[str], None] | None = None,
        forbidden_values: tuple[str, ...] = (),
    ) -> None:
        if provenance_status not in {"hook_authenticated", "untrusted_provenance"}:
            raise ValueError("invalid provenance status")
        if any(not isinstance(item, str) or not item for item in forbidden_values):
            raise ValueError("forbidden redaction values must be non-empty strings")
        self.ledger = ledger
        self.provenance_status = provenance_status
        self._decide = decide or (lambda _: ResponsePlan(body={}))
        self._correlation = correlation
        self._correlation_refresh = correlation_refresh
        self._capture_request = capture_request
        self._discard_request = discard_request
        self._forbidden_values = tuple(dict.fromkeys(forbidden_values))
        self._server: _CollectorHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._authenticator: EventAuthenticator | None = None
        self._descriptor: Mapping[str, Any] | None = None
        self._secret: str | None = None
        self._degraded_reason: str | None = None
        self._state_lock = threading.Lock()

    @property
    def url(self) -> str:
        server = self._server
        if server is None:
            raise RuntimeError("collector is not bound")
        host, port = server.server_address
        return f"http://{host}:{port}/events"

    @property
    def degraded_reason(self) -> str | None:
        with self._state_lock:
            return self._degraded_reason or self.ledger.degraded_reason

    def bind(self) -> str:
        if self._server is not None:
            raise RuntimeError("collector already bound")
        self._server = _CollectorHTTPServer(self)
        return self.url

    def start(self, *, secret: str, descriptor: Mapping[str, Any]) -> None:
        if self._server is None:
            self.bind()
        if self._server_thread is not None:
            raise RuntimeError("collector already started")
        if descriptor.get("collector_url") != self.url:
            raise ValueError("descriptor collector URL differs from bound collector")
        server = self._server
        assert server is not None
        thread = threading.Thread(
            target=server.serve_bounded,
            name="shadow-hook-collector",
            daemon=True,
        )
        ledger_started = False
        try:
            authenticator = EventAuthenticator(secret, descriptor)
            stored_descriptor = dict(descriptor)
            self.ledger.start()
            ledger_started = True
            thread.start()
        except BaseException:
            server.stop_accepting()
            server.server_close()
            try:
                if ledger_started:
                    self.ledger.stop()
            finally:
                self._server = None
                self._server_thread = None
                self._authenticator = None
                self._descriptor = None
                self._secret = None
            raise
        self._authenticator = authenticator
        self._descriptor = stored_descriptor
        self._secret = secret
        self._server_thread = thread
        server.start_accepting()

    def stop(self, *, timeout: float = 5.0) -> None:
        if timeout < 0:
            raise ValueError("collector stop timeout must not be negative")
        deadline = time.monotonic() + timeout
        server = self._server
        thread = self._server_thread
        shutdown_error: BaseException | None = None
        ledger_error: BaseException | None = None
        try:
            if server is not None and thread is not None:
                server.stop_accepting()
                server.request_shutdown()
                thread.join(max(0.0, deadline - time.monotonic()))
                if thread.is_alive():
                    self._mark_degraded("server-shutdown")
                    raise RuntimeError("collector server did not stop")
                if not server.drain_handlers(
                    max(0.0, deadline - time.monotonic())
                ):
                    self._mark_degraded("handler-drain")
                    raise RuntimeError("collector handlers did not drain")
            elif server is not None:
                server.stop_accepting()
        except BaseException as error:
            shutdown_error = error
        finally:
            if server is not None:
                try:
                    server.server_close()
                except BaseException as error:
                    shutdown_error = shutdown_error or error
            try:
                self.ledger.stop(
                    timeout=max(0.0, deadline - time.monotonic())
                )
            except BaseException as error:
                ledger_error = error
            self._server_thread = None
            self._server = None
            self._authenticator = None
            self._descriptor = None
            self._secret = None
        if shutdown_error is not None:
            if ledger_error is not None:
                raise shutdown_error from ledger_error
            raise shutdown_error
        if ledger_error is not None:
            raise ledger_error

    def process(self, headers: Mapping[str, str], body: bytes) -> bytes:
        if len(body) > MAX_RAW_INPUT_BYTES:
            raise CollectorRequestError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request exceeds 1 MiB"
            )
        authenticator = self._authenticator
        descriptor = self._descriptor
        secret = self._secret
        if authenticator is None or descriptor is None or secret is None:
            raise CollectorRequestError(
                HTTPStatus.SERVICE_UNAVAILABLE, "collector is not active"
            )
        try:
            event_id = authenticator.verify(headers, body)
        except AuthenticationError as error:
            status = (
                HTTPStatus.CONFLICT
                if "reused with different content" in str(error)
                else HTTPStatus.UNAUTHORIZED
            )
            raise CollectorRequestError(status, "event authentication failed") from error
        try:
            request_value = json.loads(body)
        except (json.JSONDecodeError, UnicodeError) as error:
            raise CollectorRequestError(
                HTTPStatus.BAD_REQUEST, "request is not valid JSON"
            ) from error
        if not isinstance(request_value, Mapping) or set(request_value) != _ALLOWED_REQUEST_FIELDS:
            raise CollectorRequestError(
                HTTPStatus.BAD_REQUEST, "request fields differ from the contract"
            )
        if (
            request_value.get("schema_version") != "0.1"
            or request_value.get("run_id") != descriptor.get("run_id")
            or request_value.get("event_id") != event_id
        ):
            raise CollectorRequestError(
                HTTPStatus.BAD_REQUEST, "request identity differs from the contract"
            )
        observed_at = request_value.get("observed_at")
        raw_hook = request_value.get("hook")
        if (
            not isinstance(observed_at, int)
            or isinstance(observed_at, bool)
            or not isinstance(raw_hook, Mapping)
        ):
            raise CollectorRequestError(
                HTTPStatus.BAD_REQUEST, "request event fields are invalid"
            )
        captured = False

        def discard_captured() -> None:
            nonlocal captured
            if captured and self._discard_request is not None:
                self._discard_request(event_id)
            captured = False

        try:
            sanitized = sanitize_hook_event(
                raw_hook,
                secret=secret,
                run_id=str(descriptor["run_id"]),
                event_id=event_id,
                observed_at=observed_at,
                provenance_status=self.provenance_status,
                forbidden_values=self._forbidden_values,
            )
            sanitized["message_digest"] = hmac.new(
                secret.encode("utf-8"),
                b"shadow-raw-hook-v1\0" + body,
                hashlib.sha256,
            ).hexdigest()
            envelope = HookEnvelope.model_validate(sanitized)
            request_digest = hashlib.sha256(
                canonical_json(envelope.model_dump(mode="json"))
            ).hexdigest()
            response = self.ledger.response_for(event_id, request_digest)
            refresh_dt = 0.0
            submit_dt = 0.0
            if response is None:
                if self._correlation_refresh is not None:
                    try:
                        started = time.monotonic()
                        self._correlation_refresh()
                        refresh_dt = time.monotonic() - started
                    except BaseException as error:
                        self._mark_degraded("correlation")
                        raise CollectorRequestError(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            "Mission correlation source failed",
                        ) from error
                if not self._correlation.accepts(envelope):
                    return b"{}"

                if self._capture_request is not None:
                    raw_request = HookRequest(
                        run_id=str(descriptor["run_id"]),
                        event_id=event_id,
                        observed_at=observed_at,
                        hook_event_name=envelope.hook_event_name,
                        session_id=str(raw_hook.get("session_id", "")),
                        transcript_path=str(raw_hook.get("transcript_path", "")),
                        cwd=str(raw_hook.get("cwd", "")),
                        payload={},
                    )
                    captured = True
                    try:
                        self._capture_request(raw_request, envelope)
                    except BaseException:
                        discard_captured()
                        raise

                def sanitized_decision(value: HookEnvelope) -> ResponsePlan:
                    plan = self._decide(value)
                    response_value, redaction_status = sanitize_value(
                        dict(plan.body),
                        forbidden_values=(secret, *self._forbidden_values),
                    )
                    if not isinstance(response_value, Mapping):
                        raise ValueError("response decision must remain an object")
                    return ResponsePlan(
                        body=dict(response_value),
                        guidance_ids=plan.guidance_ids,
                        transition_ids=plan.transition_ids,
                        redaction_status=redaction_status,
                        review_state=plan.review_state,
                        commit=plan.commit,
                    )

                started = time.monotonic()
                response = self.ledger.submit(
                    envelope,
                    request_digest=request_digest,
                    decide=sanitized_decision,
                    timeout=COLLECTOR_RESPONSE_DEADLINE_SECONDS,
                )
                submit_dt = time.monotonic() - started
                if refresh_dt >= 0.2 or submit_dt >= 0.2:
                    print(
                        "shadow-collector: "
                        f"hook={envelope.hook_event_name} "
                        f"refresh={refresh_dt:.3f}s submit={submit_dt:.3f}s",
                        file=sys.stderr,
                        flush=True,
                    )
        except LedgerConflictError as error:
            discard_captured()
            raise CollectorRequestError(
                HTTPStatus.CONFLICT, "event identity conflict"
            ) from error
        except QueueCapacityError as error:
            discard_captured()
            self._mark_degraded("capacity")
            raise CollectorRequestError(
                HTTPStatus.SERVICE_UNAVAILABLE, "collector capacity exceeded"
            ) from error
        except LedgerError as error:
            discard_captured()
            self._mark_degraded("persistence")
            raise CollectorRequestError(
                HTTPStatus.SERVICE_UNAVAILABLE, "collector persistence unavailable"
            ) from error
        except TimeoutError as error:
            self._mark_degraded("persistence")
            raise CollectorRequestError(
                HTTPStatus.SERVICE_UNAVAILABLE, "collector persistence unavailable"
            ) from error
        except CollectorRequestError:
            discard_captured()
            raise
        except (TypeError, ValueError) as error:
            discard_captured()
            raise CollectorRequestError(
                HTTPStatus.BAD_REQUEST, "sanitized event is invalid"
            ) from error
        response_bytes = response.response_body.encode("utf-8")
        if len(response_bytes) > MAX_RESPONSE_BYTES:
            self._mark_degraded("response-size")
            raise CollectorRequestError(
                HTTPStatus.SERVICE_UNAVAILABLE, "collector response exceeds 64 KiB"
            )
        return response_bytes

    def _mark_degraded(self, reason: str) -> None:
        with self._state_lock:
            if self._degraded_reason is None:
                self._degraded_reason = reason
