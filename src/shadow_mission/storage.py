"""Authoritative append-only event ledger and rebuildable SQLite index."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from .protocol import (
    ByteBoundedQueue,
    HookEnvelope,
    HookExchangeRecord,
    HookResponseRecord,
    QueueCapacityError,
    canonical_json,
    hook_response_digest,
)

MAX_SANITIZED_EVENT_BYTES = 256 << 10
MAX_PENDING_EVENTS = 1_000
MAX_PENDING_BYTES = 16 << 20
MAX_SPOOL_BYTES = 16 << 20
MAX_LEDGER_LINE_BYTES = 2 << 20
_WRITER_SETUP_TIMEOUT_SECONDS = 5.0


class LedgerError(RuntimeError):
    """Base failure for authoritative ledger operations."""


class LedgerConflictError(LedgerError):
    """An event identity was reused with different sanitized content."""


class LedgerClosedError(LedgerError):
    """The ledger is not accepting work."""


class LedgerCorruptionError(LedgerError):
    """The authoritative JSONL cannot be replayed exactly."""


@dataclass(frozen=True)
class ResponsePlan:
    """A response decision whose side effects commit only after JSONL fsync."""

    body: Mapping[str, Any] = field(default_factory=dict)
    guidance_ids: tuple[str, ...] = ()
    transition_ids: tuple[str, ...] = ()
    redaction_status: str | None = None
    review_state: Mapping[str, Any] | None = None
    commit: Callable[[], None] | None = field(default=None, compare=False, repr=False)


def compose_review_state(
    *, run_id: str, components: tuple[Mapping[str, Any], ...]
) -> dict[str, Any]:
    """Compose independent durable response states without hiding either one."""
    if not run_id or not components:
        raise ValueError("review state composition requires a run and components")
    records: dict[str, dict[str, Any]] = {}
    for component in components:
        record = json.loads(canonical_json(dict(component)))
        record_type = record.get("record_type")
        if (
            record.get("schema_version") != "0.1"
            or record.get("run_id") != run_id
            or not isinstance(record_type, str)
            or not record_type
        ):
            raise ValueError("review state component binding is invalid")
        if record_type in records:
            raise ValueError("review state repeats a component")
        records[record_type] = record
    return {
        "schema_version": "0.1",
        "record_type": "response_review_state",
        "run_id": run_id,
        "components": {name: records[name] for name in sorted(records)},
    }


def review_state_component(
    value: Mapping[str, Any],
    *,
    run_id: str,
    record_type: str,
) -> Mapping[str, Any] | None:
    """Read one legacy or composed durable response-state component."""
    if value.get("record_type") == record_type:
        if value.get("run_id") != run_id:
            raise ValueError("review state belongs to another run")
        return value
    if value.get("record_type") != "response_review_state":
        if (
            value.get("schema_version") != "0.1"
            or value.get("run_id") != run_id
            or not isinstance(value.get("record_type"), str)
        ):
            raise ValueError("review state binding is invalid")
        return None
    expected = {"schema_version", "record_type", "run_id", "components"}
    if (
        set(value) != expected
        or value.get("schema_version") != "0.1"
        or value.get("record_type") != "response_review_state"
        or value.get("run_id") != run_id
        or not isinstance(value.get("components"), Mapping)
    ):
        raise ValueError("response review state binding is invalid")
    components = value["components"]
    if tuple(sorted(components)) != tuple(components):
        raise ValueError("response review state components are not canonical")
    for name, component in components.items():
        if (
            not isinstance(name, str)
            or not isinstance(component, Mapping)
            or component.get("schema_version") != "0.1"
            or component.get("record_type") != name
            or component.get("run_id") != run_id
        ):
            raise ValueError("response review state component is invalid")
    component = components.get(record_type)
    return component if isinstance(component, Mapping) else None


@dataclass
class _PendingExchange:
    envelope: HookEnvelope
    request_digest: str
    serialized_size: int
    decide: Callable[[HookEnvelope], ResponsePlan]
    completed: threading.Event = field(default_factory=threading.Event)
    response: HookResponseRecord | None = None
    error: BaseException | None = None


class EventLedger:
    """Serialize accepted events through one durable writer per run."""

    def __init__(
        self,
        run_dir: Path,
        *,
        run_id: str,
        max_items: int = MAX_PENDING_EVENTS,
        max_pending_bytes: int = MAX_PENDING_BYTES,
        max_spool_bytes: int = MAX_SPOOL_BYTES,
        clock: Callable[[], float] = time.time,
        after_append: Callable[[HookExchangeRecord], None] | None = None,
    ) -> None:
        if not run_id:
            raise ValueError("run_id must not be empty")
        self.run_id = run_id
        self.run_dir = run_dir.resolve()
        self.ledger_path = self.run_dir / "events.jsonl"
        self.sqlite_path = self.run_dir / "index.sqlite3"
        self.degraded_path = self.run_dir / "ledger-degraded.json"
        self._max_spool_bytes = max_spool_bytes
        self._clock = clock
        self._after_append_callbacks = (
            [after_append] if after_append is not None else []
        )
        self._queue: ByteBoundedQueue[_PendingExchange] = ByteBoundedQueue(
            max_items=max_items,
            max_bytes=max_pending_bytes,
        )
        self._state_lock = threading.Lock()
        self._records: dict[str, HookExchangeRecord] = {}
        self._inflight: dict[str, _PendingExchange] = {}
        self._next_sequence = 1
        self._started = False
        self._closing = False
        self._degraded_reason: str | None = None
        self._writer: threading.Thread | None = None
        self._writer_ready = threading.Event()
        self._prepare_private_directory()
        self._recover_degraded()
        self._recover_jsonl()
        self._rebuild_sqlite()

    @property
    def degraded_reason(self) -> str | None:
        with self._state_lock:
            return self._degraded_reason

    @property
    def pending_items(self) -> int:
        return self._queue.item_count

    @property
    def pending_bytes(self) -> int:
        return self._queue.byte_count

    @property
    def spool_bytes(self) -> int:
        try:
            return self.ledger_path.stat().st_size
        except FileNotFoundError:
            return 0

    def start(self) -> None:
        with self._state_lock:
            if self._degraded_reason is not None:
                raise LedgerError("ledger is degraded")
            if self._started:
                raise LedgerClosedError("ledger already started")
            if self._closing:
                raise LedgerClosedError("ledger is closed")
            self._started = True
            self._writer = threading.Thread(
                target=self._writer_loop,
                name=f"shadow-ledger-{self.run_id[:12]}",
                daemon=True,
            )
            self._writer.start()
        if not self._writer_ready.wait(_WRITER_SETUP_TIMEOUT_SECONDS):
            reason = "writer_setup_timeout"
            with self._state_lock:
                self._degraded_reason = self._degraded_reason or reason
            try:
                self._persist_degraded(reason)
            except OSError:
                pass
            raise LedgerError("ledger writer setup timed out")
        with self._state_lock:
            setup_failure = self._degraded_reason
        if setup_failure is not None:
            raise LedgerError("ledger writer setup failed")

    def add_after_append(
        self, callback: Callable[[HookExchangeRecord], None]
    ) -> None:
        """Register one ordered post-fsync callback before the writer starts."""

        if not callable(callback):
            raise TypeError("after-append callback must be callable")
        with self._state_lock:
            if self._started or self._closing:
                raise LedgerClosedError(
                    "after-append callbacks must be registered before start"
                )
            if callback not in self._after_append_callbacks:
                self._after_append_callbacks.append(callback)

    def stop(self, *, timeout: float = 5.0) -> None:
        with self._state_lock:
            self._closing = True
            writer = self._writer
        if writer is not None:
            writer.join(timeout)
            if writer.is_alive():
                raise LedgerError("ledger writer did not stop")

    def submit(
        self,
        envelope: HookEnvelope,
        *,
        request_digest: str,
        decide: Callable[[HookEnvelope], ResponsePlan],
        timeout: float = 2.0,
    ) -> HookResponseRecord:
        if envelope.run_id != self.run_id:
            raise LedgerConflictError("event belongs to another run")
        if len(request_digest) != 64 or any(
            character not in "0123456789abcdef" for character in request_digest
        ):
            raise ValueError("request_digest must be a lowercase SHA-256 digest")
        serialized = canonical_json(envelope.model_dump(mode="json"))
        if len(serialized) > MAX_SANITIZED_EVENT_BYTES:
            raise QueueCapacityError("sanitized event exceeds 256 KiB")

        should_enqueue = False
        with self._state_lock:
            if self._degraded_reason is not None:
                raise LedgerError("ledger is degraded")
            if not self._started or self._closing:
                raise LedgerClosedError("ledger is not accepting events")
            prior = self._records.get(envelope.event_id)
            if prior is not None:
                if prior.response.request_digest != request_digest:
                    raise LedgerConflictError(
                        "event ID reused with different sanitized content"
                    )
                return prior.response
            pending = self._inflight.get(envelope.event_id)
            if pending is not None:
                if pending.request_digest != request_digest:
                    raise LedgerConflictError(
                        "event ID reused with different sanitized content"
                    )
            else:
                pending = _PendingExchange(
                    envelope=envelope,
                    request_digest=request_digest,
                    serialized_size=len(serialized),
                    decide=decide,
                )
                self._inflight[envelope.event_id] = pending
                should_enqueue = True

        if should_enqueue:
            try:
                self._queue.put(pending, serialized)
            except BaseException:
                with self._state_lock:
                    self._inflight.pop(envelope.event_id, None)
                raise

        if not pending.completed.wait(timeout):
            raise TimeoutError("ledger response timed out")
        if pending.error is not None:
            raise LedgerError("event persistence failed") from pending.error
        if pending.response is None:
            raise LedgerError("ledger completed without a response")
        return pending.response

    def response_for(self, event_id: str, request_digest: str) -> HookResponseRecord | None:
        with self._state_lock:
            if self._degraded_reason is not None:
                raise LedgerError("ledger is degraded")
            record = self._records.get(event_id)
            if record is None:
                return None
            if record.response.request_digest != request_digest:
                raise LedgerConflictError(
                    "event ID reused with different sanitized content"
                )
            return record.response

    def exchanges(self) -> tuple[HookExchangeRecord, ...]:
        with self._state_lock:
            return tuple(
                sorted(self._records.values(), key=lambda item: item.ledger_sequence)
            )

    def event_ids_for_session(self, session_alias: str) -> tuple[str, ...]:
        """Observe every durable or in-flight event for one exact session."""

        if type(session_alias) is not str or not session_alias:
            raise ValueError("session alias must not be empty")
        with self._state_lock:
            if self._degraded_reason is not None:
                raise LedgerError("ledger is degraded")
            event_ids = {
                record.envelope.event_id
                for record in self._records.values()
                if record.envelope.session_alias == session_alias
            }
            event_ids.update(
                pending.envelope.event_id
                for pending in self._inflight.values()
                if pending.envelope.session_alias == session_alias
            )
        return tuple(sorted(event_ids))

    def _prepare_private_directory(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = self.run_dir.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or self.run_dir.is_symlink():
            raise LedgerError("run directory is not a regular directory")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            os.chmod(self.run_dir, 0o700)
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise LedgerError("run directory owner differs")
        if self.ledger_path.exists() and self.ledger_path.is_symlink():
            raise LedgerError("ledger path must not be a symlink")
        if self.sqlite_path.exists() and self.sqlite_path.is_symlink():
            raise LedgerError("SQLite path must not be a symlink")
        if self.degraded_path.exists() and self.degraded_path.is_symlink():
            raise LedgerError("ledger degradation marker must not be a symlink")

    def _recover_degraded(self) -> None:
        if not self.degraded_path.exists():
            return
        try:
            metadata = self.degraded_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            ):
                raise LedgerCorruptionError(
                    "ledger degradation marker is not private"
                )
            raw = self.degraded_path.read_bytes()
            value = json.loads(raw)
            if canonical_json(value) + b"\n" != raw:
                raise LedgerCorruptionError(
                    "ledger degradation marker is not canonical JSON"
                )
            if (
                not isinstance(value, Mapping)
                or set(value) != {"run_id", "reason"}
                or value.get("run_id") != self.run_id
                or not isinstance(value.get("reason"), str)
                or not value["reason"]
            ):
                raise LedgerCorruptionError(
                    "ledger degradation marker is invalid"
                )
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise LedgerCorruptionError(
                "ledger degradation marker cannot be read"
            ) from error
        self._degraded_reason = str(value["reason"])

    def _persist_degraded(self, reason: str) -> None:
        value = canonical_json({"run_id": self.run_id, "reason": reason}) + b"\n"
        temporary = self.degraded_path.with_name(
            f".{self.degraded_path.name}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("xb", buffering=0) as handle:
                os.chmod(temporary, 0o600)
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.degraded_path)
            directory = os.open(self.run_dir, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def _clear_degraded_marker(self) -> None:
        self.degraded_path.unlink()
        directory = os.open(self.run_dir, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


    def _recover_jsonl(self) -> None:
        if not self.ledger_path.exists():
            self.ledger_path.touch(mode=0o600)
            os.chmod(self.ledger_path, 0o600)
            directory = os.open(self.run_dir, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return
        if not self.ledger_path.is_file():
            raise LedgerCorruptionError("ledger is not a regular file")
        os.chmod(self.ledger_path, 0o600)
        expected_sequence = 1
        try:
            with self.ledger_path.open("rb") as handle:
                for raw_line in handle:
                    if len(raw_line) > MAX_LEDGER_LINE_BYTES:
                        raise LedgerCorruptionError("ledger record exceeds its bound")
                    if not raw_line.endswith(b"\n"):
                        raise LedgerCorruptionError("ledger has an incomplete final record")
                    body = raw_line[:-1]
                    value = json.loads(body)
                    if canonical_json(value) != body:
                        raise LedgerCorruptionError("ledger record is not canonical JSON")
                    record = HookExchangeRecord.model_validate(value)
                    if record.ledger_sequence != expected_sequence:
                        raise LedgerCorruptionError("ledger sequence is not contiguous")
                    if record.envelope.run_id != self.run_id:
                        raise LedgerCorruptionError("ledger contains another run")
                    prior = self._records.get(record.envelope.event_id)
                    if prior is not None:
                        raise LedgerCorruptionError("ledger repeats an event ID")
                    self._records[record.envelope.event_id] = record
                    expected_sequence += 1
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            if isinstance(error, LedgerCorruptionError):
                raise
            raise LedgerCorruptionError("ledger replay failed") from error
        self._next_sequence = expected_sequence
        if self.spool_bytes > self._max_spool_bytes:
            raise LedgerCorruptionError("ledger exceeds its disk-spool bound")

    @staticmethod
    def _configure_connection(connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=2000")

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE exchanges (
                ledger_sequence INTEGER PRIMARY KEY,
                exchange_id TEXT NOT NULL UNIQUE,
                run_id TEXT NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                session_alias TEXT NOT NULL,
                source_fingerprint TEXT NOT NULL,
                hook_event_name TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                response_digest TEXT NOT NULL,
                exchange_json TEXT NOT NULL
            );
            CREATE INDEX exchanges_session_sequence
                ON exchanges(session_alias, ledger_sequence);
            CREATE TABLE capabilities (
                name TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                basis_digest TEXT NOT NULL
            );
            CREATE TABLE graph_nodes (
                kind TEXT NOT NULL,
                node_id TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                PRIMARY KEY(kind, node_id)
            );
            CREATE TABLE graph_edges (
                source_kind TEXT NOT NULL,
                source_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                target_id TEXT NOT NULL,
                PRIMARY KEY(source_kind, source_id, relation, target_kind, target_id)
            );
            """
        )

    @staticmethod
    def _insert_exchange(
        connection: sqlite3.Connection, record: HookExchangeRecord
    ) -> None:
        exchange_json = canonical_json(record.model_dump(mode="json")).decode("utf-8")
        connection.execute(
            """
            INSERT INTO exchanges (
                ledger_sequence, exchange_id, run_id, event_id, session_alias,
                source_fingerprint, hook_event_name, request_digest,
                response_digest, exchange_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.ledger_sequence,
                record.exchange_id,
                record.envelope.run_id,
                record.envelope.event_id,
                record.envelope.session_alias,
                record.envelope.source_fingerprint,
                record.envelope.hook_event_name,
                record.response.request_digest,
                record.response.response_digest,
                exchange_json,
            ),
        )

    def _rebuild_sqlite(self) -> None:
        temporary_path = self.sqlite_path.with_suffix(".rebuild")
        try:
            if temporary_path.exists():
                temporary_path.unlink()
            connection = sqlite3.connect(temporary_path)
            try:
                self._configure_connection(connection)
                self._create_schema(connection)
                with connection:
                    for record in sorted(
                        self._records.values(), key=lambda item: item.ledger_sequence
                    ):
                        self._insert_exchange(connection, record)
                check = connection.execute("PRAGMA integrity_check").fetchone()
                if check != ("ok",):
                    raise LedgerCorruptionError("rebuilt SQLite index failed integrity")
            finally:
                connection.close()
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, self.sqlite_path)
        except (OSError, sqlite3.Error) as error:
            raise LedgerError("SQLite index rebuild failed") from error
        finally:
            if temporary_path.exists():
                temporary_path.unlink()

    def _apply_sqlite(
        self, connection: sqlite3.Connection, record: HookExchangeRecord
    ) -> None:
        with connection:
            self._insert_exchange(connection, record)

    @staticmethod
    def _stable_id(prefix: str, *values: str) -> str:
        digest = hashlib.sha256("\0".join((prefix, *values)).encode("utf-8")).hexdigest()
        return f"{prefix}-{digest}"

    def _make_exchange(self, pending: _PendingExchange) -> tuple[HookExchangeRecord, ResponsePlan]:
        plan = pending.decide(pending.envelope)
        response_body = canonical_json(dict(plan.body)).decode("utf-8")
        response_digest = hook_response_digest(
            response_body=response_body,
            guidance_ids=plan.guidance_ids,
            transition_ids=plan.transition_ids,
            review_state=plan.review_state,
        )
        decided_at = int(self._clock())
        response = HookResponseRecord(
            provenance_status=pending.envelope.provenance_status,
            redaction_status=plan.redaction_status or pending.envelope.redaction_status,
            response_id=self._stable_id(
                "response",
                self.run_id,
                pending.envelope.event_id,
                pending.request_digest,
            ),
            run_id=self.run_id,
            event_id=pending.envelope.event_id,
            request_digest=pending.request_digest,
            response_body=response_body,
            response_digest=response_digest,
            guidance_ids=plan.guidance_ids,
            transition_ids=plan.transition_ids,
            review_state=(
                dict(plan.review_state)
                if plan.review_state is not None
                else None
            ),
            decided_at=decided_at,
        )
        exchange = HookExchangeRecord(
            provenance_status=pending.envelope.provenance_status,
            redaction_status=(
                "redacted"
                if "redacted"
                in {
                    pending.envelope.redaction_status,
                    response.redaction_status,
                }
                else "clean"
            ),
            ledger_sequence=self._next_sequence,
            exchange_id=self._stable_id(
                "exchange",
                self.run_id,
                pending.envelope.event_id,
                pending.request_digest,
            ),
            recorded_at=decided_at,
            envelope=pending.envelope,
            response=response,
        )
        return exchange, plan

    def _append_exchange(self, record: HookExchangeRecord) -> None:
        line = canonical_json(record.model_dump(mode="json")) + b"\n"
        if len(line) > MAX_LEDGER_LINE_BYTES:
            raise QueueCapacityError("ledger exchange exceeds its record bound")
        if self.spool_bytes + len(line) > self._max_spool_bytes:
            raise QueueCapacityError("ledger disk-spool limit exceeded")
        with self.ledger_path.open("ab", buffering=0) as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())

    def _writer_loop(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.sqlite_path)
            self._configure_connection(connection)
        except BaseException as error:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            reason = type(error).__name__
            with self._state_lock:
                self._degraded_reason = self._degraded_reason or reason
                pending_values = tuple(self._inflight.values())
                self._inflight.clear()
            try:
                self._persist_degraded(reason)
            except OSError:
                pass
            while True:
                try:
                    self._queue.get(timeout=0.0)
                except IndexError:
                    break
            for pending in pending_values:
                pending.error = error
                pending.completed.set()
            self._writer_ready.set()
            return
        self._writer_ready.set()
        try:
            while True:
                with self._state_lock:
                    closing = self._closing
                if closing and self._queue.item_count == 0:
                    return
                try:
                    pending = self._queue.get(timeout=0.05)
                except TimeoutError:
                    continue
                try:
                    with self._state_lock:
                        degraded = self._degraded_reason
                    if degraded is not None:
                        raise LedgerError("ledger is degraded")
                    exchange, plan = self._make_exchange(pending)
                    self._persist_degraded("post_fsync_incomplete")
                    self._append_exchange(exchange)
                    if plan.commit is not None:
                        plan.commit()
                    for callback in tuple(self._after_append_callbacks):
                        callback(exchange)
                    self._apply_sqlite(connection, exchange)
                    self._clear_degraded_marker()
                    with self._state_lock:
                        self._records[exchange.envelope.event_id] = exchange
                        self._next_sequence += 1
                    pending.response = exchange.response
                except BaseException as error:
                    pending.error = error
                    reason = type(error).__name__
                    with self._state_lock:
                        first_failure = self._degraded_reason is None
                        self._degraded_reason = self._degraded_reason or reason
                    if first_failure:
                        try:
                            self._persist_degraded(reason)
                        except OSError:
                            pass
                finally:
                    with self._state_lock:
                        self._inflight.pop(pending.envelope.event_id, None)
                    pending.completed.set()
        finally:
            connection.close()
