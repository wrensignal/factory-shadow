from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

import shadow_mission.collector as collector_module
from shadow_mission.auth import generate_run_secret
from shadow_mission.collector import HookCollector, MissionCorrelationRegistry
from shadow_mission.storage import EventLedger



def test_collector_socket_timeout_exceeds_response_deadline() -> None:
    assert (
        collector_module.COLLECTOR_SOCKET_TIMEOUT_SECONDS
        > collector_module.COLLECTOR_RESPONSE_DEADLINE_SECONDS
    )


def start_collector(tmp_path: Path) -> HookCollector:
    ledger = EventLedger(tmp_path / "run", run_id="run-collector")
    collector = HookCollector(
        ledger,
        provenance_status="hook_authenticated",
        correlation=MissionCorrelationRegistry(),
    )
    url = collector.bind()
    collector.start(
        secret=generate_run_secret(),
        descriptor={"collector_url": url},
    )
    return collector


def open_partial_request(collector: HookCollector) -> socket.socket:
    server = collector._server
    assert server is not None
    connection = socket.create_connection(server.server_address, timeout=1.0)
    connection.settimeout(6.0)
    connection.sendall(
        b"POST /events HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Length: 10\r\n"
        b"Connection: close\r\n\r\n"
        b"{"
    )
    return connection


def test_partial_request_body_times_out_and_handler_drains(tmp_path: Path) -> None:
    collector = start_collector(tmp_path)
    connection = open_partial_request(collector)

    response = connection.recv(4096)

    assert b" 408 " in response
    connection.close()
    collector.stop(timeout=1.0)


def test_handler_cap_precedes_thread_creation_and_stop_fails_on_drain_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collector_module, "MAX_CONCURRENT_HANDLERS", 1)
    monkeypatch.setattr(collector_module, "COLLECTOR_SOCKET_TIMEOUT_SECONDS", 5.0)
    collector = start_collector(tmp_path)
    server = collector._server
    assert server is not None
    first = open_partial_request(collector)
    with server._handler_condition:
        assert server._handler_condition.wait_for(
            lambda: server._active_handlers == 1, timeout=1.0
        )

    second = socket.create_connection(server.server_address, timeout=1.0)
    second.settimeout(1.0)
    second.sendall(b"POST /events HTTP/1.1\r\nContent-Length: 1\r\n\r\n{")
    try:
        assert second.recv(1) == b""
    except ConnectionResetError:
        pass
    with server._handler_condition:
        assert server._active_handlers == 1

    with pytest.raises(RuntimeError, match="handlers did not drain"):
        collector.stop(timeout=0.05)
    assert collector.degraded_reason == "handler-capacity"
    assert collector.ledger._closing is True
    assert collector._server is None
    assert collector._server_thread is None

    first.close()
    second.close()
    collector.stop(timeout=2.0)



def test_handler_drain_failure_still_stops_ledger_and_clears_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = start_collector(tmp_path)
    server = collector._server
    assert server is not None
    monkeypatch.setattr(server, "drain_handlers", lambda timeout: False)

    with pytest.raises(RuntimeError, match="handlers did not drain"):
        collector.stop(timeout=1.0)

    writer = collector.ledger._writer
    assert collector.ledger._closing is True
    assert writer is not None
    assert not writer.is_alive()
    assert collector._server is None
    assert collector._server_thread is None

def test_thread_start_failure_closes_server_and_stops_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = EventLedger(tmp_path / "run", run_id="run-start-failure")
    collector = HookCollector(
        ledger,
        provenance_status="hook_authenticated",
        correlation=MissionCorrelationRegistry(),
    )
    url = collector.bind()
    server = collector._server
    assert server is not None
    address = server.server_address
    real_start = threading.Thread.start

    def fail_collector_start(thread: threading.Thread) -> None:
        if thread.name == "shadow-hook-collector":
            raise RuntimeError("injected collector start failure")
        real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_collector_start)

    with pytest.raises(RuntimeError, match="injected collector start failure"):
        collector.start(
            secret=generate_run_secret(),
            descriptor={"collector_url": url},
        )

    assert collector._server is None
    assert collector._server_thread is None
    assert collector._authenticator is None
    writer = ledger._writer
    assert writer is not None
    assert not writer.is_alive()
    assert not any(
        thread.name in {"shadow-hook-collector", "shadow-ledger-run-start-fa"}
        for thread in threading.enumerate()
    )
    with pytest.raises(OSError):
        socket.create_connection(address, timeout=0.1)


def test_handler_thread_start_failure_degrades_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = start_collector(tmp_path)
    server = collector._server
    assert server is not None
    attempted = threading.Event()

    def fail_handler_start(thread: threading.Thread) -> None:
        attempted.set()
        raise RuntimeError("injected handler start failure")

    monkeypatch.setattr(threading.Thread, "start", fail_handler_start)
    connection = socket.create_connection(server.server_address, timeout=1.0)
    connection.sendall(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")

    assert attempted.wait(timeout=1.0)
    assert collector.degraded_reason == "handler-start"

    connection.close()
    collector.stop(timeout=1.0)
