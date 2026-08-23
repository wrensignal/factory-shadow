import json
import os
from pathlib import Path

import pytest

from shadow_mission.auth import (
    AuthenticationError,
    EventAuthenticator,
    create_descriptor,
    generate_run_secret,
    load_descriptor,
    load_latch,
    sign_event_headers,
    write_latch,
)
from shadow_mission.evidence import FrozenObservation, FrozenObservationRegistry


def descriptor_args(tmp_path: Path) -> dict[str, object]:
    return {
        "run_id": "run-alpha",
        "key_id": "key-alpha",
        "collector_url": "http://127.0.0.1:49152/events",
        "mission_root_digest": "a" * 64,
        "profile_digest": "b" * 64,
        "isolation_digest": "c" * 64,
        "gate_surface_digest": "d" * 64,
        "installed_artifact_digest": "e" * 64,
        "latch_path": tmp_path / "latch.json",
        "now": 1_700_000_000,
        "ttl_seconds": 300,
    }


def latch_registry(
    *,
    blocker_id: str = "blocker-alpha",
    target_id: str = "session-worker-a",
) -> FrozenObservationRegistry:
    records = {
        "evidence-alpha": FrozenObservation(
            observation_id="evidence-alpha",
            run_id="run-alpha",
            target_id=target_id,
            risk_id=blocker_id,
            transition="blocker_create",
            kind="direct_evidence",
            status="observed",
            source_class="external_frozen",
        ),
        "probe-alpha": FrozenObservation(
            observation_id="probe-alpha",
            run_id="run-alpha",
            target_id=target_id,
            risk_id=blocker_id,
            transition="blocker_create",
            kind="probe_confirmation",
            status="confirmed",
            source_class="external_frozen",
        ),
    }
    return FrozenObservationRegistry(records, source_digest="f" * 64)


def test_descriptor_is_private_signed_and_tamper_evident(tmp_path: Path) -> None:
    secret = generate_run_secret()
    descriptor_path = tmp_path / "descriptor.json"
    descriptor = create_descriptor(descriptor_path, secret, **descriptor_args(tmp_path))

    assert descriptor["provenance_capability"] == "transport_integrity_only"
    assert descriptor["latch_path"] == str((tmp_path / "latch.json").resolve())
    assert descriptor["latch_head_path"] == str(
        (tmp_path / "latch-head.json").resolve()
    )
    assert descriptor_path.stat().st_mode & 0o777 == 0o600
    assert load_descriptor(descriptor_path, secret, now=1_700_000_001) == descriptor

    tampered = json.loads(descriptor_path.read_text())
    tampered["run_id"] = "run-other"
    descriptor_path.write_text(json.dumps(tampered))
    os.chmod(descriptor_path, 0o600)

    with pytest.raises(AuthenticationError, match="signature"):
        load_descriptor(descriptor_path, secret, now=1_700_000_001)


def test_descriptor_rejects_wrong_mode_and_symlink(tmp_path: Path) -> None:
    secret = generate_run_secret()
    descriptor_path = tmp_path / "descriptor.json"
    create_descriptor(descriptor_path, secret, **descriptor_args(tmp_path))
    os.chmod(descriptor_path, 0o644)

    with pytest.raises(AuthenticationError, match="mode"):
        load_descriptor(descriptor_path, secret, now=1_700_000_001)

    os.chmod(descriptor_path, 0o600)
    link_path = tmp_path / "descriptor-link.json"
    link_path.symlink_to(descriptor_path)
    with pytest.raises(AuthenticationError, match="regular file"):
        load_descriptor(link_path, secret, now=1_700_000_001)


def test_descriptor_rejects_writable_private_parent(tmp_path: Path) -> None:
    secret = generate_run_secret()
    descriptor_path = tmp_path / "descriptor.json"
    create_descriptor(descriptor_path, secret, **descriptor_args(tmp_path))
    os.chmod(tmp_path, 0o755)
    try:
        with pytest.raises(AuthenticationError, match="directory mode"):
            load_descriptor(descriptor_path, secret, now=1_700_000_001)
    finally:
        os.chmod(tmp_path, 0o700)


def test_event_auth_rejects_replay_cross_run_and_forgery(tmp_path: Path) -> None:
    secret = generate_run_secret()
    other_secret = generate_run_secret()
    descriptor = create_descriptor(
        tmp_path / "descriptor.json", secret, **descriptor_args(tmp_path)
    )
    body = b'{"event_id":"event-alpha","run_id":"run-alpha"}'
    headers = sign_event_headers(
        body,
        secret,
        descriptor,
        event_id="event-alpha",
        now=1_700_000_010,
        nonce="nonce-alpha",
    )
    authenticator = EventAuthenticator(secret, descriptor)

    authenticator.verify(headers, body, now=1_700_000_011)
    with pytest.raises(AuthenticationError, match="nonce"):
        authenticator.verify(headers, body, now=1_700_000_011)

    fresh_headers = sign_event_headers(
        body,
        other_secret,
        descriptor,
        event_id="event-alpha",
        now=1_700_000_012,
        nonce="nonce-other",
    )
    with pytest.raises(AuthenticationError, match="signature"):
        EventAuthenticator(secret, descriptor).verify(
            fresh_headers, body, now=1_700_000_012
        )

    forged = dict(headers)
    forged["X-Shadow-Nonce"] = "nonce-forged"
    with pytest.raises(AuthenticationError, match="signature"):
        EventAuthenticator(secret, descriptor).verify(forged, body, now=1_700_000_011)


def test_latch_binds_run_target_generation_and_expiry(tmp_path: Path) -> None:
    secret = generate_run_secret()
    descriptor = create_descriptor(
        tmp_path / "descriptor.json", secret, **descriptor_args(tmp_path)
    )
    latch = write_latch(
        tmp_path / "latch.json",
        secret,
        descriptor,
        registry=latch_registry(),
        scope="worker",
        target_id="session-worker-a",
        blocker_id="blocker-alpha",
        state="active",
        generation=2,
        direct_evidence_ids=["evidence-alpha"],
        probe_result_id="probe-alpha",
        correction_evidence_ids=[],
        provenance_status="untrusted_provenance",
        now=1_700_000_020,
        ttl_seconds=30,
    )

    assert load_latch(
        tmp_path / "latch.json", secret, descriptor, now=1_700_000_021
    ) == latch

    other_descriptor = dict(descriptor)
    other_descriptor["run_id"] = "run-other"
    with pytest.raises(AuthenticationError, match="run"):
        load_latch(
            tmp_path / "latch.json", secret, other_descriptor, now=1_700_000_021
        )

    with pytest.raises(AuthenticationError, match="expired"):
        load_latch(
            tmp_path / "latch.json", secret, descriptor, now=1_700_000_051
        )

def test_latch_keeps_raw_routing_target_out_of_external_registry(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    descriptor = create_descriptor(
        tmp_path / "descriptor.json", secret, **descriptor_args(tmp_path)
    )
    latch = write_latch(
        tmp_path / "latch.json",
        secret,
        descriptor,
        registry=latch_registry(target_id="session-safe-alias"),
        scope="worker",
        target_id="factory-raw-session",
        evidence_target_id="session-safe-alias",
        blocker_id="blocker-alpha",
        state="active",
        generation=1,
        direct_evidence_ids=["evidence-alpha"],
        probe_result_id="probe-alpha",
        correction_evidence_ids=[],
        provenance_status="untrusted_provenance",
        now=1_700_000_020,
    )

    assert "factory-raw-session" not in json.dumps(latch)
    assert latch["target_alias"].startswith("session-")


def test_untrusted_latch_requires_registered_external_observation(
    tmp_path: Path,
) -> None:
    secret = generate_run_secret()
    descriptor = create_descriptor(
        tmp_path / "descriptor.json", secret, **descriptor_args(tmp_path)
    )

    with pytest.raises(AuthenticationError, match="authorized"):
        write_latch(
            tmp_path / "latch.json",
            secret,
            descriptor,
            registry=latch_registry(blocker_id="blocker-untrusted"),
            scope="worker",
            target_id="session-worker-a",
            blocker_id="blocker-untrusted",
            state="active",
            generation=1,
            direct_evidence_ids=["unregistered"],
            probe_result_id="probe-alpha",
            correction_evidence_ids=[],
            provenance_status="untrusted_provenance",
            now=1_700_000_020,
        )
