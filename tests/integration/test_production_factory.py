from __future__ import annotations

from pathlib import Path

import pytest

import shadow_mission.production as production
from shadow_mission.auth import generate_run_secret, make_alias

from shadow_mission.correlation import PinnedFactoryMissionRelationProducer
from shadow_mission.extractor import BrokerAttempt
from shadow_mission.probe import ProbeBoundary
from shadow_mission.production import ProductionReviewControllerFactory
from shadow_mission.runtime import ReviewControllerBinding
from shadow_mission.storage import EventLedger
from tests.integration.test_version_binding import make_fixture, runtime_for


class FakeProbeBroker:
    def __init__(self, **_: object) -> None:
        pass

    def prepare(self) -> ProbeBoundary:
        return ProbeBoundary(
            factory_home="clean",
            timeout_seconds=90,
            shadow_activation_stripped=True,
            mission_correlation_stripped=True,
            internal_session_alias="raw-shadow-probe",
            environment_keys=(
                "FACTORY_DROID_AUTO_UPDATE_ENABLED",
                "HOME",
            ),
            list_tools_observed=True,
            observed_tools=(),
            enabled_tools=(),
            collector_event_count=0,
            collector_events=(),
        )

    def abort(self) -> bool:
        return True


class FakeExtractionBroker:
    def __init__(self, **_: object) -> None:
        self.prewarm_calls = 0

    def prewarm(self) -> bool:
        self.prewarm_calls += 1
        return True

    def extract(self, _: object) -> BrokerAttempt:
        return BrokerAttempt(boundary={}, output=None)

    def abort(self) -> bool:
        return True


class FakeDecoy:
    alias = "decoy-alias"
    session_id = "raw-decoy-session"

    def __init__(self) -> None:
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1



def test_managed_controller_closes_decoy_when_controller_stop_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = FakeDecoy()
    controller = object.__new__(production._ManagedReviewController)
    controller._decoy = decoy
    controller._decoy_closed = False
    expected = RuntimeError("controller stop failed")

    def fail_stop(_controller: object, *, timeout: float = 5.0) -> bool:
        del timeout
        raise expected

    monkeypatch.setattr(
        production.MissionReviewController,
        "stop",
        fail_stop,
    )

    with pytest.raises(RuntimeError) as raised:
        controller.stop(timeout=1.0)

    assert raised.value is expected
    assert decoy.close_count == 1
    assert controller._decoy_closed is True

def test_production_factory_assembles_live_controller_and_negative_controls(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("FACTORY_API_KEY", raising=False)
    secret = generate_run_secret()
    fixture = make_fixture(tmp_path)
    prepared = runtime_for(fixture).prepare(fixture.request)
    run_dir = fixture.state_root / "runs" / "run-production"
    run_dir.mkdir(parents=True, mode=0o700)
    ledger = EventLedger(run_dir, run_id="run-production")
    producer = PinnedFactoryMissionRelationProducer(
        mission_root=prepared.factory_mission_root,
        project_root=prepared.repo,
        droid_binary_digest=prepared.preflight.droid_binary_digest,
        expected_source_digest=prepared.preflight.mission_relation_source_digest,
        secret=secret,
        correlation_id="run-production",
        role_configuration=prepared.preflight.role_configuration,
        clock=lambda: 1_100,
    )
    decoy = FakeDecoy()
    broker_environments: list[dict[str, str]] = []
    broker_values: list[dict[str, object]] = []
    observed_collector_aliases: list[str] = []
    decoy_credentials: list[dict[str, str]] = []

    class RecordingProbeBroker(FakeProbeBroker):
        def __init__(self, **values: object) -> None:
            broker_environments.append(dict(values["environment"]))  # type: ignore[arg-type]
            super().__init__(**values)
            broker_values.append(dict(values))

    class RecordingExtractionBroker(FakeExtractionBroker):
        def __init__(self, **values: object) -> None:
            broker_environments.append(dict(values["environment"]))  # type: ignore[arg-type]
            super().__init__(**values)
            broker_values.append(dict(values))

    def boundary(*_: object, **values: object) -> object:
        decoy_credentials.append(  # type: ignore[arg-type]
            dict(values["credential_environment"])
        )
        return object()

    monkeypatch.setattr(production, "LiveProbeBroker", RecordingProbeBroker)
    monkeypatch.setattr(
        production,
        "LiveExtractionBroker",
        RecordingExtractionBroker,
    )
    monkeypatch.setattr(production, "DroidCommandBoundary", boundary)
    monkeypatch.setattr(
        production,
        "start_inert_control_session",
        lambda **kwargs: decoy,
    )
    monkeypatch.setattr(
        ledger,
        "event_ids_for_session",
        lambda alias: observed_collector_aliases.append(alias) or (),
    )

    binding = ProductionReviewControllerFactory(
        credential_environment={"FACTORY_API_KEY": "test-only-key"},
    )(
        run_id="run-production",
        run_dir=run_dir,
        secret=secret,
        runtime_forbidden_values=(secret, "source-canary-private"),
        descriptor_path=run_dir / "descriptor.json",
        latch_path=run_dir / "latch.json",
        ledger=ledger,
        correlation=producer.binding,
        correlation_producer=producer,
        prepared=prepared,
    )

    assert isinstance(binding, ReviewControllerBinding)
    assert binding.latch_store.path == run_dir / "latch.json"
    assert len(producer.binding.excluded_session_aliases) == 2
    assert broker_environments
    assert all(
        environment["FACTORY_API_KEY"] == "test-only-key"
        for environment in broker_environments
    )
    assert decoy_credentials == [{"FACTORY_API_KEY": "test-only-key"}]
    assert binding.forbidden_values == (
        secret,
        "source-canary-private",
        "test-only-key",
    )
    forbidden_broker_values = [
        values["forbidden_values"]
        for values in broker_values
        if "forbidden_values" in values
    ]
    assert len(forbidden_broker_values) == 1
    assert forbidden_broker_values[0] is binding.forbidden_values
    assert binding.controller._secret_canaries == binding.forbidden_values
    observer = broker_values[0]["collector_event_count"]
    assert callable(observer)
    assert observer("raw-internal-session") == (  # type: ignore[operator]
        make_alias(secret, "session", "raw-internal-session"),
        (),
    )
    assert observed_collector_aliases[-1] == make_alias(
        secret,
        "session",
        "raw-internal-session",
    )
    binding_repr = repr(binding)
    assert all(
        value not in binding_repr
        for value in binding.forbidden_values
    )
    binding.controller.start()
    assert binding.controller.stop(timeout=1.0) is True
    assert decoy.close_count == 1
    producer.close()


def test_production_factory_closes_decoy_when_exclusion_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = generate_run_secret()
    fixture = make_fixture(tmp_path)
    prepared = runtime_for(fixture).prepare(fixture.request)
    run_dir = fixture.state_root / "runs" / "run-exclusion-failure"
    run_dir.mkdir(parents=True, mode=0o700)
    ledger = EventLedger(run_dir, run_id="run-exclusion-failure")
    producer = PinnedFactoryMissionRelationProducer(
        mission_root=prepared.factory_mission_root,
        project_root=prepared.repo,
        droid_binary_digest=prepared.preflight.droid_binary_digest,
        expected_source_digest=prepared.preflight.mission_relation_source_digest,
        secret=secret,
        correlation_id="run-exclusion-failure",
        role_configuration=prepared.preflight.role_configuration,
        clock=lambda: 1_100,
    )
    decoy = FakeDecoy()
    exclusions = 0
    real_exclude = producer.exclude

    def fail_second_exclusion(session_id: str, reason: str) -> None:
        nonlocal exclusions
        exclusions += 1
        if exclusions == 2:
            raise RuntimeError("decoy exclusion failed")
        real_exclude(session_id, reason)

    monkeypatch.setattr(production, "LiveProbeBroker", FakeProbeBroker)
    monkeypatch.setattr(
        production,
        "DroidCommandBoundary",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        production,
        "start_inert_control_session",
        lambda **_kwargs: decoy,
    )
    monkeypatch.setattr(producer, "exclude", fail_second_exclusion)

    with pytest.raises(RuntimeError, match="decoy exclusion failed"):
        ProductionReviewControllerFactory(
            credential_environment={"FACTORY_API_KEY": "test-only-key"},
        )(
            run_id="run-exclusion-failure",
            run_dir=run_dir,
            secret=secret,
            runtime_forbidden_values=(secret, "source-canary-private"),
            descriptor_path=run_dir / "descriptor.json",
            latch_path=run_dir / "latch.json",
            ledger=ledger,
            correlation=producer.binding,
            correlation_producer=producer,
            prepared=prepared,
        )

    assert decoy.close_count == 1
    producer.close()


def test_production_factory_stops_before_broker_setup_without_api_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("FACTORY_API_KEY", raising=False)
    secret = generate_run_secret()
    fixture = make_fixture(tmp_path)
    prepared = runtime_for(fixture).prepare(fixture.request)
    run_dir = fixture.state_root / "runs" / "run-missing-credential"
    run_dir.mkdir(parents=True, mode=0o700)
    ledger = EventLedger(run_dir, run_id="run-missing-credential")
    producer = PinnedFactoryMissionRelationProducer(
        mission_root=prepared.factory_mission_root,
        project_root=prepared.repo,
        droid_binary_digest=prepared.preflight.droid_binary_digest,
        expected_source_digest=prepared.preflight.mission_relation_source_digest,
        secret=secret,
        correlation_id="run-missing-credential",
        role_configuration=prepared.preflight.role_configuration,
        clock=lambda: 1_100,
    )

    with pytest.raises(
        RuntimeError,
        match="FACTORY_API_KEY is required for internal review sessions",
    ):
        ProductionReviewControllerFactory(credential_environment={})(
            run_id="run-missing-credential",
            run_dir=run_dir,
            secret=secret,
            runtime_forbidden_values=(secret, "source-canary-private"),
            descriptor_path=run_dir / "descriptor.json",
            latch_path=run_dir / "latch.json",
            ledger=ledger,
            correlation=producer.binding,
            correlation_producer=producer,
            prepared=prepared,
        )
    producer.close()
