"""Production assembly for the mission-wide review controller."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any, Mapping

from .auth import make_alias
from .correlation import (
    MissionCorrelationBinding,
    PinnedFactoryMissionRelationProducer,
)
from .extractor import ClaimExtractor
from .graph import MissionGraph
from .internal_session import LiveExtractionBroker, LiveProbeBroker
from .live import ActiveInertControl, DroidCommandBoundary, start_inert_control_session
from .probe import (
    FileProbeBoundaryStateStore,
    ProbeBoundaryState,
    ProbeRunner,
    ProbeScheduler,
)
from .review import MissionReviewController
from .router import InterventionLatchStore, InterventionRouter
from .rules import DeterministicRules, ProbeVerifier
from .runtime import ReviewControllerBinding, RunPreparation
from .storage import EventLedger
from .transcript import TranscriptReader


def _internal_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if isinstance(key, str) and isinstance(value, str)
    }


class _ManagedReviewController(MissionReviewController):
    def __init__(self, *args: Any, decoy: ActiveInertControl, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._decoy = decoy
        self._decoy_closed = False

    def stop(self, *, timeout: float = 5.0) -> bool:
        controller_error: BaseException | None = None
        decoy_error: BaseException | None = None
        stopped = False
        try:
            stopped = super().stop(timeout=timeout)
        except BaseException as error:
            controller_error = error
        finally:
            if not self._decoy_closed:
                try:
                    self._decoy.close()
                    self._decoy_closed = True
                except BaseException as error:
                    decoy_error = error
        if controller_error is not None:
            if decoy_error is not None:
                raise controller_error from decoy_error
            raise controller_error
        if decoy_error is not None:
            raise decoy_error
        return stopped


class ProductionReviewControllerFactory:
    """Build all live review dependencies from release-bound inputs."""
    def __init__(self, *, credential_environment: Mapping[str, str]) -> None:
        credential = dict(credential_environment)
        factory_api_key = credential.get("FACTORY_API_KEY")
        if (
            set(credential) != {"FACTORY_API_KEY"}
            or not isinstance(factory_api_key, str)
            or not factory_api_key
            or len(factory_api_key.encode("utf-8")) > 4096
            or "\x00" in factory_api_key
            or "\r" in factory_api_key
            or "\n" in factory_api_key
        ):
            raise RuntimeError(
                "FACTORY_API_KEY is required for internal review sessions"
            )
        self._credential_environment = credential


    def __call__(
        self,
        *,
        run_id: str,
        run_dir: Path,
        secret: str,
        runtime_forbidden_values: tuple[str, ...],
        descriptor_path: Path,
        latch_path: Path,
        ledger: EventLedger,
        correlation: MissionCorrelationBinding,
        correlation_producer: PinnedFactoryMissionRelationProducer,
        prepared: RunPreparation,
    ) -> ReviewControllerBinding:
        del descriptor_path
        preflight = prepared.preflight
        factory_api_key = self._credential_environment["FACTORY_API_KEY"]
        if any(
            type(item) is not str or not item
            for item in runtime_forbidden_values
        ):
            raise RuntimeError("runtime redaction values are unavailable")
        exact_forbidden_values = tuple(
            dict.fromkeys((*runtime_forbidden_values, factory_api_key))
        )
        environment = _internal_environment()
        environment.update(self._credential_environment)

        def collector_event_count(
            raw_session_id: str,
        ) -> tuple[str, tuple[str, ...]]:
            session_alias = make_alias(secret, "session", raw_session_id)
            return (
                session_alias,
                ledger.event_ids_for_session(session_alias),
            )

        broker_arguments = {
            "executable": str(prepared.droid_path),
            "expected_executable_digest": preflight.droid_binary_digest,
            "cwd": prepared.repo,
            "environment": environment,
            "collector_event_count": collector_event_count,
        }

        boundary_broker = LiveProbeBroker(
            **broker_arguments,
            model=preflight.models["probe"],
            reasoning=preflight.reasoning["probe"],
        )
        boundary_error: BaseException | None = None
        boundary: Any | None = None
        try:
            boundary = boundary_broker.prepare()
        except BaseException as error:
            boundary_error = error
        try:
            boundary_closed = boundary_broker.abort()
        except BaseException as error:
            if boundary_error is not None:
                raise boundary_error from error
            raise
        if boundary_error is not None:
            raise boundary_error
        if not boundary_closed:
            raise RuntimeError("probe boundary preparation did not close")
        assert boundary is not None
        correlation_producer.exclude(
            boundary.internal_session_alias,
            "shadow_owned",
        )

        credential_environment = self._credential_environment
        decoy_boundary = DroidCommandBoundary(
            prepared.droid_path,
            preflight.droid_version,
            preflight.droid_binary_digest,
            preflight.droid_installation_channel,
            credential_environment=credential_environment,
        )
        decoy: ActiveInertControl | None = None
        try:
            decoy = start_inert_control_session(
                boundary=decoy_boundary,
                authenticated_guest_home=Path.home().resolve(strict=True),
                fixture_path=prepared.repo,
                model=preflight.models["worker"],
                reasoning=preflight.reasoning["worker"],
                alias_secret=secret,
                internal=False,
            )
            correlation_producer.exclude(
                decoy.session_id,
                "same_project_decoy",
            )
            signing_key = hashlib.sha256(
                b"shadow-probe-signing\x00" + secret.encode("utf-8")
            ).digest()
            boundary_state = ProbeBoundaryState.enabled(boundary.policy_digest)
            boundary_store = FileProbeBoundaryStateStore(
                run_dir / "probe-boundary.json",
                boundary_state,
            )
            probe_broker = LiveProbeBroker(
                **broker_arguments,
                model=preflight.models["probe"],
                reasoning=preflight.reasoning["probe"],
            )
            probe_runner = ProbeRunner(
                probe_broker,
                signing_key=signing_key,
                approved_boundary_digest=boundary.policy_digest,
                boundary_state_store=boundary_store,
            )
            probe_scheduler = ProbeScheduler(probe_runner)
            probe_verifier = ProbeVerifier(
                signing_key,
                boundary_digest=boundary.policy_digest,
            )
            graph = MissionGraph(run_id)
            latch_store = InterventionLatchStore(
                run_dir,
                run_id=run_id,
                secret=secret,
                filename=latch_path.name,
            )
            latch_store.initialize(observed_at=int(time.time()))
            router = InterventionRouter.from_ledger(
                ledger,
                graph=graph,
                capabilities=preflight.capabilities,
                probe_verifier=probe_verifier,
                latch_store=latch_store,
                now=int(time.time()),
            )
            transcript_root = prepared.factory_mission_root.parent / "sessions"
            transcript_reader = TranscriptReader(
                transcript_root.resolve(strict=True),
                run_id=run_id,
                mode=(
                    "primary"
                    if preflight.capabilities.transcript == "pass"
                    else "fallback"
                ),
                provenance_status=(
                    "hook_authenticated"
                    if preflight.capabilities.hook_provenance == "pass"
                    else "untrusted_provenance"
                ),
                fallback_semantic_equivalence=(
                    preflight.capabilities.transcript != "pass"
                ),
            )
            extraction_broker = LiveExtractionBroker(
                **broker_arguments,
                model=preflight.models["extractor"],
                reasoning=preflight.reasoning["extractor"],
                failure_log=run_dir / "extract-failures.jsonl",
                forbidden_values=exact_forbidden_values,
            )
            # Build the first confined session before the Mission produces its
            # first triggering edit. Every request still gets a fresh session.
            extraction_broker.prewarm()
            controller = _ManagedReviewController(
                run_id=run_id,
                run_dir=run_dir,
                relations=correlation.relations,
                role_mapper=correlation.role_mapper,
                transcript_reader=transcript_reader,
                claim_extractor=ClaimExtractor(extraction_broker),
                graph=graph,
                rules=DeterministicRules(
                    capabilities=preflight.capabilities,
                    probe_verifier=probe_verifier,
                ),
                probe_scheduler=probe_scheduler,
                router=router,
                repository_root=prepared.repo,
                probe_risk_classifier=lambda finding: finding.risk_category,
                secret_canaries=exact_forbidden_values,
                decoy=decoy,
            )
            return ReviewControllerBinding(
                controller,
                latch_store,
                forbidden_values=exact_forbidden_values,
            )
        except BaseException as error:
            if decoy is not None:
                try:
                    decoy.close()
                except BaseException as cleanup_error:
                    raise error from cleanup_error
            raise
