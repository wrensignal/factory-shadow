"""Durable target-only intervention routing and bounded blocker latches."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence

from pydantic import BaseModel, Field, field_validator, model_validator

from .auth import AuthenticationError, load_signed_private_state, write_signed_private_state
from .graph import MissionGraph
from .protocol import (
    CapabilityFlags,
    EvidenceRecord,
    HookEnvelope,
    InterventionRecord,
    InterventionTransition,
    PersistedRecord,
    RepairAssignment,
    canonical_json,
)
from .redaction import sanitize_value
from .rules import Finding, ProbeAssessment, ProbeVerifier
from .storage import ResponsePlan, compose_review_state, review_state_component

_INTERVENTION_STATES = {
    "queued",
    "delivered",
    "acknowledged",
    "corrected",
    "resolved",
    "expired",
    "quarantined",
    "repair_requested",
    "repair_assigned",
    "termination_acknowledged",
}
_NONBLOCKING_STATES = {"resolved", "termination_acknowledged"}
_TERMINAL_FAILURE_STATES = {"expired", "quarantined"}
_ALLOWED_TRANSITIONS = {
    "queued": {"delivered", "quarantined", "expired"},
    "delivered": {"acknowledged", "corrected", "repair_requested", "quarantined", "expired"},
    "acknowledged": {"corrected", "repair_requested", "quarantined", "expired"},
    "corrected": {"resolved", "quarantined"},
    "repair_requested": {"repair_assigned", "quarantined", "expired"},
    "repair_assigned": {"acknowledged", "corrected", "quarantined", "expired"},
    "expired": {"termination_acknowledged"},
    "quarantined": {"termination_acknowledged"},
    "resolved": set(),
    "termination_acknowledged": set(),
}
_ACKNOWLEDGMENT_KINDS = frozenset({"target_acknowledgment"})
_CORRECTION_KINDS = frozenset({"target_correction"})
_TERMINATION_ACKNOWLEDGMENT_KINDS = frozenset(
    {"termination_acknowledgment", "child_termination_acknowledgment"}
)
_SHARED_SOURCES = frozenset(
    {"repository", "repository_output", "shared_repository", "shared_file", "git"}
)
_CRITICAL_RISKS = frozenset(
    {"money", "security", "data_loss", "public_contract", "explicit_acceptance"}
)
_SAFE_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_TARGET_ACKNOWLEDGMENT_SOURCE = "target_assistant_transcript"
_TARGET_CORRECTION_SOURCES = frozenset(
    {"target_diff_transcript", "target_test_transcript"}
)
_MAX_GUIDANCE_ITEMS = 4
_MAX_GUIDANCE_TEXT = 96
_SOURCE_CORRECTION_SOURCE = "target_diff_transcript"
_TEST_CORRECTION_SOURCE = "target_test_transcript"
_MAX_GUIDANCE_DELIVERIES = 3
_LATCH_LOCK_TIMEOUT_SECONDS = 0.5
_LATCH_LOCK_POLL_SECONDS = 0.01


def _delivery_count(item: InterventionRecord) -> int:
    """Count how many times one intervention's guidance already reached its target."""

    return sum(
        1 for transition in item.transition_history if transition.action == "delivered"
    )


def _correction_proof_complete(
    corrections: Sequence[EvidenceRecord],
) -> bool:
    """Require one source change and one passing test before resolution."""

    sources = {record.source.strip().lower() for record in corrections}
    return (
        _SOURCE_CORRECTION_SOURCE in sources and _TEST_CORRECTION_SOURCE in sources
    )


class InterventionPolicyError(ValueError):
    """An intervention or transition violates the durable policy."""


class InterventionLatchLockTimeout(AuthenticationError):
    """The signed latch lock stayed unavailable past its bounded deadline."""


class InterventionRouterState(PersistedRecord):
    """The complete rebuildable router state used by the signed latch."""

    record_type: Literal["intervention_router_state"] = "intervention_router_state"
    run_id: str = Field(min_length=1)
    generation: int = Field(ge=0)
    interventions: tuple[InterventionRecord, ...] = ()
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    @field_validator("generation", mode="before")
    @classmethod
    def reject_boolean_generation(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("router generation must not be a boolean")
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> InterventionRouterState:
        identities = tuple(item.intervention_id for item in self.interventions)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("router interventions are not canonical")
        if any(item.run_id != self.run_id for item in self.interventions):
            raise ValueError("router contains another run")
        if any(item.generation > self.generation for item in self.interventions):
            raise ValueError("intervention generation exceeds router generation")
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        if supplied != hashlib.sha256(canonical_json(value)).hexdigest():
            raise ValueError("router state digest does not match")
        return self

    @classmethod
    def empty(cls, run_id: str) -> InterventionRouterState:
        return cls.model_validate(
            _with_digest(
                cls,
                {
                    "record_type": "intervention_router_state",
                    "provenance_status": "hook_authenticated",
                    "redaction_status": "clean",
                    "run_id": run_id,
                    "generation": 0,
                    "interventions": (),
                },
            )
        )


class InterventionRouterDelta(PersistedRecord):
    """One contiguous digest-bound change to router state."""

    record_type: Literal["intervention_router_delta"] = "intervention_router_delta"
    run_id: str = Field(min_length=1)
    base_generation: int = Field(ge=0)
    base_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation: int = Field(ge=1)
    upserts: tuple[InterventionRecord, ...] = Field(min_length=1)
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    @field_validator("base_generation", "generation", mode="before")
    @classmethod
    def reject_boolean_generations(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("router delta generations must not be booleans")
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> InterventionRouterDelta:
        identities = tuple(item.intervention_id for item in self.upserts)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("router delta upserts are not canonical")
        if any(item.run_id != self.run_id for item in self.upserts):
            raise ValueError("router delta contains another run")
        if self.generation <= self.base_generation:
            raise ValueError("router delta generation is not contiguous")
        if any(
            item.generation <= self.base_generation or item.generation > self.generation
            for item in self.upserts
        ):
            raise ValueError("router delta intervention generation is invalid")
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        if supplied != hashlib.sha256(canonical_json(value)).hexdigest():
            raise ValueError("router delta digest does not match")
        return self

    def apply(self, state: InterventionRouterState) -> InterventionRouterState:
        if (
            state.run_id != self.run_id
            or state.generation != self.base_generation
            or state.record_digest != self.base_digest
        ):
            raise ValueError("router delta diverges from replay state")
        records = {item.intervention_id: item for item in state.interventions}
        records.update({item.intervention_id: item for item in self.upserts})
        result = _router_state(self.run_id, self.generation, records.values())
        if result.record_digest != self.result_digest:
            raise ValueError("router delta result digest does not match")
        return result


class InterventionLatchStore:
    """Persist signed router state and its rollback-resistant private head."""

    _LATCH_FIELDS = frozenset(
        {
            "schema_version",
            "record_type",
            "run_id",
            "generation",
            "state",
            "written_at",
            "signature",
        }
    )
    _HEAD_FIELDS = frozenset(
        {
            "schema_version",
            "record_type",
            "run_id",
            "generation",
            "state_digest",
            "updated_at",
            "signature",
        }
    )

    def __init__(
        self,
        private_root: Path,
        *,
        run_id: str,
        secret: str,
        filename: str = "intervention-latch.json",
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not run_id:
            raise AuthenticationError("latch run ID must not be empty")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", filename):
            raise AuthenticationError("unsafe latch filename")
        try:
            metadata = private_root.lstat()
        except FileNotFoundError:
            private_root.mkdir(parents=True, mode=0o700)
            os.chmod(private_root, 0o700)
            metadata = private_root.lstat()
        if (
            private_root.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise AuthenticationError("private latch root is not private")
        root = private_root.resolve(strict=True)
        self.path = root / filename
        self.head_path = root / f"{Path(filename).stem}-head{Path(filename).suffix}"
        self.lock_path = root / f".{filename}.lock"
        if (
            self.path.parent != root
            or self.head_path.parent != root
            or self.lock_path.parent != root
            or self.path == self.head_path
        ):
            raise AuthenticationError("latch path is unsafe")
        if not callable(clock):
            raise AuthenticationError("latch clock must be callable")
        self.run_id, self._secret = run_id, secret
        self._clock = clock
        self._anchor_lock = threading.RLock()
        self._minimum_generation: int | None = None
        self._minimum_state_digest: str | None = None
        self._validate_paths()

    def _validate_paths(self) -> None:
        for path in (self.path, self.head_path, self.lock_path):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            ):
                raise AuthenticationError("latch path is unsafe")

    def _acquire_lock(self) -> int:
        import fcntl

        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            os.close(descriptor)
            raise AuthenticationError("latch lock path is unsafe")
        deadline = time.monotonic() + _LATCH_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return descriptor
            except BlockingIOError as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    os.close(descriptor)
                    raise InterventionLatchLockTimeout(
                        "latch lock timed out"
                    ) from error
                time.sleep(min(_LATCH_LOCK_POLL_SECONDS, remaining))
            except BaseException:
                os.close(descriptor)
                raise

    @staticmethod
    def _release_lock(descriptor: int) -> None:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    @staticmethod
    def _state_digest(state: Mapping[str, Any]) -> str:
        return hashlib.sha256(canonical_json(state)).hexdigest()

    def _advance_anchor(self, state: InterventionRouterState) -> None:
        digest = self._state_digest(state.model_dump(mode="json"))
        with self._anchor_lock:
            generation = self._minimum_generation
            if generation is not None:
                if state.generation < generation:
                    raise AuthenticationError("latch generation rolled back")
                if (
                    state.generation == generation
                    and digest != self._minimum_state_digest
                ):
                    raise AuthenticationError(
                        "latch state changed within an observed generation"
                    )
            if generation is None or state.generation > generation:
                self._minimum_generation = state.generation
                self._minimum_state_digest = digest


    def _write_pair(
        self, state: InterventionRouterState, *, observed_at: int
    ) -> None:
        state_value = state.model_dump(mode="json")
        latch = {
            "schema_version": "0.1",
            "record_type": "intervention_latch",
            "run_id": self.run_id,
            "generation": state.generation,
            "state": state_value,
            "written_at": observed_at,
        }
        head = {
            "schema_version": "0.1",
            "record_type": "intervention_latch_head",
            "run_id": self.run_id,
            "generation": state.generation,
            "state_digest": self._state_digest(state_value),
            "updated_at": observed_at,
        }
        write_signed_private_state(self.path, self._secret, latch)
        write_signed_private_state(self.head_path, self._secret, head)

    def initialize(self, *, observed_at: int) -> InterventionRouterState:
        """Create the required generation-zero production latch and head."""
        if (
            not isinstance(observed_at, int)
            or isinstance(observed_at, bool)
            or observed_at < 0
        ):
            raise AuthenticationError("latch initialization time is invalid")
        lock_descriptor = self._acquire_lock()
        try:
            self._validate_paths()
            if self.path.exists() or self.head_path.exists():
                raise AuthenticationError("production latch is already initialized")
            state = InterventionRouterState.empty(self.run_id)
            self._write_pair(state, observed_at=observed_at)
            self._advance_anchor(state)
            return state
        finally:
            self._release_lock(lock_descriptor)

    def write(
        self,
        state: InterventionRouterState,
        *,
        expected_generation: int,
        observed_at: int,
    ) -> None:
        if state.run_id != self.run_id:
            raise AuthenticationError("latch state belongs to another run")
        if (
            not isinstance(expected_generation, int)
            or isinstance(expected_generation, bool)
            or expected_generation < 0
            or not isinstance(observed_at, int)
            or isinstance(observed_at, bool)
            or observed_at < 0
        ):
            raise AuthenticationError("latch write generation or time is invalid")
        if state.generation <= expected_generation:
            raise AuthenticationError("latch generation must advance")
        lock_descriptor = self._acquire_lock()
        try:
            self._validate_paths()
            if self.path.exists() or self.head_path.exists():
                self.load(expected_generation=expected_generation)
            elif expected_generation != 0:
                raise AuthenticationError("missing expected latch generation")
            self._write_pair(state, observed_at=observed_at)
            self._advance_anchor(state)
        finally:
            self._release_lock(lock_descriptor)

    def load(
        self, *, expected_generation: int | None = None
    ) -> InterventionRouterState:
        self._validate_paths()
        latch = load_signed_private_state(self.path, self._secret)
        head = load_signed_private_state(self.head_path, self._secret)
        if (
            set(latch) != self._LATCH_FIELDS
            or latch.get("schema_version") != "0.1"
            or latch.get("record_type") != "intervention_latch"
            or latch.get("run_id") != self.run_id
        ):
            raise AuthenticationError("latch fields or run binding are invalid")
        generation, written_at = latch.get("generation"), latch.get("written_at")
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 0
            or not isinstance(written_at, int)
            or isinstance(written_at, bool)
            or written_at < 0
        ):
            raise AuthenticationError("latch generation or time is invalid")
        if expected_generation is not None and generation != expected_generation:
            raise AuthenticationError("stale or replayed latch generation")
        try:
            state = InterventionRouterState.model_validate(latch.get("state"))
        except ValueError as error:
            raise AuthenticationError("latch state is invalid") from error
        if state.run_id != self.run_id or state.generation != generation:
            raise AuthenticationError("latch state binding is invalid")
        state_value = state.model_dump(mode="json")
        state_digest = self._state_digest(state_value)
        if (
            set(head) != self._HEAD_FIELDS
            or head.get("schema_version") != "0.1"
            or head.get("record_type") != "intervention_latch_head"
            or head.get("run_id") != self.run_id
            or head.get("generation") != generation
            or head.get("state_digest") != state_digest
            or head.get("updated_at") != written_at
        ):
            raise AuthenticationError("latch head does not match current state")
        if (
            not isinstance(head.get("generation"), int)
            or isinstance(head.get("generation"), bool)
            or not isinstance(head.get("updated_at"), int)
            or isinstance(head.get("updated_at"), bool)
            or not re.fullmatch(r"[0-9a-f]{64}", str(head.get("state_digest", "")))
        ):
            raise AuthenticationError("latch head is malformed")
        self._advance_anchor(state)
        return state

    def _load_for_status(self) -> InterventionRouterState:
        lock_descriptor = self._acquire_lock()
        try:
            return self.load()
        finally:
            self._release_lock(lock_descriptor)

    @property
    def termination_required(self) -> bool:
        """Fail closed on invalid state, terminal failure, or an elapsed blocker."""
        try:
            state = self._load_for_status()
            now = self._clock()
            if (
                not isinstance(now, (int, float))
                or isinstance(now, bool)
                or not math.isfinite(now)
            ):
                raise AuthenticationError("latch clock returned an invalid time")
        except Exception:
            return True
        return any(
            item.state in _TERMINAL_FAILURE_STATES
            or (
                item.level == "blocker"
                and item.state not in _NONBLOCKING_STATES
                and item.deadline is not None
                and now >= item.deadline
            )
            for item in state.interventions
        )

    @property
    def completion_blocked(self) -> bool:
        """Fail closed when any unresolved blocker remains active."""
        try:
            state = self._load_for_status()
        except Exception:
            return True
        return any(
            item.level == "blocker" and item.state not in _NONBLOCKING_STATES
            for item in state.interventions
        )


class InterventionRouter:
    """Plan router changes in the serialized ledger callback and commit after fsync."""

    def __init__(
        self,
        *,
        run_id: str,
        graph: MissionGraph,
        capabilities: CapabilityFlags,
        probe_verifier: ProbeVerifier,
        latch_store: InterventionLatchStore | None = None,
        state: InterventionRouterState | None = None,
    ) -> None:
        if graph.run_id != run_id:
            raise ValueError("router graph belongs to another run")
        self.run_id, self.graph, self.capabilities = run_id, graph, capabilities
        self._probe_verifier, self._latch_store = probe_verifier, latch_store
        self._state = state or InterventionRouterState.empty(run_id)
        if self._state.run_id != run_id:
            raise ValueError("router state belongs to another run")
        self._lock = threading.Lock()

    @classmethod
    def from_ledger(
        cls,
        ledger: Any,
        *,
        graph: MissionGraph,
        capabilities: CapabilityFlags,
        probe_verifier: ProbeVerifier,
        latch_store: InterventionLatchStore | None = None,
        now: int,
    ) -> InterventionRouter:
        state = InterventionRouterState.empty(ledger.run_id)
        expected_sequence = 1
        for exchange in ledger.exchanges():
            if exchange.ledger_sequence != expected_sequence:
                raise ValueError("router state exchange sequence is invalid")
            expected_sequence += 1
            if exchange.response.review_state is None:
                continue
            legacy = review_state_component(
                exchange.response.review_state,
                run_id=ledger.run_id,
                record_type="intervention_router_state",
            )
            if legacy is not None:
                raise ValueError("full router snapshots are not valid response deltas")
            component = review_state_component(
                exchange.response.review_state,
                run_id=ledger.run_id,
                record_type="intervention_router_delta",
            )
            if component is not None:
                state = InterventionRouterDelta.model_validate(component).apply(state)
        router = cls(
            run_id=ledger.run_id,
            graph=graph,
            capabilities=capabilities,
            probe_verifier=probe_verifier,
            latch_store=latch_store,
            state=state,
        )
        if latch_store is not None:
            cached_generation = 0
            if latch_store.path.exists():
                cached = latch_store.load()
                if (
                    cached.generation == state.generation
                    and cached.record_digest != state.record_digest
                ):
                    raise AuthenticationError(
                        "private latch conflicts with the authoritative ledger"
                    )
                cached_generation = cached.generation
            if cached_generation < state.generation:
                latch_store.write(
                    state, expected_generation=cached_generation, observed_at=now
                )
        return router

    def snapshot(self) -> InterventionRouterState:
        with self._lock:
            return self._state

    def intervention(self, intervention_id: str) -> InterventionRecord | None:
        return next(
            (
                item
                for item in self.snapshot().interventions
                if item.intervention_id == intervention_id
            ),
            None,
        )

    def repeatable_delivery_keys(self) -> frozenset[tuple[str, str]]:
        """Name every delivered intervention that still needs its guidance repeated."""

        return frozenset(
            (item.target_session, item.finding_dedup_key)
            for item in self.snapshot().interventions
            if item.state == "delivered"
            and _delivery_count(item) < _MAX_GUIDANCE_DELIVERIES
        )

    def undelivered_target_sessions(
        self,
        plan: ResponsePlan | None = None,
    ) -> frozenset[str]:
        """Name sessions with queued guidance in the committed or planned state."""

        state = self.snapshot()
        if plan is not None and plan.review_state is not None:
            component = review_state_component(
                plan.review_state,
                run_id=self.run_id,
                record_type="intervention_router_delta",
            )
            if component is not None:
                state = InterventionRouterDelta.model_validate(component).apply(state)
        return frozenset(
            item.target_session
            for item in state.interventions
            if item.state == "queued"
        )

    def plan_response(
        self,
        envelope: HookEnvelope,
        *,
        findings: Iterable[Finding] = (),
        probes: Iterable[ProbeAssessment] = (),
        stored_evidence: Iterable[EvidenceRecord] = (),
        original_features: Mapping[str, str] | None = None,
        repair_assignments: Iterable[RepairAssignment] = (),
        cancelled_interventions: Iterable[str] = (),
        selected_delivery_keys: Iterable[tuple[str, str]] | None = None,
        base_plan: ResponsePlan | None = None,
    ) -> ResponsePlan:
        """Plan one exact hook response and all state changes atomically."""
        if envelope.run_id != self.run_id:
            raise InterventionPolicyError("hook event belongs to another run")
        if envelope.provenance_status not in {
            "hook_authenticated",
            "untrusted_provenance",
        }:
            return base_plan or ResponsePlan(body={})
        authoritative = self.snapshot()
        expected = authoritative
        outage_transition_ids: tuple[str, ...] = ()
        latch_expected_generation = authoritative.generation
        if self._latch_store is not None and self._latch_store.path.exists():
            observed = self._latch_store.load()
            latch_expected_generation = observed.generation
            if observed.generation < authoritative.generation:
                raise InterventionPolicyError(
                    "private latch is older than authoritative router state"
                )
            if observed.generation == authoritative.generation:
                if observed.record_digest != authoritative.record_digest:
                    raise InterventionPolicyError(
                        "private latch conflicts with authoritative router state"
                    )
            else:
                expected, outage_transition_ids = self._reconcile_outage_advance(
                    authoritative, observed
                )
        records = {item.intervention_id: item for item in expected.interventions}
        generation = expected.generation
        transitions = list(outage_transition_ids)
        guidance_ids: list[str] = []
        feature_index = dict(original_features or {})
        probe_index = self._validated_probes(probes)
        finding_values = tuple(findings)
        findings_by_key = {item.dedup_key: item for item in finding_values}
        routable_keys = {
            (item.dedup_key, target)
            for item in finding_values
            for target in item.target_sessions
        }
        selected_keys = (
            None
            if selected_delivery_keys is None
            else set(selected_delivery_keys)
        )
        if selected_keys is not None and selected_keys - routable_keys:
            raise InterventionPolicyError("selected delivery lacks a routed finding")

        for finding in sorted(
            finding_values, key=lambda item: (item.dedup_key, item.finding_id)
        ):
            if finding.level == "note":
                continue
            if not finding.evidence_ids or not finding.evidence_digests:
                raise InterventionPolicyError("concern lacks direct evidence")
            probe = probe_index.get(finding.dedup_key)
            if probe is not None:
                self._validate_probe_binding(probe, finding)
            exact_blocker = (
                finding.level == "blocker"
                and finding.risk_category in _CRITICAL_RISKS
                and probe is not None
                and probe.status == "confirmed"
            )
            level: Literal["concern", "blocker"] = (
                "blocker" if exact_blocker else "concern"
            )
            for target in finding.target_sessions:
                if self.graph.role_for_session(target) is None:
                    continue
                # One conflict at one target keeps one intervention for the whole
                # Mission. A successor record after a terminal state would leave
                # the finding permanently unresolved, which is a worse error than
                # the recorded limitation it would remove.
                occurrence = 0
                intervention_id = _intervention_identity(
                    self.run_id, finding, target, occurrence
                )
                prior = records.get(intervention_id)
                feature = feature_index.get(finding.finding_id)
                if prior is not None:
                    self._validate_finding_lineage(prior, finding, probe)
                    if (
                        feature is not None
                        and prior.original_feature is not None
                        and feature != prior.original_feature
                    ):
                        raise InterventionPolicyError("original feature changed")
                    updates: dict[str, Any] = {}
                    action: str | None = None
                    if prior.state not in _NONBLOCKING_STATES | (
                        _TERMINAL_FAILURE_STATES
                    ) and (
                        prior.claim_ids != finding.claim_ids
                        or prior.direct_evidence_ids != finding.evidence_ids
                        or prior.direct_evidence_digests
                        != finding.evidence_digests
                    ):
                        updates.update(
                            {
                                "claim_ids": finding.claim_ids,
                                "direct_evidence_ids": finding.evidence_ids,
                                "direct_evidence_digests": (
                                    finding.evidence_digests
                                ),
                            }
                        )
                        action = "evidence_extended"
                    if prior.original_feature is None and feature is not None:
                        updates["original_feature"] = feature
                        action = "original_feature_bound"
                    if probe is not None and prior.probe_digest != probe.record_digest:
                        updates.update(
                            {
                                "probe_id": probe.probe_id,
                                "probe_digest": probe.record_digest,
                                "probe_status": probe.status,
                                "probe_snapshot_digest": probe.snapshot_digest,
                                "risk_category": finding.risk_category,
                            }
                        )
                        action = "probe_bound"
                    if (
                        prior.level == "concern"
                        and prior.state not in _NONBLOCKING_STATES
                        and exact_blocker
                    ):
                        updates.update(
                            {
                                "level": "blocker",
                                "probe_id": probe.probe_id,
                                "probe_digest": probe.record_digest,
                                "probe_status": probe.status,
                                "probe_snapshot_digest": probe.snapshot_digest,
                            }
                        )
                        action = "blocker_confirmed"
                    if action is not None:
                        generation += 1
                        prior = _mutate(
                            prior,
                            state=prior.state,
                            action=action,
                            generation=generation,
                            observed_at=envelope.observed_at,
                            **updates,
                        )
                        records[intervention_id] = prior
                        transitions.append(prior.transition_history[-1].transition_id)
                    continue
                scope = self._blocking_scope()
                generation += 1
                item = _new_intervention(
                    run_id=self.run_id,
                    finding=finding,
                    target_session=target,
                    completion_session_alias=self._completion_session_alias(
                        target, scope
                    ),
                    level=level,
                    probe=probe,
                    generation=generation,
                    observed_at=envelope.observed_at,
                    blocking_scope=scope,
                    original_feature=feature,
                    occurrence=occurrence,
                )
                records[intervention_id] = item
                transitions.append(item.transition_history[-1].transition_id)

        cancelled = set(cancelled_interventions)
        if cancelled - records.keys():
            raise InterventionPolicyError("cancellation names an unknown intervention")
        for intervention_id in sorted(cancelled):
            item = records[intervention_id]
            if item.state in _NONBLOCKING_STATES | _TERMINAL_FAILURE_STATES:
                continue
            generation += 1
            item = _mutate(
                item,
                state="quarantined",
                action="notification_cancelled",
                generation=generation,
                observed_at=envelope.observed_at,
                terminal_outcome="notification_cancelled",
            )
            records[intervention_id] = item
            transitions.append(item.transition_history[-1].transition_id)

        assignments = tuple(repair_assignments)
        assignment_ids = tuple(item.assignment_id for item in assignments)
        if len(set(assignment_ids)) != len(assignment_ids):
            raise InterventionPolicyError("repair assignment is duplicated")
        used_workers = {
            item.repair_assignment.worker_session
            for item in records.values()
            if item.repair_assignment is not None
        }
        target_workers = {item.target_session for item in records.values()}
        for assignment in sorted(assignments, key=lambda item: item.assignment_id):
            item = records.get(assignment.intervention_id)
            if item is None:
                raise InterventionPolicyError("repair assignment is missing or duplicated")
            if item.state == "quarantined" and item.intervention_id in cancelled:
                continue
            if item.repair_assignment is not None:
                if item.repair_assignment != assignment:
                    raise InterventionPolicyError("repair assignment binding changed")
                continue
            if item.state != "repair_requested":
                raise InterventionPolicyError("repair assignment is missing or duplicated")
            if (
                assignment.run_id != self.run_id
                or assignment.original_feature != item.original_feature
            ):
                raise InterventionPolicyError("repair assignment feature binding is invalid")
            if (
                self.graph.role_for_session(assignment.worker_session) != "worker"
                or self.graph.role_id_for_session(assignment.worker_session)
                != assignment.worker_role_id
            ):
                raise InterventionPolicyError(
                    "repair session lacks an authoritative high-confidence worker role"
                )
            if (
                assignment.worker_session in used_workers
                or assignment.worker_session in target_workers
                or assignment.worker_session == item.target_session
            ):
                raise InterventionPolicyError("repair worker is reused or unrelated")
            if (
                not _SAFE_ALIAS.fullmatch(assignment.worker_session)
                or assignment.assigned_at <= item.transition_history[0].observed_at
            ):
                raise InterventionPolicyError("repair worker is not fresh")
            generation += 1
            item = _mutate(
                item,
                state="repair_assigned",
                action="repair_assigned",
                generation=generation,
                observed_at=envelope.observed_at,
                repair_assignment=assignment,
            )
            records[item.intervention_id] = item
            used_workers.add(assignment.worker_session)
            transitions.append(item.transition_history[-1].transition_id)

        generation = self._apply_evidence_transitions(
            records,
            generation,
            tuple(stored_evidence),
            transitions,
            observed_at=envelope.observed_at,
            session_alias=envelope.session_alias,
            completion_event=envelope.hook_event_name
            in {"Stop", "SubagentStop"},
        )

        router_body: Mapping[str, Any] = {}
        if envelope.hook_event_name == "PostToolUse":
            selected_notes = [
                finding
                for finding in finding_values
                if finding.level == "note"
                and envelope.session_alias in finding.target_sessions
                and selected_keys is not None
                and (finding.dedup_key, envelope.session_alias) in selected_keys
                and self.graph.role_for_session(envelope.session_alias) is not None
            ]
            deliverable = [
                item
                for item in records.values()
                if item.state == "queued"
                and item.target_session == envelope.session_alias
                and self.graph.role_for_session(envelope.session_alias) is not None
                and (
                    selected_keys is None
                    or (item.finding_dedup_key, item.target_session) in selected_keys
                )
            ]
            if selected_notes:
                note = sorted(
                    selected_notes,
                    key=lambda value: (value.dedup_key, value.finding_id),
                )[0]
                router_body = _post_tool_note_response(note)
            elif deliverable:
                item = sorted(deliverable, key=lambda value: value.intervention_id)[0]
                generation += 1
                item = _mutate(
                    item,
                    state="delivered",
                    action="delivered",
                    generation=generation,
                    observed_at=envelope.observed_at,
                )
                records[item.intervention_id] = item
                transitions.append(item.transition_history[-1].transition_id)
                guidance_ids.append(item.intervention_id)
                router_body = _post_tool_response(
                    item, findings_by_key.get(item.finding_dedup_key)
                )
            elif repeat_deliverable := [
                item
                for item in records.values()
                if item.state == "delivered"
                and item.target_session == envelope.session_alias
                and self.graph.role_for_session(envelope.session_alias) is not None
                and _delivery_count(item) < _MAX_GUIDANCE_DELIVERIES
                and (
                    selected_keys is None
                    or (item.finding_dedup_key, item.target_session) in selected_keys
                )
            ]:
                item = sorted(
                    repeat_deliverable, key=lambda value: value.intervention_id
                )[0]
                repeat_index = _delivery_count(item)
                generation += 1
                item = _mutate(
                    item,
                    state=item.state,
                    action="delivered",
                    generation=generation,
                    observed_at=envelope.observed_at,
                )
                records[item.intervention_id] = item
                transitions.append(item.transition_history[-1].transition_id)
                guidance_ids.append(
                    _stable_id(
                        "guidance-repeat", item.intervention_id, str(repeat_index)
                    )
                )
                router_body = _post_tool_response(
                    item, findings_by_key.get(item.finding_dedup_key)
                )
            else:
                repair_deliverable = [
                    item
                    for item in records.values()
                    if item.state == "repair_assigned"
                    and item.repair_assignment is not None
                    and item.repair_assignment.worker_session == envelope.session_alias
                    and item.repair_guidance_delivered_at is None
                    and self.graph.role_for_session(envelope.session_alias) == "worker"
                ]
                if repair_deliverable:
                    item = sorted(
                        repair_deliverable, key=lambda value: value.intervention_id
                    )[0]
                    generation += 1
                    item = _mutate(
                        item,
                        state=item.state,
                        action="repair_guidance_delivered",
                        generation=generation,
                        observed_at=envelope.observed_at,
                        repair_guidance_delivered_at=envelope.observed_at,
                    )
                    records[item.intervention_id] = item
                    transitions.append(item.transition_history[-1].transition_id)
                    guidance_ids.append(
                        _stable_id("repair-guidance", item.intervention_id)
                    )
                    router_body = _post_tool_response(
                        item, findings_by_key.get(item.finding_dedup_key)
                    )
        elif envelope.hook_event_name in {"Stop", "SubagentStop"}:
            router_body, generation = self._plan_completion(
                envelope, records, generation, transitions
            )

        next_state = _router_state(self.run_id, generation, records.values())
        previous = {
            item.intervention_id: item for item in authoritative.interventions
        }
        changed = tuple(
            item
            for item in next_state.interventions
            if item.intervention_id not in previous
            or previous[item.intervention_id].record_digest != item.record_digest
        )
        delta = (
            _router_delta(authoritative, next_state, changed) if changed else None
        )
        merged = _merge_plan(
            run_id=self.run_id,
            base=base_plan,
            router_body=router_body,
            router_delta=delta,
            router_guidance_ids=tuple(guidance_ids),
            router_transition_ids=tuple(transitions),
        )

        def commit() -> None:
            with self._lock:
                if self._state.record_digest != authoritative.record_digest:
                    raise RuntimeError("router state changed before durable commit")
                if (
                    delta is not None
                    and self._latch_store is not None
                    and next_state.generation > latch_expected_generation
                ):
                    self._latch_store.write(
                        next_state,
                        expected_generation=latch_expected_generation,
                        observed_at=envelope.observed_at,
                    )
                self._state = next_state
            if base_plan is not None and base_plan.commit is not None:
                base_plan.commit()

        return ResponsePlan(
            body=merged.body,
            guidance_ids=merged.guidance_ids,
            transition_ids=merged.transition_ids,
            redaction_status=merged.redaction_status,
            review_state=merged.review_state,
            commit=commit,
        )

    def response_decider(
        self,
        *,
        findings: Callable[[], Iterable[Finding]] = lambda: (),
        probes: Callable[[], Iterable[ProbeAssessment]] = lambda: (),
        stored_evidence: Callable[[], Iterable[EvidenceRecord]] = lambda: (),
        original_features: Callable[[], Mapping[str, str]] = lambda: {},
        repair_assignments: Callable[[], Iterable[RepairAssignment]] = lambda: (),
        cancelled_interventions: Callable[[], Iterable[str]] = lambda: (),
        base_decide: Callable[[HookEnvelope], ResponsePlan] | None = None,
    ) -> Callable[[HookEnvelope], ResponsePlan]:
        """Resolve every evolving input inside each serialized decision."""
        providers = (
            findings,
            probes,
            stored_evidence,
            original_features,
            repair_assignments,
            cancelled_interventions,
        )
        if not all(callable(provider) for provider in providers):
            raise TypeError("router decision inputs must be provider callables")

        def decide(envelope: HookEnvelope) -> ResponsePlan:
            base = base_decide(envelope) if base_decide is not None else None
            return self.plan_response(
                envelope,
                findings=findings(),
                probes=probes(),
                stored_evidence=stored_evidence(),
                original_features=original_features(),
                repair_assignments=repair_assignments(),
                cancelled_interventions=cancelled_interventions(),
                base_plan=base,
            )

        return decide

    def reconcile_final_outage(
        self,
        durable_callback: Callable[[InterventionRouterDelta], None],
    ) -> InterventionRouterDelta | None:
        """Journal one valid final signed outage advance before committing it."""

        if not callable(durable_callback):
            raise TypeError("outage durable callback must be callable")
        if self._latch_store is None:
            return None
        with self._lock:
            authoritative = self._state
            observed = self._latch_store.load()
            if observed.generation < authoritative.generation:
                raise InterventionPolicyError(
                    "private latch is older than authoritative router state"
                )
            if observed.generation == authoritative.generation:
                if observed.record_digest != authoritative.record_digest:
                    raise InterventionPolicyError(
                        "private latch conflicts with authoritative router state"
                    )
                return None
            reconciled, _ = self._reconcile_outage_advance(
                authoritative, observed
            )
            before_by_id = {
                item.intervention_id: item for item in authoritative.interventions
            }
            changed = tuple(
                item
                for item in reconciled.interventions
                if before_by_id.get(item.intervention_id) != item
            )
            delta = _router_delta(authoritative, reconciled, changed)
            durable_callback(delta)
            self._state = reconciled
            return delta

    def reconcile_evidence(
        self,
        stored_evidence: Iterable[EvidenceRecord],
        durable_callback: Callable[[InterventionRouterDelta], None],
        *,
        observed_at: int,
    ) -> InterventionRouterDelta | None:
        """Journal target evidence transitions after projection drain."""

        if not callable(durable_callback):
            raise TypeError("evidence durable callback must be callable")
        evidence = tuple(stored_evidence)
        with self._lock:
            authoritative = self._state
            records = {
                item.intervention_id: item
                for item in authoritative.interventions
            }
            generation = self._apply_evidence_transitions(
                records,
                authoritative.generation,
                evidence,
                [],
                observed_at=observed_at,
            )
            if generation == authoritative.generation:
                return None
            reconciled = _router_state(
                self.run_id,
                generation,
                records.values(),
            )
            before_by_id = {
                item.intervention_id: item
                for item in authoritative.interventions
            }
            changed = tuple(
                item
                for item in reconciled.interventions
                if before_by_id.get(item.intervention_id) != item
            )
            delta = _router_delta(authoritative, reconciled, changed)
            latch_generation: int | None = None
            if self._latch_store is not None:
                latched = self._latch_store.load()
                if (
                    latched.generation != authoritative.generation
                    or latched.record_digest != authoritative.record_digest
                ):
                    raise InterventionPolicyError(
                        "private latch differs before evidence reconciliation"
                    )
                latch_generation = latched.generation
            durable_callback(delta)
            if self._latch_store is not None:
                assert latch_generation is not None
                self._latch_store.write(
                    reconciled,
                    expected_generation=latch_generation,
                    observed_at=observed_at,
                )
            self._state = reconciled
            return delta

    def replay_evidence_reconciliation(
        self,
        delta: InterventionRouterDelta,
        stored_evidence: Iterable[EvidenceRecord],
        *,
        observed_at: int,
    ) -> None:
        """Apply one journaled post-drain evidence delta exactly once."""

        evidence = tuple(stored_evidence)
        with self._lock:
            authoritative = self._state
            records = {
                item.intervention_id: item
                for item in authoritative.interventions
            }
            generation = self._apply_evidence_transitions(
                records,
                authoritative.generation,
                evidence,
                [],
                observed_at=observed_at,
            )
            if generation == authoritative.generation:
                raise InterventionPolicyError(
                    "journaled evidence reconciliation made no transition"
                )
            expected = _router_state(
                self.run_id,
                generation,
                records.values(),
            )
            try:
                observed = delta.apply(authoritative)
            except ValueError as error:
                raise InterventionPolicyError(
                    "journaled evidence delta diverges"
                ) from error
            if observed.record_digest != expected.record_digest:
                raise InterventionPolicyError(
                    "journaled evidence result differs"
                )
            self._state = expected

    def replay_outage_reconciliation(
        self, delta: InterventionRouterDelta
    ) -> None:
        """Apply one journaled outage delta after strict policy validation."""

        with self._lock:
            authoritative = self._state
            try:
                observed = delta.apply(authoritative)
            except ValueError as error:
                raise InterventionPolicyError(
                    "journaled outage delta diverges"
                ) from error
            reconciled, _ = self._reconcile_outage_advance(
                authoritative, observed
            )
            if reconciled.record_digest != delta.result_digest:
                raise InterventionPolicyError(
                    "journaled outage result differs"
                )
            self._state = reconciled

    @staticmethod
    def _reconcile_outage_advance(
        authoritative: InterventionRouterState,
        observed: InterventionRouterState,
    ) -> tuple[InterventionRouterState, tuple[str, ...]]:
        """Accept only the hook runtime's narrow contiguous outage advance."""
        if (
            observed.run_id != authoritative.run_id
            or observed.generation <= authoritative.generation
        ):
            raise InterventionPolicyError("outage latch did not advance")
        before_by_id = {
            item.intervention_id: item for item in authoritative.interventions
        }
        after_by_id = {
            item.intervention_id: item for item in observed.interventions
        }
        if before_by_id.keys() != after_by_id.keys():
            raise InterventionPolicyError(
                "outage latch changed intervention identities"
            )

        extensions: list[InterventionTransition] = []
        mutable_fields = {
            "generation",
            "state",
            "transition_history",
            "attempts",
            "deadline",
            "terminal_outcome",
            "record_digest",
        }
        for intervention_id in sorted(before_by_id):
            before = before_by_id[intervention_id]
            after = after_by_id[intervention_id]
            before_value = before.model_dump(mode="python")
            after_value = after.model_dump(mode="python")
            for field in mutable_fields:
                before_value.pop(field)
                after_value.pop(field)
            if before_value != after_value:
                raise InterventionPolicyError(
                    "outage latch changed unrelated intervention fields"
                )
            prefix_size = len(before.transition_history)
            if after.transition_history[:prefix_size] != before.transition_history:
                raise InterventionPolicyError(
                    "outage latch rewrote intervention history"
                )
            added = after.transition_history[prefix_size:]
            if not added:
                if after.record_digest != before.record_digest:
                    raise InterventionPolicyError(
                        "outage latch changed an intervention without history"
                    )
                continue

            current_state = before.state
            prior_observed_at = before.transition_history[-1].observed_at
            blocked = 0
            terminated = False
            first_blocked_at: int | None = None
            for transition in added:
                if transition.observed_at < prior_observed_at:
                    raise InterventionPolicyError(
                        "outage transition time moved backwards"
                    )
                prior_observed_at = transition.observed_at
                if transition.action == "blocked_attempt" and not terminated:
                    expected_state = (
                        "delivered" if current_state == "queued" else current_state
                    )
                    if transition.state != expected_state:
                        raise InterventionPolicyError(
                            "outage blocked attempt changed intervention state"
                        )
                    current_state = transition.state
                    blocked += 1
                    if first_blocked_at is None:
                        first_blocked_at = transition.observed_at
                elif transition.action == "termination_required" and not terminated:
                    expected_state = (
                        "quarantined"
                        if current_state == "corrected"
                        else "expired"
                    )
                    if transition.state != expected_state:
                        raise InterventionPolicyError(
                            "outage termination state is invalid"
                        )
                    current_state = transition.state
                    terminated = True
                else:
                    raise InterventionPolicyError(
                        "outage latch contains an unrelated transition"
                    )
            if terminated and added[-1].action != "termination_required":
                raise InterventionPolicyError(
                    "outage termination is not the final transition"
                )
            if after.state != current_state:
                raise InterventionPolicyError(
                    "outage state differs from its transition history"
                )
            if after.attempts != before.attempts + blocked:
                raise InterventionPolicyError(
                    "outage attempt count is not contiguous"
                )
            expected_deadline = before.deadline
            if blocked and expected_deadline is None:
                assert first_blocked_at is not None
                expected_deadline = first_blocked_at + 600
            if after.deadline != expected_deadline:
                raise InterventionPolicyError("outage deadline changed")
            expected_outcome = (
                "mission_termination_required"
                if terminated
                else before.terminal_outcome
            )
            if after.terminal_outcome != expected_outcome:
                raise InterventionPolicyError("outage terminal outcome changed")
            extensions.extend(added)

        extensions.sort(key=lambda item: item.generation)
        generations = tuple(item.generation for item in extensions)
        expected_generations = tuple(
            range(authoritative.generation + 1, observed.generation + 1)
        )
        if generations != expected_generations:
            raise InterventionPolicyError(
                "outage transition generations are not contiguous"
            )
        return observed, tuple(item.transition_id for item in extensions)

    def cached_response(
        self,
        *,
        session_alias: str,
        hook_event_name: str,
        now: int,
        expected_generation: int,
    ) -> Mapping[str, Any]:
        """Return a generation-bound signed cached block during collector outage."""
        if self._latch_store is None or hook_event_name not in {"Stop", "SubagentStop"}:
            return {}
        state = self._latch_store.load(expected_generation=expected_generation)
        role = self.graph.role_for_session(session_alias)
        candidates = [
            item
            for item in state.interventions
            if _is_blocking(item)
            and self._scope_applies(item, session_alias=session_alias, role=role)
        ]
        if not candidates:
            return {}
        item = sorted(
            candidates,
            key=lambda value: (
                0
                if value.state in _TERMINAL_FAILURE_STATES
                or (value.deadline is not None and now >= value.deadline)
                or value.attempts >= 2
                else 1,
                value.intervention_id,
            ),
        )[0]
        if (
            item.state in _TERMINAL_FAILURE_STATES
            or (item.deadline is not None and now >= item.deadline)
            or item.attempts >= 2
        ):
            return _termination_response(item)
        if item.blocking_scope == "mission" and item.state == "repair_requested":
            return _repair_response(item)
        return _block_response(item)

    def _validated_probes(
        self, probes: Iterable[ProbeAssessment]
    ) -> dict[str, ProbeAssessment]:
        result: dict[str, ProbeAssessment] = {}
        for probe in probes:
            if probe.run_id != self.run_id:
                raise InterventionPolicyError("probe belongs to another run")
            if not self._probe_verifier.verify(probe):
                raise InterventionPolicyError("probe authentication failed")
            prior = result.get(probe.finding_dedup_key)
            if prior is not None and prior != probe:
                raise InterventionPolicyError("multiple probes claim one finding")
            result[probe.finding_dedup_key] = probe
        return result

    @staticmethod
    def _validate_probe_binding(probe: ProbeAssessment, finding: Finding) -> None:
        if (
            probe.finding_dedup_key != finding.dedup_key
            or not set(probe.claim_ids) <= set(finding.claim_ids)
            or not set(probe.evidence_digests) <= set(finding.evidence_digests)
            or probe.risk_category != finding.risk_category
        ):
            raise InterventionPolicyError("probe does not bind this finding")

    @staticmethod
    def _validate_finding_lineage(
        intervention: InterventionRecord,
        finding: Finding,
        probe: ProbeAssessment | None,
    ) -> None:
        risk_unchanged = intervention.risk_category == finding.risk_category
        verified_transition = (
            intervention.risk_category == "none"
            and finding.risk_category in _CRITICAL_RISKS
            and probe is not None
            and probe.status == "confirmed"
            and probe.risk_category == finding.risk_category
        )
        if (
            intervention.finding_id != finding.finding_id
            or not set(intervention.claim_ids) <= set(finding.claim_ids)
            or not set(intervention.direct_evidence_ids) <= set(finding.evidence_ids)
            or not set(intervention.direct_evidence_digests)
            <= set(finding.evidence_digests)
            or not (risk_unchanged or verified_transition)
            or intervention.rule != finding.rule
        ):
            raise InterventionPolicyError("finding lineage changed for an intervention")

    def _apply_evidence_transitions(
        self,
        records: dict[str, InterventionRecord],
        generation: int,
        evidence: Sequence[EvidenceRecord],
        transitions: list[str],
        *,
        observed_at: int,
        session_alias: str | None = None,
        completion_event: bool = False,
    ) -> int:
        """Apply target evidence identically on a hook or at final drain."""

        for intervention_id in sorted(records):
            item = records[intervention_id]
            active_session = (
                item.repair_assignment.worker_session
                if item.repair_assignment is not None
                else item.target_session
            )
            if session_alias is not None and (
                session_alias != active_session
                and not (
                    completion_event
                    and session_alias == item.completion_session_alias
                )
            ):
                continue
            direct = self._target_evidence(self.run_id, evidence, item)
            termination_acks = tuple(
                record
                for record in direct
                if record.kind in _TERMINATION_ACKNOWLEDGMENT_KINDS
            )
            if item.state in _TERMINAL_FAILURE_STATES and termination_acks:
                record = termination_acks[0]
                generation += 1
                item = _mutate(
                    item,
                    state="termination_acknowledged",
                    action="termination_acknowledged",
                    generation=generation,
                    observed_at=observed_at,
                    termination_acknowledgment_evidence_id=record.evidence_id,
                    termination_acknowledgment_evidence_digest=record.digest,
                )
                records[intervention_id] = item
                transitions.append(item.transition_history[-1].transition_id)
                continue
            if item.state in _NONBLOCKING_STATES | _TERMINAL_FAILURE_STATES:
                continue
            acknowledgments = tuple(
                record
                for record in direct
                if record.kind in _ACKNOWLEDGMENT_KINDS
            )
            corrections = tuple(
                record
                for record in direct
                if record.kind in _CORRECTION_KINDS
            )
            correction_evidence_ids = tuple(
                sorted(
                    {
                        *item.correction_evidence_ids,
                        *(record.evidence_id for record in corrections),
                    }
                )
            )
            correction_evidence_digests = tuple(
                sorted(
                    {
                        *item.correction_evidence_digests,
                        *(record.digest for record in corrections),
                    }
                )
            )
            new_correction_evidence = (
                correction_evidence_ids != item.correction_evidence_ids
                or correction_evidence_digests != item.correction_evidence_digests
            )
            state_before_evidence = item.state
            changed_item = False
            if (
                state_before_evidence in {"delivered", "repair_assigned"}
                and acknowledgments
            ):
                generation += 1
                item = _mutate(
                    item,
                    state="acknowledged",
                    action="acknowledged",
                    generation=generation,
                    observed_at=observed_at,
                )
                transitions.append(item.transition_history[-1].transition_id)
                changed_item = True
            if (
                state_before_evidence
                in {"delivered", "acknowledged", "repair_assigned"}
                and _correction_proof_complete(corrections)
            ):
                generation += 1
                item = _mutate(
                    item,
                    state="corrected",
                    action="corrected",
                    generation=generation,
                    observed_at=observed_at,
                    correction_evidence_ids=correction_evidence_ids,
                    correction_evidence_digests=correction_evidence_digests,
                )
                transitions.append(item.transition_history[-1].transition_id)
                changed_item = True
            elif (
                state_before_evidence
                in {"delivered", "acknowledged", "repair_assigned"}
                and corrections
                and new_correction_evidence
            ):
                generation += 1
                item = _mutate(
                    item,
                    state=item.state,
                    action="correction_evidence_bound",
                    generation=generation,
                    observed_at=observed_at,
                    correction_evidence_ids=correction_evidence_ids,
                    correction_evidence_digests=correction_evidence_digests,
                )
                transitions.append(item.transition_history[-1].transition_id)
                changed_item = True
            if item.state == "corrected":
                generation += 1
                item = _mutate(
                    item,
                    state="resolved",
                    action="resolved",
                    generation=generation,
                    observed_at=observed_at,
                    terminal_outcome="corrected",
                )
                transitions.append(item.transition_history[-1].transition_id)
                changed_item = True
            if changed_item:
                records[intervention_id] = item
        return generation

    @staticmethod
    def _target_evidence(
        run_id: str,
        records: Sequence[EvidenceRecord],
        intervention: InterventionRecord,
    ) -> tuple[EvidenceRecord, ...]:
        active_session = (
            intervention.repair_assignment.worker_session
            if intervention.repair_assignment is not None
            else intervention.target_session
        )
        accepted = []
        for record in records:
            source = record.source.strip().lower()
            # A correction may land in another worker's session. Review binds it to
            # this exact intervention only when both belong to one finding, so the
            # session check stays on acknowledgments alone. The record still needs
            # this exact intervention identity, this run, and an authenticated
            # correction source.
            if (
                record.intervention_id != intervention.intervention_id
                or record.run_id != run_id
                or (
                    record.session_alias != active_session
                    and record.kind != "target_correction"
                )
                or record.provenance_status
                not in {"hook_authenticated", "collector_observed"}
                or source in _SHARED_SOURCES
                or "repository" in source
                or "shared" in source
            ):
                continue
            if (
                record.kind == "target_acknowledgment"
                and source != _TARGET_ACKNOWLEDGMENT_SOURCE
            ):
                continue
            if (
                record.kind == "target_correction"
                and source not in _TARGET_CORRECTION_SOURCES
            ):
                continue
            accepted.append(record)
        return tuple(sorted(accepted, key=lambda item: item.evidence_id))

    def _blocking_scope(self) -> Literal["worker", "mission"]:
        if self.capabilities.worker_block == "pass":
            return "worker"
        if self.capabilities.mission_block == "pass":
            return "mission"
        return "worker"

    def _completion_session_alias(
        self,
        target_session: str,
        blocking_scope: Literal["worker", "mission"],
    ) -> str:
        if blocking_scope == "worker":
            return target_session
        orchestrators = self.graph.sessions_for_role("orchestrator")
        if len(orchestrators) != 1:
            raise InterventionPolicyError(
                "mission blocker lacks one exact high-confidence orchestrator"
            )
        return orchestrators[0]

    def _scope_applies(
        self, item: InterventionRecord, *, session_alias: str, role: str | None
    ) -> bool:
        if item.completion_session_alias != session_alias:
            return False
        if item.blocking_scope == "worker":
            return self.capabilities.worker_block == "pass"
        return role == "orchestrator" and self.capabilities.mission_block == "pass"

    def _plan_completion(
        self,
        envelope: HookEnvelope,
        records: dict[str, InterventionRecord],
        generation: int,
        transitions: list[str],
    ) -> tuple[Mapping[str, Any], int]:
        role = self.graph.role_for_session(envelope.session_alias)
        candidates = [
            item
            for item in records.values()
            if _is_blocking(item)
            and self._scope_applies(
                item, session_alias=envelope.session_alias, role=role
            )
        ]
        for item in [
            value
            for value in records.values()
            if value.target_session == envelope.session_alias
            and value.state not in _NONBLOCKING_STATES | _TERMINAL_FAILURE_STATES
            and value.probe_status in {"missing", "pending"}
        ]:
            if item.probe_pending_at_completion is None:
                generation += 1
                item = _mutate(
                    item,
                    state=item.state,
                    action="probe_pending_at_completion",
                    generation=generation,
                    observed_at=envelope.observed_at,
                    probe_pending_at_completion=envelope.observed_at,
                )
                records[item.intervention_id] = item
                transitions.append(item.transition_history[-1].transition_id)
        correction_holds = [
            item
            for item in records.values()
            if item.level == "concern"
            and item.state == "acknowledged"
            and item.attempts < 2
            and (item.deadline is None or envelope.observed_at < item.deadline)
            and self._scope_applies(
                item, session_alias=envelope.session_alias, role=role
            )
        ]
        if correction_holds:
            item = sorted(
                correction_holds, key=lambda value: value.intervention_id
            )[0]
            deadline = item.deadline or (envelope.observed_at + 600)
            generation += 1
            item = _mutate(
                item,
                state=item.state,
                action="correction_required",
                generation=generation,
                observed_at=envelope.observed_at,
                attempts=item.attempts + 1,
                deadline=deadline,
            )
            records[item.intervention_id] = item
            transitions.append(item.transition_history[-1].transition_id)
            return _correction_required_response(item), generation
        if not candidates:
            return {}, generation
        item = sorted(
            candidates,
            key=lambda value: (
                0 if value.state in _TERMINAL_FAILURE_STATES else 1,
                value.intervention_id,
            ),
        )[0]
        if item.state in _TERMINAL_FAILURE_STATES:
            return _termination_response(item), generation
        if (
            item.deadline is not None
            and envelope.observed_at >= item.deadline
        ) or item.attempts >= 2:
            generation += 1
            item = _mutate(
                item,
                state="expired",
                action="terminal_failure",
                generation=generation,
                observed_at=envelope.observed_at,
                terminal_outcome="mission_termination_required",
            )
            records[item.intervention_id] = item
            transitions.append(item.transition_history[-1].transition_id)
            return _termination_response(item), generation
        fallback = item.blocking_scope == "mission"
        if fallback and item.state not in {"repair_requested", "repair_assigned"}:
            if item.original_feature is None:
                generation += 1
                item = _mutate(
                    item,
                    state="quarantined",
                    action="missing_original_feature",
                    generation=generation,
                    observed_at=envelope.observed_at,
                    terminal_outcome="missing_original_feature",
                )
                records[item.intervention_id] = item
                transitions.append(item.transition_history[-1].transition_id)
                return _termination_response(item), generation
            if item.state == "queued":
                generation += 1
                item = _mutate(
                    item,
                    state="delivered",
                    action="delivered",
                    generation=generation,
                    observed_at=envelope.observed_at,
                )
                transitions.append(item.transition_history[-1].transition_id)
            generation += 1
            item = _mutate(
                item,
                state="repair_requested",
                action="repair_requested",
                generation=generation,
                observed_at=envelope.observed_at,
            )
            transitions.append(item.transition_history[-1].transition_id)
        elif not fallback and item.state == "queued":
            generation += 1
            item = _mutate(
                item,
                state="delivered",
                action="delivered",
                generation=generation,
                observed_at=envelope.observed_at,
            )
            transitions.append(item.transition_history[-1].transition_id)
        deadline = (
            item.deadline
            if item.deadline is not None
            else envelope.observed_at + 600
        )
        generation += 1
        item = _mutate(
            item,
            state=item.state,
            action="blocked_attempt",
            generation=generation,
            observed_at=envelope.observed_at,
            attempts=item.attempts + 1,
            deadline=deadline,
        )
        records[item.intervention_id] = item
        transitions.append(item.transition_history[-1].transition_id)
        if fallback and item.state == "repair_requested":
            return _repair_response(item), generation
        return _block_response(item), generation


def _is_blocking(item: InterventionRecord) -> bool:
    return item.level == "blocker" and item.state not in _NONBLOCKING_STATES


def _with_digest(
    model_type: type[BaseModel], values: Mapping[str, Any]
) -> dict[str, Any]:
    raw = dict(values)
    raw.pop("record_digest", None)
    materialized = model_type.model_construct(
        record_digest="0" * 64, **raw
    ).model_dump(mode="json")
    materialized.pop("record_digest")
    materialized["record_digest"] = hashlib.sha256(
        canonical_json(materialized)
    ).hexdigest()
    return materialized


def _stable_id(prefix: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join((prefix, *values)).encode()).hexdigest()
    return f"{prefix}-{digest[:32]}"


def _transition_id(intervention_id: str, action: str, generation: int) -> str:
    return _stable_id("transition", intervention_id, action, str(generation))


def _intervention_identity(
    run_id: str, finding: Finding, target_session: str, occurrence: int
) -> str:
    """Name one occurrence of one conflict at one target session."""

    return _stable_id(
        "intervention", run_id, finding.dedup_key, target_session, str(occurrence)
    )


def _new_intervention(
    *,
    run_id: str,
    finding: Finding,
    target_session: str,
    completion_session_alias: str,
    level: Literal["concern", "blocker"],
    probe: ProbeAssessment | None,
    generation: int,
    observed_at: int,
    blocking_scope: Literal["worker", "mission"],
    original_feature: str | None,
    occurrence: int = 0,
) -> InterventionRecord:
    intervention_id = _intervention_identity(
        run_id, finding, target_session, occurrence
    )
    transition = InterventionTransition(
        transition_id=_transition_id(intervention_id, "queued", generation),
        generation=generation,
        state="queued",
        action="queued",
        observed_at=observed_at,
    )
    values = {
        "provenance_status": "hook_authenticated",
        "redaction_status": "clean",
        "intervention_id": intervention_id,
        "run_id": run_id,
        "finding_id": finding.finding_id,
        "finding_dedup_key": finding.dedup_key,
        "target_session": target_session,
        "completion_session_alias": completion_session_alias,
        "rule": finding.rule,
        "level": level,
        "risk_category": finding.risk_category,
        "claim_ids": tuple(sorted(set(finding.claim_ids))),
        "direct_evidence_ids": tuple(sorted(set(finding.evidence_ids))),
        "direct_evidence_digests": tuple(sorted(set(finding.evidence_digests))),
        "generation": generation,
        "state": "queued",
        "transition_history": (transition,),
        "probe_id": probe.probe_id if probe is not None else None,
        "probe_digest": probe.record_digest if probe is not None else None,
        "probe_status": probe.status if probe is not None else "missing",
        "probe_snapshot_digest": probe.snapshot_digest if probe is not None else None,
        "blocking_scope": blocking_scope,
        "original_feature": original_feature,
    }
    return InterventionRecord.model_validate(_with_digest(InterventionRecord, values))


def _mutate(
    item: InterventionRecord,
    *,
    state: str,
    action: str,
    generation: int,
    observed_at: int,
    **updates: Any,
) -> InterventionRecord:
    if state not in _INTERVENTION_STATES:
        raise InterventionPolicyError("invalid intervention state")
    if state != item.state and state not in _ALLOWED_TRANSITIONS[item.state]:
        raise InterventionPolicyError(f"invalid transition: {item.state} -> {state}")
    if generation <= item.generation:
        raise InterventionPolicyError("intervention generation did not advance")
    values = {
        name: getattr(item, name)
        for name in InterventionRecord.model_fields
        if name != "record_digest"
    }
    values.update(updates)
    transition = InterventionTransition(
        transition_id=_transition_id(item.intervention_id, action, generation),
        generation=generation,
        state=state,
        action=action,
        observed_at=observed_at,
    )
    values.update(
        {
            "state": state,
            "generation": generation,
            "transition_history": (*item.transition_history, transition),
        }
    )
    return InterventionRecord.model_validate(_with_digest(InterventionRecord, values))


def _router_state(
    run_id: str, generation: int, interventions: Iterable[InterventionRecord]
) -> InterventionRouterState:
    return InterventionRouterState.model_validate(
        _with_digest(
            InterventionRouterState,
            {
                "record_type": "intervention_router_state",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "run_id": run_id,
                "generation": generation,
                "interventions": tuple(
                    sorted(interventions, key=lambda item: item.intervention_id)
                ),
            },
        )
    )


def _router_delta(
    before: InterventionRouterState,
    after: InterventionRouterState,
    changed: tuple[InterventionRecord, ...],
) -> InterventionRouterDelta:
    return InterventionRouterDelta.model_validate(
        _with_digest(
            InterventionRouterDelta,
            {
                "record_type": "intervention_router_delta",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "run_id": after.run_id,
                "base_generation": before.generation,
                "base_digest": before.record_digest,
                "generation": after.generation,
                "upserts": tuple(
                    sorted(changed, key=lambda item: item.intervention_id)
                ),
                "result_digest": after.record_digest,
            },
        )
    )


def _review_components(
    review_state: Mapping[str, Any] | None, *, run_id: str
) -> tuple[Mapping[str, Any], ...]:
    if review_state is None:
        return ()
    if review_state.get("record_type") == "response_review_state":
        components = review_state.get("components")
        if not isinstance(components, Mapping):
            raise ValueError("base response review state is invalid")
        return tuple(
            components[name]
            for name in sorted(components)
            if name not in {"intervention_router_state", "intervention_router_delta"}
        )
    if review_state.get("run_id") != run_id:
        raise ValueError("base review state belongs to another run")
    if review_state.get("record_type") in {
        "intervention_router_state",
        "intervention_router_delta",
    }:
        return ()
    return (review_state,)


def _merge_plan(
    *,
    run_id: str,
    base: ResponsePlan | None,
    router_body: Mapping[str, Any],
    router_delta: InterventionRouterDelta | None,
    router_guidance_ids: tuple[str, ...],
    router_transition_ids: tuple[str, ...],
) -> ResponsePlan:
    base = base or ResponsePlan(body={})
    components = list(_review_components(base.review_state, run_id=run_id))
    if router_delta is not None:
        components.append(router_delta.model_dump(mode="json"))
    review_state = (
        compose_review_state(run_id=run_id, components=tuple(components))
        if components
        else None
    )
    return ResponsePlan(
        body=router_body or base.body,
        guidance_ids=(*base.guidance_ids, *router_guidance_ids),
        transition_ids=(*base.transition_ids, *router_transition_ids),
        redaction_status=base.redaction_status,
        review_state=review_state,
    )


def _marker(item: InterventionRecord) -> str:
    return f"[shadow:{item.intervention_id}]"


def _bounded(text: str) -> str:
    value = " ".join(str(text).split())
    return value if len(value) <= _MAX_GUIDANCE_TEXT else value[:_MAX_GUIDANCE_TEXT]


def _rendered_value(token: str) -> str:
    try:
        decoded = json.loads(token)
    except (TypeError, ValueError):
        return _bounded(token)
    if isinstance(decoded, Mapping) and "value" in decoded:
        return _bounded(json.dumps(decoded["value"], sort_keys=True))
    return _bounded(token)


def _guidance_detail(finding: Finding | None) -> str:
    """Render bounded direct evidence for one target session to investigate."""

    if finding is None:
        return ""
    parts: list[str] = []
    for label, values in (
        ("locator", finding.normalized_locators),
        ("property", finding.normalized_properties),
    ):
        rendered = ", ".join(
            _bounded(item) for item in values[:_MAX_GUIDANCE_ITEMS] if item
        )
        if rendered:
            parts.append(f"{label} {rendered}")
    values = ", ".join(
        _rendered_value(item)
        for item in finding.normalized_values[:_MAX_GUIDANCE_ITEMS]
    )
    if values:
        parts.append(f"observed values {values}")
    units = ", ".join(
        _bounded(item)
        for item in finding.normalized_units[:_MAX_GUIDANCE_ITEMS]
        if item
    )
    if units:
        parts.append(f"units {units}")
    related = ", ".join(
        f"{_bounded(locator)} declares {_bounded(prop)} {_rendered_value(value)}"
        for locator, prop, value in (
            finding.related_declarations[:_MAX_GUIDANCE_ITEMS]
        )
        if locator
    )
    if related:
        parts.append(f"these sessions also declared {related}")
    if (
        finding.authority.status == "resolved"
        and finding.authority.normalized_value is not None
    ):
        parts.append(
            "authoritative value "
            f"{_rendered_value(finding.authority.normalized_value)}"
        )
    if not parts:
        return ""
    detail, _ = sanitize_value("; ".join(parts))
    return f" Evidence: {detail}."


def _required_correction(item: InterventionRecord) -> str:
    if item.rule == "cross_worker_conflict":
        return (
            "The mixed values are the defect; do not preserve a per-boundary "
            "split. Change the source files named in the evidence below, not "
            "the record that reports the disagreement. Before validation, make "
            "or delegate source changes that use one unit and one declared "
            "type for this property across every listed locator and affected "
            "consumer. Convert values at each boundary instead of rejecting "
            "inputs, and keep the field names every consumer already reads. "
            "Documentation, acknowledgment, or validation alone does not "
            "resolve this intervention. Run one end-to-end test that carries a "
            "single amount through every listed locator and consumer, and "
            "assert its value and type at each boundary before completion."
        )
    if item.rule == "shared_assumption":
        return (
            "The shared unverified premise is the defect. Verify the claim "
            "against an independent authoritative source instead of reusing "
            "the cited assumption. Correct every affected source and consumer "
            "that differs, then run an end-to-end test before completion."
        )
    return (
        "The validator reused worker evidence instead of independent "
        "validation. Run a distinct check against the affected milestone and "
        "record new independent evidence. Correct any issue that check finds "
        "before completion."
    )


def _post_tool_response(
    item: InterventionRecord, finding: Finding | None = None
) -> Mapping[str, Any]:
    """Inject model-visible guidance after the target's tool call."""
    marker = _marker(item)
    guidance = (
        f"{marker} {item.rule} {item.level}: pause this path. "
        f"Repeat {marker} in your next response and state which source "
        f"you will inspect. {_required_correction(item)}"
        f"{_guidance_detail(finding)}"
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": guidance,
        }
    }



def _post_tool_note_response(finding: Finding) -> Mapping[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"[shadow:{_stable_id('note', finding.dedup_key)}] "
                f"Shadow review note ({finding.rule}): verify the direct "
                "evidence before relying on this result."
            ),
        }
    }


def _correction_required_response(item: InterventionRecord) -> Mapping[str, Any]:
    marker = _marker(item)
    return {
        "decision": "block",
        "reason": (
            f"{marker} do not stop after acknowledgment. "
            f"{_required_correction(item)}"
        ),
    }


def _block_response(item: InterventionRecord | None) -> Mapping[str, Any]:
    if item is None:
        return {}
    return {
        "decision": "block",
        "reason": (
            f"{_marker(item)} unresolved direct-evidence blocker has an "
            "authenticated confirmed probe; store correction evidence."
        ),
    }


def _repair_response(item: InterventionRecord) -> Mapping[str, Any]:
    return {
        "decision": "block",
        "reason": (
            f"{_marker(item)} create exactly one repair worker for original "
            f"feature {item.original_feature}."
        ),
    }


def _termination_response(item: InterventionRecord | None) -> Mapping[str, Any]:
    if item is None:
        return {}
    return {
        "decision": "block",
        "reason": f"{_marker(item)} mandatory Mission termination and failure.",
    }
