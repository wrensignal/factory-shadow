"""Production composition root for asynchronous Mission review."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import traceback
import re
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Callable, Iterable, Mapping, Sequence

from .extractor import (
    ApprovedMilestoneLink,
    ApprovedMissionCriterion,
    ApprovedRepositoryChange,
    ClaimExtractor,
    _edited_paths,
)
from .graph import GraphError, MissionGraph
from .probe import (
    DuplicateProbeError,
    ProbeJob,
    ProbeOutcome,
    ProbeQueueFullError,
    ProbeScheduler,
    ProbeSnapshot,
    ProbeSnapshotError,
)
from .protocol import (
    ByteBoundedQueue,
    COMPLETION_EVENTS,
    EvidenceRecord,
    HookEnvelope,
    HookExchangeRecord,
    HookRequest,
    QueueCapacityError,
    RepairAssignment,
    canonical_json,
    is_edit_tool,
    tool_observation_paths,
    tool_result_failed,
)
from .review_journal import (
    BoundaryDisabledRecord,
    ControllerDegradedRecord,
    ExchangeProjectionRecord,
    ExtractionOutcomeRecord,
    FindingSnapshotRecord,
    InterventionLineageRecord,
    OutageReconciliationRecord,
    JournalFinding,
    JournalProbeAssessment,
    ProbeCancellationRecord,
    ProbeJobRecord,
    ProbeSnapshotRejectionRecord,
    ProbeOutcomeRecord,
    ReviewJournal,
    ReviewJournalCorruptionError,
    ReviewJournalError,
    RoleDecisionRecord,
    TranscriptBatchRecord,
)
from .roles import (
    FrozenMissionRelations,
    MissionRelation,
    MissionRelations,
    RoleMapper,
)
from .router import InterventionRouter, InterventionRouterDelta
from .rules import (
    DeliverySelector,
    DeliverySelectorState,
    DeterministicRules,
    Finding,
    ProbeAssessment,
    RuleEvaluation,
    RiskCategory,
    normalize_locator,
)
from .storage import EventLedger, ResponsePlan, review_state_component
from .redaction import sanitize_value
from .transcript import TranscriptError, TranscriptObservation, TranscriptReader

MAX_REVIEW_QUEUE_ITEMS = 256
MAX_REVIEW_QUEUE_BYTES = 16 << 20
MAX_EPHEMERAL_CONTEXT_ITEMS = 1_000
MAX_EPHEMERAL_CONTEXT_BYTES = 2 << 20
_MAX_RAW_PATH_BYTES = 16 << 10
_MAX_OBSERVED_REPOSITORY_CHANGES = 4_096
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REVIEW_PENDING_MARKER = "[shadow:review-pending]"
_REVIEW_PENDING_REASON = (
    f"{_REVIEW_PENDING_MARKER} Recent Mission changes are still under review. "
    "Continue once, then retry completion after Shadow finishes the pending review."
)
# One target gets exactly one bounded completion deferral, for a pending review
# or for guidance that is queued but not yet delivered to it.
# Late cross-worker conflicts route to the sole orchestrator, so the
# orchestrator's completion must wait for its own pending review as well.
_DEFERRABLE_ROLES = frozenset({"worker", "orchestrator"})
# These reasons describe expected Mission input or an unanchored claim.
# Every other extraction rejection is a Shadow boundary failure.
_EXPECTED_EXTRACTION_QUARANTINE_REASONS = frozenset(
    {
        "criterion_mismatch",
        "transcript_unavailable",
        "unanchored_locator",
        "untrusted_provenance",
    }
)


def _extraction_rejection_status(reason: str) -> str:
    if reason in _EXPECTED_EXTRACTION_QUARANTINE_REASONS:
        return "quarantined"
    return "failed"


def _extraction_degradation_reason(
    outcome: ExtractionOutcomeRecord,
) -> str | None:
    if not outcome.trigger_kinds:
        return None
    if outcome.status == "failed":
        return "extraction_boundary_failed"
    return None


def _review_pending_body() -> dict[str, str]:
    return {"decision": "block", "reason": _REVIEW_PENDING_REASON}


def _is_review_pending_response(exchange: HookExchangeRecord) -> bool:
    """Recognize one durable deferral by its marker, never by exact prose."""

    try:
        body = json.loads(exchange.response.response_body)
    except (TypeError, ValueError):
        return False
    return (
        isinstance(body, Mapping)
        and body.get("decision") == "block"
        and str(body.get("reason", "")).startswith(_REVIEW_PENDING_MARKER)
    )


def _correction_source(kind: str, content: Mapping[str, object]) -> str:
    """Name the transcript surface that carried one correction record."""

    if kind == "diff" or (kind == "tool" and is_edit_tool(content.get("tool_name"))):
        return "target_diff_transcript"
    return "target_test_transcript"


class MissionReviewError(RuntimeError):
    """The production review controller failed closed."""


@dataclass(frozen=True)
class _RawTranscriptContext:
    event_id: str
    session_alias: str
    transcript_alias: str
    transcript_path: str
    encoded_size: int


@dataclass(frozen=True)
class _ProjectionItem:
    exchange: HookExchangeRecord
    raw_context: _RawTranscriptContext | None


@dataclass(frozen=True)
class _ProbeIdentity:
    ledger_sequence: int
    event_id: str
    probe_id: str
    finding_dedup_key: str
    snapshot_digest: str
    risk_category: RiskCategory


class MissionReviewController:
    """Serialize durable derivations while keeping model work off hook decisions."""

    def __init__(
        self,
        *,
        run_id: str,
        run_dir: Path,
        relations: MissionRelations,
        role_mapper: RoleMapper,
        transcript_reader: TranscriptReader,
        claim_extractor: ClaimExtractor,
        graph: MissionGraph,
        rules: DeterministicRules,
        probe_scheduler: ProbeScheduler,
        router: InterventionRouter,
        repository_root: Path | None = None,
        approved_criteria: Sequence[ApprovedMissionCriterion] = (),
        approved_milestone_links: Sequence[ApprovedMilestoneLink] = (),
        approved_repository_changes: Sequence[ApprovedRepositoryChange] = (),
        journal: ReviewJournal | None = None,
        max_queue_items: int = MAX_REVIEW_QUEUE_ITEMS,
        max_queue_bytes: int = MAX_REVIEW_QUEUE_BYTES,
        max_ephemeral_items: int = MAX_EPHEMERAL_CONTEXT_ITEMS,
        max_ephemeral_bytes: int = MAX_EPHEMERAL_CONTEXT_BYTES,
        probe_risk_classifier: Callable[[Finding], RiskCategory],
        probe_excerpts: Mapping[str, str] | None = None,
        probe_diffs: Mapping[str, str] | None = None,
        probe_test_results: Mapping[str, str] | None = None,
        probe_repository_paths: Mapping[str, str] | None = None,
        secret_canaries: Sequence[str] = (),
        original_features: Mapping[str, str] | None = None,
        repair_assignments: Callable[[], Iterable[RepairAssignment]] | None = None,
        cancelled_interventions: Callable[[], Iterable[str]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not run_id:
            raise ValueError("review run ID must not be empty")
        if max_ephemeral_items <= 0 or max_ephemeral_bytes <= 0:
            raise ValueError("ephemeral transcript bounds must be positive")
        if graph.run_id != run_id or router.run_id != run_id:
            raise ValueError("review dependencies belong to another run")
        if transcript_reader.run_id != run_id:
            raise ValueError("transcript reader belongs to another run")
        if role_mapper.relations.digest != relations.digest:
            raise ValueError("role mapper does not use the supplied Mission relations")
        if any(item.run_id != run_id for item in approved_criteria):
            raise ValueError("approved criterion belongs to another run")
        if any(item.run_id != run_id for item in approved_milestone_links):
            raise ValueError("approved milestone link belongs to another run")
        if any(item.run_id != run_id for item in approved_repository_changes):
            raise ValueError("approved repository change belongs to another run")

        root = (repository_root or Path.cwd()).resolve(strict=True)
        if not root.is_dir() or root.is_symlink():
            raise ValueError("probe repository root is invalid")
        self.run_id = run_id
        self.run_dir = run_dir.resolve()
        self.relations = relations
        self.role_mapper = role_mapper
        self.transcript_reader = transcript_reader
        self.claim_extractor = claim_extractor
        self.graph = graph
        self.rules = rules
        self.probe_scheduler = probe_scheduler
        self.router = router
        self.repository_root = root
        self.journal = journal or ReviewJournal(
            self.run_dir / "review.jsonl", run_id=run_id
        )
        self._approved_criteria = tuple(approved_criteria)
        self._approved_milestone_links = tuple(approved_milestone_links)
        self._approved_repository_changes = tuple(approved_repository_changes)
        self._observed_repository_changes: dict[str, ApprovedRepositoryChange] = {}
        if not callable(probe_risk_classifier):
            raise TypeError("probe risk classifier must be callable")
        if repair_assignments is not None and not callable(repair_assignments):
            raise TypeError("repair assignments must be provided by a callable")
        if cancelled_interventions is not None and not callable(cancelled_interventions):
            raise TypeError("intervention cancellations must be provided by a callable")
        self._probe_risk_classifier = probe_risk_classifier
        self._probe_excerpts = dict(probe_excerpts or {})
        self._probe_diffs = dict(probe_diffs or {})
        self._probe_test_results = dict(probe_test_results or {})
        self._probe_repository_paths = (
            None
            if probe_repository_paths is None
            else dict(probe_repository_paths)
        )
        self._secret_canaries = tuple(secret_canaries)
        self._original_features = MappingProxyType(dict(original_features or {}))
        self._repair_assignments = repair_assignments or (lambda: ())
        self._cancelled_interventions = cancelled_interventions or (lambda: ())
        self._clock = clock

        self._queue: ByteBoundedQueue[_ProjectionItem] = ByteBoundedQueue(
            max_items=max_queue_items,
            max_bytes=max_queue_bytes,
        )
        self._max_queue_items = max_queue_items
        self._max_queue_bytes = max_queue_bytes
        self._max_ephemeral_items = max_ephemeral_items
        self._max_ephemeral_bytes = max_ephemeral_bytes
        self._raw_contexts: dict[str, _RawTranscriptContext] = {}
        self._raw_context_bytes = 0
        self._pending_order: dict[int, tuple[_ProjectionItem, bytes]] = {}
        self._pending_order_bytes = 0
        self._next_intake_sequence = 1
        self._exchange_fingerprints: dict[str, tuple[int, str, str]] = {}
        self._enqueued_events: set[str] = set()
        self._latest_enqueued_by_session: dict[str, int] = {}
        self._latest_completed_by_session: dict[str, int] = {}

        self._evidence: dict[str, EvidenceRecord] = {}
        self._findings: tuple[Finding, ...] = ()
        self._findings_snapshot_available = False
        self._assessments: dict[str, ProbeAssessment] = {}
        self._cursor_offsets: dict[str, int] = {}
        self._known_probe_risks: set[str] = set()
        self._probe_jobs: dict[str, _ProbeIdentity] = {}
        self._completed_probe_risks: set[str] = set()
        self._boundary_disabled = False
        self._intervention_responses: set[str] = set()
        self._session_updates: dict[str, int] = {}
        self._completion_deferrals: set[str] = set()
        self._validation_overlap_status: str = "active"

        self._state_lock = threading.RLock()
        self._intake_lock = threading.Lock()
        self._drain_condition = threading.Condition()
        self._active_items = 0
        self._active_probe: _ProbeIdentity | None = None
        self._probe_window_reserved = False
        self._started = False
        self._closing = False
        self._worker: threading.Thread | None = None
        self._degraded_reason: str | None = None
        self._replayed = False
        self._journal_requires_replay = bool(self.journal.records())

    @classmethod
    def from_ledger(
        cls,
        ledger: EventLedger,
        **dependencies: object,
    ) -> "MissionReviewController":
        """Rebuild from the event ledger and journal, then attach post-fsync intake."""

        supplied_run_id = dependencies.pop("run_id", ledger.run_id)
        supplied_run_dir = dependencies.pop("run_dir", ledger.run_dir)
        if supplied_run_id != ledger.run_id:
            raise ValueError("review run differs from the event ledger")
        controller = cls(
            run_id=ledger.run_id,
            run_dir=Path(supplied_run_dir),
            **dependencies,
        )
        controller.replay(ledger.exchanges())
        ledger.add_after_append(controller.after_append)
        return controller

    @property
    def releasable(self) -> bool:
        with self._state_lock:
            return self._degraded_reason is None

    @property
    def non_releasable_reason(self) -> str | None:
        with self._state_lock:
            return self._degraded_reason

    @property
    def unresolved_intervention_ids(self) -> tuple[str, ...]:
        """Return interventions which have no resolved terminal outcome."""

        return tuple(
            item.intervention_id
            for item in self.router.snapshot().interventions
            if item.state not in {"resolved", "termination_acknowledged"}
        )

    @property
    def termination_required(self) -> bool:
        """Return whether an intervention reached terminal failure."""

        return any(
            item.state in {"expired", "quarantined"}
            for item in self.router.snapshot().interventions
        )

    @property
    def completion_blocked(self) -> bool:
        """Return whether an unresolved blocker prevents successful completion."""

        return any(
            item.level == "blocker"
            and item.state not in {"resolved", "termination_acknowledged"}
            for item in self.router.snapshot().interventions
        )

    @property
    def probe_boundary_disabled(self) -> bool:
        with self._state_lock:
            return self._boundary_disabled

    @property
    def pending_items(self) -> int:
        with self._intake_lock:
            return self._queue.item_count + len(self._pending_order)

    @property
    def pending_bytes(self) -> int:
        with self._intake_lock:
            return self._queue.byte_count + self._pending_order_bytes

    def _session_projection_pending(self, session_alias: str) -> bool:
        with self._intake_lock:
            return self._latest_enqueued_by_session.get(
                session_alias, 0
            ) > self._latest_completed_by_session.get(session_alias, 0)

    def findings(self) -> tuple[Finding, ...]:
        with self._state_lock:
            return self._findings

    def assessments(self) -> tuple[ProbeAssessment, ...]:
        with self._state_lock:
            return tuple(self._assessments[key] for key in sorted(self._assessments))

    def cursor_offsets(self) -> dict[str, int]:
        with self._state_lock:
            return dict(sorted(self._cursor_offsets.items()))

    def capture_request(self, request: HookRequest, envelope: HookEnvelope) -> None:
        """Hold an authenticated raw transcript path until its exact event commits."""

        if (
            request.run_id != self.run_id
            or envelope.run_id != self.run_id
            or request.event_id != envelope.event_id
            or request.hook_event_name != envelope.hook_event_name
            or request.observed_at != envelope.observed_at
        ):
            raise ValueError("raw transcript handoff does not bind the sanitized event")
        raw_path = request.transcript_path
        encoded_size = len(raw_path.encode("utf-8", errors="strict"))
        if encoded_size > _MAX_RAW_PATH_BYTES or "\x00" in raw_path:
            raise QueueCapacityError("raw transcript path exceeds its in-memory bound")
        context = _RawTranscriptContext(
            event_id=envelope.event_id,
            session_alias=envelope.session_alias,
            transcript_alias=envelope.transcript_alias,
            transcript_path=raw_path,
            encoded_size=encoded_size,
        )
        with self._intake_lock:
            prior = self._raw_contexts.get(envelope.event_id)
            if prior is not None:
                if prior != context:
                    self._mark_degraded("ephemeral_context_conflict")
                    raise MissionReviewError("event raw transcript context changed")
                return
            if (
                len(self._raw_contexts) >= self._max_ephemeral_items
                or self._raw_context_bytes + encoded_size > self._max_ephemeral_bytes
            ):
                self._mark_degraded("ephemeral_context_capacity")
                raise QueueCapacityError("ephemeral transcript context capacity exceeded")
            self._raw_contexts[envelope.event_id] = context
            self._raw_context_bytes += encoded_size

    def discard_request(self, event_id: str) -> None:
        """Discard a handoff when the ledger rejects it before durable append."""

        with self._intake_lock:
            context = self._raw_contexts.pop(event_id, None)
            if context is not None:
                self._raw_context_bytes -= context.encoded_size

    def _evaluate_cached_findings(
        self,
        *,
        updated_session: str,
        stored_update: int,
        repeatable_keys: frozenset[tuple[str, str]],
    ) -> RuleEvaluation:
        """Select delivery from the last immutable journaled finding snapshot."""

        matches = self._findings
        deliverable = matches
        validation_overlap_status = "active"
        if not self.rules._live_validation_overlap:
            validation_overlap_status = "disabled_by_role_fallback"
            deliverable = tuple(
                item for item in matches if item.rule != "validation_overlap"
            )
        deliveries, expected_state, next_state = self.rules._selector.plan(
            deliverable,
            updated_session=updated_session,
            stored_update=stored_update,
            repeatable_keys=repeatable_keys,
            graph=self.graph,
        )
        return RuleEvaluation(
            matches=matches,
            deliveries=deliveries,
            validation_overlap_status=validation_overlap_status,
            review_state=next_state.to_record(run_id=self.run_id),
            _commit=lambda: self.rules._selector.commit(
                expected_state,
                next_state,
            ),
        )


    def decide(self, envelope: HookEnvelope) -> ResponsePlan:
        """Plan one fast response from immutable, already-journaled snapshots only."""

        if envelope.run_id != self.run_id:
            raise ValueError("hook decision belongs to another run")
        pending_review = (
            envelope.hook_event_name in COMPLETION_EVENTS
            and self._session_projection_pending(envelope.session_alias)
        )
        assignments = tuple(self._repair_assignments())
        cancelled = tuple(self._cancelled_interventions())
        with self._state_lock:
            assessments = (
                tuple(self._assessments[key] for key in sorted(self._assessments))
                if self._degraded_reason is None
                else ()
            )
            evidence = tuple(self._evidence[key] for key in sorted(self._evidence))
            base_plan: ResponsePlan | None = None
            findings: tuple[Finding, ...] = ()
            selected_delivery_keys: tuple[tuple[str, str], ...] = ()
            if (
                self._degraded_reason is None
                and envelope.provenance_status
                in {"hook_authenticated", "untrusted_provenance"}
            ):
                prior_update = self._session_updates.get(envelope.session_alias, 0)
                stored_update = prior_update + 1
                repeatable_keys = self.router.repeatable_delivery_keys()
                evaluation = (
                    self._evaluate_cached_findings(
                        updated_session=envelope.session_alias,
                        stored_update=stored_update,
                        repeatable_keys=repeatable_keys,
                    )
                    if self._findings_snapshot_available
                    else self.rules.evaluate(
                        self.graph,
                        updated_session=envelope.session_alias,
                        stored_update=stored_update,
                        probes=assessments,
                        repeatable_keys=repeatable_keys,
                    )
                )
                if (
                    envelope.hook_event_name != "PostToolUse"
                    and evaluation.deliveries
                ):
                    (
                        _,
                        selector_expected,
                        selector_next,
                    ) = self.rules._selector.plan(
                        (),
                        updated_session=envelope.session_alias,
                        stored_update=stored_update,
                        graph=self.graph,
                    )
                    evaluation = replace(
                        evaluation,
                        deliveries=(),
                        review_state=selector_next.to_record(run_id=self.run_id),
                        _commit=lambda: self.rules._selector.commit(
                            selector_expected, selector_next
                        ),
                    )
                self._validation_overlap_status = (
                    evaluation.validation_overlap_status
                )
                findings = tuple(
                    item
                    for item in evaluation.matches
                    if evaluation.validation_overlap_status == "active"
                    or item.rule != "validation_overlap"
                )
                selected_delivery_keys = tuple(
                    (item.finding.dedup_key, item.target_session)
                    for item in evaluation.deliveries
                )

                def commit_evaluation() -> None:
                    with self._state_lock:
                        if (
                            self._session_updates.get(envelope.session_alias, 0)
                            != prior_update
                        ):
                            raise RuntimeError(
                                "controller session update changed before durable commit"
                            )
                        evaluation.commit()
                        self._session_updates[envelope.session_alias] = stored_update

                base_plan = replace(
                    evaluation.response_plan({}),
                    commit=commit_evaluation,
                )
            plan = self.router.plan_response(
                envelope,
                findings=findings,
                probes=assessments,
                stored_evidence=evidence,
                original_features=self._original_features,
                repair_assignments=assignments,
                cancelled_interventions=cancelled,
                selected_delivery_keys=selected_delivery_keys,
                base_plan=base_plan,
            )
            undelivered_guidance = self.router.undelivered_target_sessions(plan)
            should_defer_completion = (
                not plan.body
                and (
                    pending_review
                    or envelope.session_alias in undelivered_guidance
                )
                and self._degraded_reason is None
                and envelope.hook_event_name in COMPLETION_EVENTS
                and self.graph.role_for_session(envelope.session_alias)
                in _DEFERRABLE_ROLES
                and envelope.session_alias not in self._completion_deferrals
            )
        if not should_defer_completion:
            return plan

        def commit_completion_deferral() -> None:
            if plan.commit is not None:
                plan.commit()
            with self._state_lock:
                self._completion_deferrals.add(envelope.session_alias)

        return replace(
            plan,
            body=_review_pending_body(),
            commit=commit_completion_deferral,
        )

    def after_append(self, exchange: HookExchangeRecord) -> None:
        """Accept one committed ledger exchange without waiting for review work."""

        if exchange.envelope.run_id != self.run_id:
            self._mark_degraded("cross_run_exchange")
            raise MissionReviewError("committed exchange belongs to another run")
        fingerprint = (
            exchange.ledger_sequence,
            exchange.exchange_id,
            exchange.response.response_digest,
        )
        with self._intake_lock:
            prior = self._exchange_fingerprints.get(exchange.envelope.event_id)
            if prior is not None:
                if prior != fingerprint:
                    self._mark_degraded("exchange_identity_conflict")
                    raise MissionReviewError("committed exchange identity changed")
                self._discard_raw_locked(exchange.envelope.event_id)
                return
            for item, _ in self._pending_order.values():
                if item.exchange.envelope.event_id == exchange.envelope.event_id:
                    if self._fingerprint(item.exchange) != fingerprint:
                        self._mark_degraded("exchange_identity_conflict")
                        raise MissionReviewError("pending exchange identity changed")
                    return
            context = self._raw_contexts.get(exchange.envelope.event_id)
            encoded = self._projection_bytes(exchange)
            if context is not None:
                encoded += context.transcript_path.encode("utf-8")
            total_items = self._queue.item_count + len(self._pending_order)
            total_bytes = self._queue.byte_count + self._pending_order_bytes
            if total_items >= self._max_queue_items:
                self._mark_degraded("review_queue_items")
                raise QueueCapacityError("review projection item limit exceeded")
            if len(encoded) > self._max_queue_bytes or total_bytes + len(encoded) > self._max_queue_bytes:
                self._mark_degraded("review_queue_bytes")
                raise QueueCapacityError("review projection byte limit exceeded")
            context = self._raw_contexts.pop(exchange.envelope.event_id, None)
            if context is not None:
                self._raw_context_bytes -= context.encoded_size
            if exchange.ledger_sequence < self._next_intake_sequence:
                self._discard_raw_locked(exchange.envelope.event_id)
                return
            prior_sequence = self._pending_order.get(exchange.ledger_sequence)
            if prior_sequence is not None:
                if self._fingerprint(prior_sequence[0].exchange) != fingerprint:
                    self._mark_degraded("ledger_sequence_conflict")
                    raise MissionReviewError("ledger sequence contains two exchanges")
                return
            item = _ProjectionItem(exchange=exchange, raw_context=context)
            self._pending_order[exchange.ledger_sequence] = (item, encoded)
            self._pending_order_bytes += len(encoded)
            try:
                self._flush_ordered_locked()
            except Exception:
                self._mark_degraded("projection_enqueue")
                raise

    def replay(self, exchanges: Iterable[HookExchangeRecord]) -> None:
        """Rebuild graph and controller snapshots from both authoritative journals."""

        if self._started:
            raise MissionReviewError("cannot replay after the controller starts")
        ordered = tuple(exchanges)
        exchange_by_event: dict[str, HookExchangeRecord] = {}
        exchange_by_sequence: dict[int, HookExchangeRecord] = {}
        for expected, exchange in enumerate(ordered, start=1):
            if exchange.ledger_sequence != expected or exchange.envelope.run_id != self.run_id:
                raise ReviewJournalCorruptionError("event ledger sequence is invalid for review")
            if exchange.envelope.event_id in exchange_by_event:
                raise ReviewJournalCorruptionError("event ledger repeats a review event")
            exchange_by_event[exchange.envelope.event_id] = exchange
            exchange_by_sequence[expected] = exchange
        restored_selector = DeliverySelector.from_exchanges(ordered, run_id=self.run_id)
        current_selector = self.rules._selector.snapshot()
        restored_state = restored_selector.snapshot()
        if (
            current_selector != DeliverySelectorState()
            and current_selector != restored_state
        ):
            raise ReviewJournalCorruptionError(
                "supplied delivery selector diverges from the ledger"
            )
        self.rules._selector = restored_selector
        self._session_updates = dict(restored_state.last_updates)
        self._completion_deferrals = {
            exchange.envelope.session_alias
            for exchange in ordered
            if _is_review_pending_response(exchange)
        }


        event_record_types: dict[str, set[str]] = {}
        projected_sequences: list[int] = []
        outage_reconciled = False
        evidence_reconciled = False
        replay_extraction_degradation: tuple[str, int] | None = None
        replay_transcript_incomplete_at: int | None = None
        replayed_relations: dict[str, MissionRelation] = {}
        replayed_relations_digest = FrozenMissionRelations(
            self.relations.mission_id,
            (),
        ).digest
        final_relations_digest = self.relations.digest
        full_relations_seen = False
        for record in self.journal.records():
            if isinstance(record, ControllerDegradedRecord):
                self._degraded_reason = self._degraded_reason or record.reason
                continue
            if isinstance(record, OutageReconciliationRecord):
                evidence_error: BaseException | None = None
                if not evidence_reconciled:
                    try:
                        self.router.replay_evidence_reconciliation(
                            record.delta,
                            (
                                self._evidence[key]
                                for key in sorted(self._evidence)
                            ),
                            observed_at=record.observed_at,
                        )
                    except (TypeError, ValueError, RuntimeError) as error:
                        evidence_error = error
                    else:
                        evidence_reconciled = True
                        continue
                if evidence_reconciled or outage_reconciled:
                    raise ReviewJournalCorruptionError(
                        "review journal repeats final router reconciliation"
                    ) from evidence_error
                try:
                    self.router.replay_outage_reconciliation(record.delta)
                except (TypeError, ValueError, RuntimeError) as error:
                    raise ReviewJournalCorruptionError(
                        "final router reconciliation replay diverged"
                    ) from error
                outage_reconciled = True
                continue
            event_id = getattr(record, "event_id", None)
            ledger_sequence = getattr(record, "ledger_sequence", None)
            exchange = exchange_by_event.get(event_id)
            if (
                exchange is None
                or ledger_sequence != exchange.ledger_sequence
            ):
                raise ReviewJournalCorruptionError(
                    "derived record does not bind an event-ledger exchange"
                )
            event_record_types.setdefault(event_id, set()).add(record.record_type)
            if isinstance(record, ExchangeProjectionRecord):
                if (
                    record.exchange_id != exchange.exchange_id
                    or record.response_digest != exchange.response.response_digest
                ):
                    raise ReviewJournalCorruptionError(
                        "exchange projection binding differs from the ledger"
                    )
                projected_sequences.append(record.ledger_sequence)
                self.graph.add_exchange(exchange)
                self._exchange_fingerprints[event_id] = self._fingerprint(exchange)
            elif isinstance(record, RoleDecisionRecord):
                relation = self.relations.get(record.session_alias)
                if (
                    relation is not None
                    and relation.session_alias not in replayed_relations
                ):
                    replayed_relations[relation.session_alias] = relation
                    replayed_relations_digest = FrozenMissionRelations(
                        self.relations.mission_id,
                        tuple(replayed_relations.values()),
                    ).digest
                # Live relation sources can grow between decisions.
                # Frozen replay sources contain the final inventory.
                if record.relations_digest == final_relations_digest:
                    full_relations_seen = True
                elif (
                    full_relations_seen
                    or record.relations_digest != replayed_relations_digest
                ):
                    raise ReviewJournalCorruptionError(
                        "role decision relation inventory diverged"
                    )
                observed = self.role_mapper.observe(exchange.envelope)
                persisted = record.to_decision()
                if observed != persisted:
                    raise ReviewJournalCorruptionError("role decision replay diverged")
                self.graph.add_role_decision(persisted)
            elif isinstance(record, TranscriptBatchRecord):
                for evidence in record.evidence:
                    self.graph.add_evidence(evidence)
                    self._evidence[evidence.evidence_id] = evidence
                self._cursor_offsets[record.transcript_alias] = record.cursor_after
                if (
                    self.transcript_reader.mode == "primary"
                    and record.status in {"missing", "rejected"}
                    and exchange.envelope.hook_event_name
                    in COMPLETION_EVENTS | {"SessionEnd"}
                ):
                    replay_transcript_incomplete_at = (
                        replay_transcript_incomplete_at
                        if replay_transcript_incomplete_at is not None
                        else exchange.envelope.observed_at
                    )
            elif isinstance(record, ExtractionOutcomeRecord):
                self._derive_repository_changes(exchange.envelope)
                self._prime_extractor_classifier(exchange, record.trigger_kinds)
                replay_reason = _extraction_degradation_reason(record)
                if (
                    replay_extraction_degradation is None
                    and replay_reason is not None
                ):
                    replay_extraction_degradation = (
                        replay_reason,
                        exchange.envelope.observed_at,
                    )
                for evidence in record.derived_evidence:
                    self.graph.add_evidence(evidence)
                    self._evidence[evidence.evidence_id] = evidence
                for claim in record.claims:
                    self.graph.add_claim(claim)
            elif isinstance(record, FindingSnapshotRecord):
                if record.graph_digest != self.graph.digest():
                    raise ReviewJournalCorruptionError("finding graph snapshot diverged")
                self._findings = tuple(item.to_finding() for item in record.findings)
                self._validation_overlap_status = record.validation_overlap_status
                self._findings_snapshot_available = True
            elif isinstance(record, ProbeJobRecord):
                persisted_finding = self._finding_for_risk(record.finding_dedup_key)
                if self._classify_risk(persisted_finding) != record.risk_category:
                    raise ReviewJournalCorruptionError(
                        "probe risk category replay diverged"
                    )
                identity = _ProbeIdentity(
                    ledger_sequence=record.ledger_sequence,
                    event_id=record.event_id,
                    probe_id=record.probe_id,
                    finding_dedup_key=record.finding_dedup_key,
                    snapshot_digest=record.snapshot_digest,
                    risk_category=record.risk_category,
                )
                prior = self._probe_jobs.get(record.finding_dedup_key)
                if prior is not None and prior != identity:
                    raise ReviewJournalCorruptionError("probe risk has two durable jobs")
                self._probe_jobs[record.finding_dedup_key] = identity
                self._known_probe_risks.add(record.finding_dedup_key)
            elif isinstance(record, ProbeSnapshotRejectionRecord):
                persisted_finding = self._finding_for_risk(record.finding_dedup_key)
                if self._classify_risk(persisted_finding) != record.risk_category:
                    raise ReviewJournalCorruptionError(
                        "rejected probe risk category replay diverged"
                    )
                self._known_probe_risks.add(record.finding_dedup_key)
                self._completed_probe_risks.add(record.finding_dedup_key)
            elif isinstance(record, ProbeOutcomeRecord):
                identity = self._probe_jobs.get(record.finding_dedup_key)
                if identity is None or (
                    identity.probe_id != record.probe_id
                    or identity.snapshot_digest != record.snapshot_digest
                ):
                    raise ReviewJournalCorruptionError("probe outcome lacks its exact job")
                self._completed_probe_risks.add(record.finding_dedup_key)
                if record.assessment is not None:
                    assessment = record.assessment.to_assessment()
                    if assessment.risk_category != identity.risk_category:
                        raise ReviewJournalCorruptionError(
                            "probe outcome risk category differs from its job"
                        )
                    self._assessments[assessment.finding_dedup_key] = assessment
            elif isinstance(record, ProbeCancellationRecord):
                identity = self._probe_jobs.get(record.finding_dedup_key)
                if identity is None or identity.probe_id != record.probe_id:
                    raise ReviewJournalCorruptionError(
                        "probe cancellation lacks its job"
                    )
                self._completed_probe_risks.add(record.finding_dedup_key)
            elif isinstance(record, BoundaryDisabledRecord):
                boundary_digest = self._approved_probe_boundary_digest()
                if (
                    boundary_digest is None
                    or record.boundary_digest != boundary_digest
                ):
                    raise ReviewJournalCorruptionError(
                        "disabled probe boundary policy changed"
                    )
                self._boundary_disabled = True
            elif isinstance(record, InterventionLineageRecord):
                self._validate_intervention_lineage(exchange, record)
                self._intervention_responses.add(record.response_digest)

        for exchange in ordered:
            if (
                exchange.response.response_digest
                in self._intervention_responses
            ):
                continue
            self._journal_intervention_lineage(exchange)
            if (
                exchange.response.response_digest
                in self._intervention_responses
            ):
                event_record_types.setdefault(
                    exchange.envelope.event_id,
                    set(),
                ).add("intervention_lineage")
        replay_degradation = (
            ("transcript_incomplete", replay_transcript_incomplete_at)
            if replay_transcript_incomplete_at is not None
            else replay_extraction_degradation
        )
        if self._degraded_reason is None and replay_degradation is not None:
            reason, observed_at = replay_degradation
            self._mark_degraded(reason, observed_at=observed_at)


        if projected_sequences != list(range(1, len(projected_sequences) + 1)):
            raise ReviewJournalCorruptionError(
                "exchange projections are not a contiguous ledger prefix"
            )
        self._next_intake_sequence = len(projected_sequences) + 1
        with self._intake_lock:
            for exchange in ordered[: len(projected_sequences)]:
                if exchange.envelope.hook_event_name != "PostToolUse":
                    continue
                session_alias = exchange.envelope.session_alias
                self._latest_enqueued_by_session[session_alias] = (
                    exchange.ledger_sequence
                )
                self._latest_completed_by_session[session_alias] = (
                    exchange.ledger_sequence
                )
        self._replayed = True

        for risk in sorted(self._known_probe_risks - self._completed_probe_risks):
            identity = self._probe_jobs[risk]
            self.journal.append(
                "probe_cancellation",
                ledger_sequence=identity.ledger_sequence,
                event_id=identity.event_id,
                probe_id=identity.probe_id,
                finding_dedup_key=identity.finding_dedup_key,
                snapshot_digest=identity.snapshot_digest,
                reason="restart_pending",
            )
            self._completed_probe_risks.add(risk)

        required = {
            "exchange_projection",
            "role_decision",
            "transcript_batch",
            "extraction_outcome",
            "finding_snapshot",
        }
        for exchange in ordered[: len(projected_sequences)]:
            present = event_record_types.get(exchange.envelope.event_id, set())
            if "transcript_batch" not in present and self.transcript_reader.mode == "primary":
                self._mark_degraded(
                    "missing_ephemeral_context_replay",
                    observed_at=exchange.envelope.observed_at,
                )
                continue
            if not required <= present:
                self._enqueue_resume(exchange)
        for exchange in ordered[len(projected_sequences) :]:
            if self.transcript_reader.mode == "primary":
                self._mark_degraded(
                    "missing_ephemeral_context_replay",
                    observed_at=exchange.envelope.observed_at,
                )
                continue
            self.after_append(exchange)
        try:
            self._reconcile_findings(ordered[-1] if ordered else None)
        except (TypeError, ValueError) as error:
            raise ReviewJournalCorruptionError(
                "replayed findings or probe assessments diverged"
            ) from error

    def reconcile_final_outage(self) -> InterventionRouterDelta | None:
        """Commit final outage and post-drain evidence transitions durably."""

        observed_at = int(self._clock())

        def persist(delta: InterventionRouterDelta) -> None:
            self.journal.append(
                "outage_reconciliation",
                observed_at=observed_at,
                delta=delta,
            )

        try:
            outage_delta = self.router.reconcile_final_outage(persist)
            with self._state_lock:
                evidence = tuple(
                    self._evidence[key] for key in sorted(self._evidence)
                )
            evidence_delta = self.router.reconcile_evidence(
                evidence,
                persist,
                observed_at=observed_at,
            )
            return evidence_delta or outage_delta
        except Exception as error:
            self._mark_degraded("final_outage_reconciliation")
            raise MissionReviewError(
                "final router reconciliation failed"
            ) from error

    def start(self) -> None:
        if self._started:
            raise MissionReviewError("review controller already started")
        if self._closing:
            raise MissionReviewError("review controller is closed")
        if self._journal_requires_replay and not self._replayed:
            raise MissionReviewError(
                "existing review journal must be replayed before start"
            )
        self._started = True
        self._worker = threading.Thread(
            target=self._worker_loop,
            name=f"shadow-review-{self.run_id[:12]}",
            daemon=True,
        )
        self._worker.start()

    def drain(self, *, timeout: float = 5.0) -> bool:
        """Wait until projection work is done, excluding one active probe."""

        if timeout < 0:
            raise ValueError("drain timeout must not be negative")
        deadline = time.monotonic() + timeout
        with self._drain_condition:
            while True:
                with self._intake_lock:
                    pending = self._queue.item_count + len(self._pending_order)
                probe_only = (
                    pending == 0
                    and self._active_items == 1
                    and self._active_probe is not None
                )
                if (
                    pending == 0
                    and self._active_items == 0
                    and self._active_probe is None
                ) or probe_only:
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._drain_condition.wait(min(remaining, 0.05))

    def stop(self, *, timeout: float = 5.0) -> bool:
        """Bound shutdown and acknowledge both internal session boundaries."""

        if timeout < 0:
            raise ValueError("stop timeout must not be negative")
        deadline = time.monotonic() + timeout
        with self._drain_condition:
            with self._intake_lock:
                pending = self._queue.item_count + len(self._pending_order)
            active = self._active_probe
            probe_only = (
                pending == 0
                and self._active_items == 1
                and active is not None
            )
            self._closing = True

        extraction_aborted = self._abort_extraction_boundary(
            max(0.0, deadline - time.monotonic())
        )
        probe_aborted = self._abort_probe_boundary(
            max(0.0, deadline - time.monotonic())
        )
        boundaries_stopped = extraction_aborted and probe_aborted
        if not extraction_aborted:
            self._mark_degraded("extraction_shutdown_cancellation")
        if not probe_aborted:
            self._mark_degraded("probe_shutdown_cancellation")

        if probe_only and probe_aborted:
            assert active is not None
            try:
                self._append_probe_cancellation(
                    active, "probe_pending_at_completion"
                )
            except Exception:
                self._mark_degraded("probe_completion_cancellation")
                boundaries_stopped = False

        drained = self.drain(timeout=max(0.0, deadline - time.monotonic()))
        if not drained:
            active = self._active_probe
            if (
                probe_aborted
                and active is not None
                and active.finding_dedup_key not in self._completed_probe_risks
            ):
                try:
                    self._append_probe_cancellation(active, "shutdown_timeout")
                except Exception:
                    pass
            self._mark_degraded("shutdown_timeout")

        worker = self._worker
        if worker is not None:
            worker.join(max(0.0, deadline - time.monotonic()))
            if worker.is_alive():
                self._mark_degraded("shutdown_timeout")
                drained = False
        worker_stopped = worker is None or not worker.is_alive()
        if worker_stopped:
            try:
                self.transcript_reader.close()
            except Exception:
                self._mark_degraded("transcript_close")
                drained = False
        with self._intake_lock:
            self._raw_contexts.clear()
            self._raw_context_bytes = 0
            self._pending_order.clear()
            self._pending_order_bytes = 0
        return (
            boundaries_stopped
            and drained
            and worker_stopped
            and self.releasable
        )

    def _worker_loop(self) -> None:
        while True:
            if self._closing and self._queue.item_count == 0:
                return
            try:
                item = self._queue.get(timeout=0.05)
            except TimeoutError:
                continue
            with self._drain_condition:
                self._active_items += 1
            try:
                self._process_exchange(item)
            except BaseException as error:
                self._record_controller_failure(item, error)
                if isinstance(error, ReviewJournalError):
                    self._mark_degraded("journal_projection")
                else:
                    self._mark_degraded(f"projection_{type(error).__name__}")
            finally:
                if item.exchange.envelope.hook_event_name == "PostToolUse":
                    with self._intake_lock:
                        session_alias = item.exchange.envelope.session_alias
                        self._latest_completed_by_session[session_alias] = max(
                            item.exchange.ledger_sequence,
                            self._latest_completed_by_session.get(session_alias, 0),
                        )
                with self._drain_condition:
                    self._active_items -= 1
                    self._drain_condition.notify_all()

    def _record_controller_failure(
        self, item: _ProjectionItem, error: BaseException
    ) -> None:
        """Persist why review stopped. A degrade reason alone is not diagnosable."""

        try:
            detail = {
                "event_id": item.exchange.envelope.event_id,
                "ledger_sequence": item.exchange.ledger_sequence,
                "hook_event_name": item.exchange.envelope.hook_event_name,
                "error_type": type(error).__name__,
                "error": str(error),
                "traceback": "".join(
                    traceback.format_exception(type(error), error, error.__traceback__)
                ),
            }
            redacted, _ = sanitize_value(
                detail,
                forbidden_values=self._secret_canaries,
            )
            if not isinstance(redacted, Mapping):
                return
            bounded = dict(redacted)
            bounded["error"] = str(bounded.get("error", ""))[:2048]
            bounded["traceback"] = str(bounded.get("traceback", ""))[-4096:]
            line = canonical_json(
                {"observed_at": int(time.time()), **bounded}
            ) + b"\n"
            path = self.run_dir / "controller-failures.jsonl"
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                os.write(descriptor, line)
            finally:
                os.close(descriptor)
        except BaseException:
            return

    def _process_exchange(self, item: _ProjectionItem) -> None:
        with self._state_lock:
            if self._degraded_reason is not None:
                raise MissionReviewError(
                    "review controller is already degraded"
                )
        exchange = item.exchange
        envelope = exchange.envelope
        self._journal_intervention_lineage(exchange)
        record_types = self._record_types_for_event(envelope.event_id)
        if "exchange_projection" not in record_types:
            self.journal.append(
                "exchange_projection",
                ledger_sequence=exchange.ledger_sequence,
                event_id=envelope.event_id,
                exchange_id=exchange.exchange_id,
                response_digest=exchange.response.response_digest,
            )
            with self._state_lock:
                self.graph.add_exchange(exchange)
            self._exchange_fingerprints[envelope.event_id] = self._fingerprint(exchange)

        if "role_decision" not in record_types:
            decision = self.role_mapper.observe(envelope)
            self.journal.append(
                "role_decision",
                ledger_sequence=exchange.ledger_sequence,
                event_id=envelope.event_id,
                relations_digest=self.relations.digest,
                **RoleDecisionRecord.decision_fields(decision),
            )
            with self._state_lock:
                self.graph.add_role_decision(decision)
        self._derive_repository_changes(envelope)
        transcript_record = self._latest_event_record(
            envelope.event_id, TranscriptBatchRecord
        )
        if transcript_record is None:
            transcript_record = self._read_transcript(exchange, item.raw_context)
        # Bound evidence stays in the journal and graph for intervention routing.
        # Only source observations cross the extraction boundary.
        evidence = tuple(
            item
            for item in transcript_record.evidence
            if item.intervention_id is None
        )

        extraction_record = self._latest_event_record(
            envelope.event_id, ExtractionOutcomeRecord
        )
        if extraction_record is None:
            extraction_record = self._extract(
                exchange,
                evidence,
                transcript_available=transcript_record.status in {"read", "empty"},
            )

        if self._latest_event_record(envelope.event_id, FindingSnapshotRecord) is None:
            self._publish_findings(exchange)
        else:
            self._reconcile_findings(exchange)
        with self._intake_lock:
            projections_drained = (
                self._queue.item_count == 0
                and not self._pending_order
            )
        if projections_drained:
            self._schedule_probes(exchange)

    def _read_transcript(
        self,
        exchange: HookExchangeRecord,
        raw: _RawTranscriptContext | None,
    ) -> TranscriptBatchRecord:
        envelope = exchange.envelope
        cursor_before = self._cursor_offsets.get(envelope.transcript_alias, 0)
        observations: tuple[TranscriptObservation, ...] = ()
        status: str
        reason = "none"
        dropped_before = self.transcript_reader.dropped_records().get(
            envelope.transcript_alias, 0
        )
        try:
            if self.transcript_reader.mode == "primary":
                if raw is None or not raw.transcript_path:
                    self._mark_degraded("missing_ephemeral_context")
                    raise MissionReviewError(
                        "primary transcript context is unavailable"
                    )
                elif (
                    raw.event_id != envelope.event_id
                    or raw.session_alias != envelope.session_alias
                    or raw.transcript_alias != envelope.transcript_alias
                ):
                    status, reason = "rejected", "transcript_rejected"
                else:
                    observations = self.transcript_reader.read_primary(
                        envelope.session_alias,
                        envelope.transcript_alias,
                        Path(raw.transcript_path),
                    )
                    observations = tuple(
                        observation
                        for observation in observations
                        if self._evidence_end(observation.evidence) > cursor_before
                    )
                    status = "read" if observations else "empty"
                    if (
                        self.transcript_reader.dropped_records().get(
                            envelope.transcript_alias, 0
                        )
                        > dropped_before
                    ):
                        status, reason = "rejected", "transcript_rejected"
            elif self.transcript_reader.fallback_semantic_equivalence:
                observations = self.transcript_reader.read_fallback(envelope)
                status = "read" if observations else "empty"
            else:
                status, reason = "rejected", "fallback_disabled"
        except (OSError, TranscriptError, ValueError):
            observations = ()
            status, reason = "rejected", "transcript_rejected"
        if (
            self.transcript_reader.mode == "primary"
            and status == "rejected"
            and envelope.hook_event_name in COMPLETION_EVENTS | {"SessionEnd"}
        ):
            self._mark_degraded("transcript_incomplete")
        bound_evidence = self._bind_transcript_interventions(
            exchange,
            observations,
        )
        persisted_evidence = (
            tuple(item.evidence for item in observations) + bound_evidence
        )

        reader_offsets = self.transcript_reader.cursor_offsets()
        cursor_after = max(cursor_before, reader_offsets.get(envelope.transcript_alias, 0))
        record = self.journal.append(
            "transcript_batch",
            ledger_sequence=exchange.ledger_sequence,
            event_id=envelope.event_id,
            session_alias=envelope.session_alias,
            transcript_alias=envelope.transcript_alias,
            cursor_before=cursor_before,
            cursor_after=cursor_after,
            status=status,
            failure_reason=reason,
            evidence=persisted_evidence,
        )
        assert isinstance(record, TranscriptBatchRecord)
        with self._state_lock:
            for evidence_record in persisted_evidence:
                self.graph.add_evidence(evidence_record)
                self._evidence[evidence_record.evidence_id] = evidence_record
            self._cursor_offsets[envelope.transcript_alias] = cursor_after
        return record

    def _bind_transcript_interventions(
        self,
        exchange: HookExchangeRecord,
        observations: Sequence[TranscriptObservation],
    ) -> tuple[EvidenceRecord, ...]:
        """Bind ephemeral transcript signals to one durable intervention identity."""

        envelope = exchange.envelope
        current_transitions = frozenset(exchange.response.transition_ids)
        interventions = self.router.snapshot().interventions
        by_id = {item.intervention_id: item for item in interventions}
        bound: list[EvidenceRecord] = []
        for observation in observations:
            if len(observation.shadow_marker_ids) != 1:
                continue
            intervention = by_id.get(observation.shadow_marker_ids[0])
            if intervention is None:
                continue
            active_session = (
                intervention.repair_assignment.worker_session
                if intervention.repair_assignment is not None
                else intervention.target_session
            )
            guidance_action = (
                "repair_guidance_delivered"
                if intervention.repair_assignment is not None
                else "delivered"
            )
            guidance_transition = next(
                (
                    transition
                    for transition in reversed(intervention.transition_history)
                    if transition.action == guidance_action
                ),
                None,
            )
            evidence_ok = observation.evidence.provenance_status in {
                "hook_authenticated",
                "collector_observed",
            }
            if (
                observation.evidence.kind != "assistant"
                or not evidence_ok
                or observation.evidence.session_alias != active_session
                or envelope.session_alias != active_session
                or intervention.state not in {"delivered", "repair_assigned"}
                or guidance_transition is None
                or guidance_transition.transition_id in current_transitions
            ):
                continue
            bound.append(
                self._intervention_evidence(
                    observation.evidence,
                    intervention.intervention_id,
                    kind="target_acknowledgment",
                    source="target_assistant_transcript",
                    observed_at=envelope.observed_at,
                )
            )

        # A correction may land in a different worker's session than the one the
        # guidance reached. Proof binds through the finding, not the session.
        correction_targets = tuple(
            item
            for item in interventions
            if item.state in {"delivered", "acknowledged", "repair_assigned"}
            and any(
                transition.action
                in {"delivered", "acknowledged", "repair_guidance_delivered"}
                and transition.transition_id not in current_transitions
                for transition in item.transition_history
            )
        )
        findings_by_key = {item.dedup_key: item for item in self._findings}
        for observation in (
            item for item in observations if item.correction_candidate
        ):
            evidence = observation.evidence
            if evidence.provenance_status not in {
                "hook_authenticated",
                "collector_observed",
            }:
                continue
            explicit_id = observation.content.get("intervention_id")
            explicit_id = explicit_id if type(explicit_id) is str else None
            matching_targets = ()
            if explicit_id is not None:
                matching_targets = tuple(
                    item
                    for item in correction_targets
                    if item.intervention_id == explicit_id
                )
            elif evidence.kind == "test" or (
                evidence.kind == "tool"
                and not is_edit_tool(observation.content.get("tool_name"))
            ):
                # A passing test proves the corrected tree still holds. A test
                # command names a runner, not the conflicting locator, so the
                # observing session must own the finding instead.
                matching_targets = tuple(
                    item
                    for item in correction_targets
                    if (
                        finding := findings_by_key.get(item.finding_dedup_key)
                    )
                    is not None
                    and envelope.session_alias in finding.target_sessions
                )
            elif evidence.kind in {"diff", "tool"}:
                changed = (
                    (observation.content.get("file"),)
                    if evidence.kind == "diff"
                    else tool_observation_paths(observation.content)
                )
                normalized_files = {
                    normalize_locator(item)
                    for item in self._repository_relative(changed)
                }
                if normalized_files:
                    matching_targets = tuple(
                        item
                        for item in correction_targets
                        if (
                            finding := findings_by_key.get(
                                item.finding_dedup_key
                            )
                        )
                        is not None
                        and normalized_files.intersection(
                            finding.normalized_locators
                        )
                    )
            for intervention in matching_targets:
                bound.append(
                    self._intervention_evidence(
                        evidence,
                        intervention.intervention_id,
                        kind="target_correction",
                        source=_correction_source(evidence.kind, observation.content),
                        observed_at=envelope.observed_at,
                    )
                )
        return tuple(bound)

    @staticmethod
    def _intervention_evidence(
        evidence: EvidenceRecord,
        intervention_id: str,
        *,
        kind: str,
        source: str,
        observed_at: int,
    ) -> EvidenceRecord:
        values = evidence.model_dump(mode="python")
        values.update(
            {
                "evidence_id": "evidence-" + hashlib.sha256(
                    f"{evidence.evidence_id}\0{kind}\0{intervention_id}".encode()
                ).hexdigest(),
                "kind": kind,
                "source": source,
                "intervention_id": intervention_id,
                "observed_at": observed_at,
            }
        )
        return EvidenceRecord.model_validate(values)

    def _extract(
        self,
        exchange: HookExchangeRecord,
        evidence: Sequence[EvidenceRecord],
        *,
        transcript_available: bool,
    ) -> ExtractionOutcomeRecord:
        envelope = exchange.envelope
        predicted_triggers = self._preview_extraction_triggers(exchange)
        if not transcript_available:
            triggers = self._observe_extraction_triggers(exchange)
            if triggers:
                reason = "transcript_unavailable"
                status = _extraction_rejection_status(reason)
            else:
                status, reason = "not_triggered", None
            claims, derived = (), ()
        else:
            try:
                outcome = self.claim_extractor.extract(
                    envelope,
                    evidence,
                    approved_criteria=self._approved_criteria,
                    approved_milestone_links=self._approved_milestone_links,
                    approved_repository_changes=self._repository_changes(envelope),
                )
                if not outcome.trigger_kinds:
                    status, reason = "not_triggered", None
                elif outcome.quarantine is not None:
                    reason = outcome.quarantine.reason
                    status = _extraction_rejection_status(reason)
                else:
                    status, reason = "accepted", None
                claims = outcome.claims if status == "accepted" else ()
                derived = outcome.derived_evidence if status == "accepted" else ()
                triggers = outcome.trigger_kinds
            except Exception:
                status, reason = "failed", "boundary_fault"
                claims, derived, triggers = (), (), predicted_triggers
        rejected_claims: list[tuple[str, str]] = []
        with self._state_lock:
            if status == "accepted":
                accepted_claims = []
                for item in derived:
                    self.graph.add_evidence(item)
                    self._evidence[item.evidence_id] = item
                for claim in claims:
                    try:
                        self.graph.add_claim(claim)
                    except GraphError as error:
                        rejected_claims.append((claim.claim_id, str(error)))
                    else:
                        accepted_claims.append(claim)
                claims = tuple(accepted_claims)
            record = self.journal.append(
                "extraction_outcome",
                ledger_sequence=exchange.ledger_sequence,
                event_id=envelope.event_id,
                trigger_kinds=triggers,
                status=status,
                quarantine_reason=reason,
                claims=claims,
                derived_evidence=derived,
            )
            assert isinstance(record, ExtractionOutcomeRecord)
        extraction_degradation = _extraction_degradation_reason(record)
        if extraction_degradation is not None:
            self._mark_degraded(extraction_degradation)
        # Accepted journal records cannot carry a quarantine reason.
        # Preserve rejected claim IDs in the durable degradation record instead.
        if rejected_claims:
            details = "__".join(
                f"{claim_id}_{failure}"
                for claim_id, failure in rejected_claims
            )
            self._mark_degraded(
                f"extraction_claim_quarantined_{details}",
                observed_at=envelope.observed_at,
            )
        return record

    def _publish_findings(self, exchange: HookExchangeRecord) -> tuple[Finding, ...]:
        with self._state_lock:
            assessments = tuple(
                self._assessments[key] for key in sorted(self._assessments)
            )
            findings = self.rules.detect(self.graph, probes=assessments)
            graph_digest = self.graph.digest()
            validation_overlap_status = self._validation_overlap_status
        record = self.journal.append(
            "finding_snapshot",
            ledger_sequence=exchange.ledger_sequence,
            event_id=exchange.envelope.event_id,
            graph_digest=graph_digest,
            findings=tuple(JournalFinding.from_finding(item) for item in findings),
            validation_overlap_status=validation_overlap_status,
        )
        assert isinstance(record, FindingSnapshotRecord)
        with self._state_lock:
            self._findings = findings
            self._findings_snapshot_available = True
        return findings

    def _reserve_probe_window(self) -> bool:
        with self._intake_lock:
            if (
                self._probe_window_reserved
                or self._closing
                or self._queue.item_count != 0
                or self._pending_order
            ):
                return False
            self._probe_window_reserved = True
            return True

    def _release_probe_window(self) -> None:
        with self._intake_lock:
            self._probe_window_reserved = False


    def _schedule_probes(self, exchange: HookExchangeRecord) -> None:
        for finding in self.findings():
            risk = finding.dedup_key
            if (
                finding.level == "note"
                or risk in self._known_probe_risks
                or self._boundary_disabled
                or self._closing
                or (
                    finding.rule == "validation_overlap"
                    and self._validation_overlap_status
                    == "disabled_by_role_fallback"
                )
            ):
                continue
            category = self._classify_risk(finding)
            pending = replace(
                finding,
                risk_category=category,
                probe_status="pending",
            )
            try:
                snapshot = ProbeSnapshot.from_finding(
                    pending,
                    self.graph,
                    self.repository_root,
                    excerpts=self._probe_excerpts,
                    diffs=self._probe_diffs,
                    test_results=self._probe_test_results,
                    repository_paths=self._probe_repository_paths,
                    secret_canaries=self._secret_canaries,
                )
            except (OSError, ProbeSnapshotError, ValueError) as error:
                reason = str(error)
                if not re.fullmatch(r"[a-z0-9_]{1,64}", reason):
                    reason = "boundary_fault"
                record = self.journal.append(
                    "probe_snapshot_rejection",
                    ledger_sequence=exchange.ledger_sequence,
                    event_id=exchange.envelope.event_id,
                    finding_dedup_key=risk,
                    risk_category=category,
                    reason=reason,
                )
                assert isinstance(record, ProbeSnapshotRejectionRecord)
                self._known_probe_risks.add(risk)
                self._completed_probe_risks.add(risk)
                continue
            probe_id = "probe-" + hashlib.sha256(
                f"{self.run_id}\0{risk}\0{snapshot.digest}".encode()
            ).hexdigest()[:32]
            identity = _ProbeIdentity(
                ledger_sequence=exchange.ledger_sequence,
                event_id=exchange.envelope.event_id,
                probe_id=probe_id,
                finding_dedup_key=risk,
                snapshot_digest=snapshot.digest,
                risk_category=category,
            )
            if not self._reserve_probe_window():
                return
            try:
                self.journal.append(
                    "probe_job",
                    ledger_sequence=identity.ledger_sequence,
                    event_id=identity.event_id,
                    probe_id=identity.probe_id,
                    finding_dedup_key=identity.finding_dedup_key,
                    snapshot_digest=identity.snapshot_digest,
                    risk_category=identity.risk_category,
                    observed_at=exchange.envelope.observed_at,
                )
                self._known_probe_risks.add(risk)
                self._probe_jobs[risk] = identity
                job = ProbeJob(
                    snapshot=snapshot,
                    finding=pending,
                    probe_id=probe_id,
                    observed_at=exchange.envelope.observed_at,
                    graph=self.graph,
                    repository_root=self.repository_root,
                    excerpts=self._probe_excerpts,
                    diffs=self._probe_diffs,
                    test_results=self._probe_test_results,
                    repository_paths=self._probe_repository_paths,
                    secret_canaries=self._secret_canaries,
                )
                try:
                    self.probe_scheduler.enqueue(job)
                except (
                    DuplicateProbeError,
                    ProbeQueueFullError,
                    ProbeSnapshotError,
                    ValueError,
                ):
                    self._append_probe_cancellation(
                        identity,
                        "scheduler_rejected",
                    )
                    continue
                with self._drain_condition:
                    self._active_probe = identity
                try:
                    outcome = self.probe_scheduler.run_next()
                finally:
                    with self._drain_condition:
                        self._active_probe = None
                        self._drain_condition.notify_all()
                with self._state_lock:
                    cancelled_at_completion = (
                        identity.finding_dedup_key
                        in self._completed_probe_risks
                    )
                if cancelled_at_completion:
                    continue
                if outcome is None or outcome.snapshot_digest != snapshot.digest:
                    self._append_probe_cancellation(
                        identity,
                        "scheduler_rejected",
                    )
                    continue
                self._record_probe_outcome(exchange, identity, outcome)
            finally:
                self._release_probe_window()

    def _record_probe_outcome(
        self,
        exchange: HookExchangeRecord,
        identity: _ProbeIdentity,
        outcome: ProbeOutcome,
    ) -> None:
        if (
            outcome.assessment is not None
            and outcome.assessment.risk_category != identity.risk_category
        ):
            raise ValueError("probe outcome risk category changed")
        assessment = (
            JournalProbeAssessment.from_assessment(outcome.assessment)
            if outcome.assessment is not None
            else None
        )
        reason = (
            outcome.quarantine.reason
            if outcome.quarantine is not None
            else None
        )
        if reason == "unsafe_boundary":
            self._record_boundary_disabled(exchange)
        record = self.journal.append(
            "probe_outcome",
            ledger_sequence=identity.ledger_sequence,
            event_id=identity.event_id,
            probe_id=identity.probe_id,
            finding_dedup_key=identity.finding_dedup_key,
            snapshot_digest=identity.snapshot_digest,
            assessment=assessment,
            usage=outcome.usage,
            quarantine_reason=reason,
        )
        assert isinstance(record, ProbeOutcomeRecord)
        self._completed_probe_risks.add(identity.finding_dedup_key)
        if outcome.assessment is not None:
            with self._state_lock:
                candidate = dict(self._assessments)
                candidate[identity.finding_dedup_key] = outcome.assessment
                verified = self.rules.detect(
                    self.graph,
                    probes=tuple(candidate[key] for key in sorted(candidate)),
                )
                graph_digest = self.graph.digest()
                validation_overlap_status = self._validation_overlap_status
            self.journal.append(
                "finding_snapshot",
                ledger_sequence=exchange.ledger_sequence,
                event_id=exchange.envelope.event_id,
                graph_digest=graph_digest,
                findings=tuple(JournalFinding.from_finding(item) for item in verified),
                validation_overlap_status=validation_overlap_status,
            )
            with self._state_lock:
                self._assessments = candidate
                self._findings = verified
                self._findings_snapshot_available = True

    def _record_boundary_disabled(self, exchange: HookExchangeRecord) -> None:
        boundary_digest = self._approved_probe_boundary_digest()
        if boundary_digest is None:
            self._boundary_disabled = True
            raise MissionReviewError(
                "approved probe boundary policy digest is unavailable"
            )
        self.journal.append(
            "probe_boundary_disabled",
            ledger_sequence=exchange.ledger_sequence,
            event_id=exchange.envelope.event_id,
            boundary_digest=boundary_digest,
            stopped_at=exchange.envelope.observed_at,
        )
        self._boundary_disabled = True

    def _classify_risk(self, finding: Finding) -> RiskCategory:
        category = self._probe_risk_classifier(finding)
        if category not in {
            "none",
            "money",
            "security",
            "data_loss",
            "public_contract",
            "explicit_acceptance",
        }:
            raise ValueError("probe risk classifier returned an invalid category")
        return category

    def _finding_for_risk(self, risk: str) -> Finding:
        matches = tuple(item for item in self._findings if item.dedup_key == risk)
        if len(matches) != 1:
            raise ReviewJournalCorruptionError(
                "probe risk lacks one deterministic finding"
            )
        return matches[0]


    def _append_probe_cancellation(
        self,
        identity: _ProbeIdentity,
        reason: str,
    ) -> None:
        with self._state_lock:
            if identity.finding_dedup_key in self._completed_probe_risks:
                return
            self.journal.append(
                "probe_cancellation",
                ledger_sequence=identity.ledger_sequence,
                event_id=identity.event_id,
                probe_id=identity.probe_id,
                finding_dedup_key=identity.finding_dedup_key,
                snapshot_digest=identity.snapshot_digest,
                reason=reason,
            )
            self._completed_probe_risks.add(identity.finding_dedup_key)

    def _mark_enqueued(self, exchange: HookExchangeRecord) -> None:
        self._enqueued_events.add(exchange.envelope.event_id)
        if exchange.envelope.hook_event_name != "PostToolUse":
            return
        session_alias = exchange.envelope.session_alias
        self._latest_enqueued_by_session[session_alias] = max(
            exchange.ledger_sequence,
            self._latest_enqueued_by_session.get(session_alias, 0),
        )

    def _flush_ordered_locked(self) -> None:
        while self._next_intake_sequence in self._pending_order:
            item, encoded = self._pending_order.pop(self._next_intake_sequence)
            self._pending_order_bytes -= len(encoded)
            exchange = item.exchange
            try:
                self._queue.put(item, encoded)
            except Exception:
                self._pending_order[self._next_intake_sequence] = (item, encoded)
                self._pending_order_bytes += len(encoded)
                raise
            self._exchange_fingerprints[exchange.envelope.event_id] = self._fingerprint(
                exchange
            )
            self._mark_enqueued(exchange)
            self._next_intake_sequence += 1

    def _journal_intervention_lineage(self, exchange: HookExchangeRecord) -> None:
        review_state = exchange.response.review_state
        if review_state is None or exchange.response.response_digest in self._intervention_responses:
            return
        component = review_state_component(
            review_state,
            run_id=self.run_id,
            record_type="intervention_router_delta",
        )
        if component is None:
            return
        delta = InterventionRouterDelta.model_validate(component)
        record = self.journal.append(
            "intervention_lineage",
            ledger_sequence=exchange.ledger_sequence,
            event_id=exchange.envelope.event_id,
            response_digest=exchange.response.response_digest,
            delta=delta,
        )
        assert isinstance(record, InterventionLineageRecord)
        self._validate_intervention_lineage(exchange, record)
        self._intervention_responses.add(exchange.response.response_digest)

    def _enqueue_resume(self, exchange: HookExchangeRecord) -> None:
        if exchange.envelope.event_id in self._enqueued_events:
            return
        item = _ProjectionItem(exchange=exchange, raw_context=None)
        encoded = self._projection_bytes(exchange)
        self._queue.put(item, encoded)
        self._mark_enqueued(exchange)

    def _reconcile_findings(self, exchange: HookExchangeRecord | None) -> None:
        if exchange is None:
            return
        with self._state_lock:
            findings = self.rules.detect(
                self.graph,
                probes=tuple(
                    self._assessments[key] for key in sorted(self._assessments)
                ),
            )
            current = self._findings
        if findings != current:
            self._publish_findings(exchange)

    def _repository_relative(
        self, candidates: Sequence[object]
    ) -> tuple[str, ...]:
        """Return every candidate path as one contained repository-relative path.

        Factory records absolute paths, and a temporary repository root can
        reach the same tree through a symbolic link. Both forms must resolve
        to the exact locator that review rules and findings already cite.
        """

        roots = {PurePosixPath(str(self.repository_root)).parts}
        try:
            roots.add(PurePosixPath(str(self.repository_root.resolve())).parts)
        except OSError:
            pass
        relatives: list[str] = []
        for candidate in candidates:
            if type(candidate) is not str or not candidate.strip():
                continue
            text = candidate.strip()
            if text.startswith("$"):
                continue
            if text.startswith("/"):
                parts = PurePosixPath(text).parts
                relative = next(
                    (
                        "/".join(parts[len(root):])
                        for root in roots
                        if parts[: len(root)] == root
                    ),
                    "",
                )
            else:
                relative = text
            if not relative or ".." in PurePosixPath(relative).parts:
                continue
            if relative not in relatives:
                relatives.append(relative)
        return tuple(relatives)

    def _derive_repository_changes(self, envelope: HookEnvelope) -> None:
        """Record which repository paths one session edited.

        Claims must anchor to a locator that another session can also cite.
        Transcript spans are per session, so they can never collide. A
        repository-relative path is the shared locator the review rules need.
        The digest is a replayable identity, not a content attestation.
        """

        if len(self._observed_repository_changes) >= _MAX_OBSERVED_REPOSITORY_CHANGES:
            return
        if tool_result_failed(envelope.payload.get("tool_response")):
            return
        for relative in self._repository_relative(_edited_paths(envelope)):
            identity = {
                "run_id": self.run_id,
                "session_alias": envelope.session_alias,
                "event_id": envelope.event_id,
                "locator": relative,
            }
            digest = hashlib.sha256(canonical_json(identity)).hexdigest()
            change_id = f"change-{digest}"
            if change_id in self._observed_repository_changes:
                continue
            self._observed_repository_changes[change_id] = ApprovedRepositoryChange(
                run_id=self.run_id,
                session_alias=envelope.session_alias,
                event_id=envelope.event_id,
                change_id=change_id,
                locator=relative,
                digest=digest,
                observed_at=envelope.observed_at,
            )

    def _repository_changes(
        self, envelope: HookEnvelope
    ) -> tuple[ApprovedRepositoryChange, ...]:
        return tuple(
            item
            for item in (
                *self._approved_repository_changes,
                *self._observed_repository_changes.values(),
            )
            if item.run_id == self.run_id
            and item.session_alias == envelope.session_alias
            and item.observed_at <= envelope.observed_at
        )

    def _prime_extractor_classifier(
        self,
        exchange: HookExchangeRecord,
        persisted_triggers: tuple[str, ...],
    ) -> None:
        classifier = getattr(self.claim_extractor, "_classifier", None)
        if classifier is None or not callable(getattr(classifier, "observe", None)):
            raise ReviewJournalCorruptionError("extractor classifier cannot replay history")
        changes = self._repository_changes(exchange.envelope)
        observed = classifier.observe(
            exchange.envelope,
            repository_changes=changes,
        )
        if tuple(observed) != tuple(persisted_triggers):
            raise ReviewJournalCorruptionError("extraction trigger history diverged")

    def _observe_extraction_triggers(
        self, exchange: HookExchangeRecord
    ) -> tuple[str, ...]:
        classifier = getattr(self.claim_extractor, "_classifier", None)
        if classifier is None or not callable(getattr(classifier, "observe", None)):
            return ()
        changes = self._repository_changes(exchange.envelope)
        return tuple(
            classifier.observe(
                exchange.envelope,
                repository_changes=changes,
            )
        )

    def _preview_extraction_triggers(
        self, exchange: HookExchangeRecord
    ) -> tuple[str, ...]:
        classifier = getattr(self.claim_extractor, "_classifier", None)
        if classifier is None or not callable(getattr(classifier, "observe", None)):
            return ()
        changes = self._repository_changes(exchange.envelope)
        preview = copy.deepcopy(classifier)
        return tuple(
            preview.observe(
                exchange.envelope,
                repository_changes=changes,
            )
        )

    def _validate_intervention_lineage(
        self,
        exchange: HookExchangeRecord,
        record: InterventionLineageRecord,
    ) -> None:
        if record.response_digest != exchange.response.response_digest:
            raise ReviewJournalCorruptionError("intervention response digest differs")
        if exchange.response.review_state is None:
            raise ReviewJournalCorruptionError("intervention lineage lacks response state")
        component = review_state_component(
            exchange.response.review_state,
            run_id=self.run_id,
            record_type="intervention_router_delta",
        )
        if component is None or InterventionRouterDelta.model_validate(component) != record.delta:
            raise ReviewJournalCorruptionError("intervention lineage delta differs")

    def _record_types_for_event(self, event_id: str) -> set[str]:
        return {
            record.record_type
            for record in self.journal.records()
            if getattr(record, "event_id", None) == event_id
        }

    def _latest_event_record(self, event_id: str, model: type) -> object | None:
        for record in reversed(self.journal.records()):
            if isinstance(record, model) and getattr(record, "event_id", None) == event_id:
                return record
        return None

    def _mark_degraded(
        self,
        reason: str,
        *,
        observed_at: int | None = None,
    ) -> None:
        normalized = "".join(
            character if character.isalnum() or character in "_-" else "_"
            for character in reason
        )[:128] or "unknown"
        should_record = False
        with self._state_lock:
            if self._degraded_reason is None:
                self._degraded_reason = normalized
                should_record = True
        if should_record:
            try:
                self.journal.append(
                    "controller_degraded",
                    reason=normalized,
                    observed_at=(
                        int(self._clock()) if observed_at is None else observed_at
                    ),
                )
            except ReviewJournalError:
                pass

    @staticmethod
    def _bounded_abort(method: Callable[[], object], timeout: float) -> bool:
        result: list[object] = []
        completed = threading.Event()

        def invoke() -> None:
            try:
                result.append(method())
            except Exception:
                result.append(False)
            finally:
                completed.set()

        threading.Thread(
            target=invoke,
            name="shadow-boundary-abort",
            daemon=True,
        ).start()
        if not completed.wait(timeout):
            return False
        return result == [True]

    def _abort_extraction_boundary(self, timeout: float) -> bool:
        method = getattr(self.claim_extractor, "abort", None)
        if not callable(method):
            return False
        return self._bounded_abort(method, timeout)

    def _abort_probe_boundary(self, timeout: float) -> bool:
        method = getattr(self.probe_scheduler, "abort", None)
        if not callable(method):
            return False
        return self._bounded_abort(method, timeout)

    def _approved_probe_boundary_digest(self) -> str | None:
        runner = getattr(self.probe_scheduler, "_runner", None)
        value = getattr(runner, "_approved_boundary_policy_digest", None)
        return value if isinstance(value, str) and _DIGEST.fullmatch(value) else None

    def _discard_raw_locked(self, event_id: str) -> None:
        context = self._raw_contexts.pop(event_id, None)
        if context is not None:
            self._raw_context_bytes -= context.encoded_size

    @staticmethod
    def _fingerprint(exchange: HookExchangeRecord) -> tuple[int, str, str]:
        return (
            exchange.ledger_sequence,
            exchange.exchange_id,
            exchange.response.response_digest,
        )

    @staticmethod
    def _projection_bytes(exchange: HookExchangeRecord) -> bytes:
        return canonical_json(
            {
                "ledger_sequence": exchange.ledger_sequence,
                "exchange_id": exchange.exchange_id,
                "event_id": exchange.envelope.event_id,
                "response_digest": exchange.response.response_digest,
            }
        )

    @staticmethod
    def _evidence_end(record: EvidenceRecord) -> int:
        try:
            return int(record.locator.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return 0
