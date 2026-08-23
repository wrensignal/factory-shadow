"""Deterministic Mission graph derived from authoritative ledger records."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .evidence import EvidenceRegistryError, FrozenEvidenceRegistry
from .protocol import (
    ClaimRecord,
    EvidenceRecord,
    HookExchangeRecord,
    canonical_json,
)
from .roles import RoleDecision

_AUTHORITATIVE_EVIDENCE_SOURCES = {
    "repository_contract",
    "database_schema",
    "integration_test",
    "user_flow_test",
    "mission_criterion",
}


class GraphError(ValueError):
    """Graph source or projection is inconsistent."""


@dataclass(frozen=True, order=True)
class GraphEdge:
    source_kind: str
    source_id: str
    relation: str
    target_kind: str
    target_id: str

_MATERIAL_TARGET_KINDS = {
    "file": frozenset({"changed_file", "diff"}),
    "test": frozenset(
        {"test", "test_use", "unit_test", "integration_test", "user_flow_test"}
    ),
    "feature": frozenset({"feature_decision"}),
}

def _normalize_locator(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return " ".join(normalized.strip().split()).lower()

class MissionGraph:
    """Canonical nodes, edges, and review queries rebuilt from evidence."""

    def __init__(
        self,
        run_id: str,
        *,
        frozen_evidence_registry: FrozenEvidenceRegistry | None = None,
    ) -> None:
        if not run_id:
            raise ValueError("run_id must not be empty")
        self.run_id = run_id
        self._frozen_evidence_registry = frozen_evidence_registry
        self._nodes: dict[tuple[str, str], dict[str, Any]] = {}
        self._edges: set[GraphEdge] = set()
        self._claims: dict[str, ClaimRecord] = {}
        self._evidence: dict[str, EvidenceRecord] = {}
        self._session_roles: dict[str, str] = {}
        self._session_role_ids: dict[str, str] = {}
        self._quarantined_sessions: set[str] = set()
        self.upsert_node("mission", run_id, {"run_id": run_id})

    def upsert_node(
        self, kind: str, node_id: str, attributes: Mapping[str, Any]
    ) -> None:
        if not kind or not node_id:
            raise GraphError("graph node identity must not be empty")
        normalized = json.loads(canonical_json(dict(attributes)))
        key = (kind, node_id)
        prior = self._nodes.get(key)
        if prior is not None and prior != normalized:
            raise GraphError(f"graph node changed attributes: {kind}:{node_id}")
        self._nodes[key] = normalized

    def add_edge(
        self,
        source_kind: str,
        source_id: str,
        relation: str,
        target_kind: str,
        target_id: str,
    ) -> None:
        if (source_kind, source_id) not in self._nodes:
            raise GraphError("graph edge source does not exist")
        if (target_kind, target_id) not in self._nodes:
            raise GraphError("graph edge target does not exist")
        if not relation:
            raise GraphError("graph edge relation must not be empty")
        self._edges.add(
            GraphEdge(source_kind, source_id, relation, target_kind, target_id)
        )

    def add_exchange(self, exchange: HookExchangeRecord) -> None:
        if exchange.envelope.run_id != self.run_id:
            raise GraphError("exchange belongs to another run")
        session_alias = exchange.envelope.session_alias
        self.upsert_node(
            "session",
            session_alias,
            {"session_alias": session_alias},
        )
        self.add_edge("mission", self.run_id, "contains", "session", session_alias)
        self.upsert_node(
            "event",
            exchange.envelope.event_id,
            {
                "event_id": exchange.envelope.event_id,
                "hook_event_name": exchange.envelope.hook_event_name,
                "ledger_sequence": exchange.ledger_sequence,
                "provenance_status": exchange.envelope.provenance_status,
                "source_fingerprint": exchange.envelope.source_fingerprint,
            },
        )
        self.add_edge(
            "session", session_alias, "emitted", "event", exchange.envelope.event_id
        )
        if exchange.response.guidance_ids:
            for guidance_id in exchange.response.guidance_ids:
                self.upsert_node(
                    "guidance",
                    guidance_id,
                    {
                        "guidance_id": guidance_id,
                        "response_digest": exchange.response.response_digest,
                    },
                )
                self.add_edge(
                    "event",
                    exchange.envelope.event_id,
                    "delivered",
                    "guidance",
                    guidance_id,
                )

    def add_role_decision(self, decision: RoleDecision) -> None:
        if decision.status == "quarantined":
            self._quarantined_sessions.add(decision.session_alias)
            self._session_roles.pop(decision.session_alias, None)
            self._session_role_ids.pop(decision.session_alias, None)
            self._edges = {
                edge
                for edge in self._edges
                if not (
                    edge.source_kind == "session"
                    and edge.source_id == decision.session_alias
                    and edge.relation == "has_role"
                )
            }
            return
        if (
            decision.status != "assigned"
            or decision.confidence != "high"
            or decision.session_alias in self._quarantined_sessions
        ):
            return
        if decision.role_id is None:
            raise GraphError("assigned role lacks a role ID")
        self.upsert_node(
            "session",
            decision.session_alias,
            {"session_alias": decision.session_alias},
        )
        self.upsert_node(
            "role",
            decision.role_id,
            {"role_id": decision.role_id, "kind": decision.kind},
        )
        self.add_edge(
            "session", decision.session_alias, "has_role", "role", decision.role_id
        )
        self._session_roles[decision.session_alias] = decision.kind
        self._session_role_ids[decision.session_alias] = decision.role_id

    def add_feature(self, feature_id: str, attributes: Mapping[str, Any]) -> None:
        self.upsert_node("feature", feature_id, attributes)
        self.add_edge("mission", self.run_id, "tracks", "feature", feature_id)

    def add_milestone(self, milestone_id: str, attributes: Mapping[str, Any]) -> None:
        self.upsert_node("milestone", milestone_id, attributes)
        self.add_edge("mission", self.run_id, "tracks", "milestone", milestone_id)

    def add_file(self, locator: str) -> None:
        self.upsert_node("file", locator, {"locator": locator})

    def add_test(self, test_id: str, attributes: Mapping[str, Any]) -> None:
        self.upsert_node("test", test_id, attributes)

    def add_evidence(self, record: EvidenceRecord) -> None:
        if record.run_id != self.run_id:
            raise GraphError("evidence belongs to another run")
        if record.provenance_status == "independent_frozen":
            if self._frozen_evidence_registry is None:
                raise GraphError("independent frozen evidence lacks a registry")
            try:
                self._frozen_evidence_registry.verify(record)
            except EvidenceRegistryError as error:
                raise GraphError(
                    "independent frozen evidence binding is invalid"
                ) from error
        elif record.registry_digest is not None:
            raise GraphError("non-frozen evidence claims a frozen registry")
        prior = self._evidence.get(record.evidence_id)
        if prior is not None and prior != record:
            raise GraphError("evidence ID changed content")
        self._evidence[record.evidence_id] = record
        self.upsert_node(
            "session", record.session_alias, {"session_alias": record.session_alias}
        )
        self.upsert_node("evidence", record.evidence_id, record.model_dump(mode="json"))
        self.add_edge(
            "session", record.session_alias, "observed", "evidence", record.evidence_id
        )

    def add_claim(self, record: ClaimRecord) -> None:
        if record.run_id != self.run_id:
            raise GraphError("claim belongs to another run")
        if (
            record.provenance_status
            not in {
                "hook_authenticated",
                "independent_frozen",
                "collector_observed",
            }
            or record.redaction_status not in {"clean", "redacted"}
        ):
            raise GraphError("claim provenance is not trusted")
        missing = [
            evidence_id
            for evidence_id in record.evidence_ids
            if evidence_id not in self._evidence
        ]
        if missing:
            raise GraphError("claim references unknown evidence")
        cited = tuple(self._evidence[item] for item in record.evidence_ids)
        if record.provenance_status == "independent_frozen" and not any(
            item.provenance_status == "independent_frozen"
            and item.source in {"factory_observation", "factory_transcript"}
            for item in cited
        ):
            raise GraphError("claim lacks independent frozen evidence")
        if any(
            item.redaction_status not in {"clean", "redacted"}
            or item.session_alias != record.session_alias
            or not (
                (
                    item.provenance_status == record.provenance_status
                    and (
                        item.provenance_status != "independent_frozen"
                        or item.source
                        in {"factory_observation", "factory_transcript"}
                    )
                )
                or (
                    item.provenance_status == "authoritative_input"
                    and (
                        (
                            item.source == "mission_criterion"
                            and item.kind == "mission_criterion"
                        )
                        or (
                            item.source == "repository_change"
                            and item.kind == "changed_file"
                        )
                    )
                )
            )
            for item in cited
        ):
            raise GraphError("claim evidence provenance is not trusted")
        for target in record.targets:
            if target.evidence_id not in record.evidence_ids:
                raise GraphError("claim target references uncited evidence")
            target_evidence = self._evidence[target.evidence_id]
            if (
                _normalize_locator(target_evidence.locator)
                != _normalize_locator(target.target_id)
                or target_evidence.kind.strip().lower()
                not in _MATERIAL_TARGET_KINDS[target.kind]
            ):
                raise GraphError("claim target lacks matching material evidence")
            if target.kind == "file" and target.attributes:
                raise GraphError("file claim target cannot define attributes")
            target_id = _normalize_locator(target.target_id)
            key = (target.kind, target_id)
            if target.kind == "file":
                attributes = {"locator": target_id}
            else:
                attributes = target.attributes or {
                    f"{target.kind}_id": target_id
                }
            normalized = json.loads(canonical_json(attributes))
            prior_target = self._nodes.get(key)
            if prior_target is not None and prior_target != normalized:
                raise GraphError(
                    f"graph node changed attributes: {target.kind}:{target_id}"
                )
        prior = self._claims.get(record.claim_id)
        if prior is not None and prior != record:
            raise GraphError("claim ID changed content")
        self._claims[record.claim_id] = record
        self.upsert_node(
            "session", record.session_alias, {"session_alias": record.session_alias}
        )
        self.upsert_node("claim", record.claim_id, record.model_dump(mode="json"))
        self.add_edge(
            "session", record.session_alias, "asserted", "claim", record.claim_id
        )
        for evidence_id in record.evidence_ids:
            self.add_edge(
                "claim", record.claim_id, "supported_by", "evidence", evidence_id
            )
        for target in record.targets:
            target_id = _normalize_locator(target.target_id)
            if target.kind == "file":
                self.connect_claim_to_file(record.claim_id, target_id)
                continue
            key = (target.kind, target_id)
            if key not in self._nodes:
                attributes = target.attributes or {
                    f"{target.kind}_id": target_id
                }
                if target.kind == "test":
                    self.add_test(target_id, attributes)
                else:
                    self.add_feature(target_id, attributes)
            elif target.attributes:
                self.upsert_node(target.kind, target_id, target.attributes)
            if target.kind == "test":
                self.connect_claim_to_test(record.claim_id, target_id)
            else:
                self.connect_claim_to_feature(record.claim_id, target_id)
        for milestone_id in record.milestone_ids:
            if ("milestone", milestone_id) not in self._nodes:
                self.add_milestone(
                    milestone_id, {"milestone_id": milestone_id}
                )
            self.connect_claim_to_milestone(record.claim_id, milestone_id)

    def connect_claim_to_file(self, claim_id: str, file_locator: str) -> None:
        if claim_id not in self._claims:
            raise GraphError("unknown claim")
        self.add_file(file_locator)
        self.add_edge("claim", claim_id, "concerns", "file", file_locator)

    def connect_claim_to_feature(self, claim_id: str, feature_id: str) -> None:
        if claim_id not in self._claims:
            raise GraphError("unknown claim")
        self.add_edge("claim", claim_id, "affects", "feature", feature_id)

    def connect_claim_to_test(self, claim_id: str, test_id: str) -> None:
        if claim_id not in self._claims:
            raise GraphError("unknown claim")
        self.add_edge("claim", claim_id, "validated_by", "test", test_id)

    def connect_file_to_feature(self, file_locator: str, feature_id: str) -> None:
        self.add_edge("file", file_locator, "affects", "feature", feature_id)

    def connect_claim_to_milestone(self, claim_id: str, milestone_id: str) -> None:
        self.add_edge("claim", claim_id, "affects", "milestone", milestone_id)

    def claims_sharing(
        self, subject_locator: str, property_name: str, unit: str | None
    ) -> tuple[ClaimRecord, ...]:
        return tuple(
            sorted(
                (
                    claim
                    for claim in self._claims.values()
                    if claim.subject_locator == subject_locator
                    and claim.property == property_name
                    and claim.unit == unit
                ),
                key=lambda claim: claim.claim_id,
            )
        )

    def unsupported_matching_claims(self) -> tuple[tuple[str, ...], ...]:
        groups: dict[tuple[str, str, str | None, bytes], list[ClaimRecord]] = {}
        for claim in self._claims.values():
            evidence = [self._evidence[item] for item in claim.evidence_ids]
            if any(item.source in _AUTHORITATIVE_EVIDENCE_SOURCES for item in evidence):
                continue
            key = (
                claim.subject_locator,
                claim.property,
                claim.unit,
                canonical_json({"value": claim.value}),
            )
            groups.setdefault(key, []).append(claim)
        return tuple(
            sorted(
                tuple(sorted(claim.claim_id for claim in claims))
                for claims in groups.values()
                if len({claim.session_alias for claim in claims}) >= 2
            )
        )

    def worker_vs_validator_evidence(
        self, milestone_id: str
    ) -> dict[str, tuple[str, ...]]:
        affected_claims = {
            edge.source_id
            for edge in self._edges
            if edge.source_kind == "claim"
            and edge.relation == "affects"
            and edge.target_kind == "milestone"
            and edge.target_id == milestone_id
        }
        result: dict[str, set[str]] = {"worker": set(), "validator": set()}
        for claim_id in affected_claims:
            claim = self._claims[claim_id]
            role = self._session_roles.get(claim.session_alias)
            if role in result:
                result[role].update(claim.evidence_ids)
        return {name: tuple(sorted(values)) for name, values in result.items()}

    def claims(self) -> tuple[ClaimRecord, ...]:
        """Return every claim in stable identity order."""
        return tuple(sorted(self._claims.values(), key=lambda claim: claim.claim_id))

    def evidence_for_claim(self, claim_id: str) -> tuple[EvidenceRecord, ...]:
        """Return the evidence directly linked to one claim."""
        try:
            claim = self._claims[claim_id]
        except KeyError as error:
            raise GraphError("unknown claim") from error
        return tuple(self._evidence[item] for item in sorted(claim.evidence_ids))

    def role_for_session(self, session_alias: str) -> str | None:
        """Return the authoritative high-confidence role, when assigned."""
        return self._session_roles.get(session_alias)

    def role_id_for_session(self, session_alias: str) -> str | None:
        """Return the authoritative assigned role identity, when available."""
        return self._session_role_ids.get(session_alias)

    def sessions_for_role(self, role: str) -> tuple[str, ...]:
        """Return authoritative high-confidence sessions for one role."""
        return tuple(
            sorted(
                session_alias
                for session_alias, assigned_role in self._session_roles.items()
                if assigned_role == role
            )
        )


    def milestones(self) -> tuple[str, ...]:
        """Return milestone identities in stable order."""
        return tuple(
            node_id
            for kind, node_id in sorted(self._nodes)
            if kind == "milestone"
        )

    def claims_for_milestone(self, milestone_id: str) -> tuple[ClaimRecord, ...]:
        """Return claims explicitly connected to one milestone."""
        claim_ids = {
            edge.source_id
            for edge in self._edges
            if edge.source_kind == "claim"
            and edge.relation == "affects"
            and edge.target_kind == "milestone"
            and edge.target_id == milestone_id
        }
        return tuple(self._claims[item] for item in sorted(claim_ids))

    def claim_targets(self, claim_id: str) -> tuple[tuple[str, str], ...]:
        """Return explicit material dependency targets for one claim."""
        if claim_id not in self._claims:
            raise GraphError("unknown claim")
        material_kinds = {"file", "test", "feature"}
        return tuple(
            sorted(
                (edge.target_kind, edge.target_id)
                for edge in self._edges
                if edge.source_kind == "claim"
                and edge.source_id == claim_id
                and edge.target_kind in material_kinds
            )
        )


    def snapshot(self) -> dict[str, Any]:
        nodes = [
            {"kind": kind, "node_id": node_id, "attributes": attributes}
            for (kind, node_id), attributes in sorted(self._nodes.items())
        ]
        edges = [
            {
                "source_kind": edge.source_kind,
                "source_id": edge.source_id,
                "relation": edge.relation,
                "target_kind": edge.target_kind,
                "target_id": edge.target_id,
            }
            for edge in sorted(self._edges)
        ]
        return {"schema_version": "0.1", "run_id": self.run_id, "nodes": nodes, "edges": edges}

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.snapshot())).hexdigest()

    def persist(self, sqlite_path: Path) -> None:
        connection = sqlite3.connect(sqlite_path)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=2000")
            with connection:
                connection.execute("DELETE FROM graph_edges")
                connection.execute("DELETE FROM graph_nodes")
                connection.executemany(
                    "INSERT INTO graph_nodes(kind, node_id, attributes_json) VALUES (?, ?, ?)",
                    (
                        (kind, node_id, canonical_json(attributes).decode("utf-8"))
                        for (kind, node_id), attributes in sorted(self._nodes.items())
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO graph_edges(
                        source_kind, source_id, relation, target_kind, target_id
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            edge.source_kind,
                            edge.source_id,
                            edge.relation,
                            edge.target_kind,
                            edge.target_id,
                        )
                        for edge in sorted(self._edges)
                    ),
                )
        except sqlite3.Error as error:
            raise GraphError("graph persistence failed") from error
        finally:
            connection.close()


def load_exchanges_bytes(payload: bytes) -> tuple[HookExchangeRecord, ...]:
    """Replay one immutable canonical ledger snapshot."""

    records: list[HookExchangeRecord] = []
    expected_sequence = 1
    try:
        for line in payload.splitlines(keepends=True):
            if not line.endswith(b"\n"):
                raise GraphError("ledger has an incomplete record")
            body = line[:-1]
            value = json.loads(body)
            if canonical_json(value) != body:
                raise GraphError("ledger record is not canonical")
            record = HookExchangeRecord.model_validate(value)
            if record.ledger_sequence != expected_sequence:
                raise GraphError("ledger sequence is not contiguous")
            records.append(record)
            expected_sequence += 1
    except (json.JSONDecodeError, ValueError) as error:
        if isinstance(error, GraphError):
            raise
        raise GraphError("ledger graph source is invalid") from error
    return tuple(records)


def load_exchanges(ledger_path: Path) -> tuple[HookExchangeRecord, ...]:
    try:
        payload = ledger_path.read_bytes()
    except OSError as error:
        raise GraphError("ledger graph source is invalid") from error
    return load_exchanges_bytes(payload)


def rebuild_graph(
    *,
    run_id: str,
    ledger_path: Path,
    sqlite_path: Path,
    role_decisions: Iterable[RoleDecision] = (),
    evidence: Iterable[EvidenceRecord] = (),
    claims: Iterable[ClaimRecord] = (),
    frozen_evidence_registry: FrozenEvidenceRegistry | None = None,
) -> MissionGraph:
    graph = MissionGraph(
        run_id,
        frozen_evidence_registry=frozen_evidence_registry,
    )
    for exchange in load_exchanges(ledger_path):
        graph.add_exchange(exchange)
    for decision in role_decisions:
        graph.add_role_decision(decision)
    for record in evidence:
        graph.add_evidence(record)
    for record in claims:
        graph.add_claim(record)
    graph.persist(sqlite_path)
    return graph
