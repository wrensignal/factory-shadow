import hashlib
import json
import shutil
from pathlib import Path

import pytest
from shadow_mission.evidence import (
    EvidenceRegistryError,
    FrozenObservation,
    FrozenObservationRegistry,
)

from shadow_mission.feasibility import (
    CAPABILITY_NAMES,
    PROTECTED_TRANSITIONS,
    GateClassificationError,
    authorize_protected_transition,
    load_pinned_manifest_digest,
    classify_gate,
    verify_sealed_fixture,
)


NO_FALLBACK = {
    "run_transport_integrity",
    "independent_probe_boundary",
}


def all_pass() -> dict[str, str]:
    return {name: "pass" for name in CAPABILITY_NAMES}


def test_all_capabilities_pass_primary_gate() -> None:
    assert classify_gate(all_pass()) == "primary-pass"


def test_documented_semantic_fallbacks_pass() -> None:
    results = all_pass()
    results["live_transcript_access"] = "fallback"
    results["role_mapping"] = "fallback"
    results["stop_blocker_behavior"] = "fallback"

    assert classify_gate(results) == "fallback-pass"


@pytest.mark.parametrize("capability", CAPABILITY_NAMES)
def test_each_capability_has_an_explicit_fallback_disposition(
    capability: str,
) -> None:
    results = all_pass()
    results[capability] = "fallback"

    expected = "stop" if capability in NO_FALLBACK else "fallback-pass"
    assert classify_gate(results) == expected


def test_any_stop_wins_and_missing_rows_are_invalid() -> None:
    results = all_pass()
    results["targeted_guidance_routing"] = "stop"
    assert classify_gate(results) == "stop"

    results.pop("session_hooks")
    with pytest.raises(GateClassificationError, match="exact capability set"):
        classify_gate(results)

    results = all_pass()
    results["unexpected"] = "pass"
    with pytest.raises(GateClassificationError, match="exact capability set"):
        classify_gate(results)


@pytest.mark.parametrize("transition", PROTECTED_TRANSITIONS)
def test_untrusted_provenance_cannot_authorize_protected_transitions(
    transition: str,
) -> None:
    registry = FrozenObservationRegistry({}, source_digest="f" * 64)
    with pytest.raises(EvidenceRegistryError, match="nonempty"):
        authorize_protected_transition(
            registry=registry,
            provenance_status="untrusted_provenance",
            transition=transition,
            observation_ids=(),
            run_id="run-alpha",
            target_id="worker-alpha",
            risk_id="risk-alpha",
        )


def test_hook_hmac_is_integrity_only_for_protected_transitions() -> None:
    observation = FrozenObservation(
        observation_id="hook-identity",
        run_id="run-alpha",
        target_id="worker-alpha",
        risk_id="risk-alpha",
        transition="identity",
        kind="identity",
        status="identified",
        source_class="hook_authenticated",
    )
    registry = FrozenObservationRegistry(
        {"hook-identity": observation},
        source_digest="f" * 64,
    )
    authorize_protected_transition(
        registry=registry,
        provenance_status="hook_authenticated",
        transition="identity",
        observation_ids=("hook-identity",),
        run_id="run-alpha",
        target_id="worker-alpha",
        risk_id="risk-alpha",
    )
    with pytest.raises(EvidenceRegistryError, match="external frozen"):
        authorize_protected_transition(
            registry=registry,
            provenance_status="untrusted_provenance",
            transition="identity",
            observation_ids=("hook-identity",),
            run_id="run-alpha",
            target_id="worker-alpha",
            risk_id="risk-alpha",
        )


def test_fixture_hashes_and_source_sufficiency_are_independent() -> None:
    fixture = Path("tests/fixtures/feasibility")
    result = verify_sealed_fixture(
        fixture,
        expected_manifest_digest=load_pinned_manifest_digest(
            Path("tests/fixtures/feasibility-manifest.sha256")
        ),
    )

    assert result["sealed"] is True
    assert result["cross_worker_conflict_observed"] is True
    assert result["shared_assumption_observed"] is True
    assert result["production_rules_called"] is False


def test_external_manifest_pin_rejects_fixture_resealing(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    shutil.copytree(Path("tests/fixtures/feasibility"), fixture)
    observed_path = fixture / "observed-source.json"
    observed = json.loads(observed_path.read_text())
    observed["records"][0]["text"] += " changed"
    observed_path.write_text(json.dumps(observed))
    manifest_path = fixture / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["observed-source.json"] = hashlib.sha256(
        observed_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(GateClassificationError, match="external pin"):
        verify_sealed_fixture(
            fixture,
            expected_manifest_digest=load_pinned_manifest_digest(
                Path("tests/fixtures/feasibility-manifest.sha256")
            ),
        )


@pytest.mark.parametrize(
    ("oracle_path", "replacement"),
    [
        (("conflict", "worker_a_value"), "dollars"),
        (("controls", "worker_a_marker"), "DECOY-MARKER"),
        (("controls", "negative_marker"), "ROUTE-ALPHA-7319"),
        (("controls", "secret_canary"), "ROUTE-ALPHA-7319"),
    ],
)
def test_resealed_oracle_decoys_do_not_create_a_pass(
    tmp_path: Path,
    oracle_path: tuple[str, str],
    replacement: str,
) -> None:
    fixture = tmp_path / "fixture"
    shutil.copytree(Path("tests/fixtures/feasibility"), fixture)
    oracle_file = fixture / "oracle.json"
    oracle = json.loads(oracle_file.read_text())
    oracle[oracle_path[0]][oracle_path[1]] = replacement
    oracle_file.write_text(json.dumps(oracle))
    manifest_file = fixture / "manifest.json"
    manifest = json.loads(manifest_file.read_text())
    manifest["files"]["oracle.json"] = hashlib.sha256(
        oracle_file.read_bytes()
    ).hexdigest()
    manifest_file.write_text(json.dumps(manifest))
    resealed_digest = hashlib.sha256(manifest_file.read_bytes()).hexdigest()

    with pytest.raises(GateClassificationError):
        verify_sealed_fixture(
            fixture,
            expected_manifest_digest=resealed_digest,
        )
