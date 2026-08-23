from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Callable

import pytest

from ops import reseal_feasibility as reseal


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEALED_FIXTURE = PROJECT_ROOT / "tests/fixtures/feasibility"
SEALED_PIN = PROJECT_ROOT / "tests/fixtures/feasibility-manifest.sha256"
NOW = 2_000_000_000
STALE_GATE_SURFACE_DIGEST = "0" * 64
STALE_PLUGIN_ARTIFACT_DIGEST = "1" * 64


@dataclass(frozen=True)
class Workspace:
    root: Path
    fixture: Path
    pin: Path
    candidate: Path
    receipt: Path
    trust_anchor: Path


@dataclass(frozen=True)
class Signer:
    openssl: Path
    secret_key: Path
    public_key: Path


def _canonical(value: dict[str, Any]) -> bytes:
    return reseal.canonical_json(value) + b"\n"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_digests(fixture: Path, pin: Path) -> dict[str, str]:
    return {
        path.name: _digest(path)
        for path in sorted(fixture.iterdir())
    } | {"external-pin": _digest(pin)}


def _rewrite_fixture_bindings(
    fixture: Path,
    pin: Path,
    *,
    gate_surface_digest: str,
    installed_plugin_artifact_digest: str,
) -> None:
    profile_path = fixture / "factory-profile.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile.update(
        {
            "gate_surface_digest": gate_surface_digest,
            "installed_plugin_artifact_digest": installed_plugin_artifact_digest,
            "resolved_plugin_source": f"sha256:{installed_plugin_artifact_digest}",
        }
    )
    profile_path.write_bytes(_canonical(profile))

    manifest_path = fixture / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["factory-profile.json"] = _digest(profile_path)
    manifest_path.write_bytes(_canonical(manifest))
    pin.write_text(f"{_digest(manifest_path)}\n", encoding="ascii")

    for path in (profile_path, manifest_path, pin):
        os.chmod(path, 0o600)


def _make_workspace(tmp_path: Path) -> Workspace:
    os.chmod(tmp_path, 0o700)
    fixture = tmp_path / "fixture"
    shutil.copytree(SEALED_FIXTURE, fixture)
    os.chmod(fixture, 0o700)
    for path in fixture.iterdir():
        os.chmod(path, 0o600)
    pin = tmp_path / "fixture-manifest.sha256"
    shutil.copy2(SEALED_PIN, pin)
    _rewrite_fixture_bindings(
        fixture,
        pin,
        gate_surface_digest=STALE_GATE_SURFACE_DIGEST,
        installed_plugin_artifact_digest=STALE_PLUGIN_ARTIFACT_DIGEST,
    )

    receipt_parent = tmp_path / "receipts"
    receipt_parent.mkdir(mode=0o700)
    os.chmod(receipt_parent, 0o700)
    trust_parent = tmp_path / "trust"
    trust_parent.mkdir(mode=0o700)
    os.chmod(trust_parent, 0o700)
    return Workspace(
        root=tmp_path,
        fixture=fixture,
        pin=pin,
        candidate=tmp_path / "candidate",
        receipt=receipt_parent / "receipt.json",
        trust_anchor=trust_parent / "reseal-trusted-signers.sha256",
    )


def _generate_signer(
    root: Path,
    openssl: Path,
    *,
    algorithm: str = "ED25519",
) -> Signer:
    root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    secret_key = root / "operator-key.pem"
    public_key = root / "operator-public.pem"
    generated = subprocess.run(
        [str(openssl), "genpkey", "-algorithm", algorithm, "-out", str(secret_key)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr.decode("utf-8", "replace")
    exported = subprocess.run(
        [
            str(openssl),
            "pkey",
            "-in",
            str(secret_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert exported.returncode == 0, exported.stderr.decode("utf-8", "replace")
    os.chmod(secret_key, 0o600)
    os.chmod(public_key, 0o600)
    return Signer(openssl=openssl, secret_key=secret_key, public_key=public_key)


def _anchor_public_key(
    workspace: Workspace,
    public_key: Path,
    openssl: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace.trust_anchor.write_text(f"{_digest(public_key)}\n", encoding="ascii")
    os.chmod(workspace.trust_anchor, 0o600)
    monkeypatch.setattr(reseal, "_TRUSTED_SIGNERS_PATH", workspace.trust_anchor)
    monkeypatch.setattr(reseal, "_resolve_trusted_openssl", lambda: openssl)


def _prepare(workspace: Workspace, *, now: int = NOW) -> dict[str, Any]:
    return reseal.prepare_reseal(
        project_root=PROJECT_ROOT,
        fixture=workspace.fixture,
        fixture_manifest_pin=workspace.pin,
        candidate_dir=workspace.candidate,
        valid_for_seconds=3600,
        now=now,
    )


def _sign(signer: Signer, workspace: Workspace, name: str = "request.sig") -> Path:
    signature = workspace.root / name
    completed = subprocess.run(
        [
            str(signer.openssl),
            "pkeyutl",
            "-sign",
            "-inkey",
            str(signer.secret_key),
            "-rawin",
            "-in",
            str(workspace.candidate / "request.json"),
            "-out",
            str(signature),
        ],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    os.chmod(signature, 0o600)
    return signature


def _apply(
    workspace: Workspace,
    signer: Signer,
    signature: Path,
    *,
    receipt: Path | None = None,
) -> dict[str, Any]:
    return reseal.apply_reseal(
        project_root=PROJECT_ROOT,
        fixture=workspace.fixture,
        fixture_manifest_pin=workspace.pin,
        candidate_dir=workspace.candidate,
        signature=signature,
        trusted_public_key=signer.public_key,
        receipt=workspace.receipt if receipt is None else receipt,
    )


def _verify(
    workspace: Workspace,
    signer: Signer,
    signature: Path,
    *,
    receipt: Path | None = None,
) -> dict[str, Any]:
    return reseal.verify_reseal(
        project_root=PROJECT_ROOT,
        fixture=workspace.fixture,
        fixture_manifest_pin=workspace.pin,
        candidate_dir=workspace.candidate,
        signature=signature,
        trusted_public_key=signer.public_key,
        receipt=workspace.receipt if receipt is None else receipt,
    )


def _offline_pass(**_: Any) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "status": "offline-harness-pass",
        "checks": {"reseal-test": "pass"},
    }


def _rewrite_request(
    workspace: Workspace,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    request_path = workspace.candidate / "request.json"
    value = json.loads(request_path.read_text())
    mutate(value)
    request_path.write_bytes(_canonical(value))
    os.chmod(request_path, 0o600)


def _rewrite_receipt_with_valid_record_digest(
    workspace: Workspace,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    value = json.loads(workspace.receipt.read_text())
    mutate(value)
    material = dict(value)
    del material["record_digest"]
    value["record_digest"] = hashlib.sha256(
        reseal.canonical_json(material)
    ).hexdigest()
    workspace.receipt.write_bytes(_canonical(value))
    os.chmod(workspace.receipt, 0o644)


def _seed_prefix(workspace: Workspace, prefix: int) -> None:
    replacements = (
        (
            workspace.candidate / "factory-profile.json",
            workspace.fixture / "factory-profile.json",
        ),
        (
            workspace.candidate / "manifest.json",
            workspace.fixture / "manifest.json",
        ),
        (workspace.candidate / "manifest.sha256", workspace.pin),
    )
    for source, target in replacements[:prefix]:
        target.write_bytes(source.read_bytes())


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        reseal,
        "_now",
        lambda value: NOW if value is None else value,
    )


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Workspace:
    value = _make_workspace(tmp_path)
    monkeypatch.setattr(reseal, "_CANONICAL_FIXTURE", value.fixture)
    monkeypatch.setattr(reseal, "_CANONICAL_PIN", value.pin)
    return value


@pytest.fixture(scope="module")
def signer(tmp_path_factory: pytest.TempPathFactory) -> Signer:
    try:
        openssl = reseal._resolve_trusted_openssl()
    except reseal.ResealError:
        pytest.skip("trusted OpenSSL is unavailable")
    try:
        return _generate_signer(tmp_path_factory.mktemp("reseal-signer"), openssl)
    except AssertionError:
        pytest.skip("trusted OpenSSL lacks Ed25519 support")


@pytest.fixture
def trusted_signer(
    workspace: Workspace,
    signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> Signer:
    operator_parent = workspace.root / "operator"
    operator_parent.mkdir(mode=0o700)
    os.chmod(operator_parent, 0o700)
    public_key = operator_parent / "operator-public.pem"
    public_key.write_bytes(signer.public_key.read_bytes())
    os.chmod(public_key, 0o600)
    anchored = replace(signer, public_key=public_key)
    _anchor_public_key(workspace, anchored.public_key, anchored.openssl, monkeypatch)
    return anchored


def test_required_trusted_openssl_supports_ed25519(tmp_path: Path) -> None:
    openssl = reseal._resolve_trusted_openssl()
    key = tmp_path / "required-capability.pem"
    completed = subprocess.run(
        [str(openssl), "genpkey", "-algorithm", "ED25519", "-out", str(key)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, "trusted OpenSSL must support Ed25519"


def test_prepare_apply_verify_with_anchored_ed25519_signature(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    prepared = _prepare(workspace)
    signature = _sign(trusted_signer, workspace)

    applied = _apply(workspace, trusted_signer, signature)
    verified = _verify(workspace, trusted_signer, signature)

    assert len(signature.read_bytes()) == 64
    assert prepared["status"] == "prepared"
    assert applied["status"] == "applied"
    assert verified["status"] == "verified"
    assert prepared["request_digest"] == applied["request_digest"]
    assert applied["request_digest"] == verified["request_digest"]
    assert applied["receipt_digest"] == verified["receipt_digest"]
    receipt = json.loads(workspace.receipt.read_text())
    assert receipt["signer_public_key_sha256"] == _digest(trusted_signer.public_key)
    assert receipt["signature_sha256"] == _digest(signature)
    receipt_text = workspace.receipt.read_text()
    assert str(PROJECT_ROOT) not in receipt_text
    assert str(workspace.root) not in receipt_text
    assert "PRIVATE KEY" not in receipt_text
    assert os.stat(workspace.receipt).st_mode & 0o777 == 0o644


def test_prepare_derives_exact_successor_without_mutating_canonical_state(
    workspace: Workspace,
) -> None:
    predecessor = json.loads(
        (workspace.fixture / "factory-profile.json").read_text()
    )
    before = _fixture_digests(workspace.fixture, workspace.pin)

    result = _prepare(workspace)

    assert _fixture_digests(workspace.fixture, workspace.pin) == before
    assert {path.name for path in workspace.candidate.iterdir()} == {
        "factory-profile.json",
        "manifest.json",
        "manifest.sha256",
        "request.json",
    }
    assert os.stat(workspace.candidate).st_mode & 0o777 == 0o700
    assert all(
        os.stat(path).st_mode & 0o777 == 0o600
        for path in workspace.candidate.iterdir()
    )
    successor = json.loads(
        (workspace.candidate / "factory-profile.json").read_text()
    )
    delta = {
        name
        for name in predecessor
        if predecessor[name] != successor[name]
    }
    assert delta == reseal._ALLOWED_PROFILE_DELTA
    assert successor["shadow_activation"] is predecessor["shadow_activation"] is False
    assert reseal.canonical_json(
        {
            name: value
            for name, value in predecessor.items()
            if name not in reseal._ALLOWED_PROFILE_DELTA
        }
    ) == reseal.canonical_json(
        {
            name: value
            for name, value in successor.items()
            if name not in reseal._ALLOWED_PROFILE_DELTA
        }
    )
    gate_digest = reseal.compute_gate_surface_digest(PROJECT_ROOT)
    plugin_digest = reseal.compute_plugin_artifact_digest(PROJECT_ROOT)
    assert successor["gate_surface_digest"] == gate_digest
    assert successor["installed_plugin_artifact_digest"] == plugin_digest
    assert successor["resolved_plugin_source"] == f"sha256:{plugin_digest}"
    request = json.loads((workspace.candidate / "request.json").read_text())
    assert request["gate_surface_digest"] == gate_digest
    assert request["installed_plugin_artifact_digest"] == plugin_digest
    assert request["transition_basis"] == {
        "authorization": "external-ed25519-signature-over-canonical-request",
        "derived_fields": {
            "resolved_plugin_source": "sha256:<installed_plugin_artifact_digest>",
        },
        "measured_fields": [
            "gate_surface_digest",
            "installed_plugin_artifact_digest",
        ],
        "precommit_check": "staged-run_dry_run-success-required-before-canonical-write",
        "predecessor_authority": "external-pin+verify_sealed_fixture",
        "preserved_fields": "all-other-profile-fields-byte-identical",
        "shadow_activation": "preserved-false",
        "signed_bindings": [
            "predecessor-digests",
            "successor-digests",
            "measured-current-bindings",
        ],
        "successor_derivation": "predecessor+disk-measured-current-bindings",
    }
    assert "active_profile_digest" not in request
    assert "pass" not in (workspace.candidate / "request.json").read_text().casefold()
    assert str(PROJECT_ROOT) not in (workspace.candidate / "request.json").read_text()
    assert result["status"] == "prepared"


def test_prepare_never_overwrites_an_existing_candidate(workspace: Workspace) -> None:
    workspace.candidate.mkdir(mode=0o700)
    marker = workspace.candidate / "preserve"
    marker.write_text("preserve")
    before = _fixture_digests(workspace.fixture, workspace.pin)

    with pytest.raises(reseal.ResealError, match="candidate directory already exists"):
        _prepare(workspace)

    assert marker.read_text() == "preserve"
    assert _fixture_digests(workspace.fixture, workspace.pin) == before

def test_prepare_refuses_a_predecessor_with_current_bindings(
    workspace: Workspace,
) -> None:
    gate_digest = reseal.compute_gate_surface_digest(PROJECT_ROOT)
    plugin_digest = reseal.compute_plugin_artifact_digest(PROJECT_ROOT)
    _rewrite_fixture_bindings(
        workspace.fixture,
        workspace.pin,
        gate_surface_digest=gate_digest,
        installed_plugin_artifact_digest=plugin_digest,
    )

    with pytest.raises(reseal.ResealError, match="already current"):
        _prepare(workspace)

    assert not workspace.candidate.exists()


def test_cli_exposes_exact_options_and_no_verifier_or_signing_input() -> None:
    parser = reseal._parser()
    subparser_action = next(
        action
        for action in parser._actions
        if isinstance(action, reseal.argparse._SubParsersAction)
    )
    assert set(subparser_action.choices) == {"prepare", "apply", "verify"}
    options_by_command = {
        name: {
            option
            for action in command._actions
            for option in action.option_strings
        }
        for name, command in subparser_action.choices.items()
    }
    common = {
        "-h",
        "--help",
        "--project-root",
        "--fixture",
        "--fixture-manifest-pin",
        "--candidate-dir",
    }
    assert options_by_command == {
        "prepare": common | {"--valid-for-seconds", "--now"},
        "apply": common
        | {"--signature", "--trusted-public-key", "--receipt"},
        "verify": common
        | {"--signature", "--trusted-public-key", "--receipt"},
    }
    all_options = set().union(*options_by_command.values())
    assert "--active-profile" not in all_options
    assert "--openssl" not in all_options
    assert "--private-key" not in all_options
    assert "--sign" not in all_options
    assert all("secret" not in option.casefold() for option in all_options)
    assert "active_profile" not in inspect.signature(reseal.prepare_reseal).parameters
    assert "openssl" not in inspect.signature(reseal.apply_reseal).parameters
    assert "openssl" not in inspect.signature(reseal.verify_reseal).parameters


@pytest.mark.parametrize(
    ("anchor", "match"),
    [
        ("project", "project root does not match the trusted bootstrap root"),
        ("fixture", "fixture does not match the trusted canonical fixture"),
        ("pin", "fixture pin does not match the trusted canonical pin"),
    ],
)
def test_prepare_rejects_every_canonical_anchor_mismatch(
    workspace: Workspace,
    anchor: str,
    match: str,
) -> None:
    options = {
        "project_root": PROJECT_ROOT,
        "fixture": workspace.fixture,
        "fixture_manifest_pin": workspace.pin,
        "candidate_dir": workspace.candidate,
        "now": NOW,
    }
    if anchor == "project":
        options["project_root"] = workspace.root
    elif anchor == "fixture":
        other_fixture = workspace.root / "other-fixture"
        shutil.copytree(workspace.fixture, other_fixture)
        options["fixture"] = other_fixture
    else:
        other_pin = workspace.root / "other-pin.sha256"
        shutil.copy2(workspace.pin, other_pin)
        options["fixture_manifest_pin"] = other_pin

    with pytest.raises(reseal.ResealError, match=match):
        reseal.prepare_reseal(**options)


def test_apply_rechecks_canonical_fixture_anchor(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    other_fixture = workspace.root / "other-fixture"
    shutil.copytree(workspace.fixture, other_fixture)
    monkeypatch.setattr(reseal, "_CANONICAL_FIXTURE", other_fixture)

    with pytest.raises(reseal.ResealError, match="trusted canonical fixture"):
        _apply(workspace, trusted_signer, signature)


def test_verify_rechecks_canonical_pin_anchor(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    _apply(workspace, trusted_signer, signature)
    other_pin = workspace.root / "other-pin.sha256"
    shutil.copy2(workspace.pin, other_pin)
    monkeypatch.setattr(reseal, "_CANONICAL_PIN", other_pin)

    with pytest.raises(reseal.ResealError, match="trusted canonical pin"):
        _verify(workspace, trusted_signer, signature)




def test_unknown_signer_is_rejected_before_openssl(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    unknown = _generate_signer(
        workspace.root / "unknown-operator",
        trusted_signer.openssl,
    )
    signature = _sign(unknown, workspace, "unknown-request.sig")

    def verifier_must_not_run() -> Path:
        raise AssertionError("OpenSSL ran before the signer anchor check")

    monkeypatch.setattr(reseal, "_resolve_trusted_openssl", verifier_must_not_run)
    with pytest.raises(reseal.ResealError, match="not anchored"):
        _apply(workspace, unknown, signature)


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        (b"", "trusted signer anchor is not canonical"),
        (
            ("A" * 64 + "\n").encode("ascii"),
            "trusted signer anchor is not canonical",
        ),
        (b"# no comments\n", "trusted signer anchor is not canonical"),
        (
            ("0" * 64 + "\n\n").encode("ascii"),
            "trusted signer anchor is not canonical",
        ),
        (
            (("0" * 64 + "\n") * 2).encode("ascii"),
            "trusted signer anchor is not canonical",
        ),
    ],
    ids=("empty", "uppercase", "comment", "blank-line", "duplicate"),
)
def test_trusted_signer_anchor_is_strict(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    match: str,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    workspace.trust_anchor.write_bytes(payload)
    os.chmod(workspace.trust_anchor, 0o600)
    monkeypatch.setattr(reseal, "_TRUSTED_SIGNERS_PATH", workspace.trust_anchor)

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature)


def test_trusted_signer_anchor_parent_must_be_protected(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    os.chmod(workspace.trust_anchor.parent, 0o777)

    with pytest.raises(reseal.ResealError, match="anchor parent"):
        _apply(workspace, trusted_signer, signature)


@pytest.mark.parametrize(
    ("unsafe", "match"),
    [
        ("symlink", "trusted signer anchor must be a regular non-symlink file"),
        ("hard-link", "trusted signer anchor must have one filesystem link"),
        ("shared-write", "trusted signer anchor is writable outside its owner"),
    ],
)
def test_trusted_signer_anchor_requires_a_safe_owned_file(
    workspace: Workspace,
    trusted_signer: Signer,
    unsafe: str,
    match: str,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    if unsafe == "symlink":
        target = workspace.trust_anchor.with_name("anchor-target.sha256")
        workspace.trust_anchor.replace(target)
        workspace.trust_anchor.symlink_to(target)
    elif unsafe == "hard-link":
        os.link(
            workspace.trust_anchor,
            workspace.trust_anchor.with_name("anchor-link.sha256"),
        )
    else:
        os.chmod(workspace.trust_anchor, 0o622)

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature)


@pytest.mark.parametrize(
    ("unsafe", "match"),
    [
        ("symlink", "trusted public key must not be a symlink"),
        ("hard-link", "trusted public key must have one filesystem link"),
        ("shared-write", "trusted public key is writable outside its owner"),
        ("parent", "trusted public key parent is writable outside its owner"),
    ],
)
def test_trusted_public_key_requires_owned_protected_single_link_input(
    workspace: Workspace,
    trusted_signer: Signer,
    unsafe: str,
    match: str,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    public_key = trusted_signer.public_key
    if unsafe == "symlink":
        target = public_key.with_name("public-target.pem")
        public_key.replace(target)
        public_key.symlink_to(target)
    elif unsafe == "hard-link":
        os.link(public_key, public_key.with_name("public-link.pem"))
    elif unsafe == "shared-write":
        os.chmod(public_key, 0o622)
    else:
        os.chmod(public_key.parent, 0o777)

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature)


@pytest.mark.parametrize(
    ("size", "match"),
    [
        (0, "request signature must be exactly 64 bytes"),
        (63, "request signature must be exactly 64 bytes"),
        (65, "request signature must be exactly 64 bytes"),
    ],
)
def test_signature_must_be_exactly_64_bytes(
    workspace: Workspace,
    trusted_signer: Signer,
    size: int,
    match: str,
) -> None:
    _prepare(workspace)
    signature = workspace.root / "wrong-size.sig"
    signature.write_bytes(b"\0" * size)
    os.chmod(signature, 0o600)

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature)


def test_non_ed25519_public_key_is_rejected_by_exact_spki_shape(
    workspace: Workspace,
    signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    other = _generate_signer(
        workspace.root / "x25519-operator",
        signer.openssl,
        algorithm="X25519",
    )
    _anchor_public_key(workspace, other.public_key, other.openssl, monkeypatch)
    signature = workspace.root / "shape.sig"
    signature.write_bytes(b"\0" * 64)
    os.chmod(signature, 0o600)

    with pytest.raises(reseal.ResealError, match="not an Ed25519 SPKI"):
        _apply(workspace, other, signature)


def test_candidate_cannot_supply_its_own_trusted_key(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    candidate_key = replace(
        trusted_signer,
        public_key=workspace.candidate / "request.json",
    )

    with pytest.raises(reseal.ResealError, match="external to the candidate"):
        _apply(workspace, candidate_key, signature)


def test_candidate_rejects_an_embedded_key_file(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    _prepare(workspace)
    (workspace.candidate / "operator-public.pem").write_bytes(
        trusted_signer.public_key.read_bytes()
    )
    signature = _sign(trusted_signer, workspace)

    with pytest.raises(reseal.ResealError, match="file set"):
        _apply(workspace, trusted_signer, signature)


def test_apply_rejects_bad_signature_without_mutation(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    original = signature.read_bytes()
    signature.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    before = _fixture_digests(workspace.fixture, workspace.pin)

    with pytest.raises(reseal.ResealError, match="signature verification"):
        _apply(workspace, trusted_signer, signature)

    assert _fixture_digests(workspace.fixture, workspace.pin) == before
    assert not workspace.receipt.exists()


def test_apply_never_overwrites_an_existing_receipt(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    workspace.receipt.write_text("preserve")
    os.chmod(workspace.receipt, 0o644)
    before = _fixture_digests(workspace.fixture, workspace.pin)

    with pytest.raises(reseal.ResealError, match="receipt already exists"):
        _apply(workspace, trusted_signer, signature)

    assert workspace.receipt.read_text() == "preserve"
    assert _fixture_digests(workspace.fixture, workspace.pin) == before


def test_apply_rejects_anchored_key_that_did_not_sign_request(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    wrong = _generate_signer(
        workspace.root / "wrong-operator",
        trusted_signer.openssl,
    )
    _anchor_public_key(workspace, wrong.public_key, wrong.openssl, monkeypatch)

    with pytest.raises(reseal.ResealError, match="signature verification"):
        _apply(workspace, wrong, signature)


@pytest.mark.parametrize(
    ("prepared_at", "applied_at", "match"),
    [
        (NOW, NOW + 3600, "request has expired"),
        (NOW + 1, NOW, "request is from the future"),
    ],
)
def test_apply_rejects_expired_or_future_request(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    prepared_at: int,
    applied_at: int,
    match: str,
) -> None:
    _prepare(workspace, now=prepared_at)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(
        reseal,
        "_now",
        lambda value: applied_at if value is None else value,
    )

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature)


def test_apply_rejects_signed_request_byte_mutation(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    _rewrite_request(
        workspace,
        lambda value: value.__setitem__("request_id", f"reseal-{'1' * 32}"),
    )

    with pytest.raises(reseal.ResealError, match="signature verification"):
        _apply(workspace, trusted_signer, signature)


def test_apply_rejects_candidate_file_mutation(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    profile_path = workspace.candidate / "factory-profile.json"
    value = json.loads(profile_path.read_text())
    value["shadow_activation"] = True
    profile_path.write_bytes(_canonical(value))

    with pytest.raises(reseal.ResealError, match="candidate bytes"):
        _apply(workspace, trusted_signer, signature)


def test_apply_rejects_predecessor_fixture_mutation(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    (workspace.fixture / "mission.md").write_text("mutated predecessor\n")

    with pytest.raises(reseal.ResealError, match="predecessor sealed fixture"):
        _apply(workspace, trusted_signer, signature)


def test_apply_rejects_signed_request_with_extra_field(
    workspace: Workspace,
    trusted_signer: Signer,
) -> None:
    _prepare(workspace)
    _rewrite_request(workspace, lambda value: value.__setitem__("extra", True))
    signature = _sign(trusted_signer, workspace)

    with pytest.raises(reseal.ResealError, match="request fields"):
        _apply(workspace, trusted_signer, signature)


@pytest.mark.parametrize(
    ("unsafe", "match"),
    [
        ("candidate-mode", "candidate directory mode must be 0700"),
        ("request-mode", "candidate request mode must be 0600"),
        ("request-symlink", "candidate request must not be a symlink"),
    ],
)
def test_apply_rejects_unsafe_candidate_modes_and_symlinks(
    workspace: Workspace,
    trusted_signer: Signer,
    unsafe: str,
    match: str,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    if unsafe == "candidate-mode":
        os.chmod(workspace.candidate, 0o755)
    elif unsafe == "request-mode":
        os.chmod(workspace.candidate / "request.json", 0o644)
    else:
        request = workspace.candidate / "request.json"
        target = workspace.root / "request-target.json"
        request.replace(target)
        request.symlink_to(target)

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature)


@pytest.mark.parametrize(
    ("unsafe", "match"),
    [
        ("signature-symlink", "request signature must not be a symlink"),
        (
            "signature-parent",
            "request signature parent is writable outside its owner",
        ),
        ("receipt-parent", "receipt parent mode must be 0700"),
    ],
)
def test_apply_rejects_unsafe_operator_paths(
    workspace: Workspace,
    trusted_signer: Signer,
    unsafe: str,
    match: str,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    if unsafe == "signature-symlink":
        target = signature.with_name("signature-target.sig")
        signature.replace(target)
        signature.symlink_to(target)
    elif unsafe == "signature-parent":
        signature_parent = workspace.root / "signature-input"
        signature_parent.mkdir(mode=0o700)
        moved = signature_parent / signature.name
        signature.replace(moved)
        signature = moved
        os.chmod(signature_parent, 0o777)
    else:
        os.chmod(workspace.receipt.parent, 0o755)

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature)


def test_prepare_rejects_candidate_contained_in_fixture(workspace: Workspace) -> None:
    contained = replace(workspace, candidate=workspace.fixture / "candidate")

    with pytest.raises(reseal.ResealError, match="overlaps canonical state"):
        _prepare(contained)


@pytest.mark.parametrize(
    ("location", "match"),
    [
        ("candidate", "receipt must be external to candidate and fixture state"),
        ("fixture", "receipt must be external to candidate and fixture state"),
    ],
)
def test_apply_rejects_receipt_contained_in_transaction_inputs(
    workspace: Workspace,
    trusted_signer: Signer,
    location: str,
    match: str,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    parent = workspace.candidate if location == "candidate" else workspace.fixture
    receipt = parent / "receipt.json"

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature, receipt=receipt)


@pytest.mark.parametrize("prefix", [0, 1, 2, 3])
def test_apply_accepts_each_exact_crash_prefix(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    prefix: int,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    _seed_prefix(workspace, prefix)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)

    result = _apply(workspace, trusted_signer, signature)

    assert result["status"] == "applied"
    assert (workspace.fixture / "factory-profile.json").read_bytes() == (
        workspace.candidate / "factory-profile.json"
    ).read_bytes()
    assert (workspace.fixture / "manifest.json").read_bytes() == (
        workspace.candidate / "manifest.json"
    ).read_bytes()
    assert workspace.pin.read_bytes() == (
        workspace.candidate / "manifest.sha256"
    ).read_bytes()


@pytest.mark.parametrize(
    ("state", "match"),
    [
        ((0, 1, 0), "canonical transaction state is not an allowed crash prefix"),
        ((0, 0, 1), "canonical transaction state is not an allowed crash prefix"),
        ((1, 0, 1), "canonical transaction state is not an allowed crash prefix"),
        ((0, 1, 1), "canonical transaction state is not an allowed crash prefix"),
    ],
)
def test_apply_rejects_every_nonprefix_transaction_tuple(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    state: tuple[int, int, int],
    match: str,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    sources = (
        workspace.candidate / "factory-profile.json",
        workspace.candidate / "manifest.json",
        workspace.candidate / "manifest.sha256",
    )
    targets = (
        workspace.fixture / "factory-profile.json",
        workspace.fixture / "manifest.json",
        workspace.pin,
    )
    for use_successor, source, target in zip(state, sources, targets, strict=True):
        if use_successor:
            target.write_bytes(source.read_bytes())
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature)

    assert not workspace.receipt.exists()


@pytest.mark.parametrize("prefix", [0, 1, 2, 3])
def test_prefix_resume_writes_only_the_remaining_suffix(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    prefix: int,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    _seed_prefix(workspace, prefix)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    original = reseal._durable_replace
    writes: list[str] = []

    def recording_replace(path: Path, payload: bytes, **options: Any) -> None:
        writes.append(path.name)
        original(path, payload, **options)

    monkeypatch.setattr(reseal, "_durable_replace", recording_replace)

    _apply(workspace, trusted_signer, signature)

    assert writes == [
        "factory-profile.json",
        "manifest.json",
        "fixture-manifest.sha256",
    ][prefix:]


def test_replacements_copy_each_predecessor_mode_deterministically(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_modes = {
        workspace.fixture / "factory-profile.json": 0o400,
        workspace.fixture / "manifest.json": 0o640,
        workspace.pin: 0o600,
    }
    for path, mode in expected_modes.items():
        os.chmod(path, mode)
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)

    _apply(workspace, trusted_signer, signature)

    assert {
        path: os.stat(path).st_mode & 0o777
        for path in expected_modes
    } == expected_modes


def test_durable_replacement_temps_are_never_fixture_members(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    original = reseal.tempfile.mkstemp
    replacement_locations: list[tuple[str, Path]] = []

    def recording_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        prefix = str(kwargs.get("prefix", ""))
        directory = Path(kwargs["dir"])
        if prefix.startswith(".shadow-reseal-"):
            replacement_locations.append((prefix, directory))
        return original(*args, **kwargs)

    monkeypatch.setattr(reseal.tempfile, "mkstemp", recording_mkstemp)

    _apply(workspace, trusted_signer, signature)

    assert len(replacement_locations) == 3
    assert all(
        directory.resolve() == workspace.fixture.parent.resolve()
        for _, directory in replacement_locations
    )
    assert all(
        directory.resolve() != workspace.fixture.resolve()
        for _, directory in replacement_locations
    )
    assert {path.name for path in workspace.fixture.iterdir()} == {
        path.name for path in SEALED_FIXTURE.iterdir()
    }


@pytest.mark.parametrize(
    ("failure", "match"),
    [
        ("returned", "staged ordinary dry run did not pass"),
        ("raised", "staged ordinary dry run failed"),
    ],
)
def test_staged_dry_run_failure_never_mutates_or_writes_receipt(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    match: str,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    before = _fixture_digests(workspace.fixture, workspace.pin)

    def fail_staged(**_: Any) -> dict[str, Any]:
        if failure == "raised":
            raise RuntimeError("staged failure")
        return {
            "schema_version": "0.1",
            "status": "offline-harness-fail",
            "checks": {"reseal-test": "fail"},
        }

    monkeypatch.setattr(reseal, "run_dry_run", fail_staged)

    with pytest.raises(reseal.ResealError, match=match):
        _apply(workspace, trusted_signer, signature)

    assert _fixture_digests(workspace.fixture, workspace.pin) == before
    assert not workspace.receipt.exists()


def test_apply_runs_staged_then_canonical_ordinary_dry_run(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    calls: list[tuple[Path, Path]] = []

    def observe_dry_run(**options: Any) -> dict[str, Any]:
        fixture = options["fixture_path"]
        pin = options["fixture_manifest_pin"]
        calls.append((fixture, pin))
        if len(calls) == 1:
            assert fixture != workspace.fixture
            assert (fixture / "factory-profile.json").read_bytes() == (
                workspace.candidate / "factory-profile.json"
            ).read_bytes()
            assert (fixture / "manifest.json").read_bytes() == (
                workspace.candidate / "manifest.json"
            ).read_bytes()
            assert pin.read_bytes() == (
                workspace.candidate / "manifest.sha256"
            ).read_bytes()
        return _offline_pass()

    monkeypatch.setattr(reseal, "run_dry_run", observe_dry_run)

    _apply(workspace, trusted_signer, signature)

    assert calls[1] == (workspace.fixture.resolve(), workspace.pin.resolve())


def test_commit_cannot_fail_from_post_commit_expiry(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace, now=NOW)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    clock = iter((NOW, NOW + 3599))
    reads: list[int] = []

    def advancing_clock(value: int | None) -> int:
        if value is not None:
            return value
        try:
            current = next(clock)
        except StopIteration as error:
            raise AssertionError("time was read after canonical mutation") from error
        reads.append(current)
        return current

    monkeypatch.setattr(reseal, "_now", advancing_clock)

    result = _apply(workspace, trusted_signer, signature)

    assert result["status"] == "applied"
    assert reads == [NOW, NOW + 3599]
    assert json.loads(workspace.receipt.read_text())["applied_at"] == NOW + 3599


def test_expired_request_remains_verifiable_after_timely_apply(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace, now=NOW)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    _apply(workspace, trusted_signer, signature)
    monkeypatch.setattr(
        reseal,
        "_now",
        lambda value: NOW + 3600 if value is None else value,
    )

    result = _verify(workspace, trusted_signer, signature)

    assert result["status"] == "verified"


def test_verify_rejects_request_created_in_the_future(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace, now=NOW + 1)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    monkeypatch.setattr(
        reseal,
        "_now",
        lambda value: NOW + 1 if value is None else value,
    )
    _apply(workspace, trusted_signer, signature)
    monkeypatch.setattr(
        reseal,
        "_now",
        lambda value: NOW if value is None else value,
    )

    with pytest.raises(reseal.ResealError, match="request is from the future"):
        _verify(workspace, trusted_signer, signature)


@pytest.mark.parametrize(
    ("applied_at", "match"),
    [
        (NOW - 1, "receipt applied time is outside the request interval"),
        (NOW + 3600, "receipt applied time is outside the request interval"),
    ],
)
def test_verify_proves_receipt_apply_time_is_inside_signed_interval(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    applied_at: int,
    match: str,
) -> None:
    _prepare(workspace, now=NOW)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    _apply(workspace, trusted_signer, signature)
    _rewrite_receipt_with_valid_record_digest(
        workspace,
        lambda value: value.__setitem__("applied_at", applied_at),
    )

    with pytest.raises(reseal.ResealError, match=match):
        _verify(workspace, trusted_signer, signature)


def test_verify_rejects_semantic_offline_digest_mutation_with_valid_self_hash(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    _apply(workspace, trusted_signer, signature)
    _rewrite_receipt_with_valid_record_digest(
        workspace,
        lambda value: value.__setitem__("offline_result_digest", "0" * 64),
    )

    with pytest.raises(reseal.ResealError, match="offline result digest differs"):
        _verify(workspace, trusted_signer, signature)


def test_verify_rejects_current_binding_mismatch(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    _apply(workspace, trusted_signer, signature)
    monkeypatch.setattr(reseal, "compute_gate_surface_digest", lambda _: "0" * 64)

    with pytest.raises(reseal.ResealError, match="gate binding"):
        _verify(workspace, trusted_signer, signature)


def test_verify_rejects_receipt_symlink(
    workspace: Workspace,
    trusted_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(workspace)
    signature = _sign(trusted_signer, workspace)
    monkeypatch.setattr(reseal, "run_dry_run", _offline_pass)
    _apply(workspace, trusted_signer, signature)
    target = workspace.receipt.with_name("receipt-target.json")
    workspace.receipt.replace(target)
    workspace.receipt.symlink_to(target)

    with pytest.raises(reseal.ResealError, match="receipt must not be a symlink"):
        _verify(workspace, trusted_signer, signature)
