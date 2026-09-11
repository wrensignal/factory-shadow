from __future__ import annotations

import importlib.metadata
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from ci.verify_release import (
    ReleaseVerificationError,
    SYNTHETIC_SECRET_CANARIES,
    verify_artifacts,
    verify_marketplace_manifest,
    verify_plugin_manifests,
    verify_release,
    verify_repository_tree,
)


RELEASE_VERSION = "0.1.0b5"
RELEASE_METADATA = (
    f"Metadata-Version: 2.4\nName: shadow-mission\nVersion: {RELEASE_VERSION}\n\n"
).encode()
WHEEL_METADATA_PATH = f"shadow_mission-{RELEASE_VERSION}.dist-info/METADATA"
SOURCE_METADATA_PATH = f"shadow_mission-{RELEASE_VERSION}/PKG-INFO"


def write_wheel(
    path: Path, payload: bytes, *, metadata: bytes | None = RELEASE_METADATA
) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr("shadow_mission/module.py", payload)
        if metadata is not None:
            archive.writestr(WHEEL_METADATA_PATH, metadata)


def write_source(
    path: Path, payload: bytes, *, metadata: bytes | None = RELEASE_METADATA
) -> None:
    members = {f"shadow_mission-{RELEASE_VERSION}/src/module.py": payload}
    if metadata is not None:
        members[SOURCE_METADATA_PATH] = metadata
    with tarfile.open(path, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


def write_artifacts(dist: Path) -> tuple[Path, Path]:
    dist.mkdir()
    wheel = dist / f"shadow_mission-{RELEASE_VERSION}-py3-none-any.whl"
    source = dist / f"shadow_mission-{RELEASE_VERSION}.tar.gz"
    write_wheel(wheel, b"clean package\n")
    write_source(source, b"clean source\n")
    return wheel, source


def test_release_manifests_bind_package_plugin_lima_and_tag(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    write_artifacts(dist)
    verify_release(tag=f"v{RELEASE_VERSION}", dist=dist)

    with pytest.raises(ReleaseVerificationError, match="release tag"):
        verify_release(tag="v0.1.0b1", dist=None)


@pytest.mark.parametrize(
    ("constant_name", "message"),
    (
        ("RUNTIME_PLUGIN_VERSION", "embedded runtime version"),
        ("SOURCE_PLUGIN_VERSION", "embedded runtime version"),
        ("LIVE_PROTOCOL_PLUGIN_VERSION", "embedded runtime version"),
    ),
)
def test_release_manifests_reject_runtime_plugin_version_drift(
    monkeypatch: pytest.MonkeyPatch,
    constant_name: str,
    message: str,
) -> None:
    monkeypatch.setattr(
        f"ci.verify_release.{constant_name}",
        "0.2.0",
    )

    with pytest.raises(ReleaseVerificationError, match=message):
        verify_plugin_manifests(RELEASE_VERSION)


def test_marketplace_manifest_binds_the_repository_root_source() -> None:
    project_root = Path(__file__).resolve().parents[2]
    value = json.loads(
        (project_root / ".factory-plugin/marketplace.json").read_text(
            encoding="utf-8"
        )
    )
    verify_marketplace_manifest(value)

    plugin = dict(value["plugins"][0])
    plugin["source"] = "./shadow-mission"
    changed = dict(value)
    changed["plugins"] = [plugin]
    with pytest.raises(ReleaseVerificationError, match="marketplace manifest"):
        verify_marketplace_manifest(changed)


def test_repository_tree_scan_rejects_private_paths_in_release_files(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("clean\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", tracked.name],
        check=True,
    )
    untracked = tmp_path / "untracked.txt"
    untracked.write_text(
        "operator path: /Users/private/project\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="private path in repository release file: untracked.txt",
    ):
        verify_repository_tree(tmp_path)

    untracked.unlink()
    tracked.write_text(
        "operator path: /Users/private/project\n",
        encoding="utf-8",
    )
    with pytest.raises(
        ReleaseVerificationError,
        match="private path in repository release file: tracked.txt",
    ):
        verify_repository_tree(tmp_path)


def test_repository_tree_scan_rejects_tracked_secret(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    tracked = tmp_path / "tracked.txt"
    tracked.write_bytes(
        b"token = sk-proj-" b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n"
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", tracked.name],
        check=True,
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="secret-like value in repository release file: tracked.txt",
    ):
        verify_repository_tree(tmp_path)


def test_repository_tree_scan_rejects_untracked_secret(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    untracked = tmp_path / "untracked.txt"
    untracked.write_bytes(
        b"token = sk-proj-" b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n"
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="secret-like value in repository release file: untracked.txt",
    ):
        verify_repository_tree(tmp_path)


@pytest.mark.parametrize(
    "payload",
    (
        b"Authorization: Basic " + b"YTpi",
        b"token=" + b"xapp" + b"-1234567890-secret",
        b"token=" + b"xoxc" + b"-1234567890-secret",
    ),
)
def test_repository_tree_scan_rejects_common_authorization_secrets(
    tmp_path: Path,
    payload: bytes,
) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    tracked = tmp_path / "tracked.txt"
    tracked.write_bytes(payload)
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", tracked.name],
        check=True,
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="secret-like value in repository release file: tracked.txt",
    ):
        verify_repository_tree(tmp_path)


def test_repository_tree_scan_rejects_unapproved_canary(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    canary = tmp_path / "canary.txt"
    canary.write_bytes(SYNTHETIC_SECRET_CANARIES[0])

    with pytest.raises(
        ReleaseVerificationError,
        match="secret canary in repository release file: canary.txt",
    ):
        verify_repository_tree(tmp_path)


def test_repository_tree_scan_rejects_empty_tree(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)

    with pytest.raises(
        ReleaseVerificationError,
        match="repository release file list is empty",
    ):
        verify_repository_tree(tmp_path)


def test_repository_tree_scan_rejects_operator_routing_bridge(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    bridge = tmp_path / ".claude" / "CLAUDE.md"
    bridge.parent.mkdir()
    bridge.write_bytes(
        b"@../" b"../WrenOS/AGENTS.md\n",
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", ".claude/CLAUDE.md"],
        check=True,
    )

    with pytest.raises(
        ReleaseVerificationError,
        match=r"private path in repository release file: \.claude/CLAUDE\.md",
    ):
        verify_repository_tree(tmp_path)


def test_artifact_scan_rejects_private_paths_and_secret_like_values(
    tmp_path: Path,
) -> None:
    dist = tmp_path / "dist"
    wheel, _ = write_artifacts(dist)
    verify_artifacts(dist)

    write_wheel(wheel, b"build root: /Users/private/project\n")
    with pytest.raises(ReleaseVerificationError, match="private path"):
        verify_artifacts(dist)

    write_wheel(wheel, b"token = sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n")
    with pytest.raises(ReleaseVerificationError, match="secret-like"):
        verify_artifacts(dist)


@pytest.mark.parametrize("archive_kind", ("wheel", "source", "both"))
def test_artifacts_reject_stale_release_metadata(
    tmp_path: Path, archive_kind: str
) -> None:
    dist = tmp_path / "dist"
    wheel, source = write_artifacts(dist)
    stale = RELEASE_METADATA.replace(RELEASE_VERSION.encode(), b"0.1.0b4")
    if archive_kind in {"wheel", "both"}:
        write_wheel(wheel, b"clean package\n", metadata=stale)
    if archive_kind in {"source", "both"}:
        write_source(source, b"clean source\n", metadata=stale)

    with pytest.raises(ReleaseVerificationError, match="artifact package version"):
        verify_artifacts(dist)


@pytest.mark.parametrize("archive_kind", ("wheel", "source"))
def test_artifacts_reject_mismatched_package_names(
    tmp_path: Path, archive_kind: str
) -> None:
    dist = tmp_path / "dist"
    wheel, source = write_artifacts(dist)
    changed = RELEASE_METADATA.replace(b"Name: shadow-mission", b"Name: other-package")
    if archive_kind == "wheel":
        write_wheel(wheel, b"clean package\n", metadata=changed)
    else:
        write_source(source, b"clean source\n", metadata=changed)

    with pytest.raises(ReleaseVerificationError, match="artifact package name"):
        verify_artifacts(dist)


@pytest.mark.parametrize("archive_kind", ("wheel", "source"))
@pytest.mark.parametrize(
    "metadata",
    (
        None,
        b"Metadata-Version: 2.4\n\n",
        RELEASE_METADATA.replace(b"\n\n", b"\nName: shadow-mission\n\n"),
        RELEASE_METADATA.replace(b"\n\n", f"\nVersion: {RELEASE_VERSION}\n\n".encode()),
    ),
    ids=("missing-metadata", "missing-identity", "duplicate-name", "duplicate-version"),
)
def test_artifacts_require_unambiguous_package_metadata(
    tmp_path: Path, archive_kind: str, metadata: bytes | None
) -> None:
    dist = tmp_path / "dist"
    wheel, source = write_artifacts(dist)
    if archive_kind == "wheel":
        write_wheel(wheel, b"clean package\n", metadata=metadata)
    else:
        write_source(source, b"clean source\n", metadata=metadata)

    with pytest.raises(ReleaseVerificationError, match="artifact .*metadata"):
        verify_artifacts(dist)


@pytest.mark.parametrize("archive_kind", ("wheel", "source"))
@pytest.mark.parametrize("layout", ("wrong-root", "nested"))
def test_artifacts_require_metadata_at_the_release_root(
    tmp_path: Path, archive_kind: str, layout: str
) -> None:
    dist = tmp_path / "dist"
    wheel, source = write_artifacts(dist)
    if archive_kind == "wheel":
        metadata_path = WHEEL_METADATA_PATH
    else:
        metadata_path = SOURCE_METADATA_PATH
    if layout == "wrong-root":
        metadata_path = metadata_path.replace("shadow_mission", "other_package")
    else:
        metadata_path = f"nested/{metadata_path}"
    if archive_kind == "wheel":
        write_wheel(wheel, b"clean package\n", metadata=None)
        with zipfile.ZipFile(wheel, mode="a") as archive:
            archive.writestr(metadata_path, RELEASE_METADATA)
    else:
        with tarfile.open(source, mode="w:gz") as archive:
            info = tarfile.TarInfo(metadata_path)
            info.size = len(RELEASE_METADATA)
            archive.addfile(info, io.BytesIO(RELEASE_METADATA))

    with pytest.raises(ReleaseVerificationError, match="artifact .*metadata"):
        verify_artifacts(dist)


def test_artifacts_reject_stale_embedded_source_metadata(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _, source = write_artifacts(dist)
    members = {
        SOURCE_METADATA_PATH: RELEASE_METADATA,
        f"shadow_mission-{RELEASE_VERSION}/src/shadow_mission.egg-info/PKG-INFO": (
            RELEASE_METADATA.replace(RELEASE_VERSION.encode(), b"0.1.0b4")
        ),
    }
    with tarfile.open(source, mode="w:gz") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    with pytest.raises(ReleaseVerificationError, match="artifact package version"):
        verify_artifacts(dist)


@pytest.mark.parametrize("archive_kind", ("wheel", "source"))
def test_artifacts_keep_archive_path_safety_checks(
    tmp_path: Path, archive_kind: str
) -> None:
    dist = tmp_path / "dist"
    wheel, source = write_artifacts(dist)
    if archive_kind == "wheel":
        with zipfile.ZipFile(wheel, mode="a") as archive:
            archive.writestr("../outside.py", b"unsafe path\n")
    else:
        with tarfile.open(source, mode="w:gz") as archive:
            info = tarfile.TarInfo("../outside.py")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))

    with pytest.raises(ReleaseVerificationError, match="unsafe archive member"):
        verify_artifacts(dist)


@pytest.mark.parametrize("member_type", (tarfile.SYMTYPE, tarfile.LNKTYPE))
def test_artifacts_keep_source_link_safety_checks(
    tmp_path: Path, member_type: bytes
) -> None:
    dist = tmp_path / "dist"
    _, source = write_artifacts(dist)
    with tarfile.open(source, mode="w:gz") as archive:
        info = tarfile.TarInfo(f"shadow_mission-{RELEASE_VERSION}/linked.py")
        info.type = member_type
        info.linkname = "module.py"
        archive.addfile(info)

    with pytest.raises(ReleaseVerificationError, match="linked source artifact member"):
        verify_artifacts(dist)


@pytest.mark.parametrize(
    "member_type",
    (tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, b"Z"),
    ids=("fifo", "character-device", "block-device", "unknown"),
)
def test_artifacts_reject_nonregular_source_members(
    tmp_path: Path, member_type: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    dist = tmp_path / "dist"
    _, source = write_artifacts(dist)
    with tarfile.open(source, mode="w:gz") as archive:
        metadata = tarfile.TarInfo(SOURCE_METADATA_PATH)
        metadata.size = len(RELEASE_METADATA)
        archive.addfile(metadata, io.BytesIO(RELEASE_METADATA))
        info = tarfile.TarInfo(f"shadow_mission-{RELEASE_VERSION}/special")
        info.type = member_type
        archive.addfile(info)

    def reject_payload_read(archive: tarfile.TarFile, member: tarfile.TarInfo) -> None:
        pytest.fail("The verifier must reject special members before it reads payloads.")

    monkeypatch.setattr(tarfile.TarFile, "extractfile", reject_payload_read)
    with pytest.raises(
        ReleaseVerificationError, match="non-regular source artifact member"
    ):
        verify_artifacts(dist)


def test_artifacts_allow_source_directories_and_regular_files(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _, source = write_artifacts(dist)
    with tarfile.open(source, mode="w:gz") as archive:
        directory = tarfile.TarInfo(f"shadow_mission-{RELEASE_VERSION}")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        metadata = tarfile.TarInfo(SOURCE_METADATA_PATH)
        metadata.size = len(RELEASE_METADATA)
        archive.addfile(metadata, io.BytesIO(RELEASE_METADATA))

    verify_artifacts(dist)


def test_proof_extra_requires_pyyaml_without_the_dev_extra() -> None:
    metadata = importlib.metadata.metadata("shadow-mission")
    assert "proof" in metadata.get_all("Provides-Extra", ())
    requirements = [Requirement(value) for value in metadata.get_all("Requires-Dist", ())]
    proof_yaml = [
        requirement
        for requirement in requirements
        if requirement.name.lower() == "pyyaml"
        and requirement.marker is not None
        and requirement.marker.evaluate({"extra": "proof"})
    ]
    assert len(proof_yaml) == 1
    assert proof_yaml[0].specifier == Requirement("PyYAML>=6,<7").specifier
    assert not proof_yaml[0].marker.evaluate({"extra": ""})


@pytest.mark.parametrize(
    ("name", "expected"),
    (("setuptools", "setuptools>=77"), ("packaging", "packaging>=24")),
)
def test_dev_extra_supplies_release_test_dependencies(
    name: str, expected: str
) -> None:
    requirements = [
        Requirement(value)
        for value in importlib.metadata.requires("shadow-mission") or ()
    ]
    matches = [
        requirement
        for requirement in requirements
        if requirement.name.lower() == name
        and requirement.marker is not None
        and requirement.marker.evaluate({"extra": "dev"})
    ]
    assert len(matches) == 1
    assert matches[0].specifier == Requirement(expected).specifier


@pytest.mark.parametrize("relative", ("README.md", "docs/reproducibility.md"))
def test_public_proof_install_command_selects_the_release_and_extra(relative: str) -> None:
    project_root = Path(__file__).resolve().parents[2]
    document = (project_root / relative).read_text(encoding="utf-8")
    requirement = (
        "'shadow-mission[proof] @ "
        f"git+https://github.com/WrenSignal/factory-shadow.git@v{RELEASE_VERSION}'"
    )
    assert requirement in document
    assert ".venv/bin/python demo/proof_bundle.py verify" in document
