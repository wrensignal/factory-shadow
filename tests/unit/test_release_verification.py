from __future__ import annotations

import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from ci.verify_release import (
    ReleaseVerificationError,
    SYNTHETIC_SECRET_CANARIES,
    verify_artifacts,
    verify_marketplace_manifest,
    verify_plugin_manifests,
    verify_release,
    verify_repository_tree,
)


def write_wheel(path: Path, payload: bytes) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr("shadow_mission/module.py", payload)


def write_source(path: Path, payload: bytes) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        info = tarfile.TarInfo("shadow_mission-0.1.0b2/src/module.py")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))


def test_release_manifests_bind_package_plugin_lima_and_tag() -> None:
    verify_release(tag="v0.1.0b2", dist=None)

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
        verify_plugin_manifests("0.1.0b2")


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
    dist.mkdir()
    wheel = dist / "shadow_mission-0.1.0b2-py3-none-any.whl"
    source = dist / "shadow_mission-0.1.0b2.tar.gz"
    write_wheel(wheel, b"clean package\n")
    write_source(source, b"clean source\n")
    verify_artifacts(dist)

    write_wheel(wheel, b"build root: /Users/private/project\n")
    with pytest.raises(ReleaseVerificationError, match="private path"):
        verify_artifacts(dist)

    write_wheel(wheel, b"token = sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n")
    with pytest.raises(ReleaseVerificationError, match="secret-like"):
        verify_artifacts(dist)
