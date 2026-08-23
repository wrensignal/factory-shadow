from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from shadow_mission.source_export import (
    SourceArchiveError,
    safe_extract_source,
    validate_source_archive,
)

PROJECT_ROOT = Path(__file__).parents[2]
EXPORTER = PROJECT_ROOT / "demo/export_source.py"


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "checkout"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src/payment.py").write_text("UNIT = 'dollars'\n", encoding="utf-8")
    (repo / "README.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q", str(repo)), check=True)
    subprocess.run(("git", "-C", str(repo), "add", "."), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Shadow Tests",
            "-c",
            "user.email=shadow-tests@example.invalid",
            "commit",
            "-qm",
            "seed",
        ),
        check=True,
    )
    return repo


def export(repo: Path, output: Path, *extra: str) -> tuple[Path, Path, subprocess.CompletedProcess[str]]:
    output.mkdir()
    archive = output / "final-source.tar"
    manifest = output / "final-source-manifest.json"
    result = subprocess.run(
        (
            sys.executable,
            str(EXPORTER),
            "--repo",
            str(repo),
            "--archive",
            str(archive),
            "--manifest",
            str(manifest),
            *extra,
        ),
        capture_output=True,
        text=True,
        shell=False,
    )
    return archive, manifest, result


def test_final_checkout_export_is_deterministic_and_safe_to_extract(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "src/payment.py").write_text("UNIT = 'cents'\n", encoding="utf-8")
    (repo / "src/résumé.py").write_text("CURRENCY = 'USD'\n", encoding="utf-8")

    first_archive, first_manifest, first = export(repo, tmp_path / "first")
    second_archive, second_manifest, second = export(repo, tmp_path / "second")

    assert first.returncode == second.returncode == 0
    assert first_archive.read_bytes() == second_archive.read_bytes()
    assert first_manifest.read_bytes() == second_manifest.read_bytes()
    validated = validate_source_archive(first_archive, first_manifest)
    assert validated.archive_digest == hashlib.sha256(first_archive.read_bytes()).hexdigest()
    assert validated.manifest.dirty_state == (
        " M src/payment.py",
        "?? \"src/r\\303\\251sum\\303\\251.py\"",
    )
    extracted = safe_extract_source(validated, tmp_path / "extracted")
    assert (extracted / "src/payment.py").read_text() == "UNIT = 'cents'\n"
    assert (extracted / "src/résumé.py").read_text() == "CURRENCY = 'USD'\n"


@pytest.mark.parametrize("unsafe_name", [".env", "credentials", "access-token.txt"])
def test_export_rejects_credential_named_files(tmp_path: Path, unsafe_name: str) -> None:
    repo = make_repo(tmp_path)
    (repo / unsafe_name).write_text("private\n", encoding="utf-8")

    _, _, result = export(repo, tmp_path / "output")

    assert result.returncode == 1
    assert "credential-like" in result.stdout


def test_export_rejects_links_and_secret_canaries(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "link.py").symlink_to(repo / "src/payment.py")

    _, _, linked = export(repo, tmp_path / "linked")

    assert linked.returncode == 1
    assert "symbolic link" in linked.stdout

    (repo / "link.py").unlink()
    (repo / "src/payment.py").write_text("prefix-secret-canary-suffix\n", encoding="utf-8")
    _, _, canary = export(
        repo,
        tmp_path / "canary",
        "--secret-canary",
        "secret-canary",
    )
    assert canary.returncode == 1
    assert "secret canary" in canary.stdout


def test_host_validation_rejects_unmanifested_or_unsafe_archive_member(
    tmp_path: Path,
) -> None:
    repo = make_repo(tmp_path)
    archive, manifest, result = export(repo, tmp_path / "output")
    assert result.returncode == 0

    tampered = tmp_path / "tampered.tar"
    with tarfile.open(tampered, mode="w") as output:
        payload = b"escape"
        member = tarfile.TarInfo("../escape")
        member.size = len(payload)
        output.addfile(member, io.BytesIO(payload))

    with pytest.raises(SourceArchiveError):
        validate_source_archive(tampered, manifest)

    value = json.loads(manifest.read_text())
    value["files"][0]["sha256"] = "0" * 64
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SourceArchiveError):
        validate_source_archive(archive, manifest)
