from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parents[2]


def test_clean_noneditable_install_exposes_public_commands(tmp_path: Path) -> None:
    target = tmp_path / "site-packages"
    python = Path(sys.executable)
    installed = subprocess.run(
        (
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--no-build-isolation",
            "--no-deps",
            "--target",
            str(target),
            str(PROJECT_ROOT),
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        shell=False,
        timeout=120,
    )
    assert installed.returncode == 0, installed.stderr

    command = subprocess.run(
        (
            str(python),
            "-c",
            (
                "import importlib.metadata, pathlib, shadow_mission, shadow_mission.cli; "
                "distribution = importlib.metadata.distribution('shadow-mission'); "
                "assert distribution.metadata['Name'] == 'shadow-mission'; "
                "assert distribution.version == '0.1.0b5'; "
                f"target = pathlib.Path({str(target)!r}); "
                "assert pathlib.Path(distribution.locate_file('')).resolve() == target.resolve(); "
                "assert pathlib.Path(shadow_mission.__file__).resolve().is_relative_to(target.resolve()); "
                "print(distribution.metadata['Name'], distribution.version); "
                "print(shadow_mission.__file__); "
                "raise SystemExit(shadow_mission.cli.main(['--help']))"
            ),
        ),
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(target)},
        capture_output=True,
        text=True,
        shell=False,
        timeout=30,
    )

    assert command.returncode == 0, command.stderr
    assert "shadow-mission 0.1.0b5" in command.stdout
    assert "mission" in command.stdout
    assert "status" in command.stdout
    assert "report" in command.stdout
    assert str(PROJECT_ROOT / "src") not in command.stdout
    assert str(target) in command.stdout

    proof = subprocess.run(
        (
            str(python),
            str(PROJECT_ROOT / "demo/proof_bundle.py"),
            "verify",
            "--help",
        ),
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(target)},
        capture_output=True,
        text=True,
        shell=False,
        timeout=30,
    )
    assert proof.returncode == 0, proof.stderr
    assert "--bundle" in proof.stdout

    missing_bundle = subprocess.run(
        (
            str(python),
            str(PROJECT_ROOT / "demo/proof_bundle.py"),
            "verify",
            "--bundle",
            str(tmp_path / "missing-proof.tar"),
        ),
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(target)},
        capture_output=True,
        text=True,
        shell=False,
        timeout=30,
    )
    assert missing_bundle.returncode == 1, missing_bundle.stderr
    assert "proof bundle: fail:" in missing_bundle.stdout
    assert "unavailable" in missing_bundle.stdout
