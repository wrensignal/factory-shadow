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
            "--no-deps",
            "--no-build-isolation",
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
                "import importlib.metadata, shadow_mission, shadow_mission.cli; "
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
    assert "mission" in command.stdout
    assert "status" in command.stdout
    assert "report" in command.stdout
    assert str(PROJECT_ROOT / "src") not in command.stdout
    assert str(target) in command.stdout
