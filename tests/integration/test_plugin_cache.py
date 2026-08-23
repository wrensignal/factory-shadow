from __future__ import annotations

import ast
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from shadow_mission.profile import (
    compute_gate_surface_digest,
    compute_plugin_artifact_digest,
)

PROJECT_ROOT = Path(__file__).parents[2]


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def test_hook_runtime_imports_only_python_standard_library() -> None:
    sources = (
        PROJECT_ROOT / "hooks/shadow_hook.py",
        PROJECT_ROOT / "hooks/hook_runtime.py",
    )
    imported: set[str] = set()
    for source in sources:
        tree = ast.parse(source.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])

    assert imported <= sys.stdlib_module_names | {"hook_runtime", "__future__"}
    assert "shadow_mission" not in imported
    assert "pydantic" not in imported


def test_cached_hook_is_inert_without_activation_or_for_internal_session(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "installed-plugin/hooks"
    shutil.copytree(PROJECT_ROOT / "hooks", cache)
    before = tree_digest(cache)
    base_environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    inactive = subprocess.run(
        [sys.executable, str(cache / "shadow_hook.py")],
        input=b'{"hook_event_name":"Stop"}',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=base_environment,
        cwd=cache,
        timeout=3,
        check=False,
    )
    internal = subprocess.run(
        [sys.executable, str(cache / "shadow_hook.py")],
        input=b'{"hook_event_name":"Stop"}',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            **base_environment,
            "SHADOW_MISSION_RUN_FILE": "/unavailable/descriptor.json",
            "SHADOW_MISSION_RUN_SECRET": "must-not-be-read",
            "SHADOW_MISSION_INTERNAL": "1",
        },
        cwd=cache,
        timeout=3,
        check=False,
    )

    for result in (inactive, internal):
        assert result.returncode == 0
        assert result.stdout == b""
        assert result.stderr == b""
    assert tree_digest(cache) == before


def test_non_gate_source_change_updates_installed_artifact_only(tmp_path: Path) -> None:
    copy_root = tmp_path / "plugin"
    for relative in (".factory-plugin", "hooks", "src"):
        shutil.copytree(PROJECT_ROOT / relative, copy_root / relative)
    shutil.copy2(PROJECT_ROOT / "pyproject.toml", copy_root / "pyproject.toml")

    gate_before = compute_gate_surface_digest(copy_root)
    artifact_before = compute_plugin_artifact_digest(copy_root)
    protocol = copy_root / "src/shadow_mission/protocol.py"
    protocol.write_text(protocol.read_text() + "\n# non-gate digest test\n")

    assert compute_gate_surface_digest(copy_root) == gate_before
    assert compute_plugin_artifact_digest(copy_root) != artifact_before
