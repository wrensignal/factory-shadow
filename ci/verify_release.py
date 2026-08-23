from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

import yaml

from shadow_mission import __version__ as SOURCE_PLUGIN_VERSION
from shadow_mission.profile import PLUGIN_VERSION as RUNTIME_PLUGIN_VERSION
from shadow_mission.runtime import (
    EXPECTED_PLUGIN_VERSION as LIVE_PROTOCOL_PLUGIN_VERSION,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PLUGIN_NAME = "shadow-mission"
EXPECTED_MARKETPLACE_NAME = "factory-shadow"
EXPECTED_REPOSITORY_URL = "https://github.com/WrenSignal/factory-shadow"
EXPECTED_PROJECT_URLS = frozenset(
    {
        f"Homepage, {EXPECTED_REPOSITORY_URL}",
        f"Issues, {EXPECTED_REPOSITORY_URL}/issues",
        f"Repository, {EXPECTED_REPOSITORY_URL}",
    }
)
RELEASE_VERSION_PATTERN = re.compile(
    r"^(?P<base>[0-9]+\.[0-9]+\.[0-9]+)(?:b[0-9]+)?$"
)
EXPECTED_HOOK_EVENTS = frozenset(
    {
        "SessionStart",
        "UserPromptSubmit",
        "PostToolUse",
        "Stop",
        "SubagentStop",
        "SessionEnd",
    }
)
EXPECTED_HOOK_COMMAND = 'python3 "${DROID_PLUGIN_ROOT}/hooks/shadow_hook.py"'
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\bghp_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
)
SYNTHETIC_SECRET_CANARIES = (
    b"sk-shadow-feasibility-NEVER-PERSIST-7319",
)
PRIVATE_PATH_PATTERNS = (
    re.compile(rb"/Users/[A-Za-z0-9._-]+/"),
    re.compile(rb"/private/var/folders/[A-Za-z0-9._-]+/"),
    re.compile(rb"C:\\Users\\[A-Za-z0-9._-]+\\"),
    re.compile(rb"(?m)^@(?:\.\./){2,}WrenOS/AGENTS\.md\r?$"),
)
ALLOWED_REPOSITORY_PRIVATE_PATH_FIXTURES = {
    "tests/feasibility/test_redaction.py": (
        b"/Users/" b"scott/private/transcript.jsonl",
        b"/Users/" b"scott/private/repository",
        b"/Users/" b"scott/private/file.py",
    ),
    "tests/unit/test_redaction.py": (
        b"/Users/" b"operator/private/transcript.jsonl",
    ),
    "tests/unit/test_release_verification.py": (
        b"/Users/" b"private/project",
    ),
}

ALLOWED_REPOSITORY_SECRET_FIXTURES = {
    "ci/verify_release.py": SYNTHETIC_SECRET_CANARIES,
    "src/shadow_mission/live.py": SYNTHETIC_SECRET_CANARIES,
    "tests/feasibility/test_dry_run.py": SYNTHETIC_SECRET_CANARIES,
    "tests/feasibility/test_redaction.py": SYNTHETIC_SECRET_CANARIES,
    "tests/fixtures/feasibility/oracle.json": SYNTHETIC_SECRET_CANARIES,
    "tests/integration/test_proof_bundle.py": (
        b"sk-" b"example-value-that-is-not-real",
    ),
    "tests/unit/test_extractor.py": (
        b"sk-" b"this-must-never-persist",
    ),
    "tests/unit/test_redaction.py": (
        b"-----BEGIN " b"PRIVATE KEY-----",
    ),
    "tests/unit/test_release_verification.py": (
        b"sk-proj-" b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    ),
}


class ReleaseVerificationError(ValueError):
    pass


def _regular_archive_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ReleaseVerificationError(f"unsafe archive member: {name}")
    return path


def _scan_payload(name: str, payload: bytes) -> None:
    for pattern in PRIVATE_PATH_PATTERNS:
        if pattern.search(payload):
            raise ReleaseVerificationError(f"private path in artifact member: {name}")
    candidate = payload
    for canary in SYNTHETIC_SECRET_CANARIES:
        candidate = candidate.replace(canary, b"")
    for pattern in SECRET_PATTERNS:
        if pattern.search(candidate):
            raise ReleaseVerificationError(f"secret-like value in artifact member: {name}")


def verify_repository_tree(root: Path = PROJECT_ROOT) -> None:
    try:
        release_files = subprocess.run(
            (
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
            ),
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise ReleaseVerificationError(
            "unable to list repository release files"
        ) from error
    if release_files.returncode != 0:
        raise ReleaseVerificationError(
            "unable to list repository release files"
        )
    if not release_files.stdout:
        raise ReleaseVerificationError("repository release file list is empty")
    if not release_files.stdout.endswith(b"\0"):
        raise ReleaseVerificationError("repository release file list is invalid")
    encoded_names = release_files.stdout[:-1].split(b"\0")
    if not encoded_names or any(not name for name in encoded_names):
        raise ReleaseVerificationError("repository release file list is invalid")
    if len(encoded_names) != len(set(encoded_names)):
        raise ReleaseVerificationError(
            "repository release file list has duplicates"
        )

    for encoded_name in encoded_names:
        name = os.fsdecode(encoded_name)
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
        ):
            raise ReleaseVerificationError(
                f"unsafe repository release path: {name}"
            )
        path = root.joinpath(*relative.parts)
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                payload = os.fsencode(path.readlink())
            elif stat.S_ISREG(metadata.st_mode):
                payload = path.read_bytes()
            else:
                raise ReleaseVerificationError(
                    f"non-regular repository release file: {name}"
                )
        except ReleaseVerificationError:
            raise
        except OSError as error:
            raise ReleaseVerificationError(
                f"unreadable repository release file: {name}"
            ) from error
        candidate = payload
        for fixture in ALLOWED_REPOSITORY_PRIVATE_PATH_FIXTURES.get(name, ()):
            candidate = candidate.replace(fixture, b"")
        for fixture in ALLOWED_REPOSITORY_SECRET_FIXTURES.get(name, ()):
            candidate = candidate.replace(fixture, b"")
        for pattern in PRIVATE_PATH_PATTERNS:
            if pattern.search(candidate):
                raise ReleaseVerificationError(
                    f"private path in repository release file: {name}"
                )
        for canary in SYNTHETIC_SECRET_CANARIES:
            if canary in candidate:
                raise ReleaseVerificationError(
                    f"secret canary in repository release file: {name}"
                )
        for pattern in SECRET_PATTERNS:
            if pattern.search(candidate):
                raise ReleaseVerificationError(
                    f"secret-like value in repository release file: {name}"
                )


def _wheel_payloads(path: Path) -> Iterable[tuple[str, bytes]]:
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            _regular_archive_name(member.filename)
            if member.is_dir():
                continue
            yield member.filename, archive.read(member)


def _source_payloads(path: Path) -> Iterable[tuple[str, bytes]]:
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            _regular_archive_name(member.name)
            if member.issym() or member.islnk():
                raise ReleaseVerificationError(
                    f"linked source artifact member: {member.name}"
                )
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ReleaseVerificationError(
                    f"unreadable source artifact member: {member.name}"
                )
            yield member.name, extracted.read()


def verify_artifacts(dist: Path) -> None:
    archives = tuple(sorted(path for path in dist.iterdir() if path.is_file()))
    wheels = tuple(path for path in archives if path.suffix == ".whl")
    sources = tuple(path for path in archives if path.name.endswith(".tar.gz"))
    if len(wheels) != 1 or len(sources) != 1 or len(archives) != 2:
        raise ReleaseVerificationError("dist must contain one wheel and one source archive")
    for archive, payloads in (
        (wheels[0], _wheel_payloads(wheels[0])),
        (sources[0], _source_payloads(sources[0])),
    ):
        count = 0
        for name, payload in payloads:
            _scan_payload(name, payload)
            count += 1
        if count == 0:
            raise ReleaseVerificationError(f"empty release artifact: {archive.name}")


def _load_yaml(path: Path) -> dict[str, object]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReleaseVerificationError(f"invalid Lima manifest: {path.name}")
    return value


def verify_lima_manifest(path: Path) -> None:
    value = _load_yaml(path)
    images = value.get("images")
    if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict):
        raise ReleaseVerificationError(f"invalid image pin: {path.name}")
    image = images[0]
    required = {
        "minimumLimaVersion": "2.2.0",
        "vmType": "vz",
        "os": "Linux",
        "arch": "aarch64",
        "mounts": [],
        "mountInotify": False,
        "propagateProxyEnv": False,
    }
    if any(value.get(name) != expected for name, expected in required.items()):
        raise ReleaseVerificationError(f"unsafe Lima boundary: {path.name}")
    if image.get("arch") != "aarch64" or not isinstance(image.get("location"), str):
        raise ReleaseVerificationError(f"invalid Lima image: {path.name}")
    if not str(image["location"]).startswith("https://") or not DIGEST_PATTERN.fullmatch(
        str(image.get("digest", ""))
    ):
        raise ReleaseVerificationError(f"unpinned Lima image: {path.name}")
    for section, expected in (
        ("containerd", {"system": False, "user": False}),
        (
            "ssh",
            {
                "loadDotSSHPubKeys": False,
                "forwardAgent": False,
                "forwardX11": False,
                "forwardX11Trusted": False,
            },
        ),
    ):
        observed = value.get(section)
        if not isinstance(observed, dict) or any(
            observed.get(name) != setting for name, setting in expected.items()
        ):
            raise ReleaseVerificationError(f"unsafe Lima {section}: {path.name}")
    user = value.get("user")
    expected_passwordless_sudo = path.name == "shadow-feasibility.yaml"
    if (
        not isinstance(user, dict)
        or user.get("passwordlessSudo") is not expected_passwordless_sudo
    ):
        raise ReleaseVerificationError(f"Lima user privilege differs: {path.name}")


def _release_base_version(version: str) -> str:
    match = RELEASE_VERSION_PATTERN.fullmatch(version)
    if match is None:
        raise ReleaseVerificationError("release version is not supported")
    return match.group("base")


def verify_package_metadata(version: str) -> None:
    metadata = importlib.metadata.metadata("shadow-mission")
    project_urls = frozenset(metadata.get_all("Project-URL") or ())
    if (
        metadata.get("Name") != EXPECTED_PLUGIN_NAME
        or metadata.get("Summary") != "Mission-wide review for Factory Missions"
        or project_urls != EXPECTED_PROJECT_URLS
    ):
        raise ReleaseVerificationError("package metadata differs")
    if importlib.metadata.version("shadow-mission") != version:
        raise ReleaseVerificationError("installed package version differs")


def verify_marketplace_manifest(value: object) -> None:
    expected_plugin = {
        "name": EXPECTED_PLUGIN_NAME,
        "description": "Mission-wide review for Factory Missions.",
        "source": ".",
        "homepage": EXPECTED_REPOSITORY_URL,
        "tags": ["factory", "missions", "review", "hooks"],
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != {"name", "description", "owner", "plugins"}
        or value.get("name") != EXPECTED_MARKETPLACE_NAME
        or value.get("description")
        != "Mission-wide review plugins for Factory Missions."
        or value.get("owner") != {"name": "WrenSignal"}
        or value.get("plugins") != [expected_plugin]
    ):
        raise ReleaseVerificationError("marketplace manifest binding differs")


# The beta suffix identifies the public Python distribution.
# Factory plugin and live protocol bindings stay on the stable base version.
def verify_plugin_manifests(version: str) -> None:
    base_version = _release_base_version(version)
    if (
        RUNTIME_PLUGIN_VERSION != base_version
        or SOURCE_PLUGIN_VERSION != base_version
        or LIVE_PROTOCOL_PLUGIN_VERSION != base_version
    ):
        raise ReleaseVerificationError("embedded runtime version differs")
    plugin = json.loads(
        (PROJECT_ROOT / ".factory-plugin/plugin.json").read_text(encoding="utf-8")
    )
    if (
        not isinstance(plugin, dict)
        or plugin.get("name") != EXPECTED_PLUGIN_NAME
        or plugin.get("description") != "Mission-wide review for Factory Missions."
        or plugin.get("version") != base_version
        or plugin.get("homepage") != EXPECTED_REPOSITORY_URL
        or plugin.get("repository") != EXPECTED_REPOSITORY_URL
        or plugin.get("license") != "MIT"
    ):
        raise ReleaseVerificationError("plugin manifest binding differs")
    marketplace = json.loads(
        (PROJECT_ROOT / ".factory-plugin/marketplace.json").read_text(
            encoding="utf-8"
        )
    )
    verify_marketplace_manifest(marketplace)
    hooks = json.loads((PROJECT_ROOT / "hooks/hooks.json").read_text(encoding="utf-8"))
    if not isinstance(hooks, dict) or set(hooks) != EXPECTED_HOOK_EVENTS:
        raise ReleaseVerificationError("hook manifest event set differs")
    for event, groups in hooks.items():
        if not isinstance(groups, list) or len(groups) != 1 or groups[0].keys() != {"hooks"}:
            raise ReleaseVerificationError(f"invalid hook group: {event}")
        commands = groups[0]["hooks"]
        if (
            not isinstance(commands, list)
            or len(commands) != 1
            or commands[0]
            != {"type": "command", "command": EXPECTED_HOOK_COMMAND, "timeout": 2}
        ):
            raise ReleaseVerificationError(f"invalid hook command: {event}")


def verify_release(*, tag: str | None, dist: Path | None) -> None:
    version = importlib.metadata.version("shadow-mission")
    verify_repository_tree()
    verify_package_metadata(version)
    verify_plugin_manifests(version)
    for relative in (
        "ops/lima/shadow-feasibility.yaml",
        "ops/lima/shadow-evaluator.yaml",
    ):
        verify_lima_manifest(PROJECT_ROOT / relative)
    if tag is not None and tag.removeprefix("v") != version:
        raise ReleaseVerificationError("release tag differs from package version")
    if dist is not None:
        verify_artifacts(dist)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag")
    parser.add_argument("--dist", type=Path)
    arguments = parser.parse_args()
    verify_release(tag=arguments.tag, dist=arguments.dist)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
