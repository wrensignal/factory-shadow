import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest
import shadow_mission.profile as profile_module

from shadow_mission.isolation import IsolationError, validate_isolation_manifest
from shadow_mission.profile import (
    GATE_SURFACE_PATHS,
    PLUGIN_ARTIFACT_ROOTS,
    FactoryProfileError,
    capture_factory_profile,
    artifact_manifest,
    compare_factory_profiles,
    compute_gate_surface_digest,
    compute_plugin_artifact_digest,
    resolve_installed_plugin_root,
    validate_factory_profile,
)


FIXTURE = Path("tests/fixtures/feasibility")
LIMA_CONFIG = Path("ops/lima/shadow-feasibility.yaml")
ARTIFACTS = Path("ops/lima/shadow-feasibility-artifacts.json")


def load_profile() -> dict[str, object]:
    return json.loads((FIXTURE / "factory-profile.json").read_text())


def test_clean_factory_profile_is_complete_and_activation_is_only_allowed_delta() -> None:
    baseline = load_profile()
    shadow = copy.deepcopy(baseline)
    shadow["shadow_activation"] = True

    baseline_result = validate_factory_profile(baseline)
    shadow_result = validate_factory_profile(shadow)
    comparison = compare_factory_profiles(baseline, shadow)

    assert baseline_result.digest == shadow_result.digest
    assert comparison.identical_except_activation is True
    assert baseline_result.status == "pass"
    assert shadow_result.status == "pass"


def make_measured_factory_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path, Path, Path, Path, Path, Path]:
    project_root = tmp_path / "project"
    installed_root = tmp_path / "factory/plugins/cache/shadow-mission"
    for destination_root in (project_root, installed_root):
        for root_name in PLUGIN_ARTIFACT_ROOTS:
            source = Path(root_name)
            destination = destination_root / root_name
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
    factory_root = tmp_path / "factory"
    marketplace_root = tmp_path / "marketplace"
    marketplace_root.mkdir()
    trusted_root = tmp_path / "trusted"
    trusted_root.mkdir()
    credential_root = tmp_path / "credential"
    credential_root.mkdir()
    private_root = tmp_path / "private"
    private_root.mkdir()
    protected_root = tmp_path / "protected"
    protected_root.mkdir()
    droids_root = factory_root / "droids"
    droids_root.mkdir()
    monkeypatch.setattr(profile_module, "_APPROVED_BUILTIN_DROIDS", {})
    (factory_root / "settings.json").write_text(
        json.dumps(
            {
                "cloudSessionSync": False,
                "enabledPlugins": {
                    "shadow-mission@shadow-feasibility-local": True,
                },
                "extraKnownMarketplaces": {
                    "shadow-feasibility-local": {
                        "source": {
                            "source": "local",
                            "path": str(marketplace_root.resolve()),
                        }
                    }
                },
                "hooksDisabled": False,
                "logoAnimation": "off",
                "sandbox": {
                    "enabled": True,
                    "mode": "whole-process",
                    "filesystem": {
                        "denyRead": [
                            str(credential_root.resolve()),
                            str(project_root.resolve()),
                            str(private_root.resolve()),
                            str(protected_root.resolve()),
                        ]
                    },
                    "network": {"allowedDomains": ["127.0.0.1"]},
                },
                "trustedFolders": {
                    str(trusted_root.resolve()): {
                        "trustedAt": "2026-08-17T04:37:24.203Z",
                    }
                },
            }
        )
    )
    return (
        factory_root,
        project_root,
        installed_root,
        trusted_root,
        credential_root,
        private_root,
        protected_root,
        marketplace_root,
    )


def test_factory_profile_is_captured_from_measured_guest_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        factory_root,
        project_root,
        installed_root,
        trusted_root,
        credential_root,
        private_root,
        protected_root,
        marketplace_root,
    ) = make_measured_factory_state(tmp_path, monkeypatch)

    profile = capture_factory_profile(
        factory_root=factory_root,
        project_root=project_root,
        installed_plugin_root=installed_root,
        trusted_root=trusted_root,
        credential_root=credential_root,
        input_root=project_root,
        private_root=private_root,
        protected_root=protected_root,
        marketplace_root=marketplace_root,
        system_settings_path=tmp_path / "system/settings.json",
        shadow_activation=True,
    )

    assert validate_factory_profile(profile).activation_enabled is True
    assert profile["unknown_surfaces"] == []


def test_factory_profile_capture_rejects_inherited_builtin_droid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = make_measured_factory_state(tmp_path, monkeypatch)
    (state[0] / "droids" / "unexpected.md").write_text("inherited droid\n")

    with pytest.raises(FactoryProfileError, match="droid inventory"):
        capture_factory_profile(
            factory_root=state[0],
            project_root=state[1],
            installed_plugin_root=state[2],
            trusted_root=state[3],
            credential_root=state[4],
            input_root=state[1],
            private_root=state[5],
            protected_root=state[6],
            marketplace_root=state[7],
            system_settings_path=tmp_path / "system/settings.json",
            shadow_activation=True,
        )


def test_factory_profile_capture_rejects_unmeasured_setting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = make_measured_factory_state(tmp_path, monkeypatch)
    settings_path = state[0] / "settings.json"
    settings = json.loads(settings_path.read_text())
    settings["customModels"] = []
    settings_path.write_text(json.dumps(settings))

    with pytest.raises(FactoryProfileError, match="unknown surface"):
        capture_factory_profile(
            factory_root=state[0],
            project_root=state[1],
            installed_plugin_root=state[2],
            trusted_root=state[3],
            credential_root=state[4],
            input_root=state[1],
            private_root=state[5],
            protected_root=state[6],
            marketplace_root=state[7],
            system_settings_path=tmp_path / "system/settings.json",
            shadow_activation=True,
        )


def test_managed_factory_settings_require_documented_fallback() -> None:
    profile = load_profile()
    profile["managed_settings"] = {
        "hooks": {
            "mandatory": True,
            "readable": True,
            "sealed_digest": "f" * 64,
            "negative_control_passed": True,
        }
    }
    result = validate_factory_profile(profile)

    assert result.status == "fallback"


def test_unknown_or_extra_factory_surface_fails_closed() -> None:
    unknown = load_profile()
    unknown["unknown_surfaces"] = ["managed-hook-withheld"]
    with pytest.raises(FactoryProfileError, match="unknown"):
        validate_factory_profile(unknown)

    extra_plugin = load_profile()
    extra_plugin["plugins"].append(
        {"name": "unapproved-plugin", "version": "1.0.0", "enabled": True}
    )
    with pytest.raises(FactoryProfileError, match="plugin"):
        validate_factory_profile(extra_plugin)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("command", "python3 /tmp/shadow_hook.py"),
        ("timeout", 3),
    ],
)
def test_factory_profile_requires_exact_hook_contract(
    field_name: str,
    value: object,
) -> None:
    profile = load_profile()
    profile["hooks"][0][field_name] = value

    with pytest.raises(FactoryProfileError, match="hook contract"):
        validate_factory_profile(profile)


def test_factory_profile_binds_resolved_source_to_installed_digest() -> None:
    profile = load_profile()
    profile["resolved_plugin_source"] = "sha256:" + "f" * 64

    with pytest.raises(FactoryProfileError, match="installed artifact"):
        validate_factory_profile(profile)


def test_gate_surface_and_installed_artifact_digests_are_distinct(
    tmp_path: Path,
) -> None:
    project_copy = tmp_path / "project"
    for relative_root in PLUGIN_ARTIFACT_ROOTS:
        source = Path(relative_root)
        target = project_copy / relative_root
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    original_gate = compute_gate_surface_digest(project_copy)
    original_artifact = compute_plugin_artifact_digest(project_copy)
    (project_copy / "pyproject.toml").write_text(
        (project_copy / "pyproject.toml").read_text() + "\n# non-gate change\n"
    )

    assert compute_gate_surface_digest(project_copy) == original_gate
    assert compute_plugin_artifact_digest(project_copy) != original_artifact
    gate_file = project_copy / GATE_SURFACE_PATHS[0]
    gate_file.write_text(gate_file.read_text() + "\n")
    assert compute_gate_surface_digest(project_copy) != original_gate


def test_artifact_manifest_rejects_symlinks_and_unsafe_modes(tmp_path: Path) -> None:
    root = tmp_path / "artifact"
    root.mkdir()
    regular = root / "regular.py"
    regular.write_text("pass\n")
    regular.chmod(0o666)
    with pytest.raises(FactoryProfileError, match="writable"):
        artifact_manifest(root, ("regular.py",))

    regular.chmod(0o600)
    alias = root / "alias.py"
    alias.symlink_to(regular)
    with pytest.raises(FactoryProfileError, match="symlink"):
        artifact_manifest(root, ("alias.py",))


def test_pinned_no_mount_lima_manifest_validates_offline() -> None:
    result = validate_isolation_manifest(
        FIXTURE / "isolation-manifest.json", LIMA_CONFIG, require_live_canaries=False
    )

    assert result.mechanism == "lima"
    assert result.host_mounts == ()
    assert result.live_canaries_verified is False


def test_live_isolation_requires_all_canaries_and_teardown() -> None:
    manifest = json.loads((FIXTURE / "isolation-manifest.json").read_text())
    with pytest.raises(IsolationError, match="live canary"):
        validate_isolation_manifest(
            manifest, LIMA_CONFIG, require_live_canaries=True
        )

    for field in (
        "host_read_canary_denied",
        "host_write_canary_unchanged",
        "guest_protected_read_denied",
        "fixture_read_allowed",
        "guest_mount_table_clean",
        "guest_visible_paths_allowlisted",
        "teardown_confirmed",
    ):
        manifest[field] = True
    result = validate_isolation_manifest(
        manifest, LIMA_CONFIG, require_live_canaries=True
    )
    assert result.live_canaries_verified is True


def test_lima_config_digest_and_security_fields_are_bound(tmp_path: Path) -> None:
    modified = tmp_path / "unsafe.yaml"
    modified.write_text(LIMA_CONFIG.read_text().replace("mounts: []", "mounts:\n  - location: /Users"))
    manifest = json.loads((FIXTURE / "isolation-manifest.json").read_text())
    manifest["config_sha256"] = __import__("hashlib").sha256(
        modified.read_bytes()
    ).hexdigest()

    with pytest.raises(IsolationError, match="approved template"):
        validate_isolation_manifest(manifest, modified, require_live_canaries=False)


def test_guest_droid_artifact_and_wrapper_are_exactly_pinned() -> None:
    artifacts = json.loads(ARTIFACTS.read_text())
    droid = artifacts["droid"]
    lima = artifacts["lima"]
    wrapper = Path("ops/lima/droid-pinned").read_text()
    authenticated_wrapper = Path("ops/lima/droid-authenticated").read_text()
    bootstrap = Path("ops/lima/bootstrap-feasibility-guest.sh").read_text()
    requirements = Path("ops/lima/requirements-feasibility.txt").read_text()
    installer = Path("ops/lima/install-feasibility-plugin.sh").read_text()
    hardening = Path("ops/lima/harden-feasibility-guest.sh").read_text()
    template = LIMA_CONFIG.read_text()

    assert droid == {
        "version": "0.197.0",
        "installation_channel": "factory-npm-platform-tarball",
        "package": "@factory/cli-linux-arm64@0.197.0",
        "tarball_url": (
            "https://registry.npmjs.org/@factory/cli-linux-arm64/-/"
            "cli-linux-arm64-0.197.0.tgz"
        ),
        "published_sha1": "f5dc390c08145642037543d526c5f5f2fd90ae38",
        "published_sha512": (
            "7fd5af5edf82aa07441eab15e254026d01c17159d3ccf74230e2a883"
            "cc073dbc2f404a79fc2814f6622814841cd2f82d686d4414191114243"
            "98487f2e4daacc5"
        ),
        "binary_path": "/home/shadow/bin/droid",
        "binary_sha256": (
            "9bf6a5b667ed231d75c6aef720c02d54b042d45d1da6551832e6ae4376d667f9"
        ),
        "auto_update_control": "FACTORY_DROID_AUTO_UPDATE_ENABLED=false",
    }
    assert lima["template"] == str(LIMA_CONFIG)
    assert lima["version"] == "2.2.0"
    assert lima["image_digest"] in template
    assert droid["binary_path"] in wrapper
    assert droid["binary_sha256"] in wrapper
    assert droid["auto_update_control"] in wrapper
    assert "/home/shadow/credential/factory-api-key" in authenticated_wrapper
    assert "/home/shadow/bin/droid-pinned" in authenticated_wrapper
    assert "FACTORY_API_KEY" in authenticated_wrapper
    assert "cat " not in authenticated_wrapper
    assert droid["tarball_url"] in bootstrap
    assert droid["published_sha512"] in bootstrap
    assert droid["binary_sha256"] in bootstrap
    assert "PYTHONDONTWRITEBYTECODE=1" in bootstrap
    assert "/home/shadow/credential" in bootstrap
    assert "/home/shadow/workspace" in bootstrap
    for sealed_path in (
        "/home/shadow/input",
        "/home/shadow/bin/droid",
        "/home/shadow/bin/droid-pinned",
        "/home/shadow/bin/droid-authenticated",
        "/home/shadow/venv",
    ):
        assert sealed_path in hardening
    assert 'chown -R root:root "$path"' in hardening
    assert 'chmod -R u=rwX,go=rX "$path"' in hardening
    assert "--require-hashes" in bootstrap
    assert "droid-sdk==0.2.0" in requirements
    assert "pydantic==2.13.4" in requirements
    assert "/home/shadow/bin/droid-pinned" in installer
    assert "plugin marketplace add" in installer
    assert "shadow-mission@shadow-feasibility-local --scope user" in installer


def test_installed_plugin_root_is_resolved_from_factory_state(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "plugins/cache/shadow-mission"
    for root_name in PLUGIN_ARTIFACT_ROOTS:
        source = Path(root_name)
        destination = candidate / root_name
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    digest = compute_plugin_artifact_digest(candidate)

    resolved = resolve_installed_plugin_root(
        tmp_path / "plugins",
        plugin_name="shadow-mission",
        plugin_version="0.1.0",
        expected_digest=digest,
    )

    assert resolved == candidate.resolve()

    shutil.copytree(candidate, tmp_path / "plugins/cache/duplicate")
    with pytest.raises(FactoryProfileError, match="exactly one"):
        resolve_installed_plugin_root(
            tmp_path / "plugins",
            plugin_name="shadow-mission",
            plugin_version="0.1.0",
            expected_digest=digest,
        )
