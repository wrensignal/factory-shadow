from pathlib import Path

from shadow_mission.auth import RUN_FILE_ENV, RUN_SECRET_ENV
from shadow_mission.feasibility import internal_session_environment, run_installed_cache_hook


MISSION_ENV_KEYS = {
    RUN_FILE_ENV,
    RUN_SECRET_ENV,
    "SHADOW_MISSION_COLLECTOR_URL",
    "SHADOW_MISSION_CORRELATION_ID",
    "SHADOW_MISSION_LOG_GROUP_ID",
}


def test_internal_session_environment_strips_all_activation_and_correlation() -> None:
    parent = {key: f"value-for-{key}" for key in MISSION_ENV_KEYS}
    parent["PATH"] = "/usr/bin"
    parent["UNRELATED_SAFE_VALUE"] = "retained"

    child = internal_session_environment(parent)

    assert MISSION_ENV_KEYS.isdisjoint(child)
    assert child["PATH"] == "/usr/bin"
    assert child["UNRELATED_SAFE_VALUE"] == "retained"
    assert child["SHADOW_MISSION_INTERNAL"] == "1"


def test_plugin_stays_inert_for_internal_session_even_if_cached(tmp_path: Path) -> None:
    environment = internal_session_environment(
        {
            RUN_FILE_ENV: "/private/run/descriptor.json",
            RUN_SECRET_ENV: "must-be-removed",
        }
    )
    result = run_installed_cache_hook(
        Path.cwd(),
        {
            "hook_event_name": "SessionStart",
            "session_id": "internal-probe",
            "transcript_path": "/private/internal.jsonl",
            "cwd": "/private/internal",
        },
        environment=environment,
        cache_parent=tmp_path,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
