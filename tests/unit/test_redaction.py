from pathlib import Path

import pytest

from shadow_mission.redaction import (
    resolve_repository_path,
    sanitize_value,
    strip_shadow_markers,
)


@pytest.mark.parametrize(
    "secret",
    [
        "Bearer abc.def.ghi",
        "FACTORY_API_KEY=private-value",
        "password=hunter2",
        "session_id=raw-session-123",
        "transcript_path=/Users/operator/private/transcript.jsonl",
        "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----",
    ],
)
def test_secret_canary_corpus_is_redacted_before_persistence(secret: str) -> None:
    value, status = sanitize_value({"visible": f"prefix {secret} suffix"})

    assert status == "redacted"
    assert secret not in str(value)


def test_intervention_markers_are_removed_from_later_model_input() -> None:
    assert (
        strip_shadow_markers(
            "Before [shadow:risk-123] inspect cents [shadow:delivery-7] after"
        )
        == "Before inspect cents after"
    )


def test_repository_path_guard_allows_source_and_rejects_private_or_escape(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    source = repository / "src/module.py"
    source.parent.mkdir()
    source.write_text("pass\n")

    assert resolve_repository_path(repository, "src/module.py") == source
    for forbidden in (
        "../outside.txt",
        ".env",
        ".git/config",
        ".shadow-mission/events.jsonl",
        "credentials/token.json",
        str(source),
    ):
        with pytest.raises(ValueError):
            resolve_repository_path(repository, forbidden)
