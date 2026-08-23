from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import shadow_mission.transcript as transcript_module

from shadow_mission.protocol import HookEnvelope, tool_observation_paths
from shadow_mission.transcript import TranscriptError, TranscriptReader


def append(path: Path, *records: object, newline: bool = True) -> None:
    with path.open("ab") as handle:
        for index, record in enumerate(records):
            handle.write(json.dumps(record, sort_keys=True).encode())
            if newline or index < len(records) - 1:
                handle.write(b"\n")


def factory_message(*content: object, role: str = "assistant") -> dict[str, object]:
    return {
        "type": "message",
        "message": {"role": role, "content": list(content)},
    }


def test_primary_reader_emits_visible_records_once_at_complete_boundaries(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        {"kind": "prompt", "text": "Inspect cents", "observed_at": 1},
        {"kind": "internal", "text": "hidden"},
        {"kind": "assistant", "text": "Use [shadow:risk-1] cents", "observed_at": 2},
    )

    first = reader.read_primary("session-a", "transcript-a", transcript)
    second = reader.read_primary("session-a", "transcript-a", transcript)

    assert [item.content["kind"] for item in first] == ["prompt", "assistant"]
    assert first[1].content["text"] == "Use cents"
    assert first[1].shadow_marker_ids == ("risk-1",)
    assert all(item.evidence.session_alias == "session-a" for item in first)
    assert second == ()
    assert reader.cursor_offsets()["transcript-a"] == transcript.stat().st_size
    reader.close()



def test_only_structured_diff_or_successful_test_is_a_correction_candidate(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        {"kind": "tool", "output": "[shadow:tool-marker]"},
        {
            "kind": "diff",
            "file": "src/a.py",
            "diff": "+fixed",
            "intervention_id": "intervention-diff",
        },
        {
            "kind": "test",
            "command": "pytest",
            "result": "passed",
            "intervention_id": "intervention-test",
        },
        {
            "kind": "test",
            "command": "pytest",
            "result": {"status": "passed", "tests": 1},
        },
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert all(item.shadow_marker_ids == () for item in observations)
    assert tuple(item.correction_candidate for item in observations) == (
        False,
        True,
        False,
        True,
    )
    assert observations[1].content["intervention_id"] == "intervention-diff"
    assert observations[2].content["intervention_id"] == "intervention-test"
    reader.close()

def test_unpaired_edit_is_not_correction_evidence(tmp_path: Path) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        {
            "kind": "tool",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/webhook.py"},
        },
    )

    observations = reader.read_primary(
        "session-a",
        "transcript-a",
        transcript,
    )

    assert len(observations) == 1
    assert observations[0].correction_candidate is False
    reader.close()


def test_factory_edit_requires_its_paired_successful_result(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        factory_message(
            {
                "type": "tool_use",
                "id": "tool-edit-success",
                "name": "Edit",
                "input": {"file_path": "src/webhook.py"},
            }
        ),
        factory_message(
            {
                "type": "tool_result",
                "tool_use_id": "tool-edit-success",
                "content": {"status": "success"},
                "is_error": False,
            },
            role="user",
        ),
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert tuple(item.correction_candidate for item in observations) == (
        False,
        True,
    )
    assert observations[1].content["factory_tool_use_id"] == "tool-edit-success"
    assert (
        observations[1].content["factory_tool_result_use_id"]
        == "tool-edit-success"
    )
    reader.close()


def test_factory_edit_with_is_error_result_is_not_a_correction_candidate(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        factory_message(
            {
                "type": "tool_use",
                "id": "tool-edit-error",
                "name": "Edit",
                "input": {"file_path": "src/webhook.py"},
            }
        ),
        factory_message(
            {
                "type": "tool_result",
                "tool_use_id": "tool-edit-error",
                "content": "Edit failed",
                "is_error": True,
            },
            role="user",
        ),
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert not any(item.correction_candidate for item in observations)
    reader.close()


def test_factory_edit_without_a_result_is_not_a_correction_candidate(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        factory_message(
            {
                "type": "tool_use",
                "id": "tool-edit-pending",
                "name": "Edit",
                "input": {"file_path": "src/webhook.py"},
            }
        ),
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert len(observations) == 1
    assert observations[0].correction_candidate is False
    reader.close()


def test_factory_result_with_a_different_tool_use_id_does_not_complete_edit(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        factory_message(
            {
                "type": "tool_use",
                "id": "tool-edit-expected",
                "name": "Edit",
                "input": {"file_path": "src/webhook.py"},
            }
        ),
        factory_message(
            {
                "type": "tool_result",
                "tool_use_id": "tool-edit-other",
                "content": "Updated src/webhook.py",
                "is_error": False,
            },
            role="user",
        ),
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert not any(item.correction_candidate for item in observations)
    reader.close()


def test_factory_edit_pairs_across_cursor_batches_with_bounded_pending_state(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        factory_message(
            {
                "type": "tool_use",
                "id": "tool-edit-split",
                "name": "Edit",
                "input": {"file_path": "src/webhook.py"},
            }
        ),
    )

    first = reader.read_primary("session-a", "transcript-a", transcript)
    append(
        transcript,
        factory_message(
            {
                "type": "tool_result",
                "tool_use_id": "tool-edit-split",
                "content": "Updated src/webhook.py",
                "is_error": False,
            },
            role="user",
        ),
    )
    second = reader.read_primary("session-a", "transcript-a", transcript)

    assert len(first) == 1
    assert first[0].correction_candidate is False
    assert len(second) == 1
    assert second[0].correction_candidate is True

    limit = transcript_module.MAX_PENDING_FACTORY_TOOL_USES
    append(
        transcript,
        *(
            factory_message(
                {
                    "type": "tool_use",
                    "id": f"pending-tool-{index}",
                    "name": "Edit",
                    "input": {"file_path": f"src/pending_{index}.py"},
                }
            )
            for index in range(limit + 1)
        ),
    )
    reader.read_primary("session-a", "transcript-a", transcript)

    assert len(reader._pending_factory_tool_uses) == limit
    assert (
        "transcript-a",
        "pending-tool-0",
    ) not in reader._pending_factory_tool_uses
    assert (
        "transcript-a",
        f"pending-tool-{limit}",
    ) in reader._pending_factory_tool_uses
    reader.close()


@pytest.mark.parametrize(
    "result_content",
    (
        "Tool use was denied by the user",
        {"status": "cancelled"},
    ),
)
def test_factory_denied_or_cancelled_edit_is_not_a_correction_candidate(
    tmp_path: Path,
    result_content: object,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        factory_message(
            {
                "type": "tool_use",
                "id": "tool-edit-rejected",
                "name": "Edit",
                "input": {"file_path": "src/webhook.py"},
            }
        ),
        factory_message(
            {
                "type": "tool_result",
                "tool_use_id": "tool-edit-rejected",
                "content": result_content,
                "is_error": False,
            },
            role="user",
        ),
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert not any(item.correction_candidate for item in observations)
    reader.close()


def test_factory_paired_test_results_preserve_test_correction_classification(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        factory_message(
            {
                "type": "tool_use",
                "id": "tool-test-pass",
                "name": "Execute",
                "input": {"command": "python3 -m pytest -q tests"},
            }
        ),
        factory_message(
            {
                "type": "tool_result",
                "tool_use_id": "tool-test-pass",
                "content": {"exit_code": 0},
                "is_error": False,
            },
            role="user",
        ),
        factory_message(
            {
                "type": "tool_use",
                "id": "tool-test-fail",
                "name": "Execute",
                "input": {"command": "python3 -m pytest -q tests"},
            }
        ),
        factory_message(
            {
                "type": "tool_result",
                "tool_use_id": "tool-test-fail",
                "content": {"exit_code": 1},
                "is_error": True,
            },
            role="user",
        ),
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert tuple(item.correction_candidate for item in observations) == (
        False,
        True,
        False,
        False,
    )
    reader.close()


@pytest.mark.parametrize(
    ("patch_action", "path"),
    (
        ("Update", "/repo/src/webhook.py"),
        ("Add", "/repo/src/new_hook.py"),
        ("Delete", "/repo/src/obsolete_hook.py"),
    ),
)
def test_collapsed_patch_text_still_names_successful_source_edit_paths(
    tmp_path: Path,
    patch_action: str,
    path: str,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.touch()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    append(
        transcript,
        factory_message(
            {
                "type": "tool_use",
                "id": "tool-apply-patch",
                "name": "ApplyPatch",
                "input": {
                    "input": (
                        "*** Begin Patch\n"
                        f"*** {patch_action} File: {path}\n"
                        "@@\n-old\n+new\n*** End Patch\n"
                    )
                },
            }
        ),
        factory_message(
            {
                "type": "tool_result",
                "tool_use_id": "tool-apply-patch",
                "content": "Done!",
                "is_error": False,
            },
            role="user",
        ),
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert len(observations) == 2
    assert observations[0].correction_candidate is False
    assert observations[1].correction_candidate is True
    # Redaction collapses newlines before persistence, so the persisted
    # paired result must still name the changed path.
    assert "\n" not in observations[1].content["tool_input"]["input"]
    assert tool_observation_paths(observations[1].content) == (path,)
    reader.close()


def test_primary_reader_waits_for_partial_record_then_advances(tmp_path: Path) -> None:
    transcript = tmp_path / "worker.jsonl"
    append(transcript, {"kind": "prompt", "text": "partial"}, newline=False)
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )

    assert reader.read_primary("session-a", "transcript-a", transcript) == ()
    assert reader.cursor_offsets()["transcript-a"] == 0
    with transcript.open("ab") as handle:
        handle.write(b"\n")
    observed = reader.read_primary("session-a", "transcript-a", transcript)

    assert len(observed) == 1
    assert observed[0].content == {"kind": "prompt", "text": "partial"}
    reader.close()


def test_primary_reader_rejects_truncation_alias_collision_and_path_escape(
    tmp_path: Path,
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    transcript = trusted / "worker.jsonl"
    append(transcript, {"kind": "prompt", "text": "one"})
    other = tmp_path / "outside.jsonl"
    other.write_text("{}\n")
    reader = TranscriptReader(
        trusted,
        run_id="run-1",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    reader.read_primary("session-a", "transcript-a", transcript)

    with pytest.raises(TranscriptError, match="two aliases"):
        reader.read_primary("session-b", "transcript-b", transcript)
    with pytest.raises(TranscriptError, match="trusted root"):
        reader.read_primary("session-c", "transcript-c", other)
    transcript.write_text("")
    with pytest.raises(TranscriptError, match="shrank"):
        reader.read_primary("session-a", "transcript-a", transcript)
    reader.close()


@pytest.mark.parametrize("replacement_kind", ["entry", "parent", "symlink_parent"])
def test_primary_reader_rejects_path_replacement_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    trusted = tmp_path / "trusted"
    parent = trusted / "session"
    parent.mkdir(parents=True)
    transcript = parent / "worker.jsonl"
    append(transcript, {"kind": "prompt", "text": "approved"})
    reader = TranscriptReader(
        trusted,
        run_id="run-race",
        mode="primary",
        provenance_status="hook_authenticated",
    )
    reader._register("transcript-a", transcript)
    descriptor_reads: list[int] = []
    original_read_descriptor = reader._read_descriptor

    def record_descriptor_read(descriptor: int, offset: int) -> bytes:
        descriptor_reads.append(descriptor)
        return original_read_descriptor(descriptor, offset)

    monkeypatch.setattr(reader, "_read_descriptor", record_descriptor_read)

    if replacement_kind == "entry":
        replacement = parent / "replacement.jsonl"
        append(replacement, {"kind": "prompt", "text": "replacement"})
        os.replace(replacement, transcript)
        observed = reader.read_primary("session-a", "transcript-a", transcript)
        assert [item.content["text"] for item in observed] == ["replacement"]
        reader.close()
        return
    original_parent = trusted / "original-session"
    os.replace(parent, original_parent)
    if replacement_kind == "parent":
        parent.mkdir()
        append(
            parent / "worker.jsonl",
            {"kind": "prompt", "text": "replacement"},
        )
    else:
        parent.symlink_to(original_parent, target_is_directory=True)

    with pytest.raises(TranscriptError):
        reader.read_primary("session-a", "transcript-a", transcript)
    assert reader.cursor_offsets() == {"transcript-a": 0}
    reader.close()
    assert descriptor_reads == []



def test_primary_reader_rejects_nonregular_entry_and_close_is_idempotent(
    tmp_path: Path,
) -> None:
    directory_entry = tmp_path / "not-a-transcript"
    directory_entry.mkdir()
    reader = TranscriptReader(
        tmp_path,
        run_id="run-close",
        mode="primary",
        provenance_status="hook_authenticated",
    )

    with pytest.raises(TranscriptError, match="regular file"):
        reader.read_primary(
            "session-a", "transcript-a", directory_entry
        )
    reader.close()
    reader.close()
    with pytest.raises(TranscriptError, match="closed"):
        reader.read_primary(
            "session-a", "transcript-a", directory_entry
        )


def fallback_envelope(event: str, payload: dict[str, object]) -> HookEnvelope:
    return HookEnvelope(provenance_status="untrusted_provenance",
    redaction_status="clean",
    event_id=f"event-{event}",
    source_fingerprint="source-a",
    run_id="run-1",
    session_alias="session-a",
    transcript_alias="transcript-a",
    hook_event_name=event, observed_at=3, message_digest="d" * 64, payload=payload,)


def test_fallback_requires_semantic_equivalence_and_cannot_make_assistant_evidence(
    tmp_path: Path,
) -> None:
    disabled = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="fallback",
        provenance_status="untrusted_provenance",
    )
    with pytest.raises(TranscriptError, match="semantic equivalence"):
        disabled.read_fallback(fallback_envelope("UserPromptSubmit", {"prompt": "x"}))
    disabled.close()

    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="fallback",
        provenance_status="untrusted_provenance",
        fallback_semantic_equivalence=True,
    )
    prompt = reader.read_fallback(
        fallback_envelope("UserPromptSubmit", {"prompt": "visible"})
    )
    completion = reader.read_fallback(fallback_envelope("Stop", {}))

    assert prompt[0].content == {"kind": "prompt", "text": "visible"}
    assert completion == ()
    assert all(item.content["kind"] != "assistant" for item in prompt)
    reader.close()

def test_unpaired_fallback_edit_is_not_correction_evidence(
    tmp_path: Path,
) -> None:
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="fallback",
        provenance_status="untrusted_provenance",
        fallback_semantic_equivalence=True,
    )

    observations = reader.read_fallback(
        fallback_envelope(
            "PostToolUse",
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": "src/webhook.py"},
            },
        )
    )

    assert len(observations) == 1
    assert observations[0].correction_candidate is False
    reader.close()


def test_factory_message_records_and_tool_blocks_are_visible(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    append(
        transcript,
        {
            "type": "session_start",
            "title": "API worker",
        },
    )
    append(
        transcript,
        {
            "type": "message",
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "Keep integer cents."}],
            },
        },
    )
    append(
        transcript,
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "inspect schema"},
                    {
                        "type": "tool_use",
                        "name": "Read",
                        "input": {"file_path": "api-schema.json"},
                    },
                ],
            },
        },
    )
    append(
        transcript,
        {
            "type": "message",
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_name": "Read",
                        "content": '{"amount":{"unit":"cents"}}',
                    }
                ],
            },
        },
    )
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="untrusted_provenance",
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert [item.content["kind"] for item in observations] == [
        "prompt",
        "prompt",
        "assistant",
        "tool",
        "tool",
    ]
    assert observations[3].content["tool_name"] == "Read"
    assert observations[0].evidence.provenance_status == "collector_observed"
    assert observations[2].content["kind"] == "assistant"

    reader.close()


def test_oversized_line_is_dropped_and_later_records_are_read(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    append(transcript, {"kind": "prompt", "text": "keep"})
    huge = b'{"kind":"assistant","text":"' + (b"x" * (256 << 10)) + b'"}\n'
    with transcript.open("ab") as handle:
        handle.write(huge)
    append(transcript, {"kind": "assistant", "text": "after"})
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="untrusted_provenance",
    )

    observations = reader.read_primary("session-a", "transcript-a", transcript)

    assert [item.content["kind"] for item in observations] == ["prompt", "assistant"]
    assert reader.dropped_records()["transcript-a"] == 1
    reader.close()

def test_line_larger_than_read_bound_advances_before_later_record(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "worker.jsonl"
    transcript.write_bytes(
        b'{"kind":"assistant","text":"'
        + (b"x" * transcript_module.MAX_TRANSCRIPT_READ_BYTES)
        + b'"}\n'
    )
    append(transcript, {"kind": "assistant", "text": "after"})
    reader = TranscriptReader(
        tmp_path,
        run_id="run-1",
        mode="primary",
        provenance_status="untrusted_provenance",
    )

    first = reader.read_primary("session-a", "transcript-a", transcript)
    second = reader.read_primary("session-a", "transcript-a", transcript)

    assert first == ()
    assert [item.content["text"] for item in second] == ["after"]
    assert reader.dropped_records()["transcript-a"] == 1
    assert reader.cursor_offsets()["transcript-a"] == transcript.stat().st_size
    reader.close()
