"""Monotonic transcript and fallback evidence adapters."""

from __future__ import annotations

import hashlib
import json
import re
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .protocol import (
    EvidenceRecord,
    HookEnvelope,
    canonical_json,
    is_edit_tool,
    is_test_command,
    tool_input_paths,
    tool_result_failed,
)
from .redaction import sanitize_value, strip_shadow_markers

MAX_TRANSCRIPT_READ_BYTES = 1 << 20
MAX_TRANSCRIPT_LINE_BYTES = 256 << 10
MAX_TRANSCRIPT_ALIASES = 256
MAX_RECORDS_PER_READ = 1_000
MAX_PENDING_FACTORY_TOOL_USES = 256
_SHADOW_MARKER = re.compile(r"\[shadow:([A-Za-z0-9._:-]{1,160})\]")
_UNSUCCESSFUL_FACTORY_TOOL_RESULT = re.compile(
    r"\b(?:cancelled|canceled|denied|rejected)\b",
    re.IGNORECASE,
)


class TranscriptError(ValueError):
    """Transcript identity, boundary, or content failed closed."""


@dataclass(frozen=True)
class TranscriptObservation:
    evidence: EvidenceRecord
    content: Mapping[str, Any]
    shadow_marker_ids: tuple[str, ...] = ()
    correction_candidate: bool = False


@dataclass
class _Cursor:
    relative_components: tuple[str, ...]
    descriptor: int | None
    device: int
    inode: int
    parent_identities: tuple[tuple[int, int], ...]
    observed_size: int
    offset: int = 0


class TranscriptReader:
    """Read each trusted transcript alias once at complete JSONL boundaries."""

    def __init__(
        self,
        trusted_root: Path,
        *,
        run_id: str,
        mode: str,
        provenance_status: str,
        fallback_semantic_equivalence: bool = False,
    ) -> None:
        if mode not in {"primary", "fallback"}:
            raise ValueError("transcript mode must be primary or fallback")
        if provenance_status not in {"hook_authenticated", "untrusted_provenance"}:
            raise ValueError("invalid transcript provenance")
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise TranscriptError("secure transcript access is unavailable")
        trusted_root_location = Path(os.path.abspath(trusted_root))
        try:
            root_descriptor = os.open(
                trusted_root_location,
                os.O_RDONLY
                | nofollow
                | directory
                | getattr(os, "O_CLOEXEC", 0),
            )
            root_metadata = os.fstat(root_descriptor)
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise TranscriptError("trusted transcript root is invalid")
        except TranscriptError:
            if "root_descriptor" in locals():
                os.close(root_descriptor)
            raise
        except OSError as error:
            if "root_descriptor" in locals():
                os.close(root_descriptor)
            raise TranscriptError("trusted transcript root is invalid") from error
        self._trusted_root_location: Path | None = trusted_root_location
        self._root_descriptor: int | None = root_descriptor
        self.run_id = run_id
        self.mode = mode
        self.provenance_status = provenance_status
        self.fallback_semantic_equivalence = fallback_semantic_equivalence
        self._cursors: dict[str, _Cursor] = {}
        self._relative_aliases: dict[tuple[str, ...], str] = {}
        self._identity_aliases: dict[tuple[int, int], str] = {}
        self._dropped_records: dict[str, int] = {}
        self._pending_factory_tool_uses: dict[
            tuple[str, str], dict[str, Any]
        ] = {}


    def read_primary(
        self, session_alias: str, transcript_alias: str, transcript_path: Path
    ) -> tuple[TranscriptObservation, ...]:
        if self.mode != "primary":
            raise TranscriptError("primary transcript access is disabled")
        cursor = self._register(transcript_alias, transcript_path)
        current_descriptor, metadata, parent_identities = self._open_relative_file(
            cursor.relative_components
        )
        try:
            if parent_identities != cursor.parent_identities:
                raise TranscriptError("transcript path changed identity")
            inode_changed = (metadata.st_dev, metadata.st_ino) != (
                cursor.device,
                cursor.inode,
            )
        finally:
            os.close(current_descriptor)
        if inode_changed:
            cursor = self._reregister(transcript_alias, transcript_path)
        descriptor = cursor.descriptor
        if descriptor is None:
            raise TranscriptError("transcript reader is closed")
        metadata = self._validated_file_metadata(descriptor)
        if metadata.st_size < cursor.offset:
            raise TranscriptError("transcript shrank or changed identity")
        if (metadata.st_dev, metadata.st_ino) != (cursor.device, cursor.inode):
            cursor = self._reregister(transcript_alias, transcript_path)
            descriptor = cursor.descriptor
            if descriptor is None:
                raise TranscriptError("transcript reader is closed")
            metadata = self._validated_file_metadata(descriptor)
        chunk = self._read_descriptor(descriptor, cursor.offset)
        after_read = self._validated_file_metadata(descriptor)
        if (
            (after_read.st_dev, after_read.st_ino)
            != (cursor.device, cursor.inode)
            or after_read.st_size < metadata.st_size
        ):
            self._reregister(transcript_alias, transcript_path)
            return ()
        cursor.observed_size = after_read.st_size
        if len(chunk) > MAX_TRANSCRIPT_READ_BYTES:
            chunk = chunk[:MAX_TRANSCRIPT_READ_BYTES]
        complete_end = chunk.rfind(b"\n") + 1
        if complete_end == 0:
            oversized_end = self._oversized_line_end(
                descriptor,
                cursor.offset,
                after_read.st_size,
            )
            if oversized_end is None:
                return ()
            cursor.offset = oversized_end
            self._note_drop(transcript_alias)
            return ()
        lines = chunk[:complete_end].splitlines(keepends=True)
        if len(lines) > MAX_RECORDS_PER_READ:
            lines = lines[:MAX_RECORDS_PER_READ]
            complete_end = sum(len(line) for line in lines)


        observations: list[TranscriptObservation] = []
        relative_offset = 0
        for line in lines:
            if len(line) > MAX_TRANSCRIPT_LINE_BYTES:
                self._note_drop(transcript_alias)
                relative_offset += len(line)
                continue
            body = line[:-1]
            start = cursor.offset + relative_offset
            end = start + len(line)
            relative_offset += len(line)
            try:
                value = json.loads(body)
            except (json.JSONDecodeError, UnicodeError):
                self._note_drop(transcript_alias)
                continue
            if not isinstance(value, Mapping):
                self._note_drop(transcript_alias)
                continue
            visibles = self._visible_records(value)
            if not visibles:
                continue
            for index, visible in enumerate(visibles):
                marker_ids = self._assistant_marker_ids(visible)
                sanitized, redaction_status = sanitize_value(visible)
                if not isinstance(sanitized, Mapping):
                    self._note_drop(transcript_alias)
                    continue
                content = self._strip_markers(dict(sanitized))
                content = self._pair_factory_tool(transcript_alias, content)
                # Classify the persisted content, never the raw record, so one
                # correction candidate always carries bindable evidence.
                correction_candidate = self._is_correction_candidate(content)
                digest = hashlib.sha256(canonical_json(content)).hexdigest()
                identity = (
                    f"{self.run_id}\0{transcript_alias}\0{start}\0{end}\0{digest}"
                )
                if len(visibles) > 1:
                    identity = f"{identity}\0{index}"
                evidence_id = "evidence-" + hashlib.sha256(
                    identity.encode()
                ).hexdigest()
                observed_at = value.get("observed_at", 0)
                if not isinstance(observed_at, int) or isinstance(observed_at, bool):
                    observed_at = 0
                observations.append(
                    TranscriptObservation(
                        evidence=EvidenceRecord(
                            provenance_status=self._evidence_provenance(),
                            redaction_status=redaction_status,
                            evidence_id=evidence_id,
                            run_id=self.run_id,
                            session_alias=session_alias,
                            kind=str(content["kind"]),
                            source="transcript",
                            locator=f"{transcript_alias}@{start}:{end}",
                            digest=digest,
                            observed_at=observed_at,
                        ),
                        content=content,
                        shadow_marker_ids=marker_ids,
                        correction_candidate=correction_candidate,
                    )
                )
        cursor.offset += complete_end
        return tuple(observations)

    def read_fallback(self, envelope: HookEnvelope) -> tuple[TranscriptObservation, ...]:
        self._require_open()
        if self.mode != "fallback":
            raise TranscriptError("fallback event access is disabled")
        if not self.fallback_semantic_equivalence:
            raise TranscriptError("fallback semantic equivalence is not frozen")
        visible = self._visible_fallback(envelope)
        if visible is None:
            return ()
        sanitized, status = sanitize_value(visible)
        if not isinstance(sanitized, Mapping):
            raise TranscriptError("fallback evidence is invalid")
        content = self._strip_markers(dict(sanitized))
        digest = hashlib.sha256(canonical_json(content)).hexdigest()
        evidence_id = "evidence-" + hashlib.sha256(
            f"{self.run_id}\0{envelope.event_id}\0{digest}".encode()
        ).hexdigest()
        return (
            TranscriptObservation(
                evidence=EvidenceRecord(
                    provenance_status=self._evidence_provenance(envelope.provenance_status),
                    redaction_status=(
                        "redacted"
                        if "redacted" in {envelope.redaction_status, status}
                        else "clean"
                    ),
                    evidence_id=evidence_id,
                    run_id=self.run_id,
                    session_alias=envelope.session_alias,
                    kind=str(content["kind"]),
                    source="hook_fallback",
                    locator=f"event:{envelope.event_id}",
                    digest=digest,
                    observed_at=envelope.observed_at,
                ),
                content=content,
            ),
        )

    def cursor_offsets(self) -> dict[str, int]:
        return {
            alias: cursor.offset
            for alias, cursor in sorted(self._cursors.items())
        }

    def close(self) -> None:
        """Close all trusted descriptors. Repeated calls are safe."""

        root_descriptor = self._root_descriptor
        if root_descriptor is None:
            return
        descriptors: list[int] = []
        for cursor in self._cursors.values():
            if cursor.descriptor is not None:
                descriptors.append(cursor.descriptor)
        descriptors.append(root_descriptor)
        for cursor in self._cursors.values():
            cursor.descriptor = None
            cursor.relative_components = ()
        self._root_descriptor = None
        self._trusted_root_location = None
        self._relative_aliases.clear()
        self._identity_aliases.clear()
        self._pending_factory_tool_uses.clear()
        failed = False
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                failed = True
        if failed:
            raise TranscriptError("transcript descriptor cleanup failed")

    def dropped_records(self) -> dict[str, int]:
        return dict(self._dropped_records)

    def _note_drop(self, alias: str) -> None:
        self._dropped_records[alias] = self._dropped_records.get(alias, 0) + 1

    def _evidence_provenance(self, status: str | None = None) -> str:
        current = status or self.provenance_status
        if current == "untrusted_provenance":
            return "collector_observed"
        return current

    def _reregister(self, alias: str, path: Path) -> _Cursor:
        self._discard_pending_factory_tool_uses(alias)
        existing = self._cursors.pop(alias, None)
        if existing is not None:
            self._relative_aliases.pop(existing.relative_components, None)
            self._identity_aliases.pop((existing.device, existing.inode), None)
            if existing.descriptor is not None:
                try:
                    os.close(existing.descriptor)
                except OSError:
                    pass
        return self._register(alias, path)

    def _register(self, alias: str, path: Path) -> _Cursor:
        self._require_open()
        if not alias:
            raise TranscriptError("transcript alias must not be empty")
        relative_components = self._relative_components(path)
        existing = self._cursors.get(alias)
        if existing is not None:
            if existing.relative_components != relative_components:
                raise TranscriptError("transcript alias changed path")
            return existing
        if len(self._cursors) >= MAX_TRANSCRIPT_ALIASES:
            raise TranscriptError("transcript alias count exceeds bound")
        descriptor, metadata, parent_identities = self._open_relative_file(
            relative_components
        )
        identity = (metadata.st_dev, metadata.st_ino)
        try:
            prior_alias = self._relative_aliases.get(relative_components)
            identity_alias = self._identity_aliases.get(identity)
            if (
                prior_alias is not None
                and prior_alias != alias
                or identity_alias is not None
                and identity_alias != alias
            ):
                raise TranscriptError("transcript path has two aliases")
            cursor = _Cursor(
                relative_components=relative_components,
                descriptor=descriptor,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                parent_identities=parent_identities,
                observed_size=metadata.st_size,
            )
            self._cursors[alias] = cursor
            self._relative_aliases[relative_components] = alias
            self._identity_aliases[identity] = alias
            return cursor
        except BaseException:
            os.close(descriptor)
            raise

    def _require_open(self) -> tuple[int, Path]:
        if (
            self._root_descriptor is None
            or self._trusted_root_location is None
        ):
            raise TranscriptError("transcript reader is closed")
        return self._root_descriptor, self._trusted_root_location

    def _relative_components(self, path: Path) -> tuple[str, ...]:
        _, trusted_root_location = self._require_open()
        candidate = Path(os.path.abspath(path))
        try:
            relative = candidate.relative_to(trusted_root_location)
        except ValueError as error:
            raise TranscriptError("transcript escaped the trusted root") from error
        components = relative.parts
        if not components or any(
            component in {"", ".", ".."} for component in components
        ):
            raise TranscriptError("transcript path is invalid")
        return components

    def _open_relative_file(
        self, relative_components: tuple[str, ...]
    ) -> tuple[int, os.stat_result, tuple[tuple[int, int], ...]]:
        root_descriptor, _ = self._require_open()
        try:
            parent_descriptor = os.dup(root_descriptor)
        except OSError as error:
            raise TranscriptError("trusted transcript root is unavailable") from error
        file_descriptor: int | None = None
        parent_identities: list[tuple[int, int]] = []
        try:
            parent_flags = (
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
            )
            for component in relative_components[:-1]:
                next_descriptor = os.open(
                    component, parent_flags, dir_fd=parent_descriptor
                )
                metadata = os.fstat(next_descriptor)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(next_descriptor)
                    raise TranscriptError("transcript parent is not a directory")
                parent_identities.append((metadata.st_dev, metadata.st_ino))
                os.close(parent_descriptor)
                parent_descriptor = next_descriptor
            file_descriptor = os.open(
                relative_components[-1],
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_descriptor,
            )
            metadata = self._validated_file_metadata(file_descriptor)
            return (
                file_descriptor,
                metadata,
                tuple(parent_identities),
            )
        except TranscriptError:
            if file_descriptor is not None:
                os.close(file_descriptor)
            raise
        except OSError as error:
            if file_descriptor is not None:
                os.close(file_descriptor)
            raise TranscriptError("transcript path is unavailable") from error
        finally:
            os.close(parent_descriptor)

    @staticmethod
    def _validated_file_metadata(descriptor: int) -> os.stat_result:
        try:
            metadata = os.fstat(descriptor)
        except OSError as error:
            raise TranscriptError("transcript descriptor is unavailable") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise TranscriptError("transcript is not a regular file")
        return metadata

    @staticmethod
    def _read_descriptor(descriptor: int, offset: int) -> bytes:
        remaining = MAX_TRANSCRIPT_READ_BYTES + 1
        chunks: list[bytes] = []
        position = offset
        try:
            while remaining:
                chunk = os.pread(descriptor, remaining, position)
                if not chunk:
                    break
                chunks.append(chunk)
                position += len(chunk)
                remaining -= len(chunk)
        except OSError as error:
            raise TranscriptError("transcript read failed") from error
        return b"".join(chunks)

    @staticmethod
    def _oversized_line_end(
        descriptor: int,
        offset: int,
        observed_size: int,
    ) -> int | None:
        position = offset + MAX_TRANSCRIPT_READ_BYTES
        try:
            while position < observed_size:
                chunk = os.pread(
                    descriptor,
                    min(MAX_TRANSCRIPT_READ_BYTES, observed_size - position),
                    position,
                )
                if not chunk:
                    return None
                newline = chunk.find(b"\n")
                if newline >= 0:
                    return position + newline + 1
                position += len(chunk)
        except OSError as error:
            raise TranscriptError("transcript read failed") from error
        return None

    @staticmethod
    def _assistant_marker_ids(value: Mapping[str, Any]) -> tuple[str, ...]:
        if value.get("kind") != "assistant" or type(value.get("text")) is not str:
            return ()
        return tuple(
            dict.fromkeys(match.group(1) for match in _SHADOW_MARKER.finditer(value["text"]))
        )

    def _discard_pending_factory_tool_uses(self, transcript_alias: str) -> None:
        for key in tuple(self._pending_factory_tool_uses):
            if key[0] == transcript_alias:
                del self._pending_factory_tool_uses[key]

    def _pair_factory_tool(
        self, transcript_alias: str, content: dict[str, Any]
    ) -> dict[str, Any]:
        block_type = content.get("factory_tool_block_type")
        if block_type == "tool_use":
            tool_use_id = content.get("factory_tool_use_id")
            if type(tool_use_id) is not str or not tool_use_id.strip():
                return content
            tool_name = content.get("tool_name", "")
            tool_input = content.get("tool_input")
            if not is_edit_tool(tool_name) and not is_test_command(tool_input):
                return content
            key = (transcript_alias, tool_use_id)
            self._pending_factory_tool_uses.pop(key, None)
            if len(self._pending_factory_tool_uses) >= MAX_PENDING_FACTORY_TOOL_USES:
                oldest = next(iter(self._pending_factory_tool_uses))
                del self._pending_factory_tool_uses[oldest]
            self._pending_factory_tool_uses[key] = {
                "factory_tool_use_id": tool_use_id,
                "tool_name": tool_name,
                "tool_input": tool_input,
            }
            return content
        if block_type != "tool_result":
            return content
        tool_use_id = content.get("factory_tool_result_use_id")
        if type(tool_use_id) is not str or not tool_use_id.strip():
            return content
        pending = self._pending_factory_tool_uses.pop(
            (transcript_alias, tool_use_id), None
        )
        if pending is None:
            return content
        paired = dict(content)
        paired.update(pending)
        return paired

    @staticmethod
    def _is_correction_candidate(value: Mapping[str, Any]) -> bool:
        kind = value.get("kind")
        if kind == "tool":
            return TranscriptReader._is_tool_correction(value)
        if kind == "diff":
            return (
                type(value.get("file")) is str
                and bool(value["file"].strip())
                and type(value.get("diff")) is str
                and bool(value["diff"].strip())
            )
        if kind != "test":
            return False
        result = value.get("result")
        if not isinstance(result, Mapping):
            return False
        if result.get("success") is True:
            return True
        status = result.get("status")
        if type(status) is str and status.strip().lower() in {
            "passed",
            "success",
            "succeeded",
        }:
            return True
        exit_code = result.get("exit_code")
        return type(exit_code) is int and exit_code == 0

    @staticmethod
    def _is_tool_correction(value: Mapping[str, Any]) -> bool:
        """Accept one real Factory source edit or passing test as correction work."""

        response = value.get("tool_response")
        factory_block_type = value.get("factory_tool_block_type")
        if factory_block_type is not None:
            if factory_block_type != "tool_result":
                return False
            tool_use_id = value.get("factory_tool_use_id")
            result_use_id = value.get("factory_tool_result_use_id")
            if (
                type(tool_use_id) is not str
                or type(result_use_id) is not str
                or not tool_use_id
                or tool_use_id != result_use_id
            ):
                return False
            is_error = value.get("factory_tool_result_is_error")
            if is_error is not None and is_error is not False:
                return False
            result_status = value.get("factory_tool_result_status")
            if _UNSUCCESSFUL_FACTORY_TOOL_RESULT.search(str(result_status or "")):
                return False
            if _UNSUCCESSFUL_FACTORY_TOOL_RESULT.search(str(response or "")):
                return False
        if tool_result_failed(response):
            return False
        tool_input = value.get("tool_input")
        if is_edit_tool(value.get("tool_name")):
            return response is not None and bool(tool_input_paths(tool_input))
        return response is not None and is_test_command(tool_input)

    @staticmethod
    def _strip_markers(value: Any) -> Any:
        if isinstance(value, str):
            return strip_shadow_markers(value)
        if isinstance(value, list):
            return [TranscriptReader._strip_markers(item) for item in value]
        if isinstance(value, dict):
            return {
                str(key): TranscriptReader._strip_markers(item)
                for key, item in value.items()
            }
        return value

    @staticmethod
    def _factory_text(content: object) -> str:
        if isinstance(content, str):
            return content
        if not isinstance(content, list):
            return ""
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
                continue
            if not isinstance(block, Mapping):
                continue
            block_type = str(block.get("type", "")).lower()
            if block_type == "text" and type(block.get("text")) is str:
                parts.append(block["text"])
            elif block_type == "thinking" and type(block.get("thinking")) is str:
                parts.append(block["thinking"])
        return "\n".join(parts)

    @staticmethod
    def _factory_tool(content: object) -> dict[str, Any] | None:
        if not isinstance(content, list):
            return None
        for block in content:
            if not isinstance(block, Mapping):
                continue
            block_type = str(block.get("type", block.get("kind", ""))).lower()
            if block_type not in {"tool_use", "tool_result"}:
                continue
            tool: dict[str, Any] = {
                "kind": "tool",
                "tool_name": block.get("name", block.get("tool_name", "")),
                "tool_input": block.get("input", block.get("tool_input")),
                "tool_response": block.get(
                    "content",
                    block.get("output", block.get("tool_response")),
                ),
                "factory_tool_block_type": block_type,
            }
            if block_type == "tool_use":
                if "id" in block:
                    tool["factory_tool_use_id"] = block["id"]
                return tool
            if "tool_use_id" in block:
                tool["factory_tool_result_use_id"] = block["tool_use_id"]
            if "is_error" in block:
                tool["factory_tool_result_is_error"] = block["is_error"]
            if "status" in block:
                tool["factory_tool_result_status"] = block["status"]
            return tool
        return None

    @staticmethod
    def _visible_records(value: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
        record_type = str(value.get("type", "")).lower()
        nested = value.get("message")
        if record_type == "session_start":
            title = value.get("title", "")
            return (({"kind": "prompt", "text": title},) if title else ())
        if record_type == "message" and isinstance(nested, Mapping):
            content = nested.get("content")
            records: list[dict[str, Any]] = []
            text = TranscriptReader._factory_text(content)
            if text:
                role = str(nested.get("role", "")).lower()
                records.append(
                    {"kind": "assistant", "text": text}
                    if role == "assistant"
                    else {"kind": "prompt", "text": text}
                )
            if isinstance(content, list):
                for block in content:
                    tool = TranscriptReader._factory_tool(
                        [block] if isinstance(block, Mapping) else []
                    )
                    if tool is not None:
                        records.append(tool)
            return tuple(records)
        single = TranscriptReader._visible_record(value)
        return (single,) if single is not None else ()


    @staticmethod
    def _visible_record(value: Mapping[str, Any]) -> dict[str, Any] | None:
        record_type = str(value.get("type", "")).lower()
        nested = value.get("message")
        if record_type == "session_start":
            title = value.get("title", "")
            return {"kind": "prompt", "text": title} if title else None
        if record_type == "message" and isinstance(nested, Mapping):
            content = nested.get("content")
            tool = TranscriptReader._factory_tool(content)
            if tool is not None:
                return tool
            text = TranscriptReader._factory_text(content)
            if not text:
                return None
            role = str(nested.get("role", "")).lower()
            if role == "assistant":
                return {"kind": "assistant", "text": text}
            return {"kind": "prompt", "text": text}
        kind = str(value.get("kind", record_type)).lower()
        role = str(value.get("role", "")).lower()
        if kind in {"prompt", "user", "user_message"} or role == "user":
            text = value.get("text")
            if text is None:
                text = TranscriptReader._factory_text(value.get("content", ""))
            return {"kind": "prompt", "text": text}
        if kind in {"assistant", "assistant_message"} or role == "assistant":
            text = value.get("text")
            if text is None:
                text = TranscriptReader._factory_text(value.get("content", ""))
            return {"kind": "assistant", "text": text}
        if kind in {"tool_use", "tool_result"}:
            return TranscriptReader._factory_tool([value])
        if kind == "tool":
            return {
                "kind": "tool",
                "tool_name": value.get("tool_name", value.get("name", "")),
                "tool_input": value.get("tool_input", value.get("input")),
                "tool_response": value.get("tool_response", value.get("output")),
            }
        if kind in {"diff", "patch"}:
            visible_diff = {
                "kind": "diff",
                "file": value.get("file", ""),
                "diff": value.get("diff", value.get("content", "")),
            }
            if "intervention_id" in value:
                visible_diff["intervention_id"] = value["intervention_id"]
            return visible_diff
        if kind in {"test", "test_result"}:
            visible_test = {
                "kind": "test",
                "command": value.get("command", ""),
                "result": value.get("result", value.get("output", "")),
            }
            if "intervention_id" in value:
                visible_test["intervention_id"] = value["intervention_id"]
            return visible_test
        return None

    @staticmethod
    def _visible_fallback(envelope: HookEnvelope) -> dict[str, Any] | None:
        payload = envelope.payload
        if envelope.hook_event_name in {"SessionStart", "UserPromptSubmit"} and "prompt" in payload:
            return {"kind": "prompt", "text": payload["prompt"]}
        if envelope.hook_event_name == "PostToolUse":
            return {
                "kind": "tool",
                "tool_name": payload.get("tool_name", ""),
                "tool_input": payload.get("tool_input"),
                "tool_response": payload.get("tool_response"),
            }
        return None
