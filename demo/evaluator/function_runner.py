#!/usr/bin/env python3
"""Run one bounded Mission function without hidden evaluator logic."""

from __future__ import annotations

import importlib.util
import json
import math
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

CHILD_RESULT_LIMIT_BYTES = 4 << 10
CHILD_REQUEST_LIMIT_BYTES = 4 << 10
_FUNCTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class RunnerError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _is_bounded_value(value: object, *, depth: int = 0) -> bool:
    if depth > 3:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -(1 << 63) <= value < (1 << 63)
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, str):
        return len(value.encode("utf-8")) <= 1024
    if isinstance(value, list):
        return len(value) <= 16 and all(
            _is_bounded_value(item, depth=depth + 1) for item in value
        )
    if isinstance(value, dict):
        return len(value) <= 16 and all(
            isinstance(key, str)
            and 0 < len(key.encode("utf-8")) <= 128
            and _is_bounded_value(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def _load_module(path: Path):
    specification = importlib.util.spec_from_file_location(
        "shadow_mission_function",
        path,
    )
    if specification is None or specification.loader is None:
        raise RunnerError("function runner cannot load Mission module")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _run(arguments: Sequence[str]) -> dict[str, object]:
    if len(arguments) != 3 or not _FUNCTION_NAME.fullmatch(arguments[1]):
        raise RunnerError("function runner arguments are invalid")
    request_bytes = sys.stdin.buffer.read(CHILD_REQUEST_LIMIT_BYTES + 1)
    if len(request_bytes) > CHILD_REQUEST_LIMIT_BYTES:
        raise RunnerError("function runner request exceeds its byte limit")
    request = json.loads(request_bytes)
    if (
        not isinstance(request, Mapping)
        or set(request) != {"args"}
        or not isinstance(request["args"], list)
        or not _is_bounded_value(request["args"])
        or canonical_json(request) + b"\n" != request_bytes
    ):
        raise RunnerError("function runner request is invalid")

    module_path = Path(arguments[0]).resolve(strict=True)
    import_root = Path(arguments[2]).resolve(strict=True)
    if not import_root.is_dir() or import_root not in module_path.parents:
        raise RunnerError("function runner source boundary is invalid")
    sys.path.insert(0, str(import_root))
    function = getattr(_load_module(module_path), arguments[1])
    if not callable(function):
        raise RunnerError("function runner target is not callable")
    result_bytes = canonical_json(function(*request["args"]))
    if len(result_bytes) > CHILD_RESULT_LIMIT_BYTES:
        raise RunnerError("function result exceeds its byte limit")
    normalized = json.loads(result_bytes)
    if not _is_bounded_value(normalized):
        raise RunnerError("function result is outside the allowed schema")
    payload: dict[str, object] = {"ok": True, "value": normalized}
    if len(canonical_json(payload)) > CHILD_RESULT_LIMIT_BYTES:
        raise RunnerError("function payload exceeds its byte limit")
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    try:
        payload = _run(tuple(sys.argv[1:] if argv is None else argv))
    except BaseException:
        payload = {"ok": False}
    try:
        sys.stdout.flush()
        sys.stdout.buffer.write(canonical_json(payload) + b"\n")
        sys.stdout.buffer.flush()
    except BaseException:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
