from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).parents[2]
SEED = PROJECT_ROOT / "demo/seed"
EXPORTER = PROJECT_ROOT / "demo/export_source.py"
EVALUATOR = PROJECT_ROOT / "demo/evaluator/evaluate.py"
FUNCTION_RUNNER = PROJECT_ROOT / "demo/evaluator/function_runner.py"


def make_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "mission-checkout"
    shutil.copytree(SEED, checkout)
    subprocess.run(("git", "init", "-q", str(checkout)), check=True)
    subprocess.run(("git", "-C", str(checkout), "add", "."), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(checkout),
            "-c",
            "user.name=Shadow Demo",
            "-c",
            "user.email=shadow-demo@example.invalid",
            "commit",
            "-qm",
            "seed",
        ),
        check=True,
    )
    return checkout


def export_checkout(checkout: Path, root: Path) -> tuple[Path, Path]:
    artifact_root = root / "artifacts"
    artifact_root.mkdir(parents=True)
    archive = artifact_root / "final-source.tar"
    manifest = artifact_root / "final-source-manifest.json"
    exported = subprocess.run(
        (
            sys.executable,
            str(EXPORTER),
            "--repo",
            str(checkout),
            "--archive",
            str(archive),
            "--manifest",
            str(manifest),
        ),
        capture_output=True,
        text=True,
        shell=False,
    )
    assert exported.returncode == 0, exported.stdout
    return archive, manifest


def evaluate_checkout(
    checkout: Path,
    root: Path,
    *,
    secure_isolation: bool = False,
) -> tuple[subprocess.CompletedProcess[str], dict]:
    archive, manifest_path = export_checkout(checkout, root)
    evaluator_path = EVALUATOR
    if secure_isolation:
        evaluator_root = root / "evaluator-assets"
        evaluator_root.mkdir()
        evaluator_path = evaluator_root / EVALUATOR.name
        shutil.copy2(EVALUATOR, evaluator_path)
        shutil.copy2(
            FUNCTION_RUNNER,
            evaluator_root / FUNCTION_RUNNER.name,
        )
    output = root / "evaluator-result.json"
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    result = subprocess.run(
        (
            sys.executable,
            str(evaluator_path),
            "--archive",
            str(archive),
            "--manifest",
            str(manifest_path),
            "--work-root",
            str(root / "evaluator-source"),
            "--output",
            str(output),
            *(("--secure-isolation",) if secure_isolation else ()),
        ),
        capture_output=True,
        text=True,
        shell=False,
        env=environment,
    )
    record = (
        json.loads(output.read_text(encoding="utf-8"))
        if output.exists()
        else {}
    )
    return result, record


def write_cents_webhook(checkout: Path) -> None:
    (checkout / "src/webhook.py").write_text(
        "from decimal import Decimal\n\n"
        "def parse_webhook(payload):\n"
        "    return {\n"
        "        'payment_id': str(payload['payment_id']),\n"
        "        'amount_cents': int(Decimal(str(payload['amount'])) * 100),\n"
        "        'currency': str(payload.get('currency', 'USD')),\n"
        "    }\n",
        encoding="utf-8",
    )


def load_evaluator_module():
    specification = importlib.util.spec_from_file_location(
        "shadow_demo_evaluator_test",
        EVALUATOR,
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        specification.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def test_hidden_evaluator_fails_intended_dollar_baseline(tmp_path: Path) -> None:
    checkout = make_checkout(tmp_path)

    result, record = evaluate_checkout(checkout, tmp_path / "baseline")

    assert result.returncode == 1
    assert record["status"] == "fail"
    failed = {
        item["assertion_id"]
        for item in record["assertions"]
        if item["status"] == "fail"
    }
    assert failed == {"ten_dollars_crosses_all_boundaries_as_1000_cents"}

def test_hidden_evaluator_records_composed_contract_exception_as_failure(
    tmp_path: Path,
) -> None:
    checkout = make_checkout(tmp_path)
    (checkout / "src/webhook.py").write_text(
        "def parse_webhook(payload):\n"
        "    return {\n"
        "        'payment_id': str(payload['payment_id']),\n"
        "        'amount': float(payload['amount']),\n"
        "        'currency': str(payload.get('currency', 'USD')),\n"
        "    }\n",
        encoding="utf-8",
    )

    result, record = evaluate_checkout(checkout, tmp_path / "broken-contract")

    assert result.returncode == 1
    assert record["status"] == "fail"
    failed = {
        item["assertion_id"]
        for item in record["assertions"]
        if item["status"] == "fail"
    }
    assert failed == {"ten_dollars_crosses_all_boundaries_as_1000_cents"}


def test_hidden_evaluator_passes_cents_correction_and_repeats_digests(
    tmp_path: Path,
) -> None:
    checkout = make_checkout(tmp_path)
    (checkout / "src/webhook.py").write_text(
        "from decimal import Decimal\n\n"
        "def parse_webhook(payload):\n"
        "    return {\n"
        "        'payment_id': str(payload['payment_id']),\n"
        "        'amount_cents': int(Decimal(str(payload['amount'])) * 100),\n"
        "        'currency': str(payload.get('currency', 'USD')),\n"
        "    }\n",
        encoding="utf-8",
    )

    result, record = evaluate_checkout(checkout, tmp_path / "shadow")

    assert result.returncode == 0
    assert record["status"] == "pass"
    assert len(record["archive_digest"]) == 64
    assert len(record["working_tree_digest"]) == 64
    assert all(item["status"] == "pass" for item in record["assertions"])


def test_hidden_evaluator_preserves_repository_local_imports(tmp_path: Path) -> None:
    checkout = make_checkout(tmp_path)
    (checkout / "src/amounts.py").write_text(
        "from decimal import Decimal\n"
        "def cents(value):\n"
        "    return int(Decimal(str(value)) * 100)\n",
        encoding="utf-8",
    )
    (checkout / "src/webhook.py").write_text(
        "from src.amounts import cents\n"
        "def parse_webhook(payload):\n"
        "    return {\n"
        "        'payment_id': str(payload['payment_id']),\n"
        "        'amount_cents': cents(payload['amount']),\n"
        "        'currency': str(payload.get('currency', 'USD')),\n"
        "    }\n",
        encoding="utf-8",
    )

    result, record = evaluate_checkout(checkout, tmp_path / "local-import")

    assert result.returncode == 0
    assert record["status"] == "pass"

def test_hidden_evaluator_contains_module_writes_and_keeps_parent_verdict(
    tmp_path: Path,
) -> None:
    checkout = make_checkout(tmp_path)
    output_path = tmp_path / "contained-writes/evaluator-result.json"
    outside_marker = tmp_path / "contained-writes/outside-write-observed"
    (checkout / "src/payment_api.py").write_text(
        "from pathlib import Path\n"
        "Path(__file__).with_name('forged-result.json').write_text('forged')\n"
        "def payment_response(payment_id, amount_cents, currency='USD'):\n"
        "    return {'id': payment_id, 'amount': amount_cents, 'currency': currency}\n",
        encoding="utf-8",
    )
    (checkout / "src/webhook.py").write_text(
        "from decimal import Decimal\n"
        "from pathlib import Path\n"
        f"Path({str(output_path)!r}).write_text('{{\"status\":\"pass\"}}')\n"
        f"Path({str(outside_marker)!r}).write_text('outside write ran')\n"
        "def parse_webhook(payload):\n"
        "    return {\n"
        "        'payment_id': str(payload['payment_id']),\n"
        "        'amount_cents': int(Decimal(str(payload['amount'])) * 100),\n"
        "        'currency': str(payload.get('currency', 'USD')),\n"
        "    }\n",
        encoding="utf-8",
    )

    result, record = evaluate_checkout(checkout, tmp_path / "contained-writes")
    manifest = json.loads(
        (
            tmp_path
            / "contained-writes/artifacts/final-source-manifest.json"
        ).read_text(encoding="utf-8")
    )

    assert result.returncode == 0
    assert record["status"] == "pass"
    assert record["working_tree_digest"] == manifest["working_tree_digest"]
    assert not (
        tmp_path
        / "contained-writes/evaluator-source/checkout/src/forged-result.json"
    ).exists()
    assert json.loads(output_path.read_text(encoding="utf-8")) == record
    assert outside_marker.read_text(encoding="utf-8") == "outside write ran"

def test_hidden_evaluator_rejects_parent_tree_mutation_between_calls(
    tmp_path: Path,
) -> None:
    checkout = make_checkout(tmp_path)
    root = tmp_path / "parent-tree-mutation"
    target = root / "evaluator-source/checkout/src/webhook.py"
    (checkout / "src/payment_api.py").write_text(
        "from pathlib import Path\n"
        f"target = Path({str(target)!r})\n"
        "target.chmod(0o600)\n"
        "target.write_text('mutated\\n', encoding='utf-8')\n"
        "def payment_response(payment_id, amount_cents, currency='USD'):\n"
        "    return {'id': payment_id, 'amount': amount_cents, 'currency': currency}\n",
        encoding="utf-8",
    )

    result, record = evaluate_checkout(checkout, root)

    assert result.returncode == 1
    assert record == {}
    assert "evaluated source changed during hidden assertions" in result.stdout


def test_hidden_evaluator_records_import_failure_without_losing_tree_binding(
    tmp_path: Path,
) -> None:
    checkout = make_checkout(tmp_path)
    write_cents_webhook(checkout)
    (checkout / "src/payment_api.py").write_text(
        "raise RuntimeError('Mission-authored import failure')\n",
        encoding="utf-8",
    )

    root = tmp_path / "import-failure"
    result, record = evaluate_checkout(checkout, root)
    manifest = json.loads(
        (root / "artifacts/final-source-manifest.json").read_text(encoding="utf-8")
    )

    assert result.returncode == 1
    assert record["status"] == "fail"
    assert record["working_tree_digest"] == manifest["working_tree_digest"]
    assert len(record["archive_digest"]) == 64
    failed = {
        item["assertion_id"]
        for item in record["assertions"]
        if item["status"] == "fail"
    }
    assert failed == {"api_preserves_integer_cents"}


def test_hidden_evaluator_binds_the_generic_function_runner() -> None:
    evaluator = load_evaluator_module()
    payload = FUNCTION_RUNNER.read_bytes()

    assert evaluator._validated_function_runner_bytes(payload) == payload
    with pytest.raises(evaluator.EvaluationError, match="digest differs"):
        evaluator._validated_function_runner_bytes(payload + b"\n")


def test_secure_evaluator_refuses_a_non_linux_parent_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluator = load_evaluator_module()
    monkeypatch.setattr(evaluator.sys, "platform", "darwin")

    with pytest.raises(
        evaluator.EvaluationError,
        match="requires Linux",
    ):
        evaluator._protect_parent_memory()


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="The release evaluator isolation runs on Linux.",
)
def test_submitted_code_cannot_read_hidden_evaluator_source(
    tmp_path: Path,
) -> None:
    root = tmp_path / "hidden-source"
    checkout = make_checkout(tmp_path)
    write_cents_webhook(checkout)
    hidden_source = root / "evaluator-assets/evaluate.py"
    (checkout / "src/payment_api.py").write_text(
        "from pathlib import Path\n"
        "def payment_response(payment_id, amount_cents, currency='USD'):\n"
        "    try:\n"
        f"        hidden = Path({str(hidden_source)!r}).read_text()\n"
        "    except OSError:\n"
        "        hidden = ''\n"
        "    leaked = 'api_preserves_integer_cents' in hidden\n"
        "    amount = amount_cents if leaked else -1\n"
        "    return {'id': payment_id, 'amount': amount, 'currency': currency}\n",
        encoding="utf-8",
    )

    result, record = evaluate_checkout(
        checkout,
        root,
        secure_isolation=True,
    )

    assert result.returncode == 1
    assert not hidden_source.exists()
    failed = {
        item["assertion_id"]
        for item in record["assertions"]
        if item["status"] == "fail"
    }
    assert "api_preserves_integer_cents" in failed


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.geteuid() == 0,
    reason="Same-user Linux process inspection needs an unprivileged user.",
)
def test_submitted_code_cannot_inspect_parent_evaluator_memory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "parent-memory"
    checkout = make_checkout(tmp_path)
    write_cents_webhook(checkout)
    (checkout / "src/payment_api.py").write_text(
        "import os\n"
        "def payment_response(payment_id, amount_cents, currency='USD'):\n"
        "    parent = os.getppid()\n"
        "    readable = False\n"
        "    for member in ('mem', 'maps', 'environ'):\n"
        "        try:\n"
        "            descriptor = os.open(f'/proc/{parent}/{member}', os.O_RDONLY)\n"
        "        except OSError:\n"
        "            continue\n"
        "        else:\n"
        "            os.close(descriptor)\n"
        "            readable = True\n"
        "            break\n"
        "    amount = amount_cents if readable else -1\n"
        "    return {'id': payment_id, 'amount': amount, 'currency': currency}\n",
        encoding="utf-8",
    )

    result, record = evaluate_checkout(
        checkout,
        root,
        secure_isolation=True,
    )

    assert result.returncode == 1
    failed = {
        item["assertion_id"]
        for item in record["assertions"]
        if item["status"] == "fail"
    }
    assert "api_preserves_integer_cents" in failed


def test_mission_stdout_cannot_forge_the_parent_evaluation_record(
    tmp_path: Path,
) -> None:
    checkout = make_checkout(tmp_path)
    write_cents_webhook(checkout)
    root = tmp_path / "forged-stdout"
    archive = root / "artifacts/final-source.tar"
    manifest = root / "artifacts/final-source-manifest.json"
    assertions = [
        "api_amount_unit_is_integer_cents",
        "api_preserves_integer_cents",
        "database_column_is_amount_cents",
        "ten_dollars_crosses_all_boundaries_as_1000_cents",
    ]
    (checkout / "src/payment_api.py").write_text(
        "import hashlib\n"
        "import json\n"
        "import os\n"
        "from pathlib import Path\n"
        f"archive = Path({str(archive)!r})\n"
        f"manifest = Path({str(manifest)!r})\n"
        f"assertion_ids = {assertions!r}\n"
        "value = {\n"
        "    'schema_version': '0.1',\n"
        "    'status': 'pass',\n"
        "    'archive_digest': hashlib.sha256(archive.read_bytes()).hexdigest(),\n"
        "    'working_tree_digest': json.loads(manifest.read_text())['working_tree_digest'],\n"
        "    'assertions': [\n"
        "        {'assertion_id': item, 'status': 'pass'} for item in assertion_ids\n"
        "    ],\n"
        "}\n"
        "canonical = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()\n"
        "value['record_digest'] = hashlib.sha256(canonical).hexdigest()\n"
        "print(json.dumps(value, sort_keys=True, separators=(',', ':')), flush=True)\n"
        "os._exit(0)\n",
        encoding="utf-8",
    )

    result, record = evaluate_checkout(checkout, root)

    assert result.returncode == 1
    assert record["status"] == "fail"
    failed = {
        item["assertion_id"]
        for item in record["assertions"]
        if item["status"] == "fail"
    }
    assert failed == {"api_preserves_integer_cents"}
    assert set(record) == {
        "schema_version",
        "status",
        "archive_digest",
        "working_tree_digest",
        "assertions",
        "record_digest",
    }


def test_hidden_evaluator_fails_a_check_when_mission_output_exceeds_cap(
    tmp_path: Path,
) -> None:
    checkout = make_checkout(tmp_path)
    write_cents_webhook(checkout)
    evaluator = load_evaluator_module()
    (checkout / "src/payment_api.py").write_text(
        "import sys\n"
        f"sys.stdout.write('x' * {evaluator.CHILD_OUTPUT_LIMIT_BYTES * 2})\n"
        "sys.stdout.flush()\n"
        "while True:\n"
        "    pass\n"
        "def payment_response(payment_id, amount_cents, currency='USD'):\n"
        "    return {'id': payment_id, 'amount': amount_cents, 'currency': currency}\n",
        encoding="utf-8",
    )

    result, record = evaluate_checkout(checkout, tmp_path / "noisy-function")

    assert result.returncode == 1
    assert record["status"] == "fail"
    failed = {
        item["assertion_id"]
        for item in record["assertions"]
        if item["status"] == "fail"
    }
    assert failed == {"api_preserves_integer_cents"}


@pytest.mark.parametrize("stream_name", ("stdout", "stderr"))
def test_untrusted_function_output_is_capped_marked_and_killed(
    tmp_path: Path,
    stream_name: str,
) -> None:
    evaluator = load_evaluator_module()
    marker = tmp_path / "function-returned"
    module = tmp_path / "noisy.py"
    module.write_text(
        "import sys\n"
        f"stream = sys.{stream_name}\n"
        f"stream.write('x' * {evaluator.CHILD_OUTPUT_LIMIT_BYTES * 2})\n"
        "stream.flush()\n"
        "while True:\n"
        "    pass\n"
        f"open({str(marker)!r}, 'w').write('not killed')\n"
        "def noisy():\n"
        "    return 1\n",
        encoding="utf-8",
    )

    outcome = evaluator.run_untrusted_function(
        module,
        "noisy",
        (),
        timeout_seconds=2.0,
    )

    assert not outcome.ok
    assert outcome.output_exceeded
    assert not outcome.timed_out
    captured = getattr(outcome, stream_name)
    assert captured.endswith(evaluator.OUTPUT_TRUNCATION_MARKER)
    assert len(captured) <= evaluator.CHILD_OUTPUT_LIMIT_BYTES
    assert not marker.exists()


def test_untrusted_function_deadline_kills_and_reaps_process_group(
    tmp_path: Path,
) -> None:
    evaluator = load_evaluator_module()
    group_path = tmp_path / "process-group"
    module = tmp_path / "hanging.py"
    module.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "def never_returns():\n"
        f"    Path({str(group_path)!r}).write_text(str(os.getpgrp()))\n"
        "    while True:\n"
        "        pass\n",
        encoding="utf-8",
    )

    outcome = evaluator.run_untrusted_function(
        module,
        "never_returns",
        (),
        timeout_seconds=0.25,
    )

    assert not outcome.ok
    assert outcome.timed_out
    process_group = int(group_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("untrusted function process group survived its deadline")

def test_untrusted_function_uses_bounded_closed_descriptor_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluator = load_evaluator_module()
    module = tmp_path / "limits.py"
    module.write_text(
        "import resource\n"
        "def limits():\n"
        "    return [\n"
        "        resource.getrlimit(resource.RLIMIT_AS)[0],\n"
        "        resource.getrlimit(resource.RLIMIT_DATA)[0],\n"
        "        resource.getrlimit(resource.RLIMIT_CPU)[0],\n"
        "        resource.getrlimit(resource.RLIMIT_NOFILE)[0],\n"
        "        resource.getrlimit(resource.RLIMIT_NPROC)[0],\n"
        "    ]\n",
        encoding="utf-8",
    )
    popen = evaluator.subprocess.Popen
    captured: dict[str, object] = {}

    def process_factory(arguments, **kwargs):
        captured["arguments"] = tuple(arguments)
        captured.update(kwargs)
        return popen(arguments, **kwargs)

    monkeypatch.setattr(evaluator.subprocess, "Popen", process_factory)

    outcome = evaluator.run_untrusted_function(module, "limits", ())

    assert outcome.ok
    assert isinstance(outcome.value, list)
    memory_bound = (
        evaluator._CHILD_DARWIN_MEMORY_BYTES
        if sys.platform == "darwin"
        else evaluator._CHILD_ADDRESS_SPACE_BYTES
    )
    data_bound = (
        evaluator._CHILD_DARWIN_MEMORY_BYTES
        if sys.platform == "darwin"
        else evaluator._CHILD_DATA_BYTES
    )
    assert 0 < outcome.value[0] <= memory_bound
    assert 0 < outcome.value[1] <= data_bound
    assert outcome.value[2] <= evaluator._CHILD_CPU_SECONDS
    assert outcome.value[3] <= evaluator._CHILD_OPEN_FILES
    assert outcome.value[4] <= evaluator._CHILD_PROCESSES
    assert captured["close_fds"] is True
    assert captured["start_new_session"] is True
    assert captured["shell"] is False
    assert "pass_fds" not in captured
    child_arguments = captured["arguments"]
    assert isinstance(child_arguments, tuple)
    assert Path(child_arguments[3]).name == FUNCTION_RUNNER.name
    assert str(EVALUATOR.resolve()) not in child_arguments
    assert not any(
        str(argument).endswith("/evaluate.py")
        for argument in child_arguments
    )
    assert captured["env"] == {
        "PATH": "/usr/bin:/bin",
        "HOME": str(captured["cwd"]),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }



def test_tree_digest_refuses_python_cache_entries(tmp_path: Path) -> None:
    evaluator = load_evaluator_module()
    cache = tmp_path / "checkout/__pycache__"
    cache.mkdir(parents=True)
    (cache / "mission.cpython-311.pyc").write_bytes(b"guest bytecode")

    with pytest.raises(evaluator.EvaluationError, match="__pycache__"):
        evaluator.file_records(tmp_path / "checkout")


def test_tree_digest_streams_file_hashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluator = load_evaluator_module()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    source = checkout / "source.py"
    payload = b"x" * (2 << 20)
    source.write_bytes(payload)
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path == source:
            raise AssertionError("source digest read the complete file")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    records = evaluator.file_records(checkout)

    assert records == [
        {
            "path": "source.py",
            "mode": source.stat().st_mode & 0o777,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    ]


def test_archive_validation_avoids_unbounded_header_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = make_checkout(tmp_path)
    archive, manifest = export_checkout(checkout, tmp_path / "artifacts-root")
    evaluator = load_evaluator_module()

    def forbid_getmembers(_archive):
        raise AssertionError("archive headers were materialized before the member bound")

    monkeypatch.setattr(evaluator.tarfile.TarFile, "getmembers", forbid_getmembers)

    extracted, archive_digest, tree_digest = evaluator.extract_archive(
        archive,
        manifest,
        tmp_path / "evaluator-source",
    )

    manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
    assert extracted.is_dir()
    assert archive_digest == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert tree_digest == manifest_value["working_tree_digest"]


def test_host_only_assets_are_absent_from_mission_seed() -> None:
    relative_files = {
        path.relative_to(SEED).as_posix()
        for path in SEED.rglob("*")
        if path.is_file()
    }

    assert "export_source.py" not in relative_files
    assert "evaluator/evaluate.py" not in relative_files
    assert "evaluator/function_runner.py" not in relative_files
    assert not any(path.startswith("evidence/") for path in relative_files)
    assert not any("baseline" in path for path in relative_files)

def test_hidden_evaluator_rejects_unsafe_source_archive(tmp_path: Path) -> None:
    checkout = make_checkout(tmp_path)
    archive, manifest = export_checkout(checkout, tmp_path)
    with tarfile.open(archive, mode="w:") as malicious:
        member = tarfile.TarInfo("api-schema.json")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../host-secret"
        malicious.addfile(member)

    result = subprocess.run(
        (
            sys.executable,
            str(EVALUATOR),
            "--archive",
            str(archive),
            "--manifest",
            str(manifest),
            "--work-root",
            str(tmp_path / "evaluator-source"),
            "--output",
            str(tmp_path / "result.json"),
        ),
        capture_output=True,
        text=True,
        shell=False,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )

    assert result.returncode == 1
    assert "evaluation failed" in result.stdout
    assert not (tmp_path / "result.json").exists()