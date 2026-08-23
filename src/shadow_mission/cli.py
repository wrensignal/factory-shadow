"""Command-line boundary for one artifact-bound Shadow Mission."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .correlation import host_factory_mission_root
from .evaluation import LimaVmDriver
from .finalization import FinalizationError, finalize_run
from .live import LiveGateError, load_private_factory_environment
from .reporting import (
    ReportCorruptionError,
    ReportInputError,
    ReportWriteError,
    rebuild_report,
    write_report_outputs,
)
from .production import ProductionReviewControllerFactory
from .preflight import PreflightBuildError, build_release_preflight
from .protocol import RELEASE_REPORTABLE_RUNTIME_OUTCOMES
from .runtime import MissionExecutionError, MissionRequest, MissionRuntime, PreflightError
from .status import (
    StatusCorruptionError,
    StatusInputError,
    is_safe_run_id,
    load_status,
    render_status,
)






def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shadow")
    subcommands = parser.add_subparsers(dest="command", required=True)
    mission = subcommands.add_parser("mission", help="run one approved Factory Mission")
    mission.add_argument("--repo", type=Path, required=True)
    mission.add_argument("--file", dest="mission_file", type=Path, required=True)
    mission.add_argument("--evaluator", type=Path, required=True)
    mission.add_argument("--profile-manifest", type=Path, required=True)
    mission.add_argument("--isolation-manifest", type=Path, required=True)
    mission.add_argument("--lima-config", type=Path, required=True)
    mission.add_argument("--feasibility-record", type=Path, required=True)
    mission.add_argument("--release-preflight", type=Path, required=True)
    mission.add_argument("--factory-mission-root", type=Path)
    mission.add_argument("--source-exporter", type=Path, required=True)
    mission.add_argument("--evaluator-lima-config", type=Path, required=True)
    mission.add_argument("--evaluator-vm-name", required=True)
    mission.add_argument("--baseline-record", type=Path)
    mission.add_argument("--droid", dest="droid_path", type=Path, required=True)
    mission.add_argument("--plugin-root", type=Path, required=True)
    mission.add_argument("--state-root", type=Path, required=True)
    mission.add_argument("--factory-credential-file", type=Path, required=True)
    for role in ("orchestrator", "worker", "validator", "extractor", "probe"):
        mission.add_argument(f"--{role}-model", required=True)
        mission.add_argument(f"--{role}-reasoning", required=True)
    preflight = subcommands.add_parser(
        "preflight",
        help="build one no-spend release preflight",
    )
    preflight.add_argument("--plugin-root", type=Path, required=True)
    preflight.add_argument("--repo", type=Path, required=True)
    preflight.add_argument("--file", dest="mission_file", type=Path, required=True)
    preflight.add_argument("--evaluator", type=Path, required=True)
    preflight.add_argument("--profile-manifest", type=Path, required=True)
    preflight.add_argument("--isolation-manifest", type=Path, required=True)
    preflight.add_argument("--lima-config", type=Path, required=True)
    preflight.add_argument("--feasibility-record", type=Path, required=True)
    preflight.add_argument("--droid", dest="droid_path", type=Path, required=True)
    preflight.add_argument("--approval", dest="approval_path", type=Path, required=True)
    preflight.add_argument("--output", dest="output_path", type=Path, required=True)
    preflight.add_argument("--baseline-record", type=Path)


    status = subcommands.add_parser("status", help="show one Shadow run")
    status.add_argument("--repo", type=Path, required=True)
    status.add_argument("--run", dest="run_id", required=True)
    status.add_argument("--state-root", type=Path)

    report = subcommands.add_parser("report", help="write one Shadow report")
    report.add_argument("--repo", type=Path, required=True)
    report.add_argument("--run", dest="run_id", required=True)
    report.add_argument("--state-root", type=Path)
    report.add_argument("--baseline-record", type=Path)
    return parser


def _state_root(repo: Path, explicit: Path | None) -> Path:
    return explicit if explicit is not None else repo / ".shadow-mission"


def _run_mission(arguments: argparse.Namespace) -> int:
    try:
        credential_environment = load_private_factory_environment(
            arguments.factory_credential_file
        )
    except LiveGateError as error:
        print(f"preflight stopped: {error}", file=sys.stderr)
        return 2
    models = {
        role: getattr(arguments, f"{role}_model")
        for role in ("orchestrator", "worker", "validator", "extractor", "probe")
    }
    reasoning = {
        role: getattr(arguments, f"{role}_reasoning")
        for role in ("orchestrator", "worker", "validator", "extractor", "probe")
    }
    request = MissionRequest(
        repo=arguments.repo,
        mission_file=arguments.mission_file,
        evaluator=arguments.evaluator,
        profile_manifest=arguments.profile_manifest,
        isolation_manifest=arguments.isolation_manifest,
        lima_config=arguments.lima_config,
        feasibility_record=arguments.feasibility_record,
        release_preflight=arguments.release_preflight,
        factory_mission_root=(
            arguments.factory_mission_root
            if arguments.factory_mission_root is not None
            else host_factory_mission_root()
        ),
        droid_path=arguments.droid_path,
        models=models,
        reasoning=reasoning,
        baseline_record=arguments.baseline_record,
    )
    state_root = _state_root(arguments.repo, arguments.state_root)
    runtime = MissionRuntime(
        arguments.plugin_root,
        state_root=state_root,
    )
    mission_error: MissionExecutionError | None = None
    try:
        record = runtime.run(
            request,
            review_controller_factory=ProductionReviewControllerFactory(
                credential_environment=credential_environment,
            ),
        )
    except PreflightError as error:
        print(f"preflight stopped: {error}", file=sys.stderr)
        return 2
    except MissionExecutionError as error:
        if error.run_record is None:
            print(f"Mission failed: {error}", file=sys.stderr)
            return 1
        record = error.run_record
        mission_error = error
    except (OSError, ValueError) as error:
        print(f"Mission failed: {error}", file=sys.stderr)
        return 1
    try:
        finalization_forbidden_values = runtime.take_finalization_canaries(
            record.run_id
        )
    except MissionExecutionError as error:
        print(f"Mission failed: {error}", file=sys.stderr)
        return 1
    try:
        result = finalize_run(
            evaluator_driver=LimaVmDriver(),
            evaluator_vm_name=arguments.evaluator_vm_name,
            evaluator_lima_config=arguments.evaluator_lima_config,
            mission_repo=arguments.repo,
            exporter_path=arguments.source_exporter,
            evaluator_path=arguments.evaluator,
            run_dir=state_root / "runs" / record.run_id,
            mission_process_stopped=record.mission_process_stopped,
            hooks_stopped=True,
            secret_canaries=finalization_forbidden_values,
            mission_process_succeeded=mission_error is None,
        )
    except (FinalizationError, OSError, ValueError) as error:
        print(f"Mission finalization failed: {error}", file=sys.stderr)
        return 1
    if mission_error is not None:
        print(
            f"Mission process failed after finalization: {mission_error}",
            file=sys.stderr,
        )
    runtime_reportable = (
        result.run_record.runtime_outcome
        in RELEASE_REPORTABLE_RUNTIME_OUTCOMES
    )
    if not runtime_reportable:
        print(
            "Mission runtime outcome is not release-reportable: "
            f"{result.run_record.runtime_outcome}",
            file=sys.stderr,
        )
    print(
        json.dumps(
            {
                "mission_outcome": result.run_record.mission_outcome,
                "runtime_outcome": result.run_record.runtime_outcome,
                "run_id": result.run_record.run_id,
                "status": result.evaluation_record.status,
            },
            sort_keys=True,
        )
    )
    return 0 if runtime_reportable else 1
def _build_preflight(arguments: argparse.Namespace) -> int:
    try:
        preflight = build_release_preflight(
            project_root=arguments.plugin_root,
            repo=arguments.repo,
            mission_file=arguments.mission_file,
            evaluator=arguments.evaluator,
            profile_manifest=arguments.profile_manifest,
            isolation_manifest=arguments.isolation_manifest,
            lima_config=arguments.lima_config,
            feasibility_record=arguments.feasibility_record,
            droid_path=arguments.droid_path,
            approval_path=arguments.approval_path,
            output_path=arguments.output_path,
            baseline_record=arguments.baseline_record,
        )
    except (PreflightBuildError, OSError, ValueError) as error:
        print(f"preflight build stopped: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "preflight_id": preflight.preflight_id,
                "record_digest": preflight.record_digest,
                "output": str(arguments.output_path),
            },
            sort_keys=True,
        )
    )
    return 0




def _show_status(arguments: argparse.Namespace) -> int:
    try:
        record = load_status(
            _state_root(arguments.repo, arguments.state_root),
            arguments.run_id,
        )
    except StatusInputError as error:
        print(f"status unavailable: {error}", file=sys.stderr)
        return 2
    except (StatusCorruptionError, OSError) as error:
        print(f"status failed: {error}", file=sys.stderr)
        return 1
    print(render_status(record))
    return 0


def _build_report(arguments: argparse.Namespace) -> int:
    if not is_safe_run_id(arguments.run_id):
        print("report unavailable: run ID is invalid", file=sys.stderr)
        return 2
    run_dir = (
        _state_root(arguments.repo, arguments.state_root)
        / "runs"
        / arguments.run_id
    )
    try:
        report = rebuild_report(
            run_dir,
            baseline_record_path=arguments.baseline_record,
        )
        json_path, markdown_path = write_report_outputs(report, run_dir)
    except ReportInputError as error:
        print(f"report unavailable: {error}", file=sys.stderr)
        return 2
    except (ReportCorruptionError, ReportWriteError, OSError) as error:
        print(f"report failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "run_id": report.run_id,
                "report_json": str(json_path),
                "report_markdown": str(markdown_path),
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "mission":
        return _run_mission(arguments)
    if arguments.command == "preflight":
        return _build_preflight(arguments)
    if arguments.command == "status":
        return _show_status(arguments)
    if arguments.command == "report":
        return _build_report(arguments)
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
