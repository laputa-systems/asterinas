import copy
import errno
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from . import supervisor as supervisor_module
from .accounting import CaseOutcome, RoleResult, reconcile
from .adapter import (
    LOG_DISCARD_FLAG,
    LOG_FLUSH_FLAG,
    WRITE_LOG_ENTRY_SIZE,
    WRITE_LOG_MAGIC,
    WRITE_LOG_VERSION,
    validate_blklogwrites,
)
from .compare import compare_value, verify_comparison_claim
from .errors import EvidenceError, ManifestError
from .evidence import EvidenceBundle
from . import lock as lock_module
from .gtest import parse_gtest_report
from .lock import _probe_rebuild_required, asterinas_source_tree_hash
from .manifest import Selection, load_case_index, load_case_manifest, load_profile
from .persistence import (
    durable_writes,
    enumerate_crash_cuts,
    is_data_write,
    missing_durable_sectors,
    omitted_sync_detected,
    parse_records,
)
from .results import ResultContext, ingest_result_stream, make_result_line
from .runner import (
    BackendEvidence,
    RunFailure,
    RunSnapshot,
    RunState,
    _observed_values,
    assert_selection_snapshot,
    create_snapshot,
    evaluate_case,
    finalize_run,
    verify_backend_identity,
    verify_copied_input_hashes,
)
from .supervisor import _EXEC_RELEASE_BYTE, _EXEC_WRAPPER, Supervisor, is_full_disk_error
from .util import sha256_bytes


@dataclass
class ControlResult:
    name: str
    detected: bool
    detail: str


def _selection(repo: Path) -> Selection:
    qualification = repo / "test" / "qualification"
    case_index = load_case_index([qualification / "contracts" / "core" / "echo.json"])
    return load_profile("lc02-selftest", qualification / "profiles", case_index)


def _valid_records(selection: Selection, run_id: str) -> list[dict]:
    now = time.time()
    case_id = selection.case_ids[0]
    common = {
        "case_id": case_id,
        "manifest_hash": selection.manifest_hash,
        "payload_hash": selection.payload_hash,
    }
    return [
        {
            **common,
            "sequence": 1,
            "kind": "start",
            "emitted_at": now,
        },
        {
            **common,
            "sequence": 2,
            "kind": "subtest",
            "subtest": "echo",
            "status": "pass",
            "emitted_at": now,
            "assertions": [
                {"id": "errno", "value": 0},
                {"id": "bytes", "value": "aGVsbG8K"},
                {"id": "permission", "value": "allow"},
            ],
        },
        {
            **common,
            "sequence": 3,
            "kind": "final",
            "status": "pass",
            "emitted_at": now,
            "subtests_completed": 1,
            "assertions_completed": 3,
            "artifacts": [{"name": "stdout.log", "sha256": sha256_bytes(b"lc02 selftest\n"), "size": len(b"lc02 selftest\n")}],
        },
    ]


def _stream(run_id: str, nonce: str, records: list[dict]) -> str:
    return "".join(make_result_line(run_id, nonce, record) for record in records)


def _context(selection: Selection, run_id: str, nonce: str) -> ResultContext:
    return ResultContext(
        run_id=run_id,
        nonce=nonce,
        manifest_hash=selection.manifest_hash,
        payload_hash=selection.payload_hash,
        cases=selection.case_map,
        max_age_seconds=300,
        now=time.time(),
    )


def _first_matching(categories: list[str], category: str) -> str:
    for item in categories:
        if item.startswith(category + ":"):
            return item
    return "no diagnostic"


def _blklog_fixture(
    path: Path,
    entries: list[tuple[int, int, int]],
    declared: int | None = None,
    sector_size: int = 512,
    magic: int = WRITE_LOG_MAGIC,
    version: int = WRITE_LOG_VERSION,
) -> Path:
    header = struct.pack("<QQQI", magic, version, len(entries) if declared is None else declared, sector_size)
    data = bytearray(header + b"\0" * (sector_size - len(header)))
    for sector, nr_sectors, flags in entries:
        data.extend(struct.pack("<QQQQ", sector, nr_sectors, flags, 0))
        data.extend(b"\0" * (sector_size - WRITE_LOG_ENTRY_SIZE))
        if not (flags & LOG_DISCARD_FLAG):
            data.extend(b"\xAB" * min(nr_sectors * sector_size, 4096))
    path.write_bytes(data)
    return path


def _render_os_errors(errors: list[OSError]) -> str:
    return "; ".join(f"errno={error.errno} {error.strerror or error}" for error in errors)


def _wrapper_probe(release_payload: bytes | None) -> tuple[int, bytes]:
    release_read, release_write = os.pipe()
    error_read, error_write = os.pipe()
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                _EXEC_WRAPPER,
                str(release_read),
                str(error_write),
                sys.executable,
                "-c",
                "print('target-execed')",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(release_read, error_write),
        )
    except BaseException:
        for fd in (release_read, release_write, error_read, error_write):
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    os.close(release_read)
    os.close(error_write)
    try:
        if release_payload is not None:
            os.write(release_write, release_payload)
    finally:
        try:
            os.close(release_write)
        except OSError:
            pass
    try:
        stdout, _ = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        os.close(error_read)
        raise
    os.close(error_read)
    return process.returncode, stdout


def _scan_token_pids(token: str) -> list[int]:
    completed = subprocess.run(
        ["ps", "-eo", "pid=", "-o", "args="],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"survivor scan exited {completed.returncode}")
    pids: list[int] = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or token not in fields[1]:
            continue
        pid = int(fields[0])
        if pid != os.getpid():
            pids.append(pid)
    return pids


def selftest_main() -> int:
    repo = Path(__file__).resolve().parents[3]
    qualification_root = repo / "target" / "qualification"
    bundle = EvidenceBundle.create(qualification_root)
    run_id = bundle.run_id
    nonce = "selftest-nonce"
    controls: list[ControlResult] = []
    checks: list[str] = []
    internal_failures: list[str] = []

    print(f"LC-02 selftest evidence: {bundle.root}")

    try:
        selection = _selection(repo)
    except Exception as error:
        print(f"INTERNAL-FAIL manifest fixture: {error}")
        return 2

    def evaluate(name: str, function: Callable[[], tuple[bool, str]]) -> None:
        try:
            detected, detail = function()
        except Exception as error:
            detected = False
            detail = f"control harness raised {type(error).__name__}: {error}"
        controls.append(ControlResult(name, detected, detail))

    def ingestion_control(category: str, mutate: Callable[[list[dict], str], str]) -> tuple[bool, str]:
        records = copy.deepcopy(valid_records)
        text = mutate(records, _stream(run_id, nonce, records))
        ingestion = ingest_result_stream(text, _context(selection, run_id, nonce))
        rendered = ingestion.rendered()
        return ingestion.has(category), _first_matching(rendered, category) if ingestion.has(category) else "; ".join(rendered) or "no diagnostics"

    valid_records = _valid_records(selection, run_id)
    valid_ingestion = ingest_result_stream(_stream(run_id, nonce, valid_records), _context(selection, run_id, nonce))
    if valid_ingestion.diagnostics:
        internal_failures.append("valid result fixture produced diagnostics: " + "; ".join(valid_ingestion.rendered()))
    else:
        checks.append("run-bound positive result fixture accepted")

    outcomes = [
        CaseOutcome(
            selection.case_ids[0],
            "PASS",
            (
                RoleResult("candidate", "pass"),
                RoleResult("reference", "pass"),
                RoleResult("comparator", "pass"),
                RoleResult("validator", "pass"),
            ),
        )
    ]
    accounting = reconcile(selection.case_ids, outcomes)
    if accounting.balanced and not accounting.diagnostics and accounting.counts["PASS"] == 1:
        checks.append("terminal accounting balanced with distinct roles")
    else:
        internal_failures.append("positive terminal accounting failed")

    normalized_match = compare_value("bytes", "aGVsbG8K", b"hello\r\n", "normalized", ("unicode-newlines",)).matched
    invariant_match = (
        compare_value("errno", {"nonzero": True}, 1, "invariant").matched
        and compare_value("bytes", {"length": 6}, b"hello\n", "invariant").matched
        and compare_value("permission", {"one_of": ["allow", "deny"]}, "deny", "invariant").matched
    )
    if normalized_match and invariant_match:
        checks.append("normalized and invariant comparator primitives match valid values")
    else:
        internal_failures.append("normalized or invariant comparator positive check failed")

    validation_dir = bundle.work_dir / "validation-profiles"
    validation_dir.mkdir(parents=True, exist_ok=True)
    case_index = load_case_index([repo / "test" / "qualification" / "contracts" / "core" / "echo.json"])
    for profile_name, cases in (("unknown-case-profile", ["core.missing"]), ("duplicate-case-profile", [selection.case_ids[0], selection.case_ids[0]])):
        (validation_dir / f"{profile_name}.json").write_text(
            json.dumps({"schema": 1, "name": profile_name, "inherits": [], "cases": cases, "excludes": []}),
            encoding="utf-8",
        )
    try:
        load_profile("unknown-case-profile", validation_dir, case_index)
        internal_failures.append("manifest loader accepted an unknown case")
    except ManifestError:
        pass
    try:
        load_profile("duplicate-case-profile", validation_dir, case_index)
        internal_failures.append("manifest loader accepted a duplicate case")
    except ManifestError:
        pass
    if not any(item.startswith("manifest loader accepted") for item in internal_failures):
        checks.append("manifest loading validates inherited selection, unknown cases, and duplicate cases")

    def empty_selection() -> tuple[bool, str]:
        profile_dir = bundle.work_dir / "empty-profiles"
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "empty.json").write_text(
            json.dumps({"schema": 1, "name": "empty", "inherits": [], "cases": [], "excludes": []}),
            encoding="utf-8",
        )
        try:
            case_index = load_case_index([repo / "test" / "qualification" / "contracts" / "core" / "echo.json"])
            load_profile("empty", profile_dir, case_index)
        except ManifestError as error:
            return "empty selection" in str(error), str(error)
        return False, "empty profile was accepted"

    evaluate("empty-selection", empty_selection)

    def zero_gtests() -> tuple[bool, str]:
        report = parse_gtest_report(b'<testsuites tests="0" failures="0" skipped="0"><testsuite name="empty" tests="0" failures="0" skipped="0"/></testsuites>')
        return "zero-matching-gtests" in report.diagnostics, ", ".join(report.diagnostics) or "no diagnostics"

    evaluate("gtest-zero-matching", zero_gtests)

    def all_skipped() -> tuple[bool, str]:
        report = parse_gtest_report(
            b'<testsuites tests="2" failures="0" skipped="2"><testsuite name="skip" tests="2" failures="0" skipped="2">'
            b'<testcase name="a" status="skipped"/><testcase name="b" status="skipped"/></testsuite></testsuites>'
        )
        return "all-gtests-skipped" in report.diagnostics, ", ".join(report.diagnostics) or "no diagnostics"

    evaluate("gtest-all-skipped", all_skipped)

    evaluate(
        "unknown-case",
        lambda: ingestion_control(
            "unknown-case",
            lambda records, text: text + make_result_line(
                run_id,
                nonce,
                {
                    "case_id": "core.unknown",
                    "sequence": 4,
                    "kind": "final",
                    "status": "pass",
                    "manifest_hash": selection.manifest_hash,
                    "payload_hash": selection.payload_hash,
                    "emitted_at": time.time(),
                    "subtests_completed": 0,
                    "assertions_completed": 0,
                },
            ),
        ),
    )

    def duplicate_case() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            duplicate = copy.deepcopy(records[-1])
            duplicate["sequence"] = 4
            return text + make_result_line(run_id, nonce, duplicate)

        return ingestion_control("duplicate-case-record", mutate)

    evaluate("duplicate-case", duplicate_case)

    evaluate(
        "missing-subtest",
        lambda: ingestion_control(
            "missing-subtest",
            lambda records, text: _stream(run_id, nonce, [record for record in records if record["kind"] != "subtest"]),
        ),
    )

    def missing_assertion() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            for record in records:
                if record["kind"] == "subtest":
                    record["assertions"] = [item for item in record["assertions"] if item["id"] != "permission"]
            return _stream(run_id, nonce, records)

        return ingestion_control("missing-assertion", mutate)

    evaluate("missing-assertion", missing_assertion)

    evaluate(
        "missing-final-record",
        lambda: ingestion_control(
            "missing-final-record",
            lambda records, text: _stream(run_id, nonce, [record for record in records if record["kind"] != "final"]),
        ),
    )
    evaluate(
        "missing-start-record",
        lambda: ingestion_control(
            "missing-start-record",
            lambda records, text: _stream(run_id, nonce, [record for record in records if record["kind"] != "start"]),
        ),
    )

    def duplicate_start() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            duplicate = copy.deepcopy(records[0])
            duplicate["sequence"] = 4
            return text + make_result_line(run_id, nonce, duplicate)

        return ingestion_control("duplicate-start-record", mutate)

    evaluate("duplicate-start-record", duplicate_start)

    def future_timestamp() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            records[-1]["emitted_at"] = time.time() + 3600
            return _stream(run_id, nonce, records)

        return ingestion_control("future-timestamp", mutate)

    evaluate("future-timestamp", future_timestamp)

    def missing_required_artifact() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            records[-1]["artifacts"] = []
            return _stream(run_id, nonce, records)

        return ingestion_control("missing-required-artifact", mutate)

    evaluate("missing-required-artifact", missing_required_artifact)

    evaluate(
        "malformed-output",
        lambda: ingestion_control("malformed-output", lambda records, text: text + f"QUAL {run_id} {nonce} {{bad json}}\n"),
    )
    evaluate(
        "truncated-output",
        lambda: ingestion_control("truncated-output", lambda records, text: text + f"QUAL {run_id} {nonce} {{\"case_id\":\"core.echo-probe\"," + "\n"),
    )

    def stale_log() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            for record in records:
                if record["kind"] == "final":
                    record["emitted_at"] = time.time() - 3600
            return _stream(run_id, nonce, records)

        return ingestion_control("stale-log", mutate)

    evaluate("stale-log", stale_log)
    evaluate(
        "wrong-run-id",
        lambda: ingestion_control("wrong-run-id", lambda records, text: text.replace(f"QUAL {run_id}", "QUAL wrong-run", 1)),
    )

    def wrong_payload_hash() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            records[0]["payload_hash"] = "0" * 64
            return _stream(run_id, nonce, records)

        return ingestion_control("wrong-payload-hash", mutate)

    evaluate("wrong-payload-hash", wrong_payload_hash)

    def wrong_manifest_hash() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            records[0]["manifest_hash"] = "0" * 64
            return _stream(run_id, nonce, records)

        return ingestion_control("wrong-manifest-hash", mutate)

    evaluate("wrong-manifest-hash", wrong_manifest_hash)

    def nonfinite_timestamp() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            records[0]["emitted_at"] = float("nan")
            return _stream(run_id, nonce, records)

        return ingestion_control("malformed-output", mutate)

    evaluate("nonfinite-emitted-at", nonfinite_timestamp)

    def infinite_timestamp() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            records[0]["emitted_at"] = float("inf")
            return _stream(run_id, nonce, records)

        return ingestion_control("malformed-output", mutate)

    evaluate("infinite-emitted-at", infinite_timestamp)

    def non_string_case_id() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            records[0]["case_id"] = 4
            return _stream(run_id, nonce, records)

        return ingestion_control("malformed-output", mutate)

    evaluate("non-string-case-id", non_string_case_id)

    def unhashable_case_id() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            records[0]["case_id"] = []
            return _stream(run_id, nonce, records)

        return ingestion_control("malformed-output", mutate)

    evaluate("unhashable-case-id", unhashable_case_id)

    def final_status_wrong_type() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            records[-1]["status"] = []
            return _stream(run_id, nonce, records)

        return ingestion_control("malformed-output", mutate)

    evaluate("final-status-wrong-type", final_status_wrong_type)

    def assertion_without_value() -> tuple[bool, str]:
        def mutate(records: list[dict], text: str) -> str:
            for record in records:
                if record["kind"] == "subtest":
                    for assertion in record["assertions"]:
                        assertion.pop("value", None)
            return _stream(run_id, nonce, records)

        return ingestion_control("malformed-output", mutate)

    evaluate("assertion-without-value", assertion_without_value)

    def nonfinite_deadline() -> tuple[bool, str]:
        contract_text = (repo / "test" / "qualification" / "contracts" / "core" / "echo.json").read_text(encoding="utf-8")
        details: list[str] = []
        rejected_all = True
        for literal in ("NaN", "Infinity"):
            mutated = contract_text.replace('"deadline_seconds": 2', f'"deadline_seconds": {literal}')
            if literal not in mutated:
                return False, "contract fixture did not carry a numeric deadline to mutate"
            path = bundle.work_dir / f"nonfinite-deadline-{literal.lower()}.json"
            path.write_text(mutated, encoding="utf-8")
            try:
                load_case_manifest(path)
            except (ManifestError, ValueError) as error:
                details.append(f"{literal} rejected")
            else:
                rejected_all = False
                details.append(f"{literal} accepted")
        return rejected_all, "; ".join(details)

    evaluate("manifest-nonfinite-deadline", nonfinite_deadline)

    evaluate(
        "wrong-errno",
        lambda: (
            not compare_value("errno", 0, 1).matched,
            compare_value("errno", 0, 1).detail,
        ),
    )
    evaluate(
        "wrong-bytes",
        lambda: (
            not compare_value("bytes", "aGVsbG8K", "Z29vZGJ5ZQo=").matched,
            compare_value("bytes", "aGVsbG8K", "Z29vZGJ5ZQo=").detail,
        ),
    )
    evaluate(
        "wrong-permission-decision",
        lambda: (
            not compare_value("permission", "allow", "deny").matched,
            compare_value("permission", "allow", "deny").detail,
        ),
    )
    evaluate(
        "wrong-comparator-result",
        lambda: (
            not verify_comparison_claim("errno", 0, 1, claimed_match=True),
            "claimed match is contradicted by recomputation",
        ),
    )

    def errno_hermetic_linux() -> tuple[bool, str]:
        positive = (
            compare_value("errno", "EAGAIN", 11).matched
            and compare_value("errno", "EDEADLK", 35).matched
            and compare_value("errno", "EOPNOTSUPP", 95).matched
        )
        negative = (
            compare_value("errno", "EAGAIN", 35).matched
            or compare_value("errno", "EDEADLK", 11).matched
            or compare_value("errno", "EOPNOTSUPP", 102).matched
        )
        detail = (
            f"EAGAIN=11 {compare_value('errno', 'EAGAIN', 11).matched} "
            f"EDEADLK=35 {compare_value('errno', 'EDEADLK', 35).matched} "
            f"EOPNOTSUPP=95 {compare_value('errno', 'EOPNOTSUPP', 95).matched} "
            f"host-valued mismatches rejected: {not negative}"
        )
        return positive and not negative, detail

    evaluate("errno-hermetic-linux", errno_hermetic_linux)

    def errno_unknown_name_no_match() -> tuple[bool, str]:
        invariant = compare_value("errno", {"one_of": ["ENOT_A_REAL_ERRNO"]}, None, "invariant")
        exact = compare_value("errno", "ENOT_A_REAL_ERRNO", "ENOT_A_REAL_ERRNO")
        detail = f"invariant matched={invariant.matched} exact matched={exact.matched}"
        return not invariant.matched and not exact.matched, detail

    evaluate("errno-unknown-name-no-match", errno_unknown_name_no_match)

    def errno_boolean_no_match() -> tuple[bool, str]:
        true_matches = compare_value("errno", 1, True).matched or compare_value("errno", True, 1).matched
        false_matches = compare_value("errno", 0, False).matched or compare_value("errno", False, 0).matched
        invariant = compare_value("errno", {"one_of": [True]}, 1, "invariant").matched
        detail = f"true matched={true_matches} false matched={false_matches} invariant bool matched={invariant}"
        return not true_matches and not false_matches and not invariant, detail

    evaluate("errno-boolean-no-match", errno_boolean_no_match)

    def accounting_missing_outcome() -> tuple[bool, str]:
        result = reconcile(selection.case_ids, [])
        detail = "; ".join(item.render() for item in result.diagnostics)
        return result.has("contradiction") and not result.balanced, detail or "no diagnostics"

    evaluate("accounting-missing-outcome", accounting_missing_outcome)

    def accounting_missing_pass_role() -> tuple[bool, str]:
        outcome = CaseOutcome(
            selection.case_ids[0],
            "PASS",
            (RoleResult("candidate", "pass"), RoleResult("comparator", "pass")),
        )
        result = reconcile(selection.case_ids, [outcome])
        detail = "; ".join(item.render() for item in result.diagnostics)
        return result.has("contradiction"), detail or "no diagnostics"

    evaluate("accounting-pass-missing-role", accounting_missing_pass_role)

    def accounting_fail_all_pass() -> tuple[bool, str]:
        outcome = CaseOutcome(
            selection.case_ids[0],
            "FAIL",
            (
                RoleResult("candidate", "pass"),
                RoleResult("reference", "pass"),
                RoleResult("comparator", "pass"),
                RoleResult("validator", "pass"),
            ),
        )
        result = reconcile(selection.case_ids, [outcome])
        detail = "; ".join(item.render() for item in result.diagnostics)
        return result.has("contradiction"), detail or "no diagnostics"

    evaluate("accounting-fail-all-pass", accounting_fail_all_pass)

    def accounting_contradiction(disposition: str, roles: tuple[RoleResult, ...]) -> tuple[bool, str]:
        outcome = CaseOutcome(selection.case_ids[0], disposition, roles)
        result = reconcile(selection.case_ids, [outcome])
        detail = "; ".join(item.render() for item in result.diagnostics)
        return result.has("contradiction"), detail or "no diagnostics"

    evaluate(
        "accounting-reference-failure-pass",
        lambda: accounting_contradiction(
            "REFERENCE_FAILURE",
            (RoleResult("candidate", "fail"), RoleResult("reference", "pass"), RoleResult("comparator", "fail"), RoleResult("validator", "pass")),
        ),
    )
    evaluate(
        "accounting-fail-comparator-pass",
        lambda: accounting_contradiction(
            "FAIL",
            (RoleResult("candidate", "fail"), RoleResult("reference", "pass"), RoleResult("comparator", "pass"), RoleResult("validator", "pass")),
        ),
    )
    for disposition, candidate_status in (
        ("TIMEOUT", "timeout"),
        ("PANIC", "panic"),
        ("HARNESS_ERROR", "harness-error"),
    ):
        evaluate(
            f"accounting-{disposition.lower().replace('_', '-')}-comparator-pass",
            lambda disposition=disposition, candidate_status=candidate_status: accounting_contradiction(
                disposition,
                (
                    RoleResult("candidate", candidate_status),
                    RoleResult("reference", "pass"),
                    RoleResult("comparator", "pass"),
                    RoleResult("validator", "pass"),
                ),
            ),
        )
    evaluate(
        "accounting-reference-failure-comparator-pass",
        lambda: accounting_contradiction(
            "REFERENCE_FAILURE",
            (
                RoleResult("candidate", "fail"),
                RoleResult("reference", "fail"),
                RoleResult("comparator", "pass"),
                RoleResult("validator", "fail"),
            ),
        ),
    )
    evaluate(
        "accounting-timeout-missing-evidence",
        lambda: accounting_contradiction(
            "TIMEOUT",
            (RoleResult("reference", "not-required"), RoleResult("comparator", "fail"), RoleResult("validator", "not-required")),
        ),
    )
    evaluate(
        "accounting-panic-wrong-evidence",
        lambda: accounting_contradiction(
            "PANIC",
            (RoleResult("candidate", "pass"), RoleResult("reference", "not-required"), RoleResult("comparator", "fail"), RoleResult("validator", "pass")),
        ),
    )
    evaluate(
        "accounting-harness-missing-evidence",
        lambda: accounting_contradiction(
            "HARNESS_ERROR",
            (RoleResult("reference", "not-required"), RoleResult("comparator", "fail"), RoleResult("validator", "pass")),
        ),
    )

    all_pass_roles = (
        RoleResult("candidate", "pass"),
        RoleResult("reference", "pass"),
        RoleResult("comparator", "pass"),
        RoleResult("validator", "pass"),
    )
    xpass_result = reconcile(
        selection.case_ids,
        [CaseOutcome(selection.case_ids[0], "XPASS", all_pass_roles)],
    )
    if not xpass_result.has("contradiction"):
        checks.append("XPASS accounting accepts executed pass evidence")
    else:
        internal_failures.append("XPASS with executed pass evidence was contradicted")

    for disposition, control_name in (
        ("NOT_RUN", "accounting-not-run-all-pass"),
        ("XFAIL", "accounting-xfail-all-pass"),
        ("SKIP_PREREQUISITE", "accounting-skip-prerequisite-all-pass"),
        ("UNSUPPORTED", "accounting-unsupported-all-pass"),
    ):
        evaluate(
            control_name,
            lambda disposition=disposition: accounting_contradiction(disposition, all_pass_roles),
        )

    for disposition, control_name in (
        ("NOT_RUN", "accounting-not-run-candidate-pass"),
        ("XFAIL", "accounting-xfail-candidate-pass"),
        ("SKIP_PREREQUISITE", "accounting-skip-candidate-pass"),
        ("UNSUPPORTED", "accounting-unsupported-candidate-pass"),
    ):
        evaluate(
            control_name,
            lambda disposition=disposition: accounting_contradiction(disposition, (RoleResult("candidate", "pass"),)),
        )

    supervisor = Supervisor()
    python = sys.executable
    budget_result = supervisor.run([python, "-c", "print('x' * 100)"], timeout=3, output_budget=10)
    if budget_result.output_truncated and len(budget_result.stdout) <= 10:
        checks.append("supervisor output byte budget bounds captured output")
    else:
        internal_failures.append("supervisor output byte budget positive check failed")
    if budget_result.teardown_backend != "unsupported" and budget_result.teardown_state == "verified-empty" and budget_result.outcome == "exit":
        checks.append("leaf target teardown is verified empty through " + budget_result.teardown_backend)
    elif budget_result.teardown_backend == "unsupported" and budget_result.teardown_state == "fork-tainted-unproven":
        checks.append("leaf target teardown is explicitly unproven without a strict backend")
    else:
        internal_failures.append(
            f"leaf target teardown check failed: outcome={budget_result.outcome} state={budget_result.teardown_state} backend={budget_result.teardown_backend}"
        )

    def guest_panic() -> tuple[bool, str]:
        result = supervisor.run([python, "-c", "print('kernel panic: injected control')"], timeout=3, output_budget=4096)
        return result.outcome == "panic", f"outcome={result.outcome}"

    evaluate("guest-panic", guest_panic)

    def bracket_panic() -> tuple[bool, str]:
        result = supervisor.run([python, "-c", "print('[PANIC]: setup failure')"], timeout=3, output_budget=4096)
        return result.outcome == "panic", f"outcome={result.outcome}"

    evaluate("guest-bracket-panic", bracket_panic)

    def non_resettable_panic() -> tuple[bool, str]:
        result = supervisor.run([python, "-c", "print('Non-resettable panic!')"], timeout=3, output_budget=4096)
        return result.outcome == "panic", f"outcome={result.outcome}"

    evaluate("guest-non-resettable-panic", non_resettable_panic)

    plain_panic_result = supervisor.run([python, "-c", "print('panic')"], timeout=3, output_budget=4096)
    if plain_panic_result.outcome == "exit":
        checks.append("generic panic substring does not trigger panic classification")
    else:
        internal_failures.append(f"generic panic substring misclassified as {plain_panic_result.outcome}")

    def panic_after_output_budget() -> tuple[bool, str]:
        code = "import sys; sys.stdout.write('x' * 2048); sys.stdout.write('kernel panic: after budget'); sys.stdout.flush()"
        result = supervisor.run([python, "-c", code], timeout=3, output_budget=16)
        return result.outcome == "panic" and result.output_truncated, f"outcome={result.outcome} truncated={result.output_truncated}"

    evaluate("panic-after-output-budget", panic_after_output_budget)

    def verbose_output_is_activity() -> tuple[bool, str]:
        code = "import sys, time; end = time.time() + 0.4\nwhile time.time() < end:\n sys.stdout.write('x' * 100); sys.stdout.flush(); time.sleep(0.005)"
        result = supervisor.run([python, "-c", code], timeout=3, output_budget=16, silence_timeout=0.1)
        return result.outcome == "exit", f"outcome={result.outcome} bytes={result.stdout_bytes}"

    evaluate("verbose-output-not-silence", verbose_output_is_activity)

    def guest_hang() -> tuple[bool, str]:
        code = "import time; print('HANG-MARKER', flush=True); time.sleep(30)"

        def hook(stream: str, chunk: bytes) -> str | None:
            if b"HANG-MARKER" in chunk:
                return "hang"
            return None

        result = supervisor.run([python, "-c", code], timeout=5, output_budget=4096, event_hook=hook)
        return result.outcome == "hang", f"outcome={result.outcome}"

    evaluate("guest-hang", guest_hang)

    def host_timeout() -> tuple[bool, str]:
        result = supervisor.run([python, "-c", "import time; time.sleep(5)"], timeout=0.2, output_budget=4096)
        return result.outcome == "timeout", f"outcome={result.outcome}"

    evaluate("host-timeout", host_timeout)

    def timeout_cleanup_failure_escalates() -> tuple[bool, str]:
        def cleanup() -> None:
            raise RuntimeError("injected timeout cleanup failure")

        result = supervisor.run([python, "-c", "import time; time.sleep(5)"], timeout=0.2, output_budget=4096, cleanup=cleanup)
        detail = f"outcome={result.outcome} details={result.teardown_details}"
        return bool(result.cleanup_errors) and result.outcome == "harness-error", detail

    evaluate("timeout-cleanup-failure-escalates", timeout_cleanup_failure_escalates)

    def fork_panic_escalates() -> tuple[bool, str]:
        child = "import time; time.sleep(1)"
        code = f"import subprocess, sys; subprocess.Popen([sys.executable, '-c', {child!r}]); print('kernel panic: forked control', flush=True)"
        result = supervisor.run([python, "-c", code], timeout=5, output_budget=4096)
        detail = f"outcome={result.outcome} teardown={result.teardown_state} details={result.teardown_details}"
        return result.outcome == "harness-error" and result.teardown_state == "fork-tainted-unproven", detail

    evaluate("fork-panic-escalates", fork_panic_escalates)

    def reader_capture_failure_escalates() -> tuple[bool, str]:
        code = "import os\nfor _ in range(200):\n os.write(1, b'x' * 1024)"
        with mock.patch.object(supervisor_module.select, "select", side_effect=ValueError("filedescriptor out of range in select()")):
            result = supervisor.run([python, "-c", code], timeout=0.4, output_budget=4096)
        detail = f"outcome={result.outcome} reader_errors={result.reader_errors} bytes={result.stdout_bytes}"
        return bool(result.reader_errors) and result.outcome == "harness-error", detail

    evaluate("reader-capture-failure-escalates", reader_capture_failure_escalates)

    def supervisor_nonfinite_timeouts() -> tuple[bool, str]:
        rejected = []
        for kwargs in ({"timeout": float("nan")}, {"timeout": float("inf")}, {"timeout": 1, "silence_timeout": float("nan")}, {"timeout": 1, "process_tree_interval": float("nan")}):
            try:
                supervisor.run([python, "-c", "pass"], output_budget=1024, **kwargs)
            except ValueError:
                rejected.append(True)
            else:
                rejected.append(False)
        return all(rejected), f"rejections={rejected}"

    evaluate("supervisor-nonfinite-timeouts", supervisor_nonfinite_timeouts)

    def orphaned_child() -> tuple[bool, str]:
        child = "import time; time.sleep(30)"
        code = f"import subprocess, sys; subprocess.Popen([sys.executable, '-c', {child!r}]); print('orphan parent exiting', flush=True)"
        result = supervisor.run([python, "-c", code], timeout=5, output_budget=4096)
        detected = (
            result.outcome == "harness-error"
            and result.teardown_state == "fork-tainted-unproven"
            and not result.observed_descendant_pids
        )
        return detected, f"outcome={result.outcome} teardown={result.teardown_state} observed={result.observed_descendant_pids}"

    evaluate("orphaned-child", orphaned_child)

    def regrouped_grandchild() -> tuple[bool, str]:
        sync_path = bundle.work_dir / "fast-setsid-ready"
        grandchild = (
            f"import os, time; os.setsid(); open({str(sync_path)!r}, 'w').close(); "
            "devnull = os.open(os.devnull, os.O_WRONLY); os.dup2(devnull, 1); os.dup2(devnull, 2); time.sleep(30)"
        )
        child = (
            f"import subprocess, sys; process = subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
            "print('GRANDPID=%d' % process.pid, flush=True)"
        )
        code = (
            f"import os, subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}]); "
            f"deadline = time.time() + 1.0\nwhile not os.path.exists({str(sync_path)!r}) and time.time() < deadline:\n time.sleep(0.005)"
        )
        result = supervisor.run([python, "-c", code], timeout=5, output_budget=4096)
        try:
            sync_path.unlink()
        except FileNotFoundError:
            pass
        marker = next((line for line in result.stdout.decode(errors="replace").splitlines() if line.startswith("GRANDPID=")), "")
        grandchild_pid = int(marker.split("=", 1)[1]) if marker else -1
        cleanup_error = ""
        survivor_was_alive = False
        if grandchild_pid > 0:
            try:
                os.kill(grandchild_pid, 0)
                survivor_was_alive = True
            except ProcessLookupError:
                pass
            try:
                os.kill(grandchild_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                try:
                    os.kill(grandchild_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                cleanup_error = "test-owned grandchild survived cleanup"
        detected = (
            grandchild_pid > 0
            and survivor_was_alive
            and result.outcome == "harness-error"
            and result.teardown_state in {"fork-tainted-unproven", "failed"}
            and not cleanup_error
        )
        detail = (
            f"outcome={result.outcome} teardown={result.teardown_state} grandchild={grandchild_pid} alive={survivor_was_alive} "
            f"observed={result.observed_descendant_pids} details={result.teardown_details} cleanup={cleanup_error or 'ok'}"
        )
        return detected, detail

    evaluate("fast-double-fork-setsid-unproven", regrouped_grandchild)

    positive_rc, positive_stdout = _wrapper_probe(_EXEC_RELEASE_BYTE)
    if positive_rc == 0 and b"target-execed" in positive_stdout:
        checks.append("exec gate authorizes the target only with the release byte")
    else:
        internal_failures.append(f"exec gate positive probe failed: rc={positive_rc} stdout={positive_stdout[:80]!r}")

    def exec_gate_eof() -> tuple[bool, str]:
        returncode, stdout = _wrapper_probe(None)
        detected = b"target-execed" not in stdout and returncode != 0
        return detected, f"rc={returncode} execed={b'target-execed' in stdout}"

    evaluate("exec-gate-eof", exec_gate_eof)

    def exec_gate_wrong_byte() -> tuple[bool, str]:
        wrong_byte = bytes([_EXEC_RELEASE_BYTE[0] ^ 0xFF])
        returncode, stdout = _wrapper_probe(wrong_byte)
        detected = b"target-execed" not in stdout and returncode != 0
        return detected, f"rc={returncode} execed={b'target-execed' in stdout}"

    evaluate("exec-gate-wrong-byte", exec_gate_wrong_byte)

    def setup_exception_kills_child() -> tuple[bool, str]:
        token = "lc02-setup-exception-" + uuid.uuid4().hex
        code = f"import time; print('{token}', flush=True); time.sleep(30)"
        propagated = ""
        try:
            with mock.patch.object(supervisor_module, "ProcessTreeTracker", side_effect=RuntimeError("injected setup failure")):
                supervisor.run([python, "-c", code], timeout=5, output_budget=4096)
        except RuntimeError as error:
            propagated = str(error)
        if not propagated:
            return False, "injected post-spawn setup exception did not propagate"
        survivors: list[int] = []
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            survivors = _scan_token_pids(token)
            if not survivors:
                break
            time.sleep(0.05)
        for pid in survivors:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        detected = not survivors
        return detected, f"propagated={propagated!r} survivors={survivors}"

    evaluate("setup-exception-kills-child", setup_exception_kills_child)

    def interrupted_cleanup() -> tuple[bool, str]:
        def cleanup() -> None:
            raise RuntimeError("injected cleanup interruption")

        result = supervisor.run([python, "-c", "print('cleanup control')"], timeout=3, output_budget=4096, cleanup=cleanup)
        detected = bool(result.cleanup_errors) and result.outcome == "harness-error"
        detail = "; ".join(result.cleanup_errors) + f" outcome={result.outcome}" if result.cleanup_errors else f"no cleanup error outcome={result.outcome}"
        return detected, detail

    evaluate("interrupted-cleanup", interrupted_cleanup)

    def full_output_disk() -> tuple[bool, str]:
        class FullDisk:
            def write(self, data: bytes) -> int:
                raise OSError(errno.ENOSPC, "No space left on device")

            def flush(self) -> None:
                return None

            def close(self) -> None:
                return None

        result = supervisor.run(
            [python, "-c", "print('full disk control')"],
            timeout=3,
            output_budget=4096,
            log_opener=lambda: FullDisk(),
        )
        detected = is_full_disk_error(result.log_errors) and result.outcome == "harness-error"
        detail = (_render_os_errors(result.log_errors) or "no log error") + f" outcome={result.outcome}"
        return detected, detail

    evaluate("full-output-disk", full_output_disk)

    def logging_failure() -> tuple[bool, str]:
        missing_parent = bundle.work_dir / "missing-log-parent" / "supervisor.log"
        result = supervisor.run(
            [python, "-c", "print('logging control')"],
            timeout=3,
            output_budget=4096,
            log_path=missing_parent,
        )
        detected = bool(result.log_errors) and not is_full_disk_error(result.log_errors) and result.outcome == "harness-error"
        detail = (_render_os_errors(result.log_errors) or "no log error") + f" outcome={result.outcome}"
        return detected, detail

    evaluate("logging-failure", logging_failure)

    def missing_artifact() -> tuple[bool, str]:
        control_bundle = EvidenceBundle.create(qualification_root)
        try:
            control_bundle.register_artifact("missing.bin", b"missing artifact control")
            path = control_bundle.root / control_bundle.registry["missing.bin"]["path"]
            path.unlink()
            diagnostics = control_bundle.validate_artifacts()
            return any(item.category == "missing-artifact" for item in diagnostics), "; ".join(item.render() for item in diagnostics) or "no diagnostics"
        finally:
            shutil.rmtree(control_bundle.root)

    evaluate("missing-artifact", missing_artifact)

    def checksum_mismatch() -> tuple[bool, str]:
        control_bundle = EvidenceBundle.create(qualification_root)
        try:
            control_bundle.register_artifact("corrupt.bin", b"original bytes")
            path = control_bundle.root / control_bundle.registry["corrupt.bin"]["path"]
            path.write_bytes(b"corrupted bytes")
            diagnostics = control_bundle.validate_artifacts()
            return any(item.category == "checksum-mismatch" for item in diagnostics), "; ".join(item.render() for item in diagnostics) or "no diagnostics"
        finally:
            shutil.rmtree(control_bundle.root)

    evaluate("checksum-mismatch", checksum_mismatch)

    def source_hash_input_sensitivity() -> tuple[bool, str]:
        fixture = bundle.work_dir / "source-hash-inputs"
        vendor = fixture / "vendor" / "smoltcp" / "src"
        vendor.mkdir(parents=True, exist_ok=True)
        (fixture / "kernel").mkdir(parents=True, exist_ok=True)
        (fixture / ".cargo").mkdir(parents=True, exist_ok=True)
        (fixture / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        (fixture / "kernel" / "lib.rs").write_text("pub fn kernel() {}\n", encoding="utf-8")
        baseline = asterinas_source_tree_hash(fixture)
        (vendor / "lib.rs").write_text("pub fn changed() {}\n", encoding="utf-8")
        with_vendor = asterinas_source_tree_hash(fixture)
        (fixture / ".cargo" / "config.toml").write_text("[source.crates-io]\nreplace-with = \"mirror\"\n", encoding="utf-8")
        with_cargo = asterinas_source_tree_hash(fixture)
        detected = baseline != with_vendor and with_vendor != with_cargo
        detail = f"base={baseline[:12]} vendor={with_vendor[:12]} cargo={with_cargo[:12]}"
        return detected, detail

    evaluate("source-hash-vendored-and-cargo-sensitivity", source_hash_input_sensitivity)

    def probe_cache_container_identity() -> tuple[bool, str]:
        path = bundle.work_dir / "probe-cache-binary"
        path.write_bytes(b"cached probe")
        previous = {
            "probe": {
                "source_sha256": lock_module._sha256_file(repo / "test/qualification/probe/probe.c"),
                "nix_sha256": lock_module._sha256_file(repo / "test/qualification/probe/default.nix"),
                "binary_sha256": lock_module._sha256_file(path),
            },
            "asterinas_build": {
                "flake_lock_sha256": lock_module._sha256_file(repo / "flake.lock"),
                "nixpkgs_sha256": lock_module._sha256_file(repo / "distro/nixpkgs.nix"),
                "rust_toolchain_sha256": lock_module._sha256_file(repo / "rust-toolchain.toml"),
            },
            "dev_container": {"digest": "old-container"},
        }
        with mock.patch.object(lock_module, "read_json_file", return_value=previous):
            stale = _probe_rebuild_required(repo, path, "new-container")
        matching = copy.deepcopy(previous)
        matching["dev_container"]["digest"] = "new-container"
        with mock.patch.object(lock_module, "read_json_file", return_value=matching):
            fresh = _probe_rebuild_required(repo, path, "new-container")
        return stale and not fresh, f"stale container rebuild={stale} matching container rebuild={fresh}"

    evaluate("probe-cache-container-identity", probe_cache_container_identity)

    valid_log = bundle.work_dir / "blklog-valid.log"
    _blklog_fixture(valid_log, [(0, 1, 0), (8, 1, LOG_FLUSH_FLAG)])
    valid_failures = validate_blklogwrites(valid_log)
    if not valid_failures:
        checks.append("complete blklogwrites log with a flush record is accepted")
    else:
        internal_failures.append("valid blklogwrites fixture was rejected: " + "; ".join(valid_failures))

    def blklog_control(name, entries, cut=None, declared=None, want_fail=True):
        def function() -> tuple[bool, str]:
            path = bundle.work_dir / f"blklog-{name}.log"
            _blklog_fixture(path, entries, declared=declared)
            if cut is not None:
                raw = path.read_bytes()
                path.write_bytes(raw[:cut])
            failures = validate_blklogwrites(path)
            return (bool(failures) == want_fail), ("; ".join(failures) if failures else "log was accepted")
        return function

    two_writes = [(0, 1, 0), (8, 1, 0)]
    evaluate("blklog-truncated-final-header-fields", blklog_control("final-header-fields", two_writes, cut=1552))
    evaluate("blklog-truncated-final-header-padding", blklog_control("final-header-padding", two_writes, cut=1576))
    evaluate("blklog-truncated-final-payload", blklog_control("final-payload", two_writes, cut=2304))
    evaluate("blklog-inconsistent-count", blklog_control("inconsistent-count", two_writes, declared=3))
    evaluate("blklog-impossible-size", blklog_control("impossible-size", [(0, 1 << 62, 0)]))
    evaluate("blklog-unsupported-flags", blklog_control("unsupported-flags", [(0, 1, 1 << 20)]))
    evaluate("blklog-no-data-writes", blklog_control("no-data-writes", [(0, 0, LOG_FLUSH_FLAG)]))

    def persistence_model(name: str, entries: list[tuple[int, int, int]]) -> tuple[bool, str]:
        path = bundle.work_dir / f"persistence-{name}.log"
        _blklog_fixture(path, entries)
        records = parse_records(path)
        cuts = enumerate_crash_cuts(records)
        detected = omitted_sync_detected(records)
        durable_at_last_cut = len(durable_writes(records, cuts[-1]))
        write_count = sum(1 for record in records if is_data_write(record))
        return cuts[0] == 0 and cuts[-1] == len(records) and durable_at_last_cut == write_count and not detected, (
            f"cuts={cuts} durable={durable_at_last_cut} writes={write_count} omitted={detected}"
        )

    evaluate(
        "persistence-synced-write-durable",
        lambda: persistence_model("synced", [(0, 1, 0), (8, 1, 0), (16, 0, LOG_FLUSH_FLAG)]),
    )

    def persistence_omitted() -> tuple[bool, str]:
        path = bundle.work_dir / "persistence-omitted.log"
        _blklog_fixture(path, [(0, 1, 0), (8, 0, LOG_FLUSH_FLAG), (16, 1, 0)])
        records = parse_records(path)
        detected = omitted_sync_detected(records)
        cuts = enumerate_crash_cuts(records)
        durable = durable_writes(records, cuts[-1])
        return detected and cuts == [0, 2] and len(durable) == 1 and durable[0].index == 0, (
            f"cuts={cuts} omitted={detected} durable={list(durable)}"
        )

    evaluate("persistence-omitted-sync-detected", persistence_omitted)

    def persistence_corrupt() -> tuple[bool, str]:
        path = bundle.work_dir / "persistence-corrupt.log"
        _blklog_fixture(path, [(0, 1, 0)])
        raw = path.read_bytes()
        path.write_bytes(raw[:800])
        try:
            parse_records(path)
        except ValueError:
            return True, "corrupt log rejected by model"
        return False, "corrupt log accepted by model"

    evaluate("persistence-corrupt-log-rejected", persistence_corrupt)

    def persistence_missing_sector() -> tuple[bool, str]:
        synced_path = bundle.work_dir / "persistence-compare-synced.log"
        omitted_path = bundle.work_dir / "persistence-compare-omitted.log"
        _blklog_fixture(synced_path, [(0, 1, 0), (8, 1, 0), (16, 0, LOG_FLUSH_FLAG)])
        _blklog_fixture(omitted_path, [(0, 1, 0), (8, 0, LOG_FLUSH_FLAG)])
        missing = missing_durable_sectors(parse_records(synced_path), parse_records(omitted_path))
        return missing == {8}, f"missing durable sectors={sorted(missing)}"

    evaluate("persistence-missing-durable-sector", persistence_missing_sector)

    def copied_input_control(name: str, original: bytes, replacement: bytes) -> tuple[bool, str]:
        path = bundle.work_dir / f"copy-{name}"
        path.write_bytes(original)
        expected = {name: sha256_bytes(original)}
        path.write_bytes(replacement)
        failures = verify_copied_input_hashes({name: path}, expected)
        return bool(failures) and "hash drift" in failures[0], "; ".join(failures) or "substituted bytes were accepted"

    for control_name in ("asterinas-kernel", "probe", "initramfs.cpio", "inputs.lock.json"):
        evaluate(
            f"snapshot-changed-{control_name}",
            lambda control_name=control_name: copied_input_control(control_name, b"verified bytes", b"substituted bytes"),
        )

    matching = bundle.work_dir / "copy-matching"
    matching.write_bytes(b"verified bytes")
    if not verify_copied_input_hashes({"probe": matching}, {"probe": sha256_bytes(b"verified bytes")}):
        checks.append("copied input identity matches the verified snapshot")
    else:
        internal_failures.append("matching copied input was rejected")

    def dummy_snapshot(**overrides) -> RunSnapshot:
        values = {
            "policy_hash": "0" * 64,
            "qemu_path": Path(sys.executable),
            "qemu_resolved_path": Path(sys.executable),
            "qemu_version": "control-version",
            "qemu_sha256": sha256_bytes(b"verified backend"),
            "manifest_hash": selection.manifest_hash,
            "payload_hash": selection.payload_hash,
            "case_ids": tuple(selection.case_ids),
            "expected_hashes": {},
        }
        values.update(overrides)
        return RunSnapshot(**values)

    def selection_drift_control(field: str, value) -> tuple[bool, str]:
        try:
            assert_selection_snapshot(selection, dummy_snapshot(**{field: value}))
        except RunFailure as error:
            return True, str(error)
        return False, f"selection {field} drift was accepted"

    evaluate("snapshot-changed-selection-manifest", lambda: selection_drift_control("manifest_hash", "0" * 64))
    evaluate("snapshot-changed-selection-payload", lambda: selection_drift_control("payload_hash", "0" * 64))
    evaluate("snapshot-changed-selection-cases", lambda: selection_drift_control("case_ids", ("core.unknown",)))

    def snapshot_policy_control(change: str) -> tuple[bool, str]:
        backend = bundle.work_dir / f"verified-backend-{change}"
        backend.write_bytes(b"verified backend")
        policy = json.loads((repo / lock_module.LOCK_PATH).read_bytes())
        policy["asterinas_build"]["rw_kernel_sha256"] = "f" * 64
        policy["qemu"] = {
            "path": str(backend),
            "resolved_path": str(backend.resolve()),
            "version": "control-version",
            "sha256": sha256_bytes(backend.read_bytes()),
        }
        verification = lock_module.LockVerification("0" * 64, (), {}, policy)
        replacement = selection
        if change == "backend":
            backend.write_bytes(b"substituted backend")
        else:
            replacement = Selection(
                selection.profile_name, selection.cases, "f" * 64,
                selection.payload_hash, selection.excluded,
            )
        with mock.patch("qualcore.runner.qemu_version", return_value="control-version"):
            try:
                create_snapshot(verification, replacement)
            except RunFailure as error:
                return True, str(error)
        return False, "snapshot accepted a substitution after verification"

    evaluate("snapshot-rejects-substituted-backend", lambda: snapshot_policy_control("backend"))
    evaluate("snapshot-rejects-substituted-selection", lambda: snapshot_policy_control("selection"))

    def policy_file_substitution() -> tuple[bool, str]:
        policy_repo = bundle.work_dir / "policy-repo"
        policy = policy_repo / lock_module.LOCK_PATH
        policy.parent.mkdir(parents=True)
        policy.write_text('{"schema": 1, "revision": "verified"}', encoding="utf-8")

        def replace_policy(*args) -> tuple[str, ...]:
            policy.write_text('{"schema": 1, "revision": "substituted"}', encoding="utf-8")
            return ()

        with mock.patch.object(lock_module, "verify_lock_document", side_effect=replace_policy):
            try:
                lock_module.verify_lock(policy_repo)
            except lock_module.LockError as error:
                return "changed during verification" in str(error), str(error)
        return False, "substituted policy was accepted"

    evaluate("snapshot-rejects-substituted-policy", policy_file_substitution)

    backend_path = bundle.work_dir / "backend-binary"
    backend_path.write_bytes(b"verified backend")
    backend_failures = verify_backend_identity(backend_path, sha256_bytes(b"other backend"), None)
    evaluate(
        "snapshot-changed-backend",
        lambda: (bool(backend_failures) and "hash drift" in backend_failures[0], "; ".join(backend_failures) or "backend substitution was accepted"),
    )

    evidence_case = selection.cases[0]
    valid_observed = _observed_values(
        ingest_result_stream(_stream(run_id, nonce, valid_records), _context(selection, run_id, nonce)),
        evidence_case.case_id,
    )

    def backend_fixture(**overrides) -> BackendEvidence:
        values = {
            "label": "control",
            "stream_run_id": "control-run",
            "nonce": "control-nonce",
            "execution_outcome": "exit",
            "exit_code": 0,
            "teardown_state": "verified-empty",
            "duration_seconds": 0.1,
            "ingestion_diagnostics": (),
            "observed": {evidence_case.case_id: valid_observed},
            "final_status": "pass",
            "stream_text": "",
            "console_text": "",
            "storage_diagnostics": (),
        }
        values.update(overrides)
        return BackendEvidence(**values)

    reference_fixture = backend_fixture()

    def evidence_precedence(name: str, overrides: dict, expected: str) -> tuple[bool, str]:
        outcome = evaluate_case(evidence_case, reference_fixture, backend_fixture(**overrides))
        preserved = "runtime observation before evidence escalation" in outcome.reason
        ok = outcome.disposition == expected and (not preserved or expected == "HARNESS_ERROR")
        return ok, f"disposition={outcome.disposition} reason={outcome.reason[:140]}"

    corrupt_log = ("blklogwrites log ended after 0 of 1 entries",)
    evaluate(
        "evidence-panic-plus-corrupt-block-log",
        lambda: evidence_precedence(
            "panic-corrupt-log",
            {"execution_outcome": "panic", "exit_code": None, "storage_diagnostics": corrupt_log},
            "HARNESS_ERROR",
        ),
    )
    evaluate(
        "evidence-timeout-plus-corrupt-block-log",
        lambda: evidence_precedence(
            "timeout-corrupt-log",
            {"execution_outcome": "timeout", "exit_code": None, "storage_diagnostics": corrupt_log},
            "HARNESS_ERROR",
        ),
    )
    evaluate(
        "evidence-failure-plus-failed-capture",
        lambda: evidence_precedence(
            "failure-failed-capture",
            {"exit_code": 1, "ingestion_diagnostics": ("missing-artifact: dedicated serial log",)},
            "HARNESS_ERROR",
        ),
    )
    evaluate(
        "evidence-failure-plus-incomplete-teardown",
        lambda: evidence_precedence(
            "failure-incomplete-teardown",
            {"exit_code": 1, "teardown_state": "failed"},
            "HARNESS_ERROR",
        ),
    )
    evaluate(
        "evidence-valid-panic-remains-panic",
        lambda: evidence_precedence("valid-panic", {"execution_outcome": "panic", "exit_code": None}, "PANIC"),
    )
    passing_outcome = evaluate_case(evidence_case, reference_fixture, backend_fixture())
    if passing_outcome.disposition == "PASS":
        checks.append("valid evidence with a passing candidate remains PASS")
    else:
        internal_failures.append(f"valid passing pair rejected: {passing_outcome.disposition}")

    multi_selection = load_profile(
        "pilot-ext2",
        repo / "test" / "qualification" / "profiles",
        load_case_index(sorted((repo / "test" / "qualification" / "contracts").glob("*/*.json"))),
    )

    def finalization_control(name, message, completed: int, publication_failure: bool = False):
        def function() -> tuple[bool, str]:
            state = RunState()
            state.selection = multi_selection
            state.bundle = EvidenceBundle.create(qualification_root)
            state.run_errors = [message]
            for case_id in multi_selection.case_ids[:completed]:
                state.outcomes[case_id] = CaseOutcome(
                    case_id,
                    "PASS",
                    (
                        RoleResult("candidate", "pass"),
                        RoleResult("reference", "pass"),
                        RoleResult("comparator", "pass"),
                        RoleResult("validator", "pass"),
                    ),
                )
            try:
                if publication_failure:
                    with mock.patch.object(state.bundle, "publish_report", side_effect=RuntimeError(message)) as publish:
                        returncode = finalize_run(state, multi_selection.profile_name, "asterinas")
                    report = publish.call_args.args[0]
                    report_exists = True
                else:
                    returncode = finalize_run(state, multi_selection.profile_name, "asterinas")
                    report_path = state.bundle.root / "report.json"
                    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
                    report_exists = report_path.exists()
                outcomes = report.get("outcomes", {})
                total = sum(report.get("dispositions", {}).values())
                partition_ok = (
                    len(outcomes) == len(multi_selection.case_ids)
                    and total == len(multi_selection.case_ids)
                    and sum(1 for item in outcomes.values() if item["disposition"] == "PASS") == completed
                    and sum(1 for item in outcomes.values() if item["disposition"] == "NOT_RUN") == len(multi_selection.case_ids) - completed
                )
                errors_distinct = report.get("run_errors") == [message] and report.get("dispositions", {}).get("HARNESS_ERROR", 0) == 0
                cleanup_ok = not (state.bundle.root / "work").exists()
                artifact_ok = (state.bundle.root / "artifacts" / "harness-error.txt").is_file()
                publication_ok = True
                if publication_failure:
                    publication_ok = bool(report.get("outcomes")) and bool(report.get("run_errors"))
                detected = (
                    returncode == 1 and report_exists and partition_ok and errors_distinct
                    and cleanup_ok and artifact_ok and publication_ok
                )
                detail = (
                    f"rc={returncode} published={report_exists} partition={partition_ok} distinct={errors_distinct} "
                    f"cleanup={cleanup_ok} artifact={artifact_ok} publication={publication_ok}"
                )
                return detected, detail
            finally:
                shutil.rmtree(state.bundle.root, ignore_errors=True)

        return function

    evaluate("finalization-failure-before-boot", finalization_control("before-boot", "injected failure before boot", 0))
    evaluate(
        "finalization-failure-between-paired-executions",
        finalization_control("between-paired", "injected failure between paired executions", 1),
    )
    evaluate(
        "finalization-failure-during-capture",
        finalization_control("during-capture", "injected failure during artifact capture", 1),
    )
    evaluate(
        "finalization-failure-during-publication",
        finalization_control("during-publication", "injected publication failure", 1, publication_failure=True),
    )

    bundle.register_artifact("stdout.log", b"lc02 selftest\n")

    detected_count = sum(1 for control in controls if control.detected)
    for control in controls:
        state = "DETECTED" if control.detected else "NOT-DETECTED"
        print(f"{state} {control.name}: {control.detail}")

    all_detected = detected_count == len(controls)
    report = {
        "run_id": run_id,
        "profile": selection.profile_name,
        "manifest_hash": selection.manifest_hash,
        "payload_hash": selection.payload_hash,
        "selected_count": len(selection.case_ids),
        "dispositions": dict(accounting.counts),
        "controls": {control.name: {"detected": control.detected, "detail": control.detail} for control in controls},
        "controls_detected": detected_count,
        "controls_total": len(controls),
        "internal_failures": internal_failures,
    }

    try:
        bundle.publish_report(report)
        try:
            bundle.publish_report(report)
            internal_failures.append("immutable report accepted a second publication")
        except EvidenceError:
            checks.append("atomic report publication is immutable")
        try:
            EvidenceBundle.create(qualification_root, run_id)
            internal_failures.append("run directory reuse was accepted")
        except EvidenceError:
            checks.append("rerun with the same run id is refused")
    except Exception as error:
        internal_failures.append(f"evidence publication failed: {error}")

    teardown_errors = bundle.teardown()
    if teardown_errors:
        internal_failures.extend("evidence teardown: " + item for item in teardown_errors)

    for failure in internal_failures:
        print(f"INTERNAL-FAIL {failure}")
    for check in checks:
        print(f"CHECK {check}")

    print(f"SELFTEST RESULT: {detected_count}/{len(controls)} controls detected")
    return 0 if all_detected and not internal_failures else 1
