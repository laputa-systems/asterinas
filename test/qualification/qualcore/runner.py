import json
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .accounting import CaseOutcome, RoleResult, reconcile
from .adapter import validate_blklogwrites
from .compare import compare_value, verify_comparison_claim
from .evidence import EvidenceBundle
from .lock import (
    CACHE_DIR,
    LOCK_PATH,
    LockError,
    LockVerification,
    verify_lock,
    verify_lock_document,
    write_effective_lock,
)
from .manifest import CaseSpec, Selection, load_case_index, load_profile
from .qemu import VmExclusion, qemu_version, resolve_qemu_path, run_qemu
from .supervisor import Supervisor
from .results import ResultContext, ingest_result_stream, make_result_line
from .util import sha256_bytes


@dataclass(frozen=True)
class BackendEvidence:
    label: str
    stream_run_id: str
    nonce: str
    execution_outcome: str
    exit_code: int | None
    teardown_state: str
    duration_seconds: float
    ingestion_diagnostics: tuple[str, ...]
    observed: dict[str, dict[str, Any]]
    final_status: str | None
    stream_text: str
    console_text: str
    storage_diagnostics: tuple[str, ...] = ()


class RunFailure(Exception):
    pass


@dataclass(frozen=True)
class RunSnapshot:
    policy_hash: str
    qemu_path: Path
    qemu_resolved_path: Path
    qemu_version: str
    qemu_sha256: str
    manifest_hash: str
    payload_hash: str
    case_ids: tuple[str, ...]
    expected_hashes: dict[str, str]

    @property
    def backend_identity(self) -> dict[str, str]:
        return {
            "qemu_path": str(self.qemu_path),
            "qemu_resolved_path": str(self.qemu_resolved_path),
            "qemu_version": self.qemu_version,
            "qemu_sha256": self.qemu_sha256,
        }


@dataclass
class RunState:
    bundle: EvidenceBundle | None = None
    selection: Selection | None = None
    verification: LockVerification | None = None
    snapshot: RunSnapshot | None = None
    reference_evidence: dict[str, BackendEvidence] = field(default_factory=dict)
    candidate_evidence: dict[str, BackendEvidence] = field(default_factory=dict)
    outcomes: dict[str, CaseOutcome] = field(default_factory=dict)
    run_errors: list[str] = field(default_factory=list)
    input_hashes: dict[str, str] = field(default_factory=dict)
    effective_lock_hash: str = ""


PENDING_CONTROLS = {
    "persistence:omitted-sync-crash-cut": "LC-11",
}


def load_selection(repo: Path, profile_name: str) -> Selection:
    contracts = sorted((repo / "test/qualification/contracts").glob("*/*.json"))
    if not contracts:
        raise RunFailure("no contract manifests found")
    return load_profile(profile_name, repo / "test/qualification/profiles", load_case_index(contracts))


def create_snapshot(verification: LockVerification, selection: Selection) -> RunSnapshot:
    document = verification.document
    qemu_path = Path(document["qemu"]["path"])
    resolved = resolve_qemu_path(qemu_path)
    if not resolved.is_file():
        raise RunFailure(f"verified qemu binary is missing: {qemu_path}")
    expected_hashes = {
        "linux-bzImage": document["linux"]["bzimage_sha256"],
        "linux-config": document["linux"]["config_sha256"],
        "asterinas-kernel": document["asterinas_build"]["kernel_sha256"],
        "initramfs.cpio": document["probe"]["initramfs_sha256"],
        "probe": document["probe"]["binary_sha256"],
        "probe-input.txt": document["probe"]["input_payload_sha256"],
        "inputs.lock.json": verification.lock_hash,
        "adapter-disk.ext2": document["adapter"]["disk_sha256"],
        "adapter-wrong-disk.ext2": document["adapter"]["wrong_disk_sha256"],
        "adapter-wrong-filesystem.img": document["adapter"]["wrong_filesystem_sha256"],
    }
    return RunSnapshot(
        policy_hash=verification.lock_hash,
        qemu_path=qemu_path,
        qemu_resolved_path=resolved,
        qemu_version=qemu_version(qemu_path),
        qemu_sha256=sha256_bytes(resolved.read_bytes()),
        manifest_hash=selection.manifest_hash,
        payload_hash=selection.payload_hash,
        case_ids=tuple(selection.case_ids),
        expected_hashes=expected_hashes,
    )


def verify_copied_input_hashes(copied: dict[str, Path], expected: dict[str, str]) -> list[str]:
    failures: list[str] = []
    for name, path in sorted(copied.items()):
        wanted = expected.get(name)
        if wanted is None:
            failures.append(f"copied input has no verified identity: {name}")
            continue
        actual = sha256_bytes(path.read_bytes())
        if actual != wanted:
            failures.append(f"copied input hash drift: {name} got {actual} expected {wanted}")
    return failures


def verify_backend_identity(path: Path, expected_hash: str, expected_version: str | None) -> list[str]:
    resolved = resolve_qemu_path(path)
    if not resolved.is_file():
        return [f"backend binary is missing: {path}"]
    failures: list[str] = []
    actual_hash = sha256_bytes(resolved.read_bytes())
    if actual_hash != expected_hash:
        failures.append(f"backend binary hash drift: got {actual_hash} expected {expected_hash}")
    if expected_version is not None:
        try:
            actual_version = qemu_version(path)
        except Exception as error:
            failures.append(f"backend version probe failed: {error}")
        else:
            if actual_version != expected_version:
                failures.append(f"backend version drift: got {actual_version} expected {expected_version}")
    return failures


def assert_selection_snapshot(selection: Selection, snapshot: RunSnapshot) -> None:
    if selection.manifest_hash != snapshot.manifest_hash:
        raise RunFailure("selection manifest hash drift between verification and use")
    if selection.payload_hash != snapshot.payload_hash:
        raise RunFailure("selection payload hash drift between verification and use")
    if tuple(selection.case_ids) != snapshot.case_ids:
        raise RunFailure("selection case ids drift between verification and use")


def assert_backend_snapshot(path: Path, snapshot: RunSnapshot) -> None:
    failures = verify_backend_identity(path, snapshot.qemu_sha256, snapshot.qemu_version)
    if failures:
        raise RunFailure("backend identity changed between verification and use: " + "; ".join(failures))


def required_config_failures(case: CaseSpec, config_text: str) -> list[str]:
    values: dict[str, str | None] = {}
    for line in config_text.splitlines():
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[len("# "):].split(" ", 1)[0]] = None
        elif line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    failures: list[str] = []
    for key, expected in sorted(case.applicability["required_config"].items()):
        actual = values.get(key)
        if actual != expected:
            failures.append(f"reference configuration {key}: got {actual!r} expected {expected!r}")
    return failures


def copy_run_inputs(
    repo: Path,
    bundle: EvidenceBundle,
    snapshot: RunSnapshot,
    include_adapter: bool = False,
) -> dict[str, Path]:
    sources = {
        "linux-bzImage": repo / "test/qualification/linux/bzImage",
        "linux-config": repo / "test/qualification/linux/config",
        "asterinas-kernel": repo / CACHE_DIR / "asterinas-kernel",
        "initramfs.cpio": repo / CACHE_DIR / "initramfs.cpio",
        "probe": repo / CACHE_DIR / "probe",
        "probe-input.txt": repo / "test/qualification/probe/input.txt",
        "inputs.lock.json": repo / LOCK_PATH,
    }
    if include_adapter:
        sources.update(
            {
                "adapter-disk.ext2": repo / CACHE_DIR / "adapter-disk.ext2",
                "adapter-wrong-disk.ext2": repo / CACHE_DIR / "adapter-wrong-disk.ext2",
                "adapter-wrong-filesystem.img": repo / CACHE_DIR / "adapter-wrong-filesystem.img",
            }
        )
    copied: dict[str, Path] = {}
    for name, source in sources.items():
        if not source.is_file():
            raise RunFailure(f"run input is missing: {source}")
        destination = bundle.inputs_dir / name
        shutil.copyfile(source, destination)
        copied[name] = destination
    drift = verify_copied_input_hashes(copied, snapshot.expected_hashes)
    if drift:
        raise RunFailure("copied run inputs do not match the verified snapshot: " + "; ".join(drift))
    input_manifest = {name: sha256_bytes(path.read_bytes()) for name, path in sorted(copied.items())}
    (bundle.inputs_dir / "manifest.json").write_text(json.dumps(input_manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return copied


def bind_run_inputs(
    bundle: EvidenceBundle,
    verification: LockVerification,
    selection: Selection,
    snapshot: RunSnapshot,
) -> tuple[dict[str, str], str]:
    input_hashes = json.loads((bundle.inputs_dir / "manifest.json").read_text(encoding="utf-8"))
    effective_hash = write_effective_lock(
        bundle.inputs_dir / "effective-inputs.lock.json",
        verification,
        selection,
        input_hashes,
        snapshot.backend_identity,
    )
    return input_hashes, effective_hash


def replay_index(selection: Selection) -> dict[str, str]:
    return {case.case_id: case.replay for case in selection.cases}


def _observed_values(ingestion, case_id: str) -> dict[str, dict[str, Any]]:
    observed: dict[str, dict[str, Any]] = {}
    for record in ingestion.records.get(case_id, []):
        if record["kind"] != "subtest":
            continue
        subtest = record.get("subtest")
        if not isinstance(subtest, str):
            continue
        values: dict[str, Any] = {}
        assertions = record.get("assertions")
        if isinstance(assertions, list):
            for assertion in assertions:
                if isinstance(assertion, dict) and isinstance(assertion.get("id"), str) and "value" in assertion:
                    values[assertion["id"]] = assertion["value"]
        observed[subtest] = values
    return observed


def compare_against_contract(case: CaseSpec, observed: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for subtest in case.expected_subtests:
        subtest_values = observed.get(subtest.subtest_id, {})
        for assertion in subtest.assertions:
            if assertion.assertion_id not in subtest_values:
                failures.append(f"{case.case_id}/{subtest.subtest_id}/{assertion.assertion_id} is missing")
                continue
            comparison = compare_value(
                assertion.value_type,
                assertion.expected,
                subtest_values[assertion.assertion_id],
                assertion.mode,
                assertion.normalization,
            )
            if not comparison.matched:
                failures.append(
                    f"{case.case_id}/{subtest.subtest_id}/{assertion.assertion_id}: {comparison.detail}"
                )
    return failures


def compare_against_reference(case: CaseSpec, reference: dict[str, dict[str, Any]], candidate: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for subtest in case.expected_subtests:
        reference_values = reference.get(subtest.subtest_id, {})
        candidate_values = candidate.get(subtest.subtest_id, {})
        for assertion in subtest.assertions:
            if assertion.assertion_id not in reference_values:
                failures.append(f"reference {case.case_id}/{subtest.subtest_id}/{assertion.assertion_id} is missing")
                continue
            if assertion.assertion_id not in candidate_values:
                failures.append(f"candidate {case.case_id}/{subtest.subtest_id}/{assertion.assertion_id} is missing")
                continue
            comparison = compare_value(
                assertion.value_type,
                reference_values[assertion.assertion_id],
                candidate_values[assertion.assertion_id],
                assertion.mode,
                assertion.normalization,
            )
            if not comparison.matched:
                failures.append(
                    f"{case.case_id}/{subtest.subtest_id}/{assertion.assertion_id}: {comparison.detail}"
                )
    return failures


def _runtime_evidence(outcome: str, exit_code: int | None) -> tuple[str | None, str | None]:
    if outcome == "panic":
        return "panic", "PANIC"
    if outcome in {"timeout", "hang"}:
        return "timeout", "TIMEOUT"
    if outcome != "exit" or exit_code != 0:
        return "harness-error", "HARNESS_ERROR"
    return None, None


def execute_backend(
    repo: Path,
    bundle: EvidenceBundle,
    inputs: dict[str, Path],
    snapshot: RunSnapshot,
    selection: Selection,
    label: str,
    control: str = "none",
    deadline: float | None = None,
    silence_timeout: float | None = None,
    case: CaseSpec | None = None,
    backend: str = "linux",
) -> BackendEvidence:
    stream_run_id = f"{bundle.run_id}-{label}"
    nonce = secrets.token_hex(16)
    case = selection.cases[0] if case is None else case
    expected_cases = {case.case_id: case}
    assert_selection_snapshot(selection, snapshot)
    assert_backend_snapshot(snapshot.qemu_path, snapshot)
    termination_control = control in {"panic", "hang"} or label.endswith("timeout")
    adapter_enabled = bool(case.payload.get("adapter")) and not termination_control
    adapter_image = None
    if adapter_enabled and control != "missing-device":
        image_name = "adapter-disk.ext2"
        if control == "wrong-disk":
            image_name = "adapter-wrong-disk.ext2"
        elif control == "wrong-filesystem":
            image_name = "adapter-wrong-filesystem.img"
        adapter_image = inputs[image_name]
    execution = run_qemu(
        qemu_path=snapshot.qemu_path,
        kernel=inputs["asterinas-kernel" if backend == "asterinas" else "linux-bzImage"],
        initramfs=inputs["initramfs.cpio"],
        work_dir=bundle.work_dir,
        label=label,
        run_id=stream_run_id,
        nonce=nonce,
        manifest_hash=selection.manifest_hash,
        payload_hash=selection.payload_hash,
        deadline=deadline or case.deadline_seconds,
        output_budget=case.budget_bytes,
        control=control,
        silence_timeout=silence_timeout,
        case_id=case.case_id,
        adapter_image=adapter_image,
        adapter_serial=(
            ""
            if control == "missing-identity"
            else "qual-lc06-wrong"
            if control == "wrong-disk"
            else str(case.payload.get("disk_serial", "qual-lc06-adapter"))
        ),
        adapter_write_through=control == "wrong-cache",
        isolated_network=adapter_enabled,
        inject_read_errors=control == "failed-mount",
        inject_writeback_eio=bool(case.payload.get("inject_writeback_eio")),
        kernel_kind=backend,
    )
    bundle.register_file(f"{label}/console.log", execution.console_log)
    qual_exists = execution.qual_log.is_file()
    if qual_exists:
        bundle.register_file(f"{label}/qual.log", execution.qual_log)
        stream_bytes = execution.qual_log.read_bytes()
    else:
        stream_bytes = b""
    bundle.register_artifact(
        f"{label}/qemu-command.json",
        (json.dumps({"argv": execution.command}, indent=2) + "\n").encode("utf-8"),
    )
    storage_failures = required_config_failures(case, inputs["linux-config"].read_text(encoding="utf-8")) if backend == "linux" else []
    if adapter_enabled:
        if execution.adapter_disk is None:
            storage_failures.append("adapter disk was not attached")
        else:
            bundle.register_file(f"{label}/blkdebug.conf", execution.adapter_disk.blkdebug_config)
            bundle.register_file(f"{label}/blklogwrites.log", execution.adapter_disk.write_log)
            storage_failures.extend(validate_blklogwrites(execution.adapter_disk.write_log))
    storage_diagnostics = tuple(storage_failures)
    stream_text = stream_bytes.decode("utf-8", errors="replace")
    context = ResultContext(
        run_id=stream_run_id,
        nonce=nonce,
        manifest_hash=selection.manifest_hash,
        payload_hash=selection.payload_hash,
        cases=expected_cases,
        max_age_seconds=300,
        now=time.time(),
    )
    ingestion = ingest_result_stream(stream_text, context)
    diagnostics = tuple(ingestion.rendered())
    if not qual_exists:
        diagnostics = (*diagnostics, "missing-artifact: qemu did not create the dedicated serial log")
    observed = {case.case_id: _observed_values(ingestion, case.case_id)}
    final_status = None
    final = ingestion.finals.get(case.case_id)
    if final is not None and isinstance(final.get("status"), str):
        final_status = final["status"]
    return BackendEvidence(
        label=label,
        stream_run_id=stream_run_id,
        nonce=nonce,
        execution_outcome=execution.result.outcome,
        exit_code=execution.result.exit_code,
        teardown_state=execution.result.teardown_state,
        duration_seconds=execution.duration_seconds,
        ingestion_diagnostics=diagnostics,
        observed=observed,
        final_status=final_status,
        stream_text=stream_text,
        console_text=execution.console_log.read_text(encoding="utf-8", errors="replace") if execution.console_log.is_file() else "",
        storage_diagnostics=storage_diagnostics,
    )


def _backend_role(evidence: BackendEvidence) -> tuple[str, str, str | None]:
    runtime_status, terminal = _runtime_evidence(evidence.execution_outcome, evidence.exit_code)
    if runtime_status is not None:
        return runtime_status, f"qemu outcome {evidence.execution_outcome}", terminal
    if evidence.ingestion_diagnostics:
        return "harness-error", "; ".join(evidence.ingestion_diagnostics[:3]), "HARNESS_ERROR"
    if evidence.final_status == "pass":
        return "pass", "complete result stream", None
    return "fail", f"final status {evidence.final_status!r}", None


REQUIRED_EVIDENCE_CATEGORIES = (
    "missing-artifact",
    "checksum-mismatch",
    "wrong-run-id",
    "wrong-nonce",
    "wrong-manifest-hash",
    "wrong-payload-hash",
    "stale-log",
    "malformed-output",
    "truncated-output",
)


def evidence_compromise(evidence: BackendEvidence) -> list[str]:
    issues = [f"required storage evidence: {item}" for item in evidence.storage_diagnostics]
    issues.extend(
        f"required result evidence: {item}"
        for item in evidence.ingestion_diagnostics
        if item.startswith(REQUIRED_EVIDENCE_CATEGORIES)
    )
    if evidence.teardown_state != "verified-empty":
        issues.append(f"incomplete teardown: {evidence.teardown_state}")
    return issues


def evaluate_case(case: CaseSpec, reference: BackendEvidence, candidate: BackendEvidence) -> CaseOutcome:
    reference_status, reference_detail, reference_terminal = _backend_role(reference)
    candidate_status, candidate_detail, candidate_terminal = _backend_role(candidate)
    reference_role = RoleResult("reference", reference_status, reference_detail)
    candidate_role = RoleResult("candidate", candidate_status, candidate_detail)
    reference_compromise = evidence_compromise(reference)
    if reference_compromise:
        reference_role = RoleResult(
            "reference",
            "harness-error",
            "; ".join(reference_compromise[:3]) + " | runtime observation before evidence escalation: " + reference_detail,
        )
        reference_terminal = "HARNESS_ERROR"
    candidate_compromise = evidence_compromise(candidate)
    if candidate_compromise:
        candidate_role = RoleResult(
            "candidate",
            "harness-error",
            "; ".join(candidate_compromise[:3]) + " | runtime observation before evidence escalation: " + candidate_detail,
        )
        candidate_terminal = "HARNESS_ERROR"

    reference_observed = reference.observed.get(case.case_id, {})
    candidate_observed = candidate.observed.get(case.case_id, {})
    validator_failures: list[str] = []
    comparator_failures: list[str] = []
    if reference_role.status == "pass":
        validator_failures = compare_against_contract(case, reference_observed)
    else:
        validator_failures = ["reference stream did not complete cleanly"]
    validator_failures.extend(reference.storage_diagnostics)
    comparable = reference_role.status == "pass" and candidate_role.status in {"pass", "fail"}
    if comparable:
        comparator_failures = compare_against_reference(case, reference_observed, candidate_observed)

    validator_role = RoleResult(
        "validator",
        "pass" if not validator_failures else "fail",
        "reference matches contract" if not validator_failures else "; ".join(validator_failures[:4]),
    )
    if comparable:
        comparator_role = RoleResult(
            "comparator",
            "pass" if not comparator_failures else "fail",
            "candidate matches reference" if not comparator_failures else "; ".join(comparator_failures[:4]),
        )
    else:
        reason = "reference stream did not complete cleanly" if reference_role.status != "pass" else f"candidate evidence is {candidate_role.status}"
        comparator_role = RoleResult("comparator", "not-comparable", reason)
    roles = (candidate_role, reference_role, comparator_role, validator_role)

    if reference_terminal is not None or validator_role.status != "pass":
        return CaseOutcome(case.case_id, "REFERENCE_FAILURE", roles, validator_role.detail or reference_role.detail)
    if candidate_terminal is not None:
        return CaseOutcome(case.case_id, candidate_terminal, roles, candidate_role.detail)
    if candidate_role.status == "harness-error":
        return CaseOutcome(case.case_id, "HARNESS_ERROR", roles, candidate_role.detail)
    if comparator_role.status != "pass" or candidate_role.status != "pass":
        return CaseOutcome(case.case_id, "FAIL", roles, comparator_role.detail or candidate_role.detail)
    return CaseOutcome(case.case_id, "PASS", roles, "candidate and reference agree with the contract")


def finalize_run(state: RunState, profile_name: str, candidate: str, baseline: bool = False) -> int:
    selection = state.selection
    selected = list(selection.case_ids) if selection is not None else []
    outcomes = dict(state.outcomes)
    for case_id in selected:
        if case_id not in outcomes:
            outcomes[case_id] = CaseOutcome(
                case_id,
                "NOT_RUN",
                (
                    RoleResult("candidate", "not-run"),
                    RoleResult("comparator", "not-comparable", "case did not complete"),
                ),
                "case did not complete",
            )
    accounting = reconcile(selected, outcomes.values())

    teardown_errors: list[str] = []
    if state.bundle is not None:
        try:
            teardown_errors = list(state.bundle.teardown())
        except Exception as error:
            teardown_errors = [f"teardown raised {type(error).__name__}: {error}"]
    if state.run_errors and state.bundle is not None:
        try:
            state.bundle.register_artifact(
                "harness-error.txt",
                ("\n".join(state.run_errors) + "\n").encode("utf-8", errors="replace"),
            )
        except Exception as error:
            state.run_errors.append(f"failure artifact registration raised {type(error).__name__}: {error}")

    report = {
        "run_id": state.bundle.run_id if state.bundle is not None else None,
        "profile": profile_name,
        "candidate": candidate,
        "baseline": baseline,
        "lock_hash": state.verification.lock_hash if state.verification is not None else None,
        "manifest_hash": selection.manifest_hash if selection is not None else None,
        "payload_hash": selection.payload_hash if selection is not None else None,
        "selected_count": len(selected),
        "input_hashes": state.input_hashes,
        "effective_lock_sha256": state.effective_lock_hash,
        "backend_identity": state.snapshot.backend_identity if state.snapshot is not None else {},
        "selection_snapshot": (
            {
                "manifest_hash": state.snapshot.manifest_hash,
                "payload_hash": state.snapshot.payload_hash,
                "case_ids": list(state.snapshot.case_ids),
            }
            if state.snapshot is not None
            else {}
        ),
        "replay": replay_index(selection) if selection is not None else {},
        "backends": {
            "reference": {case_id: _backend_json(evidence) for case_id, evidence in sorted(state.reference_evidence.items())},
            "candidate": {case_id: _backend_json(evidence) for case_id, evidence in sorted(state.candidate_evidence.items())},
        },
        "outcomes": {
            case_id: {
                "disposition": outcome.disposition,
                "reason": outcome.reason,
                "results": [_role_json(role) for role in outcome.results],
            }
            for case_id, outcome in sorted(outcomes.items())
        },
        "dispositions": dict(accounting.counts),
        "accounting_diagnostics": [item.render() for item in accounting.diagnostics],
        "run_errors": list(state.run_errors),
        "teardown_errors": teardown_errors,
    }
    publication_errors: list[str] = []
    if state.bundle is not None:
        try:
            state.bundle.publish_report(report)
        except Exception as error:
            publication_errors.append(f"{type(error).__name__}: {error}")
    else:
        publication_errors.append("no evidence bundle was created")

    if state.bundle is not None:
        print(f"run evidence: {state.bundle.root}")
        print(f"report: {state.bundle.report_path}")
    print(f"dispositions: {dict(accounting.counts)}")
    for item in accounting.diagnostics:
        print(f"accounting diagnostic: {item.render()}")
    for error in state.run_errors:
        print(f"run error: {error}")
    for error in teardown_errors:
        print(f"teardown error: {error}")
    for error in publication_errors:
        print(f"publication error: {error}")

    clean = not accounting.diagnostics and not teardown_errors and not state.run_errors and not publication_errors
    if baseline:
        ok = (
            clean
            and sum(accounting.counts.values()) == len(selected)
            and accounting.counts.get("HARNESS_ERROR", 0) == 0
            and accounting.counts.get("REFERENCE_FAILURE", 0) == 0
            and accounting.counts.get("NOT_RUN", 0) == 0
        )
    else:
        ok = clean and accounting.counts.get("PASS", 0) == len(selected)
    return 0 if ok else 1


def _role_json(role: RoleResult) -> dict[str, str]:
    return {"role": role.role, "status": role.status, "detail": role.detail}


def _backend_json(evidence: BackendEvidence) -> dict[str, Any]:
    return {
        "stream_run_id": evidence.stream_run_id,
        "execution_outcome": evidence.execution_outcome,
        "exit_code": evidence.exit_code,
        "teardown_state": evidence.teardown_state,
        "duration_seconds": evidence.duration_seconds,
        "ingestion_diagnostics": list(evidence.ingestion_diagnostics),
        "final_status": evidence.final_status,
        "storage_diagnostics": list(evidence.storage_diagnostics),
    }


def _case_label(prefix: str, case_id: str) -> str:
    return f"{prefix}-" + "".join(character if character.isalnum() else "-" for character in case_id)


def run_selfcheck(repo: Path, profile_name: str, candidate: str, baseline: bool = False) -> int:
    if candidate not in {"linux", "asterinas"}:
        print(f"HARNESS_ERROR unsupported candidate {candidate!r}; supported candidates are linux and asterinas", file=sys.stderr)
        return 2
    state = RunState()
    try:
        verification = verify_lock(repo)
        state.verification = verification
        selection = load_selection(repo, profile_name)
        state.selection = selection
        snapshot = create_snapshot(verification, selection)
        state.snapshot = snapshot
        assert_selection_snapshot(selection, snapshot)
        bundle = EvidenceBundle.create(repo / "target/qualification")
        state.bundle = bundle
        inputs = copy_run_inputs(
            repo,
            bundle,
            snapshot,
            any(bool(case.payload.get("adapter")) for case in selection.cases),
        )
        input_hashes, effective_lock_hash = bind_run_inputs(bundle, verification, selection, snapshot)
        state.input_hashes = input_hashes
        state.effective_lock_hash = effective_lock_hash
        with VmExclusion(repo / "target/qualification/vm.lock"):
            for case in selection.cases:
                reference_evidence = execute_backend(
                    repo,
                    bundle,
                    inputs,
                    snapshot,
                    selection,
                    _case_label("reference", case.case_id),
                    case=case,
                    backend="linux",
                )
                state.reference_evidence[case.case_id] = reference_evidence
                candidate_evidence = execute_backend(
                    repo,
                    bundle,
                    inputs,
                    snapshot,
                    selection,
                    _case_label("candidate", case.case_id),
                    case=case,
                    backend=candidate,
                )
                state.candidate_evidence[case.case_id] = candidate_evidence
                state.outcomes[case.case_id] = evaluate_case(case, reference_evidence, candidate_evidence)
    except Exception as error:
        state.run_errors.append(f"{type(error).__name__}: {error}")
        print(f"HARNESS_ERROR {type(error).__name__}: {error}", file=sys.stderr)
    return finalize_run(state, profile_name, candidate, baseline)


def parse_qual_stream(text: str) -> list[tuple[list[str], dict[str, Any]]]:
    parsed: list[tuple[list[str], dict[str, Any]]] = []
    for line in text.splitlines():
        parts = line.split(" ", 3)
        if len(parts) == 4 and parts[0] == "QUAL":
            parsed.append((parts[:3], json.loads(parts[3])))
    return parsed


def render_qual_stream(parsed: list[tuple[list[str], dict[str, Any]]]) -> str:
    return "".join(
        make_result_line(prefix[1], prefix[2], record)
        for prefix, record in parsed
    )


def mutate_stream(text: str, mutation) -> str:
    parsed = parse_qual_stream(text)
    mutation(parsed)
    return render_qual_stream(parsed)


def _control_ingestion(base: BackendEvidence, selection: Selection, text: str, category: str) -> tuple[bool, str]:
    context = ResultContext(
        run_id=base.stream_run_id,
        nonce=base.nonce,
        manifest_hash=selection.manifest_hash,
        payload_hash=selection.payload_hash,
        cases=selection.case_map,
        max_age_seconds=300,
        now=time.time(),
    )
    ingestion = ingest_result_stream(text, context)
    rendered = ingestion.rendered()
    detail = next((item for item in rendered if item.startswith(category + ":")), "; ".join(rendered) or "no diagnostics")
    return ingestion.has(category), detail


def _first_subtest_record(parsed: list[tuple[list[str], dict[str, Any]]], subtest: str) -> dict[str, Any] | None:
    for _, record in parsed:
        if record.get("kind") == "subtest" and record.get("subtest") == subtest:
            return record
    return None


def _first_assertion_record(parsed: list[tuple[list[str], dict[str, Any]]], subtest: str) -> dict[str, Any] | None:
    """Returns the named subtest when present, otherwise the first subtest with an assertion.

    Selfcheck profiles carry the canonical selfcheck subtests; other profiles have
    their own subtests. Controls that corrupt an assertion must work on either.
    """
    preferred = _first_subtest_record(parsed, subtest)
    if preferred is not None and preferred.get("assertions"):
        return preferred
    for _, record in parsed:
        if record.get("kind") == "subtest" and record.get("assertions"):
            return record
    return None


def real_stream_controls(base: BackendEvidence, selection: Selection) -> dict[str, dict[str, Any]]:
    controls: dict[str, dict[str, Any]] = {}

    def ingestion_control(name: str, category: str, mutation) -> None:
        mutated = mutate_stream(base.stream_text, mutation)
        detected, detail = _control_ingestion(base, selection, mutated, category)
        controls[name] = {"detected": detected, "detail": detail}

    ingestion_control("real-wrong-run-id", "wrong-run-id", lambda parsed: parsed[0][0].__setitem__(1, "wrong-run"))
    ingestion_control("real-wrong-nonce", "wrong-nonce", lambda parsed: parsed[0][0].__setitem__(2, "wrong-nonce"))
    ingestion_control("real-wrong-manifest-hash", "wrong-manifest-hash", lambda parsed: parsed[0][1].__setitem__("manifest_hash", "0" * 64))
    ingestion_control("real-wrong-payload-hash", "wrong-payload-hash", lambda parsed: parsed[0][1].__setitem__("payload_hash", "0" * 64))
    ingestion_control("real-missing-final", "missing-final-record", lambda parsed: parsed.__delitem__(len(parsed) - 1))
    ingestion_control(
        "real-missing-subtest",
        "missing-subtest",
        lambda parsed: parsed.__delitem__(next(index for index, item in enumerate(parsed) if item[1].get("kind") == "subtest")),
    )

    def remove_assertion(parsed):
        record = _first_assertion_record(parsed, "errno-on-failure")
        if record is not None:
            record["assertions"] = []

    ingestion_control("real-missing-assertion", "missing-assertion", remove_assertion)

    malformed = base.stream_text + f"QUAL {base.stream_run_id} {base.nonce} {{bad json}}\n"
    detected, detail = _control_ingestion(base, selection, malformed, "malformed-output")
    controls["real-malformed-output"] = {"detected": detected, "detail": detail}
    truncated = base.stream_text + f"QUAL {base.stream_run_id} {base.nonce} {{\"case_id\":\"core.selfcheck\","
    detected, detail = _control_ingestion(base, selection, truncated, "truncated-output")
    controls["real-truncated-output"] = {"detected": detected, "detail": detail}

    def stale_final(parsed):
        for _, record in parsed:
            if record.get("kind") == "final":
                record["emitted_at"] = time.time() - 3600

    ingestion_control("real-stale-log", "stale-log", stale_final)

    case = selection.cases[0]
    for name, subtest in (
        ("real-wrong-errno", "errno-on-failure"),
        ("real-wrong-bytes", "read-fixed-input"),
        ("real-wrong-permission", "dev-null-write"),
    ):
        def wrong_value(parsed, subtest=subtest):
            record = _first_assertion_record(parsed, subtest)
            if record is not None:
                current = record["assertions"][0]["value"]
                if isinstance(current, bool) or isinstance(current, int):
                    record["assertions"][0]["value"] = -999999 if current != -999999 else 999999
                else:
                    record["assertions"][0]["value"] = "__CONTROL_WRONG__"

        mutated = mutate_stream(base.stream_text, wrong_value)
        context = ResultContext(
            run_id=base.stream_run_id,
            nonce=base.nonce,
            manifest_hash=selection.manifest_hash,
            payload_hash=selection.payload_hash,
            cases={case.case_id: case},
            max_age_seconds=300,
            now=time.time(),
        )
        ingestion = ingest_result_stream(mutated, context)
        observed = _observed_values(ingestion, case.case_id)
        contract_failures = compare_against_contract(case, observed)
        reference_observed = _observed_values(
            ingest_result_stream(base.stream_text, context),
            case.case_id,
        )
        pair_failures = compare_against_reference(case, reference_observed, observed)
        failures = contract_failures + pair_failures
        controls[name] = {
            "detected": bool(contract_failures) and bool(pair_failures) and not ingestion.diagnostics,
            "detail": "; ".join([*failures, *[f"diagnostic: {item}" for item in ingestion.diagnostics]]) if failures or ingestion.diagnostics else "mutation was not rejected",
        }

    recomputation_detected = not verify_comparison_claim("errno", "ENOENT", 0, claimed_match=True)
    controls["comparator-recomputation"] = {
        "detected": recomputation_detected,
        "detail": "claimed equality of ENOENT and 0 is contradicted by recomputation",
    }
    return controls


def _adapter_value(evidence: BackendEvidence, subtest: str, assertion: str) -> Any:
    return evidence.observed.get("core.adapter", {}).get(subtest, {}).get(assertion)


def _adapter_stream_clean(evidence: BackendEvidence) -> bool:
    return (
        evidence.execution_outcome == "exit"
        and evidence.exit_code == 0
        and evidence.teardown_state == "verified-empty"
        and not evidence.ingestion_diagnostics
    )


def _delegate_lc02_controls(repo: Path, bundle: EvidenceBundle, controls: dict[str, dict[str, Any]]) -> None:
    selftest = subprocess.run(
        [sys.executable, str(repo / "test/qualification/run.py"), "selftest"],
        cwd=repo,
        capture_output=True,
        timeout=120,
        check=False,
    )
    bundle.register_artifact("lc02-selftest/output.txt", selftest.stdout + selftest.stderr)
    selftest_text = selftest.stdout.decode("utf-8", errors="replace")
    delegated = 0
    for line in selftest_text.splitlines():
        if not line.startswith("DETECTED "):
            continue
        name_detail = line[len("DETECTED "):]
        name, _, detail = name_detail.partition(": ")
        controls[f"lc02:{name}"] = {"detected": True, "detail": detail}
        delegated += 1
    if selftest.returncode != 0 or delegated == 0:
        controls["lc02:synthetic-h1-suite"] = {
            "detected": False,
            "detail": f"selftest rc={selftest.returncode} delegated={delegated}",
        }


def run_adapter_controls(repo: Path, profile_name: str) -> int:
    bundle: EvidenceBundle | None = None
    controls: dict[str, dict[str, Any]] = {}
    internal_failures: list[str] = []
    control_backends: dict[str, dict[str, Any]] = {}
    try:
        verification = verify_lock(repo)
        selection = load_selection(repo, profile_name)
        snapshot = create_snapshot(verification, selection)
        assert_selection_snapshot(selection, snapshot)
        bundle = EvidenceBundle.create(repo / "target/qualification")
        inputs = copy_run_inputs(
            repo,
            bundle,
            snapshot,
            any(bool(case.payload.get("adapter")) for case in selection.cases),
        )
        input_hashes, effective_lock_hash = bind_run_inputs(bundle, verification, selection, snapshot)
        _delegate_lc02_controls(repo, bundle, controls)

        with VmExclusion(repo / "target/qualification/vm.lock"):
            base = execute_backend(repo, bundle, inputs, snapshot, selection, "control-base")
            control_backends["base"] = _backend_json(base)
            qemu_command_text = ""
            qemu_command_path = bundle.artifacts_dir / "control-base/qemu-command.json"
            if qemu_command_path.is_file():
                qemu_command_text = qemu_command_path.read_text(encoding="utf-8")
            base_ok = (
                _adapter_stream_clean(base)
                and base.final_status == "pass"
                and not base.storage_diagnostics
                and "cache.direct=off,cache.no-flush=off" in qemu_command_text
                and "hubport,id=net0,hubid=0" in qemu_command_text
                and "driver=blklogwrites" in qemu_command_text
                and "driver=blkdebug" in qemu_command_text
            )
            controls["adapter:baseline-device-chain"] = {
                "detected": base_ok,
                "detail": f"final={base.final_status} storage={list(base.storage_diagnostics)} teardown={base.teardown_state}",
            }
            if not base_ok:
                internal_failures.append("adapter control baseline is not clean")

            case = selection.cases[0]
            config_input = inputs["linux-config"]
            original_config = config_input.read_text(encoding="utf-8")
            config_input.write_text(original_config.replace("CONFIG_EXT2_FS=y", "# CONFIG_EXT2_FS is not set", 1), encoding="utf-8")
            try:
                missing_config_evidence = execute_backend(repo, bundle, inputs, snapshot, selection, "control-missing-reference-configuration")
            finally:
                config_input.write_text(original_config, encoding="utf-8")
            control_backends["missing-reference-configuration"] = _backend_json(missing_config_evidence)
            config_failures = [failure for failure in missing_config_evidence.storage_diagnostics if "CONFIG_EXT2_FS" in failure]
            controls["live-device:missing-reference-configuration"] = {
                "detected": bool(config_failures),
                "detail": "; ".join(config_failures) if config_failures else "missing ext2 config was accepted",
            }

            for control_name, label, extra_predicate in (
                (
                    "live-device:wrong-filesystem",
                    "wrong-filesystem",
                    lambda evidence: _adapter_value(evidence, "serial-identity", "serial") == "qual-lc06-adapter"
                    and _adapter_value(evidence, "write-cache", "mode") == "write back"
                    and _adapter_value(evidence, "mount-identity", "marker") == "",
                ),
                (
                    "live-device:wrong-disk",
                    "wrong-disk",
                    lambda evidence: _adapter_value(evidence, "serial-identity", "serial") not in {"", "qual-lc06-adapter"}
                    and _adapter_value(evidence, "mount-identity", "marker") == "",
                ),
                (
                    "live-device:failed-mount",
                    "failed-mount",
                    lambda evidence: _adapter_value(evidence, "mount-identity", "marker") == ""
                    and "I/O error, dev vda" in evidence.console_text,
                ),
                (
                    "live-device:missing-device",
                    "missing-device",
                    lambda evidence: _adapter_value(evidence, "serial-identity", "serial") == ""
                    and _adapter_value(evidence, "mount-identity", "marker") == "",
                ),
                (
                    "live-device:missing-identity",
                    "missing-identity",
                    lambda evidence: _adapter_value(evidence, "serial-identity", "serial") == ""
                    and _adapter_value(evidence, "mount-identity", "marker") == "",
                ),
                (
                    "live-device:wrong-cache",
                    "wrong-cache",
                    lambda evidence: _adapter_value(evidence, "write-cache", "mode") not in {"", "write back"},
                ),
                (
                    "live-device:missing-privileges",
                    "missing-privileges",
                    lambda evidence: _adapter_value(evidence, "mount-identity", "marker") == ""
                    and "Operation not permitted" in evidence.console_text,
                ),
            ):
                guest_control = "drop-sys-admin" if label == "missing-privileges" else label
                evidence = execute_backend(repo, bundle, inputs, snapshot, selection, f"control-{label}", control=guest_control)
                control_backends[label] = _backend_json(evidence)
                detected = _adapter_stream_clean(evidence) and evidence.final_status == "fail" and extra_predicate(evidence)
                controls[control_name] = {
                    "detected": detected,
                    "detail": (
                        f"final={evidence.final_status} serial={_adapter_value(evidence, 'serial-identity', 'serial')!r} "
                        f"marker={_adapter_value(evidence, 'mount-identity', 'marker')!r} outcome={evidence.execution_outcome}"
                    ),
                }

            hang = execute_backend(repo, bundle, inputs, snapshot, selection, "control-guest-hang", control="hang", deadline=20, silence_timeout=3)
            control_backends["guest-hang"] = _backend_json(hang)
            controls["adapter:guest-hang"] = {
                "detected": hang.execution_outcome == "hang" and hang.teardown_state == "verified-empty",
                "detail": f"outcome={hang.execution_outcome} teardown={hang.teardown_state}",
            }

            qemu_path = str(snapshot.qemu_path)
            orphan_command = [
                "/bin/sh",
                "-c",
                f"{shlex.quote(qemu_path)} -accel tcg -machine q35 -display none -monitor none -nic none -S >/dev/null 2>&1 & exit 0",
            ]
            orphan_log = bundle.work_dir / "orphaned-vm.log"
            orphan_result = Supervisor().run(orphan_command, timeout=5, output_budget=8192, log_path=orphan_log)
            bundle.register_file("orphaned-vm/output.log", orphan_log)
            orphan_detected = orphan_result.outcome == "harness-error" and orphan_result.teardown_state != "verified-empty"
            controls["adapter:orphaned-vm"] = {
                "detected": orphan_detected,
                "detail": (
                    f"outcome={orphan_result.outcome} teardown={orphan_result.teardown_state} "
                    f"descendants={orphan_result.observed_descendant_pids} details={orphan_result.teardown_details[:2]}"
                ),
            }

            base_stream_log = bundle.artifacts_dir / "control-base/blklogwrites.log"
            corrupted = bundle.work_dir / "corrupted-blklogwrites.log"
            data = bytearray(base_stream_log.read_bytes()) if base_stream_log.is_file() else bytearray()
            if data:
                data[0] ^= 0xFF
                corrupted.write_bytes(data)
                corruption_failures = validate_blklogwrites(corrupted)
                controls["adapter:corrupt-blklogwrites-log"] = {
                    "detected": bool(corruption_failures),
                    "detail": "; ".join(corruption_failures) if corruption_failures else "corrupted write log was accepted",
                }
            else:
                controls["adapter:corrupt-blklogwrites-log"] = {"detected": False, "detail": "baseline write log is empty or missing"}

        comparator_types_detected = (
            not verify_comparison_claim("text", "write back", "write through", claimed_match=True)
            and not verify_comparison_claim("integer", 0, 1, claimed_match=True)
            and verify_comparison_claim("bytes", "bGMwNi1hZGFwdGVyCg==", "bGMwNi1hZGFwdGVyCg==", claimed_match=True)
        )
        controls["adapter:comparator-text-integer-recomputation"] = {
            "detected": comparator_types_detected,
            "detail": "text and integer mismatch claims are contradicted by recomputation",
        }

        detected_count = sum(1 for item in controls.values() if item["detected"])
        report = {
            "run_id": bundle.run_id,
            "profile": profile_name,
            "controls": True,
            "lock_hash": verification.lock_hash,
            "manifest_hash": selection.manifest_hash,
            "payload_hash": selection.payload_hash,
            "input_hashes": input_hashes,
            "effective_lock_sha256": effective_lock_hash,
            "backend_identity": snapshot.backend_identity,
            "selection_snapshot": {
                "manifest_hash": snapshot.manifest_hash,
                "payload_hash": snapshot.payload_hash,
                "case_ids": list(snapshot.case_ids),
            },
            "replay": replay_index(selection),
            "control_backends": control_backends,
            "controls": controls,
            "pending_controls": {
                name: {"status": "pending", "blocked_by": item, "passed": False}
                for name, item in sorted(PENDING_CONTROLS.items())
            },
            "controls_detected": detected_count,
            "controls_total": len(controls),
            "internal_failures": internal_failures,
        }
        teardown_errors = bundle.teardown()
        report["teardown_errors"] = teardown_errors
        bundle.publish_report(report)
        print(f"controls evidence: {bundle.root}")
        print(f"report: {bundle.report_path}")
        for name, item in sorted(controls.items()):
            state = "DETECTED" if item["detected"] else "NOT-DETECTED"
            print(f"{state} {name}: {item['detail']}")
        for name, blocked_by in sorted(PENDING_CONTROLS.items()):
            print(f"PENDING {name}: blocked by {blocked_by}")
        for failure in internal_failures:
            print(f"INTERNAL-FAIL {failure}")
        for error in teardown_errors:
            print(f"teardown error: {error}")
        print(f"CONTROLS RESULT: {detected_count}/{len(controls)} controls detected")
        ok = detected_count == len(controls) and not internal_failures and not teardown_errors
        return 0 if ok else 1
    except Exception as error:
        if bundle is not None and not bundle.report_path.exists():
            try:
                bundle.register_artifact("harness-error.txt", f"{type(error).__name__}: {error}\n".encode("utf-8", errors="replace"))
                bundle.publish_report(
                    {
                        "run_id": bundle.run_id,
                        "profile": profile_name,
                        "controls": True,
                        "error": f"{type(error).__name__}: {error}",
                        "controls": controls,
                    }
                )
            except Exception:
                pass
        if bundle is not None:
            try:
                bundle.teardown()
            except Exception:
                pass
        print(f"HARNESS_ERROR {type(error).__name__}: {error}", file=sys.stderr)
        return 1


def run_controls(repo: Path, profile_name: str) -> int:
    if profile_name == "adapter":
        return run_adapter_controls(repo, profile_name)
    bundle: EvidenceBundle | None = None
    controls: dict[str, dict[str, Any]] = {}
    internal_failures: list[str] = []
    try:
        verification = verify_lock(repo)
        selection = load_selection(repo, profile_name)
        snapshot = create_snapshot(verification, selection)
        assert_selection_snapshot(selection, snapshot)
        bundle = EvidenceBundle.create(repo / "target/qualification")
        inputs = copy_run_inputs(
            repo,
            bundle,
            snapshot,
            any(bool(case.payload.get("adapter")) for case in selection.cases),
        )
        input_hashes, effective_lock_hash = bind_run_inputs(bundle, verification, selection, snapshot)
        selftest = subprocess.run(
            [sys.executable, str(repo / "test/qualification/run.py"), "selftest"],
            cwd=repo,
            capture_output=True,
            timeout=120,
            check=False,
        )
        bundle.register_artifact("lc02-selftest/output.txt", selftest.stdout + selftest.stderr)
        selftest_text = selftest.stdout.decode("utf-8", errors="replace")
        delegated = 0
        for line in selftest_text.splitlines():
            if not line.startswith("DETECTED "):
                continue
            name_detail = line[len("DETECTED "):]
            name, _, detail = name_detail.partition(": ")
            controls[f"lc02:{name}"] = {"detected": True, "detail": detail}
            delegated += 1
        if selftest.returncode != 0 or delegated == 0:
            controls["lc02:synthetic-h1-suite"] = {
                "detected": False,
                "detail": f"selftest rc={selftest.returncode} delegated={delegated}",
            }

        original_lock = json.loads((repo / LOCK_PATH).read_text(encoding="utf-8"))
        for control_name, section, key, needle in (
            ("lock-probe-source-drift", "probe", "source_sha256", "probe source hash drift"),
            ("lock-harness-drift", "harness", "files", "harness input"),
        ):
            mutated_lock = json.loads(json.dumps(original_lock))
            if key == "files":
                harness_path = sorted(mutated_lock[section][key])[0]
                mutated_lock[section][key][harness_path] = "0" * 64
            else:
                mutated_lock[section][key] = "0" * 64
            try:
                verify_lock_document(repo, mutated_lock, build_missing=False)
            except LockError as error:
                detail = str(error)
                controls[control_name] = {"detected": needle in detail, "detail": detail}
            else:
                controls[control_name] = {"detected": False, "detail": "mutated lock verification passed"}

        mutated_lock = json.loads(json.dumps(original_lock))
        mutated_lock["selections"]["lc02-selftest"]["manifest_hash"] = "0" * 64
        try:
            verify_lock_document(repo, mutated_lock, build_missing=False)
        except LockError as error:
            detail = str(error)
            controls["lock-control-selection-drift"] = {"detected": "lc02-selftest manifest hash drift" in detail, "detail": detail}
        else:
            controls["lock-control-selection-drift"] = {"detected": False, "detail": "mutated control-selection lock verification passed"}

        with VmExclusion(repo / "target/qualification/vm.lock"):
            base = execute_backend(repo, bundle, inputs, snapshot, selection, "control-base")
            if base.execution_outcome != "exit" or base.ingestion_diagnostics or base.final_status != "pass":
                internal_failures.append(
                    f"control base stream is not valid: outcome={base.execution_outcome} final={base.final_status} diagnostics={list(base.ingestion_diagnostics)}"
                )
            controls.update(real_stream_controls(base, selection))

            panic = execute_backend(repo, bundle, inputs, snapshot, selection, "control-panic", control="panic", deadline=20)
            controls["real-guest-panic"] = {
                "detected": panic.execution_outcome == "panic",
                "detail": f"outcome={panic.execution_outcome} teardown={panic.teardown_state}",
            }

            hang = execute_backend(repo, bundle, inputs, snapshot, selection, "control-hang", control="hang", deadline=20, silence_timeout=3)
            controls["real-guest-hang"] = {
                "detected": hang.execution_outcome == "hang",
                "detail": f"outcome={hang.execution_outcome} teardown={hang.teardown_state}",
            }

            timeout = execute_backend(repo, bundle, inputs, snapshot, selection, "control-timeout", deadline=1)
            controls["real-host-timeout"] = {
                "detected": timeout.execution_outcome == "timeout",
                "detail": f"outcome={timeout.execution_outcome} teardown={timeout.teardown_state}",
            }

            case = selection.cases[0]
            for control_name, evidence, expected_disposition in (
                ("real-panic-comparator-not-comparable", panic, "PANIC"),
                ("real-hang-comparator-not-comparable", hang, "TIMEOUT"),
                ("real-timeout-comparator-not-comparable", timeout, "TIMEOUT"),
            ):
                outcome = evaluate_case(case, base, evidence)
                comparator = next(result for result in outcome.results if result.role == "comparator")
                accounting = reconcile([case.case_id], [outcome])
                controls[control_name] = {
                    "detected": outcome.disposition == expected_disposition
                    and comparator.status == "not-comparable"
                    and not accounting.diagnostics,
                    "detail": f"disposition={outcome.disposition} comparator={comparator.status}: {comparator.detail}",
                }

        detected_count = sum(1 for item in controls.values() if item["detected"])
        control_backends = {
            "base": _backend_json(base),
            "panic": _backend_json(panic),
            "hang": _backend_json(hang),
            "timeout": _backend_json(timeout),
        }
        report = {
            "run_id": bundle.run_id,
            "profile": profile_name,
            "controls": True,
            "lock_hash": verification.lock_hash,
            "manifest_hash": selection.manifest_hash,
            "payload_hash": selection.payload_hash,
            "input_hashes": input_hashes,
            "effective_lock_sha256": effective_lock_hash,
            "backend_identity": snapshot.backend_identity,
            "selection_snapshot": {
                "manifest_hash": snapshot.manifest_hash,
                "payload_hash": snapshot.payload_hash,
                "case_ids": list(snapshot.case_ids),
            },
            "replay": replay_index(selection),
            "control_backends": control_backends,
            "controls": controls,
            "pending_controls": {
                name: {"status": "pending", "blocked_by": item, "passed": False}
                for name, item in sorted(PENDING_CONTROLS.items())
            },
            "controls_detected": detected_count,
            "controls_total": len(controls),
            "internal_failures": internal_failures,
        }
        teardown_errors = bundle.teardown()
        report["teardown_errors"] = teardown_errors
        bundle.publish_report(report)
        print(f"controls evidence: {bundle.root}")
        print(f"report: {bundle.report_path}")
        for name, item in sorted(controls.items()):
            state = "DETECTED" if item["detected"] else "NOT-DETECTED"
            print(f"{state} {name}: {item['detail']}")
        for name, blocked_by in sorted(PENDING_CONTROLS.items()):
            print(f"PENDING {name}: blocked by {blocked_by}")
        for failure in internal_failures:
            print(f"INTERNAL-FAIL {failure}")
        for error in teardown_errors:
            print(f"teardown error: {error}")
        print(f"CONTROLS RESULT: {detected_count}/{len(controls)} controls detected")
        ok = detected_count == len(controls) and not internal_failures and not teardown_errors
        return 0 if ok else 1
    except Exception as error:
        if bundle is not None and not bundle.report_path.exists():
            try:
                bundle.register_artifact("harness-error.txt", f"{type(error).__name__}: {error}\n".encode("utf-8", errors="replace"))
                bundle.publish_report(
                    {
                        "run_id": bundle.run_id,
                        "profile": profile_name,
                        "controls": True,
                        "error": f"{type(error).__name__}: {error}",
                        "controls": controls,
                    }
                )
            except Exception:
                pass
        if bundle is not None:
            try:
                bundle.teardown()
            except Exception:
                pass
        print(f"HARNESS_ERROR {type(error).__name__}: {error}", file=sys.stderr)
        return 1
