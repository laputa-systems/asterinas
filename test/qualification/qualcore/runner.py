import json
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .accounting import CaseOutcome, RoleResult, reconcile
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
from .qemu import VmExclusion, run_qemu
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


class RunFailure(Exception):
    pass


PENDING_CONTROLS = {
    "live-device:wrong-filesystem": "LC-06",
    "live-device:wrong-disk": "LC-06",
    "live-device:failed-mount": "LC-06",
    "live-device:missing-privileges": "LC-06",
    "live-device:missing-reference-configuration": "LC-06",
    "persistence:omitted-sync-crash-cut": "LC-11",
}


def load_selection(repo: Path, profile_name: str) -> Selection:
    contracts = sorted((repo / "test/qualification/contracts").glob("*/*.json"))
    if not contracts:
        raise RunFailure("no contract manifests found")
    return load_profile(profile_name, repo / "test/qualification/profiles", load_case_index(contracts))


def copy_run_inputs(repo: Path, bundle: EvidenceBundle) -> dict[str, Path]:
    sources = {
        "linux-bzImage": repo / "test/qualification/linux/bzImage",
        "initramfs.cpio": repo / CACHE_DIR / "initramfs.cpio",
        "probe": repo / CACHE_DIR / "probe",
        "probe-input.txt": repo / "test/qualification/probe/input.txt",
        "inputs.lock.json": repo / LOCK_PATH,
    }
    copied: dict[str, Path] = {}
    for name, source in sources.items():
        if not source.is_file():
            raise RunFailure(f"run input is missing: {source}")
        destination = bundle.inputs_dir / name
        shutil.copyfile(source, destination)
        copied[name] = destination
    input_manifest = {name: sha256_bytes(path.read_bytes()) for name, path in sorted(copied.items())}
    (bundle.inputs_dir / "manifest.json").write_text(json.dumps(input_manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return copied


def bind_run_inputs(bundle: EvidenceBundle, verification: LockVerification, selection: Selection) -> tuple[dict[str, str], str]:
    input_hashes = json.loads((bundle.inputs_dir / "manifest.json").read_text(encoding="utf-8"))
    effective_hash = write_effective_lock(
        bundle.inputs_dir / "effective-inputs.lock.json",
        verification,
        selection,
        input_hashes,
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
    selection: Selection,
    label: str,
    control: str = "none",
    deadline: float | None = None,
    silence_timeout: float | None = None,
) -> BackendEvidence:
    stream_run_id = f"{bundle.run_id}-{label}"
    nonce = secrets.token_hex(16)
    case = selection.cases[0]
    lock_document = json.loads((repo / LOCK_PATH).read_text(encoding="utf-8"))
    execution = run_qemu(
        qemu_path=Path(lock_document["qemu"]["path"]),
        kernel=inputs["linux-bzImage"],
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
    stream_text = stream_bytes.decode("utf-8", errors="replace")
    context = ResultContext(
        run_id=stream_run_id,
        nonce=nonce,
        manifest_hash=selection.manifest_hash,
        payload_hash=selection.payload_hash,
        cases=selection.case_map,
        max_age_seconds=300,
        now=time.time(),
    )
    ingestion = ingest_result_stream(stream_text, context)
    diagnostics = tuple(ingestion.rendered())
    if not qual_exists:
        diagnostics = (*diagnostics, "missing-artifact: qemu did not create the dedicated serial log")
    observed = {case_id: _observed_values(ingestion, case_id) for case_id in selection.case_ids}
    final_status = None
    if selection.case_ids:
        final = ingestion.finals.get(selection.case_ids[0])
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


def evaluate_case(case: CaseSpec, reference: BackendEvidence, candidate: BackendEvidence) -> CaseOutcome:
    reference_status, reference_detail, reference_terminal = _backend_role(reference)
    candidate_status, candidate_detail, candidate_terminal = _backend_role(candidate)
    reference_role = RoleResult("reference", reference_status, reference_detail)
    candidate_role = RoleResult("candidate", candidate_status, candidate_detail)

    reference_observed = reference.observed.get(case.case_id, {})
    candidate_observed = candidate.observed.get(case.case_id, {})
    validator_failures: list[str] = []
    comparator_failures: list[str] = []
    if reference_role.status == "pass":
        validator_failures = compare_against_contract(case, reference_observed)
    else:
        validator_failures = ["reference stream did not complete cleanly"]
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
    }


def run_selfcheck(repo: Path, profile_name: str, candidate: str) -> int:
    if candidate != "linux":
        print(f"HARNESS_ERROR unsupported candidate {candidate!r}; LC-05 implements only linux", file=sys.stderr)
        return 2
    bundle: EvidenceBundle | None = None
    try:
        verification = verify_lock(repo)
        selection = load_selection(repo, profile_name)
        bundle = EvidenceBundle.create(repo / "target/qualification")
        inputs = copy_run_inputs(repo, bundle)
        input_hashes, effective_lock_hash = bind_run_inputs(bundle, verification, selection)
        with VmExclusion(repo / "target/qualification/vm.lock"):
            reference = execute_backend(repo, bundle, inputs, selection, "reference")
            candidate_evidence = execute_backend(repo, bundle, inputs, selection, "candidate")
        outcomes = tuple(
            evaluate_case(case, reference, candidate_evidence)
            for case in selection.cases
        )
        accounting = reconcile(selection.case_ids, outcomes)
        report = {
            "run_id": bundle.run_id,
            "profile": profile_name,
            "candidate": candidate,
            "lock_hash": verification.lock_hash,
            "manifest_hash": selection.manifest_hash,
            "payload_hash": selection.payload_hash,
            "selected_count": len(selection.case_ids),
            "input_hashes": input_hashes,
            "effective_lock_sha256": effective_lock_hash,
            "replay": replay_index(selection),
            "backends": {
                "reference": _backend_json(reference),
                "candidate": _backend_json(candidate_evidence),
            },
            "outcomes": {
                outcome.case_id: {
                    "disposition": outcome.disposition,
                    "reason": outcome.reason,
                    "results": [_role_json(role) for role in outcome.results],
                }
                for outcome in outcomes
            },
            "dispositions": dict(accounting.counts),
            "accounting_diagnostics": [item.render() for item in accounting.diagnostics],
        }
        bundle.publish_report(report)
        teardown_errors = bundle.teardown()
        print(f"run evidence: {bundle.root}")
        print(f"report: {bundle.report_path}")
        print(f"dispositions: {dict(accounting.counts)}")
        for item in accounting.diagnostics:
            print(f"accounting diagnostic: {item.render()}")
        for error in teardown_errors:
            print(f"teardown error: {error}")
        ok = accounting.counts.get("PASS", 0) == len(selection.case_ids) and not accounting.diagnostics and not teardown_errors
        return 0 if ok else 1
    except Exception as error:
        if bundle is not None and not bundle.report_path.exists():
            try:
                bundle.register_artifact("harness-error.txt", f"{type(error).__name__}: {error}\n".encode("utf-8", errors="replace"))
                bundle.publish_report(
                    {
                        "run_id": bundle.run_id,
                        "profile": profile_name,
                        "candidate": candidate,
                        "dispositions": {"HARNESS_ERROR": 1},
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
            except Exception:
                pass
        print(f"HARNESS_ERROR {type(error).__name__}: {error}", file=sys.stderr)
        return 1


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
        record = _first_subtest_record(parsed, "errno-on-failure")
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
    for name, subtest, assertion_id, wrong in (
        ("real-wrong-errno", "errno-on-failure", "errno", 0),
        ("real-wrong-bytes", "read-fixed-input", "bytes", "Z29vZGJ5ZQo="),
        ("real-wrong-permission", "dev-null-write", "permission", "deny"),
    ):
        def wrong_value(parsed, subtest=subtest, wrong=wrong):
            record = _first_subtest_record(parsed, subtest)
            if record is not None:
                record["assertions"][0]["value"] = wrong

        mutated = mutate_stream(base.stream_text, wrong_value)
        context = ResultContext(
            run_id=base.stream_run_id,
            nonce=base.nonce,
            manifest_hash=selection.manifest_hash,
            payload_hash=selection.payload_hash,
            cases=selection.case_map,
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
            "detail": "; ".join(failures) if failures else "mutation was not rejected",
        }

    recomputation_detected = not verify_comparison_claim("errno", "ENOENT", 0, claimed_match=True)
    controls["comparator-recomputation"] = {
        "detected": recomputation_detected,
        "detail": "claimed equality of ENOENT and 0 is contradicted by recomputation",
    }
    return controls


def run_controls(repo: Path, profile_name: str) -> int:
    bundle: EvidenceBundle | None = None
    controls: dict[str, dict[str, Any]] = {}
    internal_failures: list[str] = []
    try:
        verification = verify_lock(repo)
        selection = load_selection(repo, profile_name)
        bundle = EvidenceBundle.create(repo / "target/qualification")
        inputs = copy_run_inputs(repo, bundle)
        input_hashes, effective_lock_hash = bind_run_inputs(bundle, verification, selection)
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
            base = execute_backend(repo, bundle, inputs, selection, "control-base")
            if base.execution_outcome != "exit" or base.ingestion_diagnostics or base.final_status != "pass":
                internal_failures.append(
                    f"control base stream is not valid: outcome={base.execution_outcome} final={base.final_status} diagnostics={list(base.ingestion_diagnostics)}"
                )
            controls.update(real_stream_controls(base, selection))

            panic = execute_backend(repo, bundle, inputs, selection, "control-panic", control="panic", deadline=20)
            controls["real-guest-panic"] = {
                "detected": panic.execution_outcome == "panic",
                "detail": f"outcome={panic.execution_outcome} teardown={panic.teardown_state}",
            }

            hang = execute_backend(repo, bundle, inputs, selection, "control-hang", control="hang", deadline=20, silence_timeout=3)
            controls["real-guest-hang"] = {
                "detected": hang.execution_outcome == "hang",
                "detail": f"outcome={hang.execution_outcome} teardown={hang.teardown_state}",
            }

            timeout = execute_backend(repo, bundle, inputs, selection, "control-timeout", deadline=1)
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
                accounting = reconcile(selection.case_ids, [outcome])
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
        bundle.publish_report(report)
        teardown_errors = bundle.teardown()
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
        print(f"HARNESS_ERROR {type(error).__name__}: {error}", file=sys.stderr)
        return 1
