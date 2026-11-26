import json
import math
import time
from dataclasses import dataclass, field
from typing import Any

from .manifest import CaseSpec


@dataclass(frozen=True)
class Diagnostic:
    category: str
    message: str

    def render(self) -> str:
        return f"{self.category}: {self.message}"


@dataclass(frozen=True)
class ResultContext:
    run_id: str
    nonce: str
    manifest_hash: str
    payload_hash: str
    cases: dict[str, CaseSpec]
    max_age_seconds: float = 300.0
    now: float = 0.0
    future_tolerance_seconds: float = 5.0


@dataclass
class Ingestion:
    records: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    finals: dict[str, dict[str, Any]] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def has(self, category: str) -> bool:
        return any(item.category == category for item in self.diagnostics)

    def categories(self) -> set[str]:
        return {item.category for item in self.diagnostics}

    def rendered(self) -> list[str]:
        return [item.render() for item in self.diagnostics]


def _add(ingestion: Ingestion, category: str, message: str) -> None:
    ingestion.diagnostics.append(Diagnostic(category, message))


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"nonstandard JSON constant {value}")


def _json_error_category(fragment: str, error: json.JSONDecodeError) -> str:
    opens = fragment.count("{") + fragment.count("[")
    closes = fragment.count("}") + fragment.count("]")
    if error.pos >= max(0, len(fragment) - 1) or opens > closes:
        return "truncated-output"
    return "malformed-output"


def ingest_result_stream(text: str, context: ResultContext) -> Ingestion:
    ingestion = Ingestion()
    selected = set(context.cases)
    last_sequence = 0
    seen_sequences: set[int] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split(" ", 3)
        if len(parts) != 4 or parts[0] != "QUAL":
            _add(ingestion, "malformed-output", f"line {line_number} is not a QUAL record")
            continue
        if parts[1] != context.run_id:
            _add(ingestion, "wrong-run-id", f"line {line_number} has run id {parts[1]!r}")
            continue
        if parts[2] != context.nonce:
            _add(ingestion, "wrong-nonce", f"line {line_number} has a mismatched nonce")
            continue
        fragment = parts[3]
        try:
            record = json.loads(fragment, parse_constant=_reject_json_constant)
        except json.JSONDecodeError as error:
            _add(ingestion, _json_error_category(fragment, error), f"line {line_number}: {error.msg}")
            continue
        except ValueError as error:
            _add(ingestion, "malformed-output", f"line {line_number}: {error}")
            continue
        if not isinstance(record, dict):
            _add(ingestion, "malformed-output", f"line {line_number} payload is not an object")
            continue

        required = ("case_id", "sequence", "kind", "manifest_hash", "payload_hash", "emitted_at")
        missing = [field for field in required if field not in record]
        if missing:
            _add(ingestion, "malformed-output", f"line {line_number} is missing {', '.join(missing)}")
            continue
        if not isinstance(record["manifest_hash"], str) or not isinstance(record["payload_hash"], str):
            _add(ingestion, "malformed-output", f"line {line_number} manifest_hash and payload_hash must be strings")
            continue
        if record["manifest_hash"] != context.manifest_hash:
            _add(ingestion, "wrong-manifest-hash", f"line {line_number} case {record.get('case_id')}")
            continue
        if record["payload_hash"] != context.payload_hash:
            _add(ingestion, "wrong-payload-hash", f"line {line_number} case {record.get('case_id')}")
            continue
        case_id = record["case_id"]
        if not isinstance(case_id, str):
            _add(ingestion, "malformed-output", f"line {line_number} case_id is not a string")
            continue
        if case_id not in selected:
            _add(ingestion, "unknown-case", f"line {line_number} names {case_id!r}")
            continue
        sequence = record["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            _add(ingestion, "malformed-output", f"line {line_number} sequence is not a positive integer")
            continue
        if sequence in seen_sequences:
            _add(ingestion, "duplicate-case-record", f"line {line_number} repeats sequence {sequence}")
            continue
        if sequence <= last_sequence:
            _add(ingestion, "contradiction", f"line {line_number} sequence regresses")
            continue
        seen_sequences.add(sequence)
        last_sequence = sequence
        kind = record["kind"]
        if not isinstance(kind, str) or kind not in {"start", "subtest", "final"}:
            _add(ingestion, "malformed-output", f"line {line_number} has unknown kind {kind!r}")
            continue
        if isinstance(record["emitted_at"], bool) or not isinstance(record["emitted_at"], (int, float)):
            _add(ingestion, "malformed-output", f"line {line_number} emitted_at is not numeric")
            continue
        if isinstance(record["emitted_at"], float) and not math.isfinite(record["emitted_at"]):
            _add(ingestion, "malformed-output", f"line {line_number} emitted_at is not finite")
            continue
        now = context.now or time.time()
        if record["emitted_at"] > now + context.future_tolerance_seconds:
            _add(ingestion, "future-timestamp", f"line {line_number} case {case_id} is emitted in the future")
            continue
        ingestion.records.setdefault(case_id, []).append(record)

    for case_id in sorted(selected):
        records = ingestion.records.get(case_id, [])
        finals = [record for record in records if record["kind"] == "final"]
        if not finals:
            _add(ingestion, "missing-final-record", case_id)
            continue
        if len(finals) > 1:
            _add(ingestion, "duplicate-case-record", f"{case_id} has {len(finals)} final records")
        final = finals[0]
        ingestion.finals[case_id] = final
        now = context.now or time.time()
        if final["emitted_at"] < now - context.max_age_seconds:
            _add(ingestion, "stale-log", f"{case_id} final record is older than {context.max_age_seconds} seconds")
        _validate_case_records(case_id, context.cases[case_id], records, final, ingestion)

    return ingestion


def _validate_required_artifacts(case_id: str, case: CaseSpec, final: dict[str, Any], ingestion: Ingestion) -> None:
    artifacts = final.get("artifacts")
    if not isinstance(artifacts, list):
        _add(ingestion, "malformed-output", f"{case_id} final artifacts field is not an array")
        return
    names: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("name"), str):
            _add(ingestion, "malformed-output", f"{case_id} has a malformed final artifact entry")
            continue
        name = artifact["name"]
        if name in names:
            _add(ingestion, "contradiction", f"{case_id} final artifact {name!r} is duplicated")
        names.add(name)
        checksum = artifact.get("sha256")
        size = artifact.get("size")
        if not isinstance(checksum, str) or len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum):
            _add(ingestion, "malformed-output", f"{case_id} final artifact {name!r} has an invalid sha256")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            _add(ingestion, "malformed-output", f"{case_id} final artifact {name!r} has an invalid size")
    for required in sorted(set(case.artifacts) - names):
        _add(ingestion, "missing-required-artifact", f"{case_id}/{required}")


def _validate_case_records(case_id: str, case: CaseSpec, records: list[dict[str, Any]], final: dict[str, Any], ingestion: Ingestion) -> None:
    starts = [record for record in records if record["kind"] == "start"]
    if not starts:
        _add(ingestion, "missing-start-record", case_id)
    if len(starts) > 1:
        _add(ingestion, "duplicate-start-record", f"{case_id} has {len(starts)} start records")
    if records and records[0]["kind"] != "start":
        _add(ingestion, "contradiction", f"{case_id} does not begin with its start record")
    if records[-1]["kind"] != "final":
        _add(ingestion, "contradiction", f"{case_id} has records after its final record")
    _validate_required_artifacts(case_id, case, final, ingestion)
    expected_subtests = {subtest.subtest_id: subtest for subtest in case.expected_subtests}
    subtest_records: dict[str, list[dict[str, Any]]] = {}
    failing_subtests: set[str] = set()
    passing_subtests: set[str] = set()
    observed_assertions = 0

    for record in records:
        if record["kind"] != "subtest":
            continue
        subtest_id = record.get("subtest")
        if not isinstance(subtest_id, str):
            _add(ingestion, "malformed-output", f"{case_id} has a subtest record without a subtest id")
            continue
        subtest_records.setdefault(subtest_id, []).append(record)
        status = record.get("status")
        if status == "pass":
            passing_subtests.add(subtest_id)
        elif status == "fail":
            failing_subtests.add(subtest_id)
        else:
            _add(ingestion, "malformed-output", f"{case_id}/{subtest_id} has invalid status {status!r}")
        if subtest_id in passing_subtests and subtest_id in failing_subtests:
            _add(ingestion, "contradiction", f"{case_id}/{subtest_id} reports both pass and fail")

    for subtest_id, items in subtest_records.items():
        if len(items) > 1:
            _add(ingestion, "duplicate-case-record", f"{case_id}/{subtest_id} has duplicate subtest records")
        if subtest_id not in expected_subtests:
            _add(ingestion, "contradiction", f"{case_id} reports unknown subtest {subtest_id!r}")
            continue
        expected_assertions = {item.assertion_id for item in expected_subtests[subtest_id].assertions}
        for record in items:
            assertions = record.get("assertions")
            if not isinstance(assertions, list):
                _add(ingestion, "malformed-output", f"{case_id}/{subtest_id} assertions are not an array")
                continue
            seen: set[str] = set()
            values: set[str] = set()
            for assertion in assertions:
                if not isinstance(assertion, dict) or not isinstance(assertion.get("id"), str):
                    _add(ingestion, "malformed-output", f"{case_id}/{subtest_id} has a malformed assertion")
                    continue
                assertion_id = assertion["id"]
                if "value" not in assertion:
                    _add(ingestion, "malformed-output", f"{case_id}/{subtest_id}/{assertion_id} carries no observed value")
                if assertion_id in seen:
                    _add(ingestion, "contradiction", f"{case_id}/{subtest_id}/{assertion_id} is duplicated")
                seen.add(assertion_id)
                values.add(assertion_id)
                observed_assertions += 1
                if assertion_id not in expected_assertions:
                    _add(ingestion, "contradiction", f"{case_id}/{subtest_id} reports unknown assertion {assertion_id!r}")
            for missing in sorted(expected_assertions - values):
                _add(ingestion, "missing-assertion", f"{case_id}/{subtest_id}/{missing}")

    for subtest_id in sorted(set(expected_subtests) - set(subtest_records)):
        _add(ingestion, "missing-subtest", f"{case_id}/{subtest_id}")

    expected_subtest_count = len(expected_subtests)
    expected_assertion_count = sum(len(subtest.assertions) for subtest in case.expected_subtests)
    actual_subtest_count = len(subtest_records)
    final_subtests = final.get("subtests_completed")
    final_assertions = final.get("assertions_completed")
    for field_name, value in (("subtests_completed", final_subtests), ("assertions_completed", final_assertions)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _add(ingestion, "malformed-output", f"{case_id} final {field_name} is not a nonnegative integer")
    if final_subtests != expected_subtest_count or final_subtests != actual_subtest_count:
        _add(
            ingestion,
            "incomplete-accounting",
            f"{case_id} final subtest count {final_subtests!r}, expected {expected_subtest_count}, observed {actual_subtest_count}",
        )
    if final_assertions != expected_assertion_count or final_assertions != observed_assertions:
        _add(
            ingestion,
            "incomplete-accounting",
            f"{case_id} final assertion count {final_assertions!r}, expected {expected_assertion_count}, observed {observed_assertions}",
        )
    final_status = final.get("status")
    if not isinstance(final_status, str) or final_status not in {"pass", "fail", "skip", "unsupported"}:
        _add(ingestion, "malformed-output", f"{case_id} final status is invalid")
    elif failing_subtests and final_status == "pass":
        _add(ingestion, "contradiction", f"{case_id} final pass contradicts failing subtests")
    elif not failing_subtests and actual_subtest_count == expected_subtest_count and final_status == "fail":
        _add(ingestion, "contradiction", f"{case_id} final fail contradicts passing subtests")


def make_result_line(run_id: str, nonce: str, record: dict[str, Any]) -> str:
    return f"QUAL {run_id} {nonce} {json.dumps(record, sort_keys=True, separators=(',', ':'))}\n"
