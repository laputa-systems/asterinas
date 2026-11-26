import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ManifestError
from .util import read_json_file, sha256_canonical


@dataclass(frozen=True)
class AssertionSpec:
    assertion_id: str
    value_type: str
    expected: Any
    mode: str
    normalization: tuple[str, ...]


@dataclass(frozen=True)
class SubtestSpec:
    subtest_id: str
    assertions: tuple[AssertionSpec, ...]


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    area: str
    item_id: str
    contract_revision: str
    source: dict[str, Any]
    membership: str
    applicability: dict[str, Any]
    procedure: str
    expected_subtests: tuple[SubtestSpec, ...]
    comparison: dict[str, Any]
    deadline_seconds: float
    budget_bytes: int
    seed: int
    iterations: int
    artifacts: tuple[str, ...]
    validators: tuple[str, ...]
    replay: str
    payload: dict[str, Any]
    raw: dict[str, Any]


@dataclass(frozen=True)
class Selection:
    profile_name: str
    cases: tuple[CaseSpec, ...]
    manifest_hash: str
    payload_hash: str
    excluded: tuple[tuple[str, str], ...]

    @property
    def case_ids(self) -> tuple[str, ...]:
        return tuple(case.case_id for case in self.cases)

    @property
    def case_map(self) -> dict[str, CaseSpec]:
        return {case.case_id: case for case in self.cases}


def _require_object(value: Any, path: Path, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{path}: {description} must be an object")
    return value


def _require_fields(value: dict[str, Any], fields: tuple[str, ...], path: Path, description: str) -> None:
    missing = [field for field in fields if field not in value]
    if missing:
        raise ManifestError(f"{path}: {description} is missing fields: {', '.join(missing)}")


def _parse_assertion(raw: Any, path: Path, case_id: str, subtest_id: str) -> AssertionSpec:
    if not isinstance(raw, dict):
        raise ManifestError(f"{path}: case {case_id} subtest {subtest_id} has a non-object assertion")
    _require_fields(raw, ("id", "type", "expected"), path, f"case {case_id} assertion")
    assertion_id = raw["id"]
    value_type = raw["type"]
    mode = raw.get("mode", "exact")
    normalization_raw = raw.get("normalization", [])
    if not isinstance(normalization_raw, list):
        raise ManifestError(f"{path}: case {case_id} assertion {assertion_id} normalization must be a list")
    normalization = tuple(normalization_raw)
    if not assertion_id or not isinstance(assertion_id, str):
        raise ManifestError(f"{path}: case {case_id} has an empty assertion id")
    if not isinstance(value_type, str) or value_type not in {"errno", "bytes", "permission"}:
        raise ManifestError(f"{path}: case {case_id} assertion {assertion_id} has unsupported type {value_type!r}")
    if not isinstance(mode, str) or mode not in {"exact", "normalized", "invariant"}:
        raise ManifestError(f"{path}: case {case_id} assertion {assertion_id} has unsupported mode {mode!r}")
    if not all(isinstance(rule, str) for rule in normalization):
        raise ManifestError(f"{path}: case {case_id} assertion {assertion_id} normalization must be strings")
    return AssertionSpec(assertion_id, value_type, raw["expected"], mode, normalization)


def _parse_subtest(raw: Any, path: Path, case_id: str) -> SubtestSpec:
    if not isinstance(raw, dict):
        raise ManifestError(f"{path}: case {case_id} has a non-object expected subtest")
    _require_fields(raw, ("id", "assertions"), path, f"case {case_id} expected subtest")
    subtest_id = raw["id"]
    if not subtest_id or not isinstance(subtest_id, str):
        raise ManifestError(f"{path}: case {case_id} has an empty subtest id")
    assertions_raw = raw["assertions"]
    if not isinstance(assertions_raw, list) or not assertions_raw:
        raise ManifestError(f"{path}: case {case_id} subtest {subtest_id} has no expected assertions")
    assertions = tuple(_parse_assertion(item, path, case_id, subtest_id) for item in assertions_raw)
    assertion_ids = [item.assertion_id for item in assertions]
    if len(assertion_ids) != len(set(assertion_ids)):
        raise ManifestError(f"{path}: case {case_id} subtest {subtest_id} has duplicate assertions")
    return SubtestSpec(subtest_id, assertions)


def parse_case(raw: dict[str, Any], path: Path) -> CaseSpec:
    required = (
        "id",
        "contract_revision",
        "area",
        "item",
        "source",
        "membership",
        "applicability",
        "procedure",
        "expected_subtests",
        "comparison",
        "deadline_seconds",
        "budget_bytes",
        "seed",
        "iterations",
        "artifacts",
        "validators",
        "replay",
        "payload",
    )
    _require_fields(raw, required, path, "case")
    case_id = raw["id"]
    if not case_id or not isinstance(case_id, str):
        raise ManifestError(f"{path}: case id must be a non-empty string")
    for field in ("contract_revision", "area", "item", "membership", "procedure", "replay"):
        if not isinstance(raw[field], str) or not raw[field]:
            raise ManifestError(f"{path}: case {case_id} field {field} must be a non-empty string")
    source = _require_object(raw["source"], path, f"case {case_id} source")
    _require_fields(source, ("upstream", "revision", "license", "patch_hash"), path, f"case {case_id} source")
    applicability = _require_object(raw["applicability"], path, f"case {case_id} applicability")
    _require_fields(applicability, ("architectures", "backends", "privileges", "required_config"), path, f"case {case_id} applicability")
    for field in ("architectures", "backends", "privileges"):
        if not isinstance(applicability[field], list) or not all(isinstance(item, str) and item for item in applicability[field]):
            raise ManifestError(f"{path}: case {case_id} applicability {field} must be a string list")
    if not isinstance(applicability["required_config"], dict):
        raise ManifestError(f"{path}: case {case_id} applicability required_config must be an object")
    comparison = _require_object(raw["comparison"], path, f"case {case_id} comparison")
    if not isinstance(comparison.get("mode"), str) or comparison.get("mode") not in {"exact", "normalized", "allowed-outcome", "invariant"}:
        raise ManifestError(f"{path}: case {case_id} comparison mode is invalid")
    subtests_raw = raw["expected_subtests"]
    if not isinstance(subtests_raw, list) or not subtests_raw:
        raise ManifestError(f"{path}: case {case_id} has no expected subtests")
    subtests = tuple(_parse_subtest(item, path, case_id) for item in subtests_raw)
    subtest_ids = [item.subtest_id for item in subtests]
    if len(subtest_ids) != len(set(subtest_ids)):
        raise ManifestError(f"{path}: case {case_id} has duplicate expected subtests")
    deadline = raw["deadline_seconds"]
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline) or deadline <= 0:
        raise ManifestError(f"{path}: case {case_id} deadline must be a finite positive number")
    budget = raw["budget_bytes"]
    if isinstance(budget, bool) or not isinstance(budget, int) or budget <= 0:
        raise ManifestError(f"{path}: case {case_id} byte budget must be positive")
    seed = raw["seed"]
    iterations = raw["iterations"]
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ManifestError(f"{path}: case {case_id} seed must be an integer")
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations <= 0:
        raise ManifestError(f"{path}: case {case_id} iterations must be positive")
    artifacts = raw["artifacts"]
    if not isinstance(artifacts, list) or not all(isinstance(item, str) and item for item in artifacts):
        raise ManifestError(f"{path}: case {case_id} artifacts must be a string list")
    validators = raw["validators"]
    if not isinstance(validators, list) or not all(isinstance(item, str) and item for item in validators):
        raise ManifestError(f"{path}: case {case_id} validators must be a string list")
    payload = _require_object(raw["payload"], path, f"case {case_id} payload")
    return CaseSpec(
        case_id=case_id,
        area=raw["area"],
        item_id=raw["item"],
        contract_revision=raw["contract_revision"],
        source=source,
        membership=raw["membership"],
        applicability=applicability,
        procedure=raw["procedure"],
        expected_subtests=subtests,
        comparison=comparison,
        deadline_seconds=float(deadline),
        budget_bytes=budget,
        seed=int(raw["seed"]),
        iterations=int(raw["iterations"]),
        artifacts=tuple(artifacts),
        validators=tuple(validators),
        replay=raw["replay"],
        payload=payload,
        raw=raw,
    )


def load_case_manifest(path: Path) -> dict[str, CaseSpec]:
    raw = read_json_file(path)
    document = _require_object(raw, path, "case manifest")
    cases_raw = document.get("cases")
    if not isinstance(cases_raw, list):
        raise ManifestError(f"{path}: case manifest requires a cases array")
    parsed: dict[str, CaseSpec] = {}
    for case_raw in cases_raw:
        case = parse_case(_require_object(case_raw, path, "case"), path)
        if case.case_id in parsed:
            raise ManifestError(f"{path}: duplicate case {case.case_id}")
        parsed[case.case_id] = case
    return parsed


def load_case_index(paths: list[Path]) -> dict[str, CaseSpec]:
    index: dict[str, CaseSpec] = {}
    for path in paths:
        for case_id, case in load_case_manifest(path).items():
            if case_id in index:
                raise ManifestError(f"{path}: duplicate case {case_id} across manifests")
            index[case_id] = case
    return index


def _load_profile_document(path: Path) -> dict[str, Any]:
    raw = read_json_file(path)
    document = _require_object(raw, path, "profile")
    _require_fields(document, ("name", "inherits", "cases"), path, "profile")
    if document["name"] != path.stem:
        raise ManifestError(f"{path}: profile name must match its file name")
    for field in ("inherits", "cases"):
        if not isinstance(document[field], list) or not all(isinstance(item, str) for item in document[field]):
            raise ManifestError(f"{path}: profile field {field} must be a string array")
    excludes = document.get("excludes", [])
    if not isinstance(excludes, list):
        raise ManifestError(f"{path}: profile excludes must be an array")
    for exclusion in excludes:
        if not isinstance(exclusion, dict) or not isinstance(exclusion.get("case"), str) or not isinstance(exclusion.get("reason"), str):
            raise ManifestError(f"{path}: profile exclusions require case and reason strings")
    return document


def load_profile(profile_name: str, profiles_dir: Path, case_index: dict[str, CaseSpec]) -> Selection:
    ordered_cases: list[str] = []
    exclusions: dict[str, str] = {}
    hash_documents: list[dict[str, Any]] = []
    visiting: list[str] = []

    def visit(name: str) -> None:
        if name in visiting:
            cycle = " -> ".join([*visiting, name])
            raise ManifestError(f"profile inheritance cycle: {cycle}")
        path = profiles_dir / f"{name}.json"
        if not path.exists():
            raise ManifestError(f"{path}: unknown inherited or requested profile {name}")
        document = _load_profile_document(path)
        visiting.append(name)
        for parent in document["inherits"]:
            visit(parent)
        visiting.pop()
        hash_documents.append(document)
        for case_id in document["cases"]:
            if case_id not in case_index:
                raise ManifestError(f"{path}: unknown case {case_id}")
            if case_id in ordered_cases:
                raise ManifestError(f"{path}: duplicate selected case {case_id}")
            ordered_cases.append(case_id)
        for exclusion in document.get("excludes", []):
            case_id = exclusion["case"]
            if case_id not in case_index:
                raise ManifestError(f"{path}: exclusion names unknown case {case_id}")
            exclusions[case_id] = exclusion["reason"]

    visit(profile_name)
    selected_ids = [case_id for case_id in ordered_cases if case_id not in exclusions]
    if not selected_ids:
        raise ManifestError(f"profile {profile_name}: empty selection")
    cases = tuple(case_index[case_id] for case_id in selected_ids)
    manifest_identity = {
        "profiles": hash_documents,
        "cases": [case_index[case_id].raw for case_id in selected_ids],
        "excluded": sorted(exclusions.items()),
    }
    payload_identity = {case.case_id: case.payload for case in cases}
    return Selection(
        profile_name=profile_name,
        cases=cases,
        manifest_hash=sha256_canonical(manifest_identity),
        payload_hash=sha256_canonical(payload_identity),
        excluded=tuple(sorted(exclusions.items())),
    )
