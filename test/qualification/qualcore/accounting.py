from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from .results import Diagnostic


TERMINAL_DISPOSITIONS = {
    "PASS",
    "FAIL",
    "XFAIL",
    "XPASS",
    "SKIP_PREREQUISITE",
    "UNSUPPORTED",
    "TIMEOUT",
    "PANIC",
    "HARNESS_ERROR",
    "REFERENCE_FAILURE",
    "NOT_RUN",
}

RESULT_ROLES = {"candidate", "reference", "comparator", "validator"}
RUNTIME_EVIDENCE_STATUSES = {
    "TIMEOUT": "timeout",
    "PANIC": "panic",
    "HARNESS_ERROR": "harness-error",
}


@dataclass(frozen=True)
class RoleResult:
    role: str
    status: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.role not in RESULT_ROLES:
            raise ValueError(f"unknown result role {self.role!r}")


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    disposition: str
    results: tuple[RoleResult, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        if self.disposition not in TERMINAL_DISPOSITIONS:
            raise ValueError(f"unknown terminal disposition {self.disposition!r}")
        roles = [result.role for result in self.results]
        if len(roles) != len(set(roles)):
            raise ValueError(f"case {self.case_id} has duplicate result roles")


@dataclass
class Accounting:
    outcomes: dict[str, CaseOutcome]
    counts: Counter[str]
    selected_count: int
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def disposition_total(self) -> int:
        return sum(self.counts.values())

    @property
    def balanced(self) -> bool:
        return self.selected_count == self.disposition_total

    def has(self, category: str) -> bool:
        return any(item.category == category for item in self.diagnostics)


def reconcile(selected_case_ids: Iterable[str], outcomes: Iterable[CaseOutcome]) -> Accounting:
    supplied_selection = list(selected_case_ids)
    selected = list(dict.fromkeys(supplied_selection))
    diagnostics: list[Diagnostic] = []
    if len(supplied_selection) != len(selected):
        diagnostics.append(Diagnostic("duplicate-case-record", "selected case list contains a duplicate"))
    by_case: dict[str, CaseOutcome] = {}

    for outcome in outcomes:
        if outcome.case_id not in selected:
            diagnostics.append(Diagnostic("unknown-case", f"accounting outcome names {outcome.case_id!r}"))
            continue
        if outcome.case_id in by_case:
            diagnostics.append(Diagnostic("duplicate-case-record", f"accounting outcome repeats {outcome.case_id!r}"))
            continue
        by_case[outcome.case_id] = outcome

    for case_id in selected:
        if case_id not in by_case:
            diagnostics.append(Diagnostic("contradiction", f"{case_id} has no terminal outcome"))

    for outcome in by_case.values():
        roles = {result.role: result for result in outcome.results}
        comparator = roles.get("comparator")
        candidate = roles.get("candidate")
        validator = roles.get("validator")
        reference = roles.get("reference")
        if outcome.disposition == "PASS":
            for role in ("candidate", "reference", "comparator", "validator"):
                if role not in roles:
                    diagnostics.append(Diagnostic("contradiction", f"{outcome.case_id} PASS lacks a {role} result"))
            if comparator is not None and comparator.status != "pass":
                diagnostics.append(Diagnostic("contradiction", f"{outcome.case_id} PASS contradicts comparator {comparator.status}"))
            if candidate is not None and candidate.status != "pass":
                diagnostics.append(Diagnostic("contradiction", f"{outcome.case_id} PASS contradicts candidate {candidate.status}"))
            if reference is not None and reference.status not in {"pass", "not-required"}:
                diagnostics.append(Diagnostic("contradiction", f"{outcome.case_id} PASS contradicts reference {reference.status}"))
            if validator is not None and validator.status not in {"pass", "not-required"}:
                diagnostics.append(Diagnostic("contradiction", f"{outcome.case_id} PASS contradicts validator {validator.status}"))
        if outcome.disposition == "FAIL" and comparator is not None and comparator.status == "pass":
            diagnostics.append(Diagnostic("contradiction", f"{outcome.case_id} FAIL contradicts comparator pass"))
        if outcome.disposition == "REFERENCE_FAILURE":
            if reference is None:
                diagnostics.append(Diagnostic("incomplete-accounting", f"{outcome.case_id} REFERENCE_FAILURE has no reference result"))
            elif reference.status == "pass":
                diagnostics.append(Diagnostic("contradiction", f"{outcome.case_id} REFERENCE_FAILURE contradicts reference pass"))
        if outcome.disposition in {"XFAIL", "SKIP_PREREQUISITE", "UNSUPPORTED", "NOT_RUN"}:
            if candidate is not None and candidate.status == "pass":
                diagnostics.append(
                    Diagnostic(
                        "contradiction",
                        f"{outcome.case_id} {outcome.disposition} contradicts the candidate pass",
                    )
                )
        runtime_status = RUNTIME_EVIDENCE_STATUSES.get(outcome.disposition)
        if runtime_status is not None:
            if candidate is None:
                diagnostics.append(Diagnostic("contradiction", f"{outcome.case_id} {outcome.disposition} lacks candidate runtime evidence"))
            elif candidate.status != runtime_status:
                diagnostics.append(
                    Diagnostic(
                        "contradiction",
                        f"{outcome.case_id} {outcome.disposition} contradicts candidate status {candidate.status}",
                    )
                )

    counts = Counter(outcome.disposition for outcome in by_case.values())
    accounting = Accounting(by_case, counts, len(supplied_selection), diagnostics)
    if not accounting.balanced:
        diagnostics.append(Diagnostic("incomplete-accounting", "selected count does not equal the disposition sum"))
    return accounting
