import json
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field


@dataclass
class GtestReport:
    tests: int
    skipped: int
    failures: int
    diagnostics: list[str] = field(default_factory=list)

    @property
    def zero_execution(self) -> bool:
        return self.tests == 0

    @property
    def all_skipped(self) -> bool:
        return self.tests > 0 and self.skipped >= self.tests


def parse_gtest_report(data: bytes) -> GtestReport:
    stripped = data.strip()
    if stripped.startswith(b"<"):
        return _parse_xml(stripped)
    return _parse_json(stripped)


def _finish(tests: int, skipped: int, failures: int, testcase_skips: list[bool]) -> GtestReport:
    diagnostics: list[str] = []
    effective_skipped = skipped
    if tests > 0 and testcase_skips and all(testcase_skips):
        effective_skipped = tests
    report = GtestReport(tests, effective_skipped, failures, diagnostics)
    if report.zero_execution:
        diagnostics.append("zero-matching-gtests")
    if report.all_skipped:
        diagnostics.append("all-gtests-skipped")
    return report


def _parse_xml(data: bytes) -> GtestReport:
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as error:
        return GtestReport(0, 0, 0, [f"malformed-gtest-report: {error}"])
    if root.tag not in {"testsuites", "testsuite"}:
        return GtestReport(0, 0, 0, ["malformed-gtest-report: root is not testsuites or testsuite"])
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    try:
        tests = sum(int(suite.get("tests", "0")) for suite in suites)
        skipped = sum(int(suite.get("skipped", "0")) for suite in suites)
        failures = sum(int(suite.get("failures", "0")) for suite in suites)
    except ValueError:
        return GtestReport(0, 0, 0, ["malformed-gtest-report: numeric suite counts are invalid"])
    testcase_skips = []
    for testcase in root.findall(".//testcase"):
        testcase_skips.append(testcase.get("status") == "skipped" or testcase.find("skipped") is not None)
    return _finish(tests, skipped, failures, testcase_skips)


def _parse_json(data: bytes) -> GtestReport:
    try:
        document = json.loads(data)
    except json.JSONDecodeError as error:
        return GtestReport(0, 0, 0, [f"malformed-gtest-report: {error.msg}"])
    if not isinstance(document, dict):
        return GtestReport(0, 0, 0, ["malformed-gtest-report: root is not an object"])
    suites = document.get("testsuites")
    if not isinstance(suites, list):
        return GtestReport(0, 0, 0, ["malformed-gtest-report: testsuites is not an array"])
    tests = 0
    skipped = 0
    failures = 0
    testcase_skips = []
    for suite in suites:
        if not isinstance(suite, dict):
            return GtestReport(0, 0, 0, ["malformed-gtest-report: testsuite is not an object"])
        cases = suite.get("testsuite", [])
        if not isinstance(cases, list):
            return GtestReport(0, 0, 0, ["malformed-gtest-report: testcase list is not an array"])
        tests += len(cases)
        for case in cases:
            if isinstance(case, dict) and (case.get("status") == "skipped" or case.get("skipped") is True):
                skipped += 1
                testcase_skips.append(True)
            else:
                testcase_skips.append(False)
            if isinstance(case, dict) and case.get("status") == "failed":
                failures += 1
    return _finish(tests, skipped, failures, testcase_skips)
