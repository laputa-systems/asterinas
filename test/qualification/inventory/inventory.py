# SPDX-License-Identifier: MPL-2.0
"""Compatibility inventory generator (LC-04).

Scans repository sources and regenerates a deterministic inventory of:

* syscall dispatch entries (``kernel/core/src/syscall/arch/*.rs``),
* SCML flag-coverage entries
  (``book/src/kernel/linux-compatibility/syscall-flag-coverage/``),
* stub and partial syscall implementations,
* unsupported-success paths in ``kernel/`` (operations whose effect is
  warned away, ignored, or recorded as not enforced while success is
  still reported),
* conformance blocklists (gVisor, kselftest, xfstests, LTP, pjdfstest),
* ``__asterinas__`` conditional-compilation branches in ``test/``.

Usage:
    python3 inventory.py generate [--repo-root PATH]
    python3 inventory.py check    [--repo-root PATH]
    python3 inventory.py --check  [--repo-root PATH]

``generate`` rewrites ``inventory.json`` and ``inventory.md`` next to this
file. ``check`` regenerates in memory and compares: it exits 1 when the
generated files are missing, empty, stale, or coverage-incomplete, and
exits 0 only when the committed inventory matches a fresh regeneration
and every dispatch entry and blocklisted case carries a status and a
source. Only the Python standard library is used.
"""

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = 1

INVENTORY_DIR_NAME = "test/qualification/inventory"
GENERATED_JSON_NAME = "inventory.json"
GENERATED_MD_NAME = "inventory.md"
ANNOTATIONS_NAME = "annotations.json"


def inventory_dir(repo_root):
    return repo_root / INVENTORY_DIR_NAME

# ---------------------------------------------------------------------------
# Keyword evidence for unsupported-success paths.
#
# A site is recorded when a `warn!`/`ostd::warn!` invocation or a comment in
# kernel source states that input is ignored, unsupported, or not enforced.
# These are heuristic evidence records for review; curated confirmations live
# in annotations.json.
# ---------------------------------------------------------------------------

WARN_KEYWORDS = re.compile(
    r"ignor(e|ed|es|ing)\b|not (yet )?(supported|implemented|enforced)"
    r"|unimplement|accepted but not",
    re.IGNORECASE,
)
TODO_KEYWORDS = re.compile(
    r"enforce|not implemented|unimplemented|not supported", re.IGNORECASE
)
COMMENT_KEYWORDS = re.compile(
    r"(will be|is|are) ignored|accepted but not|not enforced", re.IGNORECASE
)

DISPATCH_ENTRY_RE = re.compile(
    r"^\s*SYS_([A-Z0-9_]+)\s*=\s*(\d+)\s*=>\s*(sys_\w+)\(", re.MULTILINE
)
HANDLER_DEF_RE = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?fn\s+(sys_\w+)", re.MULTILINE
)
SCML_CALL_RE = re.compile(r"^([a-z_][a-z0-9_]*)\s*\(", re.MULTILINE)

SYSCALL_ARCH_DIR = "kernel/core/src/syscall/arch"
SYSCALL_SRC_DIR = "kernel/core/src/syscall"
SCML_DIR = "book/src/kernel/linux-compatibility/syscall-flag-coverage"
CONFORMANCE_DIR = "test/initramfs/src/conformance"

STATUS_VOCAB = ("implemented", "partial", "stub", "unresolvable")


# ---------------------------------------------------------------------------
# Rust source helpers
# ---------------------------------------------------------------------------


def _skip_rust_noise(text, i):
    """Advance past whitespace, comments, and string/char literals."""
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end + 1
        elif text.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
        elif text.startswith('r#"'):
            end = text.find('"#', i + 3)
            i = n if end == -1 else end + 2
        elif text[i] == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
        elif text[i] == "'":
            m = re.match(r"'(\\.|[^\\'])'", text[i:])
            i += m.end() if m else 1
        else:
            return i
    return i


def extract_brace_body(text, open_brace):
    """Return (body, end_index) for the brace block starting at open_brace."""
    depth = 0
    i = open_brace
    start = open_brace + 1
    n = len(text)
    while i < n:
        if text[i] in "/\"'" or text.startswith("r#\"", i):
            j = _skip_rust_noise(text, i)
            if j != i:
                i = j
                continue
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i], i
        i += 1
    return text[start:], n


def resolve_handlers(repo_root):
    """Map every `sys_*` function in the syscall directory to its location
    and body text."""
    handlers = {}
    src_dir = repo_root / SYSCALL_SRC_DIR
    for path in sorted(src_dir.glob("*.rs")):
        text = path.read_text(encoding="utf-8")
        for m in HANDLER_DEF_RE.finditer(text):
            name = m.group(1)
            brace = text.find("{", m.end())
            if brace == -1:
                continue
            body, _ = extract_brace_body(text, brace)
            line = text.count("\n", 0, m.start()) + 1
            body_start_line = text.count("\n", 0, brace) + 1
            handlers.setdefault(
                name,
                {
                    "path": path.relative_to(repo_root).as_posix(),
                    "line": line,
                    "body": body,
                    "body_start_line": body_start_line,
                },
            )
    return handlers


# ---------------------------------------------------------------------------
# Unsupported-success marker scanning
# ---------------------------------------------------------------------------


def scan_markers_in_lines(lines, base_path, base_line=1):
    """Scan physical lines for unsupported-success evidence.

    `lines` is a list of source lines; `base_path` is the repo-relative path
    they came from. Returns a list of evidence records.
    """
    findings = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        macro_text, macro_end = _join_macro(lines, i)
        if (
            re.search(r"(?:ostd::)?warn!", line)
            and WARN_KEYWORDS.search(macro_text)
            and not _warn_precedes_error(lines, macro_end)
        ):
            findings.append(
                {
                    "path": base_path,
                    "line": base_line + i,
                    "kind": "warn",
                    "snippet": _snippet(macro_text),
                }
            )
        elif stripped.startswith("//"):
            comment = stripped.lstrip("/").strip()
            if comment.startswith("TODO") and TODO_KEYWORDS.search(comment):
                findings.append(
                    {
                        "path": base_path,
                        "line": base_line + i,
                        "kind": "todo",
                        "snippet": _snippet(comment),
                    }
                )
            elif COMMENT_KEYWORDS.search(comment):
                findings.append(
                    {
                        "path": base_path,
                        "line": base_line + i,
                        "kind": "comment",
                        "snippet": _snippet(comment),
                    }
                )
        i += 1
    return findings


def _join_macro(lines, i, max_lines=8):
    """Join a possibly multi-line macro invocation into one string.

    Returns (text, index_of_last_line_of_the_invocation)."""
    out = []
    depth = 0
    end = i
    for j in range(i, min(i + max_lines, len(lines))):
        out.append(lines[j].strip())
        depth += lines[j].count("(") - lines[j].count(")")
        end = j
        if depth <= 0 and (";" in lines[j] or ")" in lines[j]):
            break
    return " ".join(out), end


ERROR_ADJACENT_RE = re.compile(r"errno!|Err\(|Errno::")


def _warn_precedes_error(lines, macro_end, look_ahead=3):
    """Heuristic: a warning immediately followed by an error construction
    documents a deliberate error path, not an unsupported success."""
    following = "\n".join(lines[macro_end + 1 : macro_end + 1 + look_ahead])
    return ERROR_ADJACENT_RE.search(following) is not None


def _snippet(text, limit=120):
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def scan_kernel_tree(repo_root):
    """Scan kernel/ for unsupported-success evidence."""
    findings = []
    kernel_dir = repo_root / "kernel"
    if kernel_dir.is_dir():
        for path in sorted(kernel_dir.rglob("*.rs")):
            rel = path.relative_to(repo_root).as_posix()
            lines = path.read_text(encoding="utf-8").splitlines()
            findings.extend(scan_markers_in_lines(lines, rel))
    return findings


# ---------------------------------------------------------------------------
# Dispatch tables and SCML
# ---------------------------------------------------------------------------


def extract_dispatch(repo_root, handlers):
    """Parse every arch dispatch table and classify each syscall."""
    arch_dir = repo_root / SYSCALL_ARCH_DIR
    tables = {}
    if arch_dir.is_dir():
        for path in sorted(arch_dir.glob("*.rs")):
            table = path.stem
            text = path.read_text(encoding="utf-8")
            rel = path.relative_to(repo_root).as_posix()
            for m in DISPATCH_ENTRY_RE.finditer(text):
                name = m.group(1).lower()
                line = text.count("\n", 0, m.start()) + 1
                tables.setdefault(name, []).append(
                    {
                        "table": table,
                        "number": int(m.group(2)),
                        "handler": m.group(3),
                        "source": f"{rel}:{line}",
                    }
                )

    scml = extract_scml(repo_root)
    annotations = load_annotations(repo_root).get("syscalls", {})

    syscalls = []
    for name in sorted(tables):
        entries = sorted(tables[name], key=lambda e: (e["table"], e["number"]))
        handler_name = entries[0]["handler"]
        handler = handlers.get(handler_name)
        record = {
            "name": name,
            "entries": entries,
            "handler": handler_name,
            "scml": scml.get(
                name, {"coverage": "absent", "source": None}
            ),
        }
        if handler is None:
            record["status"] = "unresolvable"
            record["source"] = entries[0]["source"]
            record["evidence"] = []
        else:
            body_lines = handler["body"].splitlines()
            sites = scan_markers_in_lines(
                body_lines, handler["path"], handler["body_start_line"]
            )
            record["handler_source"] = f"{handler['path']}:{handler['line']}"
            record["evidence"] = [
                f"{s['path']}:{s['line']}" for s in sites
            ]
            body = handler["body"]
            has_enosys_only = (
                re.search(r"ENOSYS", body) is not None
                and "Ok(SyscallReturn" not in body
            )
            annotation = annotations.get(name)
            if annotation:
                record["status"] = annotation["status"]
                record["status_reason"] = annotation["reason"]
                record["status_origin"] = "annotations.json"
            elif has_enosys_only:
                record["status"] = "stub"
                record["status_reason"] = (
                    "handler returns ENOSYS on every path"
                )
                record["status_origin"] = "mechanical"
            elif sites:
                record["status"] = "partial"
                record["status_reason"] = (
                    "handler warns that input is ignored, unsupported, or"
                    " not enforced while still returning success on some path"
                )
                record["status_origin"] = "mechanical"
            else:
                record["status"] = "implemented"
                record["status_reason"] = (
                    "handler resolves and carries no unsupported-success"
                    " evidence"
                )
                record["status_origin"] = "mechanical"
            record["source"] = record["handler_source"]
        syscalls.append(record)
    return syscalls


def extract_scml(repo_root):
    """Map syscall names to their SCML coverage."""
    coverage = {}
    scml_root = repo_root / SCML_DIR
    if not scml_root.is_dir():
        return coverage
    for path in sorted(scml_root.rglob("*.scml")):
        rel = path.relative_to(repo_root).as_posix()
        kind = "full" if path.name == "fully_covered.scml" else "constrained"
        text_lines = []
        for line in path.read_text(encoding="utf-8").splitlines():
            text_lines.append(line.split("//", 1)[0])
        text = "\n".join(text_lines)
        for m in SCML_CALL_RE.finditer(text):
            name = m.group(1)
            line_no = text.count("\n", 0, m.start()) + 1
            existing = coverage.get(name)
            entry = {"coverage": kind, "source": f"{rel}:{line_no}"}
            if existing is None or (
                existing["coverage"] != "full" and kind == "full"
            ):
                coverage[name] = entry
    return coverage


# ---------------------------------------------------------------------------
# Conformance blocklists
# ---------------------------------------------------------------------------


def _preceding_reason(lines, idx):
    """Collect the contiguous comment block directly above line idx."""
    reason = []
    j = idx - 1
    while j >= 0 and lines[j].strip().startswith("#"):
        text = lines[j].strip().lstrip("#").strip()
        if text and not re.match(r"^-+\s*.+\s*-+$", text):
            reason.append(text)
        j -= 1
    reason.reverse()
    return " ".join(reason) or None


def _simple_blocklist(repo_root, path, system, suite):
    """Parse a line-per-case blocklist file with `#` comments."""
    entries = []
    lines = path.read_text(encoding="utf-8").splitlines()
    rel = path.relative_to(repo_root).as_posix()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.append(
            {
                "system": system,
                "suite": suite,
                "case": stripped,
                "status": "blocked",
                "reason": _preceding_reason(lines, idx),
                "source": f"{rel}:{idx + 1}",
            }
        )
    return entries


def extract_blocklists(repo_root):
    entries = []
    conf = repo_root / CONFORMANCE_DIR

    gvisor = conf / "gvisor"
    for listdir in sorted(gvisor.glob("blocklists*")) if gvisor.is_dir() else []:
        if not listdir.is_dir():
            continue
        for suite_file in sorted(listdir.iterdir()):
            if suite_file.is_file():
                entries.extend(
                    _simple_blocklist(
                        repo_root, suite_file, "gvisor", suite_file.name
                    )
                )

    kselftest = conf / "kselftest"
    for listfile in sorted(kselftest.glob("blocklists*")) if kselftest.is_dir() else []:
        if listfile.is_file():
            entries.extend(
                _simple_blocklist(
                    repo_root, listfile, "kselftest", listfile.name
                )
            )

    xfstests = conf / "xfstests"
    if xfstests.is_dir():
        for fsdir in sorted(xfstests.iterdir()):
            block = fsdir / "run_list" / "block.list"
            if block.is_file():
                entries.extend(
                    _simple_blocklist(repo_root, block, "xfstests", fsdir.name)
                )

    entries.extend(_extract_ltp(repo_root, conf))
    entries.extend(_extract_pjdfstest(repo_root, conf))
    entries.sort(key=lambda e: (e["system"], e["suite"], e["case"], e["source"]))
    return entries


def _extract_ltp(repo_root, conf):
    """LTP `testcases/all.txt`: a commented-out single lowercase token is a
    blocked case."""
    entries = []
    alltxt = conf / "ltp" / "testcases" / "all.txt"
    if not alltxt.is_file():
        return entries
    rel = alltxt.relative_to(repo_root).as_posix()
    for idx, line in enumerate(alltxt.read_text(encoding="utf-8").splitlines()):
        m = re.match(r"^# ([a-z0-9_]+)\s*$", line)
        if m:
            entries.append(
                {
                    "system": "ltp",
                    "suite": "all.txt",
                    "case": m.group(1),
                    "status": "blocked",
                    "reason": None,
                    "source": f"{rel}:{idx + 1}",
                }
            )
    return entries


def _extract_pjdfstest(repo_root, conf):
    """pjdfstest runlists: `# <category>/<nn>.t: reason` is a suppressed
    case."""
    entries = []
    runlists = conf / "pjdfstest" / "runlists"
    if not runlists.is_dir():
        return entries
    for path in sorted(runlists.glob("*.list")):
        rel = path.relative_to(repo_root).as_posix()
        suite = path.name
        for idx, line in enumerate(
            path.read_text(encoding="utf-8").splitlines()
        ):
            m = re.match(r"^#\s*([\w-]+/\d+\.t):?\s*(.*)$", line)
            if m:
                entries.append(
                    {
                        "system": "pjdfstest",
                        "suite": suite,
                        "case": m.group(1),
                        "status": "blocked",
                        "reason": m.group(2).strip() or None,
                        "source": f"{rel}:{idx + 1}",
                    }
                )
    return entries


# ---------------------------------------------------------------------------
# __asterinas__ branches
# ---------------------------------------------------------------------------

BRANCH_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif)\b.*__asterinas__")
DEFINE_RE = re.compile(r"-D\s*__asterinas__|/D\s*__asterinas__")
SCAN_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".rs", ".sh", ".py", ".mk"}


def extract_asterinas_branches(repo_root):
    records = []
    test_root = repo_root / "test"
    if not test_root.is_dir():
        return records
    paths = []
    own_dir = (test_root / "qualification/inventory").resolve()
    for path in sorted(test_root.rglob("*")):
        if not path.is_file():
            continue
        if own_dir in path.resolve().parents or path.resolve() == own_dir:
            continue
        if path.suffix in SCAN_SUFFIXES or path.name.startswith("Makefile"):
            paths.append(path)
    for path in paths:
        rel = path.relative_to(repo_root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, ValueError):
            continue
        for idx, line in enumerate(lines):
            m = BRANCH_RE.match(line)
            if m:
                directive = m.group(1)
                negative = directive == "ifndef" or re.search(
                    r"!\s*defined", line
                )
                records.append(
                    {
                        "path": rel,
                        "line": idx + 1,
                        "kind": "branch",
                        "directive": directive,
                        "polarity": "negative" if negative else "positive",
                        "source": f"{rel}:{idx + 1}",
                    }
                )
            elif DEFINE_RE.search(line):
                records.append(
                    {
                        "path": rel,
                        "line": idx + 1,
                        "kind": "definition",
                        "directive": None,
                        "polarity": None,
                        "source": f"{rel}:{idx + 1}",
                    }
                )
    records.sort(key=lambda r: (r["path"], r["line"]))
    return records


# ---------------------------------------------------------------------------
# Annotations
# ---------------------------------------------------------------------------


def load_annotations(repo_root):
    path = inventory_dir(repo_root) / ANNOTATIONS_NAME
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_path_annotations(repo_root, annotation_list, findings):
    """Resolve curated unsupported-success annotations to concrete lines.

    Each annotation carries a `path` and a `match` substring; the first line
    containing the substring anchors the record. Returns (records, problems).
    """
    records = []
    problems = []
    for ann in annotation_list:
        path = repo_root / ann["path"]
        if not path.is_file():
            problems.append(
                f"annotations.json: {ann['path']} does not exist"
            )
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        hit = None
        for idx, line in enumerate(lines):
            if ann["match"] in line:
                hit = idx + 1
                break
        if hit is None:
            problems.append(
                f"annotations.json: {ann['path']} no longer contains"
                f" {ann['match']!r}"
            )
            continue
        records.append(
            {
                "path": ann["path"],
                "line": hit,
                "kind": "annotation",
                "snippet": ann["reason"],
                "source": f"{ann['path']}:{hit}",
            }
        )
    return records, problems


# ---------------------------------------------------------------------------
# Inventory assembly
# ---------------------------------------------------------------------------


def build_inventory(repo_root):
    """Scan the repository and return (inventory_dict, problems)."""
    handlers = resolve_handlers(repo_root)
    syscalls = extract_dispatch(repo_root, handlers)

    kernel_findings = scan_kernel_tree(repo_root)
    annotations = load_annotations(repo_root)
    annotated, problems = resolve_path_annotations(
        repo_root, annotations.get("unsupported_success_paths", []), kernel_findings
    )
    merged = {}
    for f in kernel_findings:
        merged[(f["path"], f["line"], f["kind"])] = {
            **f,
            "source": f"{f['path']}:{f['line']}",
        }
    for a in annotated:
        merged[(a["path"], a["line"], a["kind"])] = a
    unsupported = sorted(merged.values(), key=lambda f: (f["path"], f["line"]))

    inventory = {
        "schema": SCHEMA,
        "syscalls": syscalls,
        "unsupported_success_paths": unsupported,
        "conformance_blocklists": extract_blocklists(repo_root),
        "asterinas_branches": extract_asterinas_branches(repo_root),
    }
    return inventory, problems


def coverage_problems(inventory):
    """Every dispatch entry and blocklisted case needs a status and a
    source; unresolvable handlers are coverage failures."""
    problems = []
    for sc in inventory["syscalls"]:
        if sc.get("status") not in STATUS_VOCAB:
            problems.append(f"syscall {sc['name']}: missing or invalid status")
        if not sc.get("source"):
            problems.append(f"syscall {sc['name']}: missing source")
        if sc.get("status") == "unresolvable":
            problems.append(
                f"syscall {sc['name']}: handler {sc['handler']} not found"
                f" in {SYSCALL_SRC_DIR}"
            )
        if sc.get("status") not in (None, "unresolvable") and not sc.get(
            "handler_source"
        ):
            problems.append(f"syscall {sc['name']}: missing handler source")
    for entry in inventory["conformance_blocklists"]:
        if not entry.get("status") or not entry.get("source"):
            problems.append(
                f"blocklist entry {entry.get('case')}: missing status or source"
            )
    return problems


def render_json(inventory):
    return json.dumps(inventory, indent=1, sort_keys=True) + "\n"


def render_markdown(inventory):
    syscalls = inventory["syscalls"]
    by_status = {}
    for sc in syscalls:
        by_status.setdefault(sc["status"], []).append(sc["name"])
    scml_counts = {"full": 0, "constrained": 0, "absent": 0}
    for sc in syscalls:
        scml_counts[sc["scml"]["coverage"]] += 1

    lines = [
        "# Compatibility inventory (generated)",
        "",
        "Regenerate with `python3 test/qualification/inventory/inventory.py generate`.",
        "Verify with `python3 test/qualification/inventory/inventory.py check`.",
        "",
        "## Syscall dispatch entries",
        "",
        f"- dispatched syscalls: {len(syscalls)}",
    ]
    for status in STATUS_VOCAB:
        names = by_status.get(status, [])
        lines.append(f"- {status}: {len(names)}")
    lines += [
        "",
        "### SCML coverage",
        "",
        f"- fully covered: {scml_counts['full']}",
        f"- constrained: {scml_counts['constrained']}",
        f"- undocumented: {scml_counts['absent']}",
        "",
    ]
    for status in ("stub", "partial", "unresolvable"):
        names = by_status.get(status, [])
        if names:
            lines.append(f"### {status.capitalize()} syscalls")
            lines.append("")
            for name in names:
                sc = next(s for s in syscalls if s["name"] == name)
                lines.append(f"- `{name}` — {sc['source']}")
            lines.append("")

    lines += [
        "## Unsupported-success paths",
        "",
        f"- recorded sites: {len(inventory['unsupported_success_paths'])}",
        "",
    ]
    for f in inventory["unsupported_success_paths"]:
        lines.append(f"- `{f['source']}` ({f['kind']}): {f['snippet']}")
    lines.append("")

    lines += ["## Conformance blocklists", ""]
    systems = {}
    for e in inventory["conformance_blocklists"]:
        systems.setdefault(e["system"], []).append(e)
    for system in sorted(systems):
        entries = systems[system]
        undocumented = sum(1 for e in entries if not e.get("reason"))
        lines.append(
            f"- {system}: {len(entries)} blocked cases"
            f" ({undocumented} without a recorded reason)"
        )
    lines.append("")

    lines += ["## `__asterinas__` branches", ""]
    branches = [r for r in inventory["asterinas_branches"] if r["kind"] == "branch"]
    definitions = [
        r for r in inventory["asterinas_branches"] if r["kind"] == "definition"
    ]
    lines.append(f"- conditional branches: {len(branches)}")
    lines.append(f"- compile-flag definitions: {len(definitions)}")
    lines.append("")
    for r in inventory["asterinas_branches"]:
        if r["kind"] == "branch":
            lines.append(
                f"- `{r['source']}` #{r['directive']} ({r['polarity']})"
            )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def write_outputs(repo_root, inventory):
    out = inventory_dir(repo_root)
    out.mkdir(parents=True, exist_ok=True)
    (out / GENERATED_JSON_NAME).write_text(render_json(inventory), encoding="utf-8")
    (out / GENERATED_MD_NAME).write_text(render_markdown(inventory), encoding="utf-8")


def cmd_generate(repo_root):
    inventory, problems = build_inventory(repo_root)
    write_outputs(repo_root, inventory)
    cov = coverage_problems(inventory)
    for p in problems + cov:
        print(f"warning: {p}", file=sys.stderr)
    print(f"inventory regenerated: {inventory_dir(repo_root) / GENERATED_JSON_NAME}")
    print(
        "syscalls: {syscalls}, unsupported-success sites: {usp}, "
        "blocklisted cases: {bl}, __asterinas__ records: {br}".format(
            syscalls=len(inventory["syscalls"]),
            usp=len(inventory["unsupported_success_paths"]),
            bl=len(inventory["conformance_blocklists"]),
            br=len(inventory["asterinas_branches"]),
        )
    )
    return 0


def cmd_check(repo_root):
    out = inventory_dir(repo_root)
    json_path = out / GENERATED_JSON_NAME
    md_path = out / GENERATED_MD_NAME
    if not json_path.is_file():
        print(f"check failed: {json_path} is missing; run generate",
              file=sys.stderr)
        return 1
    if json_path.stat().st_size == 0:
        print(f"check failed: {json_path} is empty; run generate",
              file=sys.stderr)
        return 1

    inventory, problems = build_inventory(repo_root)
    stale = []
    if json_path.read_text(encoding="utf-8") != render_json(inventory):
        stale.append(str(json_path))
    if not md_path.is_file() or md_path.read_text(
        encoding="utf-8"
    ) != render_markdown(inventory):
        stale.append(str(md_path))

    cov = coverage_problems(inventory)
    if problems or cov or stale:
        for path in stale:
            print(f"check failed: {path} is stale; run generate", file=sys.stderr)
        for p in problems:
            print(f"check failed: {p}", file=sys.stderr)
        for p in cov:
            print(f"check failed: coverage: {p}", file=sys.stderr)
        return 1
    print("inventory check passed")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="inventory.py",
        description="Regenerate or verify the compatibility inventory (LC-04).",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default=None,
        choices=["generate", "check"],
        help="generate rewrites the inventory; check verifies it",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="equivalent to the check subcommand",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[3],
        help="repository root to scan (default: three levels above this file)",
    )
    args = parser.parse_args(argv)

    command = args.command
    if args.check:
        if command and command != "check":
            parser.error("conflicting command and --check")
        command = "check"
    if command is None:
        parser.error("a command is required: generate or check")

    repo_root = args.repo_root.resolve()
    if command == "generate":
        return cmd_generate(repo_root)
    return cmd_check(repo_root)


if __name__ == "__main__":
    sys.exit(main())
