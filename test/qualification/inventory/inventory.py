# SPDX-License-Identifier: MPL-2.0
"""Compatibility inventory generator (LC-04).

Scans repository sources and regenerates a deterministic inventory of:

* syscall dispatch rows — every literal ``SYS_* = N => sys_*(...)`` row in
  ``kernel/core/src/syscall/arch/*.rs``, each with its own status, source,
  and evidence, plus detection of divergent handlers grouped under one
  syscall name;
* SCML rules — every invocation row in
  ``book/src/kernel/linux-compatibility/syscall-flag-coverage/**/*.scml``
  as its own entry-by-entry collection, cross-referenced to dispatch rows
  through an explicit, machine-readable alias policy;
* stub and partial syscall implementations;
* unsupported-success paths in ``kernel/`` (operations whose effect is
  warned away, ignored, or recorded as not enforced while success is
  still reported);
* conformance blocklists (gVisor, kselftest, xfstests, LTP — including
  ``testcases/blocked/*.txt`` — and pjdfstest), with inline and
  preceding-block comments extracted as reasons;
* ``__asterinas__`` conditional-compilation branches in ``test/``.

Status semantics are shallow by design and say so in the generated
metadata: ``implemented`` means only that the handler resolves and the
heuristic scan found no unsupported-success evidence in its implementation
file. It is not a Linux-compatibility claim. Unsupported-success warnings
anywhere in a syscall implementation file are associated with every
handler defined in that file, because helpers such as conversion impls
carry warnings for the syscalls that funnel into them; each evidence site
records whether it sits inside the handler body proper (``handler``) or
elsewhere in the file (``file``). Curated confirmations and overrides live
in ``annotations.json``; heuristic scan output is never promoted to
curated truth automatically.

Usage:
    python3 inventory.py generate [--repo-root PATH]
    python3 inventory.py check    [--repo-root PATH]
    python3 inventory.py --check  [--repo-root PATH]

``generate`` rewrites ``inventory.json`` and ``inventory.md`` in
``<repo-root>/test/qualification/inventory/``. It fails closed: a missing
scan root or an implausibly empty dispatch, blocklist, SCML, or branch
section is a structural error — generation exits nonzero and writes
nothing, so a non-repository path can never yield a valid empty
inventory. ``check`` regenerates in memory and compares: it exits 1 when
the generated files are missing, empty, stale, structurally invalid, or
coverage-incomplete, and exits 0 only when the committed inventory
matches a fresh regeneration and every dispatch row and blocklisted case
carries a status and a source. Only the Python standard library is used.
"""

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = 2

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
# kernel source states that input is ignored, unsupported, or accepted
# without effect. These are heuristic evidence records for review; curated
# confirmations live in annotations.json.
# ---------------------------------------------------------------------------

WARN_KEYWORDS = re.compile(
    r"ignor(e|ed|es|ing)\b|not (yet )?(supported|implemented|enforced)"
    r"|unimplement|accepted,? but",
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
TEST_DIR = "test"

REQUIRED_ROOTS = (
    SYSCALL_ARCH_DIR,
    SYSCALL_SRC_DIR,
    SCML_DIR,
    CONFORMANCE_DIR,
    TEST_DIR,
)

STATUS_VOCAB = ("implemented", "partial", "stub", "unresolvable")

# Worst-first ordering used to aggregate row statuses into a grouped
# syscall status.
STATUS_SEVERITY = {"unresolvable": 3, "stub": 2, "partial": 1, "implemented": 0}

STATUS_SEMANTICS = {
    "implemented": (
        "the handler resolves and the heuristic scan found no"
        " unsupported-success evidence in its implementation file; this is"
        " shallow handler-resolution evidence, not a Linux-compatibility"
        " claim"
    ),
    "partial": (
        "the implementation file carries unsupported-success evidence"
        " (input warned away, ignored, or accepted without effect) on"
        " some path while the syscall still reports success"
    ),
    "stub": (
        "the handler performs none of the requested effect: it returns"
        " ENOSYS on every path, or a reviewed annotation pin states that"
        " success is always reported without effect"
    ),
    "unresolvable": (
        "the dispatch row references a handler that is not defined in"
        " the syscall source directory; always a coverage failure"
    ),
}

ALIAS_POLICY_DESCRIPTION = (
    "SCML documents user-facing Linux syscall names while dispatch rows"
    " use the kernel's SYS_* constant spelling. Names in one alias group"
    " denote the same syscall ABI (e.g. sendfile/sendfile64,"
    " getpriority/get_priority, fstat/newfstat, newfstatat/fstatat)."
    " SCML coverage lookup tries the exact dispatch name first, then every"
    " other member of its alias group. The groups are reviewed pins in"
    " annotations.json, echoed into the generated metadata; a name with"
    " no exact or alias coverage is reported as absent, never silently"
    " treated as covered."
)

EVIDENCE_ASSOCIATION_DESCRIPTION = (
    "unsupported-success warnings anywhere in a syscall implementation"
    " file are associated with every handler defined in that file,"
    " because warnings frequently live in shared helpers and conversion"
    " impls (e.g. clone3 argument conversion in clone.rs) rather than in"
    " the handler body proper; each evidence site carries a scope field"
    " distinguishing handler-body evidence from file-level evidence"
)


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
        if text[i] in "/\"'" or text.startswith('r#"', i):
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
    and body, and scan each implementation file as a whole for
    unsupported-success evidence.

    Returns (handlers, file_evidence):
      handlers: name -> {path, line, body, body_start_line, body_end_line}
      file_evidence: path -> [evidence records with scope unset]
    """
    handlers = {}
    file_evidence = {}
    src_dir = repo_root / SYSCALL_SRC_DIR
    if not src_dir.is_dir():
        return handlers, file_evidence
    for path in sorted(src_dir.glob("*.rs")):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(repo_root).as_posix()
        lines = text.splitlines()
        file_evidence[rel] = scan_markers_in_lines(lines, rel)
        for m in HANDLER_DEF_RE.finditer(text):
            name = m.group(1)
            brace = text.find("{", m.end())
            if brace == -1:
                continue
            body, end = extract_brace_body(text, brace)
            line = text.count("\n", 0, m.start()) + 1
            body_start_line = text.count("\n", 0, brace) + 1
            body_end_line = text.count("\n", 0, end) + 1
            handlers.setdefault(
                name,
                {
                    "path": rel,
                    "line": line,
                    "body": body,
                    "body_start_line": body_start_line,
                    "body_end_line": body_end_line,
                },
            )
    return handlers, file_evidence


# ---------------------------------------------------------------------------
# Unsupported-success marker scanning
# ---------------------------------------------------------------------------


def scan_markers_in_lines(lines, base_path, base_line=1):
    """Scan physical lines for unsupported-success evidence.

    `lines` is a list of source lines; `base_path` is the repo-relative
    path they came from. Returns a list of evidence records.
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
# Annotations
# ---------------------------------------------------------------------------


def load_annotations(repo_root):
    path = inventory_dir(repo_root) / ANNOTATIONS_NAME
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def alias_groups(repo_root):
    """Reviewed alias groups from annotations.json: lists of names denoting
    the same syscall ABI under different spellings."""
    return load_annotations(repo_root).get("aliases", [])


def alias_index(groups):
    """Map every aliased name to the full set of names in its group."""
    index = {}
    for group in groups:
        for name in group:
            index.setdefault(name, set()).update(group)
    return {name: sorted(mates) for name, mates in index.items()}


def resolve_path_annotations(repo_root, annotation_list):
    """Resolve curated unsupported-success annotations to concrete lines.

    Each annotation carries a `path` and a `match` substring; the first
    line containing the substring anchors the record. Returns (records,
    problems)."""
    records = []
    problems = []
    for ann in annotation_list:
        path = repo_root / ann["path"]
        if not path.is_file():
            problems.append(f"annotations.json: {ann['path']} does not exist")
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
# SCML
# ---------------------------------------------------------------------------


def extract_scml_rules(repo_root):
    """Every invocation row of every .scml file, including repeated rules.

    Returns a list of rows: {name, coverage, file, source}."""
    rows = []
    scml_root = repo_root / SCML_DIR
    if not scml_root.is_dir():
        return rows
    for path in sorted(scml_root.rglob("*.scml")):
        rel = path.relative_to(repo_root).as_posix()
        kind = "full" if path.name == "fully_covered.scml" else "constrained"
        stripped_lines = [
            line.split("//", 1)[0]
            for line in path.read_text(encoding="utf-8").splitlines()
        ]
        text = "\n".join(stripped_lines)
        for m in SCML_CALL_RE.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            rows.append(
                {
                    "name": m.group(1),
                    "coverage": kind,
                    "file": rel,
                    "source": f"{rel}:{line_no}",
                }
            )
    rows.sort(key=lambda r: (r["name"], r["file"], r["source"]))
    return rows


def scml_coverage_lookup(rules, aliases):
    """Build name -> best coverage record, then answer coverage for a
    dispatch name through the alias policy.

    Returns (by_name, lookup) where lookup(name) -> dict with coverage,
    source, and matched scml name."""
    rank = {"full": 2, "constrained": 1}
    by_name = {}
    for row in rules:
        existing = by_name.get(row["name"])
        if existing is None or rank[row["coverage"]] > rank[existing["coverage"]]:
            by_name[row["name"]] = row

    def lookup(dispatch_name):
        candidates = [dispatch_name]
        for mate in aliases.get(dispatch_name, []):
            if mate not in candidates:
                candidates.append(mate)
        for candidate in candidates:
            row = by_name.get(candidate)
            if row is not None:
                return {
                    "coverage": row["coverage"],
                    "source": row["source"],
                    "scml_name": row["name"],
                    "via_alias": candidate != dispatch_name,
                }
        return {
            "coverage": "absent",
            "source": None,
            "scml_name": None,
            "via_alias": False,
        }

    return by_name, lookup


# ---------------------------------------------------------------------------
# Dispatch rows
# ---------------------------------------------------------------------------


def parse_dispatch_rows(repo_root):
    """Every literal `SYS_* = N => sys_*(...)` row of every arch table."""
    rows = []
    arch_dir = repo_root / SYSCALL_ARCH_DIR
    if not arch_dir.is_dir():
        return rows
    for path in sorted(arch_dir.glob("*.rs")):
        table = path.stem
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(repo_root).as_posix()
        for m in DISPATCH_ENTRY_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            rows.append(
                {
                    "table": table,
                    "syscall": m.group(1).lower(),
                    "number": int(m.group(2)),
                    "handler": m.group(3),
                    "source": f"{rel}:{line}",
                }
            )
    rows.sort(key=lambda r: (r["syscall"], r["table"], r["number"]))
    return rows


def classify_row(row, handlers, file_evidence, annotations, scml_lookup):
    """Attach status, evidence, and SCML coverage to one dispatch row."""
    row = dict(row)
    handler = handlers.get(row["handler"])
    row["scml"] = scml_lookup(row["syscall"])
    if handler is None:
        row["status"] = "unresolvable"
        row["status_reason"] = (
            f"handler {row['handler']} is not defined in {SYSCALL_SRC_DIR}"
        )
        row["status_origin"] = "mechanical"
        row["handler_source"] = None
        row["evidence"] = []
        return row

    row["handler_source"] = f"{handler['path']}:{handler['line']}"
    evidence = []
    for site in file_evidence.get(handler["path"], []):
        scope = (
            "handler"
            if handler["body_start_line"] <= site["line"] <= handler["body_end_line"]
            else "file"
        )
        evidence.append({**site, "scope": scope})
    row["evidence"] = evidence
    # Classification rests on warn-kind evidence only. Comment and TODO
    # sites are heuristic candidates: they stay visible in the evidence
    # list and in the tree-wide unsupported-success inventory, but they
    # never decide a syscall's status.
    warn_evidence = [e for e in evidence if e["kind"] == "warn"]

    body = handler["body"]
    has_enosys_only = (
        re.search(r"ENOSYS", body) is not None
        and "Ok(SyscallReturn" not in body
    )
    annotation = annotations.get(row["syscall"])
    if annotation:
        row["status"] = annotation["status"]
        row["status_reason"] = annotation["reason"]
        row["status_origin"] = "annotations.json"
    elif has_enosys_only:
        row["status"] = "stub"
        row["status_reason"] = "handler returns ENOSYS on every path"
        row["status_origin"] = "mechanical"
    elif warn_evidence:
        row["status"] = "partial"
        row["status_reason"] = (
            "implementation file warns that input is ignored, unsupported,"
            " or accepted without effect while success is still reported"
            " on some path"
        )
        row["status_origin"] = "mechanical"
    else:
        row["status"] = "implemented"
        row["status_reason"] = (
            "handler resolves and heuristic scan found no"
            " unsupported-success evidence in its implementation file"
        )
        row["status_origin"] = "mechanical"
    return row


def extract_dispatch(repo_root, handlers, file_evidence, annotations, scml_lookup):
    """Classify every literal dispatch row and group rows by syscall name.

    Returns (rows, groups)."""
    base_rows = parse_dispatch_rows(repo_root)
    syscall_annotations = annotations.get("syscalls", {})
    rows = [
        classify_row(row, handlers, file_evidence, syscall_annotations, scml_lookup)
        for row in base_rows
    ]

    groups = []
    by_name = {}
    for row in rows:
        by_name.setdefault(row["syscall"], []).append(row)
    for name in sorted(by_name):
        members = by_name[name]
        handler_set = sorted({m["handler"] for m in members})
        divergent = len(handler_set) > 1
        for m in members:
            m["divergent_handlers"] = divergent
        worst = max(members, key=lambda m: STATUS_SEVERITY[m["status"]])
        best_scml = max(
            members,
            key=lambda m: {"absent": 0, "constrained": 1, "full": 2}[
                m["scml"]["coverage"]
            ],
        )
        groups.append(
            {
                "name": name,
                "entries": [
                    {
                        "table": m["table"],
                        "number": m["number"],
                        "handler": m["handler"],
                        "source": m["source"],
                        "status": m["status"],
                    }
                    for m in members
                ],
                "divergent_handlers": divergent,
                "handlers": handler_set,
                "status": worst["status"],
                "status_reason": worst["status_reason"],
                "status_origin": worst["status_origin"],
                "source": worst["handler_source"] or worst["source"],
                "handler_source": worst["handler_source"],
                "scml": best_scml["scml"],
            }
        )
    return rows, groups


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


INLINE_REASON_RE = re.compile(r"^(\S+)\s+#\s*(.+)$")


def _simple_blocklist(repo_root, path, system, suite):
    """Parse a line-per-case blocklist file.

    Reasons come from an inline ` # comment` suffix when present, else
    from the contiguous comment block directly above the entry."""
    entries = []
    lines = path.read_text(encoding="utf-8").splitlines()
    rel = path.relative_to(repo_root).as_posix()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        inline = INLINE_REASON_RE.match(stripped)
        if inline:
            case, reason = inline.group(1), inline.group(2).strip()
        else:
            case, reason = stripped, _preceding_reason(lines, idx)
        entries.append(
            {
                "system": system,
                "suite": suite,
                "case": case,
                "status": "blocked",
                "reason": reason or None,
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
                _simple_blocklist(repo_root, listfile, "kselftest", listfile.name)
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
    """LTP blocklists.

    `testcases/all.txt`: a commented-out single lowercase token is a case
    disabled for every lane. `testcases/blocked/*.txt`: bare test names,
    one per line, are blocked for the lane named by the file; comment
    lines are reasons or section notes."""
    entries = []
    alltxt = conf / "ltp" / "testcases" / "all.txt"
    if alltxt.is_file():
        rel = alltxt.relative_to(repo_root).as_posix()
        for idx, line in enumerate(
            alltxt.read_text(encoding="utf-8").splitlines()
        ):
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

    blocked_dir = conf / "ltp" / "testcases" / "blocked"
    if blocked_dir.is_dir():
        for path in sorted(blocked_dir.glob("*.txt")):
            entries.extend(
                _simple_blocklist(repo_root, path, "ltp", f"blocked/{path.name}")
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
# Inventory assembly
# ---------------------------------------------------------------------------


def build_inventory(repo_root):
    """Scan the repository and return (inventory_dict, problems).

    `problems` holds structural failures: missing scan roots, implausibly
    empty sections, and stale annotations. Any structural problem makes
    the inventory invalid."""
    problems = []
    for root in REQUIRED_ROOTS:
        if not (repo_root / root).is_dir():
            problems.append(f"required scan root missing: {root}")

    handlers, file_evidence = resolve_handlers(repo_root)
    annotations = load_annotations(repo_root)
    aliases = alias_index(alias_groups(repo_root))

    rules = extract_scml_rules(repo_root)
    scml_by_name, scml_lookup = scml_coverage_lookup(rules, aliases)

    rows, groups = extract_dispatch(
        repo_root, handlers, file_evidence, annotations, scml_lookup
    )

    # SCML as its own entry-by-entry collection, cross-referenced to
    # dispatch through the same alias policy.
    dispatch_names = {row["syscall"] for row in rows}
    scml_rules = []
    for rule in rules:
        candidates = [rule["name"], *aliases.get(rule["name"], [])]
        matched = sorted(
            name for name in set(candidates) if name in dispatch_names
        )
        scml_rules.append(
            {
                **rule,
                "dispatched": bool(matched),
                "dispatch_names": matched,
                "via_alias": bool(matched) and rule["name"] not in dispatch_names,
            }
        )

    kernel_findings = scan_kernel_tree(repo_root)
    annotated, ann_problems = resolve_path_annotations(
        repo_root, annotations.get("unsupported_success_paths", [])
    )
    problems.extend(ann_problems)
    merged = {}
    for f in kernel_findings:
        merged[(f["path"], f["line"], f["kind"])] = {
            **f,
            "source": f"{f['path']}:{f['line']}",
        }
    for a in annotated:
        merged[(a["path"], a["line"], a["kind"])] = a
    unsupported = sorted(merged.values(), key=lambda f: (f["path"], f["line"]))

    blocklists = extract_blocklists(repo_root)
    branches = extract_asterinas_branches(repo_root)

    if not rows:
        problems.append("no dispatch rows found; scan root is not a kernel tree")
    if not rules:
        problems.append("no SCML rules found; scan root is not a book tree")
    if not blocklists:
        problems.append("no conformance blocklisted cases found")
    if not branches:
        problems.append("no __asterinas__ branches found")

    inventory = {
        "schema": SCHEMA,
        "metadata": {
            "generator": "test/qualification/inventory/inventory.py",
            "status_semantics": STATUS_SEMANTICS,
            "status_vocabulary": list(STATUS_VOCAB),
            "evidence_association": EVIDENCE_ASSOCIATION_DESCRIPTION,
            "alias_policy": {
                "description": ALIAS_POLICY_DESCRIPTION,
                "groups": alias_groups(repo_root),
            },
            "scan_roots": list(REQUIRED_ROOTS),
            "blocklist_inputs": [
                "test/initramfs/src/conformance/gvisor/blocklists*/<suite>",
                "test/initramfs/src/conformance/kselftest/blocklists*",
                "test/initramfs/src/conformance/xfstests/<fs>/run_list/block.list",
                "test/initramfs/src/conformance/ltp/testcases/all.txt",
                "test/initramfs/src/conformance/ltp/testcases/blocked/*.txt",
                "test/initramfs/src/conformance/pjdfstest/runlists/*.list",
            ],
        },
        "dispatch_rows": rows,
        "syscalls": groups,
        "scml_rules": scml_rules,
        "unsupported_success_paths": unsupported,
        "conformance_blocklists": blocklists,
        "asterinas_branches": branches,
    }
    return inventory, problems


def coverage_problems(inventory):
    """Every dispatch row and blocklisted case needs a status and a
    source; unresolvable handlers are coverage failures. Divergent
    handlers across arch tables are detected and exposed on each row and
    group but not failed, because arch-specific implementations may
    legitimately differ."""
    problems = []
    for row in inventory["dispatch_rows"]:
        label = f"{row['syscall']} ({row['table']}:{row['number']})"
        if row.get("status") not in STATUS_VOCAB:
            problems.append(f"dispatch row {label}: missing or invalid status")
        if not row.get("source"):
            problems.append(f"dispatch row {label}: missing source")
        if row.get("status") == "unresolvable":
            problems.append(
                f"dispatch row {label}: handler {row['handler']} not found"
                f" in {SYSCALL_SRC_DIR}"
            )
        elif not row.get("handler_source"):
            problems.append(f"dispatch row {label}: missing handler source")
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
    rows = inventory["dispatch_rows"]
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
        "Statuses are shallow handler-resolution evidence, not"
        " Linux-compatibility claims; see `metadata.status_semantics` in"
        " inventory.json.",
        "",
        "## Syscall dispatch",
        "",
        f"- dispatch rows: {len(rows)}",
        f"- dispatched syscalls: {len(syscalls)}",
    ]
    for status in STATUS_VOCAB:
        names = by_status.get(status, [])
        lines.append(f"- {status}: {len(names)}")
    divergent = [sc["name"] for sc in syscalls if sc["divergent_handlers"]]
    lines.append(f"- divergent-handler syscalls: {len(divergent)}")
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
        "## SCML rules",
        "",
        f"- invocation rows: {len(inventory['scml_rules'])}",
        f"- undispatched rule names: "
        f"{len({r['name'] for r in inventory['scml_rules'] if not r['dispatched']})}",
        "",
    ]

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


def _print_counts(inventory):
    print(
        "dispatch rows: {rows}, syscalls: {syscalls}, scml rules: {scml}, "
        "unsupported-success sites: {usp}, blocklisted cases: {bl}, "
        "__asterinas__ records: {br}".format(
            rows=len(inventory["dispatch_rows"]),
            syscalls=len(inventory["syscalls"]),
            scml=len(inventory["scml_rules"]),
            usp=len(inventory["unsupported_success_paths"]),
            bl=len(inventory["conformance_blocklists"]),
            br=len(inventory["asterinas_branches"]),
        )
    )


def cmd_generate(repo_root):
    inventory, problems = build_inventory(repo_root)
    if problems:
        for p in problems:
            print(f"generate failed: {p}", file=sys.stderr)
        print("generate failed: refusing to write an invalid inventory",
              file=sys.stderr)
        return 1
    cov = coverage_problems(inventory)
    write_outputs(repo_root, inventory)
    for p in cov:
        print(f"warning: coverage: {p}", file=sys.stderr)
    print(f"inventory regenerated: {inventory_dir(repo_root) / GENERATED_JSON_NAME}")
    _print_counts(inventory)
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
