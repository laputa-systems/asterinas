import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .initramfs import write_selfcheck_initramfs
from .manifest import Selection, load_case_index, load_profile
from .qemu import BASE_CMDLINE, qemu_version, resolve_qemu_path
from .util import atomic_write_bytes, read_json_file, sha256_bytes, sha256_canonical


LOCK_PATH = Path("test/qualification/inputs.lock.json")
CACHE_DIR = Path("target/qualification/inputs/cache")
DEV_IMAGE = "asterinas/dev:0.19.0-20261012"


class LockError(Exception):
    pass


@dataclass(frozen=True)
class LockVerification:
    lock_hash: str
    checked: tuple[str, ...]
    repository: dict[str, Any]
    document: dict[str, Any]


def _sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _run(command: list[str], description: str) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as error:
        raise LockError(f"{description} failed to start: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise LockError(f"{description} exited {completed.returncode}: {detail}")
    return completed


def _docker_build(repo: Path, script: str, description: str) -> None:
    command = [
        "docker",
        "run",
        "--rm",
        "--privileged",
        "-v",
        f"{repo}:/root/asterinas",
        "-v",
        "asterinas-qualification-nix:/nix",
        "-w",
        "/root/asterinas",
        DEV_IMAGE,
        "sh",
        "-lc",
        script,
    ]
    _run(command, description)


def build_linux(repo: Path, clean: bool = False) -> None:
    script = "make -C test/qualification/linux"
    if clean:
        script = "make -C test/qualification/linux clean && " + script
    _docker_build(repo, script, "reference Linux build")


def build_probe(repo: Path) -> None:
    script = (
        "set -eu; "
        "mkdir -p target/qualification/inputs/cache; "
        "result=$(nix-build --no-out-link test/qualification/probe/default.nix); "
        "cp -L \"$result/init\" target/qualification/inputs/cache/probe.tmp; "
        "mv target/qualification/inputs/cache/probe.tmp target/qualification/inputs/cache/probe"
    )
    _docker_build(repo, script, "qualification probe build")


def build_asterinas(repo: Path) -> None:
    script = (
        "set -eu; "
        "mkdir -p target/qualification/inputs/cache; "
        "osdk_root=target/qualification/inputs/cache/osdk-root; "
        "osdk=target/qualification/inputs/cache/cargo-osdk; "
        "OSDK_LOCAL_DEV=1 cargo install cargo-osdk --path osdk --root \"$osdk_root\" --force >/dev/null; "
        "cp \"$osdk_root/bin/cargo-osdk\" \"$osdk\"; "
        "for suffix in '' '-rw'; do "
        "features=pvh_boot; "
        "if [ -n \"$suffix\" ]; then features=$features,ext4_rw_experimental; fi; "
        "cd kernel; "
        "OSDK_TARGET_ARCH=x86_64 /root/asterinas/$osdk osdk build --boot-method=vmm-direct --strip-elf --features=\"$features\" "
        "--kcmd-args=loglevel=error --kcmd-args=earlycon --kcmd-args=console=ttyS0 >/dev/null; "
        "cd ..; "
        "output=target/qualification/inputs/cache/asterinas-kernel$suffix; "
        "cp target/osdk/asterinas/asterinas-osdk-bin.elf \"$output.tmp\"; "
        "mv \"$output.tmp\" \"$output\"; "
        "done"
    )
    _docker_build(repo, script, "Asterinas qualification kernel build")


def build_initramfs(repo: Path) -> None:
    write_selfcheck_initramfs(
        repo / CACHE_DIR / "probe",
        repo / "test/qualification/probe/input.txt",
        repo / CACHE_DIR / "initramfs.cpio",
    )


def build_adapter_fixtures(repo: Path) -> None:
    script = (
        "set -eu; "
        "result=$(nix-build --no-out-link test/qualification/adapter/e2fsprogs.nix); "
        "export SOURCE_DATE_EPOCH=0 E2FSPROGS_FAKE_TIME=0; "
        "staging=/tmp/qual-adapter-mkfs; "
        "rm -rf \"$staging\"; "
        "mkdir -p \"$staging/good\" \"$staging/wrong\" \"$staging/ext4\" \"$staging/multigroup\" \"$staging/sparse\"; "
        "printf 'lc06-adapter\\n' > \"$staging/good/marker.txt\"; "
        "printf 'lc06-adapter\\n' > \"$staging/wrong/marker.txt\"; "
        "printf 'lc14-basic\\n' > \"$staging/ext4/marker.txt\"; "
        "for i in $(seq 1 64); do printf 'group-%03d\\n' \"$i\" > \"$staging/multigroup/f$i.txt\"; done; "
        "printf 'lc14-sparse\\n' > \"$staging/sparse/marker.txt\"; "
        "truncate -s 12M \"$staging/sparse/sparse.bin\"; printf 'tail\\n' >> \"$staging/sparse/sparse.bin\"; "
        "rm -f target/qualification/inputs/cache/adapter-disk.ext2.tmp; truncate -s 16M target/qualification/inputs/cache/adapter-disk.ext2.tmp; "
        "\"$result/bin/mkfs.ext2\" -q -F -b 4096 -I 128 -d \"$staging/good\" -U 6c636f36-6164-4070-7465-723031323334 -E hash_seed=11111111-2222-3333-4444-555555555555 target/qualification/inputs/cache/adapter-disk.ext2.tmp; "
        "mv target/qualification/inputs/cache/adapter-disk.ext2.tmp target/qualification/inputs/cache/adapter-disk.ext2; "
        "rm -f target/qualification/inputs/cache/adapter-disk.ext4.tmp; truncate -s 16M target/qualification/inputs/cache/adapter-disk.ext4.tmp; "
        "\"$result/bin/mkfs.ext4\" -q -F -b 4096 -I 128 -O ^64bit,^metadata_csum,^metadata_csum_seed -d \"$staging/ext4\" -U 6c636f36-6164-4070-7465-723031323334 -E hash_seed=11111111-2222-3333-4444-555555555555 target/qualification/inputs/cache/adapter-disk.ext4.tmp >/dev/null 2>&1; "
        "\"$result/bin/e2fsck\" -fn target/qualification/inputs/cache/adapter-disk.ext4.tmp; "
        "mv target/qualification/inputs/cache/adapter-disk.ext4.tmp target/qualification/inputs/cache/adapter-disk.ext4; "
        "rm -f target/qualification/inputs/cache/adapter-multigroup.ext4.tmp; truncate -s 128M target/qualification/inputs/cache/adapter-multigroup.ext4.tmp; "
        "\"$result/bin/mkfs.ext4\" -q -F -b 1024 -I 128 -O ^64bit,^metadata_csum,^metadata_csum_seed -d \"$staging/multigroup\" -U 6c636f36-6164-4070-7465-723031323335 -E hash_seed=11111111-2222-3333-4444-555555555555 target/qualification/inputs/cache/adapter-multigroup.ext4.tmp >/dev/null 2>&1; "
        "\"$result/bin/e2fsck\" -fn target/qualification/inputs/cache/adapter-multigroup.ext4.tmp; "
        "mv target/qualification/inputs/cache/adapter-multigroup.ext4.tmp target/qualification/inputs/cache/adapter-multigroup.ext4; "
        "rm -f target/qualification/inputs/cache/adapter-sparse.ext4.tmp; truncate -s 16M target/qualification/inputs/cache/adapter-sparse.ext4.tmp; "
        "\"$result/bin/mkfs.ext4\" -q -F -b 4096 -I 128 -O ^64bit,^metadata_csum,^metadata_csum_seed -d \"$staging/sparse\" -U 6c636f36-6164-4070-7465-723031323336 -E hash_seed=11111111-2222-3333-4444-555555555555 target/qualification/inputs/cache/adapter-sparse.ext4.tmp >/dev/null 2>&1; "
        "\"$result/bin/e2fsck\" -fn target/qualification/inputs/cache/adapter-sparse.ext4.tmp; "
        "mv target/qualification/inputs/cache/adapter-sparse.ext4.tmp target/qualification/inputs/cache/adapter-sparse.ext4; "
        "rm -f target/qualification/inputs/cache/adapter-wrong-disk.ext2.tmp; truncate -s 16M target/qualification/inputs/cache/adapter-wrong-disk.ext2.tmp; "
        "\"$result/bin/mkfs.ext2\" -q -F -b 4096 -I 128 -d \"$staging/wrong\" -U 77726f6e-6764-4973-6b31-323334353637 -E hash_seed=11111111-2222-3333-4444-555555555555 target/qualification/inputs/cache/adapter-wrong-disk.ext2.tmp; "
        "mv target/qualification/inputs/cache/adapter-wrong-disk.ext2.tmp target/qualification/inputs/cache/adapter-wrong-disk.ext2; "
        "rm -f target/qualification/inputs/cache/adapter-wrong-filesystem.img; truncate -s 16M target/qualification/inputs/cache/adapter-wrong-filesystem.img"
    )
    _docker_build(repo, script, "adapter disk fixture build")


def _docker_image_digest() -> str:
    completed = _run(
        ["docker", "image", "inspect", DEV_IMAGE, "--format", "{{json .RepoDigests}}"],
        "dev container image inspection",
    )
    digests = json.loads(completed.stdout)
    expected_prefix = DEV_IMAGE.split(":", 1)[0] + "@sha256:"
    matches = sorted(item for item in digests if isinstance(item, str) and item.startswith(expected_prefix))
    if len(matches) != 1:
        raise LockError(f"dev container image has no unique repo digest: {digests!r}")
    return matches[0].split("@", 1)[1]


def _git_output(repo: Path, arguments: list[str], description: str) -> str:
    return _run(["git", "-C", str(repo), *arguments], description).stdout


def _delta_entries(repo: Path, base_commit: str) -> list[dict[str, Any]]:
    diff_output = _git_output(
        repo,
        ["diff", "--name-only", "-z", base_commit, "--", ".", f":(exclude){LOCK_PATH}"],
        "repository delta enumeration",
    )
    untracked_output = _git_output(repo, ["ls-files", "--others", "--exclude-standard", "-z"], "untracked file enumeration")
    names = {item for item in diff_output.split("\0") if item}
    names.update(item for item in untracked_output.split("\0") if item)
    entries: list[dict[str, Any]] = []
    for name in sorted(names):
        if name == str(LOCK_PATH) or name.startswith("target/"):
            continue
        path = repo / name
        entry: dict[str, Any] = {"path": name}
        if path.is_symlink():
            entry.update({"kind": "symlink", "target": str(path.readlink())})
        elif path.is_file():
            entry.update({"kind": "file", "sha256": _sha256_file(path), "mode": path.stat().st_mode & 0o777})
        else:
            entry["kind"] = "deleted"
        entries.append(entry)
    return entries


def repository_provenance(repo: Path) -> dict[str, Any]:
    commit = _git_output(repo, ["rev-parse", "HEAD"], "repository commit resolution").strip()
    fingerprint = sha256_canonical(_delta_entries(repo, commit))
    return {
        "asterinas_commit": commit,
        "dirty_diff_sha256": fingerprint,
    }


SOURCE_TREE_EXCLUDED_DIRS = frozenset({".git", "target", ".work"})
SOURCE_TREE_EXCLUDED_FILES = frozenset(
    {"test/qualification/inputs.lock.json", "qemu.log", "qemu-serial.log"}
)


def repository_policy() -> dict[str, str]:
    return {
        "binding": "run-effective-lock",
        "delta_semantics": "content digest of the working-tree delta against HEAD, excluding inputs.lock.json and target outputs",
        "source_tree_semantics": (
            "content digest over every repository file except generated output directories "
            f"{sorted(SOURCE_TREE_EXCLUDED_DIRS)} and self-referential files "
            f"{sorted(SOURCE_TREE_EXCLUDED_FILES)}; includes vendored dependencies and nested Cargo configuration"
        ),
    }


def harness_file_paths(repo: Path) -> list[str]:
    paths = [repo / "test/qualification/run.py"]
    paths.extend(sorted((repo / "test/qualification/qualcore").glob("*.py")))
    return [str(path.relative_to(repo)) for path in paths]


def harness_lock(repo: Path) -> dict[str, Any]:
    files: dict[str, str] = {}
    for relative in harness_file_paths(repo):
        path = repo / relative
        if not path.is_file():
            raise LockError(f"harness input is missing: {relative}")
        files[relative] = _sha256_file(path)
    return {"files": files}


def _load_selection(repo: Path, profile_name: str) -> Selection:
    contracts_dir = repo / "test/qualification/contracts"
    paths = sorted(contracts_dir.glob("*/*.json"))
    if not paths:
        raise LockError("no contract manifests found")
    case_index = load_case_index(paths)
    return load_profile(profile_name, repo / "test/qualification/profiles", case_index)


def _normalization_rules(selection: Selection) -> list[str]:
    rules: set[str] = set()
    for case in selection.cases:
        for subtest in case.expected_subtests:
            for assertion in subtest.assertions:
                rules.update(assertion.normalization)
    return sorted(rules)


def _selection_lock(selection: Selection) -> dict[str, Any]:
    return {
        "manifest_hash": selection.manifest_hash,
        "payload_hash": selection.payload_hash,
        "case_ids": list(selection.case_ids),
        "cases": [
            {
                "id": case.case_id,
                "contract_revision": case.contract_revision,
                "deadline_seconds": case.deadline_seconds,
                "artifacts": list(case.artifacts),
                "validators": list(case.validators),
            }
            for case in selection.cases
        ],
        "excluded": [{"case": case, "reason": reason} for case, reason in selection.excluded],
        "normalization_rules": _normalization_rules(selection),
    }


def _qemu_lock() -> dict[str, str]:
    discovered = shutil.which("qemu-system-x86_64")
    if discovered is None:
        raise LockError("qemu-system-x86_64 is missing from PATH")
    qemu_path = Path(discovered)
    resolved = resolve_qemu_path(qemu_path)
    if not resolved.exists():
        raise LockError(f"qemu binary is missing: {qemu_path}")
    return {
        "path": str(qemu_path),
        "resolved_path": str(resolved),
        "version": qemu_version(qemu_path),
        "sha256": _sha256_file(resolved),
    }


def asterinas_source_tree_hash(repo: Path) -> str:
    entries: list[dict[str, Any]] = []
    for root, directories, files in os.walk(repo):
        directories[:] = sorted(name for name in directories if name not in SOURCE_TREE_EXCLUDED_DIRS)
        root_path = Path(root)
        for name in sorted(files):
            path = root_path / name
            relative = path.relative_to(repo).as_posix()
            if relative in SOURCE_TREE_EXCLUDED_FILES:
                continue
            entry: dict[str, Any] = {"path": relative}
            if path.is_symlink():
                entry.update({"kind": "symlink", "target": os.readlink(path)})
            elif path.is_file():
                entry.update({"kind": "file", "sha256": _sha256_file(path), "mode": path.stat().st_mode & 0o777})
            else:
                entry["kind"] = "missing"
            entries.append(entry)
    return sha256_canonical(entries)


def _linux_rebuild_required(repo: Path, linux_path: Path, dev_digest: str) -> bool:
    if not linux_path.is_file():
        return True
    try:
        previous = read_json_file(repo / LOCK_PATH)
    except Exception:
        return True
    if not isinstance(previous, dict):
        return True
    linux = previous.get("linux")
    build = previous.get("asterinas_build")
    container = previous.get("dev_container")
    if not isinstance(linux, dict) or not isinstance(build, dict) or not isinstance(container, dict):
        return True
    current = {
        "makefile_sha256": _sha256_file(repo / "test/qualification/linux/Makefile"),
        "nix_sha256": _sha256_file(repo / "test/qualification/linux/default.nix"),
        "config_sha256": _sha256_file(repo / "test/qualification/linux/config"),
        "bzimage_sha256": _sha256_file(linux_path),
    }
    build_inputs_match = (
        build.get("flake_lock_sha256") == _sha256_file(repo / "flake.lock")
        and build.get("nixpkgs_sha256") == _sha256_file(repo / "distro/nixpkgs.nix")
        and container.get("digest") == dev_digest
    )
    linux_inputs_match = all(linux.get(key) == value for key, value in current.items())
    return not (build_inputs_match and linux_inputs_match)


def _probe_rebuild_required(repo: Path, probe_path: Path, dev_digest: str) -> bool:
    if not probe_path.is_file():
        return True
    try:
        previous = read_json_file(repo / LOCK_PATH)
    except Exception:
        return True
    if not isinstance(previous, dict):
        return True
    probe = previous.get("probe")
    build = previous.get("asterinas_build")
    container = previous.get("dev_container")
    if not isinstance(probe, dict) or not isinstance(build, dict) or not isinstance(container, dict):
        return True
    recorded: dict[str, Any] = dict(probe)
    recorded.update(build)
    recorded["dev_container_digest"] = container.get("digest")
    current = {
        "source_sha256": _sha256_file(repo / "test/qualification/probe/probe.c"),
        "nix_sha256": _sha256_file(repo / "test/qualification/probe/default.nix"),
        "binary_sha256": _sha256_file(probe_path),
        "flake_lock_sha256": _sha256_file(repo / "flake.lock"),
        "nixpkgs_sha256": _sha256_file(repo / "distro/nixpkgs.nix"),
        "rust_toolchain_sha256": _sha256_file(repo / "rust-toolchain.toml"),
        "dev_container_digest": dev_digest,
    }
    return any(recorded.get(key) != value for key, value in current.items())


def generate_lock(repo: Path) -> dict[str, Any]:
    linux_path = repo / "test/qualification/linux/bzImage"
    dev_digest = _docker_image_digest()
    if _linux_rebuild_required(repo, linux_path, dev_digest):
        build_linux(repo, clean=True)
    probe_path = repo / CACHE_DIR / "probe"
    if _probe_rebuild_required(repo, probe_path, dev_digest):
        build_probe(repo)
    build_initramfs(repo)
    initramfs_path = repo / CACHE_DIR / "initramfs.cpio"
    build_adapter_fixtures(repo)
    build_asterinas(repo)
    adapter_disk = repo / CACHE_DIR / "adapter-disk.ext2"
    adapter_wrong_disk = repo / CACHE_DIR / "adapter-wrong-disk.ext2"
    adapter_wrong_filesystem = repo / CACHE_DIR / "adapter-wrong-filesystem.img"
    adapter_ext4_disk = repo / CACHE_DIR / "adapter-disk.ext4"
    adapter_multigroup_disk = repo / CACHE_DIR / "adapter-multigroup.ext4"
    adapter_sparse_disk = repo / CACHE_DIR / "adapter-sparse.ext4"
    selection = _load_selection(repo, "selfcheck")
    control_selection = _load_selection(repo, "lc02-selftest")
    adapter_selection = _load_selection(repo, "adapter")
    pilot_selection = _load_selection(repo, "pilot-ext2")
    fd_selection = _load_selection(repo, "pilot-fd")
    errors_selection = _load_selection(repo, "s0-errors")
    persistence_selection = _load_selection(repo, "s0-persistence")
    ext4_read_selection = _load_selection(repo, "ext4-read")
    ext4_extra_selection = _load_selection(repo, "ext4-read-extra")
    ext4_journal_selection = _load_selection(repo, "ext4-journal")
    ext4_alloc_selection = _load_selection(repo, "ext4-alloc")
    ext4_dir_selection = _load_selection(repo, "ext4-dir")
    ext4_orphan_selection = _load_selection(repo, "ext4-orphan")
    ext4_xattr_selection = _load_selection(repo, "ext4-xattr")
    ext4_durability_selection = _load_selection(repo, "ext4-durability")
    ext4_errors_selection = _load_selection(repo, "ext4-errors")
    return {
        "schema": 1,
        "lock_revision": "lc07-r1",
        "repository": repository_policy(),
        "harness": harness_lock(repo),
        "dev_container": {
            "image": DEV_IMAGE,
            "digest": dev_digest,
        },
        "python": {
            "minimum_version": "3.11",
        },
        "qemu": _qemu_lock(),
        "linux": {
            "version": "6.18.65",
            "makefile_path": "test/qualification/linux/Makefile",
            "makefile_sha256": _sha256_file(repo / "test/qualification/linux/Makefile"),
            "nix_path": "test/qualification/linux/default.nix",
            "nix_sha256": _sha256_file(repo / "test/qualification/linux/default.nix"),
            "config_path": "test/qualification/linux/config",
            "config_sha256": _sha256_file(repo / "test/qualification/linux/config"),
            "cmdline": BASE_CMDLINE,
            "bzimage_path": "test/qualification/linux/bzImage",
            "bzimage_sha256": _sha256_file(linux_path),
        },
        "adapter": {
            "e2fsprogs_nix_path": "test/qualification/adapter/e2fsprogs.nix",
            "e2fsprogs_nix_sha256": _sha256_file(repo / "test/qualification/adapter/e2fsprogs.nix"),
            "disk_size_bytes": 16777216,
            "serial": "qual-lc06-adapter",
            "disk_path": str(CACHE_DIR / "adapter-disk.ext2"),
            "disk_sha256": _sha256_file(adapter_disk),
            "ext4_disk_path": str(CACHE_DIR / "adapter-disk.ext4"),
            "ext4_disk_sha256": _sha256_file(adapter_ext4_disk),
            "multigroup_disk_path": str(CACHE_DIR / "adapter-multigroup.ext4"),
            "multigroup_disk_sha256": _sha256_file(adapter_multigroup_disk),
            "sparse_disk_path": str(CACHE_DIR / "adapter-sparse.ext4"),
            "sparse_disk_sha256": _sha256_file(adapter_sparse_disk),
            "wrong_disk_path": str(CACHE_DIR / "adapter-wrong-disk.ext2"),
            "wrong_disk_sha256": _sha256_file(adapter_wrong_disk),
            "wrong_filesystem_path": str(CACHE_DIR / "adapter-wrong-filesystem.img"),
            "wrong_filesystem_sha256": _sha256_file(adapter_wrong_filesystem),
        },
        "probe": {
            "source_path": "test/qualification/probe/probe.c",
            "source_sha256": _sha256_file(repo / "test/qualification/probe/probe.c"),
            "nix_path": "test/qualification/probe/default.nix",
            "nix_sha256": _sha256_file(repo / "test/qualification/probe/default.nix"),
            "binary_path": str(CACHE_DIR / "probe"),
            "binary_sha256": _sha256_file(probe_path),
            "input_path": "test/qualification/probe/input.txt",
            "input_payload_sha256": _sha256_file(repo / "test/qualification/probe/input.txt"),
            "initramfs_path": str(CACHE_DIR / "initramfs.cpio"),
            "initramfs_sha256": _sha256_file(initramfs_path),
        },
        "asterinas_build": {
            "cargo_lock_path": "Cargo.lock",
            "cargo_lock_sha256": _sha256_file(repo / "Cargo.lock"),
            "rust_toolchain_path": "rust-toolchain.toml",
            "rust_toolchain_sha256": _sha256_file(repo / "rust-toolchain.toml"),
            "flake_lock_path": "flake.lock",
            "flake_lock_sha256": _sha256_file(repo / "flake.lock"),
            "nixpkgs_path": "distro/nixpkgs.nix",
            "nixpkgs_sha256": _sha256_file(repo / "distro/nixpkgs.nix"),
            "kernel_path": str(CACHE_DIR / "asterinas-kernel"),
            "kernel_sha256": _sha256_file(repo / CACHE_DIR / "asterinas-kernel"),
            "rw_kernel_path": str(CACHE_DIR / "asterinas-kernel-rw"),
            "rw_kernel_sha256": _sha256_file(repo / CACHE_DIR / "asterinas-kernel-rw"),
            "source_tree_sha256": asterinas_source_tree_hash(repo),
        },
        "selections": {
            "selfcheck": _selection_lock(selection),
            "lc02-selftest": _selection_lock(control_selection),
            "adapter": _selection_lock(adapter_selection),
            "pilot-ext2": _selection_lock(pilot_selection),
            "pilot-fd": _selection_lock(fd_selection),
            "s0-errors": _selection_lock(errors_selection),
            "s0-persistence": _selection_lock(persistence_selection),
            "ext4-read": _selection_lock(ext4_read_selection),
            "ext4-read-extra": _selection_lock(ext4_extra_selection),
            "ext4-journal": _selection_lock(ext4_journal_selection),
            "ext4-alloc": _selection_lock(ext4_alloc_selection),
            "ext4-dir": _selection_lock(ext4_dir_selection),
            "ext4-orphan": _selection_lock(ext4_orphan_selection),
            "ext4-xattr": _selection_lock(ext4_xattr_selection),
            "ext4-durability": _selection_lock(ext4_durability_selection),
            "ext4-errors": _selection_lock(ext4_errors_selection),
        },
    }


def write_lock(repo: Path) -> Path:
    document = generate_lock(repo)
    path = repo / LOCK_PATH
    atomic_write_bytes(path, (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    return path


def _require(condition: bool, message: str, failures: list[str]) -> bool:
    if not condition:
        failures.append(message)
        return False
    return True


def _check_file_hash(repo: Path, relative: str, expected: str, label: str, failures: list[str], checked: list[str]) -> None:
    path = repo / relative
    if not _require(path.is_file(), f"{label} is missing: {relative}", failures):
        return
    try:
        actual = _sha256_file(path)
    except OSError as error:
        failures.append(f"{label} cannot be read: {relative}: {error}")
        return
    if _require(actual == expected, f"{label} hash drift: {relative} got {actual} expected {expected}", failures):
        checked.append(label)


def _load_lock(repo: Path) -> tuple[dict[str, Any], str]:
    path = repo / LOCK_PATH
    if not path.exists():
        raise LockError(f"input lock is missing: {LOCK_PATH}")
    try:
        lock_bytes = path.read_bytes()
        document = json.loads(lock_bytes)
    except (OSError, ValueError) as error:
        raise LockError(f"cannot read input policy {LOCK_PATH}: {error}") from error
    if not isinstance(document, dict):
        raise LockError("input lock root is not an object")
    if document.get("schema") != 1:
        raise LockError("input lock schema is not 1")
    return document, sha256_bytes(lock_bytes)


def _verify_version(version: str) -> bool:
    parts = version.split(".")
    try:
        numbers = tuple(int(part) for part in parts)
    except ValueError:
        return False
    return numbers >= (3, 11)


def _verify_selection(repo: Path, lock: dict[str, Any], profile_name: str, failures: list[str], checked: list[str]) -> None:
    expected = lock["selections"][profile_name]
    try:
        selection = _load_selection(repo, profile_name)
    except Exception as error:
        failures.append(f"{profile_name} selection resolution failed: {error}")
        return
    if selection.manifest_hash != expected["manifest_hash"]:
        failures.append(f"{profile_name} manifest hash drift: got {selection.manifest_hash} expected {expected['manifest_hash']}")
    if selection.payload_hash != expected["payload_hash"]:
        failures.append(f"{profile_name} payload hash drift: got {selection.payload_hash} expected {expected['payload_hash']}")
    if list(selection.case_ids) != expected["case_ids"]:
        failures.append(f"{profile_name} case selection drift: got {list(selection.case_ids)!r} expected {expected['case_ids']!r}")
    revisions = {case.case_id: case.contract_revision for case in selection.cases}
    expected_revisions = {case["id"]: case["contract_revision"] for case in expected["cases"]}
    if revisions != expected_revisions:
        failures.append(f"{profile_name} contract revision drift: got {revisions!r} expected {expected_revisions!r}")
    if _normalization_rules(selection) != expected["normalization_rules"]:
        failures.append(f"{profile_name} normalization rules drift")
    if sorted((case, reason) for case, reason in selection.excluded) != sorted(
        (item["case"], item["reason"]) for item in expected["excluded"]
    ):
        failures.append(f"{profile_name} exclusion drift")
    if _selection_lock(selection)["cases"] != expected["cases"]:
        failures.append(f"{profile_name} case policy drift")
    checked.append(f"{profile_name} selection")


def _require_lock_shape(lock: dict[str, Any]) -> None:
    required = (
        ("repository", "binding"),
        ("harness", "files"),
        ("dev_container", "digest"),
        ("qemu", "path"),
        ("qemu", "resolved_path"),
        ("qemu", "version"),
        ("qemu", "sha256"),
        ("linux", "version"),
        ("linux", "makefile_path"),
        ("linux", "makefile_sha256"),
        ("linux", "nix_path"),
        ("linux", "nix_sha256"),
        ("linux", "config_path"),
        ("linux", "config_sha256"),
        ("linux", "cmdline"),
        ("linux", "bzimage_path"),
        ("linux", "bzimage_sha256"),
        ("adapter", "e2fsprogs_nix_path"),
        ("adapter", "e2fsprogs_nix_sha256"),
        ("adapter", "disk_size_bytes"),
        ("adapter", "serial"),
        ("adapter", "disk_path"),
        ("adapter", "disk_sha256"),
        ("adapter", "ext4_disk_path"),
        ("adapter", "ext4_disk_sha256"),
        ("adapter", "multigroup_disk_path"),
        ("adapter", "multigroup_disk_sha256"),
        ("adapter", "sparse_disk_path"),
        ("adapter", "sparse_disk_sha256"),
        ("adapter", "wrong_disk_path"),
        ("adapter", "wrong_disk_sha256"),
        ("adapter", "wrong_filesystem_path"),
        ("adapter", "wrong_filesystem_sha256"),
        ("probe", "source_path"),
        ("probe", "source_sha256"),
        ("probe", "nix_path"),
        ("probe", "nix_sha256"),
        ("probe", "binary_path"),
        ("probe", "binary_sha256"),
        ("probe", "input_path"),
        ("probe", "input_payload_sha256"),
        ("probe", "initramfs_path"),
        ("probe", "initramfs_sha256"),
        ("asterinas_build", "cargo_lock_path"),
        ("asterinas_build", "cargo_lock_sha256"),
        ("asterinas_build", "rust_toolchain_path"),
        ("asterinas_build", "rust_toolchain_sha256"),
        ("asterinas_build", "flake_lock_path"),
        ("asterinas_build", "flake_lock_sha256"),
        ("asterinas_build", "nixpkgs_path"),
        ("asterinas_build", "nixpkgs_sha256"),
        ("asterinas_build", "kernel_path"),
        ("asterinas_build", "kernel_sha256"),
        ("asterinas_build", "rw_kernel_path"),
        ("asterinas_build", "rw_kernel_sha256"),
        ("asterinas_build", "source_tree_sha256"),
        ("selections", "selfcheck", "manifest_hash"),
        ("selections", "selfcheck", "payload_hash"),
        ("selections", "selfcheck", "case_ids"),
        ("selections", "selfcheck", "cases"),
        ("selections", "selfcheck", "excluded"),
        ("selections", "selfcheck", "normalization_rules"),
        ("selections", "lc02-selftest", "manifest_hash"),
        ("selections", "lc02-selftest", "payload_hash"),
        ("selections", "lc02-selftest", "case_ids"),
        ("selections", "lc02-selftest", "cases"),
        ("selections", "lc02-selftest", "excluded"),
        ("selections", "lc02-selftest", "normalization_rules"),
        ("selections", "adapter", "manifest_hash"),
        ("selections", "adapter", "payload_hash"),
        ("selections", "adapter", "case_ids"),
        ("selections", "adapter", "cases"),
        ("selections", "adapter", "excluded"),
        ("selections", "adapter", "normalization_rules"),
        ("selections", "pilot-ext2", "manifest_hash"),
        ("selections", "pilot-ext2", "payload_hash"),
        ("selections", "pilot-ext2", "case_ids"),
        ("selections", "pilot-ext2", "cases"),
        ("selections", "pilot-ext2", "excluded"),
        ("selections", "pilot-ext2", "normalization_rules"),
        ("selections", "pilot-fd", "manifest_hash"),
        ("selections", "pilot-fd", "payload_hash"),
        ("selections", "pilot-fd", "case_ids"),
        ("selections", "pilot-fd", "cases"),
        ("selections", "pilot-fd", "excluded"),
        ("selections", "pilot-fd", "normalization_rules"),
        ("selections", "s0-errors", "manifest_hash"),
        ("selections", "s0-errors", "payload_hash"),
        ("selections", "s0-errors", "case_ids"),
        ("selections", "s0-errors", "cases"),
        ("selections", "s0-errors", "excluded"),
        ("selections", "s0-errors", "normalization_rules"),
        ("selections", "s0-persistence", "manifest_hash"),
        ("selections", "s0-persistence", "payload_hash"),
        ("selections", "s0-persistence", "case_ids"),
        ("selections", "s0-persistence", "cases"),
        ("selections", "s0-persistence", "excluded"),
        ("selections", "s0-persistence", "normalization_rules"),
    )
    missing: list[str] = []
    for path in required:
        value: Any = lock
        for part in path:
            if not isinstance(value, dict) or part not in value:
                missing.append(".".join(path))
                break
            value = value[part]
    if missing:
        raise LockError("input lock is missing required fields: " + ", ".join(missing))


def verify_lock_document(repo: Path, lock: dict[str, Any], build_missing: bool = True) -> tuple[str, ...]:
    _require_lock_shape(lock)
    failures: list[str] = []
    checked: list[str] = []

    if not _verify_version(sys.version.split()[0]):
        failures.append(f"Python is below the locked minimum: {sys.version.split()[0]}")
    else:
        checked.append("python version")

    if lock["repository"].get("binding") != "run-effective-lock":
        failures.append(f"repository binding drift: {lock['repository'].get('binding')!r}")
    else:
        checked.append("repository binding")

    expected_harness = lock["harness"]["files"]
    actual_harness_paths = harness_file_paths(repo)
    if not isinstance(expected_harness, dict) or sorted(expected_harness) != sorted(actual_harness_paths):
        failures.append("harness input set drift")
    else:
        harness_failed = False
        for relative, expected_hash in sorted(expected_harness.items()):
            before = len(failures)
            _check_file_hash(repo, relative, expected_hash, f"harness input {relative}", failures, checked)
            harness_failed = harness_failed or len(failures) != before
        if not harness_failed:
            checked.append("harness inputs")

    qemu_lock = lock["qemu"]
    qemu_path = Path(qemu_lock["path"])
    if not qemu_path.exists():
        failures.append(f"qemu binary is missing: {qemu_path}")
    else:
        resolved = resolve_qemu_path(qemu_path)
        if str(resolved) != qemu_lock["resolved_path"]:
            failures.append(f"qemu resolved path drift: got {resolved} expected {qemu_lock['resolved_path']}")
        actual_hash = _sha256_file(resolved)
        if actual_hash != qemu_lock["sha256"]:
            failures.append(f"qemu binary hash drift: got {actual_hash} expected {qemu_lock['sha256']}")
        try:
            actual_version = qemu_version(qemu_path)
        except Exception as error:
            failures.append(f"qemu version probe failed: {error}")
        else:
            if actual_version != qemu_lock["version"]:
                failures.append(f"qemu version drift: got {actual_version} expected {qemu_lock['version']}")
        if not any(item.startswith("qemu ") for item in failures):
            checked.append("qemu")

    try:
        digest = _docker_image_digest()
        if digest != lock["dev_container"]["digest"]:
            failures.append(f"dev container digest drift: got {digest} expected {lock['dev_container']['digest']}")
        checked.append("dev container")
    except LockError as error:
        failures.append(str(error))

    linux = lock["linux"]
    probe = lock["probe"]
    adapter = lock["adapter"]
    asterinas_build = lock["asterinas_build"]
    for section, path_key, hash_key, label in (
        (adapter, "e2fsprogs_nix_path", "e2fsprogs_nix_sha256", "adapter e2fsprogs Nix expression"),
        (linux, "makefile_path", "makefile_sha256", "Linux makefile"),
        (linux, "nix_path", "nix_sha256", "Linux Nix expression"),
        (linux, "config_path", "config_sha256", "Linux config"),
        (probe, "source_path", "source_sha256", "probe source"),
        (probe, "nix_path", "nix_sha256", "probe Nix expression"),
        (probe, "input_path", "input_payload_sha256", "probe input payload"),
        (asterinas_build, "cargo_lock_path", "cargo_lock_sha256", "Cargo.lock"),
        (asterinas_build, "rust_toolchain_path", "rust_toolchain_sha256", "rust toolchain"),
        (asterinas_build, "flake_lock_path", "flake_lock_sha256", "flake lock"),
        (asterinas_build, "nixpkgs_path", "nixpkgs_sha256", "nixpkgs import"),
    ):
        _check_file_hash(repo, section[path_key], section[hash_key], label, failures, checked)

    if linux["cmdline"] != BASE_CMDLINE:
        failures.append(f"Linux cmdline drift in runner: {BASE_CMDLINE!r} != {linux['cmdline']!r}")
    checked.append("Linux cmdline")

    linux_path = repo / linux["bzimage_path"]
    if not linux_path.exists() and build_missing and not failures:
        build_linux(repo)
    _check_file_hash(repo, linux["bzimage_path"], linux["bzimage_sha256"], "Linux bzImage", failures, checked)

    probe_cache = repo / probe["binary_path"]
    if not probe_cache.exists() and build_missing and not failures:
        build_probe(repo)
    _check_file_hash(repo, probe["binary_path"], probe["binary_sha256"], "probe binary", failures, checked)

    initramfs_cache = repo / probe["initramfs_path"]
    if not initramfs_cache.exists() and build_missing and probe_cache.exists():
        build_initramfs(repo)
    _check_file_hash(repo, probe["initramfs_path"], probe["initramfs_sha256"], "probe initramfs", failures, checked)

    adapter_cache = repo / adapter["disk_path"]
    if not adapter_cache.exists() and build_missing and not failures:
        build_adapter_fixtures(repo)
    for path_key, hash_key, label in (
        ("disk_path", "disk_sha256", "adapter disk"),
        ("ext4_disk_path", "ext4_disk_sha256", "adapter ext4 disk"),
        ("multigroup_disk_path", "multigroup_disk_sha256", "adapter multi-group ext4 disk"),
        ("sparse_disk_path", "sparse_disk_sha256", "adapter sparse ext4 disk"),
        ("wrong_disk_path", "wrong_disk_sha256", "adapter wrong-disk fixture"),
        ("wrong_filesystem_path", "wrong_filesystem_sha256", "adapter wrong-filesystem fixture"),
    ):
        _check_file_hash(repo, adapter[path_key], adapter[hash_key], label, failures, checked)
    if adapter["serial"] != "qual-lc06-adapter":
        failures.append(f"adapter serial drift: {adapter['serial']!r}")
    else:
        checked.append("adapter serial")

    actual_source_tree = asterinas_source_tree_hash(repo)
    if actual_source_tree != asterinas_build["source_tree_sha256"]:
        failures.append(f"Asterinas source tree drift: got {actual_source_tree} expected {asterinas_build['source_tree_sha256']}")
    else:
        checked.append("Asterinas source tree")

    asterinas_kernel = repo / asterinas_build["kernel_path"]
    rw_kernel = repo / asterinas_build["rw_kernel_path"]
    if (not asterinas_kernel.exists() or not rw_kernel.exists()) and build_missing and not failures:
        build_asterinas(repo)
    _check_file_hash(repo, asterinas_build["kernel_path"], asterinas_build["kernel_sha256"], "Asterinas kernel", failures, checked)
    _check_file_hash(repo, asterinas_build["rw_kernel_path"], asterinas_build["rw_kernel_sha256"], "Asterinas experimental ext4 kernel", failures, checked)
    if asterinas_build["kernel_sha256"] == asterinas_build["rw_kernel_sha256"]:
        failures.append("default and experimental Asterinas kernels have identical hashes")

    for profile_name in ("selfcheck", "lc02-selftest", "adapter", "pilot-ext2", "pilot-fd", "s0-errors", "s0-persistence", "ext4-read", "ext4-read-extra", "ext4-journal", "ext4-alloc", "ext4-dir", "ext4-orphan", "ext4-xattr", "ext4-durability", "ext4-errors"):
        _verify_selection(repo, lock, profile_name, failures, checked)

    if failures:
        raise LockError("; ".join(failures))
    return tuple(checked)


def verify_lock(repo: Path, build_missing: bool = True) -> LockVerification:
    document, policy_hash = _load_lock(repo)
    checked = verify_lock_document(repo, document, build_missing)
    if _sha256_file(repo / LOCK_PATH) != policy_hash:
        raise LockError("input policy changed during verification")
    return LockVerification(
        lock_hash=policy_hash,
        checked=checked,
        repository=repository_provenance(repo),
        document=document,
    )


def effective_lock_bytes(
    verification: LockVerification,
    selection: Selection,
    input_hashes: dict[str, str],
    backend: dict[str, str] | None = None,
) -> bytes:
    document = {
        "schema": 1,
        "policy_lock_sha256": verification.lock_hash,
        "repository": verification.repository,
        "profile": selection.profile_name,
        "selection": _selection_lock(selection),
        "checked_inputs": list(verification.checked),
        "input_hashes": input_hashes,
        "backend": backend or {},
    }
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")


def write_effective_lock(
    path: Path,
    verification: LockVerification,
    selection: Selection,
    input_hashes: dict[str, str],
    backend: dict[str, str] | None = None,
) -> str:
    data = effective_lock_bytes(verification, selection, input_hashes, backend)
    atomic_write_bytes(path, data)
    return sha256_bytes(data)
