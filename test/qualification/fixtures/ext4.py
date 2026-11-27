# SPDX-License-Identifier: MPL-2.0
"""Deterministic ext4 fixture build and verification for LC-14.

Each fixture is produced with the pinned e2fsprogs from the dev container
under a fixed epoch and hash seed. The manifest records both the image hash
and the inspected feature mask so a rebuild proves the same bytes and the
same on-disk format policy.
"""

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from qualcore.lock import DEV_IMAGE

FIXTURE_DIR = Path("target/qualification/inputs/ext4")
MANIFEST_PATH = Path("test/qualification/fixtures/ext4/manifest.json")
BLOCK_SIZE = 4096


@dataclass(frozen=True)
class Fixture:
    name: str
    size_mb: int
    block_size: int
    features: str
    description: str


FIXTURES: tuple[Fixture, ...] = (
    Fixture("basic", 16, 4096, "^64bit,^metadata_csum,^metadata_csum_seed",
            "single-group baseline with a bounded ext4 feature mask"),
    Fixture("multi-group", 128, 1024, "^64bit,^metadata_csum,^metadata_csum_seed",
            "many block groups with 1 KiB blocks"),
    Fixture("nearly-full", 16, 4096, "^64bit,^metadata_csum,^metadata_csum_seed",
            "small free-block count for allocation edge cases"),
    Fixture("fragmented", 16, 4096, "^64bit,^metadata_csum,^metadata_csum_seed",
            "many small files producing non-contiguous extents"),
    Fixture("sparse", 16, 4096, "^64bit,^metadata_csum,^metadata_csum_seed",
            "large sparse file with holes"),
    Fixture("large-address", 16, 4096, "64bit",
            "64bit feature enabled with a fixed high hash seed"),
    Fixture("malformed", 16, 4096, "^64bit,^metadata_csum,^metadata_csum_seed",
            "one corrupted backup superblock for bounded-read tests"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _docker(repo: Path, script: str, description: str) -> str:
    completed = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{repo}:/root/asterinas", "-w", "/root/asterinas",
         DEV_IMAGE, "sh", "-lc", script],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{description} failed: {completed.stderr.strip()}")
    return completed.stdout


def build(repo: Path) -> dict:
    """Builds every fixture in the container and returns a fresh manifest."""
    output_dir = repo / FIXTURE_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    scripts: list[str] = [f"mkdir -p /root/asterinas/{FIXTURE_DIR}; "]
    for fixture in FIXTURES:
        image = FIXTURE_DIR / f"{fixture.name}.ext4"
        staging = f"/tmp/qual-ext4-{fixture.name}"
        scripts.append(
            "set -eu; "
            f"result=$(nix-build --no-out-link test/qualification/adapter/e2fsprogs.nix); "
            "export SOURCE_DATE_EPOCH=0 E2FSPROGS_FAKE_TIME=0; "
            f"rm -rf \"{staging}\"; mkdir -p \"{staging}\"; "
        )
        if fixture.name == "multi-group":
            scripts.append(f"for i in $(seq 1 64); do printf 'group-%03d\\n' \"$i\" > \"{staging}/f$i.txt\"; done; ")
        elif fixture.name == "fragmented":
            scripts.append(f"for i in $(seq 1 180); do printf 'fragment-%03d\\n' \"$i\" > \"{staging}/f$i.txt\"; done; ")
        elif fixture.name == "nearly-full":
            scripts.append(f"dd if=/dev/zero of=\"{staging}/bulk.bin\" bs=1M count=14 status=none; ")
        elif fixture.name == "sparse":
            scripts.append(f"truncate -s 12M \"{staging}/sparse.bin\"; printf 'tail\\n' >> \"{staging}/sparse.bin\"; ")
        else:
            scripts.append(f"printf 'lc14-{fixture.name}\\n' > \"{staging}/marker.txt\"; ")
        uuid = hashlib.sha256(fixture.name.encode()).hexdigest()
        uuid = f"{uuid[0:8]}-{uuid[8:12]}-{uuid[12:16]}-{uuid[16:20]}-{uuid[20:32]}"
        scripts.append(
            f"rm -f \"{image}.tmp\"; truncate -s {fixture.size_mb}M \"{image}.tmp\"; "
            f"\"$result/bin/mkfs.ext4\" -q -F -b {fixture.block_size} -I 128 "
            f"-O {fixture.features} -d \"{staging}\" -U {uuid} "
            "-E hash_seed=11111111-2222-3333-4444-555555555555 "
            f"\"{image}.tmp\" >/dev/null 2>&1; "
        )
        if fixture.name == "malformed":
            scripts.append(
                f"printf '\\x00' | dd of=\"{image}.tmp\" bs=1 seek=4096 conv=notrunc status=none; "
            )
        scripts.append(f"mv \"{image}.tmp\" \"{image}\"; ")
    _docker(repo, "".join(scripts), "ext4 fixture build")

    manifest: dict = {
        "schema": 1,
        "revision": "lc14-ext4-ordered-v1",
        "block_size": BLOCK_SIZE,
        "fixtures": [],
    }
    for fixture in FIXTURES:
        image = repo / FIXTURE_DIR / f"{fixture.name}.ext4"
        features = _inspect_features(repo, image)
        manifest["fixtures"].append({
            "name": fixture.name,
            "size_bytes": image.stat().st_size,
            "sha256": _sha256(image),
            "block_size": fixture.block_size,
            "features": features,
            "description": fixture.description,
        })
    return manifest


def _inspect_features(repo: Path, image: Path) -> list[str]:
    script = (
        "set -eu; "
        "result=$(nix-build --no-out-link test/qualification/adapter/e2fsprogs.nix); "
        f"\"$result/bin/dumpe2fs\" -h /root/asterinas/{image.relative_to(repo)} 2>/dev/null | grep '^Filesystem features:'"
    )
    output = _docker(repo, script, f"feature inspection of {image.name}")
    match = re.search(r"^Filesystem features:\s*(.*)$", output, re.MULTILINE)
    if not match:
        raise RuntimeError(f"no feature mask in dumpe2fs output for {image.name}: {output!r}")
    return sorted(match.group(1).split())


def check(repo: Path) -> tuple[bool, list[str]]:
    """Rebuilds fixtures and compares them against the pinned manifest."""
    expected = json.loads((repo / MANIFEST_PATH).read_text(encoding="utf-8"))
    actual = build(repo)
    failures: list[str] = []
    if expected.get("revision") != actual["revision"]:
        failures.append("fixture revision drift")
    expected_by_name = {item["name"]: item for item in expected["fixtures"]}
    actual_by_name = {item["name"]: item for item in actual["fixtures"]}
    if set(expected_by_name) != set(actual_by_name):
        failures.append("fixture set drift")
    for name in sorted(expected_by_name.keys() & actual_by_name.keys()):
        for field in ("sha256", "size_bytes", "block_size", "features"):
            if expected_by_name[name].get(field) != actual_by_name[name].get(field):
                failures.append(f"{name} {field} drift")
    return not failures, failures
