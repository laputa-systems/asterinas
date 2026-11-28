# SPDX-License-Identifier: MPL-2.0

import base64
import json
import shutil
import subprocess
from pathlib import Path

from .evidence import EvidenceBundle
from .lock import DEV_IMAGE
from .util import sha256_bytes


def inspect_ext_marker(repo: Path, bundle: EvidenceBundle, label: str, image: Path) -> tuple[int, bytes]:
    inspection = bundle.work_dir / label
    inspection.mkdir()
    image_hash = bundle.register_file(f"{label}/image.img", image)["sha256"]
    tools: list[dict[str, object]] = []
    results: list[subprocess.CompletedProcess[bytes]] = []
    for tool, args in (
        ("dumpe2fs", ["-h"]),
        ("e2fsck", ["-fn"]),
        ("debugfs", ["-R", "cat /marker.txt"]),
    ):
        clone = inspection / f"{tool}.img"
        shutil.copyfile(image, clone)
        command = [
            "docker", "run", "--rm", "-v", f"{repo}:/root/asterinas:ro",
            "-v", "asterinas-qualification-nix:/nix", "-w", "/root/asterinas", DEV_IMAGE,
            "sh", "-ceu",
            'result=$(nix-build --no-out-link test/qualification/adapter/e2fsprogs.nix); '
            'printf "e2fsprogs=%s\\n" "$result" >&2; tool=$1; shift; exec "$result/bin/$tool" "$@"',
            "inspection", tool, *args, str(clone.relative_to(repo)),
        ]
        result = subprocess.run(command, capture_output=True, check=False, timeout=120)
        tools.append({
            "argv": command,
            "returncode": result.returncode,
            "stdout_base64": base64.b64encode(result.stdout).decode("ascii"),
            "stderr": result.stderr.decode("utf-8", errors="replace"),
        })
        results.append(result)
    report = {"image_sha256": image_hash, "tools": tools}
    bundle.register_artifact(f"{label}/inspection.json", (json.dumps(report, indent=2) + "\n").encode())
    geometry, fsck, marker = results
    if fsck.returncode not in {0, 4, 12} or marker.returncode != 0:
        raise ValueError(f"{label}: image inspection failed to run (fsck {fsck.returncode}, debugfs {marker.returncode})")
    if fsck.returncode == 0 and geometry.returncode != 0:
        raise ValueError(f"{label}: dumpe2fs failed to read a clean image")
    return fsck.returncode, marker.stdout


def verify_pinned_replay(
    repo: Path, bundle: EvidenceBundle, label: str, *, seed: Path, log: Path, expected: Path, cut: int,
) -> bool:
    replay = bundle.work_dir / f"{label}-pinned-replay.img"
    shutil.copyfile(seed, replay)
    command = [
        "docker", "run", "--rm", "-v", f"{repo}:/root/asterinas:ro", "-v", f"{replay}:/replay.img",
        "-v", "asterinas-qualification-nix:/nix", "-w", "/root/asterinas", DEV_IMAGE,
        "sh", "-ceu",
        'result=$(nix-build --no-out-link test/qualification/adapter/replay-log.nix); '
        'printf "replay-log=%s\\n" "$result" >&2; '
        'if [ "$2" -gt 0 ]; then exec "$result/bin/replay-log" --log "$1" --limit "$2" --replay /replay.img; fi',
        "replay", str(log.relative_to(repo)), str(cut),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    actual_hash = sha256_bytes(replay.read_bytes())
    expected_hash = sha256_bytes(expected.read_bytes())
    report = {
        "argv": command, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
        "cut_after_records": cut, "replay_sha256": actual_hash, "expected_sha256": expected_hash,
    }
    bundle.register_artifact(f"{label}/pinned-replay.json", (json.dumps(report, indent=2) + "\n").encode())
    return result.returncode == 0 and actual_hash == expected_hash
