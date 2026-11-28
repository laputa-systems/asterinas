# SPDX-License-Identifier: MPL-2.0

import base64
import json
import shutil
import subprocess
from pathlib import Path

from .evidence import EvidenceBundle
from .lock import DEV_IMAGE


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
    if fsck.returncode not in {0, 4} or marker.returncode != 0:
        raise ValueError(f"{label}: image inspection failed to run (fsck {fsck.returncode}, debugfs {marker.returncode})")
    if fsck.returncode == 0 and geometry.returncode != 0:
        raise ValueError(f"{label}: dumpe2fs failed to read a clean image")
    return fsck.returncode, marker.stdout
