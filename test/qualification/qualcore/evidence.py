import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import EvidenceError
from .results import Diagnostic
from .util import sha256_bytes


def new_run_id() -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"{stamp}-{uuid.uuid4().hex[:12]}"


def _atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(temporary, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException as primary_error:
        try:
            temporary.unlink()
        except OSError as cleanup_error:
            primary_error.add_note(f"temporary artifact cleanup failed: {cleanup_error}")
        raise


def _artifact_path(root: Path, name: str) -> Path:
    if not name or name.startswith("/") or "\x00" in name:
        raise EvidenceError(f"invalid artifact name {name!r}")
    parts = Path(name).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise EvidenceError(f"invalid artifact name {name!r}")
    return root / "artifacts" / Path(*parts)


@dataclass
class EvidenceBundle:
    root: Path
    run_id: str
    registry: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def create(cls, qualification_root: Path, run_id: str | None = None) -> "EvidenceBundle":
        chosen_run_id = run_id or new_run_id()
        root = qualification_root / chosen_run_id
        if root.exists():
            raise EvidenceError(f"run directory already exists: {root}")
        root.mkdir(mode=0o700, parents=True)
        try:
            os.chmod(root, 0o700)
            for child in ("artifacts", "inputs", "work"):
                (root / child).mkdir(mode=0o700)
            bundle = cls(root, chosen_run_id)
            bundle._write_json(
                root / "run.json",
                {
                    "run_id": chosen_run_id,
                    "created_at": time.time(),
                    "private": True,
                },
            )
            bundle._save_registry()
            return bundle
        except BaseException as error:
            try:
                shutil.rmtree(root)
            except OSError as cleanup_error:
                error.add_note(f"partial run directory cleanup failed: {cleanup_error}")
            raise

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def inputs_dir(self) -> Path:
        return self.root / "inputs"

    @property
    def work_dir(self) -> Path:
        return self.root / "work"

    @property
    def report_path(self) -> Path:
        return self.root / "report.json"

    @property
    def registry_path(self) -> Path:
        return self.root / "artifacts.json"

    def _ensure_mutable(self) -> None:
        if self.report_path.exists():
            raise EvidenceError(f"run {self.run_id} report is already published and immutable")

    def _write_json(self, path: Path, value: Any) -> None:
        data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
        _atomic_write(path, data)

    def _save_registry(self) -> None:
        self._write_json(self.registry_path, {"artifacts": self.registry})

    def register_artifact(self, name: str, data: bytes) -> dict[str, Any]:
        self._ensure_mutable()
        path = _artifact_path(self.root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, data)
        entry = {
            "path": str(path.relative_to(self.root)),
            "sha256": sha256_bytes(data),
            "size": len(data),
        }
        self.registry[name] = entry
        self._save_registry()
        return dict(entry)

    def register_file(self, name: str, source: Path) -> dict[str, Any]:
        return self.register_artifact(name, source.read_bytes())

    def validate_artifacts(self) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        for name, entry in sorted(self.registry.items()):
            path = self.root / entry["path"]
            if not path.exists():
                diagnostics.append(Diagnostic("missing-artifact", name))
                continue
            if path.is_symlink():
                diagnostics.append(Diagnostic("checksum-mismatch", f"{name} is a symlink"))
                continue
            data = path.read_bytes()
            if len(data) != entry["size"] or sha256_bytes(data) != entry["sha256"]:
                diagnostics.append(Diagnostic("checksum-mismatch", name))
        return diagnostics

    def publish_report(self, report: dict[str, Any]) -> None:
        if self.report_path.exists():
            raise EvidenceError(f"run {self.run_id} report is already published and immutable")
        missing = self.validate_artifacts()
        if missing:
            raise EvidenceError("cannot publish report with invalid artifacts: " + "; ".join(item.render() for item in missing))
        self._write_json(self.report_path, report)

    def teardown(self) -> list[str]:
        errors: list[str] = []
        try:
            shutil.rmtree(self.work_dir)
        except FileNotFoundError:
            pass
        except OSError as error:
            errors.append(str(error))
        return errors
