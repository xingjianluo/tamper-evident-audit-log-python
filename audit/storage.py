"""Durable append-only JSONL storage with cross-process locking."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading

from audit.models import AuditRecord, Checkpoint
from audit.normalization import canonicalize_stored

LOG_NAME = "audit.log"
CHECKPOINT_NAME = "audit.checkpoint"


class Storage:
    """Append-only log on disk.

    A single ``threading.Lock`` serializes writers in this process and a
    ``fcntl.flock`` on a sidecar file serializes across processes. The
    same lock guards append *and* prune-rewrite, so a write arriving
    during a prune cannot be deleted or reordered.
    """

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.log_path = os.path.join(self.data_dir, LOG_NAME)
        self.checkpoint_path = os.path.join(self.data_dir, CHECKPOINT_NAME)
        self.lock_path = os.path.join(self.data_dir, ".audit.lock")
        self._thread_lock = threading.Lock()
        # Touch files so readers never see a missing path.
        for path in (self.log_path, self.checkpoint_path, self.lock_path):
            if not os.path.exists(path):
                with open(path, "a"):
                    pass

    @property
    def log_file(self) -> str:
        return self.log_path

    def _read_checkpoint(self) -> Checkpoint | None:
        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as fh:
                text = fh.read().strip()
        except FileNotFoundError:
            return None
        if not text:
            return None
        data = json.loads(text)
        return Checkpoint(
            seq=int(data["seq"]), id=str(data["id"]),
            record_hash=str(data["record_hash"]))

    def load_all(self) -> tuple[Checkpoint | None, list[AuditRecord]]:
        records: list[AuditRecord] = []
        with open(self.log_path, "r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    records.append(canonicalize_stored(raw))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"corrupt line {line_no} in {self.log_path}: {exc}"
                    ) from exc
        return self._read_checkpoint(), records

    def append(self, record: AuditRecord) -> None:
        """Durably append a single record; fsync before releasing."""
        line = json.dumps(record.to_dict(), ensure_ascii=False,
                          separators=(",", ":")) + "\n"
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    def _atomic_write(self, path: str, text: str) -> None:
        directory = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise

    def rewrite(self, checkpoint: Checkpoint,
                records: list[AuditRecord]) -> None:
        """Atomically replace the log with the retained records and the
        new checkpoint anchor (caller holds the lock)."""
        body = "".join(
            json.dumps(r.to_dict(), ensure_ascii=False,
                       separators=(",", ":")) + "\n"
            for r in records)
        cp_text = json.dumps(checkpoint.to_dict(), ensure_ascii=False,
                             separators=(",", ":"))
        self._atomic_write(self.log_path, body)
        self._atomic_write(self.checkpoint_path, cp_text)

    @contextlib.contextmanager
    def locked(self):
        """Exclusive in-process + cross-process critical section."""
        with self._thread_lock:
            with open(self.lock_path, "r+") as lock_fh:
                import fcntl
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
