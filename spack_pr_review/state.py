"""XDG-backed state storage for queues, results, logs, and reports."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import fcntl
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from .domain import BuildQueue, BuildResult, BuildTask, TaskStatus

APP_NAME = "gh-spack-pr"


class StateStore:
    """Persist state files under XDG state/cache directories."""

    def __init__(self, state_dir: Optional[Path] = None, cache_dir: Optional[Path] = None):
        self.root = state_dir or xdg_state_home() / APP_NAME
        self.cache_root = cache_dir or xdg_cache_home() / APP_NAME

    def ensure(self) -> None:
        """Create state and cache roots."""

        self.root.mkdir(parents=True, exist_ok=True)
        self.cache_root.mkdir(parents=True, exist_ok=True)

    def pr_dir(self, number: int) -> Path:
        """Return the state directory for a pull request."""

        return self.root / "prs" / str(number)

    def queue_path(self, number: int) -> Path:
        """Return the queue path for a pull request."""

        return self.pr_dir(number) / "queue.yaml"

    def log_dir(self, number: int) -> Path:
        """Return the cache directory for pull request logs."""

        return self.cache_root / "prs" / str(number) / "logs"

    def reset_pr(self, number: int) -> None:
        """Remove persisted state and cache data for a pull request."""

        shutil.rmtree(self.pr_dir(number), ignore_errors=True)
        shutil.rmtree(self.cache_root / "prs" / str(number), ignore_errors=True)

    def write_queue(self, queue: BuildQueue) -> Path:
        """Persist a build queue."""

        path = self.queue_path(queue.pull_request.number)
        write_mapping(path, queue.to_data())
        return path

    def read_queue(self, number: int) -> BuildQueue:
        """Read a persisted build queue."""

        return BuildQueue.from_data(read_mapping(self.queue_path(number)))

    def claim_next_task(
        self, number: int, owner: str, lease_seconds: int = 3600
    ) -> Optional[BuildTask]:
        """Claim the next pending or expired task for a worker."""

        queue_path = self.queue_path(number)
        with locked(queue_path.with_suffix(queue_path.suffix + ".lock")):
            queue = BuildQueue.from_data(read_mapping(queue_path))
            now = _utc_now()
            expires_at = (now + timedelta(seconds=lease_seconds)).replace(microsecond=0)
            for task in queue.tasks:
                if not _claimable(task, now):
                    continue
                task.status = TaskStatus.RUNNING
                task.lease_owner = owner
                task.lease_expires_at = expires_at.isoformat()
                task.attempts += 1
                _write_mapping_unlocked(queue_path, queue.to_data())
                return task
        return None

    def finish_task(
        self,
        number: int,
        task_id: str,
        status: TaskStatus,
        result_file: Optional[str] = None,
    ) -> None:
        """Mark a claimed task as finished and clear its lease."""

        queue_path = self.queue_path(number)
        with locked(queue_path.with_suffix(queue_path.suffix + ".lock")):
            queue = BuildQueue.from_data(read_mapping(queue_path))
            for task in queue.tasks:
                if task.id != task_id:
                    continue
                task.status = status
                task.lease_owner = None
                task.lease_expires_at = None
                task.result_file = result_file
                _write_mapping_unlocked(queue_path, queue.to_data())
                return
        raise KeyError(f"Task {task_id} not found in PR {number} queue")

    def requeue_tasks(self, number: int, status: TaskStatus) -> int:
        """Move tasks with a given status back to pending and clear their leases."""

        changed = 0
        queue_path = self.queue_path(number)
        with locked(queue_path.with_suffix(queue_path.suffix + ".lock")):
            queue = BuildQueue.from_data(read_mapping(queue_path))
            for task in queue.tasks:
                if task.status != status:
                    continue
                task.status = TaskStatus.PENDING
                task.lease_owner = None
                task.lease_expires_at = None
                task.result_file = None
                changed += 1
            if changed:
                _write_mapping_unlocked(queue_path, queue.to_data())
        return changed

    def write_result(self, number: int, result: BuildResult) -> Path:
        """Persist a build result."""

        path = self.pr_dir(number) / "results" / f"{result.task_id}.yaml"
        write_mapping(path, result.to_data())
        return path


def xdg_state_home() -> Path:
    """Return the XDG state home directory."""

    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))


def xdg_cache_home() -> Path:
    """Return the XDG cache home directory."""

    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))


def write_mapping(path: Path, data: Dict[str, Any]) -> None:
    """Atomically write YAML-compatible JSON mapping data."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with locked(path.with_suffix(path.suffix + ".lock")):
        _write_mapping_unlocked(path, data)


def read_mapping(path: Path) -> Dict[str, Any]:
    """Read a YAML-compatible JSON mapping."""

    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _write_mapping_unlocked(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
        json.dump(data, tmp, indent=2, sort_keys=True)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def _claimable(task: BuildTask, now: datetime) -> bool:
    if task.status == TaskStatus.PENDING:
        return True
    if task.status != TaskStatus.RUNNING or not task.lease_expires_at:
        return False
    return _parse_datetime(task.lease_expires_at) <= now


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@contextmanager
def locked(path: Path) -> Iterator[None]:
    """Use a POSIX advisory lock for a state file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
