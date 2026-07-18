"""Typed domain models for Spack PR review workflows."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TaskStatus(str, Enum):
    """Lifecycle states for a build task."""

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class PullRequestRef:
    """Small stable reference to a pull request."""

    number: int
    url: str = ""
    title: str = ""
    author: str = ""

    @classmethod
    def from_gh_json(cls, data: Dict[str, Any]) -> "PullRequestRef":
        """Create a pull request reference from `gh pr view --json` data."""

        author = data.get("author") or {}
        return cls(
            number=int(data["number"]),
            url=str(data.get("url", "")),
            title=str(data.get("title", "")),
            author=str(author.get("login", "")),
        )

    def to_data(self) -> Dict[str, Any]:
        """Return stable serializable data."""

        return asdict(self)


@dataclass(frozen=True)
class RecipeChange:
    """Recipe-level changes detected from a pull request diff."""

    recipe: str
    path: str
    versions: List[str] = field(default_factory=list)
    variants: List[str] = field(default_factory=list)
    deprecated_versions: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_data(self) -> Dict[str, Any]:
        """Return stable serializable data."""

        return asdict(self)


@dataclass(frozen=True)
class BuildSpec:
    """A concrete Spack spec that should be verified."""

    spec: str
    recipe: str
    reason: str
    source: str = "diff"

    def to_data(self) -> Dict[str, Any]:
        """Return stable serializable data."""

        return asdict(self)


@dataclass
class BuildTask:
    """Queue entry for a build spec."""

    id: str
    build_spec: BuildSpec
    status: TaskStatus = TaskStatus.PENDING
    lease_owner: Optional[str] = None
    lease_expires_at: Optional[str] = None
    attempts: int = 0
    result_file: Optional[str] = None

    def to_data(self) -> Dict[str, Any]:
        """Return stable serializable data."""

        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_data(cls, data: Dict[str, Any]) -> "BuildTask":
        """Create a build task from serialized data."""

        return cls(
            id=str(data["id"]),
            build_spec=BuildSpec(**data["build_spec"]),
            status=TaskStatus(data.get("status", TaskStatus.PENDING.value)),
            lease_owner=data.get("lease_owner"),
            lease_expires_at=data.get("lease_expires_at"),
            attempts=int(data.get("attempts", 0)),
            result_file=data.get("result_file"),
        )


@dataclass
class BuildQueue:
    """Persistent queue of build tasks for one or more pull requests."""

    schema_version: int
    pull_request: PullRequestRef
    tasks: List[BuildTask] = field(default_factory=list)

    def to_data(self) -> Dict[str, Any]:
        """Return stable serializable data."""

        return {
            "schema_version": self.schema_version,
            "pull_request": self.pull_request.to_data(),
            "tasks": [task.to_data() for task in self.tasks],
        }

    @classmethod
    def from_data(cls, data: Dict[str, Any]) -> "BuildQueue":
        """Create a build queue from serialized data."""

        return cls(
            schema_version=int(data["schema_version"]),
            pull_request=PullRequestRef(**data["pull_request"]),
            tasks=[BuildTask.from_data(task) for task in data.get("tasks", [])],
        )


@dataclass(frozen=True)
class BuildResult:  # pylint: disable=too-many-instance-attributes
    """Recorded outcome of one build attempt."""

    task_id: str
    spec: str
    status: TaskStatus
    command: List[str]
    exit_code: int
    started_at: str
    ended_at: str
    log_path: str = ""
    error_summary: str = ""
    submitted: bool = False

    def to_data(self) -> Dict[str, Any]:
        """Return stable serializable data."""

        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_data(cls, data: Dict[str, Any]) -> "BuildResult":
        """Create a build result from serialized data."""

        return cls(
            task_id=str(data["task_id"]),
            spec=str(data["spec"]),
            status=TaskStatus(data["status"]),
            command=list(data.get("command", [])),
            exit_code=int(data.get("exit_code", 0)),
            started_at=str(data.get("started_at", "")),
            ended_at=str(data.get("ended_at", "")),
            log_path=str(data.get("log_path", "")),
            error_summary=str(data.get("error_summary", "")),
            submitted=bool(data.get("submitted", False)),
        )
