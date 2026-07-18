"""Small adapters around external command-line tools."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class CommandResult:
    """Structured result of a command invocation."""

    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    started_at: str
    ended_at: str

    @property
    def ok(self) -> bool:
        """Return whether the command succeeded."""

        return self.exit_code == 0


class CommandRunner:  # pylint: disable=too-few-public-methods
    """Run noninteractive commands and keep structured output."""

    def run(
        self,
        command: List[str],
        *,
        cwd: Optional[str] = None,
        timeout: Optional[int] = 240,
    ) -> CommandResult:
        """Run a command and return a structured result."""

        started_at = utc_now()
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        ended_at = utc_now()
        return CommandResult(
            command=command,
            exit_code=completed.returncode,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
            started_at=started_at,
            ended_at=ended_at,
        )


class GitHubCLI:
    """Adapter for read-only GitHub CLI operations."""

    PR_FIELDS = [
        "number",
        "url",
        "title",
        "author",
        "state",
        "isDraft",
        "comments",
        "reviews",
        "latestReviews",
        "reviewRequests",
        "labels",
        "assignees",
        "mergeStateStatus",
        "statusCheckRollup",
        "files",
        "headRefName",
        "baseRefName",
    ]

    def __init__(self, runner: Optional[CommandRunner] = None):
        self.runner = runner or CommandRunner()

    def pr_view(self, number: str) -> Dict[str, Any]:
        """Return normalized JSON data for a pull request."""

        fields = ",".join(self.PR_FIELDS)
        result = self.runner.run(["gh", "pr", "view", number, "--json", fields])
        if not result.ok:
            raise ChildProcessError(result.stderr or result.stdout)
        return json.loads(result.stdout)

    def pr_diff(self, number: Optional[str] = None) -> str:
        """Return the diff for a pull request or the currently checked out PR."""

        command = ["gh", "pr", "diff"]
        if number:
            command.append(number)
        result = self.runner.run(command)
        if not result.ok:
            raise ChildProcessError(result.stderr or result.stdout)
        return result.stdout

    def current_pr_number(self) -> int:
        """Return the number of the currently checked out pull request."""

        result = self.runner.run(["gh", "pr", "view", "--json", "url", "-q", ".url"])
        if not result.ok:
            raise ChildProcessError(result.stderr or result.stdout)
        try:
            return int(result.stdout.rstrip("/").rsplit("/", 1)[-1])
        except ValueError as error:
            raise ChildProcessError(
                f"Could not parse PR number from URL: {result.stdout}"
            ) from error

    def checkout(self, number: str, branch: Optional[str] = None) -> CommandResult:
        """Checkout a pull request into a collision-safe local branch."""

        local_branch = branch or pull_request_branch_name(number)
        if self.current_branch() == local_branch:
            return CommandResult(
                command=["git", "branch", "--show-current"],
                exit_code=0,
                stdout=f"Already on {local_branch}",
                stderr="",
                started_at=utc_now(),
                ended_at=utc_now(),
            )
        archived_branch = self.archive_existing_branch(local_branch)
        if archived_branch:
            print(f"Renamed existing local branch {local_branch} to {archived_branch}")
        result = self.runner.run(
            ["gh", "pr", "checkout", number, "--branch", local_branch], timeout=None
        )
        if not result.ok:
            raise ChildProcessError(result.stderr or result.stdout)
        return result

    def current_branch(self) -> str:
        """Return the current Git branch name, or an empty string outside a branch."""

        result = self.runner.run(["git", "branch", "--show-current"])
        return result.stdout if result.ok else ""

    def archive_existing_branch(self, branch: str) -> Optional[str]:
        """Rename an existing local branch out of the way before checkout."""

        exists = self.runner.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"]
        )
        if exists.ok:
            archived_branch = self.available_archive_branch_name(branch)
            result = self.runner.run(["git", "branch", "-m", branch, archived_branch])
            if not result.ok:
                raise ChildProcessError(result.stderr or result.stdout)
            return archived_branch
        return None

    def available_archive_branch_name(self, branch: str) -> str:
        """Return an archive branch name that does not already exist locally."""

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        candidate = f"{branch}.{timestamp}"
        suffix = 2
        while self.runner.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{candidate}"]
        ).ok:
            candidate = f"{branch}.{timestamp}.{suffix}"
            suffix += 1
        return candidate

    def list_review_candidates(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List conservative Spack PR review candidates."""

        search = " ".join(
            [
                "repo:spack/spack",
                "is:open",
                "review:required",
                "draft:false",
                "no:assignee",
                "-status:failure",
                "-reviewed-by:@me",
                "-review:changes_requested",
                "-label:changes-requested",
                "-label:waiting-on-maintainer",
                "-label:waiting-on-reviewers",
                "-label:waiting-on-dependency",
                "-label:question",
            ]
        )
        result = self.runner.run(
            [
                "gh",
                "pr",
                "list",
                "--repo",
                "spack/spack",
                "--limit",
                str(limit),
                "--search",
                search,
                "--json",
                "number,title,author,url,comments,labels,statusCheckRollup",
            ]
        )
        if not result.ok:
            raise ChildProcessError(result.stderr or result.stdout)
        return json.loads(result.stdout)


def utc_now() -> str:
    """Return a compact UTC ISO-8601 timestamp."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def pull_request_branch_name(number: str) -> str:
    """Return the default local branch name for a pull request checkout."""

    return f"pr-{number}"
