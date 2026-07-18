"""Tests for the modular Spack PR review framework slice."""

from pathlib import Path
from typing import Optional


from spack_pr_review.build import run_task
from spack_pr_review.cli import build_parser
from spack_pr_review.diff_parser import parse_recipe_changes
from spack_pr_review.domain import BuildQueue, BuildTask, PullRequestRef, TaskStatus
from spack_pr_review.external import (
    CommandResult,
    GitHubCLI,
    pull_request_branch_name,
)
from spack_pr_review.planner import build_specs_from_changes
from spack_pr_review.state import StateStore


def test_parse_recipe_changes_versions_and_variants() -> None:
    """Parse added versions, boolean variants, and define-from-variant calls."""

    diff = """
diff --git a/var/spack/repos/builtin/packages/zlib-ng/package.py b/var/spack/repos/builtin/packages/zlib-ng/package.py
--- a/var/spack/repos/builtin/packages/zlib-ng/package.py
+++ b/var/spack/repos/builtin/packages/zlib-ng/package.py
@@ -1,3 +1,5 @@
+    version("2.2.1", sha256="abc")
+    variant("compat", default=True, description="Build compat library")
+    self.define_from_variant("WITH_OPT", "opt")
"""

    changes = parse_recipe_changes(diff)

    assert len(changes) == 1
    assert changes[0].recipe == "zlib-ng"
    assert changes[0].versions == ["2.2.1"]
    assert changes[0].variants == ["compat", "opt"]


def test_parse_recipe_changes_skips_deprecated_versions() -> None:
    """Exclude deprecated versions from planned build versions."""

    diff = """
diff --git a/var/spack/repos/builtin/packages/example/package.py b/var/spack/repos/builtin/packages/example/package.py
+++ b/var/spack/repos/builtin/packages/example/package.py
@@ -1,3 +1,5 @@
+    version("1.0", sha256="abc", deprecated=True)
+    version("2.0", sha256="def")
"""

    changes = parse_recipe_changes(diff)

    assert changes[0].versions == ["2.0"]
    assert changes[0].deprecated_versions == ["1.0"]


def test_parse_recipe_changes_supports_spack_repo_builtin_path() -> None:
    """Parse recipe paths from the newer repos/spack_repo/builtin layout."""

    diff = """\
diff --git a/repos/spack_repo/builtin/packages/intel_oneapi_ccl/package.py \
b/repos/spack_repo/builtin/packages/intel_oneapi_ccl/package.py
--- a/repos/spack_repo/builtin/packages/intel_oneapi_ccl/package.py
+++ b/repos/spack_repo/builtin/packages/intel_oneapi_ccl/package.py
@@ -28,6 +28,13 @@ class IntelOneapiCcl(IntelOneApiLibraryPackage):
+    version(
+        "2022.1.0",
+        url="https://example.invalid/intel-oneccl.sh",
+        sha256="abc",
+        expand=False,
+    )
"""

    changes = parse_recipe_changes(diff)
    specs = build_specs_from_changes(changes)

    assert len(changes) == 1
    assert changes[0].recipe == "intel_oneapi_ccl"
    assert changes[0].versions == ["2022.1.0"]
    assert specs[0].spec == "intel-oneapi-ccl@=2022.1.0"
    assert specs[0].recipe == "intel_oneapi_ccl"


def test_build_specs_from_changes_keeps_reasons() -> None:
    """Plan specs with stable reasons for changed versions and variants."""

    path = "var/spack/repos/builtin/packages/foo/package.py"
    changes = parse_recipe_changes(
        f"""
diff --git a/{path} b/{path}
+++ b/{path}
+    version("1.2.3", sha256="abc")
+    variant("bar", default=False, description="Enable bar")
"""
    )

    specs = build_specs_from_changes(changes)

    assert [spec.spec for spec in specs] == ["foo@=1.2.3", "foo", "foo+bar"]
    assert specs[0].reason == "changed version"
    assert specs[2].reason == "changed boolean variant bar"


def test_state_store_round_trips_queue(tmp_path: Path) -> None:
    """Persist and reload a build queue through the state store."""

    store = StateStore(state_dir=tmp_path / "state", cache_dir=tmp_path / "cache")
    queue = BuildQueue(
        schema_version=1,
        pull_request=PullRequestRef(number=123, title="Example"),
        tasks=[BuildTask(id="0001-zlib-ng", build_spec=_spec("zlib-ng", "2.2.1"))],
    )

    queue_path = store.write_queue(queue)
    loaded = store.read_queue(123)

    assert queue_path.name == "queue.yaml"
    assert loaded.pull_request.number == 123
    assert loaded.tasks[0].build_spec.spec == "zlib-ng@=2.2.1"


def test_state_store_claims_next_task_with_lease(tmp_path: Path) -> None:
    """Claim the first pending task and record its worker lease."""

    store = StateStore(state_dir=tmp_path / "state", cache_dir=tmp_path / "cache")
    queue = BuildQueue(
        schema_version=1,
        pull_request=PullRequestRef(number=456),
        tasks=[
            BuildTask(id="0001-foo", build_spec=_spec("foo", "1.0")),
            BuildTask(id="0002-foo", build_spec=_spec("foo", "2.0")),
        ],
    )
    store.write_queue(queue)

    claimed = store.claim_next_task(456, owner="worker-a", lease_seconds=30)
    loaded = store.read_queue(456)

    assert claimed is not None
    assert claimed.id == "0001-foo"
    assert loaded.tasks[0].status == TaskStatus.RUNNING
    assert loaded.tasks[0].lease_owner == "worker-a"
    assert loaded.tasks[0].attempts == 1
    assert loaded.tasks[1].status == TaskStatus.PENDING


def test_dry_run_task_writes_result_and_finishes_task(tmp_path: Path) -> None:
    """Dry-run builds should write logs, results, and finish queue tasks."""

    store = StateStore(state_dir=tmp_path / "state", cache_dir=tmp_path / "cache")
    queue = BuildQueue(
        schema_version=1,
        pull_request=PullRequestRef(number=789),
        tasks=[BuildTask(id="0001-foo", build_spec=_spec("foo", "1.0"))],
    )
    store.write_queue(queue)
    task = store.claim_next_task(789, owner="worker-a")

    assert task is not None
    result = run_task(789, task, store, dry_run=True)
    loaded = store.read_queue(789)

    assert result.status == TaskStatus.SKIPPED
    assert Path(result.log_path).read_text(encoding="utf-8").startswith("Dry run:")
    assert loaded.tasks[0].status == TaskStatus.SKIPPED
    assert loaded.tasks[0].lease_owner is None
    assert loaded.tasks[0].result_file is not None


def test_state_store_requeues_running_tasks(tmp_path: Path) -> None:
    """Move interrupted running tasks back to pending."""

    store = StateStore(state_dir=tmp_path / "state", cache_dir=tmp_path / "cache")
    queue = BuildQueue(
        schema_version=1,
        pull_request=PullRequestRef(number=790),
        tasks=[BuildTask(id="0001-foo", build_spec=_spec("foo", "1.0"))],
    )
    store.write_queue(queue)
    assert store.claim_next_task(790, owner="worker-a") is not None

    changed = store.requeue_tasks(790, TaskStatus.RUNNING)
    loaded = store.read_queue(790)

    assert changed == 1
    assert loaded.tasks[0].status == TaskStatus.PENDING
    assert loaded.tasks[0].lease_owner is None


def test_checkout_uses_pr_numbered_branch_without_source_branch_collision() -> None:
    """Checkout should use a PR-numbered local branch by default."""

    runner = FakeRunner(existing_branches=set(), current_branch="develop")
    gh = GitHubCLI(runner=runner)

    result = gh.checkout("5342")

    assert result.ok
    assert pull_request_branch_name("5342") == "pr-5342"
    assert runner.commands == [
        ["git", "branch", "--show-current"],
        ["git", "show-ref", "--verify", "--quiet", "refs/heads/pr-5342"],
        ["gh", "pr", "checkout", "5342", "--branch", "pr-5342"],
    ]


def test_checkout_archives_existing_local_branch_before_checkout() -> None:
    """Checkout should archive an existing local PR branch before retrying."""

    runner = FakeRunner(existing_branches={"pr-5342"}, current_branch="develop")
    gh = GitHubCLI(runner=runner)

    result = gh.checkout("5342")

    assert result.ok
    rename = runner.commands[3]
    assert rename[:4] == ["git", "branch", "-m", "pr-5342"]
    assert rename[4].startswith("pr-5342.")
    assert runner.commands[-1] == [
        "gh",
        "pr",
        "checkout",
        "5342",
        "--branch",
        "pr-5342",
    ]


def test_run_command_accepts_omitted_pr_number() -> None:
    """The run command should allow resolving the PR from the current branch."""

    args = build_parser().parse_args(["run", "--dry-run", "--no-checkout"])

    assert args.pr is None
    assert args.dry_run
    assert args.no_checkout


def test_checkout_skips_work_when_already_on_local_pr_branch() -> None:
    """Checkout should not archive or re-checkout the active local PR branch."""

    runner = FakeRunner(existing_branches={"pr-5342"}, current_branch="pr-5342")
    gh = GitHubCLI(runner=runner)

    result = gh.checkout("5342")

    assert result.ok
    assert result.stdout == "Already on pr-5342"
    assert runner.commands == [["git", "branch", "--show-current"]]


def test_current_pr_number_comes_from_current_pr_url() -> None:
    """Read the current PR number from the last path segment of gh's PR URL."""

    runner = FakeRunner(
        existing_branches=set(), current_pr_url="https://github.com/spack/spack/pull/5594"
    )
    gh = GitHubCLI(runner=runner)

    assert gh.current_pr_number() == 5594


class FakeRunner:  # pylint: disable=too-few-public-methods
    """Minimal command runner for checkout tests."""

    def __init__(
        self,
        existing_branches: set[str],
        current_branch: str = "develop",
        current_pr_url: str = "https://github.com/spack/spack/pull/1",
    ):
        """Create a fake runner with a set of existing local branch names."""

        self.existing_branches = existing_branches
        self.current_branch = current_branch
        self.current_pr_url = current_pr_url
        self.commands: list[list[str]] = []

    def run(
        self,
        command: list[str],
        *,
        cwd: Optional[str] = None,
        timeout: Optional[int] = 240,
    ) -> CommandResult:
        """Record a command and return the configured fake result."""

        del cwd, timeout
        self.commands.append(command)
        if command == ["git", "branch", "--show-current"]:
            return _command_result(command, 0, stdout=self.current_branch)
        if command == ["gh", "pr", "view", "--json", "url", "-q", ".url"]:
            return _command_result(command, 0, stdout=self.current_pr_url)
        if command[:4] == ["git", "show-ref", "--verify", "--quiet"]:
            branch = command[4].removeprefix("refs/heads/")
            return _command_result(command, 0 if branch in self.existing_branches else 1)
        if command[:3] == ["git", "branch", "-m"]:
            self.existing_branches.remove(command[3])
            self.existing_branches.add(command[4])
            return _command_result(command, 0)
        return _command_result(command, 0, stdout="checked out")


def _command_result(command: list[str], exit_code: int, stdout: str = "") -> CommandResult:
    return CommandResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout,
        stderr="",
        started_at="2026-07-17T00:00:00+00:00",
        ended_at="2026-07-17T00:00:00+00:00",
    )


def _spec(recipe: str, version: str):
    path = f"var/spack/repos/builtin/packages/{recipe}/package.py"
    return build_specs_from_changes(
        parse_recipe_changes(
            f"""
diff --git a/{path} b/{path}
+++ b/{path}
+    version("{version}", sha256="abc")
"""
        )
    )[0]
