"""Command-line entry point for the modular Spack PR review framework."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from .build import default_owner, print_result, run_available_tasks, run_task
from .diff_parser import parse_recipe_changes
from .domain import BuildQueue, BuildResult, BuildTask, PullRequestRef, TaskStatus
from .external import GitHubCLI
from .planner import build_specs_from_changes
from .reports import generate_markdown_report
from .state import StateStore


def main(argv: Optional[List[str]] = None) -> int:
    """Run the modular CLI."""

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ChildProcessError as error:
        print(error, file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level parser."""

    parser = argparse.ArgumentParser(description="Review and build Spack pull requests.")
    parser.add_argument("--state-dir", type=Path, help="Override the XDG state directory.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prs = subparsers.add_parser("prs", help="Discover and inspect pull requests.")
    prs_subparsers = prs.add_subparsers(dest="prs_command", required=True)
    prs_list = prs_subparsers.add_parser("list", help="List conservative review candidates.")
    prs_list.add_argument("--limit", type=int, default=20)
    prs_list.set_defaults(func=list_prs)

    checkout = subparsers.add_parser("checkout", help="Checkout a PR branch locally.")
    checkout.add_argument("pr", help="PR number to checkout.")
    checkout.add_argument("--branch", help="Local branch name. Defaults to a PR-numbered branch.")
    checkout.set_defaults(func=checkout_pr)

    analyze = subparsers.add_parser("analyze", help="Analyze a PR diff and print recipe changes.")
    analyze.add_argument("pr", nargs="?", help="PR number. Defaults to checked out PR.")
    analyze.set_defaults(func=analyze_diff)

    plan = subparsers.add_parser("plan-builds", help="Generate a build queue from a PR diff.")
    plan.add_argument("pr", type=int, help="PR number to plan.")
    plan.add_argument("--title", default="", help="Optional PR title for queue metadata.")
    plan.add_argument("--author", default="", help="Optional PR author for queue metadata.")
    plan.add_argument(
        "--keep-results", action="store_true", help="Do not clear old results/logs first."
    )
    plan.set_defaults(func=plan_builds)

    queue = subparsers.add_parser("queue", help="Inspect and claim build tasks.")
    queue_subparsers = queue.add_subparsers(dest="queue_command", required=True)
    queue_status = queue_subparsers.add_parser("status", help="Show task counts for a PR queue.")
    queue_status.add_argument("pr", type=int, help="PR number.")
    queue_status.set_defaults(func=queue_status_command)
    queue_claim = queue_subparsers.add_parser("claim", help="Claim the next task for this worker.")
    queue_claim.add_argument("pr", type=int, help="PR number.")
    queue_claim.add_argument("--owner", required=True, help="Worker name for the lease.")
    queue_claim.add_argument("--lease-seconds", type=int, default=3600)
    queue_claim.set_defaults(func=queue_claim_command)
    queue_requeue = queue_subparsers.add_parser("requeue", help="Move tasks back to pending.")
    queue_requeue.add_argument("pr", type=int, help="PR number.")
    queue_requeue.add_argument(
        "--status",
        choices=[status.value for status in TaskStatus],
        default=TaskStatus.RUNNING.value,
        help="Task status to requeue.",
    )
    queue_requeue.set_defaults(func=queue_requeue_command)

    state = subparsers.add_parser("state", help="Inspect local framework state.")
    state_subparsers = state.add_subparsers(dest="state_command", required=True)
    doctor = state_subparsers.add_parser("doctor", help="Show resolved XDG state/cache locations.")
    doctor.set_defaults(func=state_doctor)

    build = subparsers.add_parser("build", help="Run queued Spack build tasks.")
    build_subparsers = build.add_subparsers(dest="build_command", required=True)
    build_next = build_subparsers.add_parser("next", help="Claim and run one queued task.")
    add_build_arguments(build_next, include_jobs=False)
    build_next.set_defaults(func=build_next_command)
    build_all = build_subparsers.add_parser("all", help="Run queued tasks until none remain.")
    add_build_arguments(build_all, include_jobs=True)
    build_all.set_defaults(func=build_all_command)

    run = subparsers.add_parser("run", help="Checkout, plan, and run a PR build queue.")
    run.add_argument(
        "pr",
        nargs="?",
        type=int,
        help="PR number to checkout, plan, and build. Defaults to the current PR.",
    )
    run.add_argument("--branch", help="Local branch name. Defaults to a PR-numbered branch.")
    run.add_argument("--owner", default=None, help="Worker name for task leases.")
    run.add_argument("--spack", default="spack", help="Path to the Spack executable.")
    run.add_argument(
        "--dry-run", action="store_true", help="Plan and claim tasks without building."
    )
    run.add_argument("--no-checkout", action="store_true", help="Do not run gh pr checkout first.")
    run.add_argument(
        "--timeout", type=int, default=0, help="Build timeout in seconds; 0 disables it."
    )
    run.add_argument(
        "--jobs", type=int, default=2, help="Number of package builds to run in parallel."
    )
    run.set_defaults(func=run_pr_command)

    return parser


def add_build_arguments(parser: argparse.ArgumentParser, *, include_jobs: bool) -> None:
    """Add shared build worker arguments."""

    parser.add_argument("pr", type=int, help="PR number.")
    parser.add_argument("--owner", default=None, help="Worker name for the lease.")
    parser.add_argument("--spack", default="spack", help="Path to the Spack executable.")
    parser.add_argument("--dry-run", action="store_true", help="Claim tasks without building.")
    parser.add_argument("--lease-seconds", type=int, default=3600)
    parser.add_argument(
        "--timeout", type=int, default=0, help="Build timeout in seconds; 0 disables it."
    )
    if include_jobs:
        parser.add_argument("--jobs", type=int, default=2, help="Parallel package builds.")


def list_prs(args: argparse.Namespace) -> int:
    """List review candidate PRs."""

    prs = GitHubCLI().list_review_candidates(limit=args.limit)
    for pr_data in prs:
        author = (pr_data.get("author") or {}).get("login", "")
        print(f"#{pr_data['number']} {pr_data.get('title', '')} ({author})")
    return 0


def checkout_pr(args: argparse.Namespace) -> int:
    """Checkout a pull request locally."""

    result = GitHubCLI().checkout(str(args.pr), branch=args.branch)
    if result.stdout:
        print(result.stdout)
    return 0


def analyze_diff(args: argparse.Namespace) -> int:
    """Analyze a PR diff and print detected recipe changes."""

    diff = GitHubCLI().pr_diff(args.pr)
    changes = parse_recipe_changes(diff)
    print(json.dumps([change.to_data() for change in changes], indent=2, sort_keys=True))
    return 0


def plan_builds(args: argparse.Namespace) -> int:
    """Generate and persist a build queue for a PR."""

    queue = create_build_queue(args.pr, args.title, args.author)
    store = StateStore(state_dir=args.state_dir)
    store.ensure()
    if not args.keep_results:
        store.reset_pr(args.pr)
    path = store.write_queue(queue)
    print(f"Queue: {path}")
    for task in queue.tasks:
        print(f"{task.id}: {task.build_spec.spec} ({task.build_spec.reason})")
    return 0


def create_build_queue(pr_number: int, title: str = "", author: str = "") -> BuildQueue:
    """Create a build queue for a pull request from its diff."""

    diff = GitHubCLI().pr_diff(str(pr_number))
    changes = parse_recipe_changes(diff)
    build_specs = build_specs_from_changes(changes)
    pull_request = PullRequestRef(
        number=pr_number,
        url=f"https://github.com/spack/spack/pull/{pr_number}",
        title=title,
        author=author,
    )
    return BuildQueue(
        schema_version=1,
        pull_request=pull_request,
        tasks=[
            BuildTask(id=f"{index + 1:04d}-{spec.recipe}", build_spec=spec)
            for index, spec in enumerate(build_specs)
        ],
    )


def queue_status_command(args: argparse.Namespace) -> int:
    """Print task counts for a queue."""

    queue = StateStore(state_dir=args.state_dir).read_queue(args.pr)
    counts: Dict[str, int] = {}
    for task in queue.tasks:
        counts[task.status.value] = counts.get(task.status.value, 0) + 1
    for status in sorted(counts):
        print(f"{status}: {counts[status]}")
    if not queue.tasks:
        print("empty: 0")
    return 0


def queue_claim_command(args: argparse.Namespace) -> int:
    """Claim and print the next task for a worker."""

    store = StateStore(state_dir=args.state_dir)
    task = store.claim_next_task(args.pr, args.owner, args.lease_seconds)
    if task is None:
        print("No claimable tasks.")
        return 1
    print(json.dumps(task.to_data(), indent=2, sort_keys=True))
    return 0


def queue_requeue_command(args: argparse.Namespace) -> int:
    """Requeue tasks by status."""

    store = StateStore(state_dir=args.state_dir)
    changed = store.requeue_tasks(args.pr, TaskStatus(args.status))
    print(f"requeued: {changed}")
    return 0


def state_doctor(args: argparse.Namespace) -> int:
    """Show resolved state paths."""

    store = StateStore(state_dir=args.state_dir)
    store.ensure()
    print(f"state: {store.root}")
    print(f"cache: {store.cache_root}")
    return 0


def build_next_command(args: argparse.Namespace) -> int:
    """Claim and run the next task."""

    owner = args.owner or default_owner()
    store = StateStore(state_dir=args.state_dir)
    task = store.claim_next_task(args.pr, owner, args.lease_seconds)
    if task is None:
        print("No claimable tasks.")
        return 1
    result = run_task(
        args.pr,
        task,
        store,
        spack=args.spack,
        dry_run=args.dry_run,
        timeout=None if args.timeout == 0 else args.timeout,
    )
    print_result(result)
    return 0 if result.status in (TaskStatus.PASSED, TaskStatus.SKIPPED) else 1


def build_all_command(args: argparse.Namespace) -> int:
    """Run tasks until the queue has no claimable tasks left."""

    results = run_available_tasks(
        args.pr,
        StateStore(state_dir=args.state_dir),
        owner=args.owner or default_owner(),
        spack=args.spack,
        dry_run=args.dry_run,
        timeout=None if args.timeout == 0 else args.timeout,
        jobs=max(1, args.jobs),
        lease_seconds=args.lease_seconds,
    )
    print_report(results)
    return 1 if any(result.status == TaskStatus.FAILED for result in results) else 0


def run_pr_command(args: argparse.Namespace) -> int:
    """Checkout, plan, and run builds for a pull request."""

    pr_number = resolve_pr_number(args.pr)
    if not args.no_checkout:
        print(f"Checking out PR {pr_number}")
        GitHubCLI().checkout(str(pr_number), branch=args.branch)

    queue = create_build_queue(pr_number)
    store = StateStore(state_dir=args.state_dir)
    store.ensure()
    store.reset_pr(pr_number)
    path = store.write_queue(queue)
    print(f"Queue: {path}")
    for task in queue.tasks:
        print(f"{task.id}: {task.build_spec.spec} ({task.build_spec.reason})")

    results = run_available_tasks(
        pr_number,
        store,
        owner=args.owner or default_owner(),
        spack=args.spack,
        dry_run=args.dry_run,
        timeout=None if args.timeout == 0 else args.timeout,
        jobs=max(1, args.jobs),
    )
    print_report(results)
    return 1 if any(result.status == TaskStatus.FAILED for result in results) else 0


def resolve_pr_number(pr_number: Optional[int]) -> int:
    """Return the given PR number or resolve it from the current GitHub PR URL."""

    if pr_number is not None:
        return pr_number
    return GitHubCLI().current_pr_number()


def print_report(results: List[BuildResult]) -> None:
    """Print a markdown report if any tasks ran."""

    if results:
        print("\n" + generate_markdown_report(results))
    else:
        print("No claimable tasks.")


if __name__ == "__main__":
    sys.exit(main())
