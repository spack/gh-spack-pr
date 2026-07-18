# Contributing to gh-spack-pr

This project is a GitHub CLI extension for reviewing Spack pull requests by
turning recipe diffs into resumable local build queues. Contributions should
keep that workflow modular, testable, and conservative about anything that
would post to GitHub.

## Local Development Setup

Clone this repository next to a Spack checkout or wherever you prefer to keep
GitHub CLI extensions:

```sh
git clone https://github.com/spack/gh-spack-pr.git ~/gh/spack/gh-spack-pr
cd ~/gh/spack/gh-spack-pr
python -m pip install -e '.[dev]'
```

Install the local checkout as a GitHub CLI extension:

```sh
gh extension install .
```

If another copy is already installed, remove it by the extension repository name
and install again:

```sh
gh extension remove gh-spack-pr
gh extension install .
```

GitHub CLI installs local extensions by creating a symlink under its extension
directory. If installation fails with an error like this:

```text
symlink /home/bkaindl/gh/spack/gh-spack-pr /home/bkaindl/.local/share/gh/extensions/gh-spack-pr: file exists
```

remove the stale extension entry and retry:

```sh
gh extension list
gh extension remove gh-spack-pr || rm -f ~/.local/share/gh/extensions/gh-spack-pr
gh extension install .
```

After installation, confirm that GitHub CLI resolves the extension:

```sh
gh spack-pr --help
```

## Testing the Local Extension

Run command tests from a Spack checkout using `spack`:

```sh
cd ~/gh/spack
gh spack-pr analyze 5625
gh spack-pr plan-builds 5625
gh spack-pr run 5625
```

Use `--dry-run` while developing command flow or state handling:

```sh
gh spack-pr run 5625 --dry-run
```

Use `--jobs` to run multiple package builds in parallel through PTY-backed
workers while still writing per-task logs:

```sh
gh spack-pr run 5625 --jobs 4
gh spack-pr build all 5625 --jobs 4
```

Use an explicit state directory for repeatable tests and easy cleanup:

```sh
state=/tmp/gh-spack-pr-5625
gh spack-pr --state-dir "$state" plan-builds 5625
gh spack-pr --state-dir "$state" queue status 5625
gh spack-pr --state-dir "$state" build next 5625 --dry-run
```

If a worker is interrupted and leaves leased tasks behind, requeue them:

```sh
gh spack-pr --state-dir "$state" queue requeue 5625 --status running
```

## Validation

Run the focused unit tests before sending changes:

```sh
python -m pytest tests/test_diff_planner_state.py
python -m black --check spack_pr_review tests
python -m compileall spack_pr_review tests
```

If available, run the repository pre-commit checks using prek or pre-commit:

```sh
git add -up; uvx prek run -a
```

```sh
git add -up; pre-commit run -a
```

## Current State

The current implementation includes:

- a modular Python package under `spack_pr_review`,
- a GitHub CLI extension launcher exposed as `gh spack-pr`,
- PR candidate listing through `prs list`,
- diff analysis through `analyze`,
- build planning through `plan-builds`,
- XDG-backed state and cache paths,
- queue status, claiming, and requeue support,
- `build next`, `build all`, and `run` commands,
- dry-run support for workflow testing,
- PTY-backed package builds with per-task logs,
- parallel package build workers through `--jobs`, and
- markdown summaries for completed build batches.

The state files currently use JSON syntax in `.yaml` files. Keep serialization
stable and explicit when changing these schemas, because state files are meant
to be inspectable and resumable.

## Development Principles

- Keep GitHub submission manual and reviewable. Commands that post comments or
  reviews should require explicit local confirmation.
- Prefer small modules with typed dataclasses over large command functions.
- Keep command adapters isolated so tests can use fake runners instead of live
  GitHub or Spack calls.
- Preserve resumability. A task should be safe to inspect, requeue, retry, or
  audit after interruption.
- Avoid assuming a clean Spack checkout unless the command clearly documents
  that requirement.

## Roadmap

Near-term work:

- add report commands to generate, preview, and submit markdown from persisted
  result files,
- use `gh pr comment --body-file` or `gh pr review --body-file` for posting so
  long reports do not exceed command-line limits,
- always prompt before posting anything to GitHub,
- improve failure summaries by parsing logs into concise actionable excerpts,
- add richer queue/result schema tests, and
- add fake command adapters for CLI-level tests.

Build-planning improvements:

- compare base and PR recipe metadata to identify added, removed, and changed
  versions more reliably,
- inspect Spack metadata for variants, preferred versions, conditional variants,
  deprecated versions, and maintainers,
- support requested specs from PR comments,
- support optional compiler and dependency matrices,
- add configurable skip rules for expensive, licensed, manual-download, or
  hardware-specific packages, and
- evaluate dependent-package smoke checks where practical.

Longer-term ideas:

- support remote builders, containers, or sandboxed build hosts,
- coordinate parallel build workers across machines,
- add a web or VS Code-oriented frontend over the same state files,
- integrate optional `gh dash` workflows, and
- publish a stable state schema for external tooling.

## Documentation Ideas

Useful follow-up documentation would include:

- a command reference for every `gh spack-pr` subcommand,
- a state-file schema reference for queues, leases, results, logs, and reports,
- an architecture overview of the parser, planner, runner, state store, and
  reporting modules,
- a troubleshooting guide for dirty worktrees, failed checkouts, stuck leases,
  concretization failures, and interrupted builds,
- examples of real PR workflows with dry-run and full-build output,
- guidance for safely preparing and reviewing PR comments before submission,
- a guide to configuring `gh dash` for Spack review queues, and
- contributor notes for adding parser fixtures from real `gh pr diff` output.
