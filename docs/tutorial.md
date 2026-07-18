# Tutorial: Reviewing Spack PRs With `gh-spack-pr`

This tutorial shows a local reviewer workflow using the GitHub CLI and the
`gh-spack-pr` extension. The goal is to select a Spack pull request, inspect the
recipe changes, build the planned specs locally, and keep enough state to resume
or audit the run later.

## Prerequisites

Install the GitHub CLI and authenticate it:

```sh
gh auth login
```

Install the extension:

```sh
gh extension install spack/gh-spack-pr
```

Run the workflow from a Spack checkout with a working `spack`:

```sh
cd ~/gh/spack
. ~/spack-core/share/spack/setup-env.sh
spack --version
```

## Find Candidate PRs

The extension can list conservative candidates for local review. The default
query focuses on open Spack PRs that still need review, are not drafts, have no
assignee, do not have failing status, and do not carry common blocking labels.

```sh
gh spack-pr prs list --limit 20
```

You can also use the GitHub CLI directly when you want to tune the query:

```sh
search='review:required draft:false no:assignee -status:failure'
search="$search -label:changes-requested -label:waiting-on-maintainer"
search="$search -label:waiting-on-dependency -label:question"
gh pr list \
  --repo spack/spack \
  --limit 20 \
  --search "$search"
```

## Analyze a PR Diff

Use `analyze` to inspect which recipe files, versions, and simple boolean
variants are detected from `gh pr diff`:

```sh
gh spack-pr analyze 5625
```

## Plan Builds

Create a persistent build queue for the PR:

```sh
gh spack-pr plan-builds 5625
```

State is written under `~/.local/state/gh-spack-pr` by default, and logs are
written under `~/.cache/gh-spack-pr` unless XDG variables override those paths.

Use `--state-dir` when you want disposable state:

```sh
gh spack-pr --state-dir /tmp/gh-spack-pr-5625 plan-builds 5625
```

## Run the Queue

To checkout the PR, create the queue, and run planned builds using two parallel
PTY-backed workers by default:

```sh
gh spack-pr run 5625
```

Checkout creates a PR-numbered local branch, such as `pr-5625`, instead of
reusing the contributor's source branch name. This avoids collisions when two
PRs use the same branch name or when contributors submit from branches like
`develop`. If the local PR branch already exists, it is renamed to
`pr-5625.YYYYmmdd-HHMMSS` before a fresh checkout is created. Use `--branch`
when you need a specific local branch name:

```sh
gh spack-pr checkout 5625 --branch review-5625
gh spack-pr run 5625 --branch review-5625
```

Control package-level parallelism with `--jobs`:

```sh
gh spack-pr run 5625 --jobs 4
gh spack-pr build all 5625 --jobs 4
```

Use `--dry-run` to test checkout, queueing, and logs without starting builds:

```sh
gh spack-pr run 5625 --dry-run
```

If the PR is already checked out, skip checkout:

```sh
gh spack-pr run 5625 --no-checkout
```

## Resume or Repair a Queue

Show task counts:

```sh
gh spack-pr queue status 5625
```

If a worker is interrupted, move leased tasks back to `pending` before
continuing:

```sh
gh spack-pr queue requeue 5625 --status running
gh spack-pr build all 5625
```

## Review Results

At the end of `build all` or `run`, the extension prints a markdown summary of
the current batch. Detailed logs and result files remain in local state/cache
paths so the run can be audited or used to prepare a PR comment.

For now, review any generated text locally before submitting anything to GitHub.
Posting review comments is intentionally kept as an explicit manual action.
