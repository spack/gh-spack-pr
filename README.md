# gh-spack-pr

`gh-spack-pr` is a GitHub CLI extension for reviewing Spack pull requests by
turning recipe changes into a local build queue, running the selected Spack
builds, and recording reproducible results in local state files.

It is designed for reviewers who want a repeatable workflow around:

- selecting Spack pull requests that are good candidates for local review,
- analyzing `gh pr diff` for changed recipe versions and variants,
- planning build tasks from those changes,
- running queued `spack install` checks locally, and
- keeping logs and result files under XDG state/cache locations.

## Quick Start

Install and authenticate the GitHub CLI, then install this extension:

```sh
gh auth login
gh extension install spack/gh-spack-pr
```

From a Spack checkout, analyze and test-build a pull request:

```sh
gh spack-pr checkout 5625
gh spack-pr analyze 5625
gh spack-pr plan-builds 5625
gh spack-pr run 5625
```

Checkout uses a PR-numbered local branch such as `pr-5625` instead of the
contributor's source branch name. If that local branch already exists, it is
renamed to `pr-5625.YYYYmmdd-HHMMSS` before a fresh checkout is created.

Useful queue commands:

```sh
gh spack-pr queue status 5625
gh spack-pr build next 5625
gh spack-pr build all 5625
gh spack-pr queue requeue 5625 --status running
```

Use `--jobs` to run multiple package builds in parallel with PTY-backed output
and per-task logs:

```sh
gh spack-pr run 5625 --jobs 4
gh spack-pr build all 5625 --jobs 4
```

Use `--dry-run` to verify checkout, planning, queueing, and logging without
starting package builds:

```sh
gh spack-pr run 5625 --dry-run
```

## Documentation

See [docs/tutorial.md](docs/tutorial.md) for a guided workflow covering the
GitHub CLI, selecting PRs, using the extension, and inspecting local build
state. See [CONTRIBUTING.md](CONTRIBUTING.md) for local development setup,
testing commands, current project status, and the roadmap.
