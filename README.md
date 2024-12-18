# ✨ GitHub CLI extension `spack-pr`

## 🌅 Proof of concept for complimenting CI with building changed packages

- Exclusively aimed at building changed recipes (and related packages, e.g. dependents)
- Most specifically aimed at packages labelled by @spackbot with `new-package` or `new-variant`.

For an introduction to the proof of concept see the specific README: [cli/README.md](cli/README.md)

## 🌅 Introduction on using the GitHub CLI (`gh`)

GitHub has a public API that you can use to work with pull requests.

It can be used to submit (for example) build results of PRs.

This extension to the GitHub CLI does exactly that:

- It helps with checking out PRs to review and check if they work.
- You can use `gh pr checkout <PR number>` to checkout a PR
- Or, you can pass a keyword from the PR's title to check out the PR.
- Or, you can check a list of PRs by creating a file with PRs to build.
- If all goes well, you get a summary of building all specs changed in the PR
- If that looks fine, you can submit it to the PR as a comment (work in progress)
- If builds fail, you can examine the cause and submit the failure likewise.

Quick start:

- Install `gh` using `spack install gh` or any other means: <http://cli.github.com>
- Run `gh auth login`: The URL it tries to open into your browser and login
- Then you can install the `spack-pr` extension: `gh extension install spack/gh-spack-pr`

Using `gh` your `spack` checkout directory:

- Run `gh pr checkout <PR number>` for checking out a PR to review.
- Run `gh pr review --approve -b "Tested in my environment"` to approve a PR
- Run `gh pr merge --auto --squash` to merge it (enables auto-merge if not ready yet)
- Get a list of PRs that need review, are not drafts, have no assignee, are not failed
  do not have a number o labels, are not reviewed by me and have maximum comment:

  ```py
  gh pr list -L9 --search 'review:required draft:false no:assignee -status:failure -label:changes-requested -label:waiting-on-maintainer -label:waiting-on-dependency -label:question updated:>=2024-05-01' `
  ```

  The output of this command can be edited by removing PRs
  that are not safe to approve if all builds pass the reviewed
  file can be passed to `build_pr_changes.py`:

  ```py
  gh pr list -L42 --search 'review:required draft:false no:assignee -status:failure -label:changes-requested -label:waiting-on-maintainer -label:waiting-on-dependency -label:question updated:>=2024-05-01' >recent-pr-queue.txt
  gh-spack-pr/build_pr_changes.py -q recent-pr-queue.txt -mar
  ```

  This will attempt to build all changed specs that were detected
  from the `gh pr diff` of each queued PR.

  For each PR that was able to build each discovered spec,
  if the `-a|--approve` flag is given, it will approve the PR
  or will ask if changes shall be requested for each failure.

  The change request will include the build error from spack.

  If the approve was successful and no other reviewer requested
  changes, it will ask if you want to merge the PR.

## 📝 Tools for checking pull request quality

### Helpful shortcuts (aliases) for `gh`

- `co`: Checkout a PR branch using fzf (select from list)

  ```py
  gh alias set co --shell 'id="$(gh pr list -L60 | fzf | cut -f1)"; [ -n "$id" ] && gh pr checkout "$id"'
  ```

- `review`: Find and check PRs that need review

  ```py
  gh alias set review --shell 'id="$(gh pr list -L20 -S "review:required draft:false no:assignee -status:failure -label:changes-requested -label:waiting-on-maintainer -label:waiting-on-dependency"|fzf|cut -f1)"; [ -n "$id" ] && gh pr checkout $id && gh pr view -c && gh pr diff'
  ```

### ⚡️ [`build_pr_changes.py`](build_pr_changes.py)

Run the script
[build_pr_changes.py](build_pr_changes.py)
found in this repository to install the changes of the PR checked out.

It depends on `gh` to be set up and the PR checked out with `gh pr checkout <PR number>`.
With it, it:

- Gets the PR diff using `gh pr diff`
- Looks for changed and new versions in the PR diff to install
- Looks for changed and new variants in the PR diff to install
- Checks the checksums of all changed and new versions before the build.
- Can also build all versions of recipes if indicated.
- Build each version and variant found from the diff and report the result.
- The result is ready to be pasted into a Pull request review.
- In the future, it could even submit the review directly using the `gh` CLI.

## 🪟 `gh dash`

✨ A GitHub (`gh`) CLI extension to display a dashboard with
**pull requests** and **issues** by
[GitHub filters](https://docs.github.com/en/search-github/searching-on-github/searching-issues-and-pull-requests)
you care about.

It can be configured for the needs of spack
[spack pull requests](https://github.com/spack/spack/pulls) as well.

Using the example configuration, the key binding `b` checks out the
selected PR, and starts a sub-shell.

In the shell with the PR checked out, you can run
[build_pr_changes.py](build_pr_changes.py) to build the PR and submit the results.

See [tools/gh-dash/README.md](cli-extensions/gh-dash/README.md) for an introduction.

<img src="https://user-images.githubusercontent.com/6196971/198704107-6775a0ba-669d-418b-9ae9-59228aaa84d1.gif">
