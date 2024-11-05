# Packaging tests using gh-spack-pr

## Prototype to test recipes or recipe variants not covered by GitLab CI yet

- Complement, but not replace the existing GitLab CI pipelines.
- Exclusively aimed at building changed recipes (and related packages, e.g. dependents)
- Most specifically aimed at packages labelled by @spackbot with `new-package` or `new-variant`.
- Not aimed for testing against regressions in the spack library or core itself!
- If or when the spack packages would be tested separately from the spack core,
  these checks would only run on as  CI in the packages repository
  (besides existing GitLab CI of course).

### Testing of changes to recipes

- Run them during CI tests
- Make them available to PR submitters and reviewers for verification before pushing the PR and fixing issues.

#### Implementation(s)

- Build large concretized specs in GitLab CI
  (e.g. dependents of mpi/blas/rust, mesa+llvm, and other forks of llvm/gcc/numpy/scipy)
- Optional: Build smaller concretized specs in GitHub CI instead.
  - Should not be many lines in the concrete spec and do not need a large server for builds.
  - Should possibly plug into some of the infrastructure of spack

#### Unsolved issues

Should have some support from spack, for example:

- It would be good to build only the dependencies of a build first.
  When that fails, count this not as a problem caused by the PR changes
- Only when building the unchanged PR dependencies passed, build the actual changes of the PR.
  Only these are to be flagged as review/success by the PR.
- Also build the dependents of the changed packages (`spack dependents <package>`)

#### Initial proof of concept

- Only designed as a quick CLI tool to "test the ground":
  - GitHub CI extension (GH CLI is available in GitHub CI) for users and GitHub CI
  - On Linux, it uses [pexpect](https://pexpect.readthedocs.io/en/stable/) to run
    sub-processes using a Pseudo-TTY:
    - To make the GitHub CLI commands and `git diff` use colors automatically.
    - expect should work on Darwin too, and a Windows alternative (expect) also exists.

#### Code quality checks integrated into GitHub CI with pre-commit hooks before commit

To require coding standards for each commit, the proof of concept was developed with strict checks:
Clean commits based on based on <https://pre-commit.com/> ([config](https://github.com/spack/gh-spack-pr/blob/main/.pre-commit-config.yaml)):
pre-commit hooks:

- Formatting with `black`
- <https://github.com/pylint-dev/pylint> (Linting)
- <https://github.com/pre-commit/mirrors-mypy> (static analysis)
- <https://github.com/RobertCraigie/pyright-python> (static analysis tool of VS Code)
- <https://github.com/xenserver-next/pre-commit-pytype> (static analysis tool of Google)
- <https://github.com/codespell-project/codespell> (spell checks for code)

Nonetheless, all code is in one file, so for a maintainable community project,
a community project should be started instead.

- It should be properly organized into modules and classes for example for utils.
- It is likely best to start a clean slate and port code as needed.

#### Limitations

- Cannot build some recipes that are very compute-intensive. Examples:
  - composable-kernel (this package alone appears to be an overnight build, even on large servers.
    It possibly needs a strong AMD GPU to be fast.
  - Depending on the memory per CPU ratio of the GitLab CI pods.
    Some packages may need more memory than the pod has. (A few packages may need >32 GB RAM)
  - Such constraints could be handled by adding properties to recipes with such special needs (to handle them).
- Cannot install recipes with manual downloads. But it should be able to detect and skip them.
- Cannot install recipes that have automated downloads but need license approval.
  - It could however do the checksum checks for those.

An initial investigation by Bernhard Kaindl(me) has yielded some research results:

### Deriving changes to these from the PR diff for packages

To a mostly (not always) working degree, the changes that need testing can be derived from the PR.

- While the detection of those changes is not 100% reliable, most simple cases are detectable:
  - Changes to the package versions in the changes to the recipes or version-specific changes
  - Changes to the package variants in the changes to the recipes or variant-specific changes
  - Changes to the package's build_systems.

### Deriving additional sanity checks from `spack info <package>`

From `spack info <package>`, the current status of the updated recipes can be gathered:

- The preferred version of each changed package
- The list of versions of each changed package
- The variants of each changed package
- The build systems of each changed package
- The list of dependent packages of each changed package
  - The versions, variants and build_systems of dependent packages can be gathered (recursively)

- If (as an idea) the recipe can provide a function or dictionary of versions and variants to check,
  those versions could be prioritized for packaging tests.

- Based on this information, a packaging test can issue a list of package builds for testing

### Problems that need to be handled

- Some packages, have complex variants, and some variants (e.g. `~mpi`, `+serial`) may not be well-supported.
  - While known to users and maintainers of those packages such `notest` flags for variants may be helpful.
  - In other cases, such variants may work but need specific backends.
    Conflicts or testable sets of variants would have to be excluded or handled.

- For some variants, the dependencies of those variants may fail to build in spack
- For some packages, build dependency versions or variants not tested by the PR submitters may cause build failures
  - Those cases might puzzle or confuse PR submitters and can be hard to diagnose initially.
    - Those need in-depth investigation once.
      After such issues are fixed, submitting package updates would be fine.

- For packages built in GitLab CI, some base variants to apply to the build could be
  retrieved from the specs used in GitLab CI.

- Should also run the build-time and stand-alone smoke tests of packages that implement them:
  - [Spack Documentation: Testing an installation](https://spack.readthedocs.io/en/latest/packaging_guide.html#checking-an-installation)
  - Spack wiki:
  <https://github.com/spack/spack/wiki/Spack-Stand-Alone-Smoke-Testing-Support>

## Spackbot should label PRs submitted by the package maintainer

<https://github.com/hainest> (@hainest) submitted this request for PR review in
<https://github.com/spack/spack/pull/47359#issuecomment-2453572959>:

> [...] The ratio of PRs to spack maintainers is almost impossibly large.
>
> Pull requests submitted by a package maintainer would be really nice to have
> reviewed quickly as soon as the CI pipelines pass.
> That's definitely self-serving, but I think it's a place where you could be
> effective without needing to spend too much effort.

@bernhardkaindl agrees:
> Great idea and point!
> <https://github.com/spack/gh-spack-pr/blob/main/cli/check.py> meanwhile has
> a check if a PR is submitted by the maintainer of the changed package(s),
> and it could show this information to reviewers by setting a label.
>
> @spackbot is already an active, automated app that has the same information:
> It also checks the maintainers of the changed packages.
> When the PR author maintains all the changed packages,
> a bot could set a label to make his information visible and selectable to reviewers and mergers.
>
> This would be an improvement for Spackbot so reviewers and mergers see this information
> immediately (and with labels, they can also select PRs for review/merge with this as a search
> query condition for prioritizing the review and merge of these PRs)
>
> This could be a nice incentive for the submitters of PRs to add
> themselves as package maintainers.
