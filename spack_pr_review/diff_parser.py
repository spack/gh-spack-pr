"""Parse Spack recipe changes from GitHub pull request diffs."""

# pylint: disable=duplicate-code

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .domain import RecipeChange

RECIPE_PATH = re.compile(
    r"(?:var/spack/repos/builtin|repos/spack_repo/builtin)/packages/([^/]+)/package\.py"
)
VERSION_LINE = re.compile(r'^\+\s{4}version\("([^"]+)",')
VARIANT_LINE = re.compile(r'^\+\s{4}variant\("([^"]+)",')
DEFINE_FROM_VARIANT_LINE = re.compile(r'^\+.*self\.define_from_variant\("[^"]+", "([^"]+)"')


@dataclass
class _RecipeChangeBuilder:
    # pylint: disable=too-many-instance-attributes
    recipe: str
    path: str
    versions: List[str] = field(default_factory=list)
    variants: List[str] = field(default_factory=list)
    deprecated_versions: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    pending_multiline_version: Optional[str] = None
    pending_multiline_variant: Optional[str] = None
    deprecated_block: bool = False

    def finish(self) -> RecipeChange:
        """Build an immutable recipe change."""

        versions = _unique(self.versions)
        deprecated = _unique(self.deprecated_versions)
        return RecipeChange(
            recipe=self.recipe,
            path=self.path,
            versions=[version for version in versions if version not in deprecated],
            variants=_unique(self.variants),
            deprecated_versions=deprecated,
            warnings=_unique(self.warnings),
        )


def parse_recipe_changes(diff: str) -> List[RecipeChange]:
    """Return changed Spack recipes and directly detectable versions/variants."""

    builders: Dict[str, _RecipeChangeBuilder] = {}
    current: Optional[_RecipeChangeBuilder] = None

    for line in diff.splitlines():
        if line.startswith("diff --git"):
            current = _builder_from_diff_header(line, builders)
            continue
        if line.startswith("+++ b/"):
            current = _builder_from_path(line[6:], builders)
            continue
        if current is None:
            continue
        _parse_recipe_line(current, line)

    return [builder.finish() for builder in builders.values()]


def _builder_from_diff_header(
    line: str, builders: Dict[str, _RecipeChangeBuilder]
) -> Optional[_RecipeChangeBuilder]:
    match = RECIPE_PATH.search(line)
    if not match:
        return None
    path_match = re.search(r" b/(\S+)$", line)
    path = path_match.group(1) if path_match else match.group(0)
    return _get_builder(match.group(1), path, builders)


def _builder_from_path(
    path: str, builders: Dict[str, _RecipeChangeBuilder]
) -> Optional[_RecipeChangeBuilder]:
    match = RECIPE_PATH.search(path)
    if not match:
        return None
    return _get_builder(match.group(1), path, builders)


def _get_builder(
    recipe: str, path: str, builders: Dict[str, _RecipeChangeBuilder]
) -> _RecipeChangeBuilder:
    if recipe not in builders:
        builders[recipe] = _RecipeChangeBuilder(recipe=recipe, path=path)
    return builders[recipe]


def _parse_recipe_line(  # pylint: disable=too-many-return-statements
    builder: _RecipeChangeBuilder, line: str
) -> None:
    if line.startswith("-"):
        return

    if "with default_args(deprecated=True):" in line:
        builder.deprecated_block = True

    if builder.pending_multiline_version:
        if "deprecated=True" in line or builder.deprecated_block:
            builder.deprecated_versions.append(builder.pending_multiline_version)
        if line.startswith("+") and ")" in line:
            if builder.pending_multiline_version not in builder.deprecated_versions:
                builder.versions.append(builder.pending_multiline_version)
            builder.pending_multiline_version = None
        return

    if builder.pending_multiline_variant:
        _add_bool_variant(builder, builder.pending_multiline_variant, line)
        if line.startswith("+") and ")" in line:
            builder.pending_multiline_variant = None
        return

    if not line.startswith("+"):
        return

    version = VERSION_LINE.search(line)
    if version:
        if "deprecated=True" in line or builder.deprecated_block:
            builder.deprecated_versions.append(version.group(1))
        else:
            builder.versions.append(version.group(1))
        return

    if re.match(r"^\+\s{4}version\($", line):
        builder.pending_multiline_version = ""
        return

    if builder.pending_multiline_version == "":
        version_name = re.search(r'"([^"]+)"', line)
        if version_name:
            builder.pending_multiline_version = version_name.group(1)
        return

    define_variant = DEFINE_FROM_VARIANT_LINE.search(line)
    if define_variant:
        builder.variants.append(define_variant.group(1))
        return

    variant = VARIANT_LINE.search(line)
    if variant:
        _add_bool_variant(builder, variant.group(1), line)
        return

    if re.match(r"^\+\s{4}variant\($", line):
        builder.pending_multiline_variant = ""
        return

    if builder.pending_multiline_variant == "":
        variant_name = re.search(r'"([^"]+)"', line)
        if variant_name:
            builder.pending_multiline_variant = variant_name.group(1)


def _add_bool_variant(builder: _RecipeChangeBuilder, variant: str, line: str) -> None:
    if not variant or variant == "cuda":
        return
    default = re.search(r"default=(True|False|true|false)", line)
    if default:
        builder.variants.append(variant)
    elif "values=" in line:
        builder.warnings.append(f"variant {variant} has non-boolean values and was not planned")


def _unique(values: List[str]) -> List[str]:
    return list(dict.fromkeys(values))
