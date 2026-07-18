"""Build-plan generation from parsed recipe changes."""

from __future__ import annotations

from typing import Iterable, List

from .domain import BuildSpec, RecipeChange


def build_specs_from_changes(changes: Iterable[RecipeChange]) -> List[BuildSpec]:
    """Convert recipe changes to conservative Spack specs to verify."""

    specs: List[BuildSpec] = []
    seen: set[str] = set()
    for change in changes:
        package = spack_package_name(change.recipe)
        if change.versions:
            for version in change.versions:
                _append(specs, seen, f"{package}@={version}", change.recipe, "changed version")
        if change.variants:
            _append(specs, seen, package, change.recipe, "baseline for changed variants")
            for variant in change.variants:
                _append(
                    specs,
                    seen,
                    f"{package}+{variant}",
                    change.recipe,
                    f"changed boolean variant {variant}",
                )
        if not change.versions and not change.variants:
            _append(specs, seen, package, change.recipe, "changed recipe")
    return specs


def spack_package_name(recipe: str) -> str:
    """Return the Spack spec name for a recipe directory name."""

    return recipe.replace("_", "-")


def _append(specs: List[BuildSpec], seen: set[str], spec: str, recipe: str, reason: str) -> None:
    if spec in seen:
        return
    specs.append(BuildSpec(spec=spec, recipe=recipe, reason=reason))
    seen.add(spec)
