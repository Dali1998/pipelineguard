"""
Rule registry – auto-discovers and instantiates every BaseRule subclass
found in the `rules/` package.  New rule files are picked up automatically
as long as they are imported (or exist in this package).
"""

import importlib
import pkgutil
from pathlib import Path

from pipelineguard.models.issue import Severity
from pipelineguard.rules.base_rule import BaseRule

# Modules inside the rules package that are NOT rule files
_EXCLUDED_MODULES = {"base_rule", "registry", "__init__"}


def _import_all_rule_modules() -> None:
    """Import every module in the rules package so subclasses register."""
    rules_pkg_dir = Path(__file__).parent
    for module_info in pkgutil.iter_modules([str(rules_pkg_dir)]):
        if module_info.name in _EXCLUDED_MODULES:
            continue
        importlib.import_module(f"pipelineguard.rules.{module_info.name}")


def load_rules(
    severity_filter: list[Severity] | None = None,
) -> list[BaseRule]:
    """
    Return instantiated, enabled rules.

    Args:
        severity_filter: If provided, only return rules whose default
                         severity is in this list.
    """
    _import_all_rule_modules()

    rules: list[BaseRule] = []
    for subclass in _all_subclasses(BaseRule):
        instance = subclass()
        if not instance.enabled():
            continue
        if severity_filter and getattr(instance, "severity", None) not in severity_filter:
            continue
        rules.append(instance)

    return rules


def _all_subclasses(cls: type) -> list[type]:
    """Recursively collect all concrete subclasses."""
    result = []
    for sub in cls.__subclasses__():
        if not _is_abstract(sub):
            result.append(sub)
        result.extend(_all_subclasses(sub))
    return result


def _is_abstract(cls: type) -> bool:
    import inspect

    return inspect.isabstract(cls)
