"""Check discovery and registry system for CloudGuard."""

import importlib
import inspect
import pkgutil
from typing import Dict, List, Optional, Type
import cloudguard.checks
from cloudguard.checks.base import BaseCheck

_CHECK_REGISTRY: Dict[str, Type[BaseCheck]] = {}


def register_check(cls: Type[BaseCheck]) -> Type[BaseCheck]:
    """Decorator or function to explicitly register a BaseCheck subclass.

    Args:
        cls: BaseCheck subclass to register.

    Returns:
        The registered class.
    """
    if not inspect.isclass(cls) or not issubclass(cls, BaseCheck):
        raise TypeError(f"Registered item must be a subclass of BaseCheck, got {cls}")
    if cls is BaseCheck:
        return cls

    check_id = getattr(cls, "check_id", None)
    if not check_id:
        raise ValueError(f"Check class {cls.__name__} must define a non-empty 'check_id'")

    _CHECK_REGISTRY[check_id] = cls
    return cls


def discover_checks(package_name: str = "cloudguard.checks") -> Dict[str, Type[BaseCheck]]:
    """Auto-discover all BaseCheck subclasses in the specified package and subpackages.

    Imports all modules in the package, then registers any concrete subclasses of BaseCheck.

    Args:
        package_name: Dot-separated package name to scan (default: 'cloudguard.checks').

    Returns:
        Dictionary mapping check_id to check class.
    """
    try:
        package = importlib.import_module(package_name)
    except ImportError:
        return _CHECK_REGISTRY

    # Walk and import all modules inside the package
    if hasattr(package, "__path__"):
        for _, module_name, is_pkg in pkgutil.walk_packages(package.__path__, f"{package.__name__}."):
            try:
                importlib.import_module(module_name)
            except Exception:
                # In scanner context, skip unimportable modules gracefully
                continue

    # Find all concrete subclasses of BaseCheck belonging to the target package
    def _collect_subclasses(cls: Type[BaseCheck]) -> None:
        for sub in cls.__subclasses__():
            if (
                not inspect.isabstract(sub)
                and getattr(sub, "check_id", None)
                and sub.__module__.startswith(package_name)
            ):
                register_check(sub)
            _collect_subclasses(sub)

    _collect_subclasses(BaseCheck)
    return dict(_CHECK_REGISTRY)


def get_all_checks() -> List[Type[BaseCheck]]:
    """Return a list of all discovered and registered check classes.

    Ensures auto-discovery has executed at least once for cloudguard.checks.
    """
    discover_checks("cloudguard.checks")
    return list(_CHECK_REGISTRY.values())


def get_check(check_id: str) -> Optional[Type[BaseCheck]]:
    """Retrieve a specific registered check class by check_id."""
    discover_checks("cloudguard.checks")
    return _CHECK_REGISTRY.get(check_id)


def clear_registry() -> None:
    """Clear all registered checks (primarily for test isolation)."""
    _CHECK_REGISTRY.clear()
