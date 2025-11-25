"""Parser for ldap_protocol packages with exceptions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

import importlib
import inspect
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from types import ModuleType
from typing import Iterator

from fastapi_error_map.rules import Rule
from loguru import logger

from api.error_routing import DomainErrorTranslator
from errors import BaseDomainException


def get_ldap_protocol_path(path: Path | None = None) -> Path:
    """Get path to ldap_protocol directory."""
    return Path(path) if path else Path("ldap_protocol")


def should_skip_path(path: Path) -> bool:
    """Check if path should be skipped."""
    skip_names = {
        "__pycache__",
        "__init__.py",
        ".pyc",
        ".pyo",
        ".pyd",
    }
    return (
        path.name.startswith(".")
        or path.name in skip_names
        or any(part in skip_names for part in path.parts)
    )


@dataclass
class ValidatedPackage:
    """Information about validated package."""

    path: Path
    package_name: str
    name: str


def find_validated_packages(
    base_path: Path | None = None,
) -> Iterator[ValidatedPackage]:
    """Find all packages that contain exceptions and optional components.

    Yields:
        ValidatedPackage: Information about validated package.

    """
    if base_path is None:
        base_path = get_ldap_protocol_path()

    if not base_path.exists():
        return

    for item in sorted(base_path.iterdir()):
        if should_skip_path(item):
            continue

        if item.is_dir() and (item / "__init__.py").exists():
            yield from find_validated_packages(item)

        relative_path = item.relative_to(base_path)
        package_name = str(relative_path).replace("/", ".")
        logger.error(package_name)

        yield ValidatedPackage(
            path=item,
            package_name=package_name,
            name=item.name,
        )


@dataclass
class RouetrSettings:
    """Router settings."""

    module_name: ModuleType
    error_map: dict[type[BaseDomainException], Rule]
    translator: DomainErrorTranslator
    domain_name: str


def path_to_import_format(
    file_path: Path,
    base_path: Path | None = None,
) -> str:
    """Convert file path to Python module import format.

    Args:
        file_path: Path to the Python file
        base_path: Base path to remove from the beginning (e.g., Path("app"))

    Returns:
        Module name in import format (e.g., "api.dhcp.router")

    Examples:
        >>> path_to_import_format(Path("app/api/dhcp/router.py"), Path("app"))
        'api.dhcp.router'
        >>> path_to_import_format(Path("app/api/auth/router_mfa.py"), Path("app"))
        'api.auth.router_mfa'

    """
    if base_path is None:
        # Try to detect base path (app or current directory)
        base_path = (
            Path("ldap_protocol")
            if "ldap_protocol" in file_path.parts
            else Path(".")
        )

    try:
        relative_path = file_path.relative_to(base_path)
    except ValueError:
        # If file_path is not relative to base_path, use it as is
        relative_path = file_path

    # Remove .py extension and convert to module format
    module_parts = []
    for part in relative_path.parts:
        if part.endswith(".py"):
            part = part[:-3]  # Remove .py extension
        module_parts.append(part)

    return ".".join(module_parts)


def get_module_name(item: Path) -> RouetrSettings:
    """Get module name for router file."""
    module_path = path_to_import_format(item, base_path=Path("ldap_protocol"))
    module_name = importlib.import_module(module_path)
    logger.error(module_name)
    return RouetrSettings(
        module_name=module_name,
        error_map=module_name.error_map,
        translator=module_name.translator,
        domain_name=module_name.translator.domain_code.name,
    )


def get_router_conf(
    package: ValidatedPackage,
) -> RouetrSettings | None:
    """Get router configuration for package."""
    if package.path.is_dir():
        for item in package.path.iterdir():
            if "router" in item.name and item.suffix == ".py":
                return get_module_name(item)
    elif package.path.is_file() and package.path.match("router*.py"):
        return get_module_name(package.path)
    logger.error(f"No router found in {package.path}")
    return None


async def get_router_confs() -> list[RouetrSettings]:
    """Get router configuration for domain."""
    return [
        router_conf
        for pack in find_validated_packages(Path("api"))
        if (router_conf := get_router_conf(pack)) is not None
    ]


def import_exceptions_module(module_name: str) -> ModuleType:
    """Dynamically import exceptions module."""
    try:
        return importlib.import_module(module_name)
    except (ImportError, ModuleNotFoundError) as e:
        raise ImportError(f"Failed to import {module_name}: {e}") from e


def find_error_codes_enum(module: ModuleType) -> type[IntEnum] | None:
    """Find ErrorCodes enum in module."""
    for _, obj in inspect.getmembers(module):
        if (
            inspect.isclass(obj)
            and issubclass(obj, IntEnum)
            and obj.__name__ == "ErrorCodes"
        ):
            return obj
    return None


def find_exception_classes(
    module: ModuleType,
) -> list[type[BaseDomainException]]:
    """Find all exception classes in module."""
    exceptions = []
    for _, obj in inspect.getmembers(module):
        if (
            inspect.isclass(obj)
            and issubclass(obj, BaseDomainException)
            and obj is not BaseDomainException
        ):
            exceptions.append(obj)
    return exceptions


@dataclass
class ErrorCodeValidation:
    """Validation result for error codes."""

    package_name: str
    error_codes_enum: type[IntEnum] | None
    enum_module_name: str
    all_error_codes: list[IntEnum]
    used_codes: set[IntEnum]
    unused_codes: list[IntEnum]
    exception_classes: list[type[BaseDomainException]]

    @property
    def is_valid(self) -> bool:
        """Check if all error codes are used."""
        return len(self.unused_codes) == 0
