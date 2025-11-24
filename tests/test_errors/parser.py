"""Parser for ldap_protocol packages with exceptions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import importlib
import inspect
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from types import ModuleType
from typing import Iterator

from loguru import logger

from errors import BaseDomainException


def get_ldap_protocol_path() -> Path:
    """Get path to ldap_protocol directory."""
    return Path("ldap_protocol")


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


def has_exceptions(package_path: Path) -> bool:
    """Check if package has exceptions (file or directory)."""
    exceptions_file = package_path / "exceptions.py"
    exceptions_dir = package_path / "exceptions"
    return exceptions_file.exists() or (
        exceptions_dir.exists() and (exceptions_dir / "__init__.py").exists()
    )


@dataclass
class ValidatedPackage:
    """Information about validated package."""

    path: Path
    package_name: str
    has_exceptions: bool

    @property
    def is_valid(self) -> bool:
        """Check if package is valid (has exceptions)."""
        return self.has_exceptions


def find_validated_packages(
    base_path: Path | None = None,
    relative_to: Path | None = None,
) -> Iterator[ValidatedPackage]:
    """Find all packages that contain exceptions and optional components.

    Yields:
        ValidatedPackage: Information about validated package

    """
    if base_path is None:
        base_path = get_ldap_protocol_path()

    if relative_to is None:
        relative_to = base_path.parent

    if not base_path.exists():
        return

    for item in sorted(base_path.iterdir()):
        if should_skip_path(item):
            continue

        if item.is_dir() and (item / "__init__.py").exists():
            relative_path = item.relative_to(relative_to)
            package_name = str(relative_path).replace("/", ".")

            if has_exceptions(item):
                yield ValidatedPackage(
                    path=item,
                    package_name=package_name,
                    has_exceptions=True,
                )

            yield from find_validated_packages(item, relative_to)


def get_all_validated_packages() -> list[ValidatedPackage]:
    """Get all validated packages as a list."""
    return list(find_validated_packages())


def get_package_info(package: ValidatedPackage) -> dict:
    """Get detailed information about package."""
    return {
        "package_name": package.package_name,
        "path": str(package.path),
        "has_exceptions": package.has_exceptions,
    }


def get_exceptions_module_name(package: ValidatedPackage) -> str:
    """Get module name for exceptions in package."""
    exceptions_file = package.path / "exceptions.py"
    exceptions_dir = package.path / "exceptions"

    if exceptions_file.exists() or (
        exceptions_dir.exists() and (exceptions_dir / "__init__.py").exists()
    ):
        return f"{package.package_name}.exceptions"
    return ""


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


def get_all_exception_classes_from_package(
    package: ValidatedPackage,
) -> list[type[BaseDomainException]]:
    """Get all exception classes from package (including submodules)."""
    exceptions_module_name = get_exceptions_module_name(package)
    if not exceptions_module_name:
        return []

    all_exceptions = []

    try:
        exceptions_module = import_exceptions_module(exceptions_module_name)
        all_exceptions.extend(find_exception_classes(exceptions_module))

        exceptions_dir = package.path / "exceptions"
        if exceptions_dir.exists() and exceptions_dir.is_dir():
            for item in exceptions_dir.iterdir():
                if (
                    item.is_file()
                    and item.suffix == ".py"
                    and item.stem != "__init__"
                    and not should_skip_path(item)
                ):
                    submodule_name = f"{exceptions_module_name}.{item.stem}"
                    try:
                        submodule = import_exceptions_module(submodule_name)
                        all_exceptions.extend(
                            find_exception_classes(submodule),
                        )
                    except ImportError:
                        continue
    except ImportError:
        return []

    return all_exceptions


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


def _find_error_codes_in_submodules(
    exceptions_module_name: str,
    package_path: Path,
) -> type[IntEnum] | None:
    """Find ErrorCodes enum in submodules of exceptions package."""
    exceptions_dir = package_path / "exceptions"
    if not exceptions_dir.exists() or not exceptions_dir.is_dir():
        return None

    for item in exceptions_dir.iterdir():
        if (
            item.is_file()
            and item.suffix == ".py"
            and item.stem != "__init__"
            and not should_skip_path(item)
        ):
            submodule_name = f"{exceptions_module_name}.{item.stem}"
            try:
                submodule = import_exceptions_module(submodule_name)
                error_codes_enum = find_error_codes_enum(submodule)
                if error_codes_enum is not None:
                    return error_codes_enum
            except ImportError:
                continue
    return None


def _collect_used_codes(
    exception_classes: list[type[BaseDomainException]],
    all_error_codes: list[IntEnum],
) -> set[IntEnum]:
    """Collect all error codes used by exception classes."""
    used_codes = set()
    for exc_class in exception_classes:
        if not hasattr(exc_class, "code"):
            continue

        code_value = None

        code_value = getattr(exc_class, "code", None)

        if code_value is None:
            code_value = exc_class.__dict__.get("code")

        if code_value is None:
            class_vars = vars(exc_class)
            code_value = class_vars.get("code")

        if code_value is None:
            continue

        if isinstance(code_value, IntEnum):
            used_codes.add(code_value)
        else:
            try:
                if hasattr(code_value, "value"):
                    code_value_int = code_value.value
                elif hasattr(code_value, "__int__"):
                    code_value_int = int(code_value)
                else:
                    continue

                for enum_code in all_error_codes:
                    if enum_code.value == code_value_int:
                        used_codes.add(enum_code)
                        break
            except (ValueError, TypeError, AttributeError):
                continue
    return used_codes


def _find_all_error_codes_enums_in_package(
    package: ValidatedPackage,
) -> list[tuple[type[IntEnum], ModuleType]]:
    """Find all ErrorCodes enums in package exceptions module and submodules.

    Returns:
        list[tuple[type[IntEnum], ModuleType]]: List of (ErrorCodes enum,
            module)

    """
    exceptions_module_name = get_exceptions_module_name(package)
    if not exceptions_module_name:
        return []

    enums = []

    try:
        exceptions_module = import_exceptions_module(exceptions_module_name)
        error_codes_enum = find_error_codes_enum(exceptions_module)
        if error_codes_enum is not None:
            enums.append((error_codes_enum, exceptions_module))
    except ImportError:
        pass

    exceptions_dir = package.path / "exceptions"
    if exceptions_dir.exists() and exceptions_dir.is_dir():
        for item in exceptions_dir.iterdir():
            if (
                item.is_file()
                and item.suffix == ".py"
                and item.stem != "__init__"
                and not should_skip_path(item)
            ):
                submodule_name = f"{exceptions_module_name}.{item.stem}"
                try:
                    submodule = import_exceptions_module(submodule_name)
                    error_codes_enum = find_error_codes_enum(submodule)
                    if error_codes_enum is not None:
                        enums.append((error_codes_enum, submodule))
                except ImportError:
                    continue

    return enums


def _get_exception_classes_from_module(
    module: ModuleType,
) -> list[type[BaseDomainException]]:
    """Get exception classes from a specific module."""
    return find_exception_classes(module)


def validate_error_codes_usage(
    package: ValidatedPackage,
) -> list[ErrorCodeValidation]:
    """Validate that all error codes from ErrorCodes enum are used.

    Returns:
        list[ErrorCodeValidation]: List of validation results for each
            ErrorCodes enum found in the package.

    """
    error_codes_enums = _find_all_error_codes_enums_in_package(package)

    if not error_codes_enums:
        return []

    validations = []

    for error_codes_enum, enum_module in error_codes_enums:
        enum_module_name = enum_module.__name__

        exception_classes = _get_exception_classes_from_module(enum_module)

        exceptions_module_name = get_exceptions_module_name(package)
        exceptions_dir = package.path / "exceptions"
        if exceptions_dir.exists() and exceptions_dir.is_dir():
            for item in exceptions_dir.iterdir():
                if (
                    item.is_file()
                    and item.suffix == ".py"
                    and item.stem != "__init__"
                    and not should_skip_path(item)
                ):
                    submodule_name = f"{exceptions_module_name}.{item.stem}"
                    try:
                        submodule = import_exceptions_module(submodule_name)
                        submodule_error_codes = find_error_codes_enum(
                            submodule,
                        )
                        if submodule_error_codes is error_codes_enum:
                            exception_classes.extend(
                                _get_exception_classes_from_module(
                                    submodule,
                                ),
                            )
                    except ImportError:
                        continue

        all_error_codes = list(error_codes_enum)

        used_codes = _collect_used_codes(exception_classes, all_error_codes)

        unused_codes = [
            code for code in all_error_codes if code not in used_codes
        ]

        validations.append(
            ErrorCodeValidation(
                package_name=package.package_name,
                error_codes_enum=error_codes_enum,
                enum_module_name=enum_module_name,
                all_error_codes=all_error_codes,
                used_codes=used_codes,
                unused_codes=unused_codes,
                exception_classes=exception_classes,
            ),
        )

    return validations


def validate_all_packages_error_codes() -> Iterator[ErrorCodeValidation]:
    """Validate error codes usage for all validated packages.

    Yields:
        ErrorCodeValidation: Validation result for each ErrorCodes enum
            found in each package

    """
    for package in find_validated_packages():
        validations = validate_error_codes_usage(package)
        yield from validations


logger.error([i for i in validate_all_packages_error_codes()])
