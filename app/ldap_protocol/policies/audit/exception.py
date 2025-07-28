"""Audit destination dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class AuditNotFoundError(Exception):
    """Exception raised when an audit model is not found."""


class AuditAlreadyExistsError(Exception):
    """Exception raised when an audit model already exists."""
