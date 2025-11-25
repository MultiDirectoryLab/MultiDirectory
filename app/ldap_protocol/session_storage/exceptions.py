"""Exceptions for session storage.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class SessionStorageError(Exception):
    """Session storage error."""


class SessionStorageInvalidKeyError(SessionStorageError):
    """Session storage invalid key error."""


class SessionStorageMissingDataError(SessionStorageError):
    """Session storage missing data error."""


class SessionStorageInvalidIpError(SessionStorageError):
    """Session storage invalid ip error."""


class SessionStorageInvalidUserAgentError(SessionStorageError):
    """Session storage invalid user agent error."""


class SessionStorageInvalidSignatureError(SessionStorageError):
    """Session storage invalid signature error."""


class SessionStorageInvalidDataError(SessionStorageError):
    """Session storage invalid data error."""
