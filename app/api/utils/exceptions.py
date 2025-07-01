"""Common business exceptions for all service classes in the project."""


class KerberosConflictError(Exception):
    """Raised when a conflict occurs."""


class KerberosNotFoundError(Exception):
    """Raised when a resource is not found."""


class KerberosDependencyError(Exception):
    """Raised when a dependency fails."""


class KerberosUnavailableError(Exception):
    """Raised when the service is unavailable."""


class KerberosInternalError(Exception):
    """Raised for internal errors."""
