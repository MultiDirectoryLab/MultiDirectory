"""Directory Deletion Exceptions module."""

class SystemDirectoryDeletionError(Exception):
    """Raised when attempting to delete a system directory."""

class DomainDirectoryDeletionError(Exception):
    """Raised when attempting to delete a domain directory."""

class UserSelfDeletionError(Exception):
    """Raised when a user attempts to delete their own directory."""

class DirectoryNotFoundError(Exception):
    """Raised when the specified directory is not found."""

class DirectoryHasPrimaryGroupMembersError(Exception):
    """Raised when attempting to delete a group directory that has primary group members."""  # noqa: E501
