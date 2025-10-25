"""DNS exceptions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class DNSError(Exception):
    """DNS Error."""


class DNSSetupError(DNSError):
    """DNS setup error."""
