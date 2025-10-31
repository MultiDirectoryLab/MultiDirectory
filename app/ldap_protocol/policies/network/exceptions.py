"""Network policies exceptions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class NetworkPolicyError(Exception):
    """Network policy error."""


class NetworkPolicyAlreadyExistsError(NetworkPolicyError):
    """Network policy already exists error."""


class NetworkPolicyNotFoundError(NetworkPolicyError):
    """Network policy not found error."""


class LastActivePolicyError(NetworkPolicyError):
    """Last active policy error."""
