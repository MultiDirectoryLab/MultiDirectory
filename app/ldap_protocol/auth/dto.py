"""Identity DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from typing import Generic, TypeVar

from enums import MFAChallengeStatuses

_MfaChallengeStatuses = TypeVar(
    "_MfaChallengeStatuses",
    MFAChallengeStatuses,
    None,
)


@dataclass
class LoginRequestDTO:
    """Login request DTO."""

    username: str
    password: str


@dataclass
class SetupDTO:
    """Setup DTO."""

    domain: str
    username: str
    user_principal_name: str
    display_name: str
    mail: str
    password: str


@dataclass
class MFAChallengeResponseDTO:
    """MFA challenge response DTO."""

    status: MFAChallengeStatuses
    message: str


@dataclass
class LoginResponseDTO(Generic[_MfaChallengeStatuses]):
    """Login response DTO."""

    session_key: str | None
    mfa_challenge: MFAChallengeResponseDTO = None  # type: ignore[assignment]


@dataclass
class MFACreateRequestDTO:
    """MFA create request DTO."""

    mfa_key: str
    mfa_secret: str
    is_ldap_scope: bool
    secret_name: str
    key_name: str


@dataclass
class MFAGetResponseDTO:
    """MFA get response DTO."""

    mfa_key: str | None
    mfa_secret: str | None
    mfa_key_ldap: str | None
    mfa_secret_ldap: str | None
