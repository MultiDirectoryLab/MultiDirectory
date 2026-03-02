"""Schemas for auth module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from pydantic import BaseModel


class MFAChallengeResponse(BaseModel):
    """MFA Challenge state."""

    status: str
    message: str


@dataclass
class LoginDTO:
    """Login Data Transfer Object."""

    session_key: str | None
    mfa_challenge: MFAChallengeResponse | None
