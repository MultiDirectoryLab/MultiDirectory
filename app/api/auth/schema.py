"""Schemas for auth module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from fastapi.param_functions import Form
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    computed_field,
    field_validator,
)

from ldap_protocol.utils.const import EmailStr

_domain_re = re.compile(
    "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z-]{2,63}$",
)


class Login(BaseModel):
    """Login form."""

    username: str
    password: str


class OAuth2Form(OAuth2PasswordRequestForm):
    """OAuth2 custom form."""

    def __init__(
        self,
        username: str = Form(),
        password: str = Form(),
    ):
        """Initialize form.

        Args:
            username (str): username
            password (str): password
        """
        self.username = username
        self.password = password


class Token(BaseModel):
    """Token model."""

    access_token: str
    refresh_token: str
    type: str


class SetupRequest(BaseModel):
    """Setup app form."""

    domain: str
    username: str
    user_principal_name: str
    display_name: str
    mail: EmailStr
    password: str

    @field_validator("domain")
    def validate_domain(cls, v: str) -> str:  # noqa FIXME why noqa?
        """Validate domain.

        Args:
            v (str): value

        Returns:
            str: Validated domain string.

        Raises:
            ValueError: If the domain is invalid.
        """
        if re.match(_domain_re, v) is None:
            raise ValueError("Invalid domain value")
        return v.lower()


class MFACreateRequest(BaseModel):
    """Create MFA creds request."""

    mfa_key: str
    mfa_secret: str
    is_ldap_scope: bool

    @computed_field  # type: ignore
    @property
    def key_name(self) -> str:
        """Get key name.

        Returns:
            str: key name
        """
        if self.is_ldap_scope:
            return "mfa_key_ldap"

        return "mfa_key"

    @computed_field  # type: ignore
    @property
    def secret_name(self) -> str:
        """Get secret name.

        Returns:
            str: secret name
        """
        if self.is_ldap_scope:
            return "mfa_secret_ldap"

        return "mfa_secret"


class MFAGetResponse(BaseModel):
    """Secret creds of api."""

    mfa_key: str | None
    mfa_secret: SecretStr | None
    mfa_key_ldap: str | None
    mfa_secret_ldap: SecretStr | None


class MFAChallengeResponse(BaseModel):
    """MFA Challenge state."""

    status: str
    message: str


class SessionContentSchema(BaseModel):
    """Session content schema."""

    model_config = ConfigDict(extra="allow")

    id: int
    sign: str = Field("", description="Session signature")
    issued: datetime
    ip: IPv4Address | IPv6Address
    protocol: Literal["ldap", "http"] = "http"
