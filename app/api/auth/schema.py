"""Schemas for auth module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re

from fastapi.param_functions import Form
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, SecretStr, computed_field, field_validator

from ldap_protocol.utils.const import EmailStr

domain_regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
domain_re = re.compile(domain_regex)
REFRESH_PATH = "/api/auth/token/refresh"


class Login(BaseModel):
    """Login form."""

    username: str
    password: str


class OAuth2Form(OAuth2PasswordRequestForm):
    """OAuth2 custom form."""

    def __init__(  # noqa: D107
        self,
        username: str = Form(),  # noqa: B008
        password: str = Form(),  # noqa: B008
    ):
        self.username = username
        self.password = password


class Token(BaseModel):
    """Token model."""

    access_token: str
    refresh_token: str
    type: str  # noqa: A003


class SetupRequest(BaseModel):
    """Setup app form."""

    domain: str
    username: str
    user_principal_name: str
    display_name: str
    mail: EmailStr
    password: str

    @field_validator("domain")
    def validate_domain(cls, v: str) -> str:  # noqa
        if re.match(domain_re, v) is None:
            raise ValueError("Invalid domain value")
        return v.lower().replace("http://", "").replace("https://", "")


class MFACreateRequest(BaseModel):
    """Crete MFA creds request."""

    mfa_key: str
    mfa_secret: str
    is_ldap_scope: bool

    @computed_field  # type: ignore
    @property
    def key_name(self) -> str:  # noqa
        if self.is_ldap_scope:
            return "mfa_key_ldap"

        return "mfa_key"

    @computed_field  # type: ignore
    @property
    def secret_name(self) -> str:  # noqa
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
