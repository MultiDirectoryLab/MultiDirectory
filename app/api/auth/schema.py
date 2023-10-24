"""Schemas for auth module."""

import re
from typing import Literal

from fastapi.param_functions import Form
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, SecretStr, computed_field, validator

from models.ldap3 import User as DBUser

domain_regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
domain_re = re.compile(domain_regex)


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


class User(BaseModel):
    """User model, alias for db user."""

    id: int  # noqa: A003
    sam_accout_name: str
    user_principal_name: str
    mail: str
    display_name: str

    _access_type: Literal['access', 'refresh', 'multifactor']

    @classmethod
    def from_db(cls, user: DBUser, access: str) -> 'User':
        """Create model from db model."""
        return cls(
            id=user.id,
            sam_accout_name=user.sam_accout_name,
            user_principal_name=user.user_principal_name,
            mail=user.mail,
            display_name=user.display_name,
            _access_type=access,
        )


class SetupRequest(BaseModel):
    """Setup app form."""

    domain: str
    username: str
    user_principal_name: str
    display_name: str
    mail: EmailStr
    password: str

    @validator('domain')
    def validate_domain(cls, v):  # noqa
        if re.match(domain_re, v) is None:
            raise ValueError('Invalid domain value')
        return v.lower().replace('http://', '').replace('https://', '')


class MFACreateRequest(BaseModel):
    """Crete MFA creds request."""

    mfa_key: str
    mfa_secret: str
    is_ldap_scope: bool

    @computed_field
    def key_name(self) -> str:  # noqa
        if self.is_ldap_scope:
            return 'mfa_key_ldap'

        return 'mfa_key'

    @computed_field
    def secret_name(self) -> str:  # noqa
        if self.is_ldap_scope:
            return 'mfa_secret_ldap'

        return 'mfa_secret'


class MFAGetResponse(BaseModel):
    """Secret creds of api."""

    mfa_key: str | None
    mfa_secret: SecretStr | None
    mfa_key_ldap: str | None
    mfa_secret_ldap: SecretStr | None
