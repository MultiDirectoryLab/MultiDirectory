"""Schemas for auth module."""

from fastapi.param_functions import Form
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from models.ldap3 import User


class Login(BaseModel):
    """Login form."""

    username: str
    password: str


class OAuth2Form(OAuth2PasswordRequestForm):
    """OAuth2 custom form."""

    def __init__(  # noqa: D107
        self,
        username: str = Form(),
        password: str = Form(),
    ):
        self.username = username
        self.password = password


class Token(BaseModel):
    """Token model."""

    access_token: str
    refresh_token: str
    type: str  # noqa: A003


class UserModel(BaseModel):
    """User model, alias for db user."""

    id: int  # noqa: A003
    sam_accout_name: str
    user_principal_name: str
    mail: str
    display_name: str

    @classmethod
    def from_db(cls, user: User) -> 'UserModel':
        """Create model from db model."""
        return cls(
            id=user.id,
            sam_accout_name=user.sam_accout_name,
            user_principal_name=user.user_principal_name,
            mail=user.mail,
            display_name=user.display_name,
        )
