"""Schemas for auth module."""

from pydantic import BaseModel

from models.ldap3 import User


class Login(BaseModel):
    """Login form."""

    name: str
    password: str


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
