from pydantic import BaseModel

from models.ldap3 import User


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserModel(BaseModel):
    id: int
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
