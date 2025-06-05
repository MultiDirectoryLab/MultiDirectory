"""Sasl plain auth method.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.utils.queries import get_user
from models import User
from security import verify_password

from .base import SaslAuthentication, SASLMethod


class SaslPLAINAuthentication(SaslAuthentication):
    """Sasl plain auth form."""

    mechanism: ClassVar[SASLMethod] = SASLMethod.PLAIN
    credentials: bytes
    username: str | None = None

    def is_valid(self, user: User | None) -> bool:
        """Check if pwd is valid for user.

        Args:
            user (User | None): in db user

        Returns:
            bool: status
        """
        password = getattr(user, "password", None)
        if password is not None:
            return verify_password(
                self.password.get_secret_value(),
                password,
            )
        return False

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        Returns:
            bool: status

        """
        return False

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> "SaslPLAINAuthentication":
        """Get auth from data.

        Args:
            data (list[ASN1Row]): data

        Returns:
            SaslPLAINAuthentication
        """
        _, username, password = data[1].value.split("\\x00")
        return cls(
            credentials=data[1].value,
            username=username,
            password=password,
        )

    async def get_user(self, session: AsyncSession, _: str) -> User:
        """Get user.

        Args:
            session (AsyncSession): async db session
            _ (str): unused arg

        Returns:
            User: user
        """
        return await get_user(session, self.username)  # type: ignore
