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

        :param User | None user: indb user
        :return bool: status
        """
        password = getattr(user, "password", None)
        if password is not None:
            return verify_password(self.password.get_secret_value(), password)
        return False

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        :return bool: status
        """
        return False

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> "SaslPLAINAuthentication":
        """Get auth from data."""
        _, username, password = data[1].value.split("\\x00")
        return cls(
            credentials=data[1].value,
            username=username,
            password=password,
        )

    async def get_user(self, session: AsyncSession, _: str) -> User:
        """Get user."""
        return await get_user(session, self.username)  # type: ignore
