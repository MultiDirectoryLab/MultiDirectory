"""Identity utility functions for authentication and user management.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address, ip_address

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from entities import User
from ldap_protocol.utils.queries import get_user
from password_manager import PasswordValidator


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str,
    password_validator: PasswordValidator,
) -> User | None:
    """Get user and verify password.

    :param AsyncSession session: sa session
    :param str username: any str
    :param str password: any str
    :return User | None: User model (pydantic).
    """
    user = await get_user(session, username)

    if not user or not user.password or not password:
        return None
    if not password_validator.verify_password(password, user.password):
        return None
    return user


def get_ip_from_request(request: Request) -> IPv4Address | IPv6Address:
    """Get IP address from request.

    :param Request request: The incoming request object.
    :return IPv4Address | None: The IP address or None.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0]
    else:
        if request.client is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST)
        client_ip = request.client.host

    return ip_address(client_ip)


def get_user_agent_from_request(request: Request) -> str:
    """Get user agent from request.

    :param Request request: The incoming request object.
    :return str: The user agent header.
    """
    user_agent_header = request.headers.get("User-Agent")
    return user_agent_header if user_agent_header else ""
