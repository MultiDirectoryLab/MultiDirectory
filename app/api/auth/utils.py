"""Auth utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address

from fastapi import Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dialogue import SessionStorage
from ldap_protocol.utils.queries import set_last_logon_user
from models import User


def get_ip_from_request(request: Request) -> IPv4Address | None:
    """Get IP address from request.

    :param Request request: The incoming request object.
    :return IPv4Address | None: The IP address or None.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0]
    else:
        if request.client is None:
            return None
        client_ip = request.client.host

    return IPv4Address(client_ip)


async def create_and_set_session_key(
    user: User,
    session: AsyncSession,
    settings: Settings,
    response: Response,
    storage: SessionStorage,
) -> None:
    """Create and set access and refresh tokens.

    Update the user's last logon time and set the appropriate cookies
    in the response.

    :param User user: db user
    :param AsyncSession session: db session
    :param Settings settings: app settings
    :param Response response: fastapi response object
    """
    await set_last_logon_user(user, session, settings.TIMEZONE)

    response.set_cookie(
        key="id",
        value=await storage.create_session(user.id, settings),
        httponly=True,
        expires=storage.key_ttl,
    )
