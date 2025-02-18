"""Auth utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address, ip_address

from fastapi import HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.utils.queries import set_last_logon_user
from models import User


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
            raise HTTPException(status.HTTP_403_FORBIDDEN)
        client_ip = request.client.host

    return ip_address(client_ip)


def get_user_agent_from_request(request: Request) -> str:
    """Get user agent from request.

    :param Request request: The incoming request object.
    :return str: The user agent header.
    """
    return request.headers.get("User-Agent", "")


async def create_and_set_session_key(
    user: User,
    session: AsyncSession,
    settings: Settings,
    response: Response,
    storage: SessionStorage,
    ip: IPv4Address | IPv6Address,
    user_agent: str,
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

    key = await storage.create_session(
        user.id,
        settings,
        extra_data={
            "ip": str(ip),
            "user_agent": storage.get_user_agent_hash(user_agent),
        },
    )

    response.set_cookie(
        key="id",
        value=key,
        httponly=True,
        expires=storage.key_ttl,
    )
