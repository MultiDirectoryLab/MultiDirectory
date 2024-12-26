"""Auth utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import secrets
from ipaddress import IPv4Address

from fastapi import Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.utils.queries import set_last_logon_user
from models import User

from .oauth2 import create_token
from .schema import REFRESH_PATH


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


async def create_and_set_tokens(
    user: User,
    session: AsyncSession,
    settings: Settings,
    response: Response,
) -> None:
    """Create and set access and refresh tokens.

    Update the user's last logon time and set the appropriate cookies
    in the response.

    :param User user: db user
    :param AsyncSession session: db session
    :param Settings settings: app settings
    :param Response response: fastapi response object
    """
    access_token = create_token(  # noqa: S106
        uid=user.id,
        secret=settings.SECRET_KEY,
        expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        grant_type="access",
        extra_data={"uuid": secrets.token_urlsafe(8)},
    )
    refresh_token = create_token(  # noqa: S106
        uid=user.id,
        secret=settings.SECRET_KEY,
        expires_minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES,
        grant_type="refresh",
        extra_data={"uuid": secrets.token_urlsafe(8)},
    )

    await set_last_logon_user(user, session, settings.TIMEZONE)

    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
    )
    response.set_cookie(
        key="refresh_token",
        value=f"Bearer {refresh_token}",
        httponly=True,
        path=REFRESH_PATH,
    )
