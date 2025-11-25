"""OAuth utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address, ip_address

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import HTTPException, Request, status

from api.auth.adapters import AuthFastAPIAdapter


@inject
async def verify_auth(
    identity_adapter: FromDishka[AuthFastAPIAdapter],
) -> None:
    """Retrieve the currently authenticated user and rekey their session.

    This function fetches the current user based on the request's
    authentication credentials and rekeys the user's session
    for security purposes.

    Args:
        identity_adapter (FromDishka[IdentityFastAPIAdapter]): The user adapter
            instance injected from Dishka DI container, used for
            user operations.

    """
    await identity_adapter.get_current_user()


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
    user_agent_header = request.headers.get("User-Agent")
    return user_agent_header if user_agent_header else ""
