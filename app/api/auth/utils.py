"""Auth utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address

from fastapi import Request


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
