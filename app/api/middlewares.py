"""Middlewares MultiDirectory module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import time
from typing import Callable

from fastapi import Request, Response

from ldap_protocol.identity.identity_provider import IdentityProvider


async def proc_time_header_middleware(
    request: Request,
    call_next: Callable,
) -> Response:
    """Set X-Process-Time header.

    :param Request request: incoming HTTP request
    :param Callable call_next: next middleware or route handler
    :return Response: HTTP response with session cookie
    """
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}"
    return response


async def set_key_middleware(
    request: Request,
    call_next: Callable,
) -> Response:
    """Set session key to response cookies.

    :param Request request: incoming HTTP request
    :param Callable call_next: next middleware or route handler
    :return Response: HTTP response with session cookie
    """
    response: Response = await call_next(request)
    identity_provider: IdentityProvider = (
        await request.state.dishka_container.get(
            IdentityProvider,
        )
    )

    if identity_provider.new_key:
        response.set_cookie(
            key="id",
            value=identity_provider.new_key,
            httponly=True,
            expires=identity_provider.key_ttl,
        )

    return response
