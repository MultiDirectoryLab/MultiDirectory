"""Fixtures and providers for auth-related API tests."""

import datetime
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, Mock, NonCallableMagicMock

import pytest
import pytest_asyncio
from dishka import (
    AsyncContainer,
    Provider,
    Scope,
    make_async_container,
    provide,
)
from fastapi import HTTPException, status
from httpx import AsyncClient
from starlette.requests import Request
from starlette.responses import Response

from api.auth.adapters import CurrentUserGateway
from config import Settings
from ldap_protocol.dialogue import UserSchema
from tests.conftest import TestProvider


class TestAuthProvider(Provider):
    """Provide mocked gateways tailored for authentication tests."""

    __test__ = False

    _cached_current_user_gateway: Mock | None = None

    @provide(scope=Scope.APP, provides=CurrentUserGateway)
    async def get_current_user_gateway(self) -> AsyncIterator[Mock]:
        """Get mock current user gateway."""
        current_user_gateway = NonCallableMagicMock(spec=CurrentUserGateway)

        current_user_gateway.rekey_session = AsyncMock()

        if not self._cached_current_user_gateway:
            self._cached_current_user_gateway = current_user_gateway

        yield self._cached_current_user_gateway

        self._cached_current_user_gateway = None


@pytest_asyncio.fixture(scope="session")
async def container(settings: Settings) -> AsyncIterator[AsyncContainer]:
    """Fixture to provide the test container."""
    container = make_async_container(
        TestProvider(),
        TestAuthProvider(),
        context={Settings: settings},
        start_scope=Scope.RUNTIME,
    )
    yield container
    await container.close()


@pytest_asyncio.fixture
async def request_params() -> dict:
    """Return minimal ASGI scope plus response for request-scoped providers."""
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": ("testclient", 0),
        "server": ("testserver", 80),
    }
    request = Request(scope)
    response = Response()
    return {Request: request, Response: response}


@pytest_asyncio.fixture
async def current_user_gateway(
    container: AsyncContainer,
    request_params: dict,
) -> AsyncIterator[CurrentUserGateway]:
    """Yield a gateway mock that mimics successful authentication flow."""
    async with container(
        scope=Scope.REQUEST,
        context=request_params,
    ) as cont:
        gateway = await cont.get(CurrentUserGateway)
        gateway_any: Any = gateway
        gateway_any.get_current_user = AsyncMock(
            return_value=UserSchema(
                id=1,
                session_id="1",
                sam_account_name="user0",
                user_principal_name="user0@example.com",
                mail="user0@example.com",
                display_name="User Zero",
                directory_id=1,
                dn="CN=User Zero,CN=Users,DC=example,DC=com",
                account_exp=datetime.datetime.max,
                role_ids=[1],
            ),
        )
        yield gateway


@pytest_asyncio.fixture
async def invalid_user_gateway(
    container: AsyncContainer,
    request_params: dict,
) -> AsyncIterator[CurrentUserGateway]:
    """Yield a gateway mock that raises 401 to simulate invalid sessions."""
    async with container(
        scope=Scope.REQUEST,
        context=request_params,
    ) as cont:
        gateway = await cont.get(CurrentUserGateway)
        gateway_any: Any = gateway
        gateway_any.get_current_user = AsyncMock(
            side_effect=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session",
            ),
        )
        yield gateway


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_auth_user(
    http_client: AsyncClient,
    current_user_gateway: CurrentUserGateway,
) -> None:
    """Get token with ACCOUNTDISABLE flag in userAccountControl attribute."""
    response = await http_client.get("/auth/me")
    assert response.status_code == status.HTTP_200_OK

    current_user_gateway.get_current_user.assert_called()  # type: ignore
    current_user_gateway.rekey_session.assert_called()  # type: ignore


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_auth_invalid_user(
    unbound_http_client: AsyncClient,
    invalid_user_gateway: Mock,
) -> None:
    """Get token with ACCOUNTDISABLE flag in userAccountControl attribute."""
    response = await unbound_http_client.get("/auth/me")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    invalid_user_gateway.get_current_user.assert_called()  # type: ignore
    invalid_user_gateway.rekey_session.assert_not_called()  # type: ignore
