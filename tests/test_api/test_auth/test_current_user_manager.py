"""Fixtures and providers for auth-related API tests."""

import datetime
from typing import AsyncIterator
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

from api.auth.utils import get_ip_from_request, get_user_agent_from_request
from config import Settings
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.identity.identity_provider import IdentityProvider
from tests.conftest import TestProvider


class TestAuthProvider(Provider):
    """Provide mocked gateways tailored for authentication tests."""

    __test__ = False

    _cached_identity_provider: Mock | None = None

    @provide(scope=Scope.REQUEST, provides=IdentityProvider)
    async def get_identity_provider(
        self,
        request: Request,
    ) -> AsyncIterator[Mock]:
        """Get mock current user gateway."""
        identity_provider = NonCallableMagicMock(
            spec=IdentityProvider,
        )

        identity_provider.rekey_session = AsyncMock()
        identity_provider.get_current_user = (
            IdentityProvider.get_current_user.__get__(identity_provider)
        )
        ip_from_request = get_ip_from_request(request)
        user_agent = get_user_agent_from_request(request)
        identity_provider.ip_from_request = str(ip_from_request)
        identity_provider.user_agent = user_agent
        identity_provider.session_key = request.cookies.get("id", "")

        if not self._cached_identity_provider:
            self._cached_identity_provider = identity_provider

        yield self._cached_identity_provider

        self._cached_identity_provider = None


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
        "client": ("127.0.0.1", 0),
        "server": ("testserver", 80),
    }
    request = Request(scope)
    response = Response()
    return {Request: request, Response: response}


@pytest_asyncio.fixture
async def current_user_provider(
    container: AsyncContainer,
    request_params: dict,
) -> AsyncIterator[IdentityProvider]:
    """Yield a provider mock that mimics successful authentication flow."""
    async with container(
        scope=Scope.REQUEST,
        context=request_params,
    ) as cont:
        provider = await cont.get(IdentityProvider)
        user = UserSchema(
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
        )
        provider.get_user_id = AsyncMock(return_value=1)  # type: ignore
        provider.get = AsyncMock(return_value=user)  # type: ignore

        yield provider


@pytest_asyncio.fixture
async def invalid_user_provider(
    container: AsyncContainer,
    request_params: dict,
) -> AsyncIterator[IdentityProvider]:
    """Yield a provider mock that raises 401 to simulate invalid sessions."""
    async with container(
        scope=Scope.REQUEST,
        context=request_params,
    ) as cont:
        provider = await cont.get(IdentityProvider)
        provider.get_user_id = AsyncMock(  # type: ignore
            side_effect=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Coubld not validate credentials",
            ),
        )
        yield provider


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_auth_user(
    http_client: AsyncClient,
    current_user_provider: Mock,
) -> None:
    """Verify successful authentication and session rekeying is performed."""
    response = await http_client.get("/auth/me")
    assert response.status_code == status.HTTP_200_OK

    current_user_provider.get_user_id.assert_called()  # type: ignore
    current_user_provider.get.assert_called()  # type: ignore
    current_user_provider.rekey_session.assert_called()  # type: ignore


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_auth_invalid_user(
    unbound_http_client: AsyncClient,
    invalid_user_provider: Mock,
) -> None:
    """Validate unauthorized sessions return 401 and do not rekey session."""
    response = await unbound_http_client.get("/auth/me")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    invalid_user_provider.get_user_id.assert_called()  # type: ignore
    invalid_user_provider.get.assert_not_called()  # type: ignore
    invalid_user_provider.rekey_session.assert_not_called()  # type: ignore
