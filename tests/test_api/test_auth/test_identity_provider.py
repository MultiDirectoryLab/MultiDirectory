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
from entities import User
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.identity.exceptions.auth import UnauthorizedError
from ldap_protocol.identity.identity_provider import IdentityProvider
from ldap_protocol.identity.identity_provider_gateway import (
    IdentityProviderGateway,
)
from ldap_protocol.session_storage.base import SessionStorage
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
        idp = NonCallableMagicMock(spec=IdentityProvider)

        idp.rekey_session = AsyncMock()
        idp.get_current_user = IdentityProvider.get_current_user.__get__(idp)
        idp.ip_from_request = str(get_ip_from_request(request))
        idp.user_agent = get_user_agent_from_request(request)
        idp.session_key = request.cookies.get("id", "")

        if not self._cached_identity_provider:
            self._cached_identity_provider = idp

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


@pytest.fixture
def gateway() -> IdentityProviderGateway:
    """Return a mock identity provider gateway."""
    gw = NonCallableMagicMock(spec=IdentityProviderGateway)
    gw.get_user = AsyncMock()
    return gw


@pytest.fixture
def gateway_with_error() -> IdentityProviderGateway:
    """Return a mock identity provider gateway."""
    gw = NonCallableMagicMock(spec=IdentityProviderGateway)
    gw.get_user = AsyncMock(return_value=None)
    return gw


@pytest_asyncio.fixture
async def session_storage() -> SessionStorage:
    """Return a mock session storage."""
    session_storage = NonCallableMagicMock(spec=SessionStorage)
    session_storage.key_length = 16
    session_storage.key_ttl = 300
    session_storage.get_user_id = AsyncMock(return_value=1)
    session_storage.rekey_session_if_needed = AsyncMock(return_value="test")
    return session_storage


@pytest_asyncio.fixture
async def session_storage_with_error() -> SessionStorage:
    """Return a mock session storage."""
    session_storage = NonCallableMagicMock(spec=SessionStorage)
    session_storage.key_length = 16
    session_storage.key_ttl = 300
    session_storage.get_user_id = AsyncMock(
        side_effect=KeyError("Invalid data"),
    )
    session_storage.rekey_session_if_needed = AsyncMock(return_value="test")
    return session_storage


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_identity_provider(
    settings: Settings,
    gateway: IdentityProviderGateway,
    session_storage: SessionStorage,
) -> None:
    """Test identity provider."""
    idp = IdentityProvider(
        session_storage=session_storage,
        settings=settings,
        identity_provider_gateway=gateway,
        ip_from_request="127.0.0.1",
        user_agent="",
        session_key="test.session",
    )
    assert idp.key_ttl == 300
    assert idp.new_key is None

    user_id = await idp.get_user_id()
    idp._session_storage.get_user_id.assert_awaited_with(  # type: ignore  # noqa: SLF001
        idp._settings,  # noqa: SLF001
        idp._session_key,  # noqa: SLF001
        idp._user_agent,  # noqa: SLF001
        idp._ip_from_request,  # noqa: SLF001
    )

    await idp.get(user_id)
    idp._identity_provider_gateway.get_user.assert_awaited_with(  # type: ignore  # noqa: SLF001
        user_id,
    )

    session_id = idp._session_key.split(".")[0]  # noqa: SLF001
    await idp.rekey_session()
    idp._session_storage.rekey_session_if_needed.assert_awaited_with(  # type: ignore  # noqa: SLF001
        session_id,
        idp._settings,  # noqa: SLF001
    )

    assert idp.new_key == "test"


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_identity_provider_errors(
    settings: Settings,
    gateway_with_error: IdentityProviderGateway,
    session_storage_with_error: SessionStorage,
) -> None:
    """Test identity provider exception raising."""
    idp = IdentityProvider(
        session_storage=session_storage_with_error,
        settings=settings,
        identity_provider_gateway=gateway_with_error,
        ip_from_request="127.0.0.1",
        user_agent="",
        session_key="test.session",
    )

    with pytest.raises(
        UnauthorizedError,
        match="Could not validate credentials",
    ):
        await idp.get_user_id()

    with pytest.raises(
        UnauthorizedError,
        match="Could not validate credentials",
    ):
        await idp.get(123)
