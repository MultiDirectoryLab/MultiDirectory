"""Test MultifactorAPI."""

from unittest.mock import patch

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.multifactor import MultifactorAPI, _MultifactorError
from models import NetworkPolicy


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
@pytest.mark.parametrize(
    (
        "mock_post_side_effect",
        "policy_bypass_no_connection",
        "policy_bypass_service_failure",
        "expected_result",
        "expected_exception",
    ),
    [
        # 1. httpx.ConnectTimeout, bypass_no_connection=True => True
        (
            httpx.ConnectTimeout("Connection timed out"), True, False, True,
            None,
        ),

        # 2. httpx.ConnectTimeout, bypass_no_connection=False =>
        # raise MultifactorError
        (
            httpx.ConnectTimeout("Connection timed out"), False, False, None,
            _MultifactorError,
        ),

        # 3. httpx.ReadTimeout => False
        (httpx.ReadTimeout("Read timed out"), False, False, False, None),

        # 4. status_code=401 => True
        (
            httpx.Response(status_code=401),
            False, False, True, None,
        ),

        # 5. status_code=500, bypass_service_failure=True => True
        (
            httpx.Response(status_code=500, json={"detail": "Server Error"}),
            False, True, True, None,
        ),

        # 6. status_code=500, bypass_service_failure=False =>
        # raise MultifactorError
        (
            httpx.Response(status_code=500, json={"detail": "Server Error"}),
            False, False, None, _MultifactorError,
        ),

        # 7. status_code=200, 'model.status' != "Granted" => False
        (
            httpx.Response(
                status_code=200,
                json={"model": {"status": "Denied"}},
            ),
            False, False, False, None,
        ),

        # 8. status_code=200, 'model.status' == "Granted" => True
        (
            httpx.Response(
                status_code=200,
                json={"model": {"status": "Granted"}},
            ),
            False, False, True, None,
        ),
    ],
)
async def test_ldap_validate_mfa(
    mock_post_side_effect,
    policy_bypass_no_connection,
    policy_bypass_service_failure,
    expected_result,
    expected_exception,
    mfa_api: MultifactorAPI,
    session: AsyncSession,
    setup_session: None,
):
    """Test the LDAP validate MFA function with various scenarios."""
    policy = await session.scalar(
        select(NetworkPolicy)
        .limit(1),
    )

    policy.bypass_no_connection = policy_bypass_no_connection
    policy.bypass_service_failure = policy_bypass_service_failure
    await session.commit()

    async def handler(request: httpx.Request) -> httpx.Response:
        if isinstance(mock_post_side_effect, httpx.Response):
            return mock_post_side_effect
        raise mock_post_side_effect

    with patch.object(
        mfa_api.settings.__class__, 'MFA_API_URI',
        'http://mocked.api.multifactor.ru',
    ):

        assert mfa_api.settings.MFA_API_URI == \
            'http://mocked.api.multifactor.ru'

        mocked_client = httpx.AsyncClient(
            timeout=4,
            transport=httpx.MockTransport(handler),
        )
        mfa_api.client = mocked_client

        if expected_exception:
            with pytest.raises(expected_exception):
                await mfa_api.ldap_validate_mfa("user", "password", policy)
        else:
            result = await mfa_api.ldap_validate_mfa(
                "user", "password", policy,
            )
            assert result == expected_result
