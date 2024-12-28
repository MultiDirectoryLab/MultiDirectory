"""Test MultifactorAPI."""

from unittest.mock import patch

import httpx
import pytest

from ldap_protocol.multifactor import MultifactorAPI


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
@pytest.mark.parametrize(
    (
        "mock_post_side_effect",
        "expected_result",
        "expected_exception",
    ),
    [
        # 1. httpx.ConnectTimeout => raise MFAConnectError
        (
            httpx.ConnectTimeout("Connection timed out"), True,
            MultifactorAPI.MFAConnectError,
        ),

        # 2. httpx.ReadTimeout => False
        (httpx.ReadTimeout("Read timed out"), False, None),

        # 3. status_code=401 => raise MFAMissconfiguredError
        (
            httpx.Response(status_code=401), True,
            MultifactorAPI.MFAMissconfiguredError,
        ),

        # 4. status_code=500 => raise MultifactorError
        (
            httpx.Response(status_code=500, json={"detail": "Server Error"}),
            True, MultifactorAPI.MultifactorError,
        ),

        # 5. status_code=200, 'model.status' != "Granted" => False
        (
            httpx.Response(
                status_code=200,
                json={"model": {"status": "Denied"}},
            ), False, None,
        ),

        # 6. status_code=200, 'model.status' == "Granted" => True
        (
            httpx.Response(
                status_code=200,
                json={"model": {"status": "Granted"}},
            ), True, None,
        ),
    ],
)
async def test_ldap_validate_mfa(
    mock_post_side_effect,
    expected_result,
    expected_exception,
    mfa_api: MultifactorAPI,
):
    """Test the LDAP validate MFA function with various scenarios."""

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
                await mfa_api.ldap_validate_mfa("user", "password")
        else:
            result = await mfa_api.ldap_validate_mfa(
                "user", "password",
            )
            assert result == expected_result
