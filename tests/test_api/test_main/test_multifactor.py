"""Test MultifactorAPI."""

from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from config import Settings
from ldap_protocol.multifactor import MultifactorAPI


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize(
    (
        "mock_post_side_effect",
        "expected_result",
        "expected_exception",
    ),
    [
        # 1. httpx.ConnectTimeout => raise MFAConnectError
        (
            httpx.ConnectTimeout("Connection timed out"),
            True,
            MultifactorAPI.MFAConnectError,
        ),
        # 2. httpx.ReadTimeout => False
        (
            httpx.ReadTimeout("Read timed out"),
            False,
            None,
        ),
        # 3. status_code=401 => raise MFAMissconfiguredError
        (
            httpx.Response(status_code=401),
            True,
            MultifactorAPI.MFAMissconfiguredError,
        ),
        # 4. status_code=500 => raise MultifactorError
        (
            httpx.Response(status_code=500),
            True,
            MultifactorAPI.MultifactorError,
        ),
        # 5. status_code=200, 'model.status' != "Granted" => False
        (
            httpx.Response(
                status_code=200,
                json={"model": {"status": "Denied"}},
                request=httpx.Request("POST", ""),
            ),
            False,
            None,
        ),
        # 6. status_code=200, 'model.status' == "Granted" => True
        (
            httpx.Response(
                status_code=200,
                json={"model": {"status": "Granted"}},
                request=httpx.Request("POST", ""),
            ),
            True,
            None,
        ),
    ],
)
async def test_ldap_validate_mfa(
    mock_post_side_effect: httpx.Response,
    expected_result: bool,
    expected_exception: Exception | None,
    settings: Settings,
) -> None:
    """Test the LDAP validate MFA function with various scenarios."""
    async_client = Mock()
    if isinstance(mock_post_side_effect, Exception):
        async_client.post = AsyncMock(side_effect=mock_post_side_effect)
    else:
        async_client.post = AsyncMock(return_value=mock_post_side_effect)

    mfa_api = MultifactorAPI("test", "test", async_client, settings)

    if expected_exception:
        with pytest.raises(expected_exception):  # type: ignore
            await mfa_api.ldap_validate_mfa("user", "password")
    else:
        result = await mfa_api.ldap_validate_mfa(
            "user",
            "_P@55w0rD!",
        )
        assert result == expected_result
