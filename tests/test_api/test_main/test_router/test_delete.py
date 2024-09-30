"""Test API Delete.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import pytest
from httpx import AsyncClient

from app.ldap_protocol.dialogue import LDAPCodes


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_delete(http_client: AsyncClient) -> None:
    """Test API for delete object."""
    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={
            "entry": "cn=test,dc=md,dc=test",
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.SUCCESS


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_delete_with_incorrect_dn(http_client: AsyncClient) -> None:
    """Test API for delete object with incorrect DN."""
    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={
            "entry": "cn!=test,dc=md,dc=test",
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_delete_non_exist_object(
        http_client: AsyncClient, ) -> None:
    """Test API for delete non-existen object."""
    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={
            "entry": "cn=non-exist-object,dc=md,dc=test",
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.NO_SUCH_OBJECT
