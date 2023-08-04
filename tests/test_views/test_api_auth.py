"""Test api calls."""
import pytest


@pytest.mark.asyncio()
async def test_first_setup_and_oauth(http_client, session):
    """Test api first setup."""
    response = await http_client.get("/auth/setup")
    assert response.status_code == 200
    assert response.json() is False

    response = await http_client.post("/auth/setup", json={
        "domain": "multidirectory.test",
        "username": "test",
        "user_principal_name": "test",
        "display_name": "test",
        "mail": "test@example.com",
        "password": "password",
    })
    assert response.status_code == 200
    assert response.json() == {
        "resultCode": 0,
        "matchedDN": "",
        "errorMessage": "",
    }
    response = await http_client.post("auth/token/get", data={
        "username": "test", "password": "password"})
    assert response.status_code == 200
