import pytest_asyncio


@pytest_asyncio.fixture(scope='function')
async def adding_test_user(http_client, login_headers):
    """Test api first setup."""
    await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [
                {
                    "type": "name",
                    "vals": ["test"],
                },
                {
                    "type": "cn",
                    "vals": ["test"],
                },
                {
                    "type": "testing_attr",
                    "vals": ['test'],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
            ],
        },
        headers=login_headers,
    )
