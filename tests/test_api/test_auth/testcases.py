from typing import List
from tests.test_api.test_auth.typing import AuthSetupRequestDataType


invalid_domain_test_cases: List[AuthSetupRequestDataType] = [
    {
        "domain": "https://md.test-localhost",
        "username": "test",
        "user_principal_name": "test",
        "display_name": "test",
        "mail": "test@example.com-test",
        "password": "Password123",
    },
    {
        "domain": "http://md.test-localhost",
        "username": "test",
        "user_principal_name": "test",
        "display_name": "test",
        "mail": "test@example.com-test",
        "password": "Password123",
    },
    {
        "domain": "test-localhost",
        "username": "test",
        "user_principal_name": "test",
        "display_name": "test",
        "mail": "test@example.com-test",
        "password": "Password123",
    },
    {
        "domain": "md.test-localhost!",
        "username": "test",
        "user_principal_name": "test",
        "display_name": "test",
        "mail": "test@example.com-test",
        "password": "Password123",
    },
]
