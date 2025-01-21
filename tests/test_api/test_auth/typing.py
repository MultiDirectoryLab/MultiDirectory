from typing import TypedDict


class AuthSetupRequestDataType(TypedDict):
    domain: str
    username: str
    user_principal_name: str
    display_name: str
    mail: str
    password: str
