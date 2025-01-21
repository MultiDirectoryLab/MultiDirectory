from pydantic import BaseModel


class AuthSetupRequestDataType(BaseModel):
    domain: str
    username: str
    user_principal_name: str
    display_name: str
    mail: str
    password: str
