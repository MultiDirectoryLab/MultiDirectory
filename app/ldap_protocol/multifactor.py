"""MFA integration."""
import asyncio
from json import JSONDecodeError

import httpx
from fastapi import Depends
from sqlalchemy import select

from config import Settings, get_settings
from models.database import AsyncSession, get_session
from models.ldap3 import CatalogueSetting


class _MultifactorError(Exception):
    """MFA exc."""


async def get_auth(
        session: AsyncSession = Depends(get_session)) -> tuple[str, str]:
    """Get API creds.

    :return tuple[str, str]: api key and secret
    """
    q1 = select(CatalogueSetting).filter_by(name='mfa_key')
    q2 = select(CatalogueSetting).filter_by(name='mfa_secret')

    key, secret = await asyncio.gather(session.scalar(q1), session.scalar(q2))

    if not key or not secret:
        return None, None

    return key.value, secret.value


async def get_client():
    """Get async client for DI."""
    async with httpx.AsyncClient() as client:
        yield client


class MultifactorAPI:
    """Multifactor integration."""

    MultifactorError = _MultifactorError

    CHECK_URL = "/requests/ra"
    CREATE_URL = "/requests"

    client: httpx.AsyncClient
    settings: Settings

    def __init__(
            self, key: str, secret: str,
            client: httpx.AsyncClient, settings: Settings):
        """Set creds and web client.

        :param str key: _description_
        :param str secret: _description_
        :param httpx.AsyncClient client: _description_
        :param Settings settings: _description_
        """
        self.client = client
        self.settings = settings
        self.auth: tuple[str] = (key, secret)

    async def ldap_validate_mfa(self, username: str, password: str) -> bool:
        """Validate multifactor.

        :param str username: un
        :param str password: pwd
        :raises MultifactorError: connect timeout
        :raises MultifactorError: invalid json
        :raises MultifactorError: Invalid status
        :return bool: status
        """
        try:
            response = await self.client.post(
                self.settings.MFA_API_URI + self.CHECK_URL,
                auth=self.auth,
                json={"Identity": username, "passCode": password}, timeout=42)

            data = response.json()
        except httpx.ConnectTimeout as err:
            raise self.MultifactorError('API Timeout') from err
        except JSONDecodeError as err:
            raise self.MultifactorError('Invalid json') from err

        if response.status_code != 200:
            raise self.MultifactorError('Status error')

        if data['success'] is not True:
            return False
        return True

    async def get_create_mfa(self, username: str, callback_url: str, sub: str):
        data = {
            "identity": username,
            "claims": {
                "sub": sub,
            },
            "callback": {
                "action": callback_url,
                "target": "_self",
            },
        }
        try:
            response = await self.client.post(
                self.settings.MFA_API_URI + self.CREATE_URL,
                auth=self.auth,
                json=data)
        except httpx.TimeoutException:
            raise self.MultifactorError('API timeout')

        return response['model']['url']

    @classmethod
    async def from_di(
        cls,
        credentials: tuple[str, str] = Depends(get_auth),
        client: httpx.AsyncClient = Depends(get_client),
        settings: Settings = Depends(get_settings),
    ) -> 'MultifactorAPI':
        """Get api from DI.

        :param httpx.AsyncClient client: httpx client
        :param tuple[str, str] credentials: creds
        :return MultifactorAPI: _description_
        """
        return cls(credentials[0], credentials[1], client, settings)
