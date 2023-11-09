"""MFA integration."""
import asyncio
from collections import namedtuple
from json import JSONDecodeError
from typing import Annotated

import httpx
from fastapi import Depends
from loguru import logger
from sqlalchemy import select

from config import Settings, get_settings
from models.database import AsyncSession, get_session
from models.ldap3 import CatalogueSetting

Creds = namedtuple('Creds', ['key', 'secret'])


class _MultifactorError(Exception):
    """MFA exc."""


async def _get_creds(
    session: AsyncSession,
    key_name: str,
    secret_name: str,
) -> Creds | None:
    """Get API creds.

    :return tuple[str, str]: api key and secret
    """
    q1 = select(CatalogueSetting).filter_by(name=key_name)
    q2 = select(CatalogueSetting).filter_by(name=secret_name)

    key, secret = await asyncio.gather(session.scalar(q1), session.scalar(q2))

    if not key or not secret:
        return None

    return Creds(key.value, secret.value)


async def get_auth(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Creds | None:
    """Admin creds get.

    :param Annotated[AsyncSession, Depends session: session
    :return Creds | None: optional creds
    """
    return await _get_creds(session, 'mfa_key', 'mfa_secret')


async def get_auth_ldap(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Creds | None:
    """Admin creds get.

    :param Annotated[AsyncSession, Depends session: session
    :return Creds | None: optional creds
    """
    return await _get_creds(session, 'mfa_key_ldap', 'mfa_secret_ldap')


async def get_client():
    """Get async client for DI."""
    async with httpx.AsyncClient(timeout=4) as client:
        yield client


class MultifactorAPI:
    """Multifactor integration."""

    MultifactorError = _MultifactorError

    CHECK_URL = "/access/requests/ra"
    CREATE_URL = "/access/requests"
    REFRESH_URL = "/token/refresh"

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

    @logger.catch(reraise=True)
    async def ldap_validate_mfa(self, username: str, password: str) -> bool:
        """Validate multifactor.

        :param str username: un
        :param str password: pwd
        :raises MultifactorError: connect timeout
        :raises MultifactorError: invalid json
        :raises MultifactorError: Invalid status
        :return bool: status
        """
        logger.debug(f'LDAP MFA request: {username}, {password}')
        try:
            response = await self.client.post(
                self.settings.MFA_API_URI + self.CHECK_URL,
                auth=self.auth,
                json={"Identity": username, "passCode": password}, timeout=42)
            data = response.json()
            logger.info(data)
        except httpx.ConnectTimeout as err:
            raise self.MultifactorError('API Timeout') from err
        except JSONDecodeError as err:
            raise self.MultifactorError('Invalid json') from err

        if response.status_code != 200:
            raise self.MultifactorError('Status error')

        if data['success'] is not True:
            return False
        return True

    @logger.catch(reraise=True)
    async def get_create_mfa(
            self, username: str, callback_url: str, uid: int) -> str:
        """Create mfa link.

        :param str username: un
        :param str callback_url: callback uri to send token
        :param int uid: user id
        :raises self.MultifactorError: on invalid json, Key or timeout
        :return str: url to open in new page
        """
        data = {
            "identity": username,
            "claims": {
                "uid": uid,
                "grant_type": "multifactor",
            },
            "callback": {
                "action": callback_url,
                "target": "_self",
            },
        }
        try:
            logger.debug(data)

            response = await self.client.post(
                self.settings.MFA_API_URI + self.CREATE_URL,
                auth=self.auth,
                json=data)

            response_data = response.json()
            logger.info(response_data)
            return response_data['model']['url']

        except (httpx.TimeoutException, JSONDecodeError, KeyError) as err:
            raise self.MultifactorError(f'MFA API error: {err}') from err

    async def refresh_token(self, token: str) -> str:
        """Refresh mfa token.

        :param str token: str jwt token
        :raises self.MultifactorError: on api err
        :return str: new token
        """
        try:
            response = await self.client.post(
                self.settings.MFA_API_URI + self.REFRESH_URL,
                auth=self.auth,
                json={"AccessToken": token})

            response_data = response.json()
            logger.info(response_data)
            return response_data['model']

        except (httpx.TimeoutException, JSONDecodeError, KeyError) as err:
            raise self.MultifactorError(f'MFA API error: {err}') from err

    @classmethod
    async def from_di(
        cls,
        credentials: Annotated[Creds | None, Depends(get_auth)],
        client: Annotated[httpx.AsyncClient, Depends(get_client)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> 'MultifactorAPI':
        """Get api from DI.

        :param httpx.AsyncClient client: httpx client
        :param Creds credentials: creds
        :return MultifactorAPI: mfa integration
        """
        if credentials is None:
            return None
        return cls(credentials.key, credentials.secret, client, settings)
