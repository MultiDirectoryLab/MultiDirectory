"""MFA integration.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import uuid
from dataclasses import dataclass
from json import JSONDecodeError
from typing import NewType

import httpx
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from models.ldap3 import CatalogueSetting


@dataclass(frozen=True)
class Creds:
    """Creds for mfa."""

    key: str
    secret: str


MFA_HTTP_Creds = NewType('MFA_HTTP_Creds', Creds)
MFA_LDAP_Creds = NewType('MFA_LDAP_Creds', Creds)

log_mfa = logger.bind(name='mfa')

log_mfa.add(
    "logs/mfa_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == 'mfa',
    rotation="500 MB",
    colorize=False)


class _MultifactorError(Exception):
    """MFA exc."""


async def get_creds(
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

    return Creds(key.value, secret.value)  # type: ignore


class MultifactorAPI:
    """Multifactor integration."""

    MultifactorError = _MultifactorError

    AUTH_URL_USERS = "/access/requests/md"
    AUTH_URL_ADMIN = "/access/requests"
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
        self.auth: tuple[str, str] = (key, secret)

    @staticmethod
    def _generate_trace_id_header() -> dict[str, str]:
        return {"mf-trace-id": f"md:{uuid.uuid4()}"}

    @log_mfa.catch(reraise=True)
    async def ldap_validate_mfa(self, username: str, password: str) -> bool:
        """Validate multifactor.

        :param str username: un
        :param str password: pwd
        :raises MultifactorError: connect timeout
        :raises MultifactorError: invalid json
        :raises MultifactorError: Invalid status
        :return bool: status
        """
        passcode = password or 'm'
        log_mfa.debug(f'LDAP MFA request: {username}, {password}')
        try:
            response = await self.client.post(
                self.settings.MFA_API_URI + self.AUTH_URL_USERS,
                auth=self.auth,
                headers=self._generate_trace_id_header(),
                json={
                    "Identity": username,
                    "passCode": passcode,
                    "GroupPolicyPreset": {},
                }, timeout=60)

            data = response.json()
            log_mfa.info({
                "response": data,
                "req_content": response.request.content.decode(),
                "req_headers": response.request.headers,
            })
        except httpx.ConnectTimeout as err:
            raise self.MultifactorError('API Timeout') from err
        except JSONDecodeError as err:
            raise self.MultifactorError('Invalid json') from err

        if response.status_code != 200:
            raise self.MultifactorError('Status error')

        if data.get('model', {}).get('status') != 'Granted':
            return False
        return True

    @log_mfa.catch(reraise=True)
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
            log_mfa.debug(data)

            response = await self.client.post(
                self.settings.MFA_API_URI + self.AUTH_URL_ADMIN,
                auth=self.auth,
                headers=self._generate_trace_id_header(),
                json=data)

            response_data = response.json()
            log_mfa.info(response_data)
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
                headers=self._generate_trace_id_header(),
                json={"AccessToken": token})

            response_data = response.json()
            log_mfa.info(response_data)
            return response_data['model']

        except (httpx.TimeoutException, JSONDecodeError, KeyError) as err:
            raise self.MultifactorError(f'MFA API error: {err}') from err


LDAPMultiFactorAPI = NewType('LDAPMultiFactorAPI', MultifactorAPI)
