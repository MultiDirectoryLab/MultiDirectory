"""MFA integration.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import uuid
from dataclasses import dataclass
from json import JSONDecodeError
from typing import NewType

import httpx
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from models import CatalogueSetting


@dataclass(frozen=True)
class Creds:
    """Creds for mfa."""

    key: str | None
    secret: str | None


MFA_HTTP_Creds = NewType("MFA_HTTP_Creds", Creds)
MFA_LDAP_Creds = NewType("MFA_LDAP_Creds", Creds)

log_mfa = logger.bind(name="mfa")

log_mfa.add(
    "logs/mfa_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "mfa",
    rotation="500 MB",
    colorize=False,
)


class _MultifactorError(Exception):
    """MFA exc."""


class _MFAConnectError(Exception):
    """MFA connect error."""


class _MFAMissconfiguredError(Exception):
    """MFA missconfigured error."""


async def get_creds(
    session: AsyncSession,
    key_name: str,
    secret_name: str,
) -> Creds | None:
    """Get API creds.

    :return tuple[str, str]: api key and secret
    """
    query = (
        select(CatalogueSetting)
        .where(CatalogueSetting.name.in_([key_name, secret_name]))
    )  # fmt: skip

    vals = await session.scalars(query)
    secrets = {s.name: s.value for s in vals.all()}

    key = secrets.get(key_name)
    secret = secrets.get(secret_name)

    if not key or not secret:
        return None

    return Creds(key, secret)


class MultifactorAPI:
    """Multifactor authentication integration.

    LDAP and HTTP manager for multifactor authentication.

    Methods:
    - `__init__(key, secret, client, settings)`: Initializes the object with
      the required credentials and bound HTTP client from di.
    - `ldap_validate_mfa(username, password)`: Validates MFA for a user. If the
      password is not provided, sends a push notification and waits for user
      approval with a timeout of 60 seconds.
    - `get_create_mfa(username)`: Retrieves or creates an MFA token for the
      specified user.
    - `refresh_token()`: Refreshes the authentication token using the refresh
      endpoint.

    Attributes:
    - `MultifactorError`: Exception class for MFA-related errors.
    - `AUTH_URL_USERS`: Endpoint URL for user authentication requests.
    - `AUTH_URL_ADMIN`: Endpoint URL for admin authentication requests.
    - `REFRESH_URL`: Endpoint URL for token refresh.
    - `client`: Asynchronous HTTP client for making requests.
    - `settings`: Configuration settings for the MFA service.

    """

    MultifactorError = _MultifactorError
    MFAConnectError = _MFAConnectError
    MFAMissconfiguredError = _MFAMissconfiguredError

    AUTH_URL_USERS = "/access/requests/md"
    AUTH_URL_ADMIN = "/access/requests"
    REFRESH_URL = "/token/refresh"

    is_initialized = False

    client: httpx.AsyncClient
    settings: Settings

    def __init__(
        self,
        key: str,
        secret: str,
        client: httpx.AsyncClient,
        settings: Settings,
    ):
        """Set creds and web client.

        :param str key: mfa key
        :param str secret: mfa secret
        :param httpx.AsyncClient client: client for making queries (activated)
        :param Settings settings: app settings
        """
        self.client = client
        self.settings = settings
        self.auth: tuple[str, str] = (key, secret)
        self.is_initialized = bool(key and secret)

    @staticmethod
    def _generate_trace_id_header() -> dict[str, str]:
        return {"mf-trace-id": f"md:{uuid.uuid4()}"}

    @log_mfa.catch(reraise=True)
    async def ldap_validate_mfa(
        self,
        username: str,
        password: str | None,
    ) -> bool:
        """Validate multifactor.

        If pwd not passed, use "m" for querying push request from mfa,
        it will send push request to user's app and long poll for response,
        timeout is 60 seconds.
        "m" key-character is used to mark push request in multifactor API.

        :param str username: un
        :param str password: pwd
        :param NetworkPolicy policy: policy
        :raises MultifactorError: connect timeout
        :raises MultifactorError: invalid json
        :raises MultifactorError: Invalid status
        :return bool: status
        """
        passcode = password or "m"
        log_mfa.debug(f"LDAP MFA request: {username}, {password}")
        try:
            response = await self.client.post(
                self.settings.MFA_API_URI + self.AUTH_URL_USERS,
                auth=self.auth,
                headers=self._generate_trace_id_header(),
                json={
                    "Identity": username,
                    "passCode": passcode,
                    "GroupPolicyPreset": {},
                },
                timeout=httpx.Timeout(
                    self.settings.MFA_LDAP_READ_TIMEOUT_SECONDS,
                    connect=self.settings.MFA_CONNECT_TIMEOUT_SECONDS,
                ),
            )
        except httpx.ConnectTimeout as err:
            raise self.MFAConnectError("API Timeout") from err
        except httpx.ReadTimeout:
            # Push was not approved
            log_mfa.debug("MFA ReadTimeout")
            return False

        if response.status_code == 401:
            raise self.MFAMissconfiguredError("API Key or Secret is invalid")

        if response.status_code != 200:
            raise self.MultifactorError("Status error")

        try:
            data = response.json()
        except JSONDecodeError as err:
            raise self.MultifactorError("Invalid json") from err

        log_mfa.info(
            {
                "response": data,
                "req_content": response.request.content.decode(),
                "req_headers": response.request.headers,
            },
        )

        return data.get("model", {}).get("status") == "Granted"

    @log_mfa.catch(reraise=True)
    async def get_create_mfa(
        self,
        username: str,
        callback_url: str,
        uid: int,
    ) -> str:
        """Create mfa link.

        :param str username: un
        :param str callback_url: callback uri to send token
        :param int uid: user id
        :raises httpx.TimeoutException: on timeout
        :raises self.MultifactorError: on invalid json, Key or error status
            code
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
        log_mfa.debug(data)
        try:
            response = await self.client.post(
                self.settings.MFA_API_URI + self.AUTH_URL_ADMIN,
                auth=self.auth,
                headers=self._generate_trace_id_header(),
                json=data,
            )
        except httpx.TimeoutException as err:
            raise self.MFAConnectError("API Timeout") from err

        if response.status_code == 401:
            raise self.MFAMissconfiguredError("API Key or Secret is invalid")

        if response.status_code == 403:
            raise self.MultifactorError("Incorrect resource")

        if response.status_code == 429:
            raise self.MultifactorError("API calls quota exceeded")

        try:
            response_data = response.json()
            log_mfa.info(response_data)

            if response_data.get("success") is False:
                raise self.MultifactorError(response_data.get("message"))

            return response_data["model"]["url"]
        except (JSONDecodeError, KeyError) as err:
            raise self.MultifactorError(f"MFA API error: {err}") from err

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
                json={"AccessToken": token},
            )

            response_data = response.json()
            log_mfa.info(response_data)
            return response_data["model"]

        except (httpx.TimeoutException, JSONDecodeError, KeyError) as err:
            raise self.MultifactorError(f"MFA API error: {err}") from err


LDAPMultiFactorAPI = NewType("LDAPMultiFactorAPI", MultifactorAPI)
