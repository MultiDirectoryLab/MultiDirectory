"""MFA integration.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import uuid
from dataclasses import dataclass
from enum import StrEnum
from json import JSONDecodeError
from typing import Any, NewType

import httpx
from loguru import logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from models import CatalogueSetting, NetworkPolicy


@dataclass(frozen=True)
class Creds:
    """Creds for mfa."""

    key: str | None
    secret: str | None


MFA_HTTP_Creds = NewType("MFA_HTTP_Creds", Creds)
MFA_LDAP_Creds = NewType("MFA_LDAP_Creds", Creds)


class MFAStatus(StrEnum):
    """MFА status enum."""

    AVAILABLE = "1"
    UNAVAILABLE = "2"
    MISCONFIGURED = "3"
    FAULTED = "4"


MFA_CHECK_INTERVAL_NAME = "MFACheckInterval"
MFA_STATUS_NAME = "MFAStatus"

log_mfa = logger.bind(name="mfa")

log_mfa.add(
    "logs/mfa_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "mfa",
    rotation="500 MB",
    colorize=False,
)


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
    query = select(CatalogueSetting).where(
        CatalogueSetting.name.in_([key_name, secret_name]))

    vals = await session.scalars(query)
    secrets = {s.name: s.value for s in vals.all()}

    key = secrets.get(key_name)
    secret = secrets.get(secret_name)

    if not key or not secret:
        return None

    return Creds(key, secret)


async def update_mfa_status(
    session: AsyncSession,
    status: MFAStatus,
) -> None:
    """Update MFA status.

    :param AsyncSession session: db session
    :param MFAStatus status: status
    """
    await session.execute(
        update(CatalogueSetting)
        .values({"value": status.value})
        .where(CatalogueSetting.name == MFA_STATUS_NAME),
    )


async def get_mfa_status(
    session: AsyncSession,
) -> MFAStatus:
    """Get MFA status or create MFA status.

    :param AsyncSession session: db session
    :return MFAStatus: status
    """
    status = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == MFA_STATUS_NAME),
    )

    if not status:
        session.add(
            CatalogueSetting(
                name=MFA_STATUS_NAME,
                value=MFAStatus.MISCONFIGURED.value,
            ),
        )
        await session.commit()
        return MFAStatus.MISCONFIGURED

    return MFAStatus(status.value)


async def get_mfa_check_interval(
    session: AsyncSession,
) -> int:
    """Get or create MFA check interval."""
    interval = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == MFA_CHECK_INTERVAL_NAME),
    )

    if not interval:
        session.add(
            CatalogueSetting(
                name=MFA_CHECK_INTERVAL_NAME,
                value="50",
            ),
        )
        await session.commit()
        return 50

    return int(interval.value)


async def get_bypass(
    network_policy: NetworkPolicy,
    session: AsyncSession,
) -> tuple[bool, bool]:
    """Get bypass and bypass_block status.

    :param NetworkPolicy network_policy: Network policy settings
    :param AsyncSession session: Database session
    :return bool: True if bypass is allowed, False otherwise
    """
    mfa_state = await get_mfa_status(session)
    bypass = (
        (
            network_policy.bypass_no_connection
            and mfa_state == MFAStatus.UNAVAILABLE
        )
        |
        (mfa_state == MFAStatus.MISCONFIGURED)
        |
        (
            network_policy.bypass_service_failure
            and mfa_state == MFAStatus.FAULTED
        )
    )
    bypass_block = (
        (
            not network_policy.bypass_no_connection
            and mfa_state == MFAStatus.UNAVAILABLE
        )
        |
        (
            not network_policy.bypass_service_failure
            and mfa_state == MFAStatus.FAULTED
        )
    )
    return bypass, bypass_block


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

    AUTH_URL_USERS = "/access/requests/md"
    AUTH_URL_ADMIN = "/access/requests"
    REFRESH_URL = "/token/refresh"
    PING_URL = "/ping"

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

    @staticmethod
    def _generate_trace_id_header() -> dict[str, str]:
        return {"mf-trace-id": f"md:{uuid.uuid4()}"}

    async def _make_mfa_request(
        self,
        session: AsyncSession,
        endpoint: str,
        json: dict[str, Any] | None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Make MFA request and update status.

        :param str endpoint: endpoint
        :param dict[str, Any] | None json: json
        :param float | None timeout: timeout
        :raise MultifactorError: on invalid status
        :raise MultifactorError: on invalid json
        :raise MultifactorError: on timeout
        :raise MultifactorError: on invalid credentials
        :return dict[str, Any]: response data
        """
        try:
            response = await self.client.post(
                self.settings.MFA_API_URI + endpoint,
                auth=self.auth,
                headers=self._generate_trace_id_header(),
                json=json,
                timeout=timeout,
            )

            if response.status_code == 200:
                response_data = response.json()
                if endpoint == self.AUTH_URL_USERS:
                    log_mfa.info(
                        {
                            "response": response_data,
                            "req_content": response.request.content.decode(),
                            "req_headers": response.request.headers,
                        },
                    )
                return response_data

            if response.status_code == 401:
                await update_mfa_status(session, MFAStatus.MISCONFIGURED)
                raise self.MultifactorError("Invalid credentials")

            await update_mfa_status(session, MFAStatus.FAULTED)
            raise self.MultifactorError(
                f"Invalid status: {response.status_code}",
            )
        except self.MultifactorError as err:
            raise err
        except httpx.TimeoutException as err:
            await update_mfa_status(session, MFAStatus.UNAVAILABLE)
            raise self.MultifactorError("API Timeout") from err
        except JSONDecodeError as err:
            await update_mfa_status(session, MFAStatus.FAULTED)
            raise self.MultifactorError("Invalid json") from err

    @log_mfa.catch(reraise=True)
    async def ldap_validate_mfa(
        self,
        username: str,
        password: str | None,
        session: AsyncSession,
    ) -> bool:
        """Validate multifactor.

        If pwd not passed, use "m" for querying push request from mfa,
        it will send push request to user's app and long poll for response,
        timeout is 60 seconds.
        "m" key-character is used to mark push request in multifactor API.

        :param str username: un
        :param str password: pwd
        :raises MultifactorError: connect timeout
        :raises MultifactorError: invalid json
        :raises MultifactorError: Invalid status
        :return bool: status
        """
        passcode = password or "m"
        log_mfa.debug(f"LDAP MFA request: {username}, {password}")

        response_data = await self._make_mfa_request(
            session=session,
            endpoint=self.AUTH_URL_USERS,
            json={
                "Identity": username,
                "passCode": passcode,
                "GroupPolicyPreset": {},
            },
            timeout=self.settings.MFA_TIMEOUT_SECONDS,
        )

        status = response_data.get("model", {}).get("status")
        if status != "Granted":
            return False
        return True

    @log_mfa.catch(reraise=True)
    async def get_create_mfa(
        self,
        username: str,
        callback_url: str,
        uid: int,
        session: AsyncSession,
    ) -> str:
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

        response_data = await self._make_mfa_request(
            session=session,
            endpoint=self.AUTH_URL_ADMIN,
            json=data,
            timeout=self.settings.MFA_TIMEOUT_SECONDS,
        )

        log_mfa.debug(response_data)
        try:
            return response_data["model"]["url"]
        except KeyError as err:
            raise self.MultifactorError(f"Invalid response: {err}") from err

    async def refresh_token(self, token: str, session: AsyncSession) -> str:
        """Refresh mfa token.

        :param str token: str jwt token
        :raises self.MultifactorError: on api err
        :return str: new token
        """
        response_data = await self._make_mfa_request(
            session=session,
            endpoint=self.REFRESH_URL,
            json={"AccessToken": token},
            timeout=self.settings.MFA_TIMEOUT_SECONDS,
        )

        try:
            return response_data["model"]
        except KeyError as err:
            raise self.MultifactorError(f"Invalid response: {err}") from err

    async def ping(self) -> bool:
        """Ping Multifactor.

        :return bool: status
        """
        try:
            response = await self.client.get(
                self.settings.MFA_API_URI + self.PING_URL,
                headers=self._generate_trace_id_header(),
            )
            response_data = response.json()
            return response_data["success"]
        except (httpx.TimeoutException, JSONDecodeError, KeyError):
            return False


LDAPMultiFactorAPI = NewType("LDAPMultiFactorAPI", MultifactorAPI)
