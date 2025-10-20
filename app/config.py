"""Module with settings.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import os
import socket
import tomllib
from functools import cached_property
from typing import ClassVar, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import jinja2
from pydantic import (
    BaseModel,
    Field,
    HttpUrl,
    IPvAnyAddress,
    PostgresDsn,
    RedisDsn,
    computed_field,
    field_validator,
)
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool


def _get_vendor_version() -> str:
    with open("/pyproject.toml", "rb") as f:
        return tomllib.load(f)["project"]["version"]


class Settings(BaseModel):
    """Settigns with database dsn."""

    DOMAIN: str

    DEBUG: bool = False
    AUTO_RELOAD: bool = False
    HOST: IPvAnyAddress = "0.0.0.0"  # type: ignore  # noqa
    PORT: int = 389
    TLS_PORT: int = 636
    HTTP_PORT: int = 8000
    USE_CORE_TLS: bool = False
    LDAP_LOAD_SSL_CERT: bool = False

    TCP_PACKET_SIZE: int = 1024
    COROUTINES_NUM_PER_CLIENT: int = 3

    POSTGRES_SCHEMA: ClassVar[str] = "postgresql+psycopg"
    POSTGRES_DB: str = "postgres"

    POSTGRES_HOST: str = "pgpool"
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str

    SESSION_STORAGE_URL: RedisDsn = RedisDsn("redis://dragonfly:6379/1")
    SESSION_KEY_LENGTH: int = 16
    SESSION_REKEY_INTERVAL: int = 30 * 60

    LDAP_SESSION_CHECK_INTERVAL: int = 15  # seconds

    SERVICE_NAME: str | None = None

    EVENT_HANDLER_URL: RedisDsn = RedisDsn("redis://dragonfly:6379/2")

    EVENT_CONSUMER_NAME: str = Field(default_factory=socket.gethostname)
    EVENT_HANDLER_GROUP: str = "event_handlers"
    EVENT_SENDER_GROUP: str = "event_senders"
    RAW_EVENT_STREAM_NAME: str = "RAW_EVENT_LOG"
    NORMALIZED_EVENT_STREAM_NAME: str = "NORMALIZED_EVENT_LOG"
    IS_PROC_EVENT_KEY: str = "IS_PROC_EVENT"

    SSL_CERT: str = "/certs/cert.pem"
    SSL_KEY: str = "/certs/privkey.pem"

    AUDIT_LOG_FILE: str = "/audit/audit.log"

    AUDIT_FIRST_RETRY_TIME: int = 5
    AUDIT_SECOND_RETRY_TIME: int = 60
    AUDIT_THIRD_RETRY_TIME: int = 1440

    @computed_field  # type: ignore
    @cached_property
    def POSTGRES_URI(self) -> PostgresDsn:  # noqa
        """Build postgres DSN."""
        return PostgresDsn(
            f"{self.POSTGRES_SCHEMA}://"
            f"{self.POSTGRES_USER}:"
            f"{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_HOST}/"
            f"{self.POSTGRES_DB}",
        )

    VENDOR_NAME: ClassVar[str] = "MultiFactor"
    VENDOR_VERSION: str = Field(
        default_factory=_get_vendor_version,
        alias="VERSION",
    )
    # to get a string run: `openssl rand -hex 32`
    SECRET_KEY: str
    SESSION_KEY_EXPIRE_SECONDS: int = 60 * 60 * 8

    MFA_LDAP_READ_TIMEOUT_SECONDS: int = 60
    MFA_CONNECT_TIMEOUT_SECONDS: int = 4
    MFA_MAX_CONN: int = 50
    MFA_MAX_KEEPALIVE: int = 15
    MFA_API_SOURCE: Literal["dev", "ru"] = "ru"

    TIMEZONE: ZoneInfo = Field(ZoneInfo("UTC"), alias="TZ")

    KRB5_LDAP_URI: str = "ldap://ldap_server"
    KADMIN_API_SERVER: str = "kadmin_api"
    KRB5_SERVER_MAX_CONN: int = 500
    KRB5_SERVER_MAX_KEEPALIVE: int = 100
    KRB5_LDAP_KEYTAB: str = "/LDAP_keytab/ldap.keytab"
    KRB5_MFA_PUSH_URL: str = "http://shadow_api:8000/mfa/push"
    KRB5_SYNC_PASSWORD_URL: str = "http://shadow_api:8000/sync/password"  # noqa: S105

    TEMPLATES: ClassVar[jinja2.Environment] = jinja2.Environment(
        loader=jinja2.FileSystemLoader("extra/templates"),
        enable_async=True,
        autoescape=True,
    )

    DNS_BIND_HOST: str = "bind_dns"

    ENABLE_SQLALCHEMY_LOGGING: bool = False

    GSSAPI_MAX_OUTPUT_TOKEN_SIZE: int = 1024

    OTP_TAIL_SIZE: Literal[6] = 6

    @field_validator("TIMEZONE", mode="before")
    def create_tz(cls, tz: str) -> ZoneInfo:  # noqa: N805
        """Get timezone from a string."""
        try:
            value = ZoneInfo(tz)
        except ZoneInfoNotFoundError as err:
            raise ValueError(str(err)) from err
        except TypeError:
            return tz  # type: ignore
        else:
            return value

    @computed_field  # type: ignore
    @cached_property
    def MFA_API_URI(self) -> str:  # noqa: N802
        """Multifactor API url.

        :return str: url
        """
        if self.MFA_API_SOURCE == "dev":
            return "https://api.multifactor.dev"
        return "https://api.multifactor.ru"

    @computed_field  # type: ignore
    @cached_property
    def KRB5_CONFIG_SERVER(self) -> HttpUrl:  # noqa: N802
        return f"https://{self.KADMIN_API_SERVER}:8000"  # type: ignore

    def get_copy_4_tls(self) -> "Settings":
        """Create a copy for TLS bind."""
        from copy import copy

        tls_settings = copy(self)
        tls_settings.USE_CORE_TLS = True
        tls_settings.PORT = tls_settings.TLS_PORT
        return tls_settings

    def check_certs_exist(self) -> bool:
        """Check if certs exist."""
        return os.path.exists(self.SSL_CERT) and os.path.exists(self.SSL_KEY)

    @cached_property
    def engine(self) -> AsyncEngine:
        """Get engine."""
        return create_async_engine(
            str(self.POSTGRES_URI),
            poolclass=NullPool,
            future=True,
        )

    @classmethod
    def from_os(cls) -> "Settings":
        """Get cls from environ."""
        return Settings(**os.environ)

    @cached_property
    def HOST_DNS_SERVERS(self) -> list[str]:  # noqa: N802
        """Get resolv.conf path."""
        host_dns_servers: list[str] = []
        if os.path.exists("/resolv.conf"):
            with open("/resolv.conf") as resolv_file:
                lines = resolv_file.readlines()

                for line in lines:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) == 2:
                            host_dns_servers.append(parts[1].strip())

            return host_dns_servers

        return ["1.1.1.1"]
