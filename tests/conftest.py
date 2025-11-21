"""Test main config.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import uuid
import weakref
from contextlib import suppress
from dataclasses import dataclass
from typing import AsyncGenerator, AsyncIterator, Generator, Iterator
from unittest.mock import AsyncMock, Mock

import aioldap3
import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis
import uvloop
from alembic import command
from alembic.config import Config as AlembicConfig
from authorization_provider_protocol import AuthorizationProviderProtocol
from dishka import (
    AsyncContainer,
    Provider,
    Scope,
    from_context,
    make_async_container,
    provide,
)
from dishka.integrations.fastapi import setup_dishka
from fastapi import FastAPI, Request, Response
from multidirectory import _create_basic_app
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

from api import shadow_router
from api.audit.adapter import AuditPoliciesAdapter
from api.auth.adapters import (
    AuthFastAPIAdapter,
    MFAFastAPIAdapter,
    SessionFastAPIGateway,
)
from api.auth.utils import get_ip_from_request, get_user_agent_from_request
from api.dhcp.adapter import DHCPAdapter
from api.ldap_schema.adapters.attribute_type import AttributeTypeFastAPIAdapter
from api.ldap_schema.adapters.entity_type import LDAPEntityTypeFastAPIAdapter
from api.ldap_schema.adapters.object_class import ObjectClassFastAPIAdapter
from api.main.adapters.dns import DNSFastAPIAdapter
from api.main.adapters.kerberos import KerberosFastAPIAdapter
from api.network.adapters.network import NetworkPolicyFastAPIAdapter
from api.password_policy.adapter import (
    PasswordBanWordsFastAPIAdapter,
    PasswordPolicyFastAPIAdapter,
)
from api.shadow.adapter import ShadowAdapter
from config import Settings
from constants import ENTITY_TYPE_DATAS
from entities import AttributeType
from enums import AuthorizationRules
from ioc import AuditRedisClient, MFACredsProvider, SessionStorageClient
from ldap_protocol.auth import AuthManager, MFAManager
from ldap_protocol.auth.setup_gateway import SetupGateway
from ldap_protocol.auth.use_cases import SetupUseCase
from ldap_protocol.dhcp import AbstractDHCPManager, StubDHCPManager
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSManagerSettings,
    StubDNSManager,
)
from ldap_protocol.dns.dns_gateway import DNSStateGateway
from ldap_protocol.dns.dto import DNSSettingDTO
from ldap_protocol.dns.use_cases import DNSUseCase
from ldap_protocol.identity import IdentityProvider
from ldap_protocol.identity.provider_gateway import IdentityProviderGateway
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.kerberos.ldap_structure import KRBLDAPStructureManager
from ldap_protocol.kerberos.service import KerberosService
from ldap_protocol.kerberos.template_render import KRBTemplateRenderer
from ldap_protocol.ldap_requests.bind import BindRequest
from ldap_protocol.ldap_requests.contexts import (
    LDAPAddRequestContext,
    LDAPBindRequestContext,
    LDAPDeleteRequestContext,
    LDAPExtendedRequestContext,
    LDAPModifyDNRequestContext,
    LDAPModifyRequestContext,
    LDAPSearchRequestContext,
    LDAPUnbindRequestContext,
)
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.attribute_type_use_case import (
    AttributeTypeUseCase,
)
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.ldap_schema.object_class_use_case import ObjectClassUseCase
from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.permissions_checker import AuthorizationProvider
from ldap_protocol.policies.audit.audit_use_case import AuditUseCase
from ldap_protocol.policies.audit.destination_dao import AuditDestinationDAO
from ldap_protocol.policies.audit.events.managers import (
    NormalizedAuditManager,
    RawAuditManager,
)
from ldap_protocol.policies.audit.monitor import (
    AuditMonitor,
    AuditMonitorUseCase,
)
from ldap_protocol.policies.audit.policies_dao import AuditPoliciesDAO
from ldap_protocol.policies.audit.service import AuditService
from ldap_protocol.policies.network.gateway import NetworkPolicyGateway
from ldap_protocol.policies.network.use_cases import NetworkPolicyUseCase
from ldap_protocol.policies.password import (
    PasswordPolicyDAO,
    PasswordPolicyUseCases,
    PasswordPolicyValidator,
)
from ldap_protocol.policies.password.ban_word_repository import (
    PasswordBanWordRepository,
)
from ldap_protocol.policies.password.settings import PasswordValidatorSettings
from ldap_protocol.policies.password.use_cases import PasswordBanWordUseCases
from ldap_protocol.roles.access_manager import AccessManager
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.dataclasses import RoleDTO
from ldap_protocol.roles.role_dao import RoleDAO
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.server import PoolClientHandler
from ldap_protocol.session_storage import RedisSessionStorage, SessionStorage
from ldap_protocol.session_storage.repository import SessionRepository
from ldap_protocol.utils.queries import get_user
from password_manager.password_validator import PasswordValidator
from tests.constants import TEST_DATA


class TestProvider(Provider):
    """Test provider."""

    __test__ = False

    scope = Scope.RUNTIME
    settings = from_context(provides=Settings, scope=Scope.RUNTIME)
    _cached_session: AsyncSession | None = None
    _cached_kadmin: Mock | None = None
    _cached_audit_service: Mock | None = None
    _cached_dns_manager: Mock | None = None
    _cached_dhcp_manager: Mock | None = None
    _session_id: uuid.UUID | None = None

    @provide(scope=Scope.APP, provides=AbstractKadmin)
    async def get_kadmin(self) -> AsyncIterator[AsyncMock]:
        """Get mock kadmin."""
        kadmin = Mock()

        ok_response = Mock()
        ok_response.status_code = 200
        ok_response.aiter_bytes.return_value = map(bytes, zip(b"test_string"))

        kadmin.setup = AsyncMock()
        kadmin.ktadd = AsyncMock(return_value=ok_response)
        kadmin.get_status = AsyncMock(return_value=False)
        kadmin.add_principal = AsyncMock()
        kadmin.del_principal = AsyncMock()
        kadmin.rename_princ = AsyncMock()
        kadmin.create_or_update_principal_pw = AsyncMock()
        kadmin.change_principal_password = AsyncMock()
        kadmin.lock_principal = AsyncMock()
        kadmin.reset_setup = AsyncMock()

        if not self._cached_kadmin:
            self._cached_kadmin = kadmin

        yield self._cached_kadmin

        self._cached_kadmin = None

    @provide(scope=Scope.REQUEST, provides=AbstractDHCPManager)
    async def get_dhcp_mngr(self) -> AsyncIterator[AsyncMock]:
        """Get mock DHCP manager."""
        dhcp_manager = AsyncMock(spec=StubDHCPManager)

        if not self._cached_dhcp_manager:
            self._cached_dhcp_manager = dhcp_manager

        yield self._cached_dhcp_manager

        self._cached_dhcp_manager = None

    @provide(scope=Scope.REQUEST, provides=AbstractDNSManager)
    async def get_dns_mngr(self) -> AsyncIterator[AsyncMock]:
        """Get mock DNS manager."""
        dns_manager = AsyncMock(spec=StubDNSManager)

        dns_manager.setup.return_value = DNSSettingDTO(
            zone_name="example.com",
            dns_server_ip="127.0.0.1",
            tsig_key=None,
        )
        dns_manager.get_all_records.return_value = [
            {
                "type": "A",
                "records": [
                    {
                        "name": "example.com",
                        "value": "127.0.0.1",
                        "ttl": 3600,
                    },
                ],
            },
        ]
        dns_manager.get_server_options.return_value = [
            {
                "name": "dnssec-validation",
                "value": "no",
            },
        ]
        dns_manager.get_forward_zones.return_value = [
            {
                "name": "test.local",
                "type": "forward",
                "forwarders": [
                    "127.0.0.1",
                    "127.0.0.2",
                ],
            },
        ]
        dns_manager.get_all_zones_records.return_value = [
            {
                "name": "test.local",
                "type": "master",
                "records": [
                    {
                        "type": "A",
                        "records": [
                            {
                                "name": "example.com",
                                "value": "127.0.0.1",
                                "ttl": 3600,
                            },
                        ],
                    },
                ],
            },
        ]

        if not self._cached_dns_manager:
            self._cached_dns_manager = dns_manager

        yield self._cached_dns_manager

        self._cached_dns_manager = None

    @provide(scope=Scope.REQUEST, provides=DNSManagerSettings, cache=False)
    async def get_dns_mngr_settings(
        self,
        dns_state_gateway: DNSStateGateway,
    ) -> AsyncIterator["DNSManagerSettings"]:
        """Get DNS manager's settings."""

        async def resolve() -> str:
            return "127.0.0.1"

        resolver = resolve()
        yield await dns_state_gateway.get_dns_manager_settings(resolver)
        weakref.finalize(resolver, resolver.close)

    @provide(scope=Scope.REQUEST, provides=AttributeTypeDAO, cache=False)
    def get_attribute_type_dao(
        self,
        session: AsyncSession,
    ) -> AttributeTypeDAO:
        """Get Attribute Type DAO."""
        return AttributeTypeDAO(session)

    @provide(scope=Scope.REQUEST, provides=ObjectClassDAO, cache=False)
    def get_object_class_dao(self, session: AsyncSession) -> ObjectClassDAO:
        """Get Object Class DAO."""
        return ObjectClassDAO(session=session)

    get_entity_type_dao = provide(
        EntityTypeDAO,
        scope=Scope.REQUEST,
        cache=False,
    )
    attribute_type_use_case = provide(
        AttributeTypeUseCase,
        scope=Scope.REQUEST,
    )
    object_class_use_case = provide(ObjectClassUseCase, scope=Scope.REQUEST)

    password_ban_word_repository = provide(
        PasswordBanWordRepository,
        scope=Scope.REQUEST,
    )
    password_policy_dao = provide(PasswordPolicyDAO, scope=Scope.REQUEST)
    password_use_cases = provide(PasswordPolicyUseCases, scope=Scope.REQUEST)
    password_policy_validator = provide(
        PasswordPolicyValidator,
        scope=Scope.REQUEST,
    )
    password_validator_settings = provide(
        PasswordValidatorSettings,
        scope=Scope.REQUEST,
    )
    password_policies_adapter = provide(
        PasswordPolicyFastAPIAdapter,
        scope=Scope.REQUEST,
    )
    password_ban_words_use_cases = provide(
        PasswordBanWordUseCases,
        scope=Scope.REQUEST,
    )
    password_ban_words_adapter = provide(
        PasswordBanWordsFastAPIAdapter,
        scope=Scope.REQUEST,
    )
    password_validator = provide(PasswordValidator, scope=Scope.RUNTIME)

    dns_fastapi_adapter = provide(DNSFastAPIAdapter, scope=Scope.REQUEST)
    dns_use_case = provide(DNSUseCase, scope=Scope.REQUEST)
    dns_state_gateway = provide(DNSStateGateway, scope=Scope.REQUEST)

    @provide(scope=Scope.RUNTIME, provides=AsyncEngine)
    def get_engine(self, settings: Settings) -> AsyncEngine:
        """Get async engine."""
        return settings.engine

    @provide(scope=Scope.APP, provides=async_sessionmaker[AsyncSession])
    def get_session_factory(
        self,
        engine: AsyncEngine,
    ) -> async_sessionmaker[AsyncSession]:
        """Create session factory."""
        return async_sessionmaker(
            engine,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )

    @provide(scope=Scope.APP, cache=False)
    async def get_session(
        self,
        engine: AsyncEngine,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> AsyncIterator[AsyncSession]:
        """Get test session with a savepoint."""
        if self._cached_session:
            yield self._cached_session
            return

        connection = await engine.connect()
        trans = await connection.begin()

        async_session = session_factory(
            bind=connection,
            info={"mode": "test_transaction"},
            join_transaction_mode="create_savepoint",
        )

        self._cached_session = async_session
        self._session_id = uuid.uuid4()

        yield async_session

        self._cached_session = None
        self._session_id = None

        async_session.expire_all()
        await trans.rollback()
        await async_session.close()
        await connection.close()

    @provide(scope=Scope.SESSION)
    async def get_ldap_session(
        self,
        storage: SessionStorage,
    ) -> AsyncIterator[LDAPSession]:
        """Create ldap session."""
        session = LDAPSession(storage=storage)
        await session.start()
        yield session
        await session.disconnect()

    monitor_use_case = provide(AuditMonitorUseCase, scope=Scope.REQUEST)

    @provide(scope=Scope.REQUEST, provides=MultifactorAPI)
    async def get_mfa_api(self) -> Mock:
        """Create mock mfa."""
        mfa = Mock()
        mfa.ldap_validate_mfa = AsyncMock()
        mfa.get_create_mfa = AsyncMock(return_value="example.com")
        return mfa

    @provide(scope=Scope.REQUEST, provides=LDAPMultiFactorAPI)
    async def get_mfa_ldap_api(self) -> Mock:
        """Create mock mfa."""
        mfa = Mock()
        mfa.ldap_validate_mfa = AsyncMock()
        mfa.get_create_mfa = AsyncMock(return_value="example.com")
        return mfa

    @provide(scope=Scope.APP)
    async def get_redis_for_sessions(
        self,
        settings: Settings,
    ) -> AsyncIterator[SessionStorageClient]:
        """Get redis connection."""
        client = redis.Redis.from_url(str(settings.SESSION_STORAGE_URL))

        if not await client.ping():
            raise SystemError("Redis is not available")

        yield SessionStorageClient(client)

        await client.flushdb()
        with suppress(RuntimeError):
            await client.aclose()

    @provide(scope=Scope.APP)
    async def get_session_storage(
        self,
        client: SessionStorageClient,
        settings: Settings,
    ) -> SessionStorage:
        """Get session storage."""
        return RedisSessionStorage(
            client,
            settings.SESSION_KEY_LENGTH,
            settings.SESSION_KEY_EXPIRE_SECONDS,
        )

    role_dao = provide(RoleDAO, scope=Scope.REQUEST, cache=False)
    ace_dao = provide(AccessControlEntryDAO, scope=Scope.REQUEST)
    access_manager = provide(AccessManager, scope=Scope.REQUEST)
    role_use_case = provide(RoleUseCase, scope=Scope.REQUEST)

    identity_fastapi_adapter = provide(
        AuthFastAPIAdapter,
        scope=Scope.REQUEST,
    )

    auth_manager = provide(
        AuthManager,
        scope=Scope.REQUEST,
    )

    @provide(scope=Scope.REQUEST)
    async def get_identity_provider(
        self,
        request: Request,
        session_storage: SessionStorage,
        settings: Settings,
        identity_provider_gateway: IdentityProviderGateway,
    ) -> IdentityProvider:
        """Create ldap session."""
        ip_from_request = get_ip_from_request(request)
        user_agent = get_user_agent_from_request(request)

        return IdentityProvider(
            session_storage,
            settings,
            identity_provider_gateway,
            ip_from_request=str(ip_from_request),
            user_agent=user_agent,
            session_key=request.cookies.get("id", ""),
        )

    identity_provider_gateway = provide(
        IdentityProviderGateway,
        scope=Scope.REQUEST,
    )
    mfa_fastapi_adapter = provide(MFAFastAPIAdapter, scope=Scope.REQUEST)
    mfa_manager = provide(MFAManager, scope=Scope.REQUEST)
    ldap_entity_type_adapter = provide(
        LDAPEntityTypeFastAPIAdapter,
        scope=Scope.REQUEST,
    )

    kerberos_service = provide(KerberosService, scope=Scope.REQUEST)
    kerberos_fastapi_adapter = provide(
        KerberosFastAPIAdapter,
        scope=Scope.REQUEST,
    )

    @provide(scope=Scope.REQUEST)
    def get_krb_template_render(
        self,
        settings: Settings,
    ) -> KRBTemplateRenderer:
        """Provide KRBTemplateRenderer with settings.TEMPLATES."""
        return KRBTemplateRenderer(settings.TEMPLATES)

    krb_ldap_manager = provide(KRBLDAPStructureManager, scope=Scope.REQUEST)
    audit_policy_dao = provide(AuditPoliciesDAO, scope=Scope.REQUEST)
    audit_use_case = provide(AuditUseCase, scope=Scope.REQUEST)
    audit_destination_dao = provide(AuditDestinationDAO, scope=Scope.REQUEST)

    @provide(scope=Scope.REQUEST, provides=AuditService)
    async def get_audit_service(self) -> AsyncIterator[AsyncMock]:
        """Provide a mock audit service."""
        audit_service = Mock()

        ok_response = Mock()
        ok_response.status_code = 200

        audit_service.get_policies = AsyncMock(return_value=[])
        audit_service.update_policy = AsyncMock(return_value=None)
        audit_service.get_destinations = AsyncMock(return_value=[])
        audit_service.create_destination = AsyncMock(return_value=None)
        audit_service.update_destination = AsyncMock(return_value=None)
        audit_service.delete_destination = AsyncMock(return_value=None)

        if not self._cached_audit_service:
            self._cached_audit_service = audit_service

        yield self._cached_audit_service

        self._cached_audit_service = None

    audit_adapter = provide(AuditPoliciesAdapter, scope=Scope.REQUEST)

    @provide(scope=Scope.RUNTIME)
    async def get_audit_redis_client(
        self,
        settings: Settings,
    ) -> AsyncIterator[AuditRedisClient]:
        """Get audit redis client."""
        client = redis.Redis.from_url(str(settings.EVENT_HANDLER_URL))

        if not await client.ping():
            raise SystemError("Redis is not available")

        yield AuditRedisClient(client)

        with suppress(RuntimeError):
            await client.aclose()

    @provide(scope=Scope.APP)
    async def get_raw_audit_manager(
        self,
        client: AuditRedisClient,
        settings: Settings,
    ) -> AsyncIterator[RawAuditManager]:
        """Get raw audit manager."""
        yield RawAuditManager(
            client,
            settings.RAW_EVENT_STREAM_NAME,
            settings.EVENT_HANDLER_GROUP,
            settings.EVENT_CONSUMER_NAME,
            settings.IS_PROC_EVENT_KEY,
        )

    @provide(scope=Scope.APP)
    async def get_normalized_audit_manager(
        self,
        client: AuditRedisClient,
        settings: Settings,
    ) -> AsyncIterator[NormalizedAuditManager]:
        """Get raw audit manager."""
        yield NormalizedAuditManager(
            client,
            settings.NORMALIZED_EVENT_STREAM_NAME,
            settings.EVENT_SENDER_GROUP,
            settings.EVENT_CONSUMER_NAME,
            settings.IS_PROC_EVENT_KEY,
        )

    shadow_adapter = provide(
        ShadowAdapter,
        scope=Scope.REQUEST,
    )
    request = from_context(provides=Request, scope=Scope.REQUEST)

    @provide(scope=Scope.REQUEST)
    async def get_audit_monitor(
        self,
        session: AsyncSession,
        audit_use_case: "AuditUseCase",
        session_storage: SessionStorage,
        settings: Settings,
        request: Request,
    ) -> AuditMonitor:
        """Create ldap session."""
        ip_from_request = get_ip_from_request(request)
        user_agent = get_user_agent_from_request(request)
        session_key = request.cookies.get("id", "")

        return AuditMonitor(
            session=session,
            audit_use_case=audit_use_case,
            session_storage=session_storage,
            settings=settings,
            ip_from_request=ip_from_request,
            user_agent=user_agent,
            session_key=session_key,
        )

    add_request_context = provide(
        LDAPAddRequestContext,
        scope=Scope.REQUEST,
    )
    bind_request_context = provide(
        LDAPBindRequestContext,
        scope=Scope.REQUEST,
    )
    delete_request_context = provide(
        LDAPDeleteRequestContext,
        scope=Scope.REQUEST,
    )
    extended_request_context = provide(
        LDAPExtendedRequestContext,
        scope=Scope.REQUEST,
    )
    modify_request_context = provide(
        LDAPModifyRequestContext,
        scope=Scope.REQUEST,
    )
    modify_dn_request_context = provide(
        LDAPModifyDNRequestContext,
        scope=Scope.REQUEST,
    )
    search_request_context = provide(
        LDAPSearchRequestContext,
        scope=Scope.REQUEST,
    )
    unbind_request_context = provide(
        LDAPUnbindRequestContext,
        scope=Scope.REQUEST,
    )
    session_repository = provide(SessionRepository, scope=Scope.REQUEST)
    session_gateway = provide(SessionFastAPIGateway, scope=Scope.REQUEST)
    attribute_type_fastapi_adapter = provide(
        AttributeTypeFastAPIAdapter,
        scope=Scope.REQUEST,
    )
    object_class_fastapi_adapter = provide(
        ObjectClassFastAPIAdapter,
        scope=Scope.REQUEST,
    )

    entity_type_use_case = provide(EntityTypeUseCase, scope=Scope.REQUEST)

    dhcp_adapter = provide(DHCPAdapter, scope=Scope.REQUEST)
    setup_gateway = provide(SetupGateway, scope=Scope.REQUEST)
    setup_use_case = provide(SetupUseCase, scope=Scope.REQUEST)
    network_policy_adapter = provide(
        NetworkPolicyFastAPIAdapter,
        scope=Scope.REQUEST,
    )
    network_policy_use_case = provide(
        NetworkPolicyUseCase,
        scope=Scope.REQUEST,
    )
    network_policy_gateway = provide(NetworkPolicyGateway, scope=Scope.REQUEST)

    @provide(
        provides=AuthorizationProviderProtocol,
        scope=Scope.REQUEST,
    )
    def authorization_provider_protocol(
        self,
        identity_provider: IdentityProvider,
    ) -> AuthorizationProvider:
        return AuthorizationProvider(identity_provider)


@dataclass
class TestCreds:
    """Test credentials class."""

    __test__ = False

    un: str
    pw: str


@dataclass
class TestAdminCreds(TestCreds):
    """Test admin credentials class."""

    __test__ = False


@pytest_asyncio.fixture(scope="session")
async def container(settings: Settings) -> AsyncIterator[AsyncContainer]:
    """Create test container."""
    ctnr = make_async_container(
        TestProvider(),
        MFACredsProvider(),
        context={Settings: settings},
        start_scope=Scope.RUNTIME,
    )
    yield ctnr
    await ctnr.close()


class MutePolicyBindRequest(BindRequest):
    """Mute group validaton."""

    __test__ = False

    @staticmethod
    async def is_user_group_valid(*args, **kwargs) -> bool:  # type: ignore
        """Stub."""
        return True


@pytest_asyncio.fixture
async def kadmin(container: AsyncContainer) -> AsyncIterator[AbstractKadmin]:
    """Get di kadmin."""
    async with container(scope=Scope.APP) as container:
        yield await container.get(AbstractKadmin)


@pytest_asyncio.fixture
async def audit_service(
    container: AsyncContainer,
) -> AsyncIterator[AuditService]:
    """Get di audit_service."""
    async with container(scope=Scope.REQUEST) as container:
        yield await container.get(AuditService)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create uvloop event loop."""
    loop = uvloop.new_event_loop()
    yield loop
    with suppress(asyncio.CancelledError, RuntimeError):
        asyncio.gather(*asyncio.tasks.all_tasks(loop)).cancel()
        loop.close()


@pytest.fixture(scope="session")
def settings() -> Settings:
    """Get settings."""
    return Settings.from_os()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _migrations(
    container: AsyncContainer,
    settings: Settings,
) -> AsyncGenerator:
    """Run simple migrations."""
    engine = await container.get(AsyncEngine)

    config = AlembicConfig("alembic.ini")
    config.attributes["app_settings"] = settings

    def upgrade(conn: AsyncConnection) -> None:
        config.attributes["connection"] = conn
        command.upgrade(config, "head")

    def downgrade(conn: AsyncConnection) -> None:
        config.attributes["connection"] = conn
        command.downgrade(config, "base")

    async with engine.begin() as conn:
        config.attributes["connection"] = conn
        await conn.run_sync(upgrade)  # type: ignore

    yield

    async with engine.begin() as conn:
        await conn.run_sync(downgrade)  # type: ignore


@pytest_asyncio.fixture(scope="function")
async def session(
    container: AsyncContainer,
    handler: PoolClientHandler,
) -> AsyncIterator[AsyncSession]:
    """Get session and acquire after completion."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        handler.container = container
        yield session


@pytest_asyncio.fixture(scope="function")
async def raw_audit_manager(
    container: AsyncContainer,
) -> AsyncIterator[RawAuditManager]:
    """Get raw audit adapter."""
    async with container(scope=Scope.APP) as container:
        yield await container.get(RawAuditManager)


@pytest_asyncio.fixture(scope="function")
async def setup_session(
    session: AsyncSession,
    raw_audit_manager: RawAuditManager,
    password_validator: PasswordValidator,
) -> None:
    """Get session and acquire after completion."""
    object_class_dao = ObjectClassDAO(session)
    entity_type_dao = EntityTypeDAO(session, object_class_dao=object_class_dao)
    for entity_type_data in ENTITY_TYPE_DATAS:
        await entity_type_dao.create(
            dto=EntityTypeDTO(
                id=None,
                name=entity_type_data["name"],  # type: ignore
                object_class_names=entity_type_data["object_class_names"],  # type: ignore
                is_system=True,
            ),
        )

    await session.flush()

    audit_policy_dao = AuditPoliciesDAO(session)
    audit_destination_dao = AuditDestinationDAO(session)
    audit_use_case = AuditUseCase(
        audit_policy_dao,
        audit_destination_dao,
        raw_audit_manager,
    )
    password_policy_dao = PasswordPolicyDAO(session)
    password_policy_validator = PasswordPolicyValidator(
        PasswordValidatorSettings(),
        password_validator,
    )
    password_ban_word_repository = PasswordBanWordRepository(session)
    password_use_cases = PasswordPolicyUseCases(
        password_policy_dao,
        password_policy_validator,
        password_ban_word_repository,
    )
    setup_gateway = SetupGateway(session, password_validator, entity_type_dao)
    await audit_use_case.create_policies()
    await setup_gateway.setup_enviroment(dn="md.test", data=TEST_DATA)

    # NOTE: after setup environment we need base DN to be created
    await password_use_cases.create_default_domain_policy()

    role_dao = RoleDAO(session)
    ace_dao = AccessControlEntryDAO(session)
    role_use_case = RoleUseCase(role_dao, ace_dao)
    await role_use_case.create_domain_admins_role()

    await role_use_case._role_dao.create(  # noqa: SLF001
        dto=RoleDTO(
            name="TEST ONLY LOGIN ROLE",
            creator_upn=None,
            is_system=True,
            groups=["cn=admin login only,cn=groups,dc=md,dc=test"],
            permissions=AuthorizationRules.AUTH_LOGIN,
        ),
    )

    session.add(
        AttributeType(
            oid="1.2.3.4.5.6.7.8",
            name="attr_with_bvalue",
            syntax="1.3.6.1.4.1.1466.115.121.1.40",  # Octet String
            single_value=True,
            no_user_modification=False,
            is_system=True,
        ),
    )
    session.add(
        AttributeType(
            oid="1.2.3.4.5.6.7.8.9",
            name="testing_attr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
            no_user_modification=False,
            is_system=True,
        ),
    )
    await session.commit()


@pytest_asyncio.fixture(scope="function")
async def ldap_session(
    container: AsyncContainer,
) -> AsyncIterator[LDAPSession]:
    """Yield empty session."""
    async with container(scope=Scope.SESSION) as container:
        yield await container.get(LDAPSession)


@pytest_asyncio.fixture(scope="function")
async def ldap_bound_session(
    ldap_session: LDAPSession,
    session: AsyncSession,
    creds: TestCreds,
    setup_session: None,  # noqa: ARG001
) -> AsyncIterator[LDAPSession]:
    """Yield bound session."""
    user = await get_user(session, creds.un)
    assert user
    await ldap_session.set_user(user)
    yield ldap_session
    return


@pytest_asyncio.fixture(scope="session")
async def handler(
    settings: Settings,
    container: AsyncContainer,
) -> AsyncIterator[PoolClientHandler]:
    """Create test handler."""
    async with container(scope=Scope.APP) as app_scope:
        yield PoolClientHandler(settings, app_scope)


@pytest_asyncio.fixture(scope="function")
async def entity_type_dao(
    container: AsyncContainer,
) -> AsyncIterator[EntityTypeDAO]:
    """Get session and acquire after completion."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        object_class_dao = ObjectClassDAO(session)
        yield EntityTypeDAO(session, object_class_dao)


@pytest_asyncio.fixture(scope="function")
async def password_policy_dao(
    container: AsyncContainer,
) -> AsyncIterator[PasswordPolicyDAO]:
    """Get session and acquire after completion."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        yield PasswordPolicyDAO(session)


@pytest_asyncio.fixture(scope="function")
async def password_ban_word_repository(
    container: AsyncContainer,
) -> AsyncIterator[PasswordBanWordRepository]:
    """Get password ban word repository."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        yield PasswordBanWordRepository(session)


@pytest_asyncio.fixture(scope="function")
async def password_validator(
    container: AsyncContainer,
) -> AsyncIterator[PasswordValidator]:
    """Get session and acquire after completion."""
    async with container(scope=Scope.APP) as container:
        yield PasswordValidator()


@pytest_asyncio.fixture(scope="function")
async def password_policy_use_cases(
    container: AsyncContainer,
    password_policy_dao: PasswordPolicyDAO,
    password_ban_word_repository: PasswordBanWordRepository,
    password_policy_validator: PasswordPolicyValidator,
) -> AsyncIterator[PasswordPolicyUseCases]:
    """Get session and acquire after completion."""
    async with container(scope=Scope.APP) as container:
        yield PasswordPolicyUseCases(
            password_policy_dao,
            password_policy_validator,
            password_ban_word_repository,
        )


@pytest_asyncio.fixture(scope="function")
async def password_validator_settings(
    container: AsyncContainer,
) -> AsyncIterator[PasswordValidatorSettings]:
    """Get session and acquire after completion."""
    async with container(scope=Scope.APP) as container:
        yield PasswordValidatorSettings()


@pytest_asyncio.fixture(scope="function")
async def password_policy_validator(
    container: AsyncContainer,
    password_validator_settings: PasswordValidatorSettings,
    password_validator: PasswordValidator,
) -> AsyncIterator[PasswordPolicyValidator]:
    """Get session and acquire after completion."""
    async with container(scope=Scope.APP) as container:
        yield PasswordPolicyValidator(
            password_validator_settings,
            password_validator,
        )


@pytest_asyncio.fixture(scope="function")
async def attribute_type_dao(
    container: AsyncContainer,
) -> AsyncIterator[AttributeTypeDAO]:
    """Get session and acquire after completion."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        yield AttributeTypeDAO(session)


@pytest_asyncio.fixture(scope="function")
async def role_dao(container: AsyncContainer) -> AsyncIterator[RoleDAO]:
    """Get session and acquire after completion."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        yield RoleDAO(session)


@pytest_asyncio.fixture(scope="function")
async def access_control_entry_dao(
    container: AsyncContainer,
) -> AsyncIterator[AccessControlEntryDAO]:
    """Get session and aquire after completion."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        yield AccessControlEntryDAO(session)


@pytest.fixture
def access_manager() -> AccessManager:
    """Get access manager."""
    return AccessManager()


@pytest_asyncio.fixture(scope="function")
async def role_use_case(
    container: AsyncContainer,
) -> AsyncIterator[RoleUseCase]:
    """Get role use case."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        role_dao = RoleDAO(session)
        ace_dao = AccessControlEntryDAO(session)
        yield RoleUseCase(role_dao, ace_dao)


@pytest.fixture(scope="session", autouse=True)
def _server(
    event_loop: asyncio.BaseEventLoop,
    handler: PoolClientHandler,
) -> Generator:
    """Run server in background."""
    task = asyncio.ensure_future(handler.start(), loop=event_loop)
    event_loop.run_until_complete(asyncio.sleep(0.1))
    yield
    with suppress(asyncio.CancelledError):
        task.cancel()


@pytest.fixture
async def ldap_client(
    settings: Settings,
    creds: TestCreds,
) -> AsyncIterator[aioldap3.LDAPConnection]:
    """Get LDAP client without credentials."""
    conn = aioldap3.LDAPConnection(
        aioldap3.Server(host=str(settings.HOST), port=settings.PORT),
    )
    await conn.bind(creds.un, creds.pw)
    yield conn
    await conn.unbind()


@pytest.fixture
async def anonymous_ldap_client(
    settings: Settings,
) -> AsyncIterator[aioldap3.LDAPConnection]:
    """Get LDAP client without credentials."""
    conn = aioldap3.LDAPConnection(
        aioldap3.Server(host=str(settings.HOST), port=settings.PORT),
    )
    await conn.bind()
    yield conn
    await conn.unbind()


@pytest_asyncio.fixture(scope="function")
async def app(
    settings: Settings,
    container: AsyncContainer,
) -> AsyncIterator[FastAPI]:
    """App creator fixture."""
    async with container(scope=Scope.APP) as container:
        app = _create_basic_app(settings)
        app.include_router(shadow_router, prefix="/shadow")
        setup_dishka(container, app)
        yield app


@pytest_asyncio.fixture(scope="function")
async def unbound_http_client(
    app: FastAPI,
) -> AsyncIterator[httpx.AsyncClient]:
    """Get async client for fastapi tests.

    :param FastAPI app: asgi app
    :yield Iterator[AsyncIterator[httpx.AsyncClient]]: yield client
    """
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, root_path="/api"),
        timeout=3,
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture(scope="function")
async def http_client(
    unbound_http_client: httpx.AsyncClient,
    creds: TestCreds,
    setup_session: None,  # noqa: ARG001
) -> httpx.AsyncClient:
    """Authenticate and return client with cookies.

    :param httpx.AsyncClient unbound_http_client: client w/o cookies
    :param TestCreds creds: creds to authn
    :param None setup_session: just a fixture call
    :return httpx.AsyncClient: bound client with cookies
    """
    response = await unbound_http_client.post(
        "auth/",
        data={"username": creds.un, "password": creds.pw},
    )

    assert response.status_code == 200
    assert unbound_http_client.cookies.get("id")

    return unbound_http_client


@pytest_asyncio.fixture(scope="function")
async def http_client_without_perms(
    unbound_http_client: httpx.AsyncClient,
    creds_without_api_perms: TestCreds,
    setup_session: None,  # noqa: ARG001
) -> httpx.AsyncClient:
    """Authenticate and return client with cookies.

    :param httpx.AsyncClient unbound_http_client: client w/o cookies
    :param TestCreds creds: creds to authn
    :param None setup_session: just a fixture call
    :return httpx.AsyncClient: bound client with cookies
    """
    response = await unbound_http_client.post(
        "auth/",
        data={
            "username": creds_without_api_perms.un,
            "password": creds_without_api_perms.pw,
        },
    )

    assert response.status_code == 200
    assert unbound_http_client.cookies.get("id")

    return unbound_http_client


@pytest_asyncio.fixture(scope="function")
async def admin_http_client(
    app: FastAPI,
    admin_creds: TestAdminCreds,
    setup_session: None,  # noqa: ARG001
) -> AsyncIterator[httpx.AsyncClient]:
    """Authenticate as admin and return client with cookies.

    :param httpx.AsyncClient unbound_http_client: client w/o cookies
    :param None setup_session: just a fixture call
    :return httpx.AsyncClient: bound client with cookies
    """
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, root_path="/api"),
        timeout=3,
        base_url="http://test",
    ) as unbound_http_client:
        response = await unbound_http_client.post(
            "auth/",
            data={"username": admin_creds.un, "password": admin_creds.pw},
        )

        assert response.status_code == 200
        assert unbound_http_client.cookies.get("id")

        yield unbound_http_client


@pytest.fixture
def creds(user: dict) -> TestCreds:
    """Get creds from test data."""
    return TestCreds(user["sam_account_name"], user["password"])


@pytest.fixture
def user() -> dict:
    """Get user data."""
    return TEST_DATA[1]["children"][0]["organizationalPerson"]  # type: ignore


@pytest.fixture
def creds_without_api_perms(user_without_api_perms: dict) -> TestCreds:
    """Get creds from test data."""
    return TestCreds(
        user_without_api_perms["sam_account_name"],
        user_without_api_perms["password"],
    )


@pytest.fixture
def admin_creds(admin_user: dict) -> TestAdminCreds:
    """Get admin creds from test data."""
    return TestAdminCreds(
        admin_user["sam_account_name"],
        admin_user["password"],
    )


@pytest.fixture
def user_without_api_perms() -> dict:
    """Get user data."""
    return TEST_DATA[1]["children"][2]["organizationalPerson"]  # type: ignore


@pytest.fixture
def admin_user() -> dict:
    """Get admin user data."""
    return TEST_DATA[1]["children"][1]["organizationalPerson"]  # type: ignore


@pytest.fixture
async def api_permissions_checker(
    request_container: AsyncContainer,
) -> AsyncIterator[AuthorizationProvider]:
    """Get all api permissions."""
    return await request_container.get(AuthorizationProviderProtocol)


@pytest_asyncio.fixture
async def request_params() -> dict:
    """Return minimal ASGI scope plus response for request-scoped providers."""
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": ("127.0.0.1", 0),
        "server": ("testserver", 80),
    }
    request = Request(scope)
    response = Response()
    return {Request: request, Response: response}


@pytest_asyncio.fixture
async def request_container(
    container: AsyncContainer,
    request_params: dict,
) -> AsyncIterator[AsyncContainer]:
    """Create request scope with Request context."""
    async with container(scope=Scope.REQUEST, context=request_params) as cont:
        yield cont


@pytest.fixture
def _force_override_tls(settings: Settings) -> Iterator:
    """Override tls status for tests."""
    current_status = settings.USE_CORE_TLS
    settings.USE_CORE_TLS = True
    yield
    settings.USE_CORE_TLS = current_status


@pytest_asyncio.fixture
async def dns_manager(
    container: AsyncContainer,
) -> AsyncIterator[AbstractDNSManager]:
    """Get DI DNS manager."""
    async with container(scope=Scope.REQUEST) as container:
        yield await container.get(AbstractDNSManager)


@pytest_asyncio.fixture
async def dhcp_manager(
    request_container: AsyncContainer,
) -> AsyncIterator[AbstractDHCPManager]:
    """Get DI DHCP manager."""
    yield await request_container.get(AbstractDHCPManager)


@pytest.fixture
async def storage(container: AsyncContainer) -> AsyncIterator[SessionStorage]:
    """Return session storage."""
    async with container() as c:
        yield await c.get(SessionStorage)


@pytest.fixture
async def ctx_bind(
    container: AsyncContainer,
) -> AsyncIterator[LDAPBindRequestContext]:
    """Return session storage."""
    async with container(scope=Scope.REQUEST) as c:
        yield await c.get(LDAPBindRequestContext)


@pytest.fixture
async def ctx_unbind(
    container: AsyncContainer,
) -> AsyncIterator[LDAPUnbindRequestContext]:
    """Return session storage."""
    async with container(scope=Scope.REQUEST) as c:
        yield await c.get(LDAPUnbindRequestContext)


@pytest.fixture
async def ctx_add(
    container: AsyncContainer,
) -> AsyncIterator[LDAPAddRequestContext]:
    """Return session storage."""
    async with container(scope=Scope.REQUEST) as c:
        yield await c.get(LDAPAddRequestContext)


@pytest.fixture
async def ctx_search(
    container: AsyncContainer,
) -> AsyncIterator[LDAPSearchRequestContext]:
    """Return session storage."""
    async with container(scope=Scope.REQUEST) as c:
        yield await c.get(LDAPSearchRequestContext)
