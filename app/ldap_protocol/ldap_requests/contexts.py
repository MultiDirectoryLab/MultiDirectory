"""LDAP Dataclasses for handle requests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.multifactor import LDAPMultiFactorAPI
from ldap_protocol.policies.password import PasswordPolicyUseCases
from ldap_protocol.roles.access_manager import AccessManager
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.session_storage import SessionStorage
from password_manager import PasswordUtils


@dataclass
class LDAPAddRequestContext:
    """Context for LDAP add request."""

    session: AsyncSession
    ldap_session: LDAPSession
    kadmin: AbstractKadmin
    entity_type_dao: EntityTypeDAO
    pwd_policy_use_cases: PasswordPolicyUseCases
    password_utils: PasswordUtils
    access_manager: AccessManager
    role_use_case: RoleUseCase


@dataclass
class LDAPModifyRequestContext:
    """Context for LDAP modify request."""

    ldap_session: LDAPSession
    session: AsyncSession
    session_storage: SessionStorage
    kadmin: AbstractKadmin
    settings: Settings
    entity_type_dao: EntityTypeDAO
    access_manager: AccessManager
    pwd_policy_use_cases: PasswordPolicyUseCases
    password_utils: PasswordUtils


@dataclass
class LDAPBindRequestContext:
    """Context for LDAP bind request."""

    session: AsyncSession
    ldap_session: LDAPSession
    kadmin: AbstractKadmin
    settings: Settings
    pwd_policy_use_cases: PasswordPolicyUseCases
    password_utils: PasswordUtils
    mfa: LDAPMultiFactorAPI


@dataclass
class LDAPSearchRequestContext:
    """Context for LDAP search request."""

    session: AsyncSession
    ldap_session: LDAPSession
    settings: Settings
    access_manager: AccessManager


@dataclass
class LDAPDeleteRequestContext:
    """Context for LDAP delete request."""

    session: AsyncSession
    ldap_session: LDAPSession
    kadmin: AbstractKadmin
    session_storage: SessionStorage
    access_manager: AccessManager


@dataclass
class LDAPUnbindRequestContext:
    """Context for LDAP unbind request."""

    ldap_session: LDAPSession


@dataclass
class LDAPExtendedRequestContext:
    """Context for LDAP extended request."""

    ldap_session: LDAPSession
    session: AsyncSession
    kadmin: AbstractKadmin
    pwd_policy_use_cases: PasswordPolicyUseCases
    password_utils: PasswordUtils
    settings: Settings
    role_use_case: RoleUseCase
    session_storage: SessionStorage


@dataclass
class LDAPModifyDNRequestContext:
    """Context for LDAP modify dn request."""

    ldap_session: LDAPSession
    session: AsyncSession
    entity_type_dao: EntityTypeDAO
    access_manager: AccessManager
    role_use_case: RoleUseCase
