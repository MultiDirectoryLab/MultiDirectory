"""LDAP Dataclasses for handle requests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from application.dialogue import LDAPSession
from application.kerberos import AbstractKadmin
from application.ldap_schema.attribute_value_validator import (
    AttributeValueValidator,
)
from application.ldap_schema.entity_type_dao import EntityTypeDAO
from application.multifactor import LDAPMultiFactorAPI
from application.policies.network import NetworkPolicyValidatorUseCase
from application.policies.password import PasswordPolicyUseCases
from application.roles.access_manager import AccessManager
from application.roles.role_use_case import RoleUseCase
from application.rootdse.reader import RootDSEReader
from application.session_storage import SessionStorage
from password_utils import PasswordUtils


@dataclass
class LDAPAddRequestContext:
    """Context for LDAP add request."""

    session: AsyncSession
    ldap_session: LDAPSession
    kadmin: AbstractKadmin
    entity_type_dao: EntityTypeDAO
    password_use_cases: PasswordPolicyUseCases
    password_utils: PasswordUtils
    access_manager: AccessManager
    role_use_case: RoleUseCase
    attribute_value_validator: AttributeValueValidator


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
    password_use_cases: PasswordPolicyUseCases
    password_utils: PasswordUtils
    attribute_value_validator: AttributeValueValidator


@dataclass
class LDAPBindRequestContext:
    """Context for LDAP bind request."""

    session: AsyncSession
    ldap_session: LDAPSession
    kadmin: AbstractKadmin
    settings: Settings
    password_use_cases: PasswordPolicyUseCases
    password_utils: PasswordUtils
    mfa: LDAPMultiFactorAPI
    network_policy_validator: NetworkPolicyValidatorUseCase


@dataclass
class LDAPSearchRequestContext:
    """Context for LDAP search request."""

    session: AsyncSession
    ldap_session: LDAPSession
    settings: Settings
    access_manager: AccessManager
    rootdse_rd: RootDSEReader


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
    password_use_cases: PasswordPolicyUseCases
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
    attribute_value_validator: AttributeValueValidator


@dataclass
class LDAPAbandonRequestContext: ...
