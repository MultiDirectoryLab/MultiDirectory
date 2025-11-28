"""Tests for permissions checker."""

from unittest.mock import AsyncMock

import pytest
from dishka import AsyncContainer
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_service import AbstractService
from authorization_provider_protocol import AuthorizationProviderProtocol
from enums import AuthorizationRules
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.permissions_checker import AuthorizationError
from ldap_protocol.utils.queries import get_user
from tests.conftest import TestCreds
from tests.test_api.test_web_permissions.conftest import (
    get_params,
    get_test_instance_generator,
)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_perm_checker_without_roles(
    creds_with_login_perm: TestCreds,
    session: AsyncSession,
    api_permissions_checker: AuthorizationProviderProtocol,
) -> None:
    """Test that user without permissions cannot access protected resources."""
    user_with_login_perm = await get_user(
        session,
        creds_with_login_perm.un,
    )
    assert user_with_login_perm

    api_permissions_checker._idp.get_current_user = AsyncMock(  # type: ignore  # noqa: SLF001
        return_value=await UserSchema.from_db(user_with_login_perm, ""),
    )

    has_perm = await api_permissions_checker._has_permission(  # type: ignore # noqa: SLF001
        AuthorizationRules.PASSWORD_POLICY_GET_ALL,
    )
    assert has_perm is False

    with pytest.raises(AuthorizationError):  # type: ignore
        await api_permissions_checker.check_permission(
            AuthorizationRules.PASSWORD_POLICY_GET_ALL,
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_perm_checker_with_roles(
    creds_with_login_perm: TestCreds,
    session: AsyncSession,
    api_permissions_checker: AuthorizationProviderProtocol,
) -> None:
    """Test that user with permissions can access protected resources."""
    user = await get_user(session, creds_with_login_perm.un)
    assert user
    user.groups[0].roles[0].permissions |= AuthorizationRules.PASSWORD_POLICY_GET_ALL  # fmt: skip  # noqa: E501
    await session.commit()
    api_permissions_checker._idp.get_current_user = AsyncMock(  # type: ignore # noqa: SLF001
        return_value=await UserSchema.from_db(user, ""),
    )

    has_perm = await api_permissions_checker._has_permission(  # type: ignore # noqa: SLF001
        AuthorizationRules.PASSWORD_POLICY_GET_ALL,
    )
    assert has_perm is True

    try:  # type: ignore
        await api_permissions_checker.check_permission(
            AuthorizationRules.PASSWORD_POLICY_GET_ALL,
        )
    except AuthorizationError:
        pytest.fail("AuthorizationError was raised unexpectedly")


@pytest.mark.asyncio
async def test_no_duplicate_permissions_in_service() -> None:
    """Get all permissions used in AbstractService subclasses.

    :return: Set of used AuthorizationRules
    """
    used_permissions: list[AuthorizationRules] = []
    subclasses = AbstractService.__subclasses__()
    for cls in subclasses:
        if hasattr(cls, "PERMISSIONS"):
            for permission in cls.PERMISSIONS.values():
                used_permissions.append(permission)

    assert len(used_permissions) == len(set(used_permissions))


@pytest.mark.asyncio
async def test_all_authorization_rules_are_used() -> None:
    """Test that all AuthorizationRules are used in AbstractService subclasses.

    This test ensures that every permission defined in AuthorizationRules enum
    is actually used in at least one AbstractService subclass PERMISSIONS dict.
    """
    used_permissions: set[AuthorizationRules] = set()
    subclasses = AbstractService.__subclasses__()
    for cls in subclasses:
        if hasattr(cls, "PERMISSIONS"):
            for permission in cls.PERMISSIONS.values():
                used_permissions.add(permission)

    unused_perm = {rule for rule in AuthorizationRules} - used_permissions
    assert unused_perm == {AuthorizationRules.AUTH_LOGIN}
    assert not used_permissions - {rule for rule in AuthorizationRules}


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_all_authorization_rules_forbid(
    session: AsyncSession,
    api_permissions_checker: AuthorizationProviderProtocol,
    container: AsyncContainer,
    request_params: dict,
) -> None:
    """Test that user without permissions cannot access protected resources."""
    user_without_api_perms = await get_user(session, "user_non_admin")
    assert user_without_api_perms

    api_permissions_checker._idp.get_current_user = AsyncMock(  # type: ignore  # noqa: SLF001
        return_value=await UserSchema.from_db(user_without_api_perms, ""),
    )
    cls_instances = get_test_instance_generator(
        container,
        request_params,
        api_permissions_checker,
    )
    async for cls_instance in cls_instances:
        for method_name in cls_instance.PERMISSIONS:
            method = getattr(cls_instance, method_name)
            args, kwargs = get_params(method)
            with pytest.raises(AuthorizationError):
                await method(*args, **kwargs)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_all_authorization_rules_available(
    session: AsyncSession,
    api_permissions_checker: AuthorizationProviderProtocol,
    container: AsyncContainer,
    request_params: dict,
    creds: TestCreds,
) -> None:
    """Test that user without permissions cannot access protected resources."""
    user_with_api_perms = await get_user(session, creds.un)
    assert user_with_api_perms

    api_permissions_checker._idp.get_current_user = AsyncMock(  # type: ignore  # noqa: SLF001
        return_value=await UserSchema.from_db(user_with_api_perms, ""),
    )
    cls_instances = get_test_instance_generator(
        container,
        request_params,
        api_permissions_checker,
    )
    async for cls_instance in cls_instances:
        for method_name in cls_instance.PERMISSIONS:
            method = getattr(cls_instance, method_name)
            args, kwargs = get_params(method)

            try:
                await method(*args, **kwargs)
            except AuthorizationError:
                pytest.fail("AuthorizationError was raised unexpectedly")
            except Exception:
                await session.rollback()
