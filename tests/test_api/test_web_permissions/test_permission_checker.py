"""Tests for permisions checker."""

import inspect
from typing import Any, Literal
from unittest.mock import AsyncMock, Mock

import pytest
from dishka import AsyncContainer, Scope
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_service import AbstractService
from authorization_provider_protocol import AuthorizationProviderProtocol
from enums import AuthorizationRules
from ldap_protocol.auth.auth_manager import AuthManager
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.permissions_checker import AuthorizationError
from ldap_protocol.utils.queries import get_user
from tests.conftest import TestCreds
from tests.test_api.test_web_permissions.conftest import create_mock_arg


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
    creds: TestCreds,
    session: AsyncSession,
    api_permissions_checker: AuthorizationProviderProtocol,
) -> None:
    """Test that user with permissions can access protected resources."""
    user = await get_user(session, creds.un)
    assert user

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
    subclasses = AbstractService.__subclasses__()
    for cls in subclasses:
        async with container(
            scope=Scope.REQUEST,
            context=request_params,
        ) as cont:
            cls_instance = await cont.get(cls)

        cls_instance.set_permissions_checker(api_permissions_checker)
        if cls == AuthManager:
            cls_instance._monitor.wrap_login = lambda x: x  # noqa: SLF001
            cls_instance._monitor.wrap_reset_password = lambda x: x  # noqa: SLF001
            cls_instance._monitor.wrap_change_password = lambda x: x  # noqa: SLF001

        for method_name in cls.PERMISSIONS:
            method = getattr(cls_instance, method_name)
            sig = inspect.signature(method)
            params = [p for p in sig.parameters.values() if p.name != "self"]
            args = [
                create_mock_arg(p.annotation)
                for p in params
                if p.default == inspect.Parameter.empty
            ]
            kwargs = {
                p.name: create_mock_arg(p.annotation)
                for p in params
                if p.default != inspect.Parameter.empty
            }

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
    subclasses = AbstractService.__subclasses__()
    for cls in subclasses:
        async with container(
            scope=Scope.REQUEST,
            context=request_params,
        ) as cont:
            cls_instance = await cont.get(cls)

        cls_instance.set_permissions_checker(api_permissions_checker)
        if cls == AuthManager:
            cls_instance._monitor.wrap_login = lambda x: x  # noqa: SLF001
            cls_instance._monitor.wrap_reset_password = lambda x: x  # noqa: SLF001
            cls_instance._monitor.wrap_change_password = lambda x: x  # noqa: SLF001

        for method_name in cls.PERMISSIONS:
            method = getattr(cls_instance, method_name)
            sig = inspect.signature(method)
            params = [p for p in sig.parameters.values() if p.name != "self"]
            args = [
                create_mock_arg(p.annotation)
                for p in params
                if p.default == inspect.Parameter.empty
            ]
            kwargs = {
                p.name: create_mock_arg(p.annotation)
                for p in params
                if p.default != inspect.Parameter.empty
            }

        try:  # type: ignore
            await method(*args, **kwargs)
        except AuthorizationError:
            pytest.fail("AuthorizationError was raised unexpectedly")
        except Exception:  # noqa: S112
            continue
