"""Test password change.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from aioldap3 import LDAPConnection
from pyasn1.codec.ber import encoder
from pyasn1.type import namedtype, tag, univ
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.asn1parser import LDAPOID, ASN1Row, asn1todict
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.kerberos.base import AbstractKadmin
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests.extended import (
    ExtendedRequest,
    PasswdModifyRequestValue,
)
from ldap_protocol.ldap_responses import (
    BaseExtendedResponseValue,
    ExtendedResponse,
)
from ldap_protocol.policies.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.utils.queries import get_user
from models import Directory, User
from security import get_password_hash, verify_password
from tests.conftest import TestCreds


class PasswordModifyRequest(univ.Sequence):
    """ASN.1 definition for password modify request.

    PasswdModifyRequestValue ::= SEQUENCE {
        userIdentity    [0]  OCTET STRING OPTIONAL
        oldPasswd       [1]  OCTET STRING OPTIONAL
        newPasswd       [2]  OCTET STRING OPTIONAL }
    """

    componentType = namedtype.NamedTypes(  # noqa: N815
        namedtype.OptionalNamedType(
            "userIdentity",
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            ),
        ),
        namedtype.OptionalNamedType(
            "oldPassword",
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            ),
        ),
        namedtype.OptionalNamedType(
            "newPassword",
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 2
                )
            ),
        ),
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("_force_override_tls")
async def test_anonymous_pwd_change(
    session: AsyncSession,
    ldap_client: LDAPConnection,
    ldap_session: LDAPSession,
    kadmin: AbstractKadmin,
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test anonymous pwd change."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"
    password = creds.pw
    new_test_password = "Password123"  # noqa
    await ldap_client.bind(user_dn, password)

    # request_value = PasswdModifyRequestValue(
    #     user_identity=user_dn,
    #     old_password=SecretStr(password),
    #     new_password=SecretStr(new_test_password),
    # )

    # ex_request = ExtendedRequest(
    #     request_name="1.3.6.1.4.1.4203.1.11.1", request_value=request_value
    # )

    request_value = PasswordModifyRequest()
    request_value.setComponentByName("userIdentity", user_dn)
    request_value.setComponentByName("oldPassword", password)
    request_value.setComponentByName("newPassword", new_test_password)
    res = encoder.encode(request_value)
    await ldap_client.extended("1.3.6.1.4.1.4203.1.11.1", request_value=res)

    # async for response in ex_request.handle(
    #     ldap_session=ldap_session,
    #     session=session,
    #     kadmin=kadmin,
    #     settings=settings,
    # ):
    #     assert response.result_code == LDAPCodes.SUCCESS

    user = await get_user(session, user_dn)
    assert user
    assert user.password

    assert verify_password(new_test_password, user.password)

    await ldap_client.unbind()


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("_force_override_tls")
async def test_bind_pwd_change(
    session: AsyncSession,
    ldap_client: LDAPConnection,
    creds: TestCreds,
) -> None:
    """Test anonymous pwd change."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"
    password = creds.pw
    new_test_password = "Password123"  # noqa
    await ldap_client.bind(user_dn, password)
    await ldap_client.modify_password(new_test_password)

    user = await get_user(session, user_dn)

    assert user
    assert user.password

    assert verify_password(new_test_password, user.password)

    await ldap_client.unbind()
