"""Test kadmin."""

import asyncio
from functools import partial
from hashlib import blake2b
from unittest.mock import Mock

import pytest
from fastapi import status
from httpx import AsyncClient
from ldap3 import Connection
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KerberosState, KRBAPIError
from ldap_protocol.ldap_requests.bind import LDAPCodes, SimpleAuthentication
from tests.conftest import MutePolicyBindRequest, TestCreds


def _create_test_user_data(
        name: str, pw: str) -> dict[
            str, str | list[dict[str, str | list[str]]]]:
    return {
        "entry": "cn=ktest,dc=md,dc=test",
        "password": pw,
        "attributes": [
            {"type": "mail", "vals": ['123@mil.com']},
            {"type": "objectClass", "vals": [
                "user", "top", "person",
                "organizationalPerson",
                "posixAccount",
                "shadowAccount",
                "inetOrgPerson",
            ]},
            {"type": "loginShell", "vals": ["/bin/false"]},
            {"type": "uidNumber", "vals": ["800"]},
            {"type": "gidNumber", "vals": ["800"]},
            {"type": "sn", "vals": ["ktest"]},
            {"type": "uid", "vals": ["ktest"]},
            {"type": "homeDirectory", "vals": ["/home/ktest"]},
            {"type": "sAMAccountName", "vals": [name]},
            {"type": "userPrincipalName", "vals": ['ktest']},
            {"type": "displayName", "vals": ["Kerberos Administrator"]},
            {"type": "userAccountControl", "vals": ["512"]},
        ]}


@pytest.mark.asyncio
async def test_tree_creation(
    http_client: AsyncClient,
    ldap_session: LDAPSession,
    session: AsyncSession,
    kadmin: AbstractKadmin,
    settings: Settings,
) -> None:
    """Test tree creation."""
    krbadmin_pw = 'Password123'
    response = await http_client.post('/kerberos/setup/tree', json={
        "mail": '777@example.com',
        "krbadmin_password": krbadmin_pw,
    })

    assert response.status_code == status.HTTP_200_OK

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "ou=services,dc=md,dc=test",
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
    )
    assert response.json()[
        'search_result'][0]['object_name'] == "ou=services,dc=md,dc=test"

    bind = MutePolicyBindRequest(
        version=0,
        name='cn=krbadmin,ou=users,dc=md,dc=test',
        AuthenticationChoice=SimpleAuthentication(password=krbadmin_pw),
    )

    result = await anext(bind.handle(
        session, ldap_session, kadmin, settings, None))  # type: ignore
    assert result.result_code == LDAPCodes.SUCCESS


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_tree_collision(http_client: AsyncClient) -> None:
    """Test tree collision double creation."""
    response = await http_client.post('/kerberos/setup/tree', json={
        "mail": '777@example.com',
        "krbadmin_password": 'Password123',
    })

    assert response.status_code == status.HTTP_200_OK

    response = await http_client.post('/kerberos/setup/tree', json={
        "mail": '777@example.com',
        "krbadmin_password": 'Password123',
    })

    assert response.status_code == status.HTTP_409_CONFLICT


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_setup_call(
    http_client: AsyncClient,
    kadmin: Mock,
    creds: TestCreds,
) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param LDAPSession ldap_session: ldap
    """
    response = await http_client.post('/kerberos/setup', json={
        "krbadmin_password": 'Password123',
        "admin_password": creds.pw,
        "stash_password": 'Password123',
    })

    assert response.status_code == status.HTTP_200_OK

    kadmin.setup.assert_called()

    krb_doc = kadmin.setup.call_args.kwargs.pop('krb5_config').encode()
    kdc_doc = kadmin.setup.call_args.kwargs.pop('kdc_config').encode()

    # NOTE: Asserting documents integrity, tests template rendering
    assert blake2b(krb_doc, digest_size=8).hexdigest() == '4ad6476a349f5f80'
    assert blake2b(kdc_doc, digest_size=8).hexdigest() == 'b6b24f89078a2572'

    assert kadmin.setup.call_args.kwargs == {
        'domain': 'md.test',
        'admin_dn': 'cn=user0,ou=users,dc=md,dc=test',
        'services_dn': 'ou=services,dc=md,dc=test',
        'krbadmin_dn': 'cn=krbadmin,ou=users,dc=md,dc=test',
        'krbadmin_password': 'Password123',
        'ldap_keytab_path': '/LDAP_keytab/krb5.keytab',
        'admin_password': creds.pw,
        'stash_password': 'Password123',
    }


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_status_change(
    http_client: AsyncClient,
    creds: TestCreds,
) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param LDAPSession ldap_session: ldap
    """
    response = await http_client.get(
        '/kerberos/status')
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == KerberosState.NOT_CONFIGURED

    await http_client.post('/kerberos/setup', json={
        "krbadmin_password": 'Password123',
        "admin_password": creds.pw,
        "stash_password": 'Password123',
    })

    response = await http_client.get(
        '/kerberos/status')
    assert response.json() == KerberosState.WAITING_FOR_RELOAD


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_ktadd(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Test ktadd.

    :param AsyncClient http_client: http cl
    :param LDAPSession ldap_session: ldap
    """
    names = ['test1', 'test2']
    response = await http_client.post('/kerberos/ktadd', json=names)

    kadmin.ktadd.assert_called()  # type: ignore
    assert kadmin.ktadd.call_args.args[0] == names  # type: ignore

    assert response.status_code == status.HTTP_200_OK
    assert response.content == b'test_string'
    assert response.headers[
        'Content-Disposition'] == 'attachment; filename="krb5.keytab"'
    assert response.headers['content-type'] == 'application/txt'


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_ktadd_404(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Test ktadd failure.

    :param AsyncClient http_client: http cl
    :param LDAPSession ldap_session: ldap
    """
    kadmin.ktadd.side_effect = KRBAPIError()  # type: ignore

    names = ['test1', 'test2']
    response = await http_client.post('/kerberos/ktadd', json=names)

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_ldap_add(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Test add calls add_principal on user creation.

    :param AsyncClient http_client: http
    :param TestKadminClient kadmin: kadmin
    """
    san = 'ktest'
    pw = 'Password123'

    response = await http_client.post(
        "/entry/add",
        json=_create_test_user_data(san, pw))

    assert response.status_code == status.HTTP_200_OK, response.json()
    assert kadmin.add_principal.call_args.args == (san, pw)  # type: ignore


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_ldap_kadmin_delete_user(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Test API for delete object."""
    await http_client.post(
        "/entry/add",
        json=_create_test_user_data('ktest', 'Password123'))

    response = await http_client.request(
        "delete", "/entry/delete",
        json={"entry": "cn=ktest,dc=md,dc=test"},
    )

    data = response.json()

    assert data.get('resultCode') == LDAPCodes.SUCCESS

    assert kadmin.del_principal.call_args.args[0] == "ktest"  # type: ignore


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_ldap_kadmin_delete_computer(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Test API for delete object."""
    await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=ktest,dc=md,dc=test",
            "password": None,
            "attributes": [
                {"type": "objectClass", "vals": ["computer", "top"]}],
        })

    response = await http_client.request(
        "delete", "/entry/delete",
        json={"entry": "cn=ktest,dc=md,dc=test"},
    )

    data = response.json()

    assert data.get('resultCode') == LDAPCodes.SUCCESS
    principal = kadmin.del_principal.call_args.args[0]  # type: ignore
    assert principal == 'host/ktest.md.test'


@pytest.mark.asyncio
async def test_bind_create_user(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
    settings: Settings,
) -> None:
    """Test bind create user."""
    san = 'ktest'
    pw = 'Password123'

    await http_client.post("/entry/add", json=_create_test_user_data(san, pw))

    proc = await asyncio.create_subprocess_exec(
        'ldapwhoami', '-x',
        '-H', f'ldap://{settings.HOST}:{settings.PORT}',
        '-D', san,
        '-w', pw,
    )

    assert await proc.wait() == 0
    kadmin_args = kadmin.add_principal.call_args.args  # type: ignore
    assert kadmin_args == (san, pw, 0.1)


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
@pytest.mark.usefixtures('_force_override_tls')
async def test_extended_pw_change_call(
    event_loop: asyncio.BaseEventLoop,
    ldap_client: Connection,
    creds: TestCreds,
    kadmin: AbstractKadmin,
) -> None:
    """Test anonymous pwd change."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"
    password = creds.pw
    new_test_password = 'Password123'  # noqa

    await event_loop.run_in_executor(
        None, partial(ldap_client.rebind, user=user_dn, password=password))

    result = await event_loop.run_in_executor(
        None,
        partial(  # noqa: S106
            ldap_client.extend.standard.modify_password,
            old_password=password,
            new_password=new_test_password,
        ))

    assert result
    kadmin_args = (
        kadmin.create_or_update_principal_pw.call_args.args)  # type: ignore
    assert kadmin_args == ('user0', new_test_password)


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_add_princ(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param LDAPSession ldap_session: ldap
    """
    response = await http_client.post(
        '/kerberos/principal/add',
        json={
            "primary": "host",
            "instance": "12345",
        },
    )
    kadmin_args = kadmin.add_principal.call_args.args  # type: ignore
    assert response.status_code == status.HTTP_200_OK
    assert kadmin_args == ("host/12345", None)


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_rename_princ(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param LDAPSession ldap_session: ldap
    """
    response = await http_client.patch(
        '/kerberos/principal/rename',
        json={
            "principal_name": "name",
            "principal_new_name": "nname",
        },
    )
    kadmin_args = kadmin.rename_princ.call_args.args  # type: ignore
    assert response.status_code == status.HTTP_200_OK
    assert kadmin_args == ("name", "nname")


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_change_princ(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param LDAPSession ldap_session: ldap
    """
    response = await http_client.patch(
        '/kerberos/principal/reset',
        json={
            "principal_name": "name",
            "new_password": "pw123",
        },
    )
    kadmin_args = (
        kadmin.change_principal_password.call_args.args)  # type: ignore
    assert response.status_code == status.HTTP_200_OK
    assert kadmin_args == ("name", "pw123")


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_delete_princ(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param LDAPSession ldap_session: ldap
    """
    response = await http_client.request(
        "delete",
        '/kerberos/principal/delete',
        json={"principal_name": "name"},
    )
    assert response.status_code == status.HTTP_200_OK
    assert kadmin.del_principal.call_args.args == ("name",)  # type: ignore


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
@pytest.mark.usefixtures('setup_session')
async def test_admin_incorrect_pw_setup(http_client: AsyncClient) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param LDAPSession ldap_session: ldap
    """
    response = await http_client.get('/kerberos/status')
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == KerberosState.NOT_CONFIGURED

    response = await http_client.post('/kerberos/setup', json={
        "krbadmin_password": 'Password123',
        "admin_password": '----',
        "stash_password": 'Password123',
    })

    assert response.status_code == 403


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_api_update_password(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Update policy."""
    await http_client.patch(
        "auth/user/password",
        json={"identity": "user0", "new_password": "Password123"},
    )
    kadmin_args = (
        kadmin.create_or_update_principal_pw.call_args.args)  # type: ignore
    assert kadmin_args == ("user0", "Password123")


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_update_password(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Update policy."""
    (
        kadmin.
        create_or_update_principal_pw.
        side_effect  # type: ignore
    ) = KRBAPIError()
    response = await http_client.patch(
        "auth/user/password",
        json={"identity": "user0", "new_password": "Password123"},
    )
    assert response.status_code == status.HTTP_424_FAILED_DEPENDENCY
