"""Test kadmin."""

import asyncio
from functools import partial
from hashlib import blake2b

import pytest
from fastapi import status
from httpx import AsyncClient
from ldap3 import Connection
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import KerberosState, KRBAPIError
from ldap_protocol.ldap_requests.bind import LDAPCodes, SimpleAuthentication
from tests.conftest import MutePolicyBindRequest, TestCreds, TestKadminClient


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
        ]}


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_tree_creation(
    http_client: AsyncClient,
    login_headers: dict,
    ldap_session: LDAPSession,
    session: AsyncSession,
) -> None:
    """Test tree creation."""
    krbadmin_pw = 'Password123'
    response = await http_client.post('/kerberos/setup/tree', json={
        "mail": '777@example.com',
        "krbadmin_password": krbadmin_pw,
    }, headers=login_headers)

    assert response.status_code == 200

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
        headers=login_headers,
    )
    assert response.json()[
        'search_result'][0]['object_name'] == "ou=services,dc=md,dc=test"

    bind = MutePolicyBindRequest(
        version=0,
        name='cn=krbadmin,ou=users,dc=md,dc=test',
        AuthenticationChoice=SimpleAuthentication(password=krbadmin_pw),
    )

    result = await anext(bind.handle(ldap_session, session))
    assert result.result_code == LDAPCodes.SUCCESS


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_tree_collision(
    http_client: AsyncClient,
    login_headers: dict,
) -> None:
    """Test tree collision double creation."""
    response = await http_client.post('/kerberos/setup/tree', json={
        "mail": '777@example.com',
        "krbadmin_password": 'Password123',
    }, headers=login_headers)

    assert response.status_code == status.HTTP_200_OK

    response = await http_client.post('/kerberos/setup/tree', json={
        "mail": '777@example.com',
        "krbadmin_password": 'Password123',
    }, headers=login_headers)

    assert response.status_code == status.HTTP_409_CONFLICT


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_setup_call(
    http_client: AsyncClient,
    login_headers: dict,
    ldap_session: LDAPSession,
) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param dict login_headers: headers
    :param LDAPSession ldap_session: ldap
    """
    response = await http_client.post('/kerberos/setup', json={
        "krbadmin_password": 'Password123',
        "admin_password": 'Password123',
        "stash_password": 'Password123',
    }, headers=login_headers)

    assert response.status_code == 200

    krb_doc = ldap_session.kadmin.kwargs.pop('krb5_config').encode()
    kdc_doc = ldap_session.kadmin.kwargs.pop('kdc_config').encode()

    # NOTE: Asserting documents integrity, tests template rendering
    assert blake2b(krb_doc, digest_size=8).hexdigest() == '6d7f2acd6790183a'
    assert blake2b(kdc_doc, digest_size=8).hexdigest() == '54574991e75bba8c'

    assert ldap_session.kadmin.kwargs == {
        'domain': 'md.test',
        'admin_dn': 'cn=user0,ou=users,dc=md,dc=test',
        'services_dn': 'ou=services,dc=md,dc=test',
        'krbadmin_dn': 'cn=krbadmin,ou=users,dc=md,dc=test',
        'krbadmin_password': 'Password123',
        'admin_password': 'Password123',
        'stash_password': 'Password123',
    }


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_status_change(
    http_client: AsyncClient,
    login_headers: dict,
) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param dict login_headers: headers
    :param LDAPSession ldap_session: ldap
    """
    response = await http_client.get(
        '/kerberos/status', headers=login_headers)
    assert response.status_code == 200
    assert response.json() == KerberosState.NOT_CONFIGURED

    await http_client.post('/kerberos/setup', json={
        "krbadmin_password": 'Password123',
        "admin_password": 'Password123',
        "stash_password": 'Password123',
    }, headers=login_headers)

    response = await http_client.get(
        '/kerberos/status', headers=login_headers)
    assert response.json() == KerberosState.WAITING_FOR_RELOAD


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ktadd(
    http_client: AsyncClient,
    login_headers: dict,
    kadmin: TestKadminClient,
) -> None:
    """Test ktadd.

    :param AsyncClient http_client: http cl
    :param dict login_headers: headers
    :param LDAPSession ldap_session: ldap
    """
    names = ['test1', 'test2']
    response = await http_client.post(
        '/kerberos/ktadd', headers=login_headers, json=names)

    assert kadmin.args[0] == names
    assert response.status_code == status.HTTP_200_OK
    assert response.content == TestKadminClient.KTADD_CONTENT
    assert response.headers == {
        'Content-Disposition': 'attachment; filename="md.keytab"',
        'content-type': 'application/txt',
    }


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ktadd_404(
    http_client: AsyncClient,
    login_headers: dict,
    kadmin: TestKadminClient,
) -> None:
    """Test ktadd failure.

    :param AsyncClient http_client: http cl
    :param dict login_headers: headers
    :param LDAPSession ldap_session: ldap
    """
    async def ktadd(names: list[str]) -> TestKadminClient.MuteOkResponse:
        raise KRBAPIError()

    kadmin.ktadd = ktadd  # type: ignore

    names = ['test1', 'test2']
    response = await http_client.post(
        '/kerberos/ktadd', headers=login_headers, json=names)

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap_add(
    http_client: AsyncClient,
    login_headers: dict,
    kadmin: TestKadminClient,
) -> None:
    """Test add calls add_principal on user creation.

    :param AsyncClient http_client: http
    :param dict login_headers: headers
    :param TestKadminClient kadmin: kadmin
    """
    san = 'ktest'
    pw = 'Password123'

    response = await http_client.post(
        "/entry/add",
        headers=login_headers,
        json=_create_test_user_data(san, pw))

    assert response.status_code == 200, response.json()
    assert kadmin.args == (san, pw)


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap_kadmin_delete(
    http_client: AsyncClient,
    login_headers: dict,
    kadmin: TestKadminClient,
) -> None:
    """Test API for delete object."""
    await http_client.post(
        "/entry/add",
        headers=login_headers,
        json=_create_test_user_data('ktest', 'Password123'))

    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={"entry": "cn=ktest,dc=md,dc=test"},
        headers=login_headers,
    )

    data = response.json()

    assert data.get('resultCode') == LDAPCodes.SUCCESS

    assert kadmin.args == ("ktest",)


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_bind_create_user(
    http_client: AsyncClient,
    login_headers: dict,
    kadmin: TestKadminClient,
    settings: Settings,
) -> None:
    """Test bind create user."""
    san = 'ktest'
    pw = 'Password123'

    await http_client.post(
        "/entry/add",
        headers=login_headers,
        json=_create_test_user_data(san, pw))

    proc = await asyncio.create_subprocess_exec(
        'ldapwhoami', '-x',
        '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', san,
        '-w', pw,
    )

    assert await proc.wait() == 0
    assert kadmin.args == (san, pw)


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('_force_override_tls')
async def test_extended_pw_change_call(
    event_loop: asyncio.BaseEventLoop,
    ldap_client: Connection,
    creds: TestCreds,
    kadmin: TestKadminClient,
    ldap_session: LDAPSession,
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
    assert ldap_session.kadmin.args == ('user0', new_test_password)
