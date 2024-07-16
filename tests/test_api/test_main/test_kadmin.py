"""Test kadmin."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.dialogue import Session
from ldap_protocol.ldap_requests.bind import LDAPCodes, SimpleAuthentication
from tests.conftest import MutePolicyBindRequest
from hashlib import blake2b


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_tree_creation(
    http_client: AsyncClient,
    login_headers: dict,
    ldap_session: Session,
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
async def test_setup_call(
    http_client: AsyncClient,
    login_headers: dict,
    ldap_session: Session,
) -> None:
    """Test setup args.

    :param AsyncClient http_client: http cl
    :param dict login_headers: headers
    :param Session ldap_session: ldap
    """
    response = await http_client.post('/kerberos/setup', json={
        "krbadmin_password": 'Password123',
        "admin_password": 'Password123',
        "stash_password": 'Password123',
    }, headers=login_headers)

    assert response.status_code == 200

    krb_doc = ldap_session.kadmin.kwargs.pop('krb5_config').encode()
    kdc_doc = ldap_session.kadmin.kwargs.pop('kdc_config').encode()

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
