"""KRB5 router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

import jinja2
from annotated_types import Len
from fastapi import Body, HTTPException, Response, status
from fastapi.params import Depends
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRouter
from pydantic import EmailStr, SecretStr
from starlette.background import BackgroundTask

from api.auth import User, get_current_user
from config import Settings, get_settings
from ldap_protocol.dialogue import Session as LDAPSession
from ldap_protocol.kerberos import (
    KerberosState,
    KRBAPIError,
    get_krb_server_state,
    set_state,
)
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.utils import get_base_dn, get_dn_by_id
from models.database import AsyncSession, get_session

from .schema import KerberosSetupRequest
from .utils import get_ldap_session

krb5_router = APIRouter(prefix='/kerberos', tags=['KRB5 API'])

TEMPLATES = jinja2.Environment(
    loader=jinja2.FileSystemLoader('extra'),
    enable_async=True, autoescape=True)


@krb5_router.post(
    '/setup/tree',
    response_class=Response,
    dependencies=[Depends(get_current_user)])
async def setup_krb_catalogue(
    session: Annotated[AsyncSession, Depends(get_session)],
    mail: Annotated[EmailStr, Body()],
    krbadmin_password: Annotated[SecretStr, Body()],
    ldap_session: Annotated[LDAPSession, Depends(get_ldap_session)],
) -> None:
    """Generate tree for kdc/kadmin.

    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[EmailStr, Body mail: krbadmin email
    :param Annotated[SecretStr, Body krbadmin_password: pw
    :raises HTTPException: on conflict
    """
    base_dn = await get_base_dn(session)

    krbadmin = 'cn=krbadmin,ou=users,' + base_dn
    services_container = 'ou=services,' + base_dn
    krbgroup = 'cn=krbadmin,cn=groups,' + base_dn

    group = AddRequest.from_dict(krbgroup, {
        "objectClass": ["group", "top", 'posixGroup'],
        'groupType': ['-2147483646'],
        'instanceType': ['4'],
        'description': ["Kerberos administrator's group."],
        'gidNumber': ["800"],
    })

    services = AddRequest.from_dict(
        services_container,
        {"objectClass": ["organizationalUnit", "top", "container"]},
    )

    rkb_user = AddRequest.from_dict(
        krbadmin, password=krbadmin_password.get_secret_value(),
        attributes={
            "mail": [mail],
            "objectClass": [
                "user", "top", "person",
                "organizationalPerson",
                "posixAccount",
                "shadowAccount",
                "inetOrgPerson",
            ],
            "loginShell": ["/bin/false"],
            "uidNumber": ["800"],
            "gidNumber": ["800"],
            "givenName": ["Kerberos Administrator"],
            "sn": ["krbadmin"],
            "uid": ["krbadmin"],
            "homeDirectory": ["/home/krbadmin"],
            "memberOf": [krbgroup],
            "sAMAccountName": ['krbadmin'],
            "userPrincipalName": ['krbadmin'],
            "displayName": ["Kerberos Administrator"],
        },
    )

    async with session.begin_nested():
        results = (
            await anext(services.handle(ldap_session, session)),
            await anext(group.handle(ldap_session, session)),
            await anext(rkb_user.handle(ldap_session, session)),
        )
        await session.flush()
        if not all(result.result_code == 0 for result in results):
            await session.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT)
        await session.commit()


@krb5_router.post('/setup', response_class=Response)
async def setup_kdc(
    data: KerberosSetupRequest,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    ldap_session: Annotated[LDAPSession, Depends(get_ldap_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """Set up KDC server.

    Create data structure in catalogue, generate config files, trigger commands

    - **mail**: krbadmin mail
    - **password**: krbadmin password

    \f
    :param Annotated[EmailStr, Body mail: json, defaults to 'admin')]
    :param Annotated[str, Body password: json, defaults to 'password')]
    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[LDAPSession, Depends ldap_session: ldap session
    """  # noqa: D301
    base_dn = await get_base_dn(session)
    domain = await get_base_dn(session, normal=True)

    krbadmin = 'cn=krbadmin,ou=users,' + base_dn
    services_container = 'ou=services,' + base_dn

    krb5_template = TEMPLATES.get_template('krb5.conf')
    kdc_template = TEMPLATES.get_template('kdc.conf')

    kdc_config = await kdc_template.render_async(domain=domain)

    krb5_config = await krb5_template.render_async(
        domain=domain,
        krbadmin=krbadmin,
        services_container=services_container,
        ldap_uri=settings.KRB5_LDAP_URI,
    )

    try:
        await ldap_session.kadmin.setup(
            domain=domain,
            admin_dn=await get_dn_by_id(user.directory_id, session),
            services_dn=services_container,
            krbadmin_dn=krbadmin,
            krbadmin_password=data.krbadmin_password.get_secret_value(),
            admin_password=data.admin_password.get_secret_value(),
            stash_password=data.stash_password.get_secret_value(),
            krb5_config=krb5_config,
            kdc_config=kdc_config,
        )
    except KRBAPIError as err:
        raise HTTPException(status.HTTP_304_NOT_MODIFIED, err)

    await set_state(session, KerberosState.READY)
    await session.commit()


LIMITED_STR = Annotated[str, Len(min_length=1, max_length=8100)]
LIMITED_LIST = Annotated[
    list[LIMITED_STR], Len(min_length=1, max_length=10000)]


@krb5_router.post(
    '/ktadd',
    dependencies=[Depends(get_current_user)])
async def ktadd(
    ldap_session: Annotated[LDAPSession, Depends(get_ldap_session)],
    names: Annotated[LIMITED_LIST, Body()],
) -> StreamingResponse:
    """Create keytab from kadmin server.

    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return bytes: file
    """
    try:
        response = await ldap_session.kadmin.ktadd(names)
    except KRBAPIError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Principal not found")

    return StreamingResponse(
        response.aiter_bytes(),
        media_type="application/txt",
        headers={'Content-Disposition': 'attachment; filename="md.keytab"'},
        background=BackgroundTask(response.aclose),
    )


@krb5_router.get('/status', dependencies=[Depends(get_current_user)])
async def get_krb_status(
    session: Annotated[AsyncSession, Depends(get_session)],
    ldap_session: Annotated[LDAPSession, Depends(get_ldap_session)],
) -> KerberosState:
    """Get server status.

    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return KerberosState: state
    """
    db_state = await get_krb_server_state(session)
    try:
        server_state = await ldap_session.kadmin.get_status()
    except KRBAPIError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)

    if server_state is False and db_state == KerberosState.READY:
        return KerberosState.WAITING_FOR_RELOAD

    return db_state


@krb5_router.post('/add', dependencies=[Depends(get_current_user)])
async def add_principal(
    principal_name: Annotated[LIMITED_STR, Body()],
    ldap_session: Annotated[LDAPSession, Depends(get_ldap_session)],
) -> None:
    """Create principal in kerberos with given name.
    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request
    """  # noqa: D301
    try:
        await ldap_session.kadmin.add_principal(principal_name, None)
    except KRBAPIError as err:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, detail=str(err))
