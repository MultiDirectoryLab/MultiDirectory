"""KRB5 router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from annotated_types import Len
from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Body, HTTPException, Response, status
from fastapi.params import Depends
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRouter
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from api.auth import get_current_user
from api.auth.oauth2 import authenticate_user
from config import Settings
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.kerberos import (
    AbstractKadmin,
    KerberosState,
    KRBAPIError,
    get_krb_server_state,
    set_state,
)
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.policies.access_policy import create_access_policy
from ldap_protocol.utils.const import EmailStr
from ldap_protocol.utils.queries import get_base_directories, get_dn_by_id

from .schema import KerberosSetupRequest
from .utils import get_ldap_session

krb5_router = APIRouter(prefix="/kerberos", tags=["KRB5 API"])


@krb5_router.post(
    "/setup/tree",
    response_class=Response,
    dependencies=[Depends(get_current_user)],
)
@inject
async def setup_krb_catalogue(
    session: FromDishka[AsyncSession],
    mail: Annotated[EmailStr, Body()],
    krbadmin_password: Annotated[SecretStr, Body()],
    ldap_session: Annotated[LDAPSession, Depends(get_ldap_session)],
    kadmin: FromDishka[AbstractKadmin],
) -> None:
    """Generate tree for kdc/kadmin.

    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[EmailStr, Body mail: krbadmin email
    :param Annotated[SecretStr, Body krbadmin_password: pw
    :raises HTTPException: on conflict
    """
    base_dn_list = await get_base_directories(session)
    base_dn = base_dn_list[0].path_dn

    krbadmin = "cn=krbadmin,ou=users," + base_dn
    services_container = "ou=services," + base_dn
    krbgroup = "cn=krbadmin,cn=groups," + base_dn

    group = AddRequest.from_dict(
        krbgroup,
        {
            "objectClass": ["group", "top", "posixGroup"],
            "groupType": ["-2147483646"],
            "instanceType": ["4"],
            "description": ["Kerberos administrator's group."],
            "gidNumber": ["800"],
        },
    )

    services = AddRequest.from_dict(
        services_container,
        {"objectClass": ["organizationalUnit", "top", "container"]},
    )

    rkb_user = AddRequest.from_dict(
        krbadmin,
        password=krbadmin_password.get_secret_value(),
        attributes={
            "mail": [mail],
            "objectClass": [
                "user",
                "top",
                "person",
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
            "sAMAccountName": ["krbadmin"],
            "userPrincipalName": ["krbadmin"],
            "displayName": ["Kerberos Administrator"],
        },
    )

    async with session.begin_nested():
        results = (
            await anext(services.handle(session, ldap_session, kadmin)),
            await anext(group.handle(session, ldap_session, kadmin)),
            await anext(rkb_user.handle(session, ldap_session, kadmin)),
        )
        await session.flush()
        if not all(result.result_code == 0 for result in results):
            await session.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT)

        await create_access_policy(
            name="Kerberos Access Policy",
            can_add=True,
            can_modify=True,
            can_read=True,
            can_delete=True,
            grant_dn=services_container,
            groups=[krbgroup],
            session=session,
        )
        await session.commit()


@krb5_router.post("/setup", response_class=Response)
@inject
async def setup_kdc(
    data: KerberosSetupRequest,
    user: Annotated[UserSchema, Depends(get_current_user)],
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
    kadmin: FromDishka[AbstractKadmin],
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
    """
    if not await authenticate_user(
        session,
        user.user_principal_name,
        data.admin_password.get_secret_value(),
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    base_dn_list = await get_base_directories(session)
    base_dn = base_dn_list[0].path_dn
    domain: str = base_dn_list[0].name

    krbadmin = "cn=krbadmin,ou=users," + base_dn
    services_container = "ou=services," + base_dn

    krb5_template = settings.TEMPLATES.get_template("krb5.conf")
    kdc_template = settings.TEMPLATES.get_template("kdc.conf")

    kdc_config = await kdc_template.render_async(domain=domain)

    krb5_config = await krb5_template.render_async(
        domain=domain,
        krbadmin=krbadmin,
        services_container=services_container,
        ldap_uri=settings.KRB5_LDAP_URI,
    )

    try:
        await kadmin.setup(
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
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(err))

    await set_state(session, KerberosState.READY)
    await session.commit()


LIMITED_STR = Annotated[str, Len(min_length=1, max_length=8100)]
LIMITED_LIST = Annotated[
    list[LIMITED_STR],
    Len(min_length=1, max_length=10000),
]


@krb5_router.post("/ktadd", dependencies=[Depends(get_current_user)])
@inject
async def ktadd(
    kadmin: FromDishka[AbstractKadmin],
    names: Annotated[LIMITED_LIST, Body()],
) -> StreamingResponse:
    """Create keytab from kadmin server.

    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return bytes: file
    """
    try:
        response = await kadmin.ktadd(names)
    except KRBAPIError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Principal not found")

    return StreamingResponse(
        response.aiter_bytes(),
        media_type="application/txt",
        headers={"Content-Disposition": 'attachment; filename="md.keytab"'},
        background=BackgroundTask(response.aclose),
    )


@krb5_router.get("/status", dependencies=[Depends(get_current_user)])
@inject
async def get_krb_status(
    session: FromDishka[AsyncSession],
    kadmin: FromDishka[AbstractKadmin],
) -> KerberosState:
    """Get server status.

    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return KerberosState: state
    """
    db_state = await get_krb_server_state(session)
    try:
        server_state = await kadmin.get_status()
    except KRBAPIError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)

    if server_state is False and db_state == KerberosState.READY:
        return KerberosState.WAITING_FOR_RELOAD

    return db_state


@krb5_router.post("/principal/add", dependencies=[Depends(get_current_user)])
@inject
async def add_principal(
    primary: Annotated[LIMITED_STR, Body()],
    instance: Annotated[LIMITED_STR, Body()],
    kadmin: FromDishka[AbstractKadmin],
) -> None:
    """Create principal in kerberos with given name.
    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request
    """
    try:
        await kadmin.add_principal(f"{primary}/{instance}", None)
    except KRBAPIError as err:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, str(err))


@krb5_router.patch(
    "/principal/rename", dependencies=[Depends(get_current_user)],
)
@inject
async def rename_principal(
    principal_name: Annotated[LIMITED_STR, Body()],
    principal_new_name: Annotated[LIMITED_STR, Body()],
    kadmin: FromDishka[AbstractKadmin],
) -> None:
    """Rename principal in kerberos with given name.
    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LIMITED_STR, Body principal_new_name: _description_
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request
    """
    try:
        await kadmin.rename_princ(principal_name, principal_new_name)
    except KRBAPIError as err:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, str(err))


@krb5_router.patch(
    "/principal/reset",
    dependencies=[Depends(get_current_user)],
)
@inject
async def reset_principal_pw(
    principal_name: Annotated[LIMITED_STR, Body()],
    new_password: Annotated[LIMITED_STR, Body()],
    kadmin: FromDishka[AbstractKadmin],
) -> None:
    """Reset principal password in kerberos with given name.
    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LIMITED_STR, Body new_password: _description_
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request
    """
    try:
        await kadmin.change_principal_password(principal_name, new_password)
    except KRBAPIError as err:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, str(err))


@krb5_router.delete(
    "/principal/delete", dependencies=[Depends(get_current_user)],
)
@inject
async def delete_principal(
    principal_name: Annotated[LIMITED_STR, Body(embed=True)],
    kadmin: FromDishka[AbstractKadmin],
) -> None:
    """Delete principal in kerberos with given name.
    \f
    :param Annotated[str, Body principal_name: upn
    :param FromDishka[AbstractKadmin] kadmin: _description_
    :raises HTTPException: on failed kamin request
    """
    try:
        await kadmin.del_principal(principal_name)
    except KRBAPIError as err:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, str(err))
