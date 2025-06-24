"""KRB5 router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from annotated_types import Len
from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import Body, HTTPException, Request, Response, status
from fastapi.params import Depends
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRouter
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from api.auth import get_current_user
from api.utils import KerberosService
from api.utils.exceptions import KerberosError
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.kerberos import (
    AbstractKadmin,
    KerberosState,
    KRBAPIError,
    get_krb_server_state,
)
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.utils.const import EmailStr

from .schema import KerberosSetupRequest
from .utils import get_ldap_session

krb5_router = APIRouter(
    prefix="/kerberos",
    tags=["KRB5 API"],
    route_class=DishkaRoute,
)
KERBEROS_POLICY_NAME = "Kerberos Access Policy"


@krb5_router.post(
    "/setup/tree",
    response_class=Response,
    dependencies=[Depends(get_current_user)],
)
async def setup_krb_catalogue(
    session: FromDishka[AsyncSession],
    mail: Annotated[EmailStr, Body()],
    krbadmin_password: Annotated[SecretStr, Body()],
    ldap_session: Annotated[LDAPSession, Depends(get_ldap_session)],
    entity_type_dao: FromDishka[EntityTypeDAO],
    kerberos_service: FromDishka[KerberosService],
) -> None:
    """Generate tree for kdc/kadmin.

    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[EmailStr, Body mail: krbadmin email
    :param Annotated[SecretStr, Body krbadmin_password: pw
    :raises HTTPException: on conflict
    """
    try:
        await kerberos_service.setup_krb_catalogue(
            mail, krbadmin_password, ldap_session, entity_type_dao
        )
    except KerberosError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))


@krb5_router.post("/setup", response_class=Response)
async def setup_kdc(
    data: KerberosSetupRequest,
    user: Annotated[UserSchema, Depends(get_current_user)],
    request: Request,
    kerberos_service: FromDishka[KerberosService],
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
    try:
        await kerberos_service.setup_kdc(data, user)
    except KerberosError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


LIMITED_STR = Annotated[str, Len(min_length=1, max_length=8100)]
LIMITED_LIST = Annotated[
    list[LIMITED_STR],
    Len(min_length=1, max_length=10000),
]


@krb5_router.post("/ktadd", dependencies=[Depends(get_current_user)])
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
        headers={"Content-Disposition": 'attachment; filename="krb5.keytab"'},
        background=BackgroundTask(response.aclose),
    )


@krb5_router.get("/status", dependencies=[Depends(get_current_user)])
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
async def add_principal(
    primary: Annotated[LIMITED_STR, Body()],
    instance: Annotated[LIMITED_STR, Body()],
    kerberos_service: FromDishka[KerberosService],
) -> None:
    """Create principal in kerberos with given name.

    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request.
    """
    try:
        await kerberos_service.add_principal(primary, instance)
    except KerberosError as exc:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, detail=str(exc))


@krb5_router.patch(
    "/principal/rename",
    dependencies=[Depends(get_current_user)],
)
async def rename_principal(
    principal_name: Annotated[LIMITED_STR, Body()],
    principal_new_name: Annotated[LIMITED_STR, Body()],
    kerberos_service: FromDishka[KerberosService],
) -> None:
    """Rename principal in kerberos with given name.

    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LIMITED_STR, Body principal_new_name: _description_
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request.
    """
    try:
        await kerberos_service.rename_principal(
            principal_name, principal_new_name
        )
    except KerberosError as exc:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, detail=str(exc))


@krb5_router.patch(
    "/principal/reset",
    dependencies=[Depends(get_current_user)],
)
async def reset_principal_pw(
    principal_name: Annotated[LIMITED_STR, Body()],
    new_password: Annotated[LIMITED_STR, Body()],
    kerberos_service: FromDishka[KerberosService],
) -> None:
    """Reset principal password in kerberos with given name.

    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LIMITED_STR, Body new_password: _description_
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request.
    """
    try:
        await kerberos_service.reset_principal_pw(principal_name, new_password)
    except KerberosError as exc:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, detail=str(exc))


@krb5_router.delete(
    "/principal/delete",
    dependencies=[Depends(get_current_user)],
)
async def delete_principal(
    principal_name: Annotated[LIMITED_STR, Body(embed=True)],
    kerberos_service: FromDishka[KerberosService],
) -> None:
    """Delete principal in kerberos with given name.

    \f
    :param Annotated[str, Body principal_name: upn
    :param FromDishka[AbstractKadmin] kadmin: _description_
    :raises HTTPException: on failed kamin request
    """
    try:
        await kerberos_service.delete_principal(principal_name)
    except KerberosError as exc:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, detail=str(exc))
