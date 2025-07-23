"""KRB5 router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from annotated_types import Len
from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import Body, Request, Response
from fastapi.params import Depends
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRouter
from pydantic import SecretStr

from api.auth import get_current_user
from api.main.adapters.kerberos import KerberosFastAPIAdapter
from api.main.schema import KerberosSetupRequest
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.kerberos import KerberosState
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.roles.access_manager import AccessManager
from ldap_protocol.utils.const import EmailStr

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
    mail: Annotated[EmailStr, Body()],
    krbadmin_password: Annotated[SecretStr, Body()],
    ldap_session: Annotated[LDAPSession, Depends(get_ldap_session)],
    entity_type_dao: FromDishka[EntityTypeDAO],
    access_manager: FromDishka[AccessManager],
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> None:
    """Generate tree for kdc/kadmin.

    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[EmailStr, Body mail: krbadmin email
    :param Annotated[SecretStr, Body krbadmin_password: pw
    :raises HTTPException: on conflict
    """
    await kerberos_adapter.setup_krb_catalogue(
        mail,
        krbadmin_password,
        ldap_session,
        entity_type_dao,
        access_manager,
    )


@krb5_router.post("/setup", response_class=Response)
async def setup_kdc(
    data: KerberosSetupRequest,
    user: Annotated[UserSchema, Depends(get_current_user)],
    request: Request,
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> Response:
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
    return await kerberos_adapter.setup_kdc(data, user, request)


LIMITED_STR = Annotated[str, Len(min_length=1, max_length=8100)]
LIMITED_LIST = Annotated[
    list[LIMITED_STR],
    Len(min_length=1, max_length=10000),
]


@krb5_router.post("/ktadd", dependencies=[Depends(get_current_user)])
async def ktadd(
    names: Annotated[LIMITED_LIST, Body()],
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> StreamingResponse:
    """Create keytab from kadmin server.

    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return bytes: file
    """
    return await kerberos_adapter.ktadd(names)


@krb5_router.get("/status", dependencies=[Depends(get_current_user)])
async def get_krb_status(
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> KerberosState:
    """Get server status.

    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return KerberosState: state
    """
    return await kerberos_adapter.get_status()


@krb5_router.post("/principal/add", dependencies=[Depends(get_current_user)])
async def add_principal(
    primary: Annotated[LIMITED_STR, Body()],
    instance: Annotated[LIMITED_STR, Body()],
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> None:
    """Create principal in kerberos with given name.

    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request.
    """
    await kerberos_adapter.add_principal(primary, instance)


@krb5_router.patch(
    "/principal/rename",
    dependencies=[Depends(get_current_user)],
)
async def rename_principal(
    principal_name: Annotated[LIMITED_STR, Body()],
    principal_new_name: Annotated[LIMITED_STR, Body()],
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> None:
    """Rename principal in kerberos with given name.

    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LIMITED_STR, Body principal_new_name: _description_
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request.
    """
    await kerberos_adapter.rename_principal(
        principal_name,
        principal_new_name,
    )


@krb5_router.patch(
    "/principal/reset",
    dependencies=[Depends(get_current_user)],
)
async def reset_principal_pw(
    principal_name: Annotated[LIMITED_STR, Body()],
    new_password: Annotated[LIMITED_STR, Body()],
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> None:
    """Reset principal password in kerberos with given name.

    \f
    :param Annotated[str, Body principal_name: upn
    :param Annotated[LIMITED_STR, Body new_password: _description_
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :raises HTTPException: on failed kamin request.
    """
    await kerberos_adapter.reset_principal_pw(principal_name, new_password)


@krb5_router.delete(
    "/principal/delete",
    dependencies=[Depends(get_current_user)],
)
async def delete_principal(
    principal_name: Annotated[LIMITED_STR, Body(embed=True)],
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> None:
    """Delete principal in kerberos with given name.

    \f
    :param Annotated[str, Body principal_name: upn
    :param FromDishka[AbstractKadmin] kadmin: _description_
    :raises HTTPException: on failed kamin request
    """
    await kerberos_adapter.delete_principal(principal_name)
