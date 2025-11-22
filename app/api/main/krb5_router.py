"""KRB5 router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from annotated_types import Len
from dishka import FromDishka
from fastapi import Body, Request, Response
from fastapi.params import Depends
from fastapi.responses import StreamingResponse
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule
from pydantic import SecretStr

from api.auth import verify_auth
from api.auth.adapters.identity import IdentityFastAPIAdapter
from api.main.adapters.kerberos import KerberosFastAPIAdapter
from api.main.schema import KerberosSetupRequest
from enums import ProjectPartCodes
from errors import (
    ERROR_MAP_TYPE,
    BaseErrorTranslator,
    DishkaErrorAwareRoute,
    ErrorStatusCodes,
)
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import KerberosState
from ldap_protocol.kerberos.exceptions import (
    KerberosBaseDnNotFoundError,
    KerberosConflictError,
    KerberosDependencyError,
    KerberosNotFoundError,
    KerberosUnavailableError,
)
from ldap_protocol.ldap_requests.contexts import LDAPAddRequestContext
from ldap_protocol.utils.const import EmailStr

from .utils import get_ldap_session


class KRB5ErrorTranslator(BaseErrorTranslator):
    """KRB5 error translator."""

    domain_code = ProjectPartCodes.KERBEROS


error_map: ERROR_MAP_TYPE = {
    KerberosBaseDnNotFoundError: rule(
        status=ErrorStatusCodes.INTERNAL_SERVER_ERROR,
        translator=KRB5ErrorTranslator(),
    ),
    KerberosConflictError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=KRB5ErrorTranslator(),
    ),
    KerberosDependencyError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=KRB5ErrorTranslator(),
    ),
    KerberosNotFoundError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=KRB5ErrorTranslator(),
    ),
    KerberosUnavailableError: rule(
        status=ErrorStatusCodes.INTERNAL_SERVER_ERROR,
        translator=KRB5ErrorTranslator(),
    ),
}

krb5_router = ErrorAwareRouter(
    prefix="/kerberos",
    tags=["KRB5 API"],
    route_class=DishkaErrorAwareRoute,
)
KERBEROS_POLICY_NAME = "Kerberos Access Policy"


@krb5_router.post(
    "/setup/tree",
    response_class=Response,
    error_map=error_map,
    dependencies=[Depends(verify_auth)],
)
async def setup_krb_catalogue(
    mail: Annotated[EmailStr, Body()],
    krbadmin_password: Annotated[SecretStr, Body()],
    ldap_session: Annotated[LDAPSession, Depends(get_ldap_session)],
    ctx: FromDishka[LDAPAddRequestContext],
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
        ctx,
    )


@krb5_router.post("/setup", response_class=Response, error_map=error_map)
async def setup_kdc(
    data: KerberosSetupRequest,
    identity_adapter: FromDishka[IdentityFastAPIAdapter],
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
    user = await identity_adapter.get_current_user()
    return await kerberos_adapter.setup_kdc(data, user, request)


LIMITED_STR = Annotated[str, Len(min_length=1, max_length=8100)]
LIMITED_LIST = Annotated[
    list[LIMITED_STR],
    Len(min_length=1, max_length=10000),
]


@krb5_router.post(
    "/ktadd", dependencies=[Depends(verify_auth)], error_map=error_map
)
async def ktadd(
    names: Annotated[LIMITED_LIST, Body()],
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> StreamingResponse:
    """Create keytab from kadmin server.

    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return bytes: file
    """
    return await kerberos_adapter.ktadd(names)


@krb5_router.get(
    "/status", dependencies=[Depends(verify_auth)], error_map=error_map
)
async def get_krb_status(
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter],
) -> KerberosState:
    """Get server status.

    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return KerberosState: state
    """
    return await kerberos_adapter.get_status()


@krb5_router.post(
    "/principal/add", dependencies=[Depends(verify_auth)], error_map=error_map
)
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
    dependencies=[Depends(verify_auth)],
    error_map=error_map,
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
    dependencies=[Depends(verify_auth)],
    error_map=error_map,
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
    dependencies=[Depends(verify_auth)],
    error_map=error_map,
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
