"""KRB5 router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from annotated_types import Len
from dishka import FromDishka
from fastapi import Body, Request, Response, status
from fastapi.params import Depends
from fastapi.responses import StreamingResponse
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule
from pydantic import SecretStr

from api.auth.adapters.auth import AuthFastAPIAdapter
from api.auth.utils import verify_auth
from api.error_routing import ERROR_MAP_TYPE, DishkaErrorAwareRoute, DomainErrorTranslator
from api.main.adapters.kerberos import KerberosFastAPIAdapter
from api.main.schema import KerberosSetupRequest, KtaddRequest, ModifyPrincipalRequest, PrincipalAddRequest
from api.utils import require_master_db
from enums import DomainCodes
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import KerberosState
from ldap_protocol.kerberos.exceptions import (
    KerberosBaseDnNotFoundError,
    KerberosConflictError,
    KerberosDependencyError,
    KerberosNotFoundError,
    KerberosUnavailableError,
    KRBAPIConnectionError,
)
from ldap_protocol.ldap_requests.contexts import LDAPAddRequestContext
from ldap_protocol.utils.const import EmailStr

from .utils import get_ldap_session

translator = DomainErrorTranslator(DomainCodes.KERBEROS)


error_map: ERROR_MAP_TYPE = {
    KerberosBaseDnNotFoundError: rule(status=status.HTTP_500_INTERNAL_SERVER_ERROR, translator=translator),
    KerberosConflictError: rule(status=status.HTTP_400_BAD_REQUEST, translator=translator),
    KerberosDependencyError: rule(status=status.HTTP_400_BAD_REQUEST, translator=translator),
    KerberosNotFoundError: rule(status=status.HTTP_400_BAD_REQUEST, translator=translator),
    KerberosUnavailableError: rule(status=status.HTTP_500_INTERNAL_SERVER_ERROR, translator=translator),
    KRBAPIConnectionError: rule(status=status.HTTP_500_INTERNAL_SERVER_ERROR, translator=translator),
}

krb5_router = ErrorAwareRouter(prefix="/kerberos", tags=["KRB5 API"], route_class=DishkaErrorAwareRoute)
KERBEROS_POLICY_NAME = "Kerberos Access Policy"


@krb5_router.post(
    "/setup/tree",
    response_class=Response,
    error_map=error_map,
    dependencies=[Depends(verify_auth), Depends(require_master_db)],
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
    await kerberos_adapter.setup_krb_catalogue(mail, krbadmin_password, ldap_session, ctx)


@krb5_router.post("/setup", response_class=Response, error_map=error_map, dependencies=[Depends(require_master_db)])
async def setup_kdc(
    data: KerberosSetupRequest,
    identity_adapter: FromDishka[AuthFastAPIAdapter],
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
LIMITED_LIST = Annotated[list[LIMITED_STR], Len(min_length=1, max_length=10000)]


@krb5_router.post("/ktadd", dependencies=[Depends(verify_auth)], error_map=error_map)
async def ktadd(
    kerberos_adapter: FromDishka[KerberosFastAPIAdapter], names: Annotated[LIMITED_LIST, Body()]
) -> StreamingResponse:
    """Create keytab from kadmin server.

    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return bytes: file
    """
    request = KtaddRequest(names=names)
    return await kerberos_adapter.ktadd(request)


@krb5_router.get("/status", dependencies=[Depends(verify_auth)], error_map=error_map)
async def get_krb_status(kerberos_adapter: FromDishka[KerberosFastAPIAdapter]) -> KerberosState:
    """Get server status.

    :param Annotated[AsyncSession, Depends session: db
    :param Annotated[LDAPSession, Depends ldap_session: ldap
    :return KerberosState: state
    """
    return await kerberos_adapter.get_status()


@krb5_router.post(
    "/principal/add", dependencies=[Depends(verify_auth), Depends(require_master_db)], error_map=error_map
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
    request = PrincipalAddRequest(principal_name=f"{primary}/{instance}")
    await kerberos_adapter.add_principal(request)


@krb5_router.put("/principal", dependencies=[Depends(verify_auth), Depends(require_master_db)], error_map=error_map)
async def modify_principal(
    request: ModifyPrincipalRequest, kerberos_adapter: FromDishka[KerberosFastAPIAdapter]
) -> None:
    await kerberos_adapter.modify_principal(request)


@krb5_router.delete(
    "/principal/delete", dependencies=[Depends(verify_auth), Depends(require_master_db)], error_map=error_map
)
async def delete_principal(
    principal_name: Annotated[LIMITED_STR, Body(embed=True)], kerberos_adapter: FromDishka[KerberosFastAPIAdapter]
) -> None:
    """Delete principal in kerberos with given name.

    \f
    :param Annotated[str, Body principal_name: upn
    :param FromDishka[AbstractKadmin] kadmin: _description_
    :raises HTTPException: on failed kamin request
    """
    await kerberos_adapter.delete_principal(principal_name)
