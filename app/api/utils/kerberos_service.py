"""KerberosService: Class for encapsulating Kerberos business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import SecretStr
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.oauth2 import authenticate_user
from api.main.schema import KerberosSetupRequest
from api.utils.exceptions import KerberosError
from config import Settings
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.kerberos import (
    AbstractKadmin,
    KerberosState,
    KRBAPIError,
    set_state,
)
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.policies.access_policy import create_access_policy
from ldap_protocol.utils.queries import (
    get_base_directories,
    get_dn_by_id,
    get_filter_from_path,
)
from models import AccessPolicy, Directory


class KerberosService:
    """Service Kerberos for working with AbstractKadmin."""

    def __init__(
        self, session: AsyncSession, settings: Settings, kadmin: AbstractKadmin
    ) -> None:
        """Initialize dependencies of the service (via DI).

        :param session: SQLAlchemy AsyncSession
        :param settings: Settings
        :param kadmin: AbstractKadmin
        """
        self.session = session
        self.settings = settings
        self.kadmin = kadmin

    async def setup_krb_catalogue(
        self,
        mail: str,
        krbadmin_password: SecretStr,
        ldap_session: LDAPSession,
        entity_type_dao: EntityTypeDAO,
    ) -> None:
        """Generate tree for kdc/kadmin.

        :param mail: EmailStr
        :param krbadmin_password: SecretStr
        :param ldap_session: LDAPSession
        :param entity_type_dao: EntityTypeDAO
        :raises KerberosService.SetupError: if an error occurs
        """
        try:
            base_dn_list = await get_base_directories(self.session)
            base_dn = base_dn_list[0].path_dn

            krbadmin = f"cn=krbadmin,ou=users,{base_dn}"
            services_container = f"ou=services,{base_dn}"
            krbgroup = f"cn=krbadmin,cn=groups,{base_dn}"

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

            async with self.session.begin_nested():
                results = (
                    await anext(
                        services.handle(
                            self.session,
                            ldap_session,
                            self.kadmin,
                            entity_type_dao,
                        )
                    ),
                    await anext(
                        group.handle(
                            self.session,
                            ldap_session,
                            self.kadmin,
                            entity_type_dao,
                        )
                    ),
                    await anext(
                        rkb_user.handle(
                            self.session,
                            ldap_session,
                            self.kadmin,
                            entity_type_dao,
                        )
                    ),
                )
                await self.session.flush()
                if not all(result.result_code == 0 for result in results):
                    await self.session.rollback()
                    raise KerberosError(
                        "Error creating Kerberos structure in directory"
                    )

                await create_access_policy(
                    name="Kerberos Access Policy",
                    can_add=True,
                    can_modify=True,
                    can_read=True,
                    can_delete=True,
                    grant_dn=services_container,
                    groups=[krbgroup],
                    session=self.session,
                )
                await self.session.commit()
        except Exception as exc:
            raise KerberosError(f"Error generating KDC tree: {exc}") from exc

    async def setup_kdc(
        self,
        data: KerberosSetupRequest,
        user: UserSchema,
    ) -> None:
        """Create structure, generate configs, call commands.

        :param data: KerberosSetupRequest
        :param user: UserSchema
        :raises KerberosService.SetupError: if setup error occurs
        """
        try:
            base_dn_list = await get_base_directories(self.session)
            base_dn = base_dn_list[0].path_dn
            domain: str = base_dn_list[0].name

            krbadmin = f"cn=krbadmin,ou=users,{base_dn}"
            krbgroup = f"cn=krbadmin,cn=groups,{base_dn}"
            services_container = f"ou=services,{base_dn}"

            krb5_template = self.settings.TEMPLATES.get_template("krb5.conf")
            kdc_template = self.settings.TEMPLATES.get_template("kdc.conf")

            kdc_config = await kdc_template.render_async(domain=domain)

            krb5_config = await krb5_template.render_async(
                domain=domain,
                krbadmin=krbadmin,
                services_container=services_container,
                ldap_uri=self.settings.KRB5_LDAP_URI,
            )

            if not await authenticate_user(
                self.session,
                user.user_principal_name,
                data.admin_password.get_secret_value(),
            ):
                raise KRBAPIError("Incorrect password")

            await self.kadmin.setup(
                domain=domain,
                admin_dn=await get_dn_by_id(user.directory_id, self.session),
                services_dn=services_container,
                krbadmin_dn=krbadmin,
                krbadmin_password=data.krbadmin_password.get_secret_value(),
                admin_password=data.admin_password.get_secret_value(),
                stash_password=data.stash_password.get_secret_value(),
                krb5_config=krb5_config,
                kdc_config=kdc_config,
                ldap_keytab_path=self.settings.KRB5_LDAP_KEYTAB,
            )
        except KRBAPIError as err:
            direstories_query = select(Directory).where(
                or_(
                    get_filter_from_path(krbadmin),
                    get_filter_from_path(services_container),
                    get_filter_from_path(krbgroup),
                )
            )
            direstories = await self.session.scalars(direstories_query)
            if direstories:
                await self.session.execute(
                    delete(Directory).where(
                        Directory.id.in_([dir_.id for dir_ in direstories])
                    )
                )
            await self.session.execute(
                delete(AccessPolicy).where(
                    AccessPolicy.name == "Kerberos Access Policy"
                )
            )
            await self.kadmin.reset_setup()
            raise KerberosError(str(err))
        except Exception as exc:
            raise KerberosError(f"Error setting up KDC: {exc}") from exc
        else:
            await set_state(self.session, KerberosState.READY)
            await self.session.commit()

    async def add_principal(self, primary: str, instance: str) -> None:
        """Add principal to Kerberos.

        :param primary: str
        :param instance: str
        :raises KerberosService.PrincipalError: if an error occurs
        """
        try:
            principal_name = f"{primary}/{instance}"
            await self.kadmin.add_principal(principal_name, None)
        except Exception as exc:
            raise KerberosError(f"Error adding principal: {exc}") from exc

    async def rename_principal(
        self, principal_name: str, principal_new_name: str
    ) -> None:
        """Rename principal in Kerberos.

        :param principal_name: str
        :param principal_new_name: str
        :raises KerberosService.PrincipalError: if an error occurs.
        """
        try:
            await self.kadmin.rename_princ(principal_name, principal_new_name)
        except Exception as exc:
            raise KerberosError(f"Error renaming principal: {exc}") from exc

    async def reset_principal_pw(
        self, principal_name: str, new_password: str
    ) -> None:
        """Reset principal password in Kerberos.

        :param principal_name: str
        :param new_password: str
        :raises KerberosService.PrincipalError: if an error occurs.
        """
        try:
            await self.kadmin.change_principal_password(
                principal_name, new_password
            )
        except Exception as exc:
            raise KerberosError(
                f"Error resetting principal password: {exc}"
            ) from exc

    async def delete_principal(self, principal_name: str) -> None:
        """Delete principal in Kerberos.

        :param principal_name: str
        :raises KerberosService.PrincipalError: if an error occurs.
        """
        try:
            await self.kadmin.del_principal(principal_name)
        except Exception as exc:
            raise KerberosError(f"Error deleting principal: {exc}") from exc
