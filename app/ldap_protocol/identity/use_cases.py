"""Setup service.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abstract_dao import AbstractService
from constants import FIRST_SETUP_DATA
from ldap_protocol.identity.dto import SetupDTO
from ldap_protocol.identity.exceptions.auth import AlreadyConfiguredError
from ldap_protocol.identity.setup_gateway import SetupGateway
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.utils.helpers import ft_now


class SetupUseCase(AbstractService):
    """Setup manager."""

    def __init__(
        self,
        setup_gateway: SetupGateway,
        entity_type_use_case: EntityTypeUseCase,
    ) -> None:
        """Initialize Setup manager.

        :param setup_gateway: Setup use case
        :param entity_type_use_case: Entity Type use case
        return: None.
        """
        self._setup_gateway = setup_gateway
        self._entity_type_use_case = entity_type_use_case

    async def setup(self, dto: SetupDTO) -> None:
        """Perform the initial setup of structure and policies.

        :param dto: SetupDTO with setup parameters
        :raises AlreadyConfiguredError: if setup already performed
        :raises ForbiddenError: if password policy not passed
        :return: None.
        """
        if await self.is_setup():
            raise AlreadyConfiguredError("Setup already performed")
        await self._entity_type_use_case.create_for_first_setup()

        user_data = self._create_user_data(dto)

        FIRST_SETUP_DATA.append(user_data)

        await self._setup_gateway.create(
            dto,
            FIRST_SETUP_DATA,
        )

    async def is_setup(self) -> bool:
        """Check if setup is performed.

        :return: bool (True if setup is performed, False otherwise)
        """
        return await self._setup_gateway.is_setup()

    def _create_user_data(self, dto: SetupDTO) -> dict:
        """Create user data by request.

        :param dto: SetupDTO with setup parameters
        :return: dict with user data
        """
        return {
            "name": "users",
            "object_class": "container",
            "attributes": {"objectClass": ["top"]},
            "children": [
                {
                    "name": dto.username,
                    "object_class": "user",
                    "organizationalPerson": {
                        "sam_account_name": dto.username,
                        "user_principal_name": dto.user_principal_name,
                        "mail": dto.mail,
                        "display_name": dto.display_name,
                        "password": dto.password,
                        "groups": ["domain admins"],
                    },
                    "attributes": {
                        "objectClass": [
                            "top",
                            "person",
                            "organizationalPerson",
                            "posixAccount",
                            "shadowAccount",
                            "inetOrgPerson",
                        ],
                        "pwdLastSet": [ft_now()],
                        "loginShell": ["/bin/bash"],
                        "uidNumber": ["1000"],
                        "gidNumber": ["513"],
                        "userAccountControl": ["512"],
                        "primaryGroupID": ["512"],
                    },
                    "objectSid": 500,
                },
            ],
        }
