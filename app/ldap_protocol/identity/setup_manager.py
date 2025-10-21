"""Setup service.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abstract_dao import AbstractService
from constants import FIRST_SETUP_DATA
from ldap_protocol.identity.dto import SetupDTO
from ldap_protocol.identity.exceptions.auth import AlreadyConfiguredError
from ldap_protocol.identity.use_cases import SetupUseCase
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.utils.helpers import ft_now


class SetupManager(AbstractService):
    """Setup manager."""

    def __init__(
        self,
        setup_use_case: SetupUseCase,
        entity_type_use_case: EntityTypeUseCase,
    ) -> None:
        """Initialize Setup manager.

        :param setup_use_case: Setup use case
        :param entity_type_use_case: Entity Type use case
        return: None.
        """
        self._setup_use_case = setup_use_case
        self._entity_type_use_case = entity_type_use_case

    async def setup(self, dto: SetupDTO) -> None:
        """Perform the initial setup of structure and policies.

        :param dto: SetupDTO with setup parameters
        :raises AlreadyConfiguredError: if setup already performed
        :raises ForbiddenError: if password policy not passed
        :return: None.
        """
        if await self.is_setuped():
            raise AlreadyConfiguredError("Setup already performed")
        await self._entity_type_use_case.create_for_first_setup()

        user_data = self._create_user_data_by_request(dto)
        FIRST_SETUP_DATA.append(user_data)

        await self._setup_use_case.create(
            dto,
            FIRST_SETUP_DATA,
        )

    async def is_setuped(self) -> bool:
        """Check if setup is performed.

        :return: bool (True if setup is performed, False otherwise)
        """
        return await self._setup_use_case.is_setuped()

    def _create_user_data_by_request(self, dto: SetupDTO) -> dict:
        """Create user data by request.

        :param dto: SetupDTO with setup parameters
        :return: dict with user data
        """
        return {
            "name": "users",
            "object_class": "organizationalUnit",
            "attributes": {"objectClass": ["top", "container"]},
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
